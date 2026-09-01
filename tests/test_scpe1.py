"""Security-property tests for `scpe/1`.

These test the PROPERTIES the specification claims, not the happy path. Every test below
corresponds to a claim in SPECIFICATION.md §13.1, and several exist because an earlier draft
of the design failed them.

Keys are generated per-session into a temp directory and never written into the repository.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
REFERENCE = REPO / "reference"
sys.path.insert(0, str(REFERENCE))

from scpe_sign import build_envelope, key_algorithm, key_fingerprint, sha256_file  # noqa: E402
from scpe_verify import ROLE_NAMESPACES, SPEC_VERSION, STATEMENT_TYPE, pae  # noqa: E402

VERIFIER = REFERENCE / "scpe_verify.py"
SIGNER = REFERENCE / "scpe_sign.py"
PREDICATE_TYPE = "https://augbastos.github.io/scpe/generation/v1"
SOURCE_TYPE = "http://c2pa.org/digitalsourcetype/trainedAlgorithmicData"


# --------------------------------------------------------------------- helpers


def keygen(directory: Path, name: str) -> Path:
    path = directory / name
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"{name} (test)",
                    "-f", str(path)], check=True, capture_output=True)
    return path


def pubkey(key: Path) -> str:
    return key.with_suffix(key.suffix + ".pub").read_text().strip()


def policy(path: Path, *entries: tuple[str, str, Path]) -> Path:
    """entries: (principal, namespaces, key)"""
    path.write_text("".join(f'{p} namespaces="{ns}" {pubkey(k)}\n' for p, ns, k in entries),
                    encoding="utf-8")
    return path


def statement(artifact: Path, key: Path, *, role: str = "producer", **extra) -> dict:
    generation = {"digitalSourceType": SOURCE_TYPE}
    generation.update(extra.pop("generation", {}))
    predicate = {
        "scpeVersion": SPEC_VERSION,
        "generation": generation,
        "signer": [{"keyFingerprint": key_fingerprint(key), "alg": key_algorithm(key),
                    "role": role}],
    }
    predicate.update(extra)
    return {"_type": STATEMENT_TYPE,
            "subject": [{"name": artifact.name, "digest": {"sha256": sha256_file(artifact)}}],
            "predicateType": PREDICATE_TYPE, "predicate": predicate}


def line(stmt: dict, key: Path, role: str = "producer") -> str:
    return json.dumps(build_envelope(stmt, key, ROLE_NAMESPACES[role]),
                      separators=(",", ":")) + "\n"


def payload_sha256(record_line: str) -> str:
    import hashlib
    return hashlib.sha256(base64.b64decode(json.loads(record_line)["payload"])).hexdigest()


def run(artifact: Path, policy_file: Path | None = None, keys: Path | None = None) -> dict:
    cmd = [sys.executable, str(VERIFIER), str(artifact), "--json"]
    if policy_file:
        cmd += ["--policy", str(policy_file)]
    if keys:
        cmd += ["--keys", str(keys)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert proc.stdout.strip(), f"no stdout; stderr:\n{proc.stderr[-2000:]}"
    result = json.loads(proc.stdout)
    assert result["exit"] == proc.returncode, "exit code must match the reported status"
    return result


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    """A producer, an independent observer, an untrusted third party, and a signed artifact."""
    d = tmp_path_factory.mktemp("scpe1")
    alice, bob, mallory = keygen(d, "alice"), keygen(d, "bob"), keygen(d, "mallory")

    artifact = d / "report.txt"
    artifact.write_bytes(b"quarterly summary, machine generated\n")
    record = line(statement(artifact, alice, generation={
        "provider": "anthropic", "model": "claude-opus-4-5-20251101"}), alice)
    (d / "report.txt.scpe.jsonl").write_text(record, encoding="utf-8")

    return {
        "dir": d, "alice": alice, "bob": bob, "mallory": mallory,
        "artifact": artifact, "record": record,
        "producer_policy": policy(d / "p_producer", ("alice", "scpe/1", alice)),
        "both_policy": policy(d / "p_both", ("alice", "scpe/1", alice),
                              ("bob", "scpe-obs/1", bob)),
    }


# ------------------------------------------------------------- the happy path


def test_valid_record_verifies(world):
    r = run(world["artifact"], world["producer_policy"])
    assert r["status"] == "ok"
    assert r["facets"]["binding"] == "bound"
    assert r["facets"]["signature"] == "valid"
    assert r["facets"]["anchor"] == "policy"


def test_a_pass_always_says_what_it_did_not_check(world):
    """SPEC §11.4: there is always something a signature did not prove."""
    r = run(world["artifact"], world["producer_policy"])
    assert r["not_checked"], "a passing result with an empty not_checked is a broken verifier"


def test_declared_claims_never_appear_in_proved(world):
    """SPEC §11.3 — the anti-laundering property. The model name is a claim, not a finding."""
    r = run(world["artifact"], world["producer_policy"])
    assert any("claude-opus-4-5" in d for d in r["declared"])
    assert not any("claude-opus-4-5" in p for p in r["proved"])


def test_strongest_available_attribution_is_self_asserted(world):
    """The honest default. If this ever passes trivially, something is overclaiming."""
    r = run(world["artifact"], world["producer_policy"])
    assert r["facets"]["attribution"] == "self-asserted"


# ------------------------------------------------------------------- tampering


def test_modified_artifact_is_rejected(world, tmp_path):
    art = tmp_path / "report.txt"
    art.write_bytes(world["artifact"].read_bytes() + b"EXTRA")
    (tmp_path / "report.txt.scpe.jsonl").write_text(world["record"])
    assert run(art, world["producer_policy"])["status"] == "digest-mismatch"


def test_modified_record_is_rejected(world, tmp_path):
    env = json.loads(world["record"])
    body = json.loads(base64.b64decode(env["payload"]))
    body["predicate"]["generation"]["model"] = "some-other-model"
    env["payload"] = base64.b64encode(
        json.dumps(body, separators=(",", ":"), sort_keys=True).encode()).decode()

    art = tmp_path / "report.txt"
    art.write_bytes(world["artifact"].read_bytes())
    (tmp_path / "report.txt.scpe.jsonl").write_text(json.dumps(env, separators=(",", ":")) + "\n")
    assert run(art, world["producer_policy"])["status"] == "signature-invalid"


def test_record_cannot_be_transplanted_onto_other_bytes(world, tmp_path):
    """The subject digest is inside the signed payload, so it cannot follow the file."""
    art = tmp_path / "report.txt"
    art.write_bytes(b"a completely different file\n")
    (tmp_path / "report.txt.scpe.jsonl").write_text(world["record"])
    assert run(art, world["producer_policy"])["status"] == "digest-mismatch"


def test_missing_record_is_not_an_error_but_is_not_a_pass(world, tmp_path):
    art = tmp_path / "naked.txt"
    art.write_bytes(b"no record here\n")
    assert run(art, world["producer_policy"])["status"] == "no-provenance-found"


def test_untrusted_signer_is_rejected(world, tmp_path):
    pol = policy(tmp_path / "p", ("mallory", "scpe/1", world["mallory"]))
    assert run(world["artifact"], pol)["status"] == "signature-invalid"


# --------------------------------------------------------------- fail-closed


@pytest.mark.parametrize("mutate,expected", [
    (lambda s: s["predicate"].update({"scpeVersion": "99"}), "unsupported-version"),
    (lambda s: s.update({"predicateType": "https://example.invalid/other/v1"}),
     "unsupported-predicate"),
    (lambda s: s["predicate"]["signer"][0].update({"alg": "ml-dsa-44"}), "unsupported-suite"),
])
def test_unrecognised_input_fails_closed(world, tmp_path, mutate, expected):
    """SPEC §9.7. Correctly signed and still refused — never a partial or best-effort read."""
    stmt = json.loads(base64.b64decode(json.loads(world["record"])["payload"]))
    mutate(stmt)
    art = tmp_path / "report.txt"
    art.write_bytes(world["artifact"].read_bytes())
    (tmp_path / "report.txt.scpe.jsonl").write_text(line(stmt, world["alice"]))
    assert run(art, world["producer_policy"])["status"] == expected


def test_registered_but_unimplemented_suite_does_not_need_a_format_change(world, tmp_path):
    """`ml-dsa-44` must fail closed today. That it is *named* in the spec is what lets a
    future verifier accept it without touching a single signed byte."""
    stmt = json.loads(base64.b64decode(json.loads(world["record"])["payload"]))
    stmt["predicate"]["signer"][0]["alg"] = "ml-dsa-44"
    art = tmp_path / "report.txt"
    art.write_bytes(world["artifact"].read_bytes())
    (tmp_path / "report.txt.scpe.jsonl").write_text(line(stmt, world["alice"]))
    assert run(art, world["producer_policy"])["exit"] == 32


# ------------------------------------------------------- the anti-overclaim law


def test_a_signed_assurance_claim_is_refused(world, tmp_path):
    """SPEC §10.1. The signature is VALID; the claim is still refused, because the verifier
    computes facets and a producer does not. This is the whole discipline in one test."""
    stmt = statement(world["artifact"], world["alice"])
    stmt["predicate"]["assurance"] = {"attribution": "tee-attested"}

    art = tmp_path / "report.txt"
    art.write_bytes(world["artifact"].read_bytes())
    (tmp_path / "report.txt.scpe.jsonl").write_text(line(stmt, world["alice"]))

    r = run(art, world["producer_policy"])
    assert r["status"] == "assurance-overclaimed"
    assert r["facets"]["signature"] == "valid", "the signature was fine; the claim was not"


# -------------------------------------------------------- countersignature


def test_independent_countersignature_is_recognised(world, tmp_path):
    art = tmp_path / "report.txt"
    art.write_bytes(world["artifact"].read_bytes())
    obs = statement(art, world["bob"], role="observer",
                    observed={"statementDigest": {"sha256": payload_sha256(world["record"])}})
    (tmp_path / "report.txt.scpe.jsonl").write_text(
        world["record"] + line(obs, world["bob"], "observer"))
    assert run(art, world["both_policy"])["facets"]["attribution"] == "countersigned"


def test_one_party_with_two_keys_under_one_principal_does_not_countersign(world, tmp_path):
    """The H-1 regression.

    An earlier draft required only that the observer key differ from the producer key, which
    one person defeats in a minute with a second `ssh-keygen`. When the operator's policy
    lists both keys under the SAME principal — the operator's own statement that this is one
    party — the facet must not rise.
    """
    second = keygen(tmp_path, "alice2")
    art = tmp_path / "report.txt"
    art.write_bytes(world["artifact"].read_bytes())
    obs = statement(art, second, role="observer",
                    observed={"statementDigest": {"sha256": payload_sha256(world["record"])}})
    (tmp_path / "report.txt.scpe.jsonl").write_text(
        world["record"] + line(obs, second, "observer"))

    pol = policy(tmp_path / "p", ("alice", "scpe/1", world["alice"]),
                 ("alice", "scpe-obs/1", second))
    assert run(art, pol)["facets"]["attribution"] == "self-asserted"


def test_self_supplied_keys_cannot_raise_attribution(world, tmp_path):
    """SPEC §10.5 anchor cap. A producer who supplies the key file supplies both 'parties'."""
    art = tmp_path / "report.txt"
    art.write_bytes(world["artifact"].read_bytes())
    obs = statement(art, world["bob"], role="observer",
                    observed={"statementDigest": {"sha256": payload_sha256(world["record"])}})
    (tmp_path / "report.txt.scpe.jsonl").write_text(
        world["record"] + line(obs, world["bob"], "observer"))

    keyfile = tmp_path / "keys"
    keyfile.write_text(pubkey(world["alice"]) + "\n" + pubkey(world["bob"]) + "\n")

    r = run(art, keys=keyfile)
    assert r["facets"]["anchor"] == "flag"
    assert r["facets"]["attribution"] == "self-asserted"


def test_observer_cannot_claim_what_it_cannot_witness(world, tmp_path):
    """SPEC §8.4. An observer saw bytes on disk; it cannot know which model made them."""
    art = tmp_path / "report.txt"
    art.write_bytes(world["artifact"].read_bytes())
    obs = statement(art, world["bob"], role="observer",
                    observed={"statementDigest": {"sha256": payload_sha256(world["record"])}})
    obs["predicate"]["generation"]["model"] = "claude-opus-4-5-20251101"
    (tmp_path / "report.txt.scpe.jsonl").write_text(
        world["record"] + line(obs, world["bob"], "observer"))
    assert run(art, world["both_policy"])["status"] == "malformed-predicate"


def test_an_observation_of_a_different_statement_raises_nothing(world, tmp_path):
    """A genuine countersignature, pasted into the wrong bundle, must not travel."""
    decoy = tmp_path / "decoy.bin"
    decoy.write_bytes(b"unrelated\n")
    decoy_record = line(statement(decoy, world["alice"]), world["alice"])
    stolen = statement(decoy, world["bob"], role="observer",
                       observed={"statementDigest": {"sha256": payload_sha256(decoy_record)}})

    art = tmp_path / "report.txt"
    art.write_bytes(world["artifact"].read_bytes())
    (tmp_path / "report.txt.scpe.jsonl").write_text(
        world["record"] + line(stolen, world["bob"], "observer"))

    r = run(art, world["both_policy"])
    assert r["status"] == "ok"
    assert r["facets"]["attribution"] == "self-asserted"


def test_role_is_discovered_from_the_namespace_not_read_from_the_payload(world, tmp_path):
    """SPEC §8.3. A payload claiming `observer` over a producer-namespace signature must not
    be credited as an observation — otherwise the record chooses the verifier's control flow."""
    art = tmp_path / "report.txt"
    art.write_bytes(world["artifact"].read_bytes())
    liar = statement(art, world["bob"], role="observer",
                     observed={"statementDigest": {"sha256": payload_sha256(world["record"])}})
    # Claims observer, signs under the PRODUCER namespace.
    forged = json.dumps(build_envelope(liar, world["bob"], ROLE_NAMESPACES["producer"]),
                        separators=(",", ":")) + "\n"
    (tmp_path / "report.txt.scpe.jsonl").write_text(world["record"] + forged)

    pol = policy(tmp_path / "p", ("alice", "scpe/1", world["alice"]),
                 ("bob", "scpe/1,scpe-obs/1", world["bob"]))
    r = run(art, pol)
    # The signature verifies under the producer namespace, so it IS a producer signature
    # regardless of what the payload calls itself. The bundle then carries two producer
    # statements and is refused outright — a stronger outcome than merely not crediting it.
    assert r["facets"].get("attribution") != "countersigned"
    assert r["status"] == "malformed-input"


# ---------------------------------------------------------------- derivation


def test_parent_edge_requires_the_parent_record(world, tmp_path):
    """SPEC §6.2. A parent with no provenance cannot be declared as one, so the pin that
    defends against parent substitution cannot simply be omitted."""
    orphan = tmp_path / "orphan.txt"
    orphan.write_bytes(b"no record\n")
    child = tmp_path / "child.txt"
    child.write_bytes(b"child\n")

    proc = subprocess.run(
        [sys.executable, str(SIGNER), str(child), "--key", str(world["alice"]),
         "--derived-from", f"{orphan}:parentOf"], capture_output=True, text=True)
    assert proc.returncode != 0
    assert "parentOf" in (proc.stdout + proc.stderr)


def test_unresolved_lineage_is_declared_never_verified(world, tmp_path):
    parent = tmp_path / "draft.txt"
    parent.write_bytes(b"draft\n")
    subprocess.run([sys.executable, str(SIGNER), str(parent), "--key", str(world["alice"])],
                   check=True, capture_output=True)

    child = tmp_path / "final.txt"
    child.write_bytes(b"final\n")
    subprocess.run([sys.executable, str(SIGNER), str(child), "--key", str(world["alice"]),
                    "--derived-from", f"{parent}:parentOf"], check=True, capture_output=True)

    r = run(child, world["producer_policy"])
    assert r["facets"]["lineage"] == "declared"
    assert any("derivation edge" in n for n in r["not_checked"])


# ------------------------------------------------------------------ hygiene


def test_no_facet_is_ever_a_single_score(world):
    """SPEC §10.1: facets are reported separately and never collapsed."""
    r = run(world["artifact"], world["producer_policy"])
    assert set(r["facets"]) == {"binding", "signature", "anchor", "attribution",
                                "time", "lineage"}
    assert "score" not in r and "grade" not in r


def _chain(tmp_path, key, policy_file):
    """draft.txt <- final.txt, both signed, parent pinned."""
    draft = tmp_path / "draft.txt"
    draft.write_bytes(b"draft v1\n")
    subprocess.run([sys.executable, str(SIGNER), str(draft), "--key", str(key)],
                   check=True, capture_output=True)
    final = tmp_path / "final.txt"
    final.write_bytes(b"final v2\n")
    subprocess.run([sys.executable, str(SIGNER), str(final), "--key", str(key),
                    "--derived-from", f"{draft}:parentOf"], check=True, capture_output=True)
    return draft, final


def run_chain(artifact, policy_file):
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(artifact), "--policy", str(policy_file),
         "--chain", "--json"], capture_output=True, text=True, timeout=180)
    return json.loads(proc.stdout)


def test_a_pinned_parent_on_disk_verifies_the_chain(world, tmp_path):
    _, final = _chain(tmp_path, world["alice"], world["producer_policy"])
    assert run_chain(final, world["producer_policy"])["facets"]["lineage"] == "verified-depth-1"


def test_lineage_is_declared_until_asked_to_resolve(world, tmp_path):
    _, final = _chain(tmp_path, world["alice"], world["producer_policy"])
    assert run(final, world["producer_policy"])["facets"]["lineage"] == "declared"


def test_a_substituted_parent_breaks_the_chain(world, tmp_path):
    """SPEC §6.2. Someone who publishes their own record about the same input must not
    silently become your ancestor — which is why the pin is over the parent's signed
    statement and not merely over the parent's bytes."""
    draft, final = _chain(tmp_path, world["alice"], world["producer_policy"])
    # Mallory re-signs the parent artifact, replacing the record the child pinned.
    subprocess.run([sys.executable, str(SIGNER), str(draft), "--key", str(world["mallory"])],
                   check=True, capture_output=True)
    pol = policy(tmp_path / "p2", ("alice", "scpe/1", world["alice"]),
                 ("mallory", "scpe/1", world["mallory"]))
    assert run_chain(final, pol)["facets"]["lineage"] == "broken"


def test_self_supplied_keys_cannot_raise_lineage(world, tmp_path):
    """The anchor cap applies to lineage too: a producer holding the key set can sign every
    parent in the chain, so a self-anchored chain corroborates nothing (SPEC §10.5)."""
    _, final = _chain(tmp_path, world["alice"], world["producer_policy"])
    keyfile = tmp_path / "k"
    keyfile.write_text(pubkey(world["alice"]) + "\n")
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(final), "--keys", str(keyfile), "--chain",
         "--json"], capture_output=True, text=True, timeout=180)
    assert json.loads(proc.stdout)["facets"]["lineage"] == "declared"


def test_forge_anchor_requires_a_second_explicit_opt_in(world):
    """SPEC §12.3/§13.4: naming an account is not consent to reach the network."""
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(world["artifact"]),
         "--forge", "github:octocat", "--json"], capture_output=True, text=True, timeout=60)
    r = json.loads(proc.stdout)
    assert r["status"] == "malformed-input"
    assert "allow-host" in r["detail"]


def test_forge_refuses_a_host_outside_the_fixed_table(world):
    """The record never supplies a hostname; the operator picks a provider from a closed set."""
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(world["artifact"]),
         "--forge", "evilforge:victim", "--allow-host", "attacker.invalid", "--json"],
        capture_output=True, text=True, timeout=60)
    assert json.loads(proc.stdout)["status"] == "malformed-input"


def test_a_commitment_can_actually_be_opened(world, tmp_path):
    """SPEC §12.2, and a regression.

    An earlier producer built the SD-JWT disclosure, hashed it, and let the salt fall out of
    scope — so no commitment could ever be opened by anyone, including its author. A
    commitment nobody can open is not privacy; it is a hash of nothing checkable.
    """
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Summarise the quarterly figures.\n", encoding="utf-8")
    art = tmp_path / "out.txt"
    art.write_bytes(b"generated output\n")

    subprocess.run([sys.executable, str(SIGNER), str(art), "--key", str(world["alice"]),
                    "--commit-prompt", str(prompt)], check=True, capture_output=True)

    record = json.loads((tmp_path / "out.txt.scpe.jsonl").read_text().strip())
    payload = base64.b64decode(record["payload"])
    commitment = json.loads(payload)["predicate"]["commitments"][0]

    # The prompt text must NOT be in the signed record.
    assert b"Summarise the quarterly" not in payload

    # …and the disclosure the producer kept must open it.
    disclosure = (tmp_path / "out.txt.scpe.disclosures.jsonl").read_bytes().strip()
    import hashlib
    assert hashlib.sha256(disclosure).hexdigest() == commitment["value"]
    assert json.loads(disclosure)[1] == "prompt"


def test_time_is_never_raised_by_a_declared_timestamp(world, tmp_path):
    """SPEC §10.6. `producedAt` is a claim; a facet is an observation."""
    stmt = statement(world["artifact"], world["alice"],
                     generation={"producedAt": "2020-01-01T00:00:00Z"})
    art = tmp_path / "report.txt"
    art.write_bytes(world["artifact"].read_bytes())
    (tmp_path / "report.txt.scpe.jsonl").write_text(line(stmt, world["alice"]))

    r = run(art, world["producer_policy"])
    assert r["facets"]["time"] == "unanchored"
    assert any("producedAt" in d for d in r["declared"])
