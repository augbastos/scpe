#!/usr/bin/env python3
"""Generate the normative `scpe/1` conformance corpus.

Each vector is a directory containing the artifact, its `.scpe.jsonl` record, an
`allowed_signers` policy, the public key, and an `expected.json` naming the status and the
facets a conforming verifier MUST produce (SPEC §2).

Signing keys are generated fresh into a temporary directory and are NEVER written into the
corpus. Only public keys ship, marked as throwaway — the same convention the retired corpus
used. Regenerating the corpus therefore produces different signatures, which is expected:
the vectors are for VERIFYING conformance, not for byte-comparing against a golden file.

    python make_vectors.py [--out DIR]
"""

from __future__ import annotations

import argparse
import base64
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REFERENCE = HERE.parent.parent / "reference"
sys.path.insert(0, str(REFERENCE))

from scpe_sign import (  # noqa: E402
    build_envelope, key_algorithm, key_fingerprint, sha256_file, SOURCE_TYPES,
)
from scpe_verify import ROLE_NAMESPACES, SPEC_VERSION, STATEMENT_TYPE  # noqa: E402

PREDICATE_TYPE = "https://augbastos.github.io/scpe/generation/v1"
COMMENT = "scpe-v1-test-vector-key (throwaway)"


def keygen(directory: Path, name: str) -> Path:
    path = directory / name
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", COMMENT, "-f", str(path)],
                   check=True, capture_output=True)
    return path


def statement(artifact: Path, key: Path, *, role: str = "producer", **predicate_extra) -> dict:
    generation = {"digitalSourceType": SOURCE_TYPES["trainedAlgorithmicData"]}
    generation.update(predicate_extra.pop("generation", {}))
    predicate = {
        "scpeVersion": SPEC_VERSION,
        "generation": generation,
        "signer": [{"keyFingerprint": key_fingerprint(key),
                    "alg": key_algorithm(key), "role": role}],
    }
    predicate.update(predicate_extra)
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": artifact.name, "digest": {"sha256": sha256_file(artifact)}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def envelope_line(stmt: dict, key: Path, role: str = "producer") -> str:
    return json.dumps(build_envelope(stmt, key, ROLE_NAMESPACES[role]),
                      separators=(",", ":")) + "\n"


def payload_digest(line: str) -> str:
    import hashlib
    return hashlib.sha256(base64.b64decode(json.loads(line)["payload"])).hexdigest()


def resign_mutated(line: str, key: Path, mutate, role: str = "producer") -> str:
    """Re-sign after mutating, so the vector tests the RULE rather than a broken signature."""
    stmt = json.loads(base64.b64decode(json.loads(line)["payload"]))
    mutate(stmt)
    return envelope_line(stmt, key, role)


def mutate_unsigned(line: str, mutate) -> str:
    """Mutate WITHOUT re-signing — the signature must then fail."""
    env = json.loads(line)
    stmt = json.loads(base64.b64decode(env["payload"]))
    mutate(stmt)
    env["payload"] = base64.b64encode(
        json.dumps(stmt, separators=(",", ":"), sort_keys=True).encode()).decode()
    return json.dumps(env, separators=(",", ":")) + "\n"


def write_vector(out: Path, name: str, *, artifact_bytes: bytes, record: str,
                 policy_lines: list[str], expected: dict, note: str) -> None:
    d = out / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "artifact.bin").write_bytes(artifact_bytes)
    (d / "artifact.bin.scpe.jsonl").write_text(record, encoding="utf-8")
    (d / "allowed_signers").write_text("".join(policy_lines), encoding="utf-8")
    expected = dict(expected)
    expected["note"] = note
    (d / "expected.json").write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=HERE)
    args = parser.parse_args()

    if shutil.which("ssh-keygen") is None:
        raise SystemExit("ssh-keygen is required to generate vectors")

    with tempfile.TemporaryDirectory(prefix="scpe-vectors-") as tmp:
        tmpdir = Path(tmp)
        alice = keygen(tmpdir, "alice")          # producer
        bob = keygen(tmpdir, "bob")              # independent observer
        mallory = keygen(tmpdir, "mallory")      # not in any policy

        alice_pub = (tmpdir / "alice.pub").read_text().strip()
        bob_pub = (tmpdir / "bob.pub").read_text().strip()

        producer_policy = [f'alice namespaces="scpe/1" {alice_pub}\n']
        both_policy = [f'alice namespaces="scpe/1" {alice_pub}\n',
                       f'bob namespaces="scpe-obs/1" {bob_pub}\n']

        content = b"quarterly summary, machine generated\n"
        artifact = tmpdir / "artifact.bin"
        artifact.write_bytes(content)

        base = statement(artifact, alice, generation={
            "provider": "anthropic", "model": "claude-opus-4-5-20251101",
            "humanOversight": "prompt_guided"})
        base_line = envelope_line(base, alice)

        facets = {"binding": "bound", "signature": "valid", "anchor": "policy",
                  "attribution": "self-asserted", "time": "unanchored", "lineage": "none"}

        # 1 — the happy path.
        write_vector(args.out, "valid-generation", artifact_bytes=content, record=base_line,
                     policy_lines=producer_policy,
                     expected={"status": "ok", "exit": 0, "facets": facets},
                     note="A well-formed generation record. Note that the strongest available "
                          "attribution is still self-asserted.")

        # 2 — the artifact changed after signing.
        write_vector(args.out, "tampered-artifact", artifact_bytes=content + b"EXTRA",
                     record=base_line, policy_lines=producer_policy,
                     expected={"status": "digest-mismatch", "exit": 21},
                     note="Bytes edited after signing; the subject digest no longer matches.")

        # 3 — the record changed after signing.
        write_vector(args.out, "tampered-provenance", artifact_bytes=content,
                     record=mutate_unsigned(
                         base_line,
                         lambda s: s["predicate"]["generation"].update({"model": "other-model"})),
                     policy_lines=producer_policy,
                     expected={"status": "signature-invalid", "exit": 20},
                     note="The declared model was edited without re-signing.")

        # 4 — a valid record, attached to bytes it was not made for.
        write_vector(args.out, "transplanted-provenance", artifact_bytes=b"entirely different\n",
                     record=base_line, policy_lines=producer_policy,
                     expected={"status": "digest-mismatch", "exit": 21},
                     note="A genuine, correctly signed record moved onto another file. The "
                          "subject digest lives inside the signed payload, so it cannot follow.")

        # 5 — signer absent from the policy.
        write_vector(args.out, "signer-not-in-policy", artifact_bytes=content, record=base_line,
                     policy_lines=[f'mallory namespaces="scpe/1" '
                                   f'{(tmpdir / "mallory.pub").read_text().strip()}\n'],
                     expected={"status": "signature-invalid", "exit": 20},
                     note="The signature is cryptographically sound but no trusted principal "
                          "holds the key.")

        # 6 — a version this verifier does not implement.
        write_vector(args.out, "unknown-version", artifact_bytes=content,
                     record=resign_mutated(base_line, alice,
                                           lambda s: s["predicate"].update({"scpeVersion": "99"})),
                     policy_lines=producer_policy,
                     expected={"status": "unsupported-version", "exit": 31},
                     note="Correctly signed, unknown version. Fail closed, never a partial read.")

        # 7 — a predicate type this verifier does not implement.
        write_vector(args.out, "unknown-predicate", artifact_bytes=content,
                     record=resign_mutated(
                         base_line, alice,
                         lambda s: s.update({"predicateType": "https://example.invalid/x/v1"})),
                     policy_lines=producer_policy,
                     expected={"status": "unsupported-predicate", "exit": 30},
                     note="A signed statement of some other kind. Refused, not best-effort read.")

        # 8 — a suite registered in the spec and implemented by nobody yet.
        write_vector(args.out, "unsupported-suite", artifact_bytes=content,
                     record=resign_mutated(
                         base_line, alice,
                         lambda s: s["predicate"]["signer"][0].update({"alg": "ml-dsa-44"})),
                     policy_lines=producer_policy,
                     expected={"status": "unsupported-suite", "exit": 32},
                     note="Post-quantum suite registered in SPEC 8.1 and not implemented. Today "
                          "this must fail closed; tomorrow it must pass with no format change.")

        # 9 — the anti-overclaim rule. This is why a hostile producer is worth writing.
        overclaim = statement(artifact, alice)
        overclaim["predicate"]["assurance"] = {"attribution": "tee-attested"}
        write_vector(args.out, "assurance-overclaimed", artifact_bytes=content,
                     record=envelope_line(overclaim, alice), policy_lines=producer_policy,
                     expected={"status": "assurance-overclaimed", "exit": 22},
                     note="A VALID signature over a false assurance claim. The verifier "
                          "recomputes the facet and refuses. Signature validity is not the "
                          "question; who computed the claim is.")

        # 10 — an independent observation lights the ladder's second rung.
        observation = statement(artifact, bob, role="observer",
                                observed={"statementDigest": {"sha256": payload_digest(base_line)}})
        observed_facets = dict(facets, attribution="countersigned")
        write_vector(args.out, "countersigned", artifact_bytes=content,
                     record=base_line + envelope_line(observation, bob, "observer"),
                     policy_lines=both_policy,
                     expected={"status": "ok", "exit": 0, "facets": observed_facets},
                     note="A second key, under a different principal and namespace, signs a "
                          "narrow statement about these bytes. It does NOT establish a second "
                          "party - see SPEC 10.5 for why no offline verifier can.")

        # 11 — the same observation, transplanted. Must not raise attribution.
        decoy = tmpdir / "decoy.bin"
        decoy.write_bytes(b"unrelated\n")
        decoy_line = envelope_line(statement(decoy, alice), alice)
        stolen = statement(decoy, bob, role="observer",
                           observed={"statementDigest": {"sha256": payload_digest(decoy_line)}})
        write_vector(args.out, "transplanted-observation", artifact_bytes=content,
                     record=base_line + envelope_line(stolen, bob, "observer"),
                     policy_lines=both_policy,
                     expected={"status": "ok", "exit": 0, "facets": facets},
                     note="A genuine observation about a DIFFERENT statement, pasted into this "
                          "bundle. The record stays valid and attribution stays self-asserted: "
                          "an unrelated signature must never raise a facet.")

        # 12 — an observer reaching beyond what it could have witnessed.
        wide = statement(artifact, bob, role="observer",
                         observed={"statementDigest": {"sha256": payload_digest(base_line)}})
        wide["predicate"]["generation"]["model"] = "claude-opus-4-5-20251101"
        write_vector(args.out, "observer-overreach", artifact_bytes=content,
                     record=base_line + envelope_line(wide, bob, "observer"),
                     policy_lines=both_policy,
                     expected={"status": "malformed-predicate", "exit": 35},
                     note="An observer claiming a model identity it cannot have witnessed. "
                          "Refused by schema, so the wider claim is unrepresentable rather "
                          "than merely discouraged.")

        # 13 — duplicate JSON key: identical bytes must not admit two readings.
        env = json.loads(base_line)
        body = base64.b64decode(env["payload"]).decode()
        doubled = body.replace('"scpeVersion":"1"', '"scpeVersion":"1","scpeVersion":"99"', 1)
        env["payload"] = base64.b64encode(doubled.encode()).decode()
        write_vector(args.out, "duplicate-json-key", artifact_bytes=content,
                     record=json.dumps(env, separators=(",", ":")) + "\n",
                     policy_lines=producer_policy,
                     expected={"status": "signature-invalid", "exit": 20},
                     note="A repeated key at any depth is refused rather than resolved to "
                          "first- or last-wins. Here the signature also fails, which is the "
                          "belt to the parser's braces.")

        # 14 — a SIGNED duplicate key where both values are legal. This is the vector that
        # matters most for cross-language conformance, and it was added after measuring that
        # Go's encoding/json, Rust's serde_json, JavaScript's JSON.parse and Python's own
        # default loader ALL accept duplicate keys with last-wins. Only an explicit hook
        # rejects them. So an implementer who follows this spec using their language's
        # standard library produces a verifier that ACCEPTS this record and reports one
        # origin, while a conforming verifier refuses it — on identical bytes, under a valid
        # signature. Here the same signed artifact claims to be both a human photograph and
        # model output; swap the order and the naive verifier reports the other one.
        both_origins = (
            '{"_type":"https://in-toto.io/Statement/v1",'
            '"subject":[{"name":"artifact.bin","digest":{"sha256":"%s"}}],'
            '"predicateType":"%s",'
            '"predicate":{"scpeVersion":"1",'
            '"generation":{"digitalSourceType":"%s",'
            '"digitalSourceType":"%s"},'
            '"signer":[{"keyFingerprint":"%s","alg":"%s","role":"producer"}]}}'
            % (sha256_file(artifact), PREDICATE_TYPE,
               SOURCE_TYPES["digitalCapture"], SOURCE_TYPES["trainedAlgorithmicData"],
               key_fingerprint(alice), key_algorithm(alice))
        ).encode()
        import base64 as _b64
        from scpe_sign import sshsig_sign as _sign
        from scpe_verify import PAYLOAD_TYPE as _pt, pae as _pae
        _sig = _sign(_pae(_pt, both_origins), alice, ROLE_NAMESPACES["producer"])
        write_vector(args.out, "signed-duplicate-key", artifact_bytes=content,
                     record=json.dumps({"payload": _b64.b64encode(both_origins).decode(),
                                        "payloadType": _pt,
                                        "signatures": [{"sig": _b64.b64encode(_sig).decode()}]},
                                       separators=(",", ":")) + "\n",
                     policy_lines=producer_policy,
                     expected={"status": "malformed-input", "exit": 34},
                     note="A VALID signature over a payload containing a duplicate key whose "
                          "two values are both legal - one saying a human captured this, one "
                          "saying a model generated it. Measured: Go encoding/json, Rust "
                          "serde_json, JavaScript and Python's default loader all accept this "
                          "with last-wins. A verifier that does so reports an origin the "
                          "signer can choose per-reader. Refusing is the only reading that "
                          "makes identical bytes yield identical verdicts everywhere.")

        # 15 — a payload whose bytes and characters differ in count.
        #
        # PAE length-prefixes the payload, and LEN() counts BYTES. Every non-ASCII character
        # below occupies more than one byte, so an implementation that measures the payload
        # in characters or UTF-16 code units computes a different LEN(b), signs different
        # bytes, and produces a signature no one else can verify. JavaScript's
        # String.prototype.length does exactly that. Rust invites the neighbouring mistake:
        # decoding the payload to a String via from_utf8_lossy before hashing it.
        #
        # Go and Python return byte counts for len() over []byte/bytes, so neither reference
        # implementation would have caught this alone. That is the point of the vector.
        # Serialized with ensure_ascii=False ON PURPOSE. The reference producer escapes
        # non-ASCII to \uXXXX, so it can never emit this shape and would never exercise the
        # rule; another producer emitting raw UTF-8 is equally conforming, because PAE signs
        # whatever bytes it is given. A verifier has to handle both.
        unicode_stmt = statement(artifact, alice, generation={
            "provider": "anthropic",
            "model": "modèle-génératif-日本語",
        })
        unicode_stmt["subject"][0]["name"] = "relatório-anual-café.pdf"
        raw_body = json.dumps(unicode_stmt, separators=(",", ":"), sort_keys=True,
                              ensure_ascii=False).encode("utf-8")
        import base64 as _b
        from scpe_sign import sshsig_sign as _s
        from scpe_verify import PAYLOAD_TYPE as _p, pae as _pae
        _sig = _s(_pae(_p, raw_body), alice, ROLE_NAMESPACES["producer"])
        write_vector(args.out, "non-ascii-payload", artifact_bytes=content,
                     record=json.dumps({"payload": _b.b64encode(raw_body).decode(),
                                        "payloadType": _p,
                                        "signatures": [{"sig": _b.b64encode(_sig).decode()}]},
                                       separators=(",", ":")) + "\n",
                     policy_lines=producer_policy,
                     expected={"status": "ok", "exit": 0, "facets": facets},
                     note="A well-formed record whose payload contains multi-byte UTF-8 in "
                          "both a declared field and the subject name. Verifies only if PAE "
                          "length-prefixes the payload in BYTES and the payload is never "
                          "decoded to a text type before signing or verifying.")

        # 16 — no record at all.
        d = args.out / "no-provenance"
        d.mkdir(parents=True, exist_ok=True)
        (d / "artifact.bin").write_bytes(content)
        (d / "allowed_signers").write_text("".join(producer_policy), encoding="utf-8")
        (d / "expected.json").write_text(json.dumps({
            "status": "no-provenance-found", "exit": 40,
            "note": "Absence of a record proves nothing: the file either never had one or was "
                    "stripped. These are indistinguishable, and the status says so."}, indent=2)
            + "\n", encoding="utf-8")

        (args.out / "PUBLIC_KEYS").write_text(
            f"{alice_pub}\n{bob_pub}\n", encoding="utf-8")

    print(f"wrote vectors to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
