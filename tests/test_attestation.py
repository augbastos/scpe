"""Attestation — signed AUDIT record (in-toto Statement in a DSSE envelope, Ed25519).
No diff, no credit, no scpe-specific trust root. The crucial test here proves
the format is NOT circular: an INDEPENDENT code path (raw `cryptography` Ed25519
verify over a by-hand DSSE PAE) accepts the same signature our own helpers produce."""
import base64
import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scpe.attestation import (
    AttestationFormatError, PAYLOAD_TYPE, build_statement, load_attestation,
    pae, parse_statement, save_attestation, sign_attestation, verify_attestation,
)
from scpe.signing import generate_private_key_pem, public_key_hex

REPORT = {
    "repo": "https://example.com/acme/widget.git",
    "base_sha": "a" * 40,
    "backend": "mock",
    "grade": "B",
    "summary": "solid, one real bug",
    "issues": [{"title": "add() subtracts", "rationale": "planted bug", "files": ["demo/calc.py"]}],
}

CLEAN_REPORT = {**REPORT, "issues": []}


def _statement(report=REPORT, pubkey=None) -> dict:
    return build_statement(
        repo_url=report["repo"], base_sha=report["base_sha"], auditor_name="Alice Auditor",
        auditor_email="alice@example.com", auditor_pubkey_hex=pubkey or "00" * 32,
        backend_label=report["backend"], created_at_iso="2026-07-20T00:00:00+00:00",
        report_dict=report)


def _signed(report=REPORT, pem=None):
    pem = pem or generate_private_key_pem()
    pub = public_key_hex(pem)
    statement = _statement(report, pubkey=pub)
    return sign_attestation(statement, pem), statement, pem, pub


# ---- build_statement --------------------------------------------------------

def test_build_statement_shape():
    statement = _statement()
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["subject"] == [{"name": REPORT["repo"], "digest": {"gitCommit": REPORT["base_sha"]}}]
    assert statement["predicateType"] == "https://scpe.dev/attestation/audit/v1"
    pred = statement["predicate"]
    assert pred["tool"]["name"] == "scpe"
    assert pred["auditor"] == {"name": "Alice Auditor", "email": "alice@example.com",
                                "publicKey": "00" * 32}
    assert pred["backend"] == "mock"
    assert pred["verdict"] == "findings"
    assert pred["findingsCount"] == 1
    assert pred["report"]["findings"] == [
        {"title": "add() subtracts", "rationale": "planted bug", "files": ["demo/calc.py"]}]


def test_build_statement_clean_verdict_when_no_issues():
    statement = _statement(CLEAN_REPORT)
    assert statement["predicate"]["verdict"] == "clean"
    assert statement["predicate"]["findingsCount"] == 0
    assert statement["predicate"]["report"]["findings"] == []


# ---- checks evidence (signed alongside the LLM verdict) ----------------------

SAMPLE_CHECKS = [
    {"tool": "tests", "ran": True, "passed": True, "summary": "pass", "tail": "1 passed"},
    {"tool": "bandit", "ran": False, "passed": None, "summary": "not installed", "tail": ""},
]


def test_build_statement_omits_checks_key_when_not_given():
    """checks=None (the default) must OMIT the key entirely — an omitted key means
    'we didn't look', distinct from an empty/absent-evidence list."""
    statement = _statement()
    assert "checks" not in statement["predicate"]


def test_build_statement_includes_checks_when_given():
    statement = build_statement(
        repo_url=REPORT["repo"], base_sha=REPORT["base_sha"], auditor_name="Alice Auditor",
        auditor_email="alice@example.com", auditor_pubkey_hex="00" * 32,
        backend_label=REPORT["backend"], created_at_iso="2026-07-20T00:00:00+00:00",
        report_dict=REPORT, checks=SAMPLE_CHECKS)
    assert statement["predicate"]["checks"] == SAMPLE_CHECKS


def test_signed_statement_with_checks_round_trips_and_verifies():
    """The checks array lives inside the predicate, so it's part of what gets signed —
    proving it survives sign -> verify -> parse is the load-bearing claim here."""
    pem = generate_private_key_pem()
    pub = public_key_hex(pem)
    statement = build_statement(
        repo_url=REPORT["repo"], base_sha=REPORT["base_sha"], auditor_name="Alice Auditor",
        auditor_email="alice@example.com", auditor_pubkey_hex=pub,
        backend_label=REPORT["backend"], created_at_iso="2026-07-20T00:00:00+00:00",
        report_dict=REPORT, checks=SAMPLE_CHECKS)
    envelope = sign_attestation(statement, pem)
    assert verify_attestation(envelope) is True
    loaded = parse_statement(envelope)
    assert loaded["predicate"]["checks"][0]["tool"] == "tests"
    assert loaded["predicate"]["checks"][0]["passed"] is True
    assert loaded["predicate"]["checks"][1]["ran"] is False


def test_verify_tamper_checks_field_false():
    """Signed evidence, not decoration: flipping a fail to a pass inside checks must
    be caught exactly like tampering a finding or a verdict."""
    pem = generate_private_key_pem()
    pub = public_key_hex(pem)
    statement = build_statement(
        repo_url=REPORT["repo"], base_sha=REPORT["base_sha"], auditor_name="Alice Auditor",
        auditor_email="alice@example.com", auditor_pubkey_hex=pub,
        backend_label=REPORT["backend"], created_at_iso="2026-07-20T00:00:00+00:00",
        report_dict=REPORT, checks=SAMPLE_CHECKS)
    envelope = sign_attestation(statement, pem)
    tampered = copy.deepcopy(statement)
    tampered["predicate"]["checks"][0]["passed"] = False
    envelope["payload"] = base64.standard_b64encode(
        json.dumps(tampered, separators=(",", ":"), sort_keys=True).encode()).decode()
    assert verify_attestation(envelope) is False


def test_parse_statement_sanitizes_checks_free_text():
    dirty_checks = [{"tool": "tests", "ran": True, "passed": False,
                      "summary": "fail\nwith\tcontrol", "tail": "trace\x00back"}]
    pem = generate_private_key_pem()
    statement = build_statement(
        repo_url=REPORT["repo"], base_sha=REPORT["base_sha"], auditor_name="Alice Auditor",
        auditor_email="alice@example.com", auditor_pubkey_hex=public_key_hex(pem),
        backend_label=REPORT["backend"], created_at_iso="2026-07-20T00:00:00+00:00",
        report_dict=REPORT, checks=dirty_checks)
    envelope = sign_attestation(statement, pem)
    parsed = parse_statement(envelope)
    c = parsed["predicate"]["checks"][0]
    assert "\n" not in c["summary"] and "\t" not in c["summary"]
    assert "\x00" not in c["tail"]


# ---- sign / verify round trip -----------------------------------------------

def test_sign_and_verify_round_trip():
    envelope, _statement_, _pem, pub = _signed()
    assert envelope["payloadType"] == PAYLOAD_TYPE
    assert len(envelope["signatures"]) == 1
    assert verify_attestation(envelope) is True
    assert verify_attestation(envelope, expected_pubkey_hex=pub) is True


def test_verify_expected_pubkey_mismatch_false():
    envelope, _statement_, _pem, _pub = _signed()
    other_pub = public_key_hex(generate_private_key_pem())
    assert verify_attestation(envelope, expected_pubkey_hex=other_pub) is False


def test_verify_flipped_signature_byte_false():
    envelope, *_ = _signed()
    sig = bytearray(base64.standard_b64decode(envelope["signatures"][0]["sig"]))
    sig[0] ^= 0xFF
    envelope["signatures"][0]["sig"] = base64.standard_b64encode(bytes(sig)).decode()
    assert verify_attestation(envelope) is False


@pytest.mark.parametrize("mutate", [
    lambda s: s.__setitem__("predicateType", "tampered"),
    lambda s: s["predicate"].__setitem__("verdict", "clean"),
    lambda s: s["predicate"].__setitem__("findingsCount", 999),
    lambda s: s["subject"][0].__setitem__("name", "https://evil.example/hijacked.git"),
    lambda s: s["subject"][0]["digest"].__setitem__("gitCommit", "f" * 40),
    lambda s: s["predicate"]["auditor"].__setitem__("publicKey", "11" * 32),
    lambda s: s["predicate"]["report"]["findings"].append(
        {"title": "injected", "rationale": "x", "files": []}),
])
def test_verify_tamper_any_field_false(mutate):
    envelope, statement, _pem, _pub = _signed()
    tampered = copy.deepcopy(statement)
    mutate(tampered)
    # Re-encode the mutated Statement into the payload, but keep the ORIGINAL signature —
    # exactly what an attacker who doesn't hold the private key would have to do.
    envelope["payload"] = base64.standard_b64encode(
        json.dumps(tampered, separators=(",", ":"), sort_keys=True).encode()).decode()
    assert verify_attestation(envelope) is False


def test_verify_malformed_envelope_fails_closed():
    assert verify_attestation({}) is False
    assert verify_attestation({"payloadType": PAYLOAD_TYPE, "payload": "not-b64!!", "signatures": []}) is False
    assert verify_attestation({"payloadType": PAYLOAD_TYPE, "payload": "", "signatures": [
        {"keyid": "x", "sig": "not-b64!!"}]}) is False


# ---- parse_statement ---------------------------------------------------------

def test_parse_statement_sanitizes_free_text():
    report = {**REPORT, "summary": "clean\nreport\twith\rcontrol chars",
              "issues": [{"title": "bad\ntitle", "rationale": "bad\x00rationale", "files": []}]}
    envelope, *_ = _signed(report)
    statement = parse_statement(envelope)
    pred = statement["predicate"]
    assert "\n" not in pred["report"]["summary"] and "\t" not in pred["report"]["summary"]
    assert "\n" not in pred["report"]["findings"][0]["title"]
    assert "\x00" not in pred["report"]["findings"][0]["rationale"]


def test_parse_statement_oversized_payload_raises():
    envelope, *_ = _signed()
    huge = base64.standard_b64encode(b"x" * (3 * 1024 * 1024)).decode()
    envelope = {**envelope, "payload": huge}
    with pytest.raises(AttestationFormatError):
        parse_statement(envelope)


# ---- save / load -------------------------------------------------------------

def test_save_and_load_attestation_round_trip(tmp_path: Path):
    envelope, *_ = _signed()
    out = save_attestation(envelope, tmp_path / "a.intoto.json")
    loaded = load_attestation(out)
    assert loaded == envelope
    assert verify_attestation(loaded) is True


def test_load_attestation_rejects_oversized(tmp_path: Path):
    p = tmp_path / "huge.json"
    p.write_bytes(b"{" + b"x" * (3 * 1024 * 1024))
    with pytest.raises(AttestationFormatError):
        load_attestation(p)


def test_load_attestation_rejects_garbage(tmp_path: Path):
    p = tmp_path / "garbage.json"
    p.write_bytes(b"\x00\x01 not json at all")
    with pytest.raises(AttestationFormatError):
        load_attestation(p)


def test_load_attestation_rejects_non_dsse_shape(tmp_path: Path):
    p = tmp_path / "not-dsse.json"
    p.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    with pytest.raises(AttestationFormatError):
        load_attestation(p)


def test_load_attestation_rejects_malformed_signature_entry(tmp_path: Path):
    p = tmp_path / "bad-sig.json"
    p.write_text(json.dumps({"payloadType": PAYLOAD_TYPE, "payload": "x",
                              "signatures": [{"keyid": "x"}]}), encoding="utf-8")
    with pytest.raises(AttestationFormatError):
        load_attestation(p)


# ---- CRUCIAL: independent-verifier interop -----------------------------------

def test_interop_verifiable_by_independent_dsse_code_path():
    """Prove the signature is verifiable WITHOUT any scpe helper: re-derive the
    DSSE Pre-Authentication Encoding by hand straight from the spec (not by calling
    `attestation.pae`), and Ed25519-verify the raw signature via the `cryptography`
    library directly. If this passes, any standard DSSE/in-toto verifier (cosign, a
    Go/JS DSSE lib, etc.) would accept the same envelope — the format is not
    self-referential."""
    envelope, _statement_, _pem, pub_hex = _signed()

    payload_type = envelope["payloadType"]
    payload_bytes = base64.standard_b64decode(envelope["payload"])
    sig_bytes = base64.standard_b64decode(envelope["signatures"][0]["sig"])

    # DSSE PAE, hand-built per https://github.com/secure-systems-lab/dsse — independent
    # of scpe.attestation.pae.
    pt = payload_type.encode("utf-8")
    pae_by_hand = (b"DSSEv1 " + str(len(pt)).encode() + b" " + pt
                   + b" " + str(len(payload_bytes)).encode() + b" " + payload_bytes)

    # Sanity: our own pae() must agree with the hand-derivation (both implement the
    # same public spec) — but the verification below does NOT depend on that helper.
    assert pae_by_hand == pae(payload_type, payload_bytes)

    pubkey_obj = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    pubkey_obj.verify(sig_bytes, pae_by_hand)  # raises InvalidSignature if it fails

    # And a tampered payload must be REJECTED by that same independent path.
    from cryptography.exceptions import InvalidSignature
    with pytest.raises(InvalidSignature):
        pubkey_obj.verify(sig_bytes, pae_by_hand + b"tamper")


# ---- GitHub auditor identity (additive, on the statement's predicate) --------

def _ssh_key(tmp_path: Path, name: str = "ak") -> tuple[Path, str]:
    import subprocess
    kp = tmp_path / name
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(kp), "-N", "", "-q"],
                   check=True, capture_output=True)
    pub = " ".join((tmp_path / f"{name}.pub").read_text(encoding="utf-8").split()[:2])
    return kp, pub


def test_attach_and_verify_auditor_identity_roundtrip(tmp_path: Path):
    from scpe.attestation import attach_ssh_auditor, verify_auditor_identity
    kp, pub = _ssh_key(tmp_path)
    statement = _statement()
    attach_ssh_auditor(statement, login="ada", user_id="9", pubkey=pub, key_path=str(kp))
    assert statement["predicate"]["sig_method"] == "ssh-github"
    assert statement["predicate"]["github_login"] == "ada"
    got = verify_auditor_identity(statement, keys=[pub])
    assert got is not None and got.login == "ada"


def test_auditor_identity_tamper_fails_closed(tmp_path: Path):
    from scpe.attestation import attach_ssh_auditor, verify_auditor_identity
    kp, pub = _ssh_key(tmp_path)
    statement = _statement()
    attach_ssh_auditor(statement, login="ada", user_id="9", pubkey=pub, key_path=str(kp))
    statement["predicate"]["verdict"] = "clean"  # tamper the audited verdict after signing
    assert verify_auditor_identity(statement, keys=[pub]) is None


def test_auditor_identity_signer_key_absent_from_account_rejected(tmp_path: Path):
    from scpe.attestation import attach_ssh_auditor, verify_auditor_identity
    kp, pub = _ssh_key(tmp_path, "a")
    _, other = _ssh_key(tmp_path, "b")
    statement = _statement()
    attach_ssh_auditor(statement, login="ada", user_id="9", pubkey=pub, key_path=str(kp))
    # the account's published keys don't include the signer's key -> fail-closed
    assert verify_auditor_identity(statement, keys=[other]) is None


def test_legacy_statement_has_no_auditor_identity():
    from scpe.attestation import verify_auditor_identity
    assert verify_auditor_identity(_statement(), keys=["ssh-ed25519 AAAA"]) is None
