"""GitHub-bound identity: a signature proves the login only when it verifies against a key
GitHub lists for that login. Every negative case must fail CLOSED (return None), never leak
a trusted identity. Network is never touched — every test injects `keys=` explicitly."""
import json
import subprocess
from pathlib import Path

import pytest

from scpe import identity
from scpe.identity import Identity, IdentityError

DIGEST = b"scpe canonical digest v1: deadbeef"


def _make_key(tmp_path: Path, name: str = "k") -> tuple[Path, str]:
    kp = tmp_path / name
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(kp), "-N", "", "-q", "-C", f"{name}@test"],
        check=True, capture_output=True)
    pub = (tmp_path / f"{name}.pub").read_text(encoding="utf-8").strip()
    return kp, pub


def _bare(pub: str) -> str:
    return " ".join(pub.split()[:2])


def test_sign_verify_roundtrip(tmp_path: Path):
    kp, pub = _make_key(tmp_path)
    sig = identity.sign_digest(DIGEST, key_path=kp)
    ident = identity.verify_digest(DIGEST, sig, "octocat", keys=[pub])
    assert ident == Identity(login="octocat", pubkey=_bare(pub))


def test_tampered_digest_fails_closed(tmp_path: Path):
    kp, pub = _make_key(tmp_path)
    sig = identity.sign_digest(DIGEST, key_path=kp)
    assert identity.verify_digest(DIGEST + b"x", sig, "octocat", keys=[pub]) is None


def test_impersonation_with_another_key_rejected(tmp_path: Path):
    kp_a, _ = _make_key(tmp_path, "a")
    _, pub_b = _make_key(tmp_path, "b")
    sig = identity.sign_digest(DIGEST, key_path=kp_a)
    # Signed by A; if the claimed victim's .keys only holds B's key, it must not verify.
    assert identity.verify_digest(DIGEST, sig, "victim", keys=[pub_b]) is None


def test_signer_key_absent_from_keys_rejected(tmp_path: Path):
    kp, _ = _make_key(tmp_path)
    _, other = _make_key(tmp_path, "other")
    sig = identity.sign_digest(DIGEST, key_path=kp)
    assert identity.verify_digest(DIGEST, sig, "octocat", keys=[other]) is None


def test_expected_pubkey_pins_the_signing_key(tmp_path: Path):
    kp, pub = _make_key(tmp_path)
    _, other = _make_key(tmp_path, "other")
    sig = identity.sign_digest(DIGEST, key_path=kp)
    # Correct pin, among several of the account's keys.
    ok = identity.verify_digest(DIGEST, sig, "octocat", keys=[other, pub], expected_pubkey=pub)
    assert ok is not None and ok.pubkey == _bare(pub)
    # Pinning to a real-but-not-the-signer key must fail (can't re-attribute the signature).
    assert identity.verify_digest(
        DIGEST, sig, "octocat", keys=[other, pub], expected_pubkey=other) is None


def test_empty_keys_fail_closed(tmp_path: Path):
    kp, _ = _make_key(tmp_path)
    sig = identity.sign_digest(DIGEST, key_path=kp)
    assert identity.verify_digest(DIGEST, sig, "octocat", keys=[]) is None


def test_wrong_namespace_signature_rejected(tmp_path: Path):
    kp, pub = _make_key(tmp_path)
    # Sign under a different namespace directly with ssh-keygen; scpe-verify must reject.
    blob = tmp_path / "blob"
    blob.write_bytes(DIGEST)
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(kp), "-n", "other", str(blob)],
                   check=True, capture_output=True)
    sig = (tmp_path / "blob.sig").read_text(encoding="utf-8")
    assert identity.verify_digest(DIGEST, sig, "octocat", keys=[pub]) is None


def test_parse_keys_filters_comments_blanks_and_key_comment():
    body = "\n".join([
        "# a comment", "", "   ",
        "ssh-ed25519 AAAAbbbb user@host",
        "ssh-rsa AAAArsa",
        "not-a-key foo bar",
    ])
    assert identity.parse_keys(body) == ["ssh-ed25519 AAAAbbbb", "ssh-rsa AAAArsa"]


def test_parse_signing_api_extracts_keys():
    body = json.dumps([
        {"id": 1, "key": "ssh-ed25519 AAAAsign1 title-ignored", "title": "laptop"},
        {"id": 2, "key": "ssh-rsa AAAAsign2"},
        {"id": 3, "title": "no key field"},
    ])
    assert identity.parse_signing_api(body) == ["ssh-ed25519 AAAAsign1", "ssh-rsa AAAAsign2"]


def test_parse_signing_api_bad_json_is_empty():
    assert identity.parse_signing_api("not json") == []


def test_noreply_email_format():
    assert identity.noreply_email("octocat", 583231) == "583231+octocat@users.noreply.github.com"


def test_sign_missing_key_raises(tmp_path: Path):
    with pytest.raises(IdentityError):
        identity.sign_digest(DIGEST, key_path=tmp_path / "does-not-exist")
