"""The GitHub identity layer on the Envelope: attach_ssh_identity signs the identity
digest, the Ed25519 seal covers the ssh_sig, and any tamper breaks BOTH. Network is never
touched — verify_envelope_identity is given the key list explicitly."""
import subprocess
from pathlib import Path

from scpe.envelope import (
    PROTOCOL_VERSION, Envelope, Manifest, Piece,
    attach_ssh_identity, identity_digest, pack, sign_envelope, unpack,
    verify_envelope_identity, verify_signature,
)
from scpe.signing import generate_private_key_pem

FIX_DIFF = (
    "--- a/demo/calc.py\n+++ b/demo/calc.py\n@@ -1,2 +1,2 @@\n"
    " def add(a, b):\n-    return a - b\n+    return a + b\n")


def _make_key(tmp_path: Path, name: str = "k") -> tuple[Path, str]:
    kp = tmp_path / name
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(kp), "-N", "", "-q"],
                   check=True, capture_output=True)
    return kp, (tmp_path / f"{name}.pub").read_text(encoding="utf-8").strip()


def _envelope() -> Envelope:
    return Envelope(
        manifest=Manifest(PROTOCOL_VERSION, "https://github.com/o/r", "0" * 40, "",
                          "Augusto Bastos", "a@b.c", "2026-07-20T00:00:00+00:00"),
        briefing_md="# fix", pieces=[Piece("p1", "fix add", "bug", FIX_DIFF, ["demo/calc.py"])],
        provenance={"backend": "none"})


def _signed(tmp_path: Path, *, login="augbastos", uid="67170506"):
    kp, pub = _make_key(tmp_path)
    env = _envelope()
    attach_ssh_identity(env, login=login, user_id=uid, pubkey=pub, key_path=kp)
    sign_envelope(env, generate_private_key_pem())  # Ed25519 seal AFTER identity
    return env, pub


def test_manifest_identity_fields_roundtrip(tmp_path: Path):
    env, pub = _signed(tmp_path)
    out = pack(env, tmp_path / "e.zip")
    back = unpack(out)
    assert back.manifest.sig_method == "ssh-github"
    assert back.manifest.github_login == "augbastos"
    assert back.manifest.github_id == "67170506"
    assert back.manifest.ssh_pubkey == " ".join(pub.split()[:2])
    assert "BEGIN SSH SIGNATURE" in back.manifest.ssh_sig  # armored sig survived intact


def test_identity_and_ed25519_both_verify(tmp_path: Path):
    env, pub = _signed(tmp_path)
    back = unpack(pack(env, tmp_path / "e.zip"))
    assert verify_signature(back) is True  # Ed25519 seal covers the ssh_sig
    ident = verify_envelope_identity(back, keys=[pub])
    assert ident is not None and ident.login == "augbastos"


def test_tamper_breaks_both_signatures(tmp_path: Path):
    env, pub = _signed(tmp_path)
    back = unpack(pack(env, tmp_path / "e.zip"))
    back.pieces[0].diff = back.pieces[0].diff.replace("a + b", "a * b")  # tamper the fix
    assert verify_signature(back) is False
    assert verify_envelope_identity(back, keys=[pub]) is None


def test_identity_digest_excludes_both_signatures(tmp_path: Path):
    env, _ = _signed(tmp_path)
    d = identity_digest(env)
    assert env.manifest.ssh_sig.encode() not in d
    assert env.signature.encode() not in d
    assert b"ssh_sig" not in d and b'"signature"' not in d


def test_legacy_envelope_has_no_identity(tmp_path: Path):
    env = _envelope()
    sign_envelope(env, generate_private_key_pem())  # Ed25519 only, no identity
    back = unpack(pack(env, tmp_path / "e.zip"))
    assert back.manifest.sig_method == ""
    assert verify_envelope_identity(back, keys=["ssh-ed25519 AAAAwhatever"]) is None
