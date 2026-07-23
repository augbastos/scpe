import json, zipfile
from pathlib import Path
import pytest
from scpe.envelope import (
    PROTOCOL_VERSION, Envelope, Manifest, Piece, EnvelopeFormatError,
    _MAX_ENVELOPE_JSON, canonical_payload, from_dict, pack, sanitize_text, sign_envelope,
    to_dict, unpack, verify_signature,
)
from scpe.signing import generate_private_key_pem

def _env() -> Envelope:
    return Envelope(
        manifest=Manifest(PROTOCOL_VERSION, "https://example.com/r.git", "abc123",
                          "", "Alice Dev", "alice@example.com", "2026-07-20T00:00:00+00:00"),
        briefing_md="# One fix",
        pieces=[Piece("p1", "Fix add()", "off-by-sign bug", "--- a/x\n+++ b/x\n", ["x"])],
        provenance={"backend": "mock", "runs": []},
    )

def test_sign_then_verify():
    env = sign_envelope(_env(), generate_private_key_pem())
    assert env.signature and env.manifest.sender_public_key
    assert verify_signature(env) is True

def test_tamper_any_field_breaks_signature():
    env = sign_envelope(_env(), generate_private_key_pem())
    env.pieces[0].diff += " "          # one byte
    assert verify_signature(env) is False

def test_pack_unpack_round_trip(tmp_path: Path):
    env = sign_envelope(_env(), generate_private_key_pem())
    p = pack(env, tmp_path / "e.zip")
    out = unpack(p)
    assert to_dict(out) == to_dict(env)
    assert verify_signature(out) is True

def test_unpack_rejects_wrong_protocol(tmp_path: Path):
    env = sign_envelope(_env(), generate_private_key_pem())
    d = to_dict(env); d["manifest"]["protocol_version"] = "99"
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("envelope.json", json.dumps(d))
    with pytest.raises(EnvelopeFormatError):
        unpack(bad)

def test_unpack_rejects_zip_bomb(tmp_path: Path):
    """A member that declares a huge decompressed size is refused before it can OOM us."""
    bad = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bad, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("envelope.json", "a" * (_MAX_ENVELOPE_JSON + 1))  # compresses tiny, inflates huge
    with pytest.raises(EnvelopeFormatError):
        unpack(bad)

def test_unpack_rejects_extra_members(tmp_path: Path):
    """Only the single expected member may be present — no stowaway files."""
    env = sign_envelope(_env(), generate_private_key_pem())
    bad = tmp_path / "extra.zip"
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("envelope.json", json.dumps(to_dict(env)))
        z.writestr("evil.txt", "surprise")
    with pytest.raises(EnvelopeFormatError):
        unpack(bad)

def test_canonical_payload_is_stable_and_sig_free():
    env = _env()
    a = canonical_payload(env); b = canonical_payload(env)
    assert a == b and b"signature" not in a or json.loads(a).get("signature") is None


def _raw_pack(d: dict, out: Path) -> Path:
    """Write a hand-crafted (not-necessarily-clean) envelope dict straight to a zip,
    bypassing the Envelope dataclass entirely — simulates an attacker who controls the
    raw JSON bytes directly (not just fields via our own Piece/Manifest constructors)."""
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("envelope.json", json.dumps(d))
    return out


def test_unpack_sanitizes_trailer_injection_in_title_and_sender_fields(tmp_path: Path):
    """FIX 1 (trailer injection): a crafted title/sender_name containing an embedded
    newline + fake `Signed-off-by:`/`Co-authored-by:` trailer must never survive unpack()
    as raw control characters — every consumer downstream (cli's commit message, inspect)
    only ever sees the collapsed, single-line value."""
    dirty_title = "fix\n\nSigned-off-by: Linus Torvalds <t@k.org>\nCo-authored-by: victim <v@e.com>"
    dirty_name = "Mallory\n\nSigned-off-by: Linus Torvalds <t@k.org>"
    env = Envelope(
        manifest=Manifest(PROTOCOL_VERSION, "local", "a" * 40, "", dirty_name,
                          "mallory\r\nevil@example.com", "2026-07-20T00:00:00+00:00"),
        briefing_md="# x", provenance={"backend": "mock", "runs": []},
        pieces=[Piece("p1", dirty_title, "r\ndirty\ttoo", "--- a/x\n+++ b/x\n", ["x"])])
    # Sign it exactly as a real (malicious) contributor would: sign_envelope operates on
    # whatever is in the dataclass right now (dirty), producing a validly-signed envelope
    # over the DIRTY payload — this is the actual proven attack, not a hypothetical.
    signed = sign_envelope(env, generate_private_key_pem())
    p = pack(signed, tmp_path / "e.zip")

    out = unpack(p)
    for bad in ("\n", "\r", "\t"):
        assert bad not in out.pieces[0].title
        assert bad not in out.pieces[0].rationale
        assert bad not in out.manifest.sender_name
        assert bad not in out.manifest.sender_email
    assert "Signed-off-by" in out.pieces[0].title      # content survives, just de-fanged
    assert "\n" not in out.pieces[0].title

    # Because the sanitized in-memory value no longer matches what was actually signed
    # (the DIRTY bytes), the signature no longer verifies — a crafted envelope is REJECTED
    # outright, not merely "cleaned and accepted". This is stronger than trailer-stripping
    # alone: it also proves the sanitized env can never silently pass as authentic.
    assert verify_signature(out) is False


def test_sanitize_text_collapses_control_chars():
    assert sanitize_text("a\nb\r\nc\td\x00e") == "a b c d e"
    assert sanitize_text("  clean  ") == "clean"


def test_apply_end_to_end_never_forges_a_trailer(fixture_repo: Path, tmp_path: Path, monkeypatch):
    """Integration proof for FIX 1: running the full `verify --apply` pipeline on an
    envelope whose piece.title / sender_name carries an embedded newline + forged
    `Signed-off-by:`/`Co-authored-by:` trailer must NEVER result in a commit that contains
    those forged trailers — whether because the envelope is rejected outright (signature no
    longer verifies post-sanitization) or, were it ever applied, because the value is clean."""
    import json as _json, subprocess as _sp
    from scpe import backends
    from scpe.cli import main
    monkeypatch.setattr(backends, "make_backend", lambda kind=None: backends.MockBackend(
        {"SAFETY": _json.dumps({"safe": True, "reasons": []}),
         "FIT": _json.dumps({"fits": True, "notes": []})}))
    from tests.conftest import FIX_DIFF
    head = _sp.run(["git", "-C", str(fixture_repo), "rev-parse", "HEAD"],
                   capture_output=True, text=True).stdout.strip()
    dirty_title = "fix add()\n\nSigned-off-by: Linus Torvalds <t@k.org>"
    dirty_name = "Mallory\n\nCo-authored-by: victim <v@e.com>"
    env = Envelope(
        manifest=Manifest(PROTOCOL_VERSION, "local", head, "", dirty_name, "mallory@example.com",
                          "2026-07-20T00:00:00+00:00"),
        briefing_md="# x", provenance={"backend": "mock", "runs": []},
        pieces=[Piece("p1", dirty_title, "r", FIX_DIFF, ["demo/calc.py"])])
    envp = str(tmp_path / "evil.zip")
    pack(sign_envelope(env, generate_private_key_pem()), envp)

    before = _sp.run(["git", "-C", str(fixture_repo), "rev-parse", "HEAD"],
                     capture_output=True, text=True).stdout.strip()
    main(["verify", envp, "--repo", str(fixture_repo), "--apply", "--disclosure", "signoff"])
    log = _sp.run(["git", "-C", str(fixture_repo), "log", "--all"],
                  capture_output=True, text=True).stdout
    assert "Signed-off-by: Linus Torvalds" not in log
    assert "Co-authored-by: victim" not in log
    # Whatever happened (rejected outright, or applied with the sanitized/clean value), no
    # NEW commit carrying the forged trailer text exists — HEAD is either unchanged or points
    # at a clean commit.
    after = _sp.run(["git", "-C", str(fixture_repo), "rev-parse", "HEAD"],
                    capture_output=True, text=True).stdout.strip()
    assert before == after or "Signed-off-by: Linus Torvalds" not in log


def test_unpack_rejects_duplicate_piece_ids(tmp_path: Path):
    """FIX 2a (duplicate piece-id bypass): a malicious piece sharing an id with a benign
    one must never be allowed to ride the benign piece's verdict. unpack() refuses the
    envelope outright, before any handshake logic ever sees it."""
    env = sign_envelope(Envelope(
        manifest=Manifest(PROTOCOL_VERSION, "local", "a" * 40, "", "Alice", "a@b.c",
                          "2026-07-20T00:00:00+00:00"),
        briefing_md="# dup", provenance={"backend": "mock", "runs": []},
        pieces=[Piece("p1", "benign", "ok", "--- a/x\n+++ b/x\n", ["x"]),
                Piece("p1", "malicious, same id", "evil", "--- a/y\n+++ b/y\n", ["y"])],
    ), generate_private_key_pem())
    p = pack(env, tmp_path / "dup.zip")
    with pytest.raises(EnvelopeFormatError, match="duplicate"):
        unpack(p)
