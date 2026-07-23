import json
from pathlib import Path

import pytest

from scpe.backends import MockBackend
from scpe.contribute import contribute
from scpe.envelope import EnvelopeFormatError, pack, unpack
from scpe.inspect import inspect_envelope
from scpe.signing import generate_private_key_pem
from tests.conftest import FIX_DIFF, make_test_identity

ANALYZE_OK = json.dumps({"issues": [
    {"title": "add() subtracts", "rationale": "planted bug", "files": ["demo/calc.py"]},
]})


def _mock() -> MockBackend:
    return MockBackend({
        "ANALYZE": ANALYZE_OK,
        "FIXGEN": f"```diff\n{FIX_DIFF}```",
        "BRIEFING": "# Fix: add() subtracts\nOne piece.",
    })


def _build_envelope(fixture_repo: Path, tmp_path: Path) -> Path:
    return contribute(
        str(fixture_repo), _mock(),
        identity=make_test_identity(tmp_path, login="alice", name="Alice Dev")[0],
        workdir=tmp_path / "w", out_path=tmp_path / "e.zip",
        now_iso="2026-07-20T00:00:00+00:00",
    )


def test_inspect_reports_pieces_and_valid_signature(fixture_repo: Path, tmp_path: Path):
    out = _build_envelope(fixture_repo, tmp_path)
    report = inspect_envelope(out)

    assert report["signature_valid"] is True
    # WS3: deterministic risk, recomputed from the diff (the FIX_DIFF is a clean arithmetic fix).
    assert report["risk"]["band"] == "LOW"
    assert report["risk"]["flags"] == []
    assert report["pieces"][0]["risk_band"] == "LOW"
    # Sender is the verifiable GitHub identity: display name + noreply email.
    assert report["sender"] == "Alice Dev <1+alice@users.noreply.github.com>"
    assert report["github_login"] == "alice"
    assert report["identity_method"] == "ssh-github"
    assert report["repo"] == str(fixture_repo)
    assert report["backend"] == "mock"
    assert len(report["base_sha"]) == 40
    assert report["sender_key"].endswith("…")

    assert len(report["pieces"]) == 1
    piece = report["pieces"][0]
    assert piece["files"] == ["demo/calc.py"]
    assert piece["added"] > 0 and piece["removed"] > 0


def test_inspect_tampered_signature_false(fixture_repo: Path, tmp_path: Path):
    out = _build_envelope(fixture_repo, tmp_path)
    env = unpack(out)
    # Mutate a piece's diff and re-pack WITHOUT re-signing: the signature is now stale.
    env.pieces[0].diff = env.pieces[0].diff.replace("a + b", "a * b")
    tampered = pack(env, tmp_path / "tampered.zip")

    report = inspect_envelope(tampered)
    assert report["signature_valid"] is False
    assert len(report["pieces"]) == 1  # still lists the pieces


def test_inspect_bad_zip_raises(tmp_path: Path):
    bad = tmp_path / "not-a-zip.zip"
    bad.write_bytes(b"\x00\x01 random garbage, definitely not a zip")
    with pytest.raises(EnvelopeFormatError):
        inspect_envelope(bad)
