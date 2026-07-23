import json
from pathlib import Path
import pytest
from scpe.backends import MockBackend
from scpe.contribute import ContributeError, contribute, parse_diff_reply, parse_json_reply
from scpe.envelope import unpack, verify_envelope_identity, verify_signature
from tests.conftest import FIX_DIFF, make_test_identity

ANALYZE_OK = json.dumps({"issues": [
    {"title": "add() subtracts", "rationale": "planted bug", "files": ["demo/calc.py"]},
]})

def _mock():
    return MockBackend({
        "ANALYZE": ANALYZE_OK,
        "FIXGEN": f"```diff\n{FIX_DIFF}```",
        "BRIEFING": "# Fix: add() subtracts\nOne piece.",
    })

def test_parse_helpers():
    assert parse_json_reply('```json\n{"a": 1}\n```') == {"a": 1}
    assert "--- a/demo/calc.py" in parse_diff_reply(f"```diff\n{FIX_DIFF}```")
    with pytest.raises(ContributeError):
        parse_diff_reply("no diff here")

def test_contribute_emits_signed_envelope_with_github_identity(fixture_repo: Path, tmp_path: Path):
    ident, pub = make_test_identity(tmp_path, login="alice", name="Alice Dev")
    out = contribute(str(fixture_repo), _mock(), identity=ident,
                     workdir=tmp_path / "w", out_path=tmp_path / "e.zip",
                     now_iso="2026-07-20T00:00:00+00:00")
    env = unpack(out)
    assert verify_signature(env)
    assert len(env.pieces) == 1 and env.pieces[0].diff.rstrip("\n") == FIX_DIFF.rstrip("\n")
    # Path A envelopes carry the same verifiable GitHub identity as path B.
    assert env.manifest.sender_name == "Alice Dev"
    assert env.manifest.github_login == "alice"
    assert env.manifest.sig_method == "ssh-github"
    assert verify_envelope_identity(env, keys=[pub]).login == "alice"
    assert env.provenance["backend"] == "mock"
    assert any(r["stage"] == "ANALYZE" for r in env.provenance["runs"])

def test_contribute_clean_repo_returns_none_no_envelope(fixture_repo: Path, tmp_path: Path):
    """Zero issues found -> contribute() returns None (nothing to contribute), does NOT
    raise, writes NO envelope, and never even resolves an identity."""
    clean = MockBackend({"ANALYZE": json.dumps({"issues": []})})
    out_path = tmp_path / "e3.zip"
    result = contribute(str(fixture_repo), clean, identity=None,
                        workdir=tmp_path / "w3", out_path=out_path)
    assert result is None
    assert not out_path.exists()


def test_contribute_drops_broken_fix_and_errors_when_none_left(fixture_repo: Path, tmp_path: Path):
    bad = MockBackend({
        "ANALYZE": ANALYZE_OK,
        "FIXGEN": "```diff\n--- a/demo/calc.py\n+++ b/demo/calc.py\n@@ -1,2 +1,2 @@\n def add(a, b):\n-    return a - b  # BUG\n+    return a * b\n```",
        "BRIEFING": "x",
    })  # applies but tests still fail → dropped → zero pieces → error
    with pytest.raises(ContributeError):
        contribute(str(fixture_repo), bad, identity=None,
                   workdir=tmp_path / "w2", out_path=tmp_path / "e2.zip")
