"""CLI wiring for `scpe seal` — the verification seal (human pill+box) and the
machine-readable results.json the GitHub Action hands between its two jobs.

Same shape as test_cli_commands.py: build a real ssh-github envelope via the conftest
helpers (pull + pack, fully offline), then drive `main(["seal", ...])`. The identity
check against GitHub is injected offline by monkeypatching `cli.verify_envelope_identity`,
so no test ever touches the network."""
import json
from pathlib import Path

from scpe import cli
from scpe.cli import main
from scpe.identity import Identity
from tests.conftest import patch_cli_identity


def _make_envelope(fixture_repo: Path, tmp_path: Path, monkeypatch, capsys, *,
                   login: str = "alice-dev") -> tuple[Path, str]:
    """A signed (ssh-github) envelope that fixes the fixture repo's add() bug. Returns the
    envelope path + the bare pubkey (so a test can build the injected verified Identity).
    Drains pull/pack chatter so a later capsys read sees only the seal's own output."""
    _ident, pub = patch_cli_identity(monkeypatch, tmp_path, login=login)
    ws = tmp_path / "ws"
    assert main(["pull", str(fixture_repo), "--dest", str(ws)]) == 0
    (ws / "demo" / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    envp = tmp_path / "e.zip"
    assert main(["pack", "--workspace", str(ws), "--out", str(envp)]) == 0
    capsys.readouterr()  # drop pull/pack chatter
    return envp, pub


def _verified(login: str, pub: str):
    return lambda env, **kw: Identity(login=login, pubkey=pub)


# ---- human seal ------------------------------------------------------------

def test_seal_human_prints_pill_then_fenced_box(fixture_repo, tmp_path, monkeypatch, capsys):
    envp, pub = _make_envelope(fixture_repo, tmp_path, monkeypatch, capsys)
    monkeypatch.setattr(cli, "verify_envelope_identity", _verified("alice-dev", pub))
    assert main(["seal", str(envp), "--repo", str(fixture_repo)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("### scpe")
    assert "img.shields.io/badge/" in out          # the pill carries shields badges
    assert "```" in out                            # the ASCII box is fenced
    assert "@alice-dev" in out
    assert "UNVERIFIED" not in out                 # identity injected as verified


# ---- machine results.json --------------------------------------------------

def test_seal_json_shape_and_values(fixture_repo, tmp_path, monkeypatch, capsys):
    envp, pub = _make_envelope(fixture_repo, tmp_path, monkeypatch, capsys)
    monkeypatch.setattr(cli, "verify_envelope_identity", _verified("alice-dev", pub))
    assert main(["seal", str(envp), "--repo", str(fixture_repo), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data) == {"login", "verified", "band", "flags", "matched", "rules_checked",
                         "added", "removed", "files", "tests", "provenance", "hook"}
    assert data["login"] == "alice-dev"
    assert data["verified"] is True
    assert data["band"] in {"LOW", "MED", "HIGH"}
    # explainable, reproducible — not a magic score
    assert isinstance(data["matched"], list) and data["rules_checked"] >= 1
    assert data["added"] >= 1 and data["removed"] >= 1
    assert "demo/calc.py" in data["files"]
    assert data["provenance"] == "hand-authored"   # pack, no backend -> not AI-assisted
    # No --run-tests: honest "not run", never a fabricated pass.
    assert data["tests"] == {"ran": False, "ok": False, "summary": "not run"}


def test_seal_json_unverified_when_identity_check_fails(fixture_repo, tmp_path, monkeypatch, capsys):
    envp, _pub = _make_envelope(fixture_repo, tmp_path, monkeypatch, capsys)
    monkeypatch.setattr(cli, "verify_envelope_identity", lambda env, **kw: None)
    assert main(["seal", str(envp), "--repo", str(fixture_repo), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["verified"] is False
    # login still surfaced from the manifest's CLAIM even when the check fails.
    assert data["login"] == "alice-dev"


def test_seal_run_tests_passes_on_the_fixed_repo(fixture_repo, tmp_path, monkeypatch, capsys):
    envp, pub = _make_envelope(fixture_repo, tmp_path, monkeypatch, capsys)
    monkeypatch.setattr(cli, "verify_envelope_identity", _verified("alice-dev", pub))
    assert main(["seal", str(envp), "--repo", str(fixture_repo), "--json", "--run-tests"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["tests"]["ran"] is True
    assert data["tests"]["ok"] is True


def test_seal_needs_envelope_or_from_results(capsys):
    assert main(["seal"]) == 1
    assert "from-results" in capsys.readouterr().err


# ---- --from-results (the trusted job's render / re-check) -------------------

def _results_file(tmp_path: Path, **over) -> Path:
    results = {"login": "bob", "verified": True, "band": "LOW", "flags": [],
               "added": 3, "removed": 1, "files": ["a.py"],
               "tests": {"ran": True, "ok": True, "summary": "1 passed"},
               "provenance": "hand-authored", "hook": ""}
    results.update(over)
    rf = tmp_path / "results.json"
    rf.write_text(json.dumps(results), encoding="utf-8")
    return rf


def test_seal_from_results_render_comment(tmp_path, capsys):
    rf = _results_file(tmp_path)
    assert main(["seal", "--from-results", str(rf), "--render-comment"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("### scpe")
    assert "```" in out
    assert "@bob" in out


def test_seal_ai_recheck_is_noop_without_backend(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SCPE_BACKEND", raising=False)
    rf = _results_file(tmp_path)
    assert main(["seal", "--from-results", str(rf), "--ai-recheck"]) == 0
    # No owner model configured -> nothing appended, nothing printed (honest, not a fake pass).
    assert capsys.readouterr().out.strip() == ""


def test_seal_ai_recheck_appends_verdict_when_backend_configured(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SCPE_BACKEND", "openai")
    monkeypatch.setenv("SCPE_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("SCPE_MODEL", "llama3")
    rf = _results_file(tmp_path)
    assert main(["seal", "--from-results", str(rf), "--ai-recheck"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "ai_recheck" in data
    assert data["ai_recheck"]["backend"].startswith("openai-compat")
