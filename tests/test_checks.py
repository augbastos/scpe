"""checks.run_checks — signed evidence from REAL, recognized tools (repo's own test
suite, bandit, ruff/pyflakes), each executed inside sandbox.py's existing isolation.
The whole point is honesty: a check that never ran must never be reported as passed."""
from pathlib import Path

import pytest

from scpe import checks as checks_mod
from scpe.checks import run_checks, summarize_checks


def _by_tool(results: list[dict], tool: str) -> dict:
    return next(c for c in results if c["tool"] == tool)


# ---- the repo's own test suite ------------------------------------------------

def test_run_checks_tests_pass_on_a_real_passing_suite(tmp_path: Path):
    repo = tmp_path / "passing-repo"
    repo.mkdir()
    (repo / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (repo / "test_trivial.py").write_text("def test_ok():\n    assert 1 == 1\n", encoding="utf-8")

    results = run_checks(repo)
    tests = _by_tool(results, "tests")
    assert tests["ran"] is True
    assert tests["passed"] is True
    assert tests["summary"] == "pass"
    assert isinstance(tests["tail"], str)


def test_run_checks_tests_fail_on_a_real_failing_suite(tmp_path: Path):
    repo = tmp_path / "failing-repo"
    repo.mkdir()
    (repo / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (repo / "test_trivial.py").write_text("def test_bad():\n    assert 1 == 2\n", encoding="utf-8")

    results = run_checks(repo)
    tests = _by_tool(results, "tests")
    assert tests["ran"] is True
    assert tests["passed"] is False
    assert tests["summary"] == "fail"


def test_run_checks_tests_ran_false_when_no_runner_detected(tmp_path: Path):
    repo = tmp_path / "no-runner-repo"
    repo.mkdir()
    (repo / "README.md").write_text("hello\n", encoding="utf-8")

    results = run_checks(repo)
    tests = _by_tool(results, "tests")
    assert tests["ran"] is False
    assert tests["passed"] is None
    assert "no test runner" in tests["summary"]
    assert tests["tail"] == ""


# ---- missing tool binaries never crash, never fabricate a result --------------

def test_run_checks_missing_bandit_and_ruff_are_not_installed_not_a_crash(
        tmp_path: Path, monkeypatch):
    # Force the "not on PATH" branch deterministically, independent of whatever
    # happens to be installed in the environment running this test.
    monkeypatch.setattr(checks_mod.shutil, "which", lambda name: None)
    repo = tmp_path / "plain-repo"
    repo.mkdir()

    results = run_checks(repo)
    bandit = _by_tool(results, "bandit")
    ruff = _by_tool(results, "ruff")
    assert bandit == {"tool": "bandit", "ran": False, "passed": None,
                      "summary": "not installed", "tail": ""}
    assert ruff["ran"] is False
    assert ruff["passed"] is None
    assert ruff["summary"] == "not installed"


def test_run_checks_falls_back_to_pyflakes_when_ruff_missing(tmp_path: Path, monkeypatch):
    calls = []

    def which(name):
        return "/usr/bin/pyflakes" if name == "pyflakes" else None

    def fake_run(repo_dir, tool, cmd, timeout):
        calls.append((tool, cmd))
        return {"tool": tool, "ran": True, "passed": True, "summary": "pass", "tail": ""}

    monkeypatch.setattr(checks_mod.shutil, "which", which)
    monkeypatch.setattr(checks_mod, "_run", fake_run)
    repo = tmp_path / "pf-repo"
    repo.mkdir()

    results = run_checks(repo)
    ruff_slot = _by_tool(results, "pyflakes")
    assert ruff_slot["ran"] is True
    assert calls[-1][0] == "pyflakes"
    assert calls[-1][1][0] == "pyflakes"


def test_run_catches_filenotfound_from_sandbox_as_not_installed(tmp_path: Path, monkeypatch):
    """Even if a binary LOOKED available (shutil.which found something) but the
    sandboxed subprocess call itself raises FileNotFoundError, that must degrade to
    ran=false, never crash the whole checks run."""
    def boom(*args, **kwargs):
        raise FileNotFoundError("no such file or directory: 'bandit'")

    import scpe.sandbox as sandbox_mod
    monkeypatch.setattr(sandbox_mod, "run_in_sandbox", boom)
    result = checks_mod._run(tmp_path, "bandit", ["bandit", "-r", "."], 30)
    assert result == {"tool": "bandit", "ran": False, "passed": None,
                      "summary": "not installed", "tail": ""}


def test_run_checks_never_raises_for_a_missing_repo_dir(tmp_path: Path):
    """Defensive: a bogus repo_dir must not crash run_checks. detect_test_cmd degrades
    to None for a nonexistent dir (Path.is_file() is just False, never raises), so this
    exercises the "nothing recognizable" path end to end without needing bandit/ruff
    installed to reach the sandbox-copy failure path."""
    missing = tmp_path / "does-not-exist"
    results = run_checks(missing)
    assert isinstance(results, list)
    assert len(results) == 3
    assert all(c["ran"] is False for c in results)


# ---- summarize_checks ----------------------------------------------------------

def test_summarize_checks_one_line():
    results = [
        {"tool": "tests", "ran": True, "passed": True, "summary": "pass", "tail": ""},
        {"tool": "bandit", "ran": False, "passed": None, "summary": "not installed", "tail": ""},
    ]
    assert summarize_checks(results) == "tests=pass, bandit=not installed"


def test_summarize_checks_empty_list():
    assert summarize_checks([]) == ""
