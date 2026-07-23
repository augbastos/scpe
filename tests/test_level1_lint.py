"""SCPE LEVEL 1 — the Action-facing wrapper (reference/level1_lint.py).

Executes the actual script the composite action invokes (as a subprocess, with the
same env vars action.yml sets), not just its importable pieces — proving the
untrusted job's real code path produces the results.json the trusted job reads.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LINT_PATH = ROOT / "reference" / "level1_lint.py"
PY = sys.executable


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args],
                          check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo_with_commits(tmp_path: Path):
    """A tiny repo with a base commit and two commits ahead of it — one plain, one
    carrying an Assisted-by trailer — so BASE_SHA..HEAD_SHA has real git history."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "fixture@example.com")
    _git(repo, "config", "user.name", "Fixture")
    (repo / "a.txt").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "base commit")
    base_sha = _git(repo, "rev-parse", "HEAD")

    (repo / "a.txt").write_text("base\nplain change\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "plain commit, no trailer")

    (repo / "a.txt").write_text("base\nplain change\nai change\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "ai-assisted commit\n\nAssisted-by: claude-opus")
    head_sha = _git(repo, "rev-parse", "HEAD")

    return repo, base_sha, head_sha


def _run_lint(cwd: Path, env: dict) -> dict:
    proc = subprocess.run([PY, str(LINT_PATH)], cwd=str(cwd), env=env,
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, f"level1_lint.py must always exit 0: stderr={proc.stderr}"
    results = json.loads((cwd / "results.json").read_text(encoding="utf-8"))
    return results


def _base_env(**overrides) -> dict:
    import os
    env = dict(os.environ)
    env.update({"PR_BODY": "", "BASE_SHA": "", "HEAD_SHA": "", "REPO_DIR": ".",
                "REQUIRE": "false"})
    env.update(overrides)
    return env


def test_lint_finds_trailer_in_commit_range(repo_with_commits, tmp_path):
    repo, base, head = repo_with_commits
    env = _base_env(BASE_SHA=base, HEAD_SHA=head, REPO_DIR=str(repo))
    results = _run_lint(tmp_path, env)
    assert results["level"] == "1"
    assert results["disclosure"] == {"present": True, "form": "trailer", "value": "claude-opus"}
    assert results["status"] == "verified"
    assert results["gate_pass"] is True


def test_lint_reports_absent_when_no_signal(tmp_path):
    env = _base_env()
    results = _run_lint(tmp_path, env)
    assert results["disclosure"]["present"] is False
    assert results["status"] == "unattested"


def test_require_false_never_fails_gate_even_when_absent(tmp_path):
    results = _run_lint(tmp_path, _base_env(REQUIRE="false"))
    assert results["gate_pass"] is True
    assert results["require"] is False


def test_require_true_fails_gate_when_absent_with_exact_message(tmp_path):
    results = _run_lint(tmp_path, _base_env(REQUIRE="true"))
    assert results["gate_pass"] is False
    assert results["fail_message"] == (
        "⚠️ Missing AI-use disclosure — this repository requires "
        "contributors to declare AI use"
    )


def test_require_true_passes_gate_when_disclosure_present_in_pr_body(tmp_path):
    env = _base_env(REQUIRE="true", PR_BODY="Assisted-by: gpt-5")
    results = _run_lint(tmp_path, env)
    assert results["gate_pass"] is True
    assert results["status"] == "verified"


def test_pr_body_disclosure_used_when_no_commit_range_given(tmp_path):
    env = _base_env(PR_BODY="- [x] I did not use generative AI")
    results = _run_lint(tmp_path, env)
    assert results["disclosure"] == {"present": True, "form": "checkbox", "value": "none"}


def test_bad_repo_dir_degrades_gracefully_not_crash(tmp_path):
    # A REPO_DIR that isn't a git repo at all must not crash the untrusted job —
    # git log fails, commit_messages degrades to [], PR body is still checked.
    env = _base_env(BASE_SHA="deadbeef", HEAD_SHA="cafebabe",
                    REPO_DIR=str(tmp_path / "not-a-repo"), PR_BODY="Assisted-by: still-found")
    (tmp_path / "not-a-repo").mkdir()
    results = _run_lint(tmp_path, env)
    assert results["disclosure"]["present"] is True
    assert results["disclosure"]["value"] == "still-found"


def test_comment_field_present_for_trusted_job_to_post_verbatim(tmp_path):
    results = _run_lint(tmp_path, _base_env(PR_BODY="Assisted-by: cursor"))
    assert "AI-use disclosure found" in results["comment"]
    assert "cursor" in results["comment"]


def test_informational_comment_when_absent(tmp_path):
    results = _run_lint(tmp_path, _base_env())
    assert "No AI-use disclosure found" in results["comment"]
