"""CLI wiring for `scpe submit` — open a native GitHub PR carrying the signed
envelope at .scpe/contribution.cc.zip, authored with the contributor's GitHub
no-reply email.

Every gh/git call is monkeypatched: no network, no real `gh`, no real clone. The envelope
itself is built for real (offline) via the conftest helpers so the manifest carries a
genuine ssh-github identity to derive the author from."""
import subprocess
import types
from pathlib import Path

from scpe.cli import main
from scpe.identity import noreply_email
from tests.conftest import patch_cli_identity


def _make_envelope(fixture_repo: Path, tmp_path: Path, monkeypatch, *,
                   login: str = "alice-dev", uid: str = "42") -> Path:
    patch_cli_identity(monkeypatch, tmp_path, login=login, uid=uid)
    ws = tmp_path / "ws"
    assert main(["pull", str(fixture_repo), "--dest", str(ws)]) == 0
    (ws / "demo" / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    envp = tmp_path / "e.zip"
    assert main(["pack", "--workspace", str(ws), "--out", str(envp)]) == 0
    return envp


def _fake_gh_git(calls: list):
    """A subprocess.run stand-in that records argv and never shells out. `gh pr create`
    returns a PR URL on stdout, like the real CLI."""
    def run(cmd, *a, **k):
        calls.append(list(cmd))
        stdout = ""
        if cmd[:3] == ["gh", "pr", "create"]:
            stdout = "https://github.com/owner/name/pull/7\n"
        return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")
    return run


def test_submit_opens_pr_with_envelope_and_contributor_author(
        fixture_repo, tmp_path, monkeypatch, capsys):
    envp = _make_envelope(fixture_repo, tmp_path, monkeypatch)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/gh")
    calls: list = []
    monkeypatch.setattr(subprocess, "run", _fake_gh_git(calls))

    assert main(["submit", str(envp), "--repo", "owner/name"]) == 0
    out = capsys.readouterr().out
    assert "pull/7" in out

    # gh pr create was invoked against the target repo
    pr = next(c for c in calls if c[:3] == ["gh", "pr", "create"])
    assert "owner/name" in pr

    # the commit is authored with the contributor's GitHub no-reply email
    commit = next(c for c in calls if c[:2] == ["git", "-C"] and "commit" in c)
    author = commit[commit.index("--author") + 1]
    assert noreply_email("alice-dev", "42") in author

    # the contribution's diff is applied onto the branch (a native, reviewable PR)
    assert any(c[:2] == ["git", "-C"] and "apply" in c and "--index" in c for c in calls)
    # the envelope is NOT committed to the tree — it rides in the PR body so the merge keeps
    # the owner's repo clean; the body carries the base64 marker the seal Action extracts
    assert not any("contribution.cc.zip" in str(a) for c in calls for a in c)
    body = pr[pr.index("--body") + 1]
    assert "scpe-envelope:v1" in body


def test_submit_derives_repo_from_envelope_when_flag_omitted(
        fixture_repo, tmp_path, monkeypatch, capsys):
    envp = _make_envelope(fixture_repo, tmp_path, monkeypatch)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/gh")
    calls: list = []
    monkeypatch.setattr(subprocess, "run", _fake_gh_git(calls))
    # The fixture repo's remote is a local path (no owner/name slug), so submit cannot
    # derive a target and must ask for --repo rather than guess.
    assert main(["submit", str(envp)]) == 1
    assert "--repo owner/name" in capsys.readouterr().err


def test_submit_guarded_when_gh_missing(fixture_repo, tmp_path, monkeypatch, capsys):
    envp = _make_envelope(fixture_repo, tmp_path, monkeypatch)
    monkeypatch.setattr("shutil.which", lambda name: None)
    # subprocess must never be reached when gh is absent.
    def boom(*a, **k):
        raise AssertionError("subprocess.run should not run when gh is missing")
    monkeypatch.setattr(subprocess, "run", boom)
    assert main(["submit", str(envp), "--repo", "owner/name"]) == 1
    assert "gh" in capsys.readouterr().err.lower()


def test_submit_pr_create_failure_reported(fixture_repo, tmp_path, monkeypatch, capsys):
    envp = _make_envelope(fixture_repo, tmp_path, monkeypatch)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/gh")

    def run(cmd, *a, **k):
        if cmd[:3] == ["gh", "pr", "create"]:
            return types.SimpleNamespace(returncode=1, stdout="", stderr="no commits between branches")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(subprocess, "run", run)
    assert main(["submit", str(envp), "--repo", "owner/name"]) == 1
    assert "gh pr create failed" in capsys.readouterr().err
