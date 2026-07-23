"""`producer.submit` opens a native PR carrying the SPEC §9 attestation in the body and
the code diff applied to the branch — with every gh/git call mocked (no network).

Mirrors tests/test_cli_submit.py's approach: build a real, signed envelope offline, then
stub subprocess.run + shutil.which so nothing shells out.
"""
import importlib.util
import io
import subprocess
import sys
import types
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PRODUCER_PATH = ROOT / "reference" / "producer.py"
_spec = importlib.util.spec_from_file_location("scpe_producer_ref_submit", PRODUCER_PATH)
producer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(producer)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args],
                          check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def envelope(tmp_path: Path) -> Path:
    key = tmp_path / "k"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(key), "-N", "", "-q"],
                   check=True, capture_output=True)
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "fix")
    head = _git(repo, "rev-parse", "HEAD")
    env = tmp_path / "envelope.zip"
    producer.pack(repo=repo, base=base, head=head, out=env,
                  login="alice-dev", key=str(key), repo_name="owner/name",
                  created_at="2026-07-21T18:00:00Z")
    return env


def _fake_gh_git(calls: list):
    def run(cmd, *a, **k):
        calls.append(list(cmd))
        stdout = b""
        if cmd[:3] == ["gh", "pr", "create"]:
            stdout = b"https://github.com/owner/name/pull/7\n"
        return types.SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")
    return run


def test_submit_embeds_attestation_and_applies_diff(envelope, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/gh")
    calls: list = []
    monkeypatch.setattr(subprocess, "run", _fake_gh_git(calls))

    url = producer.submit(envelope=envelope, repo="owner/name")
    assert url == "https://github.com/owner/name/pull/7"

    # the diff is applied onto the branch (a native, reviewable PR)
    assert any(c[:2] == ["git", "-C"] and "apply" in c and "--index" in c for c in calls)

    # gh pr create targets the repo; the body carries exactly one attestation block whose
    # base64 decodes to a manifest+sig zip WITHOUT diff.patch
    pr = next(c for c in calls if c[:3] == ["gh", "pr", "create"])
    assert "owner/name" in pr
    body = pr[pr.index("--body") + 1]
    m = producer.ATTESTATION_RE.search(body)
    assert m, "no SCPE-ATTESTATION-v1 block in the PR body"
    import base64
    inner = base64.b64decode(m.group(1).strip())
    with zipfile.ZipFile(io.BytesIO(inner)) as zf:
        assert set(zf.namelist()) == {"manifest.json", "manifest.sig"}


def test_submit_guarded_when_gh_missing(envelope, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)

    def boom(*a, **k):
        raise AssertionError("subprocess.run must not run when gh is missing")
    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(producer.ProducerError):
        producer.submit(envelope=envelope, repo="owner/name")


def test_submit_pr_create_failure_raises(envelope, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/gh")

    def run(cmd, *a, **k):
        if cmd[:3] == ["gh", "pr", "create"]:
            return types.SimpleNamespace(returncode=1, stdout=b"",
                                         stderr=b"no commits between branches")
        return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(producer.ProducerError, match="gh pr create failed"):
        producer.submit(envelope=envelope, repo="owner/name")
