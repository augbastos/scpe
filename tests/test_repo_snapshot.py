from pathlib import Path
import pytest
from scpe.repo_snapshot import RepoError, clone_at, repo_digest

def test_clone_local_repo_and_head_sha(fixture_repo: Path, tmp_path: Path):
    snap = clone_at(str(fixture_repo), tmp_path / "clone")
    assert (snap.path / "demo" / "calc.py").exists()
    assert len(snap.head_sha) == 40

def test_clone_bad_source_raises(tmp_path: Path):
    with pytest.raises(RepoError):
        clone_at(str(tmp_path / "nope"), tmp_path / "c2")

def test_clone_passes_end_of_options_separator(monkeypatch, tmp_path: Path):
    """A '--' must precede the source so a dash-leading source is a path, not a git option."""
    import scpe.repo_snapshot as rs
    calls: list[list[str]] = []

    class _Proc:
        returncode = 0
        stdout = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"
        stderr = ""

    def fake_run(args, cwd=None, capture_output=False, text=False):
        calls.append(args)
        return _Proc()

    monkeypatch.setattr(rs.subprocess, "run", fake_run)
    clone_at("-evil-source", tmp_path / "c")
    clone_args = calls[0]
    assert "--" in clone_args
    assert clone_args.index("--") < clone_args.index("-evil-source")

def test_clone_rejects_non_hex_sha(fixture_repo: Path, tmp_path: Path):
    with pytest.raises(RepoError):
        clone_at(str(fixture_repo), tmp_path / "c3", sha="--upload-pack=touch pwned")

def test_clone_pins_protocol_transport(monkeypatch, tmp_path: Path):
    """FIX 4: clone_at must pin the transport so a manifest-derived `source` can never be an
    `ext::` command runner or an unrestricted `file://` URL — both are disabled/restricted at
    the git-config level, in addition to the existing `--` end-of-options guard."""
    import scpe.repo_snapshot as rs
    calls: list[list[str]] = []

    class _Proc:
        returncode = 0
        stdout = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"
        stderr = ""

    def fake_run(args, cwd=None, capture_output=False, text=False):
        calls.append(args)
        return _Proc()

    monkeypatch.setattr(rs.subprocess, "run", fake_run)
    clone_at("ext::sh -c touch pwned", tmp_path / "c")
    clone_args = calls[0]
    assert "-c" in clone_args
    assert "protocol.ext.allow=never" in clone_args
    assert "protocol.file.allow=user" in clone_args
    # the pins must precede `--` / the source, not trail after it as a no-op
    assert clone_args.index("protocol.ext.allow=never") < clone_args.index("--")


def test_digest_contains_tree_and_code_scrubbed(fixture_repo: Path):
    (fixture_repo / "demo" / "cfg.py").write_text('api_key = "sk-secretsecretsecret1234"', encoding="utf-8")
    d = repo_digest(fixture_repo)
    assert "demo/calc.py" in d and "return a - b" in d
    assert "sk-secret" not in d
