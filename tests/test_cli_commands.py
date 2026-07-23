"""CLI wiring for the full command set: analyze, pull, pack, inspect, init.

Same shape as test_cli.py — monkeypatch `backends.make_backend` to a canned MockBackend
so the CLI never touches a network or a real model. Every command is driven through
`main([...])` and asserted on its exit code + the artifact it produced."""
import json
import subprocess
from pathlib import Path

from scpe import cli
from scpe.cli import main
from scpe.envelope import pack, unpack, verify_signature
from scpe.identity import LocalIdentity
from scpe.optin import BADGE_MARK
from tests.conftest import FIX_DIFF


def _patch_cli_identity(monkeypatch, tmp_path: Path, *, login: str = "bob",
                        name: str = "Bob Hand") -> str:
    """Replace the CLI's GitHub-identity resolution (gh CLI + network) with a throwaway
    SSH key so `scpe pack` runs fully offline. Returns the bare public key."""
    kp = tmp_path / "sk"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(kp), "-N", "", "-q"],
                   check=True, capture_output=True)
    pub = " ".join((tmp_path / "sk.pub").read_text(encoding="utf-8").split()[:2])
    ident = LocalIdentity(login=login, user_id="7", name=name, pubkey=pub, key_path=str(kp))
    monkeypatch.setattr(cli, "resolve_local_identity", lambda **kw: ident)
    return pub


def _canned_analyze(monkeypatch):
    """Two ANALYZE issues + a letter GRADE — drives `scpe analyze`."""
    from scpe import backends
    canned = {
        "ANALYZE": json.dumps({"issues": [
            {"title": "add() subtracts", "rationale": "bug", "files": ["demo/calc.py"]},
            {"title": "no docstring", "rationale": "clarity", "files": ["demo/calc.py"]},
        ]}),
        "GRADE": json.dumps({"grade": "B", "summary": "solid, one real bug"}),
    }
    monkeypatch.setattr(backends, "make_backend", lambda kind=None: backends.MockBackend(canned))


def _canned_contribute(monkeypatch):
    """The MVP contributor pipeline responses — used to mint an envelope to inspect."""
    from scpe import backends
    canned = {
        "ANALYZE": json.dumps({"issues": [{"title": "add() subtracts",
                                           "rationale": "bug", "files": ["demo/calc.py"]}]}),
        "FIXGEN": f"```diff\n{FIX_DIFF}```",
        "BRIEFING": "# fix add",
    }
    monkeypatch.setattr(backends, "make_backend", lambda kind=None: backends.MockBackend(canned))


# ---- analyze ---------------------------------------------------------------

def test_cli_analyze_prints_grade(fixture_repo: Path, monkeypatch, capsys):
    _canned_analyze(monkeypatch)
    assert main(["analyze", str(fixture_repo)]) == 0
    out = capsys.readouterr().out
    assert "grade" in out.lower()
    assert "B" in out
    assert "add() subtracts" in out


def test_cli_analyze_json(fixture_repo: Path, monkeypatch, capsys):
    _canned_analyze(monkeypatch)
    assert main(["analyze", str(fixture_repo), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["grade"] == "B"
    assert len(data["issues"]) == 2
    assert len(data["base_sha"]) == 40


# ---- contribute (clean repo) ------------------------------------------------

def test_cli_contribute_clean_repo_graceful_no_envelope(fixture_repo: Path, tmp_path: Path,
                                                          monkeypatch, capsys):
    """Zero-issue analysis -> exit 0, no envelope written, clear stderr message —
    never a crash, never an error exit for a clean repo."""
    from scpe import backends
    _patch_cli_identity(monkeypatch, tmp_path)
    canned = {"ANALYZE": json.dumps({"issues": []})}
    monkeypatch.setattr(backends, "make_backend", lambda kind=None: backends.MockBackend(canned))
    envp = tmp_path / "clean.zip"
    assert main(["contribute", str(fixture_repo), "--out", str(envp)]) == 0
    assert not envp.exists()
    err = capsys.readouterr().err
    assert "nothing to contribute" in err
    assert "clean" in err


# ---- pull + pack -----------------------------------------------------------

def test_cli_pull_then_pack(fixture_repo: Path, tmp_path: Path, monkeypatch, capsys):
    pub = _patch_cli_identity(monkeypatch, tmp_path)
    ws = tmp_path / "ws"
    assert main(["pull", str(fixture_repo), "--dest", str(ws)]) == 0
    assert (ws / ".scpe" / "base.json").exists()

    # Fix the bug by hand — no AI in this path.
    (ws / "demo" / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    envp = tmp_path / "e.zip"
    assert main(["pack", "--workspace", str(ws), "--out", str(envp)]) == 0
    env = unpack(str(envp))
    assert len(env.pieces) == 1
    assert "a + b" in env.pieces[0].diff
    assert verify_signature(env) is True
    assert env.manifest.sender_name == "Bob Hand"
    assert env.manifest.github_login == "bob"
    assert env.manifest.ssh_pubkey == pub


def test_cli_pack_no_changes_errors(fixture_repo: Path, tmp_path: Path, monkeypatch, capsys):
    _patch_cli_identity(monkeypatch, tmp_path)
    ws = tmp_path / "ws2"
    assert main(["pull", str(fixture_repo), "--dest", str(ws)]) == 0
    # No edits → nothing to pack → operational error (exit 1), no envelope written.
    envp = tmp_path / "none.zip"
    assert main(["pack", "--workspace", str(ws), "--out", str(envp)]) == 1
    assert not envp.exists()


# ---- inspect ---------------------------------------------------------------

def test_cli_inspect_valid(fixture_repo: Path, tmp_path: Path, monkeypatch, capsys):
    _canned_contribute(monkeypatch)
    _patch_cli_identity(monkeypatch, tmp_path)
    envp = str(tmp_path / "e.zip")
    assert main(["contribute", str(fixture_repo), "--out", envp]) == 0
    capsys.readouterr()  # drop contribute's stderr chatter

    assert main(["inspect", envp]) == 0
    out = capsys.readouterr().out
    assert "signature_valid: True" in out
    assert "@bob" in out  # inspect surfaces the verifiable GitHub contributor


def test_cli_inspect_json(fixture_repo: Path, tmp_path: Path, monkeypatch, capsys):
    _canned_contribute(monkeypatch)
    _patch_cli_identity(monkeypatch, tmp_path)
    envp = str(tmp_path / "e.zip")
    main(["contribute", str(fixture_repo), "--out", envp])
    capsys.readouterr()
    assert main(["inspect", envp, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["signature_valid"] is True
    assert data["pieces"][0]["added"] > 0 and data["pieces"][0]["removed"] > 0


def test_cli_inspect_tampered_exit2(fixture_repo: Path, tmp_path: Path, monkeypatch):
    _canned_contribute(monkeypatch)
    _patch_cli_identity(monkeypatch, tmp_path)
    envp = tmp_path / "e.zip"
    main(["contribute", str(fixture_repo), "--out", str(envp)])
    # Tamper: mutate a piece and re-pack WITHOUT re-signing.
    env = unpack(str(envp))
    env.pieces[0].title = "tampered title"
    pack(env, str(envp))
    assert main(["inspect", str(envp)]) == 2


def test_cli_inspect_bad_zip_exit1(tmp_path: Path):
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"not a zip at all")
    assert main(["inspect", str(junk)]) == 1


# ---- extract (WS4: open format) --------------------------------------------

def test_cli_extract_writes_open_form(fixture_repo: Path, tmp_path: Path, monkeypatch):
    _patch_cli_identity(monkeypatch, tmp_path)
    ws = tmp_path / "ws"
    assert main(["pull", str(fixture_repo), "--dest", str(ws)]) == 0
    (ws / "demo" / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    envp = tmp_path / "e.zip"
    assert main(["pack", "--workspace", str(ws), "--out", str(envp)]) == 0

    outdir = tmp_path / "extracted"
    assert main(["extract", str(envp), "--dir", str(outdir)]) == 0
    # Any language can read these two files, no scpe needed.
    data = json.loads((outdir / "envelope.json").read_text(encoding="utf-8"))
    assert data["manifest"]["github_login"] == "bob"
    assert data["manifest"]["sig_method"] == "ssh-github"
    patch = (outdir / "contribution.patch").read_text(encoding="utf-8")
    assert "a + b" in patch and "--- a/demo/calc.py" in patch


# ---- init ------------------------------------------------------------------

def test_cli_init(fixture_repo: Path, capsys):
    # The fixture repo has no README — init creates one with the badge.
    assert main(["init", "--repo", str(fixture_repo), "--url", "https://github.com/x/y"]) == 0
    out = capsys.readouterr().out
    assert "badge added" in out
    content = (fixture_repo / "README.md").read_text(encoding="utf-8")
    assert BADGE_MARK in content
    assert "https://github.com/x/y" in content


def test_cli_init_idempotent(fixture_repo: Path, capsys):
    assert main(["init", "--repo", str(fixture_repo), "--url", "https://github.com/x/y"]) == 0
    before = (fixture_repo / "README.md").read_text(encoding="utf-8")
    capsys.readouterr()
    assert main(["init", "--repo", str(fixture_repo), "--url", "https://github.com/x/y"]) == 0
    assert "already opted in" in capsys.readouterr().out
    assert (fixture_repo / "README.md").read_text(encoding="utf-8") == before
