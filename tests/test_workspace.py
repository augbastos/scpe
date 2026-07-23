import json
import subprocess
from pathlib import Path

import pytest

from scpe.backends import MockBackend
from scpe.envelope import unpack, verify_envelope_identity, verify_signature
from scpe.identity import LocalIdentity, noreply_email
from scpe.workspace import WORKMETA, WorkspaceError, pack, pull


def _edit_fix(ws: Path) -> None:
    """Hand-fix the planted bug in the pulled workspace (a - b → a + b)."""
    (ws / "demo" / "calc.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8")


def _ident(tmp_path: Path, *, login: str = "alice", name: str = "Alice Dev",
           uid: str = "1") -> tuple[LocalIdentity, str]:
    """A LocalIdentity backed by a throwaway SSH key — lets pack sign an envelope offline
    without touching gh/GitHub (that resolution/verification is exercised separately)."""
    kp = tmp_path / "sign_key"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(kp), "-N", "", "-q"],
                   check=True, capture_output=True)
    pub = " ".join((tmp_path / "sign_key.pub").read_text(encoding="utf-8").split()[:2])
    return LocalIdentity(login=login, user_id=uid, name=name, pubkey=pub, key_path=str(kp)), pub


def test_pull_writes_base_meta(fixture_repo: Path, tmp_path: Path):
    ws = pull(str(fixture_repo), tmp_path / "ws", now_iso="2026-07-20T00:00:00+00:00")
    meta_path = ws / WORKMETA
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert len(meta["base_sha"]) == 40
    assert meta["repo_url"] == str(fixture_repo)
    assert meta["pulled_at"] == "2026-07-20T00:00:00+00:00"


def test_pull_refuses_nonempty_dest(fixture_repo: Path, tmp_path: Path):
    dest = tmp_path / "ws"
    dest.mkdir()
    (dest / "existing.txt").write_text("x", encoding="utf-8")
    with pytest.raises(WorkspaceError):
        pull(str(fixture_repo), dest)


def test_pack_of_manual_edit_produces_signed_envelope(fixture_repo: Path, tmp_path: Path):
    ws = pull(str(fixture_repo), tmp_path / "ws")
    _edit_fix(ws)
    ident, pub = _ident(tmp_path)
    out = pack(ws, out_path=tmp_path / "e.zip", identity=ident,
               now_iso="2026-07-20T00:00:00+00:00")
    env = unpack(out)
    assert verify_signature(env)
    got = verify_envelope_identity(env, keys=[pub])
    assert got is not None and got.login == "alice"
    assert len(env.pieces) == 1
    piece = env.pieces[0]
    assert "-    return a - b" in piece.diff
    assert "+    return a + b" in piece.diff
    assert "demo/calc.py" in piece.target_files
    meta = json.loads((ws / WORKMETA).read_text(encoding="utf-8"))
    assert env.manifest.base_sha == meta["base_sha"]
    # Credit is the resolved GitHub identity, not free text.
    assert env.manifest.sender_name == "Alice Dev"
    assert env.manifest.sender_email == noreply_email("alice", "1")
    assert env.manifest.github_login == "alice"
    assert env.manifest.sig_method == "ssh-github"
    assert env.provenance["mode"] == "manual"
    assert env.provenance["backend"] == "none"
    # our own metadata must never leak into the user's contribution
    assert WORKMETA not in piece.diff
    assert all(not f.startswith(".scpe") for f in piece.target_files)


def test_pack_no_changes_raises(fixture_repo: Path, tmp_path: Path):
    ws = pull(str(fixture_repo), tmp_path / "ws")
    ident, _ = _ident(tmp_path)
    with pytest.raises(WorkspaceError):
        pack(ws, out_path=tmp_path / "e.zip", identity=ident)


def test_pack_missing_base_meta_raises(tmp_path: Path):
    ws = tmp_path / "not-a-workspace"
    ws.mkdir()
    ident, _ = _ident(tmp_path)
    with pytest.raises(WorkspaceError):
        pack(ws, out_path=tmp_path / "e.zip", identity=ident)


def test_pack_with_backend_uses_llm_briefing(fixture_repo: Path, tmp_path: Path):
    ws = pull(str(fixture_repo), tmp_path / "ws")
    _edit_fix(ws)
    ident, _ = _ident(tmp_path)
    backend = MockBackend({"BRIEFING": "# Manual fix\nHand-authored calc fix."})
    # self_verify=False keeps the sandbox (real pytest) out of this unit test
    out = pack(ws, out_path=tmp_path / "e.zip", identity=ident,
               backend=backend, self_verify=False, now_iso="2026-07-20T00:00:00+00:00")
    env = unpack(out)
    assert "Hand-authored calc fix." in env.briefing_md
    assert env.provenance["backend"] == "mock"
