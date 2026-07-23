import subprocess
from pathlib import Path
import pytest

from scpe.identity import LocalIdentity, noreply_email


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def make_test_identity(tmp_path: Path, *, login: str = "alice", name: str = "Alice Dev",
                       uid: str = "1", key_name: str = "cc_test_key") -> tuple[LocalIdentity, str]:
    """A LocalIdentity backed by a throwaway SSH key — lets pack/contribute sign an envelope
    fully offline (no gh CLI, no GitHub fetch). Returns (identity, bare_pubkey) so a test can
    also verify the resulting envelope identity by injecting `keys=[bare_pubkey]`."""
    kp = tmp_path / key_name
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(kp), "-N", "", "-q"],
                   check=True, capture_output=True)
    pub = " ".join((tmp_path / f"{key_name}.pub").read_text(encoding="utf-8").split()[:2])
    return LocalIdentity(login=login, user_id=uid, name=name, pubkey=pub, key_path=str(kp)), pub


def patch_cli_identity(monkeypatch, tmp_path: Path, *, login: str = "alice-dev",
                       name: str = "Alice Dev", uid: str = "42") -> tuple[LocalIdentity, str]:
    """Replace `scpe.cli`'s GitHub-identity resolution (gh CLI + network) with a
    throwaway key so `contribute`/`pack` via the CLI run fully offline."""
    from scpe import cli
    ident, pub = make_test_identity(tmp_path, login=login, name=name, uid=uid,
                                    key_name="cli_id_key")
    monkeypatch.setattr(cli, "resolve_local_identity", lambda **kw: ident)
    return ident, pub

def make_fixture_repo(tmp_path: Path, *, with_test_marker: bool = True) -> Path:
    repo = tmp_path / "fixture-repo"
    (repo / "demo").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "demo" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "demo" / "calc.py").write_text("def add(a, b):\n    return a - b  # BUG\n", encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(
        "from demo.calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
    if with_test_marker:
        # This IS a pytest project (that's what run_in_sandbox's own default assumes, and
        # what every test in this suite runs against it) — declare it via a real marker file
        # so scpe.sandbox.detect_test_cmd finds it too, instead of silently disagreeing
        # with the fixture's own ground truth.
        (repo / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    subprocess.run(["git", "init", "-b", "master", str(repo)], check=True, capture_output=True)
    _git(repo, "config", "user.email", "fixture@example.com")
    _git(repo, "config", "user.name", "Fixture")
    _git(repo, "add", "-A")          # fixture repo only — never the real repo
    _git(repo, "commit", "-m", "seed")
    return repo

FIX_DIFF = """--- a/demo/calc.py
+++ b/demo/calc.py
@@ -1,2 +1,2 @@
 def add(a, b):
-    return a - b  # BUG
+    return a + b
"""

@pytest.fixture
def fixture_repo(tmp_path: Path) -> Path:
    return make_fixture_repo(tmp_path)


@pytest.fixture
def no_runner_repo(tmp_path: Path) -> Path:
    """Same repo, minus any language marker — nothing for detect_test_cmd to recognize."""
    return make_fixture_repo(tmp_path / "nr", with_test_marker=False)
