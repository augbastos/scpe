import sys
from pathlib import Path
from scpe.sandbox import detect_test_cmd, run_in_sandbox
from tests.conftest import FIX_DIFF

def test_good_fix_applies_and_tests_pass(fixture_repo: Path):
    r = run_in_sandbox(fixture_repo, FIX_DIFF)
    assert r.applied and r.tests_ran and r.passed

def test_without_fix_tests_fail(fixture_repo: Path):
    r = run_in_sandbox(fixture_repo, "")  # empty diff = no change; planted bug remains
    assert r.applied and r.tests_ran and not r.passed

def test_malformed_diff_does_not_apply(fixture_repo: Path):
    r = run_in_sandbox(fixture_repo, "--- a/nope\n+++ b/nope\n@@ -1 +1 @@\n-x\n+y\n")
    assert not r.applied and not r.tests_ran

def test_original_repo_untouched(fixture_repo: Path):
    run_in_sandbox(fixture_repo, FIX_DIFF)
    assert "a - b" in (fixture_repo / "demo" / "calc.py").read_text(encoding="utf-8")

def test_secret_env_not_leaked_into_sandbox(fixture_repo: Path, monkeypatch):
    monkeypatch.setenv("SCPE_API_KEY", "supersecret")
    import sys
    r = run_in_sandbox(
        fixture_repo, FIX_DIFF,
        test_cmd=[sys.executable, "-c",
                  "import os,sys; sys.exit(1 if 'SCPE_API_KEY' in os.environ else 0)"])
    assert r.passed


def test_home_is_redirected_to_a_throwaway_sandbox_dir(fixture_repo: Path):
    """FIX 5: untrusted code under test must never see the owner's REAL HOME/USERPROFILE
    (that's where ~/.scpe/key.pem, ~/.ssh, ~/.aws live) — it must resolve to a
    throwaway dir that lives (and dies) with the sandbox tmpdir."""
    import os, sys
    real_home = os.environ.get("USERPROFILE") or os.environ.get("HOME") or ""
    r = run_in_sandbox(
        fixture_repo, FIX_DIFF,
        test_cmd=[sys.executable, "-c",
                 "import os, sys\n"
                 "home = os.environ.get('USERPROFILE') or os.environ.get('HOME') or ''\n"
                 "real = " + repr(real_home) + "\n"
                 "sys.exit(0 if home and home != real else 1)"])
    assert r.passed


def test_home_dir_does_not_survive_after_sandbox_cleanup(fixture_repo: Path, monkeypatch):
    """The throwaway HOME must be inside the sandbox tmpdir that gets rmtree'd — no leftover
    directory sticking around after run_in_sandbox returns."""
    import sys
    import scpe.sandbox as sbmod
    captured = {}
    real = sbmod._clean_env

    def spy(home):
        captured["home"] = home
        return real(home)

    monkeypatch.setattr(sbmod, "_clean_env", spy)
    run_in_sandbox(fixture_repo, FIX_DIFF, test_cmd=[sys.executable, "-c", "pass"])
    assert "home" in captured
    assert not captured["home"].exists()          # cleaned up with the rest of the sandbox tmp


# ---- detect_test_cmd (language-agnostic runner detection) -----------------------------

def test_detect_test_cmd_python_pyproject(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    assert detect_test_cmd(tmp_path) == [sys.executable, "-m", "pytest", "-q"]


def test_detect_test_cmd_python_setup_py(tmp_path: Path):
    (tmp_path / "setup.py").write_text("", encoding="utf-8")
    assert detect_test_cmd(tmp_path) == [sys.executable, "-m", "pytest", "-q"]


def test_detect_test_cmd_python_pytest_ini(tmp_path: Path):
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    assert detect_test_cmd(tmp_path) == [sys.executable, "-m", "pytest", "-q"]


def test_detect_test_cmd_node_real_test_script(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"name": "x", "scripts": {"test": "jest"}}', encoding="utf-8")
    assert detect_test_cmd(tmp_path) == ["npm", "test", "--silent"]


def test_detect_test_cmd_node_placeholder_test_script_is_ignored(tmp_path: Path):
    """npm's default placeholder ('no test specified', exit 1) is not a real runner —
    must NOT be reported as one, or every un-configured node project auto-fails."""
    (tmp_path / "package.json").write_text(
        '{"name": "x", "scripts": {"test": "echo \\"Error: no test specified\\" && exit 1"}}',
        encoding="utf-8")
    assert detect_test_cmd(tmp_path) is None


def test_detect_test_cmd_rust_cargo(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n", encoding="utf-8")
    assert detect_test_cmd(tmp_path) == ["cargo", "test"]


def test_detect_test_cmd_go(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    assert detect_test_cmd(tmp_path) == ["go", "test", "./..."]


def test_detect_test_cmd_makefile_with_test_target(tmp_path: Path):
    (tmp_path / "Makefile").write_text("build:\n\techo build\n\ntest:\n\techo test\n",
                                       encoding="utf-8")
    assert detect_test_cmd(tmp_path) == ["make", "test"]


def test_detect_test_cmd_makefile_without_test_target_is_none(tmp_path: Path):
    (tmp_path / "Makefile").write_text("build:\n\techo build\n", encoding="utf-8")
    assert detect_test_cmd(tmp_path) is None


def test_detect_test_cmd_none_when_nothing_recognizable(tmp_path: Path):
    (tmp_path / "README.md").write_text("hello\n", encoding="utf-8")
    assert detect_test_cmd(tmp_path) is None
