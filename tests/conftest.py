"""Shared fixtures and the two subprocess entry points every seal test drives.

The package under test is a thin adapter over reference/standalone/verify_envelope.py,
so the tests exercise it the way its two real callers do and nothing else:

  * `run_seal(...)`  -> `PYTHONPATH=<repo root> python -m scpe.cli seal ...`, byte for byte
    the invocation action.yml makes on a runner (no pipx, no PyPI, no install step). If
    this stops working, the Action stops working.
  * `run_verifier(...)` -> the standalone verifier as a bare-interpreter subprocess, the
    way an auditor runs it and the way spec/test-vectors is verified in CI.

Both are subprocesses on purpose: an in-process import would prove the functions agree
with each other while saying nothing about whether the shipped command line still works.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PRODUCER_PATH = ROOT / "reference" / "producer.py"
VERIFIER_PATH = ROOT / "reference" / "standalone" / "verify_envelope.py"
VECTORS = ROOT / "spec" / "test-vectors"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args],
                          check=True, capture_output=True, text=True).stdout.strip()


# --------------------------------------------------------------- reference producer

_producer_module = None


def load_producer():
    """reference/producer.py loaded by path (it lives outside the package on purpose —
    it is the spec's auditable reference producer, not part of the adapter). Cached, so a
    suite that packs a hundred envelopes still executes the module once."""
    global _producer_module
    if _producer_module is None:
        spec = importlib.util.spec_from_file_location("scpe_producer_ref", PRODUCER_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _producer_module = module
    return _producer_module


# ------------------------------------------------------------------ subprocess runs

def _child_env(extra: dict | None = None) -> dict:
    """The runner's environment: the repo root on PYTHONPATH and nothing installed. This
    is the `PYTHONPATH="${{ github.action_path }}"` line from action.yml — a checkout is
    the only thing the package is allowed to need."""
    env = os.environ.copy()
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = f"{ROOT}{os.pathsep}{existing}" if existing else str(ROOT)
    env.update(extra or {})
    return env


def run_cli(*args: str, env_extra: dict | None = None, cwd: Path | None = None,
            timeout: int = 300) -> subprocess.CompletedProcess:
    """`python -m scpe.cli <args>` from a checkout — the Action's exact entry point."""
    return subprocess.run([sys.executable, "-m", "scpe.cli", *args],
                          capture_output=True, text=True, timeout=timeout,
                          env=_child_env(env_extra), cwd=str(cwd) if cwd else None)


def run_seal(*args: str, **kw) -> subprocess.CompletedProcess:
    return run_cli("seal", *args, **kw)


def seal_json(*args: str, **kw) -> tuple[dict, int]:
    """`scpe seal ... --json` -> (results dict, exit code). `--json` is appended here so
    no test can forget it and then assert on human output by accident."""
    proc = run_seal(*args, "--json", **kw)
    assert proc.stdout.strip(), f"seal produced no stdout; stderr:\n{proc.stderr[-2000:]}"
    return json.loads(proc.stdout), proc.returncode


def run_verifier(path: Path, *, keys: Path | None = None, diff: Path | None = None,
                 artifact: Path | None = None, json_out: bool = True,
                 timeout: int = 120) -> subprocess.CompletedProcess:
    """The standalone reference verifier, bare interpreter, no PYTHONPATH — exactly the
    arrangement CI's `vectors` job uses to prove the one-file claim."""
    args = [sys.executable, str(VERIFIER_PATH), str(path)]
    if keys is not None:
        args += ["--keys", str(keys)]
    if diff is not None:
        args += ["--diff", str(diff)]
    if artifact is not None:
        args += ["--artifact", str(artifact)]
    if json_out:
        args.append("--json")
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


# ------------------------------------------------------------------------- envelopes

# The complete member set a spec envelope may carry (SPEC §4/§6) — the verifier rejects a
# zip containing anything else, so tests build from this list rather than from a glob.
ENVELOPE_MEMBERS = ("manifest.json", "manifest.sig", "diff.patch", "artifact.bin")


def envelope_from_dir(vector: Path, out: Path) -> Path:
    """Repack a test-vector DIRECTORY as an envelope zip, so the same normative bytes can
    be fed to a CLI flag that takes an envelope. Only spec members are copied — notably
    the vector's `keys` file is left out, so the key anchor stays the operator's `--keys`
    (key_source "flag") instead of quietly becoming a submitter-chosen `bundled` one."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in ENVELOPE_MEMBERS:
            member = vector / name
            if member.is_file():
                zf.writestr(zipfile.ZipInfo(name), member.read_bytes())
    out.write_bytes(buf.getvalue())
    return out


# -------------------------------------------------------------------------- fixtures

@pytest.fixture
def signing_key(tmp_path: Path) -> Path:
    """A throwaway ed25519 key. Every signature in this suite is minted per-test and
    verified offline against a local `keys` file — no account, no network, no gh."""
    key = tmp_path / "scpe_test_ed25519"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(key), "-N", "", "-q"],
                   check=True, capture_output=True)
    return key


@pytest.fixture
def keys_file(signing_key: Path, tmp_path: Path) -> Path:
    """The local stand-in for https://github.com/<subject>.keys — the bare public key."""
    kf = tmp_path / "keys"
    kf.write_bytes(Path(str(signing_key) + ".pub").read_bytes())
    return kf


def make_fixture_repo(tmp_path: Path, *, with_test_marker: bool = True) -> Path:
    repo = tmp_path / "fixture-repo"
    (repo / "demo").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "demo" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "demo" / "calc.py").write_text("def add(a, b):\n    return a - b  # BUG\n", encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text(
        "from demo.calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
    if with_test_marker:
        # This IS a pytest project (that's what the suite runs against it), so declare it
        # via a real marker file — otherwise scpe.testrun.detect_test_cmd would honestly
        # report "no runner" while the fixture's own ground truth says otherwise.
        (repo / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    subprocess.run(["git", "init", "-b", "master", str(repo)], check=True, capture_output=True)
    _git(repo, "config", "user.email", "fixture@example.com")
    _git(repo, "config", "user.name", "Fixture")
    _git(repo, "add", "-A")          # fixture repo only — never the real repo
    _git(repo, "commit", "-m", "seed")
    return repo


@pytest.fixture
def fixture_repo(tmp_path: Path) -> Path:
    return make_fixture_repo(tmp_path)


@pytest.fixture
def no_runner_repo(tmp_path: Path) -> Path:
    """Same repo, minus any language marker — nothing for detect_test_cmd to recognize."""
    return make_fixture_repo(tmp_path / "nr", with_test_marker=False)


@pytest.fixture
def repo_with_fix(tmp_path: Path) -> tuple[Path, str, str]:
    """A throwaway repo: a base commit with a buggy `add`, then a second commit (the 'PR
    branch') carrying the one-line fix. Returns (repo, base_sha, head_sha) — the three
    things the Action has on a runner and nothing more."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    _git(repo, "config", "user.email", "e2e@example.com")
    _git(repo, "config", "user.name", "E2E")
    (repo / "calc.py").write_text(
        "def add(a, b):\n    return a - b  # BUG: should add\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "base: buggy add()")
    base = _git(repo, "rev-parse", "HEAD")

    _git(repo, "checkout", "-b", "fix/add-arithmetic")
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "fix: add() should add, not subtract")
    head = _git(repo, "rev-parse", "HEAD")
    return repo, base, head
