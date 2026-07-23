"""Apply an UNTRUSTED diff and run the target's tests in isolation.

MVP isolation = fresh temp copy + cleaned environment + hard timeout, executed in a
subprocess. That contains accidents and env exfiltration, NOT a determined attacker:
container/VM hardening is the documented post-MVP step. Never run on a working tree
you care about — the temp copy is always discarded."""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

_POSIX = os.name == "posix"

# APPDATA/LOCALAPPDATA are load-bearing on Windows: the per-user site-packages dir
# (where pip --user / editable installs land) is resolved from APPDATA, so dropping
# it breaks `python -m pytest` in the sandbox. Both are standard non-secret path vars,
# so they stay pointed at their REAL absolute paths (independent of HOME/USERPROFILE
# below — Windows resolves them separately, they are not derived from the profile dir).
# HOME/USERPROFILE are deliberately NOT in this pass-through set: untrusted test code
# runs here, and the real profile dir is where the owner's signing key lives
# (~/.scpe/key.pem), plus ~/.ssh, ~/.aws, etc. — see _clean_env, which redirects
# HOME/USERPROFILE to a throwaway dir instead of copying them from os.environ.
_KEEP = {"PATH", "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC", "WINDIR", "TEMP", "TMP",
         "PYTHONIOENCODING", "PATHEXT",
         "APPDATA", "LOCALAPPDATA"}


@dataclass
class SandboxResult:
    applied: bool
    tests_ran: bool
    passed: bool
    output_tail: str


def _clean_env(home: Path) -> dict[str, str]:
    env = {}
    for k, v in os.environ.items():
        up = k.upper()
        if up.startswith("SCPE_"):
            continue
        if up.endswith(("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD")):
            continue
        if up in _KEEP or up.startswith(("PYTHON", "LANG", "LC_")):
            env[k] = v
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Redirect HOME/USERPROFILE to a throwaway dir INSIDE the sandbox (never the real
    # profile): untrusted code under test could otherwise read the owner's signing key,
    # ~/.ssh, ~/.aws, etc. by resolving `~`. `home` is cleaned up with the rest of the
    # sandbox tmpdir in run_in_sandbox's `finally`.
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    return env


def _as_text(value) -> str:
    """subprocess.TimeoutExpired.stdout/stderr can be bytes even under text=True
    depending on platform/timing — coerce defensively."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


_MAKE_TARGET_RE = re.compile(r"(?m)^test\s*:")


def detect_test_cmd(repo_dir: Path) -> list[str] | None:
    """Best-effort, language-agnostic test-runner detection from marker files at the repo
    root. `run_in_sandbox` defaults to pytest for backward compat, but that default is wrong
    for a non-Python repo — this is what lets a caller (the strict handshake) ask "does this
    repo even HAVE a runner?" instead of assuming pytest and mis-scoring every other
    language's contributions as a correctness failure.

    Checked in order, first match wins (favors the ecosystem's own manifest over an
    incidental extra file): Python markers -> pytest; package.json with a real `scripts.test`
    (not npm's "no test specified" placeholder) -> npm test; Cargo.toml -> cargo test;
    go.mod -> go test; Makefile/makefile with a `test:` target -> make test. Returns None
    when nothing recognizable is present."""
    repo_dir = Path(repo_dir)

    if any((repo_dir / name).is_file() for name in
           ("pyproject.toml", "setup.py", "setup.cfg", "pytest.ini", "tox.ini")):
        return [sys.executable, "-m", "pytest", "-q"]

    pkg = repo_dir / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            data = {}
        test_script = (data.get("scripts") or {}).get("test", "") if isinstance(data, dict) else ""
        if isinstance(test_script, str) and test_script.strip() and "no test specified" not in test_script:
            return ["npm", "test", "--silent"]

    if (repo_dir / "Cargo.toml").is_file():
        return ["cargo", "test"]

    if (repo_dir / "go.mod").is_file():
        return ["go", "test", "./..."]

    for name in ("Makefile", "makefile"):
        mk = repo_dir / name
        if mk.is_file():
            try:
                text = mk.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            if _MAKE_TARGET_RE.search(text):
                return ["make", "test"]

    return None


def _spawn(cmd: list[str], cwd: Path, env: dict[str, str]) -> subprocess.Popen:
    """Start the UNTRUSTED test command in its OWN process group / session, so the whole
    group can be killed later — not just the immediate child. A malicious test/build
    script can detach a background worker (Popen(start_new_session=True), setsid, a
    double-fork) that would otherwise outlive the sandbox and, sharing the runner
    filesystem, race to overwrite results.json / pr-number.txt before the artifact is
    uploaded. Containing the group is the MVP mitigation; real container/namespace
    isolation (see module docstring) is the post-MVP hard boundary."""
    kwargs: dict = {}
    if _POSIX:
        # setsid in the child: it becomes session+group leader, so its pgid == its pid.
        kwargs["start_new_session"] = True
    else:
        # Windows has no setsid; a new process group lets taskkill /T reach the tree.
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen(cmd, cwd=str(cwd), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, **kwargs)


def _kill_group(proc: subprocess.Popen) -> None:
    """SIGKILL the ENTIRE process group/tree rooted at the sandboxed command, whether it
    timed out or exited on its own — a background process it spawned in the same group
    (that did NOT itself re-setsid to escape) must not survive to tamper with results.
    Best-effort: an already-dead group/PID is not an error."""
    try:
        if _POSIX:
            # The child is its own group leader (start_new_session), so its pgid == pid.
            # The group persists while any member lives, even after the leader is reaped.
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True)
    except (ProcessLookupError, OSError):
        pass


def run_in_sandbox(repo_dir: Path, diff: str, *, test_cmd: list[str] | None = None,
                   timeout: int = 600) -> SandboxResult:
    tmp = Path(tempfile.mkdtemp(prefix="cc-sandbox-"))
    work = tmp / "repo"
    home = tmp / "home"       # throwaway HOME/USERPROFILE — never the owner's real profile
    try:
        home.mkdir(parents=True, exist_ok=True)
        shutil.copytree(repo_dir, work)
        if diff.strip():
            patch = tmp / "piece.patch"
            patch.write_text(diff, encoding="utf-8", newline="\n")
            check = subprocess.run(["git", "apply", "--check", str(patch)],
                                   cwd=work, capture_output=True, text=True)
            if check.returncode != 0:
                return SandboxResult(False, False, False, check.stderr[-4000:])
            subprocess.run(["git", "apply", str(patch)], cwd=work,
                           capture_output=True, text=True, check=True)
        cmd = test_cmd or [sys.executable, "-m", "pytest", "-q"]
        proc = _spawn(cmd, work, _clean_env(home))
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            out = (_as_text(stdout) + "\n" + _as_text(stderr))[-4000:]
            # Sweep the group even on a clean exit: the immediate child may have left a
            # detached background process behind that would otherwise race results.json.
            _kill_group(proc)
            return SandboxResult(True, True, proc.returncode == 0, out)
        except subprocess.TimeoutExpired as exc:
            _kill_group(proc)   # kill the whole group, not just the immediate PID
            try:
                stdout, stderr = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                stdout, stderr = exc.stdout, exc.stderr
            partial = (_as_text(stdout) + "\n" + _as_text(stderr))[-3900:]
            return SandboxResult(True, True, False, partial + "\n[sandbox] TIMEOUT — killed")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
