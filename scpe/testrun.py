"""Run the target repository's OWN test suite, where the code already is.

This is NOT a sandbox. Under the SPEC §9 transport the pull request itself carries the
change, so by the time this runs the checkout already contains it — there is no pending
diff to apply to a temporary copy, and building one would only test a reconstruction of
what is already on disk.

What it still is: the execution of code written by whoever opened the pull request. That
is acceptable exactly once — inside the UNTRUSTED CI job, the one with no secrets and a
read-only token, which exists to be the place contributor code may run. The two
precautions kept from the older sandbox are the ones that still buy something there: the
environment is stripped of anything that looks like a credential before the command
starts, and the whole process group is killed afterwards, because a test script can
detach a background worker that would otherwise outlive this call and race to overwrite
results.json before the artifact is uploaded. Neither is isolation. Do not run this on a
machine you care about.

Honesty invariant, enforced by construction below: a test run that did not happen is
reported as `not run`, never as passed. `ok` can only be true when `ran` is true.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
import sys
from pathlib import Path

_POSIX = os.name == "posix"

# APPDATA/LOCALAPPDATA are load-bearing on Windows: the per-user site-packages dir is
# resolved from APPDATA, so dropping it breaks `python -m pytest`. HOME/USERPROFILE are
# kept for the same reason on the other side — npm, cargo and go all resolve their caches
# and toolchains from the profile dir, and a suite that cannot find its toolchain reports a
# failure that says nothing about the contribution. Keeping them is a deliberate trade, not
# an oversight: this function narrows the credential surface, it does not build a boundary.
_KEEP = {"PATH", "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC", "WINDIR", "TEMP", "TMP",
         "PYTHONIOENCODING", "PATHEXT", "APPDATA", "LOCALAPPDATA", "CI", "HOME", "USERPROFILE"}

_MAKE_TARGET_RE = re.compile(r"^test\s*:", re.M)

NOT_RUN = {"ran": False, "ok": False, "summary": "not run"}
NO_RUNNER = {"ran": False, "ok": False, "summary": "no test runner detected"}


def _clean_env() -> dict[str, str]:
    """The environment the suite runs in: path-ish variables and the language locale, minus
    anything shaped like a credential. A repository's own tests legitimately need PATH and a
    working interpreter; they never need a token."""
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        up = key.upper()
        if up.startswith("SCPE_"):
            continue
        if up.endswith(("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_KEY")):
            continue
        if up in _KEEP or up.startswith(("PYTHON", "LANG", "LC_")):
            env[key] = value
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _configured_test_cmd(repo: Path) -> list[str] | None:
    """The repo's own declaration: `.scpe/verify.json` with a `test_cmd`, either a JSON array
    of args or a shell-style string. It wins over marker detection so an owner can pin the
    exact runner (`tox -e unit`, a monorepo target) instead of relying on a guess. A
    malformed or missing config is ignored, not an error — the caller falls back."""
    cfg = repo / ".scpe" / "verify.json"
    if not cfg.is_file():
        return None
    try:
        data = json.loads(cfg.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    cmd = data.get("test_cmd") if isinstance(data, dict) else None
    if isinstance(cmd, list) and cmd and all(isinstance(c, str) for c in cmd):
        return cmd
    if isinstance(cmd, str) and cmd.strip():
        return shlex.split(cmd)
    return None


def detect_test_cmd(repo: Path) -> list[str] | None:
    """The repo's declared command, else a language-marker guess, else None.

    Marker order, first match wins (the ecosystem's own manifest beats an incidental extra
    file): Python markers -> pytest; package.json with a real `scripts.test` -> npm test;
    Cargo.toml -> cargo test; go.mod -> go test; Makefile with a `test:` target -> make test.

    None means "this repo has no runner I recognize", which is a real answer. Defaulting to
    pytest instead would mis-score every non-Python contribution as a correctness failure."""
    repo = Path(repo)
    declared = _configured_test_cmd(repo)
    if declared:
        return declared

    if any((repo / name).is_file() for name in
           ("pyproject.toml", "setup.py", "setup.cfg", "pytest.ini", "tox.ini")):
        return [sys.executable, "-m", "pytest", "-q"]

    pkg = repo / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            data = {}
        script = (data.get("scripts") or {}).get("test", "") if isinstance(data, dict) else ""
        if isinstance(script, str) and script.strip() and "no test specified" not in script:
            return ["npm", "test", "--silent"]

    if (repo / "Cargo.toml").is_file():
        return ["cargo", "test"]
    if (repo / "go.mod").is_file():
        return ["go", "test", "./..."]
    for name in ("Makefile", "makefile"):
        mk = repo / name
        if mk.is_file():
            try:
                text = mk.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            if _MAKE_TARGET_RE.search(text):
                return ["make", "test"]
    return None


def runner_summary(output: str) -> str:
    """The runner's OWN summary line (e.g. '35 passed in 0.1s'), so the seal reports real
    counts instead of a phrase this code made up. Empty when the output has no such line."""
    for line in reversed([ln.strip() for ln in output.splitlines() if ln.strip()]):
        low = line.lower()
        if ("passed" in low or "failed" in low or "error" in low) and any(c.isdigit() for c in line):
            return line.strip("= ").strip()
    return ""


def _kill_group(proc: subprocess.Popen) -> None:
    """Kill the whole group rooted at the test command, on timeout AND on clean exit — a
    background process it spawned shares this runner's filesystem and must not survive to
    touch results.json. Best-effort: an already-dead group is not an error."""
    try:
        if _POSIX:
            os.killpg(proc.pid, signal.SIGKILL)   # the child is its own group leader
        else:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True)
    except (ProcessLookupError, OSError):
        pass


def run_tests(repo: Path, cmd: list[str] | None = None, *, timeout: int = 600) -> dict:
    """Run `cmd` (or the detected runner) in `repo`. Returns {ran, ok, summary}.

    Every failure mode — no runner, a missing executable, a timeout — reports ran=False or
    ok=False with a summary that says which one it was. Nothing here can report a pass for
    a suite that did not complete."""
    repo = Path(repo)
    # Checked before detection, not after: a nonexistent path has no marker files either, so
    # detecting first would report "no test runner detected" for what is really a bad --repo.
    if not repo.is_dir():
        return {"ran": False, "ok": False, "summary": f"no such repo: {repo}"}
    cmd = cmd or detect_test_cmd(repo)
    if not cmd:
        return dict(NO_RUNNER)

    kwargs: dict = ({"start_new_session": True} if _POSIX
                    else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP})
    try:
        proc = subprocess.Popen(cmd, cwd=str(repo), env=_clean_env(),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, errors="replace", **kwargs)
    except OSError as exc:
        return {"ran": False, "ok": False, "summary": f"cannot start {cmd[0]}: {exc}"}

    try:
        output = proc.communicate(timeout=timeout)[0] or ""
        _kill_group(proc)
        ok = proc.returncode == 0
        return {"ran": True, "ok": ok,
                "summary": runner_summary(output[-4000:]) or ("passed" if ok else "failed")}
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        # A suite that was killed mid-run proved nothing, so it did not "run" for reporting
        # purposes — ran=False keeps a timeout from ever being spun as a result.
        return {"ran": False, "ok": False, "summary": f"TIMEOUT after {timeout}s — killed"}
