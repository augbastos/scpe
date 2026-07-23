"""checks — run a small set of RECOGNIZED, independent tools against a repo and
report exactly what happened, so `attest` can carry signed EVIDENCE alongside the
LLM's verdict instead of just the verdict on its own. This is what makes the
attestation credibly closer to formal (an attacker also has to fake tool output,
not just an opinion) WITHOUT overclaiming: a check that never ran is never reported
as passed, and nothing here becomes a "formal certification" — see attestation.py's
module docstring and cli.py's `_ATTESTATION_DISCLAIMER`.

Each check EXECUTES (its own test suite) or READS (bandit/ruff statically parse
source) code from an UNTRUSTED repo, so every one of them reuses sandbox.py's
existing isolation — fresh temp copy, cleaned env, HOME/USERPROFILE redirected,
hard timeout — via `sandbox.run_in_sandbox(repo_dir, "", test_cmd=<cmd>)` (empty
diff = no patch, just run `cmd` against the repo as-is). Nothing here re-implements
or bypasses that isolation.

Honesty contract: a check is only ever reported `"ran": true` if its command
actually executed. A missing tool binary, or no recognizable test runner, is
recorded as `"ran": false` with a `reason` in `summary` — NEVER silently skipped
(the caller wouldn't be able to tell the difference between "not installed" and
"passed") and never fabricated as a pass."""
from __future__ import annotations

import shutil
from pathlib import Path

from scpe import sandbox

# Tail kept per check — enough to show the reader why a check failed without
# ballooning the attestation (the whole document is meant to stay a small,
# signable JSON file; sandbox.run_in_sandbox already caps its own tail at 4000
# chars, this trims further for the evidence entry).
_TAIL_CHARS = 500


def _not_ran(tool: str, reason: str) -> dict:
    return {"tool": tool, "ran": False, "passed": None, "summary": reason, "tail": ""}


def _run(repo_dir: Path, tool: str, cmd: list[str], timeout: int) -> dict:
    """Actually execute `cmd` against `repo_dir` inside the sandbox and shape the
    result. Catches FileNotFoundError so a binary that vanished between the
    availability check and the sandboxed subprocess call (or one whose PATH
    resolution differs from the outer process for any other reason) degrades to
    `ran=false` instead of crashing the whole attest run — the same "never claim a
    check that did not run" contract as the upfront `shutil.which` gate below."""
    try:
        result = sandbox.run_in_sandbox(repo_dir, "", test_cmd=cmd, timeout=timeout)
    except FileNotFoundError:
        return _not_ran(tool, "not installed")
    if not result.applied or not result.tests_ran:
        # Diff is always empty here, so run_in_sandbox has nothing to apply — this
        # branch is effectively unreachable in normal use, but if the sandbox ever
        # reports it couldn't even start the command, that is "didn't run", not a
        # silent failure to report.
        return _not_ran(tool, "sandbox could not run the check")
    tail = result.output_tail[-_TAIL_CHARS:]
    return {"tool": tool, "ran": True, "passed": result.passed,
            "summary": "pass" if result.passed else "fail", "tail": tail}


def run_checks(repo_dir: Path, *, timeout: int = 300) -> list[dict]:
    """Run the repo's own test suite plus bandit (Python SAST) and ruff/pyflakes
    (lint) — whichever are actually installed — and return one result dict per
    check: `{"tool", "ran", "passed", "summary", "tail"}`. `passed` is `None` when
    `ran` is `False` (there is no pass/fail verdict for a check that never
    executed). Never raises for a missing tool or an unrecognized repo — those are
    normal, honestly-reported outcomes, not errors."""
    repo_dir = Path(repo_dir)
    checks: list[dict] = []

    test_cmd = sandbox.detect_test_cmd(repo_dir)
    if test_cmd is None:
        checks.append(_not_ran("tests", "no test runner detected"))
    else:
        checks.append(_run(repo_dir, "tests", test_cmd, timeout))

    if shutil.which("bandit"):
        checks.append(_run(repo_dir, "bandit", ["bandit", "-r", ".", "-q"], timeout))
    else:
        checks.append(_not_ran("bandit", "not installed"))

    if shutil.which("ruff"):
        checks.append(_run(repo_dir, "ruff", ["ruff", "check", "."], timeout))
    elif shutil.which("pyflakes"):
        checks.append(_run(repo_dir, "pyflakes", ["pyflakes", "."], timeout))
    else:
        checks.append(_not_ran("ruff", "not installed"))

    return checks


def summarize_checks(checks: list[dict]) -> str:
    """One-line, comma-joined `tool=summary` rendering for a terminal/log — e.g.
    'tests=pass, bandit=not installed, ruff=fail'. Callers prefix their own label
    (e.g. 'checks: ')."""
    return ", ".join(f"{c.get('tool', '?')}={c.get('summary', '')}" for c in checks)
