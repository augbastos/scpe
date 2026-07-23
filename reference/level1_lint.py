#!/usr/bin/env python3
"""SCPE LEVEL 1 — the Action-facing wrapper around disclosure.py.

Invoked by action.yml's untrusted step (no secrets, no signature, no envelope —
`pipx install scpe` is never even run for this path). It reads the ambient GitHub
context the composite action's step already passed through as env vars, asks
disclosure.detect_disclosure() the one question it answers, and writes results.json
in the schema the trusted `seal` job (docs/workflows/scpe.yml) already reads:
`status`, `require`, `gate_pass` (existing contract) plus `disclosure`, `level`,
`fail_message`, `comment` (new, level-1-only fields the trusted job falls back
around when absent, so level 2/default behavior is untouched).

Environment (all optional; missing values degrade to "no disclosure found" rather
than raising — the untrusted job must always finish and hand a result to the
trusted job, per spec §8 "unattested is a state, not an error"):
    PR_BODY    the pull request description
    BASE_SHA   the PR's base commit (for `git log BASE..HEAD`)
    HEAD_SHA   the PR's head commit
    REPO_DIR   the checked-out repo to read commit messages from (default ".")
    REQUIRE    "true" to gate (fail when absent); anything else = informational
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from disclosure import detect_disclosure  # noqa: E402  (path set up above, on purpose)

FAIL_MESSAGE = (
    "⚠️ Missing AI-use disclosure — this repository requires "
    "contributors to declare AI use"
)


def _commit_messages(repo_dir: str, base: str, head: str) -> list[str]:
    """Commit messages in `base..head`, oldest-first. Never raises: any git failure
    degrades to an empty list rather than crashing the untrusted job — the PR body
    is still checked either way. Honest limitation: `actions/checkout@v4`'s default
    `fetch-depth: 1` won't have `base` locally, so on a shallow checkout this
    silently returns [] and the trailer check falls back to the PR body only — a
    repo wanting the commit-trailer form reliably checked should set
    `fetch-depth: 0` (or enough depth to cover the PR) on its checkout step."""
    if not base or not head:
        return []
    try:
        out = subprocess.run(
            ["git", "-C", repo_dir, "log", f"{base}..{head}", "--format=%B%x00"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if out.returncode != 0 or not out.stdout:
        return []
    return [m for m in out.stdout.split("\x00") if m.strip()]


def build_results(*, pr_body: str, base: str, head: str, repo_dir: str, require: bool) -> dict:
    commits = _commit_messages(repo_dir, base, head)
    result = detect_disclosure(pr_body=pr_body, commit_messages=commits)
    status = "verified" if result["present"] else "unattested"
    gate_pass = (not require) or result["present"]
    comment = (
        f"✅ AI-use disclosure found ({result['form']}: {result['value'] or 'none'})"
        if result["present"] else
        "ℹ️ No AI-use disclosure found (informational — set "
        '`require: "true"` on this Action to enforce).'
    )
    return {
        "level": "1",
        "disclosure": result,
        "status": status,
        "require": require,
        "gate_pass": gate_pass,
        "fail_message": FAIL_MESSAGE,
        "comment": comment,
    }


def main() -> int:
    require = (os.environ.get("REQUIRE") or "false").strip().lower() == "true"
    data = build_results(
        pr_body=os.environ.get("PR_BODY") or "",
        base=os.environ.get("BASE_SHA") or "",
        head=os.environ.get("HEAD_SHA") or "",
        repo_dir=os.environ.get("REPO_DIR") or ".",
        require=require,
    )
    Path("results.json").write_text(json.dumps(data), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
