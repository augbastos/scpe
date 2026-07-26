"""Input and diff RESOLUTION — the adapter around the reference verifier, not a verifier.

Every verdict this package reports is produced by
`reference/standalone/verify_envelope.py`: the single-file, stdlib-only implementation of
SPEC §8 that the eighteen normative test vectors and the Go and Rust ports are all measured
against. Nothing here re-implements a step of it. There is no signature check in this file,
no digest comparison, no status of its own — only the two questions the verifier
deliberately leaves to its caller:

    1. WHICH bytes are being verified?  A committed envelope zip, a file holding an
       SCPE-ATTESTATION-v1 block, or the pull request body itself (SPEC §9 transport).
    2. WHERE does the diff come from?  Enclosed in the envelope, or recomputed from the
       checkout with `git diff base...head` — three-dot, matching the producer.

It is imported as a module rather than shelled out to. The subprocess form costs a fresh
interpreter per call and hands back only the JSON projection, while the in-process call
returns the whole `Result` — status, detail, attestations, profile, key_source. The
subprocess form stays alive exactly where it proves something: reference/producer.py and
the CI `vectors` job still run the file with a bare interpreter, so the claim "an auditor
runs ONE file, no install" keeps being tested mechanically rather than asserted in prose.

Reading order for an auditor: the verdict is born in `verify_envelope.verify()`. This file
only decides what to hand it.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from reference.standalone import verify_envelope as _ref

# The env var the Action exports the pull request body through. The body is attacker-
# controlled text, so it travels by environment and is written to a temp file — it never
# becomes a command-line argument, where a hostile body would be visible in the process
# table and subject to the shell's own parsing.
PR_BODY_ENV = "SCPE_PR_BODY"

# Where the diff came from. These are NOT statuses: they never influence the verdict, they
# explain what the verdict had to work with. They also describe the diff only — for an
# `artifact` subject the integrity anchor is the enclosed artifact bytes (SPEC §6.2) and the
# diff, whatever its source, is carried for the risk scan and never checked against a digest.
ENCLOSED = "enclosed"        # carried inside the envelope as diff.patch
GIT = "git"                  # recomputed from the checkout, base...head
UNAVAILABLE = "unavailable"  # no diff could be obtained (see `note`)

SHALLOW_HINT = ("the base commit is not in this checkout — set `fetch-depth: 0` on "
                "actions/checkout so the PR's base is available to diff against")


@dataclass
class Resolved:
    """What was handed to the verifier: the input path, the diff (if any) and where it
    came from. `note` carries an operator-facing explanation when the diff is missing."""
    path: Path
    diff: Path | None
    diff_source: str
    note: str = ""


def _write(workdir: Path, name: str, data: bytes) -> Path:
    p = workdir / name
    p.write_bytes(data)
    return p


def enclosed_diff(path: Path) -> bytes | None:
    """The diff carried inside the input, or None. Uses the verifier's own `load_input`
    so "what counts as an envelope" has exactly one definition. Any unreadable input
    resolves to None here and is reported by the verifier itself a moment later — this
    function never decides that an input is bad, it only fails to find a diff in it."""
    try:
        _man, _sig, diff, _art, _keys = _ref.load_input(path)
    except Exception:                       # noqa: BLE001 - the verifier reports the reason
        return None
    return diff


def branch_diff(repo: Path, base: str, head: str) -> bytes | None:
    """`git diff base...head` from the checkout — three dots, matching what the producer
    signed (reference/producer.py `compute_diff`). Two dots would include commits that
    landed on the base branch after the contributor forked, producing a diff the
    contributor never signed — and therefore an integrity failure on an honest PR.

    Returns None when git cannot produce it, which on CI almost always means a shallow
    checkout that does not contain the base commit."""
    if not base or not head or not (repo / ".git").exists():
        return None
    try:
        proc = subprocess.run(["git", "-C", str(repo), "diff", f"{base}...{head}"],
                              capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def resolve(workdir: Path, *, envelope: str | None = None, attestation: str | None = None,
            pr_body_env: str = PR_BODY_ENV, repo: str = ".",
            base: str = "", head: str = "") -> Resolved:
    """Pick the input and the diff. `workdir` must outlive the verify call — the temp files
    written here are what the verifier reads.

    Never raises for missing or malformed material, and never invents a verdict for it: a
    path that does not exist, a zip in some other format, or an empty PR body all end up
    handed to the verifier as-is, and the verifier is the one that names the outcome. That
    is what keeps an older pinned tag of this Action — which still points at a path from a
    retired format — reporting a state rather than crashing a job.
    """
    if envelope:
        path = Path(envelope)
    elif attestation:
        path = Path(attestation)
    else:
        # SPEC §9: the attestation rides in the PR body. Written verbatim, including an
        # empty body — the verifier's own block scan decides whether anything is there.
        path = _write(workdir, "pr_body.txt",
                      (os.environ.get(pr_body_env) or "").encode("utf-8"))

    enclosed = enclosed_diff(path)
    if enclosed is not None:
        return Resolved(path, _write(workdir, "enclosed.patch", enclosed), ENCLOSED)

    raw = branch_diff(Path(repo), base, head)
    if raw is not None:
        return Resolved(path, _write(workdir, "branch.patch", raw), GIT)

    return Resolved(path, None, UNAVAILABLE, SHALLOW_HINT if base or head else "")


def run(resolved: Resolved, *, keys: str | None = None,
        artifact: str | None = None) -> _ref.Result:
    """Hand the resolved material to the reference verifier and return its Result untouched.

    The one line in this package where a verdict is produced. Nothing downstream may
    re-derive, soften or override it — results.py projects it into JSON, the seal renders
    it, and neither is allowed to disagree with what this call returned."""
    return _ref.verify(resolved.path,
                       Path(keys) if keys else None,
                       resolved.diff,
                       Path(artifact) if artifact else None)
