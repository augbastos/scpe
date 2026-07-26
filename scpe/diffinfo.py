"""Unified-diff arithmetic: how many lines moved, and which files they moved in.

Counting only. Nothing here decides anything — the integrity of a diff against its signed
digest is the reference verifier's job (SPEC §8 step 7), and these numbers are reported
beside that verdict, never in place of it.
"""
from __future__ import annotations

import re

# A file header is `+++ ` (three plus signs + a SPACE); an ADDED source line that merely
# starts with '+' (e.g. `+++counter`) has no space at index 3, so it is NOT a header.
# Requiring the space is what distinguishes the two — scpe.seal imports this same regex
# so the risk scan and the file list can never disagree about what a header is.
FILE_HEADER_RE = re.compile(r"^\+\+\+ (?:b/)?(.+)$")


def count_diff_lines(diff: str) -> tuple[int, int]:
    """Added/removed source lines in a unified diff.

    Counts only INSIDE hunks. The obvious shortcut — skip anything starting with
    '+++'/'---' — miscounts real edits: adding a line whose own content starts with
    '++' produces '+++...' and would be silently dropped as if it were a file header.
    Tracking hunk state is the only way to tell a header from content that looks like
    one, because inside a hunk every line is prefixed and a header cannot appear.
    """
    added = removed = 0
    in_hunk = False
    for line in diff.splitlines():
        if line.startswith("@@"):
            in_hunk = True
            continue
        if not in_hunk:
            continue                       # preamble: 'diff --git', 'index', '---'/'+++'
        if line.startswith("diff --git "):
            in_hunk = False                # unprefixed, so it can only start the next file
            continue
        if line.startswith("+"):
            added += 1
        elif line.startswith("-"):
            removed += 1
    return added, removed


def files_from_diff(diff: str) -> list[str]:
    """The files a unified diff touches, in first-seen order, read from its `+++ ` headers.

    Order-preserving and de-duplicated rather than a set, so the seal renders the same list
    every time for the same diff. `/dev/null` (a deletion's new-side header) is dropped: it
    names no file. This is the OBSERVED list; `subject.change.files_changed` in the signed
    manifest is the CLAIMED one, and results.json reports both rather than reconciling them
    — git's numstat and a raw +/- count legitimately disagree on renames and binaries.
    """
    out: list[str] = []
    for line in diff.splitlines():
        m = FILE_HEADER_RE.match(line)
        if not m:
            continue
        name = m.group(1).strip()
        # git appends a tab-separated timestamp in some diff dialects; the path ends there.
        name = name.split("\t")[0].strip()
        if not name or name == "/dev/null" or name in out:
            continue
        out.append(name)
    return out
