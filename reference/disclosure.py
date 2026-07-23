#!/usr/bin/env python3
"""SCPE LEVEL 1 — the AI-disclosure signal detector.

Zero-friction entry point: no envelope, no signing key, no GitHub key fetch. Given the
free text a contributor already writes (a PR body and/or the commit messages of a
range), this module answers exactly one question — did they disclose AI use at all,
in either of the two shapes real projects already require today:

  * a commit-trailer, e.g. OpenSSL's `Assisted-by: <tool>` (or a bare "none"/"no" to
    explicitly disclose that NO AI was used — that is still a disclosure);
  * a PR-template checkbox, e.g. MicroPython's "I used generative AI" /
    "I did not use generative AI".

It does NOT judge whether the disclosure is honest (see SPEC.md §2, THREAT_MODEL.md) —
only whether the signal is present, and in which form.

Like reference/producer.py and reference/standalone/verify_envelope.py this is a
small, self-contained, stdlib-only module: no imports beyond the standard library,
no `eval`/`exec`, no shell-out. Every input here is UNTRUSTED (a stranger's PR body
and commit messages), so parsing is defensive throughout:

  * inputs are truncated to MAX_LEN before any regex runs, and non-str input is
    coerced to "" rather than raising, so a hostile/oversized payload cannot be used
    to exhaust memory or CPU;
  * every pattern is anchored per-line (`^...$`, MULTILINE) with no nested/overlapping
    quantifiers, so matching stays linear in the input size — no catastrophic
    backtracking (ReDoS) on adversarial input;
  * a match only ever extracts a substring; nothing here is ever passed to `eval`,
    `exec`, a shell, or a template engine, so injected shell metacharacters, HTML,
    or control characters in a disclosure value are inert — they come back as inert
    data, never as code.
"""
from __future__ import annotations

import re

# Never regex-scan more than this many characters of a single untrusted source (a PR
# body or one commit message) — bounds CPU/memory regardless of how large the input is.
MAX_LEN = 20_000
# Never scan more than this many lines when looking for a checkbox — same rationale,
# expressed in lines instead of characters for the line-oriented checkbox scan.
MAX_LINES = 2_000

# `Assisted-by:` / `Assisted-By:` / `ASSISTED-BY:` ... — case-insensitive, one per
# line, value = the rest of the line. `.` does not match a newline by default, so a
# value can never smuggle a second line/trailer past this pattern.
_TRAILER_RE = re.compile(r"^[ \t]*assisted-by[ \t]*:[ \t]*(.*?)[ \t]*$", re.IGNORECASE | re.MULTILINE)

# A PR-template checkbox line, e.g. "- [x] I used generative AI" / "- [x] I did not
# use generative AI". Only a CHECKED box (`[x]`/`[X]`) counts as a signal — an
# unchecked template line means the contributor never filled it in.
_CHECKBOX_NOT_USED_RE = re.compile(
    r"^[ \t]*-[ \t]*\[[xX]\][ \t]*i[ \t]+(?:did[ \t]+not|have[ \t]+not|haven't)[ \t]+"
    r"use[d]?[ \t]+(?:generative[ \t]+)?ai\b",
    re.IGNORECASE,
)
_CHECKBOX_USED_RE = re.compile(
    r"^[ \t]*-[ \t]*\[[xX]\][ \t]*i[ \t]+(?:have[ \t]+)?used[ \t]+(?:generative[ \t]+)?ai\b",
    re.IGNORECASE,
)


def _bounded(text) -> str:
    """Coerce to str and truncate — the one gate every untrusted source passes through
    before it ever reaches a regex."""
    if not isinstance(text, str):
        return ""
    return text[:MAX_LEN]


def _normalize_value(value: str) -> str:
    """A trailer that explicitly says no AI was used ("none"/"no"/"n/a"/empty) is still
    a disclosure — normalize its value to the canonical "none" rather than echoing
    whatever casing/spelling the contributor used."""
    v = value.strip()
    return "none" if v.lower() in ("", "none", "no", "n/a", "nil") else v


def _find_trailer(text) -> str | None:
    """The LAST `Assisted-by:` trailer in `text`, normalized — or None if there isn't
    one. Last-wins: if a contributor amends/overrides an earlier trailer, the final
    line is the one that stands, matching how git trailers are conventionally read."""
    matches = _TRAILER_RE.findall(_bounded(text))
    return _normalize_value(matches[-1]) if matches else None


def _find_checkbox(text) -> tuple[str, str] | None:
    """The first checked disclosure checkbox in `text`, scanned line-by-line (bounded
    by MAX_LINES) so a pathological single "line" longer than MAX_LEN was already
    truncated by `_bounded` before we ever split it. Returns (form, value) or None."""
    for line in _bounded(text).splitlines()[:MAX_LINES]:
        if _CHECKBOX_NOT_USED_RE.match(line):
            return ("checkbox", "none")
        if _CHECKBOX_USED_RE.match(line):
            return ("checkbox", "ai")
    return None


def detect_disclosure(pr_body: str = "", commit_messages: list[str] | None = None) -> dict:
    """Detect the AI-disclosure signal for one contribution.

    Args:
        pr_body: the pull request description (untrusted).
        commit_messages: the commit messages of the PR's range, most-recent-last if
            known (untrusted); order only matters as a tie-breaker (see below).

    Returns:
        {"present": bool, "form": "trailer" | "checkbox" | "none", "value": str}

        `present` is True whenever a recognized signal exists at all — including an
        explicit "no AI was used" trailer/checkbox, since that IS a disclosure, just
        a negative one. `value` is the free-text tool/model name for a trailer (or
        "none"/"ai" for a checkbox), never executed or interpreted — pure data.

    Precedence when more than one signal is present (checked in this order, first
    match wins): the LAST `Assisted-by:` trailer across `commit_messages` (closest to
    the actual authored work), then a trailer in `pr_body`, then a checked PR-template
    checkbox in `pr_body`. Trailers outrank the checkbox because a trailer is a
    specific, machine-conventional claim (OpenSSL-style); the checkbox is a coarser,
    template-driven signal (MicroPython-style).
    """
    for msg in reversed(commit_messages or []):
        value = _find_trailer(msg)
        if value is not None:
            return {"present": True, "form": "trailer", "value": value}

    value = _find_trailer(pr_body)
    if value is not None:
        return {"present": True, "form": "trailer", "value": value}

    checkbox = _find_checkbox(pr_body)
    if checkbox is not None:
        form, value = checkbox
        return {"present": True, "form": form, "value": value}

    return {"present": False, "form": "none", "value": ""}


if __name__ == "__main__":  # pragma: no cover — manual/local use only
    import json
    import sys

    body = sys.stdin.read() if not sys.stdin.isatty() else ""
    print(json.dumps(detect_disclosure(pr_body=body)))
