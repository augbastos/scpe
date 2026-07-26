"""The rendered PR comment: tolerant of old input, hostile to injected markdown, and
honest about which key anchored the pass.

Rendering moved into the UNTRUSTED job (the sealer pre-renders, the trusted job pastes).
That does not lower the trust level of the CONTENT — the trusted job already posted a
string derived from attacker-controlled data, which is exactly what level 1 does today —
but it does make escaping this renderer's job rather than nobody's. Two of the values it
interpolates (`flags[].file`, `flags[].added`) are raw bytes from a stranger's diff.
"""
from __future__ import annotations

import re

import pytest

from scpe.seal import render_comment

FENCE_LINE = re.compile(r"^\s*(`{3,})\s*[A-Za-z0-9_-]*\s*$")


def _results(**over) -> dict:
    base = {
        "status": "verified", "verified": True, "login": "octocat", "subject": "octocat",
        "provider": "github", "band": "LOW", "flags": [], "matched": [],
        "rules_checked": 13, "added": 3, "removed": 1, "files": ["calc.py"],
        "tests": {"ran": True, "ok": True, "summary": "1 passed"},
        "provenance": "AI-assisted (one-line fix)", "hook": "",
        "key_source": "forge", "profile": None, "attestations": [],
        "spec_version": "scpe/0.1", "detail": "", "diff_source": "git",
        "require": True, "gate_pass": True, "level": "2",
    }
    base.update(over)
    return base


def _outside_fences(markdown: str) -> str:
    """Everything a GitHub comment renders as MARKDOWN — i.e. with fenced code blocks
    removed. Anything an attacker put in the diff must end up inside a fence (inert) or
    be stripped; if it shows up here it is live formatting in a maintainer's PR."""
    out: list[str] = []
    fence: str | None = None
    for line in markdown.splitlines():
        m = FENCE_LINE.match(line)
        if fence is None:
            if m:
                fence = m.group(1)
                continue
            out.append(line)
        elif m and len(m.group(1)) >= len(fence) and line.strip() == m.group(1):
            fence = None
    assert fence is None, "a fenced block was opened and never closed"
    return "\n".join(out)


# ---- tolerance: an old results.json must still render -------------------------

def test_render_survives_a_results_json_with_only_a_status():
    """A repository pinned to an old Action tag can hand this renderer a file written by
    the previous package. It must degrade to a thin comment, not raise inside the trusted
    job — the failure mode of a crash there is a red check on a stranger's PR."""
    out = render_comment({"status": "unattested"})
    assert isinstance(out, str) and out.strip()


def test_render_survives_an_empty_dict():
    assert render_comment({}).strip()


# ---- injection: a diff line is attacker input ---------------------------------

HOSTILE_FILE = "src/a`` `.py\n```\n### pwned by the file name\n"
HOSTILE_ADDED = "```\n<img src=x onerror=alert(1)>\n### pwned by the added line"


def test_a_hostile_flag_cannot_break_out_of_the_code_fence():
    results = _results(
        band="HIGH", matched=["subprocess"],
        flags=[{"pattern": "subprocess", "file": HOSTILE_FILE, "line": 1,
                "added": HOSTILE_ADDED}])
    comment = render_comment(results)
    live = _outside_fences(comment)

    assert "### pwned" not in live, "an added source line injected a heading into the comment"
    assert "<img" not in live, "raw HTML from a diff reached the rendered part of the comment"
    # `_clip` only truncates; it never removed the backticks that end a fence. Whatever the
    # fix is (stripping them, or opening a longer fence), the block must stay one block.
    assert comment.count("\n```\n### pwned") == 0


def test_a_hostile_subject_cannot_inject_markdown_into_the_glance_line():
    """The pill and the one-line verdict print the contributor's name outside any fence.
    The name is a §8 `subject`, charset-checked by the verifier — but the renderer also
    runs on UNVERIFIED input, where nothing has checked it yet."""
    comment = render_comment(_results(verified=False, status="signature-invalid",
                                      login="a](https://evil/)![x", subject="a](https://evil/)![x"))
    live = _outside_fences(comment)
    assert "https://evil" not in live


def test_rendered_lines_stay_within_the_box():
    """The seal box is fixed-width ASCII; a newline smuggled through a flag would tear it
    open. Every non-empty line inside the fence is exactly the box width or shorter."""
    comment = render_comment(_results(
        band="HIGH", flags=[{"pattern": "exec", "file": HOSTILE_FILE, "line": 2,
                             "added": HOSTILE_ADDED}]))
    in_fence = False
    for line in comment.splitlines():
        if FENCE_LINE.match(line):
            in_fence = not in_fence
            continue
        if in_fence and line.strip():
            assert len(line) <= 62, f"box line escaped its width: {line!r}"


# ---- disclosure: not every `verified` is the same claim ------------------------

def test_a_bundled_key_never_renders_like_a_forge_key():
    """`verified` with `key_source: "bundled"` means the bytes match a key that travelled
    WITH them — chosen by the submitter. A reader who cannot tell that apart from a key
    published on the named account is being shown a stronger claim than the one that was
    proved (verify_envelope.py's own docstring exists to prevent exactly this)."""
    forge = render_comment(_results(key_source="forge"))
    bundled = render_comment(_results(key_source="bundled"))
    assert forge != bundled
    assert "bundled" in bundled.lower()


def test_the_flag_key_is_disclosed_too():
    """`--keys` (an operator-supplied file, e.g. an air-gapped runner) is a third distinct
    anchor and must read as itself, not as a forge-backed pass."""
    flagged = render_comment(_results(key_source="flag"))
    assert flagged != render_comment(_results(key_source="forge"))


@pytest.mark.parametrize("status", ["unattested", "tampered", "signature-invalid",
                                    "identity-unverifiable"])
def test_an_unverified_status_is_named_in_the_comment(status):
    """"not-verified" told a maintainer nothing they could act on. The specific §8 status
    is the whole point of the rewrite, so it has to reach the comment."""
    comment = render_comment(_results(status=status, verified=False, key_source=None,
                                      gate_pass=False))
    assert status in comment
    assert "UNVERIFIED" in comment or "unverified" in comment.lower()
