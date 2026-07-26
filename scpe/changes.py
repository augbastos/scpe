"""changes — a human-readable summary of what a contributor modified in an envelope,
so the owner can read the changes without reading the raw diff by hand.

Read-only and side-effect-free: it unpacks the envelope and renders. No clone, no
sandbox, no backend call. Safe to point at an UNTRUSTED envelope (unpack already
caps decompressed size, rejects duplicate piece ids, and sanitizes free text)."""
from __future__ import annotations

import re

from scpe.envelope import Envelope, unpack
from scpe.seal import risk_band

# git puts the enclosing definition in the hunk header: `@@ -a,b +c,d @@ def foo(...)`.
# Also catch added/removed definition lines directly. Language-agnostic-ish: def/class
# (Python), fn (Rust), func (Go), function (JS/TS).
_HUNK_DEF = re.compile(r"^@@.*@@\s*(?:pub\s+|async\s+|export\s+|default\s+)*"
                       r"(?:def|class|fn|func|function)\s+([A-Za-z_][\w]*)", re.M)
_LINE_DEF = re.compile(r"^[+-]\s*(?:pub\s+|async\s+|export\s+|default\s+)*"
                       r"(?:def|class|fn|func|function)\s+([A-Za-z_][\w]*)", re.M)


def count_diff_lines(diff: str) -> tuple[int, int]:
    """Added/removed source lines in a unified diff.

    Counts only INSIDE hunks. The obvious shortcut — skip anything starting with
    '+++'/'---' — miscounts real edits: adding a line whose own content starts with
    '++' produces '+++...' and would be silently dropped as if it were a file header.
    Tracking hunk state is the only way to tell a header from content that looks like
    one, because inside a hunk every line is prefixed and a header cannot appear.

    Single source of truth: scpe.inspect imports this rather than keeping its own copy.
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


_counts = count_diff_lines


def _touched_symbols(diff: str) -> list[str]:
    names: list[str] = []
    for m in list(_HUNK_DEF.finditer(diff)) + list(_LINE_DEF.finditer(diff)):
        if m.group(1) not in names:
            names.append(m.group(1))
    return names


def summarize(envelope_path) -> str:
    """Render a 'Changes' digest of an envelope. Propagates EnvelopeFormatError for a
    malformed/oversized/non-zip file (the caller reports it)."""
    env: Envelope = unpack(envelope_path)
    m = env.manifest
    has_briefing = bool(env.briefing_md and env.briefing_md.strip())

    out = ["Changes in this contribution",
           f"  from:   {m.sender_name} <{m.sender_email}>",
           f"  repo:   {m.repo_url} @ {m.base_sha[:8]}",
           f"  pieces: {len(env.pieces)}",
           ""]

    if has_briefing:
        out.append("Summary from the contributor:")
        out.append(env.briefing_md.strip())
        out.append("")

    total_add = total_rem = 0
    bands: list[str] = []
    for i, p in enumerate(env.pieces, 1):
        added, removed = _counts(p.diff)
        total_add += added
        total_rem += removed
        files = ", ".join(p.target_files) or "(no files declared)"
        out.append(f"{i}. {p.title}   (+{added}/-{removed})")
        if p.rationale and p.rationale.strip():
            out.append(f"   why:     {p.rationale.strip()}")
        out.append(f"   files:   {files}")
        syms = _touched_symbols(p.diff)
        if syms:
            out.append(f"   changed: {', '.join(syms)}")
        # Deterministic risk, RECOMPUTED from the diff here (never a stored claim the
        # contributor could fake). A triage aid, not a guarantee — see seal.risk_band.
        risk = risk_band(p.diff)
        bands.append(risk["band"])
        if risk["band"] != "LOW":
            where = ", ".join(sorted({f"{f['pattern']} ({f['file']}:{f['line']})"
                                      for f in risk["flags"]}))
            out.append(f"   risk:    {risk['band']} - {where}")

    out.append("")
    overall = "HIGH" if "HIGH" in bands else ("MED" if "MED" in bands else "LOW")
    out.append(f"Total: {len(env.pieces)} piece(s), +{total_add}/-{total_rem}, "
               f"risk {overall} across the envelope.")
    if not has_briefing:
        out.append("(No written summary was included, so the digest above was generated from "
                   "the diff. A scpe `contribute` run fills this in with the AI's "
                   "per-change explanation.)")
    return "\n".join(out)
