"""Verification seal: a decision-first, risk-adaptive summary of a contribution, rendered
for a GitHub PR comment (a shields.io pill + a pure-ASCII box) and reused on the site/README.
Pure and offline — renders from already-parsed data, never a network call."""
from __future__ import annotations

import re

from scpe.label import _bottom, _row, _top  # reuse the one box engine

# Directly executes / derives / shells out. A determined obfuscator can hide these behind
# dynamic construction — see the MED "obfuscation smells" below — so this scan SURFACES common
# danger, it does not GUARANTEE safety.
_HIGH = {"os.system": r"os\.system", "subprocess": r"subprocess", "eval": r"eval\(",
         "exec": r"exec\(", "__import__": r"__import__"}
# Network/encoding reach, PLUS obfuscation smells (string/byte building rare in benign code and
# typically used to hide a dangerous call) — their presence RAISES risk, never lowers it, so a
# getattr(os, chr(...))(...) style bypass lands at MED ("look here"), not LOW/green.
_MED = {"socket": r"socket", "urllib": r"urllib", "requests": r"requests",
        "base64": r"base64", "chr": r"\bchr\(", "fromhex": r"\.fromhex\(",
        "hex-escape": r"\\x[0-9a-fA-F]{2}", "b64decode": r"b64decode"}
# A file header is `+++ ` (three plus signs + a SPACE); an ADDED source line that merely starts
# with '+' (e.g. `+++counter`) has no space at index 3, so it is NOT a header and must be
# scanned. Requiring the space is what distinguishes the two.
_HDR = re.compile(r"^\+\+\+ (?:b/)?(.+)$")

# The COMPLETE, published rule set — no weights, no magic score. A rule "matches" when its
# literal pattern appears in an added source line; band = the highest-band rule that matched.
# `scpe seal --json` and docs/format.md expose this so an owner can reproduce every band.
RULES = ([{"name": n, "band": "HIGH", "matches": p} for n, p in _HIGH.items()]
         + [{"name": n, "band": "MED", "matches": p} for n, p in _MED.items()])
RULE_COUNT = len(RULES)


def risk_band(diff: str) -> dict:
    """Triage a unified diff's ADDED lines into LOW/MED/HIGH by a PUBLISHED, weightless rule set
    (see RULES) — not a magic score: band = the highest-band rule that literally matched an
    added line. Returns {band, flags (located), matched (rule names), rules_checked}. Still a
    TRIAGE AID, not a guarantee: a determined obfuscator can build a call dynamically and slip
    past ANY static scan, so LOW means 'no rule matched', never 'proven safe'. The owner's
    review, the sandbox tests, and re-verification are the real safeguards."""
    flags: list[dict] = []
    cur_file = ""
    added_no = 0
    for line in diff.splitlines():
        m = _HDR.match(line)
        if m:  # a real `+++ ` file header (space-delimited) — not an added line
            cur_file, added_no = m.group(1), 0
            continue
        if not line.startswith("+"):  # context/removed line, or the `--- ` header
            continue
        added_no += 1
        body = line[1:]  # strip exactly the one diff '+' marker; the rest is source
        for name, pat in {**_HIGH, **_MED}.items():
            if re.search(pat, body):
                flags.append({"pattern": name, "file": cur_file, "line": added_no,
                              "added": body.strip()[:80]})
    band = "LOW"
    if any(f["pattern"] in _MED for f in flags):
        band = "MED"
    if any(f["pattern"] in _HIGH for f in flags):
        band = "HIGH"
    return {"band": band, "flags": flags,
            "matched": sorted({f["pattern"] for f in flags}), "rules_checked": RULE_COUNT}


_BAND_COLOR = {"LOW": "2ea043", "MED": "d29922", "HIGH": "cf222e"}
_BAND_WORD = {"LOW": "VERIFIED / LOW RISK", "MED": "REVIEW / MED RISK",
              "HIGH": "REVIEW / HIGH RISK"}


def pr_pill(band: str, login: str, verified: bool, tests_ok: bool) -> str:
    """The colored glance line. Each badge reflects REAL state: the identity badge says
    'verified' (green) ONLY when the GitHub signature actually verified, else 'UNVERIFIED'
    (red) — it describes the person, never the code's safety (that is the risk badge)."""
    band_color = _BAND_COLOR.get(band, "8b949e")
    id_txt, id_color = ("verified", "2ea043") if verified else ("UNVERIFIED", "cf222e")
    tests_txt, t_color = ("tests_green", "2ea043") if tests_ok else ("tests_FAILED", "cf222e")
    return (f"### scpe "
            f"![](https://img.shields.io/badge/{band}_RISK-{band_color}) "
            f"![](https://img.shields.io/badge/@{login}-{id_txt}-{id_color}) "
            f"![](https://img.shields.io/badge/{tests_txt}-{t_color})")


def pr_summary_line(band: str, verified: bool, tests_ok: bool) -> str:
    """The one-line glance a maintainer reads in 5 seconds — the whole verdict, no scrolling.
    The full box lives behind a <details> in the comment."""
    idc = "identity verified" if verified else "identity UNVERIFIED"
    tc = "tests passed" if tests_ok else "tests FAILED"
    return f"**{idc}** - **{tc}** - **risk {band}** (rule-based, reproducible)"


def pr_seal(*, login, verified, profile, band, flags, added, removed, files,
            tests_ok, tests_summary, provenance, hook="", rules_checked=RULE_COUNT) -> str:
    lines = [_top(_BAND_WORD.get(band, "REVIEW")), _row()]
    if band == "HIGH" and flags:
        f = flags[0]
        lines.append(_row(f"!! adds {f['pattern']} in {f['file']}:{f['line']}"))
        lines.append(_row("   confirm this is intended before you merge"))
        lines.append(_row())
    if hook:
        lines.append(_row(f">> {hook}"))
        lines.append(_row())
    who = f"@{login}" + ("     verified vs github .keys" if verified else "   UNVERIFIED")
    matched = sorted({f["pattern"] for f in flags})
    # Explainable, never a magic score: N rules checked, which matched, reproducible.
    risk_detail = (f"0 of {rules_checked} rules matched" if not matched
                   else f"{len(matched)}/{rules_checked} rules: " + ", ".join(matched))
    lines += [
        _row(f"contributor  {who}"),
        _row(f"change       +{added} / -{removed},  {len(files)} files"),
        _row(f"risk         {band}   ({risk_detail})"),
        _row(f"tests        {tests_summary}   " + ("[OK]" if tests_ok else "[FAILED]")),
        _row(f"made with    {provenance}"),
        _row(),
        _bottom("rule-based, reproducible - a report, not an approval"),
    ]
    return "\n".join(lines)
