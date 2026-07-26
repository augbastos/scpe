"""Verification seal: a decision-first, risk-adaptive summary of a contribution, rendered
for a GitHub PR comment (a shields.io pill + a pure-ASCII box) and reused on the site/README.
Pure and offline — renders from already-parsed data, never a network call.

PURE ASCII by design: the box must render identically in a Windows cp1252 console, a plain
terminal, a git commit message and a GitHub comment — no box-drawing, no ·/→/✓ that a legacy
codec turns into mojibake.

This module is also the ESCAPING BOUNDARY. Two of the values it interpolates — a flagged
file path and the added source line itself — are attacker-controlled text lifted verbatim
out of a contributor's diff, and the rendered markdown is posted by a job holding a write
token. So every untrusted value passes through `_safe` before it reaches a row, and the
code fence in `render_comment` is sized to be longer than the longest backtick run in what
it wraps. Truncation alone (the old behavior) is not escaping: a path containing ``` closed
the fence and let the rest of the line render as markdown.
"""
from __future__ import annotations

import re

from scpe.diffinfo import FILE_HEADER_RE as _HDR  # one definition of "what is a header"

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

# The COMPLETE, published rule set — no weights, no magic score. A rule "matches" when its
# literal pattern appears in an added source line; band = the highest-band rule that matched.
# `scpe seal --json` and docs/format.md expose this so an owner can reproduce every band.
#
# NOT PART OF THE PROTOCOL. SPEC.md defines no risk scan; this is an Action-layer triage aid
# that ships in the same package, and results.json / docs/format.md label it as such. It can
# never change a status: the verdict comes from the reference verifier alone.
RULES = ([{"name": n, "band": "HIGH", "matches": p} for n, p in _HIGH.items()]
         + [{"name": n, "band": "MED", "matches": p} for n, p in _MED.items()])
RULE_COUNT = len(RULES)


def risk_band(diff: str) -> dict:
    """Triage a unified diff's ADDED lines into LOW/MED/HIGH by a PUBLISHED, weightless rule set
    (see RULES) — not a magic score: band = the highest-band rule that literally matched an
    added line. Returns {band, flags (located), matched (rule names), rules_checked}. Still a
    TRIAGE AID, not a guarantee: a determined obfuscator can build a call dynamically and slip
    past ANY static scan, so LOW means 'no rule matched', never 'proven safe'. The owner's
    review, the tests, and re-verification are the real safeguards."""
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


# ------------------------------------------------------------------ the ASCII box engine

_W = 62          # total line width, borders included
_INNER = _W - 4  # usable text width inside "| " ... " |"

# Everything that is not printable 7-bit ASCII becomes '?'. Backtick and pipe are excluded
# too: the first would break out of the markdown fence the box is wrapped in, the second
# would fake a box border. This is a RENDERING sanitizer, so it is deliberately destructive
# — a value that cannot be shown safely is shown wrong-but-inert, never passed through.
_UNSAFE = re.compile(r"[^\x20-\x7e]|[`|]")


def _safe(text: object, limit: int = _INNER) -> str:
    """Neutralize an untrusted value for a fixed-width ASCII row.

    Applied to every value that originated in a contributor's diff or an unverified
    manifest. Collapses whitespace (so a newline cannot forge a new row), drops backticks
    (so the value cannot close the markdown fence around the box) and pipes (so it cannot
    forge a border), maps anything non-ASCII to '?', and caps the length."""
    s = " ".join(str(text).split())   # newlines/tabs/runs -> single spaces, FIRST, so a
    s = _UNSAFE.sub("?", s)           # line break reads as a space rather than as '?'
    return s[:limit]


def _clip(text: str) -> str:
    return text if len(text) <= _INNER else text[: _INNER - 3] + "..."


def _row(text: str = "") -> str:
    return "| " + _clip(text).ljust(_INNER) + " |"


def _top(kind: str) -> str:
    left = "--<+> scpe "
    right = f" {kind} --"
    mid = max(1, (_W - 2) - len(left) - len(right))
    return "+" + left + ("-" * mid) + right + "+"


def _bottom(tag: str) -> str:
    return "+" + f" {tag} ".rjust(_W - 2, "-") + "+"


# ------------------------------------------------------------------------- the seal itself

_BAND_COLOR = {"LOW": "2ea043", "MED": "d29922", "HIGH": "cf222e"}
_BAND_WORD = {"LOW": "VERIFIED / LOW RISK", "MED": "REVIEW / MED RISK",
              "HIGH": "REVIEW / HIGH RISK"}
_BADGE_CHARS = re.compile(r"[^A-Za-z0-9._-]")

# Which §8 step-4 anchor supplied the keys the verdict rests on, spelled out on the seal.
# All three can end in `verified` and they are NOT the same claim: a `bundled` key set was
# chosen by whoever submitted the package, so a pass there means "these bytes match a key
# that travelled with them", not "the named forge account signed this". Rendering the three
# identically would launder the weakest one into looking like the strongest, which is exactly
# what the verifier discloses key_source to prevent.
_KEY_ANCHOR = {
    "forge": ("forge - fetched live from the provider", ""),
    "bundled": ("bundled - self-anchored, NOT proof the forge", "account signed this"),
    "flag": ("flag - operator-supplied key file (--keys)", ""),
}


def _badge_text(text: str, fallback: str) -> str:
    """A shields.io path segment. Stricter than `_safe`: the value lands inside a URL inside
    a markdown image, so anything outside [A-Za-z0-9._-] is dropped rather than replaced."""
    out = _BADGE_CHARS.sub("", str(text))[:39]
    return out or fallback


def pr_pill(band: str, login: str, verified: bool, tests_ok: bool) -> str:
    """The colored glance line. Each badge reflects REAL state: the identity badge says
    'verified' (green) ONLY when the signature actually verified, else 'UNVERIFIED'
    (red) — it describes the person, never the code's safety (that is the risk badge)."""
    band = band if band in _BAND_COLOR else "NONE"
    band_color = _BAND_COLOR.get(band, "8b949e")
    who = _badge_text(login, "unknown")
    id_txt, id_color = ("verified", "2ea043") if verified else ("UNVERIFIED", "cf222e")
    tests_txt, t_color = ("tests_green", "2ea043") if tests_ok else ("tests_FAILED", "cf222e")
    return (f"### scpe "
            f"![](https://img.shields.io/badge/{band}_RISK-{band_color}) "
            f"![](https://img.shields.io/badge/@{who}-{id_txt}-{id_color}) "
            f"![](https://img.shields.io/badge/{tests_txt}-{t_color})")


def pr_summary_line(band: str, verified: bool, tests_ok: bool) -> str:
    """The one-line glance a maintainer reads in 5 seconds — the whole verdict, no scrolling.
    The full box lives behind a <details> in the comment."""
    idc = "identity verified" if verified else "identity UNVERIFIED"
    tc = "tests passed" if tests_ok else "tests FAILED"
    return f"**{idc}** - **{tc}** - **risk {_safe(band) or 'n/a'}** (rule-based, reproducible)"


def pr_seal(*, login, verified, profile, band, flags, added, removed, files,
            tests_ok, tests_summary, provenance, hook="", rules_checked=RULE_COUNT,
            key_source=None, status="") -> str:
    """Render the fixed-width seal box. `profile` is the advisory SPEC §13 label, surfaced
    verbatim and never dispatched on; `key_source` is the §8 step-4 anchor, rendered on its
    own row because the verdict word alone cannot tell a forge-backed pass from a
    self-anchored one."""
    # Shape-tolerant by design: this also renders a results.json written by an older tag of
    # the Action, or one a hostile PR influenced the contents of. A wrong TYPE must degrade
    # to a blank row, never to a traceback inside the job that posts the comment.
    band = band if isinstance(band, str) else ""
    flags = [f for f in flags if isinstance(f, dict)] if isinstance(flags, list) else []
    files = files if isinstance(files, (list, tuple)) else []
    lines = [_top(_BAND_WORD.get(band, "REVIEW")), _row()]
    if band == "HIGH" and flags:
        f = flags[0]
        lines.append(_row(f"!! adds {_safe(f.get('pattern'), 20)} in "
                          f"{_safe(f.get('file'), 24)}:{_safe(f.get('line'), 8)}"))
        lines.append(_row("   confirm this is intended before you merge"))
        lines.append(_row())
    if hook:
        lines.append(_row(f">> {_safe(hook, 52)}"))
        lines.append(_row())
    who = (f"@{_safe(login, 30)}" if login else "(no signed identity)")
    who += "   identity verified" if verified else "   UNVERIFIED"
    matched = sorted({str(f.get("pattern")) for f in flags})
    # Explainable, never a magic score: N rules checked, which matched, reproducible.
    risk_detail = (f"0 of {rules_checked} rules matched" if not matched
                   else f"{len(matched)}/{rules_checked} rules: " + _safe(", ".join(matched), 28))
    lines += [
        _row(f"contributor  {who}"),
        _row(f"change       +{added} / -{removed},  {len(files)} files"),
        _row(f"risk         {_safe(band, 8) or 'n/a'}   ({risk_detail})"),
        _row(f"tests        {_safe(tests_summary, 30)}   " + ("[OK]" if tests_ok else "[FAILED]")),
        _row(f"made with    {_safe(provenance, 44) or 'undisclosed'}"),
    ]
    anchor, anchor_more = _KEY_ANCHOR.get(str(key_source), ("", ""))
    if anchor:
        lines.append(_row(f"keys         {anchor}"))
        if anchor_more:
            lines.append(_row(f"             {anchor_more}"))
    if profile:
        # SPEC §13.2: surfaced verbatim, never dispatched on — a label, not a capability.
        lines.append(_row(f"profile      {_safe(profile, 32)}  (advisory, not checked)"))
    if status and not verified:
        # The specific §8 reason, so a non-verified seal is actionable instead of just red.
        lines.append(_row(f"status       {_safe(status, 44)}"))
    lines += [_row(), _bottom("rule-based, reproducible - a report, not an approval")]
    return "\n".join(lines)


def _fence_for(body: str) -> str:
    """A code fence at least one backtick longer than the longest run inside `body`.

    `_safe` already strips backticks from every untrusted value, so this is the second
    lock on the same door: if a future row forgets to sanitize, the fence still closes
    where it should and the contributor's text cannot become markdown in a comment posted
    with a write token."""
    longest = max((len(m) for m in re.findall(r"`+", body)), default=0)
    return "`" * max(3, longest + 1)


def render_comment(results: dict) -> str:
    """The PR comment, SHORT by default: the shields pill + a one-line verdict a maintainer
    reads in 5 seconds. The full ASCII seal box is collapsed behind <details> so it never
    becomes wall-of-text spam (the #1 reason a maintainer removes a bot).

    Every field is read with `.get`: this renders results.json produced by an OLDER pinned
    tag of the Action just as well as today's, and a results.json carrying only a status
    must still produce a comment rather than raise inside a CI job."""
    tests = results.get("tests")
    tests = tests if isinstance(tests, dict) else {}
    tests_ok = bool(tests.get("ok"))
    login = results.get("login") or results.get("subject") or ""
    login = login if isinstance(login, str) else ""
    verified = bool(results.get("verified"))
    band = results.get("band") or ""
    band = band if isinstance(band, str) else ""
    box = pr_seal(
        login=login, verified=verified,
        profile=results.get("profile") or "",
        band=band, flags=results.get("flags") or [],
        added=results.get("added", 0), removed=results.get("removed", 0),
        files=results.get("files") or [], tests_ok=tests_ok,
        tests_summary=tests.get("summary", "not run"),
        provenance=results.get("provenance", ""), hook=results.get("hook", ""),
        rules_checked=results.get("rules_checked") or RULE_COUNT,
        key_source=results.get("key_source"), status=results.get("status", ""))
    fence = _fence_for(box)
    comment = (
        pr_pill(band, login, verified, tests_ok) + "\n\n"
        + pr_summary_line(band, verified, tests_ok)
        + f"\n\n<details><summary>full report</summary>\n\n{fence}\n" + box + f"\n{fence}\n\n"
        + "Risk is a published, weightless rule set and an Action-layer aid, not part of "
        + "the protocol — reproduce every band with `scpe seal --json`.\n</details>")
    detail = results.get("detail")
    if detail and not verified:
        comment += f"\n\n_{_safe(detail, 200)}_"
    # A results.json written by an older tag may still carry the retired AI re-check field;
    # render it rather than dropping it, so a mixed-version pipeline loses no information.
    ai = results.get("ai_recheck")
    if isinstance(ai, dict) and ai.get("verdict"):
        comment += f"\n\n_AI re-check ({_safe(ai.get('backend', ''), 40)}): " \
                   f"{_safe(ai['verdict'], 120)}_"
    return comment
