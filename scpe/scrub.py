"""Secret scrubbing — one choke point every outbound text passes through.
Ported in spirit from the author's earlier digest-scrubber work (MIT)."""
from __future__ import annotations

import re

_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    # Broader GitHub token family: ghp_ (personal), gho_ (oauth), ghs_ (server-to-server),
    # ghr_ (refresh), ghu_ (user-to-server) — all share the `gh[type]_<token>` shape.
    re.compile(r"\bgh[opsru]_[A-Za-z0-9]{20,}"),
    # GitLab personal/project/group access tokens.
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),
    # AWS access key ids: AKIA (long-term) and ASIA (STS temporary).
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    # Stripe uses an UNDERSCORE (sk_live_/sk_test_/rk_live_…), so the sk- rule above misses it.
    re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    # Google API keys.
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    # Slack bot/user/app/refresh tokens.
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"),
    # Slack app-level tokens (distinct shape from the xox... family above).
    re.compile(r"\bxapp-[0-9]-[A-Za-z0-9-]{10,}"),
    # AWS secret access key given by name (the 40-char value form is caught by the entropy rule).
    re.compile(r"(?i)\baws_secret_access_key\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    # JWTs: three dot-separated base64url segments starting with the `eyJ` (`{"`) header.
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    # Name-based secret assignment. `\w*` BEFORE the keyword catches compound identifiers
    # like `client_secret` / `db_password` / `session_secret_key` (the bare keyword alone,
    # anchored right after `\b`, missed anything with a prefix — a real gap: `client_secret`
    # never matched `\bsecret`, since `_` is a word char and there's no boundary there).
    re.compile(r"(?i)\b\w*(?:password|passwd|secret|token|key)\s*[:=]\s*[\"']?[^\s\"']{4,}[\"']?"),
    # High-entropy fallback: a >=40-char base64-ish blob mixing lower+upper+digit — catches AWS
    # secret keys and unknown provider tokens. The lookaheads spare all-lowercase git SHAs and prose.
    re.compile(r"(?<![A-Za-z0-9+/])"
               r"(?=[A-Za-z0-9+/]*[a-z])(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*\d)"
               r"[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])"),
]


def scrub(text: str) -> str:
    for pat in _PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text
