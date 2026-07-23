"""Plain-text confirmation labels — the ASCII twin of the site's spec-label card.

A label is a standardized, monospace summary that rides WITH an artifact (paste it in a
PR/issue/commit, or save it beside the .zip) so a human can confirm the key facts by eye.
It states a CLAIM plus how to verify it. The green "VERIFIED" receipt is only ever emitted
by the OWNER after a real `verify` — a sender never self-asserts verification.

PURE ASCII by design: the label must render identically in a Windows cp1252 console, a
plain terminal, a git commit message, and a GitHub comment — no box-drawing, no ·/→/✓/…
that a legacy codec turns into mojibake. Deterministic and offline: it renders from an
already-parsed envelope/attestation with no network call, so the same artifact always
renders the same label and a tampered artifact renders a different one.
"""
from __future__ import annotations

from scpe.envelope import Envelope

_W = 62          # total line width, borders included
_INNER = _W - 4  # usable text width inside "| " ... " |"


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


def _count(diff: str) -> tuple[int, int]:
    add = sum(1 for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++"))
    rem = sum(1 for ln in diff.splitlines() if ln.startswith("-") and not ln.startswith("---"))
    return add, rem


def _repo_short(url: str) -> str:
    return url.replace("https://", "").replace("http://", "").rstrip("/")


def contribution_label(env: Envelope, *, filename: str = "envelope.zip", risk: str = "") -> str:
    """The CONTRIBUTION claim label that rides with an envelope. States who is credited and
    how the owner confirms it — never asserts 'verified' (that is the owner's step). `risk` is
    the caller-computed deterministic band (seal.risk_band) — passed in to avoid a seal<->label
    import cycle; the owner recomputes it anyway, so it is a hint, not a trusted claim."""
    m = env.manifest
    added = removed = 0
    files: set[str] = set()
    for p in env.pieces:
        a, r = _count(p.diff)
        added += a
        removed += r
        files.update(p.target_files)
    n = len(env.pieces)

    if m.sig_method == "ssh-github" and m.github_login:
        who = f"@{m.github_login}  (github.com/{m.github_login})"
        signed = "signed by    an SSH key on that GitHub account"
        claim = [
            "CLAIM - confirm it yourself:",
            f"  uvx --from scpe-protocol scpe verify {filename} --repo .",
            f"  checks the signature vs github.com/{m.github_login}.keys",
        ]
    else:  # legacy / unsigned identity
        who = f"{m.sender_name} <{m.sender_email}>"
        signed = "signed by    (no GitHub identity - legacy envelope)"
        claim = ["CLAIM - confirm it yourself:",
                 f"  uvx --from scpe-protocol scpe verify {filename} --repo ."]

    lines = [
        _top("CONTRIBUTION"),
        _row(),
        _row(f"repo         {_repo_short(m.repo_url)}"),
        _row(f"base         {m.base_sha[:7]}"),
        _row(f"contributor  {who}"),
        _row(signed),
        _row(f"changes      {n} piece(s),  +{added} / -{removed},  {len(files)} files"),
        *([_row(f"risk         {risk}  (recompute to confirm)")] if risk else []),
        _row(),
        *[_row(c) for c in claim],
        _row(),
        _bottom("cc/spec-01 - claim, not proof"),
    ]
    return "\n".join(lines)


def verified_receipt(env: Envelope, *, commit: str = "", owner: str = "",
                     identity_ok: bool = True, tests_ok: bool | None = None) -> str:
    """The OWNER's receipt, emitted only AFTER a real verify/apply. Asserts what the owner
    actually confirmed on their machine: identity checked, tests run, commit authored."""
    m = env.manifest
    who = f"@{m.github_login}" if m.github_login else m.sender_name
    lines = [_top("VERIFIED"), _row(), _row(f"{who}  ->  {_repo_short(m.repo_url)}")]
    if m.github_login:
        mark = "OK" if identity_ok else "FAILED"
        lines.append(_row(f"identity     verified vs github.com/{m.github_login}.keys  [{mark}]"))
    else:
        lines.append(_row("identity     (legacy - no GitHub identity)"))
    if tests_ok is not None:
        lines.append(_row(f"tests        {'passed in sandbox  [OK]' if tests_ok else 'FAILED'}"))
    if commit:
        lines.append(_row(f"merged       {commit[:7]}, authored by {who}"))
    lines += [_row(), _bottom(f"verified by {owner or 'the owner'}")]
    return "\n".join(lines)


def attestation_label(statement: dict, *, filename: str = "attestation.json") -> str:
    """A label for a signed in-toto/DSSE attestation: a repo audited at a commit, with a
    verdict, verifiable with standard tooling. Self-certifying (the artifact is signed), so
    unlike a contribution label it points at independent verification."""
    subj = statement.get("subject") or [{}]
    name = subj[0].get("name", "") if subj else ""
    digest = ""
    if subj and isinstance(subj[0].get("digest"), dict):
        digest = next(iter(subj[0]["digest"].values()), "")
    pred = statement.get("predicate", {}) if isinstance(statement.get("predicate"), dict) else {}
    verdict = pred.get("verdict", "?")
    findings = pred.get("findingsCount", pred.get("findings", ""))
    # Prefer the verifiable GitHub auditor identity when present (surfaced as @<login>);
    # otherwise fall back to whatever `auditor` carries — a dict {name,email,...} or a bare
    # string — so the label renders for both new and legacy attestations.
    login = pred.get("github_login") or ""
    if login:
        auditor_row = f"auditor      @{login}"
    else:
        auditor = pred.get("auditor", pred.get("signer", ""))
        if isinstance(auditor, dict):
            auditor = auditor.get("name") or auditor.get("email") or ""
        auditor_row = f"auditor      {auditor[:40]}" if auditor else "auditor      (see signature)"
    lines = [
        _top("ATTESTATION"),
        _row(),
        _row(f"repo         {_repo_short(name)}" + (f" @ {digest[:7]}" if digest else "")),
        _row(auditor_row),
        _row(f"verdict      {verdict}" + (f",  {findings} findings" if findings != "" else "")),
        _row("format       in-toto/DSSE/ed25519 (verify w/ cosign)"),
        _row(),
        _row("VERIFY independently:"),
        _row(f"  uvx --from scpe-protocol scpe verify-attest {filename}"),
        _row(),
        _bottom("cc/spec-01 - signed audit"),
    ]
    return "\n".join(lines)
