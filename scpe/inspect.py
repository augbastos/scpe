"""Inspect — read an envelope and report what's inside WITHOUT running anything.

Pure and side-effect-free: it unpacks the zip, checks the signature, and summarizes
the pieces. Safe to point at an UNTRUSTED envelope — it never clones, never sandboxes,
never calls a backend. Parsing + a signature check is the whole attack surface, and
`envelope.unpack` already caps the decompressed size against a zip bomb."""
from __future__ import annotations

from scpe.envelope import unpack, verify_signature
from scpe.seal import risk_band


def _count_changes(diff: str) -> tuple[int, int]:
    """Added/removed source lines in a unified diff, EXCLUDING the '+++ '/'--- '
    file-header lines so the counts reflect real edits, not diff headers."""
    added = removed = 0
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return added, removed


def inspect_envelope(envelope_path) -> dict:
    """Parse an envelope and return a human/machine summary. Propagates
    EnvelopeFormatError for a malformed/oversized/non-zip file."""
    env = unpack(envelope_path)  # propagates EnvelopeFormatError
    m = env.manifest

    pieces = []
    bands = []
    all_flags = []
    for p in env.pieces:
        added, removed = _count_changes(p.diff)
        risk = risk_band(p.diff)  # recomputed from the diff, never a stored claim
        bands.append(risk["band"])
        all_flags += risk["flags"]
        pieces.append({
            "id": p.id,
            "title": p.title,
            "files": list(p.target_files),
            "added": added,
            "removed": removed,
            "risk_band": risk["band"],
        })
    overall_band = "HIGH" if "HIGH" in bands else ("MED" if "MED" in bands else "LOW")

    # provenance is attacker-controlled JSON; guard the .get so an untrusted
    # envelope with a non-dict provenance can't crash a pure inspection.
    prov = env.provenance if isinstance(env.provenance, dict) else {}

    key = m.sender_public_key
    return {
        "repo": m.repo_url,
        "base_sha": m.base_sha,
        "sender": f"{m.sender_name} <{m.sender_email}>",
        "sender_key": (key[:16] + "…") if key else "",
        # CLAIMED GitHub identity — inspect is pure/offline, so it never verifies against
        # GitHub here (that is `verify`'s job); it only surfaces what the envelope asserts.
        "github_login": m.github_login,
        "github_profile": f"https://github.com/{m.github_login}" if m.github_login else "",
        "identity_method": m.sig_method,  # "ssh-github" for identity envelopes, else ""
        "created_at": m.created_at,
        "protocol": m.protocol_version,
        "signature_valid": verify_signature(env),
        "backend": prov.get("backend"),
        # Deterministic risk over the diff (a triage aid recomputed on read, not a stored
        # claim). Full metrics like coverage/complexity are language-specific and deferred.
        "risk": {"band": overall_band, "flags": all_flags},
        "pieces": pieces,
        "briefing": env.briefing_md,
    }
