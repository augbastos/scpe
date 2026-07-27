"""results.json — the machine-readable seal a CI job hands from its untrusted half to its
trusted one, and the only module in this package that COMPARES against a §8 status. (The
word also appears in scpe/seal.py, twice, as a badge label and as the name of a field in
this dict — never as a test of what the verifier decided.)

Two rules govern this file.

FIRST: it projects, it never decides. `Result.status` arrives from the reference verifier
and is copied verbatim — all eight §8 statuses pass through unchanged, none is collapsed,
softened or renamed. Everything else here (the gate, the risk band, the counts, the test
run) sits BESIDE the verdict and is clearly marked as such. `verified` is true if and only
if the status is exactly `verified`; any consumer that derives it another way is wrong.

SECOND: the schema only ever grows. Every field an earlier version of the Action or a
copied workflow reads is still emitted with the same name and type, because a repository
pinned to an old tag must degrade to a truthful report, never to a red X caused by a
missing key. Two fields (`hook`, `login`) are retained purely for that reason and are
marked deprecated below.

The manifest-derived fields are CLAIMS, not proof, unless `verified` is true. A manifest
whose signature failed still parses, and its `contributor.identity` still says whatever
the submitter wrote. They are surfaced because a reviewer needs to see what was claimed;
the seal renders identity as UNVERIFIED whenever `verified` is false, and nothing
downstream may present a claim from an unverified manifest as established fact.
"""
from __future__ import annotations

from pathlib import Path

from reference.standalone import verify_envelope as _ref
from scpe import context as _context, diffinfo, seal
from scpe.testrun import NOT_RUN
from scpe.verify import UNAVAILABLE

# ai_disclosure.mode (SPEC §4) -> the "made with" line on the seal. Derived from the SIGNED
# manifest, so on a verified contribution the provenance line is covered by the signature.
_PROVENANCE = {"none": "hand-authored", "assisted": "AI-assisted", "generated": "AI-generated"}

# The declared modes. Anything else (absent, empty, a typo, a value from a future spec) is
# NOT a disclosure: it fails the level-1 obligation rather than being waved through.
DISCLOSURE_MODES = frozenset(_PROVENANCE)

VERIFIED = "verified"


def _display_manifest(path: Path) -> dict:
    """Parse the manifest for DISPLAY only. Returns {} when there is nothing parseable —
    the verifier has already reported why, and this function must never turn a parse
    failure into a second, competing verdict."""
    try:
        manifest_bytes, *_rest = _ref.load_input(path)
        return _ref.parse_manifest(manifest_bytes)
    except Exception:                       # noqa: BLE001 - the verifier reports the reason
        return {}


def signed_manifest(path: Path) -> dict:
    """The same bytes, for callers acting on them rather than printing them.

    Identical parse; a different name because the safety condition is different. Display can
    happen whatever the verdict — an `unattested` seal still shows what the manifest claimed.
    Acting on a field (comparing a target repository, enforcing a gate) is only sound once
    the signature over these bytes has verified, so a caller must check that first. The two
    names exist so the distinction is visible at every call site instead of living in a
    comment nobody re-reads."""
    return _display_manifest(path)


def _dig(obj: object, *keys: str) -> object:
    """Walk nested dicts, tolerating any shape. A manifest is attacker-controlled JSON
    until the signature verifies, so every level is checked instead of assumed."""
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _provenance(ai_disclosure: object) -> str:
    """The 'made with' line, read from the signed disclosure block. A hand-authored
    contribution must NEVER read as AI-assisted, and an undisclosed one must never read as
    hand-authored — an absent block yields "", not a default."""
    mode = _dig(ai_disclosure, "mode")
    base = _PROVENANCE.get(mode if isinstance(mode, str) else "", "")
    notes = _dig(ai_disclosure, "notes")
    if base and isinstance(notes, str) and notes.strip():
        base += f" ({notes.strip()[:80]})"
    return base


def _fail_message(status: str, detail: str, *, disclosure_present: bool,
                  key_source: str | None = None, context_detail: str = "") -> str:
    """The one line the trusted job posts when the gate closes. Specific by construction:
    the trusted job must never have to recompute a reason, and "not verifiable" without a
    cause is an unactionable check."""
    if status == VERIFIED and context_detail:
        # The hardest case to guess from outside: everything cryptographic is in order. The
        # signature is genuine, the diff matches the digest it was signed over, the identity
        # resolves — the envelope is just being presented somewhere other than where it was
        # signed for. Name which, or a maintainer reads "verified" next to a red check and
        # concludes the tool is broken.
        return ("❌ Wrong context — the signature and the diff are both valid, but this "
                f"envelope was not signed for this pull request: {context_detail}. A valid "
                "envelope replayed onto another repository or another history is still a "
                "valid envelope; it just does not attest to this contribution.")
    if status == VERIFIED and key_source == "bundled":
        # Rejected while the status says `verified`, which is the one case a maintainer will
        # not guess: the signature is genuine, it just proves nothing about the account named
        # in the manifest, because the keys that checked it travelled with the submission.
        return ("❌ Self-anchored identity — the signature is valid, but it was checked "
                "against a keys file included in the submission, not against the keys the "
                "declared provider publishes for that account. A `bundled` anchor proves "
                "the signing act alone (spec scpe/0.1 §8 step 4); this repository requires "
                "a forge-backed identity.")
    if status == VERIFIED and not disclosure_present:
        # Level 2 is documented as implying level 1. The reference verifier does not read
        # `ai_disclosure` (SPEC's schema is advisory), so the obligation is re-imposed here
        # rather than in the verifier — changing the verifier would change the normative
        # meaning of the eighteen vectors and of the Go and Rust ports.
        return ("❌ Missing AI-use disclosure — the contribution is signed and verified, "
                "but its manifest carries no `ai_disclosure.mode`. This repository "
                "requires contributors to declare AI use (spec scpe/0.1 §4).")
    reason = f": {detail}" if detail else ""
    return (f"❌ Not verifiable — status `{status}`{reason}. This repository requires a "
            f"signed SCPE contribution (spec scpe/0.1).")


def build_results(result: _ref.Result, *, path: Path, diff: str = "",
                  diff_source: str = UNAVAILABLE, diff_note: str = "",
                  require: bool = False, level: str = "2",
                  tests: dict | None = None,
                  context: "_context.ContextCheck | None" = None) -> dict:
    """Project a verifier `Result` (plus the diff and test run that accompanied it) into
    the results.json contract."""
    manifest = _display_manifest(path)
    identity = _dig(manifest, "contributor", "identity")
    subject_block = manifest.get("subject") if isinstance(manifest.get("subject"), dict) else {}
    change = subject_block.get("change") if isinstance(subject_block.get("change"), dict) else {}
    target = subject_block.get("target") if isinstance(subject_block.get("target"), dict) else {}
    ai_disclosure = manifest.get("ai_disclosure")
    ai_disclosure = ai_disclosure if isinstance(ai_disclosure, dict) else None

    def _str(value: object) -> str:
        """Surface a manifest field only when it really is a string. A manifest is
        attacker-controlled JSON until the signature verifies, so a number or an object
        where a name belongs degrades to "" instead of reaching a renderer as some other
        type and breaking the consumer that reads results.json."""
        return value if isinstance(value, str) else ""

    subject = _str(_dig(identity, "subject"))
    provider = _str(_dig(identity, "provider"))
    fingerprint = _str(_dig(manifest, "contributor", "key_fingerprint"))
    mode = _dig(ai_disclosure, "mode")
    disclosure_present = isinstance(mode, str) and mode in DISCLOSURE_MODES

    band = seal.risk_band(diff)
    added, removed = diffinfo.count_diff_lines(diff)
    verified = result.status == VERIFIED
    # A `verified` anchored on `bundled` keys was checked against a key set the SUBMITTER
    # enclosed, so it says nothing about the forge account named in the manifest (SPEC §8
    # step 4, THREAT_MODEL §2.1). The seal already labels it as self-anchored; a merge gate
    # has to go further and refuse it, or "require: true" would accept a contribution that
    # authenticated itself. `flag` passes: those keys came from the repository owner.
    #
    # Under the §9 PR-body transport this is unreachable today — that path never carries a
    # keys member, so the anchor is always forge or flag. It is enforced anyway, because the
    # gate must be safe by construction and not by which input shape happens to reach it.
    forge_backed = result.key_source in ("forge", "flag")
    # Level 2 implies level 1 (docs/LEVELS.md): a pass must carry BOTH a valid signature and
    # a declared AI-use mode. The verifier answers the first question only, so the second is
    # enforced here, at the gate — the layer that is allowed to have a policy.
    # The envelope must also be presented where it was signed for. A signature and a diff
    # digest together prove the change is authentic and unaltered; they say nothing about
    # which repository or which history it was meant for, and the manifest carries both
    # precisely so that can be answered. See scpe/context.py — before it existed, an
    # attestation lifted off a public pull request verified on an unrelated repository.
    context_ok = context.ok if context is not None else True
    context_detail = "" if context is None or context.ok else context.detail
    would_pass = verified and disclosure_present and forge_backed and context_ok
    gate_pass = (not require) or would_pass
    # Populated whenever the contribution would NOT clear a gate, even at require=false, so
    # an informational run previews exactly what enabling the gate would say. Empty means
    # there is nothing to report — never a generic "not verifiable" a job might post anyway.
    fail_message = "" if would_pass else _fail_message(
        result.status, result.detail, disclosure_present=disclosure_present,
        key_source=result.key_source, context_detail=context_detail)

    stats = change.get("stats") if isinstance(change.get("stats"), dict) else None
    claimed_files = change.get("files_changed")
    signed_stats = None
    if stats is not None:
        # The CLAIMED counts, surfaced verbatim beside the OBSERVED ones and never
        # reconciled with them: git's numstat and a raw +/- count legitimately disagree on
        # renames and binary files, so a mismatch is information for a reviewer, not grounds
        # for this layer to overrule a signature it did not check.
        signed_stats = {
            "insertions": stats.get("insertions"),
            "deletions": stats.get("deletions"),
            "files_changed": claimed_files if isinstance(claimed_files, list) else [],
        }

    return {
        # ---- fields every existing consumer already reads, unchanged in name and type ----
        "login": subject,          # DEPRECATED alias of `subject`; only meaningful for
                                   # provider=github. Use (provider, subject).
        "verified": verified,
        "band": band["band"] if diff else "",   # always present: older renderers index it
        "flags": band["flags"] if diff else [],
        "matched": band["matched"] if diff else [],
        "rules_checked": seal.RULE_COUNT,
        "added": added,
        "removed": removed,
        "files": diffinfo.files_from_diff(diff),
        "tests": dict(tests) if tests else dict(NOT_RUN),
        "provenance": _provenance(ai_disclosure),
        "hook": "",                # DEPRECATED: nothing has ever written this. Kept so a
                                   # renderer from an older tag does not KeyError. Remove
                                   # at the next MAJOR.
        "status": result.status,   # verbatim, one of the eight in SPEC §8
        "require": require,
        "gate_pass": gate_pass,
        "level": level,
        "fail_message": fail_message,

        # ---- the protocol's own fields, from the manifest and the verifier ----
        "spec_version": _str(manifest.get("spec_version")),
        "provider": provider,
        "subject": subject,
        "subject_type": _str(subject_block.get("type")),
        # Which §8 step-4 anchor the verdict rests on: flag | bundled | forge | null. A
        # `verified` anchored on `bundled` keys was anchored on a key set chosen by whoever
        # submitted the package — it must never be displayed the same way as a forge-backed
        # pass, which is why the seal renders this on its own row.
        "key_source": result.key_source,
        "key_fingerprint": fingerprint,     # displayed for a reviewer, never dispatched on
        "profile": result.profile,          # SPEC §13: advisory label, displayed, never dispatched
        "attestations": result.attestations,
        "ai_disclosure": ai_disclosure,
        "disclosure_present": disclosure_present,
        "detail": result.detail,
        "diff_source": diff_source,
        "diff_note": diff_note,
        "signed_stats": signed_stats,       # the CLAIMED counts; `added`/`removed` are observed
        "target_repo": _str(target.get("repo")),
        "base_sha": _str(target.get("base_sha")),
        "head_sha": _str(change.get("head_sha")),
        # Whether the three fields above were COMPARED with the checkout, not just copied
        # out of the manifest. `context_checked: false` means no expectation was supplied
        # and the signed target went unexamined — which is what every run did before
        # scpe/context.py existed, and is why a consumer needs to be able to tell.
        "context_checked": bool(context.checked) if context is not None else False,
        "context_ok": context_ok,
        "context_detail": context_detail,

        # ---- provenance of the numbers above, so nobody mistakes them for the protocol ----
        "risk_scan": {
            "in_spec": False,
            "note": ("Action-layer triage aid. SPEC scpe/0.1 defines no risk scan; "
                     "the band never influences the status."),
        },
    }
