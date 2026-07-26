"""The merge gate must refuse a self-anchored identity.

SPEC §8 step 4 resolves keys in the order `flag` > `bundled` > `forge`. A `bundled` anchor
is a `keys` file that travelled *inside the submission*, so it is chosen by whoever opened
the pull request. The signature over it is genuine; what it proves is only that the
submitter signed their own bytes with their own key. It says nothing about the account named
in the manifest, and an attacker needs no stolen key to produce one — they enclose their own.

`status` stays `verified` in that case, deliberately: the verifier reports what it checked
and does not hold policy. The gate is the layer allowed to have a policy, and this is the
policy — `require: true` means a forge-backed identity, not merely a valid signature.

Under the §9 PR-body transport this is unreachable today: that path never carries a `keys`
member, so the anchor is always `forge` or `flag`. These tests exist anyway, because "safe
because of which input shape happens to reach it" is not safe by construction — the day a
directory input is accepted, this file is what stops the gate from opening.
"""
from __future__ import annotations

from scpe.results import _fail_message


def _msg(**over) -> str:
    kw = {"status": "verified", "detail": "", "disclosure_present": True, "key_source": "forge"}
    kw.update(over)
    return _fail_message(kw.pop("status"), kw.pop("detail"), **kw)


def test_bundled_anchor_is_refused_with_its_own_reason():
    """A maintainer reading `status: verified` next to a red X will not guess why. The
    message has to name the actual cause, not fall through to the generic one."""
    msg = _msg(key_source="bundled")
    assert "Self-anchored" in msg
    assert "included in the submission" in msg
    assert "§8 step 4" in msg
    # Must NOT be mistaken for the disclosure failure, which is a different fix entirely.
    assert "AI-use disclosure" not in msg


def test_forge_and_flag_anchors_are_not_refused_for_being_anchors():
    """`forge` is the published key set; `flag` is one the repository owner supplied. Both
    are outside the submitter's control, so neither is a reason to close the gate."""
    for anchor in ("forge", "flag"):
        assert _msg(key_source=anchor, disclosure_present=False, ) != ""
        # …and the reason given is the disclosure, not the anchor.
        assert "AI-use disclosure" in _msg(key_source=anchor, disclosure_present=False)


def test_an_unverified_status_still_reports_the_status_not_the_anchor():
    """The anchor branch is scoped to `verified`. A signature that failed outright gets the
    status message, so the specific reason is never masked by the newer, narrower one."""
    msg = _msg(status="signature-invalid", detail="SSHSIG verification failed",
               key_source="bundled")
    assert "Not verifiable" in msg and "signature-invalid" in msg
    assert "Self-anchored" not in msg
