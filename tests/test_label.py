"""Plain-text confirmation labels: PURE ASCII, fixed-width, deterministic, and honest —
a contribution label states a claim, the verified receipt is the owner's post-verify
assertion. A tampered artifact must render a different label."""
from scpe import label
from scpe.envelope import PROTOCOL_VERSION, Envelope, Manifest, Piece

FIX_DIFF = "--- a/f.py\n+++ b/f.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"


def _env(*, ssh: bool = True) -> Envelope:
    kw = dict(github_login="augbastos", sig_method="ssh-github") if ssh else {}
    m = Manifest(PROTOCOL_VERSION, "https://github.com/o/r", "abc1234" + "0" * 33, "",
                 "Augusto Bastos", "67170506+augbastos@users.noreply.github.com", "t", **kw)
    return Envelope(manifest=m, briefing_md="",
                    pieces=[Piece("p1", "fix", "b", FIX_DIFF, ["f.py"])], provenance={})


def test_contribution_label_is_pure_ascii_and_fixed_width():
    s = label.contribution_label(_env(), filename="e.zip")
    s.encode("ascii")  # must not raise — renders in any console / commit / comment
    assert "<+> scpe" in s and "CONTRIBUTION" in s
    assert "@augbastos" in s
    assert "github.com/augbastos.keys" in s
    assert "CLAIM" in s
    assert {len(line) for line in s.splitlines()} == {62}  # every line same width


def test_contribution_label_legacy_shows_sender_not_handle():
    s = label.contribution_label(_env(ssh=False))
    assert "legacy" in s.lower()
    assert "Augusto Bastos" in s
    assert "@augbastos" not in s


def test_label_changes_when_artifact_changes():
    a = label.contribution_label(_env())
    e2 = _env()
    e2.pieces[0].diff += "+extra line\n"  # one more added line
    assert label.contribution_label(e2) != a


def test_verified_receipt_is_the_owners_post_verify_assertion():
    s = label.verified_receipt(_env(), commit="deadbeef123", owner="@ancaferro", tests_ok=True)
    s.encode("ascii")
    assert "VERIFIED" in s and "[OK]" in s and "deadbee" in s
    assert "@ancaferro" in s


def test_attestation_label_points_at_independent_verify():
    stmt = {"subject": [{"name": "github.com/o/r", "digest": {"sha1": "4e91a2c000"}}],
            "predicate": {"verdict": "clean", "findingsCount": 0, "auditor": "@augbastos"}}
    s = label.attestation_label(stmt, filename="att.json")
    s.encode("ascii")
    assert "ATTESTATION" in s and "clean" in s
    assert "verify-attest" in s and "cosign" in s
