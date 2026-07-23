"""SCPE LEVEL 1 — the AI-disclosure signal detector (reference/disclosure.py).

reference/disclosure.py lives outside the scpe package on purpose (same reason as
reference/producer.py and reference/standalone/verify_envelope.py: it is a small,
stdlib-only reference implementation the Action reads directly out of its own
checkout, no `pip install scpe` required), so it is loaded here by path.
"""
from __future__ import annotations

import importlib.util
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DISCLOSURE_PATH = ROOT / "reference" / "disclosure.py"

_spec = importlib.util.spec_from_file_location("scpe_disclosure_ref", DISCLOSURE_PATH)
disclosure = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(disclosure)

detect_disclosure = disclosure.detect_disclosure


# ---- trailer: present, various forms ---------------------------------------


def test_trailer_present_in_commit_message():
    r = detect_disclosure(pr_body="", commit_messages=["fix: bug\n\nAssisted-by: claude-opus"])
    assert r == {"present": True, "form": "trailer", "value": "claude-opus"}


def test_trailer_is_case_insensitive_on_the_key():
    for key in ("Assisted-by", "assisted-by", "ASSISTED-BY", "Assisted-By"):
        r = detect_disclosure(commit_messages=[f"{key}: gpt-5"])
        assert r == {"present": True, "form": "trailer", "value": "gpt-5"}


def test_trailer_present_in_pr_body_when_absent_from_commits():
    r = detect_disclosure(pr_body="Summary\n\nAssisted-by: cursor", commit_messages=["plain commit"])
    assert r == {"present": True, "form": "trailer", "value": "cursor"}


@pytest.mark.parametrize("value", ["none", "None", "NONE", "no", "No", "n/a", "nil", ""])
def test_trailer_declaring_no_ai_use_is_still_a_disclosure(value):
    r = detect_disclosure(commit_messages=[f"Assisted-by: {value}"])
    assert r["present"] is True
    assert r["form"] == "trailer"
    assert r["value"] == "none"


def test_trailer_value_is_trimmed():
    r = detect_disclosure(commit_messages=["Assisted-by:   gpt-4o   "])
    assert r["value"] == "gpt-4o"


def test_last_trailer_across_commits_wins():
    r = detect_disclosure(commit_messages=["Assisted-by: first-tool", "Assisted-by: second-tool"])
    assert r["value"] == "second-tool"


def test_last_trailer_within_a_single_message_wins():
    r = detect_disclosure(commit_messages=["Assisted-by: old\nAssisted-by: new"])
    assert r["value"] == "new"


def test_commit_trailer_takes_precedence_over_pr_body_trailer():
    r = detect_disclosure(pr_body="Assisted-by: body-tool", commit_messages=["Assisted-by: commit-tool"])
    assert r["value"] == "commit-tool"


# ---- trailer: absent ---------------------------------------------------------


def test_absent_when_no_signal_anywhere():
    r = detect_disclosure(pr_body="just a normal PR description", commit_messages=["fix: typo"])
    assert r == {"present": False, "form": "none", "value": ""}


def test_absent_with_no_input_at_all():
    assert detect_disclosure() == {"present": False, "form": "none", "value": ""}


def test_trailer_key_must_be_at_start_of_line_not_mid_sentence():
    # "assisted-by" appearing as prose, not as a trailer (no line starts with it).
    r = detect_disclosure(pr_body="This tool was assisted-by nothing in particular.")
    assert r["present"] is False


# ---- checkbox: both states ---------------------------------------------------


def test_checkbox_checked_used_ai():
    r = detect_disclosure(pr_body="- [x] I used generative AI\n- [ ] I did not use generative AI")
    assert r == {"present": True, "form": "checkbox", "value": "ai"}


def test_checkbox_checked_did_not_use_ai():
    r = detect_disclosure(pr_body="- [ ] I used generative AI\n- [x] I did not use generative AI")
    assert r == {"present": True, "form": "checkbox", "value": "none"}


def test_checkbox_uppercase_x():
    r = detect_disclosure(pr_body="- [X] I used generative AI")
    assert r["present"] is True
    assert r["value"] == "ai"


def test_checkbox_unchecked_both_is_absent():
    r = detect_disclosure(pr_body="- [ ] I used generative AI\n- [ ] I did not use generative AI")
    assert r["present"] is False


def test_checkbox_ignored_when_a_trailer_is_already_present():
    r = detect_disclosure(
        pr_body="- [x] I used generative AI",
        commit_messages=["Assisted-by: claude"],
    )
    assert r["form"] == "trailer"
    assert r["value"] == "claude"


def test_checkbox_only_scanned_in_pr_body_not_commit_messages():
    r = detect_disclosure(pr_body="", commit_messages=["- [x] I used generative AI"])
    assert r["present"] is False


# ---- malformed / injection-shaped inputs --------------------------------------


def test_non_string_inputs_do_not_raise():
    r = detect_disclosure(pr_body=None, commit_messages=None)  # type: ignore[arg-type]
    assert r["present"] is False
    r2 = detect_disclosure(pr_body=12345, commit_messages=[None, 42, "Assisted-by: ok"])  # type: ignore[list-item]
    assert r2["present"] is True
    assert r2["value"] == "ok"


def test_shell_metacharacters_in_the_value_come_back_as_inert_data():
    payload = "Assisted-by: $(rm -rf /); `whoami`; ${IFS}| evil"
    r = detect_disclosure(commit_messages=[payload])
    assert r["present"] is True
    # The whole shell-looking tail is captured verbatim as a STRING — never executed.
    assert "rm -rf" in r["value"]


def test_html_and_script_injection_in_value_is_inert_text():
    r = detect_disclosure(commit_messages=['Assisted-by: <script>alert(1)</script>'])
    assert r["present"] is True
    assert r["value"] == "<script>alert(1)</script>"


def test_null_byte_and_control_characters_do_not_crash():
    r = detect_disclosure(pr_body="Assisted-by: model\x00\x01\x02", commit_messages=[])
    assert r["present"] is True


def test_unicode_homoglyph_key_is_not_matched_as_ascii_trailer():
    # Cyrillic 'а' (U+0430) instead of ASCII 'a' — must NOT be treated as a match;
    # a homoglyph disclosure key is not a real disclosure of anything real projects
    # actually check for.
    homoglyph = "аssisted-by: sneaky"
    r = detect_disclosure(commit_messages=[homoglyph])
    assert r["present"] is False


def test_oversized_input_is_bounded_and_does_not_hang_or_crash():
    huge = "x" * 5_000_000 + "\nAssisted-by: found-me"
    start = time.monotonic()
    r = detect_disclosure(pr_body=huge)
    elapsed = time.monotonic() - start
    assert elapsed < 2.0
    # Truncated well before reaching the trailer placed after 5M characters, so it
    # is correctly reported ABSENT rather than silently accepted despite the size.
    assert r["present"] is False


def test_pathological_repeated_pattern_does_not_hang_redos_probe():
    # A classic ReDoS probe shape (many repeats + a non-matching tail) — must return
    # near-instantly since the patterns have no nested/overlapping quantifiers.
    probe = ("assisted-by: " * 2000) + "!"
    start = time.monotonic()
    detect_disclosure(pr_body=probe, commit_messages=[probe])
    assert time.monotonic() - start < 2.0


def test_many_commit_messages_bounded_reasonably_fast():
    commits = [f"commit {i}" for i in range(5000)] + ["Assisted-by: last"]
    start = time.monotonic()
    r = detect_disclosure(commit_messages=commits)
    assert time.monotonic() - start < 2.0
    assert r["present"] is True
    assert r["value"] == "last"


def test_no_eval_or_exec_reachable_from_public_api():
    # Static guard: the module must not use eval/exec/os.system/subprocess anywhere —
    # it is a pure text-parsing module and must stay that way. Note: these are STRING
    # LITERALS being searched for in disclosure.py's own source (a banned-pattern
    # scan), not calls to eval/exec here — nothing in this test executes anything.
    src = DISCLOSURE_PATH.read_text(encoding="utf-8")
    for banned in ("eval(", "exec(", "os.system", "subprocess", "__import__"):
        assert banned not in src, f"disclosure.py must never use {banned!r}"
