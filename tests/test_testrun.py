"""Running the repository's own tests, where the code already is.

This is NOT the old sandbox. `scpe/sandbox.py` existed because the agent held a diff that
had not been applied anywhere: it copied the repo, `git apply`-ed the patch and ran the
suite against the result. Under the SPEC §9 transport there is no pending diff — the pull
request already contains the change and CI already checked it out, so building a second
copy would only add a way for the two to disagree.

What remains is narrow and worth keeping honest: find the command this repository declares,
run it, report what happened. The invariant that survives from the sandbox is the important
one — `ok` can never be true unless the suite actually ran. A green tick for a suite that
was never executed is the single worst thing a seal can say.

The commands below are `git` invocations rather than real test suites: git is already a hard
dependency of this file's fixtures, its exit codes are certain, and it needs no interpreter
lookup — so a failure here is about run_tests and never about the environment.
"""
from __future__ import annotations

import json

import pytest

from scpe.testrun import detect_test_cmd, run_tests
from tests.conftest import seal_json

PASSING_CMD = ["git", "--version"]
# `cat-file -e` and not `rev-parse --verify <sha>`: rev-parse validates the SHAPE of an
# object name, so it exits 0 on a well-formed all-zero SHA that no repository contains
# (measured). A "failing command" that returns 0 would make this test assert nothing.
FAILING_CMD = ["git", "cat-file", "-e",
               "0000000000000000000000000000000000000000"]
# The same passing command in the shell-string form `.scpe/verify.json` also accepts.
PASSING_DECL = "git --version"


def _as_text(cmd) -> str:
    return " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)


def _declare(repo, cmd) -> None:
    """The `.scpe/verify.json` convention the old handshake defined. It is the only piece
    of that flow worth keeping: a repository that already told scpe how to test itself must
    not silently start being probed by guesswork instead."""
    (repo / ".scpe").mkdir(exist_ok=True)
    (repo / ".scpe" / "verify.json").write_text(json.dumps({"test_cmd": cmd}),
                                                encoding="utf-8")


# ---- detection ----------------------------------------------------------------

def test_a_declared_command_beats_a_language_marker(fixture_repo):
    # fixture_repo ships pytest.ini, so guesswork would answer "pytest" here.
    _declare(fixture_repo, PASSING_DECL)
    assert "git" in _as_text(detect_test_cmd(fixture_repo))


def test_a_declared_command_may_be_a_list_or_a_string(fixture_repo):
    _declare(fixture_repo, PASSING_CMD)
    assert detect_test_cmd(fixture_repo) == PASSING_CMD


def test_a_language_marker_is_the_fallback(fixture_repo):
    assert "pytest" in _as_text(detect_test_cmd(fixture_repo)).lower()


def test_no_marker_means_no_command(no_runner_repo):
    """Guessing wrong is worse than declining: a made-up command that errors out would be
    reported as a failing suite, which reads as "this contribution broke the tests"."""
    assert detect_test_cmd(no_runner_repo) is None


# ---- running ------------------------------------------------------------------

def test_a_passing_command_is_reported_as_ran_and_ok(fixture_repo):
    result = run_tests(fixture_repo, PASSING_CMD)
    assert result["ran"] is True
    assert result["ok"] is True
    assert result["summary"]


def test_a_failing_command_is_reported_as_ran_and_not_ok(fixture_repo):
    result = run_tests(fixture_repo, FAILING_CMD)
    assert result["ran"] is True
    assert result["ok"] is False


def test_no_command_means_nothing_ran(no_runner_repo):
    result = run_tests(no_runner_repo, None)
    assert result == {"ran": False, "ok": False, "summary": "no test runner detected"}


def test_a_missing_repo_is_reported_not_guessed(tmp_path):
    """A bad `--repo` has no marker files either, so detecting first would blame the
    contribution ("no test runner detected") for what is an operator mistake."""
    result = run_tests(tmp_path / "nope", PASSING_CMD)
    assert result["ran"] is False and result["ok"] is False
    assert "no such repo" in result["summary"]


@pytest.mark.parametrize("cmd", [PASSING_CMD, FAILING_CMD, ["definitely-not-a-binary-xyz"]])
def test_ok_is_impossible_without_ran(fixture_repo, cmd):
    """The invariant, stated directly rather than inferred from the cases above — including
    the case where the runner itself cannot start."""
    result = run_tests(fixture_repo, cmd)
    assert not (result["ok"] and not result["ran"])


# ---- wiring -------------------------------------------------------------------

def test_the_sealer_reports_a_declared_suite_it_actually_ran(repo_with_fix, tmp_path):
    """`--run-tests` end to end: the flag reaches run_tests, and the result lands in the
    `tests` block old consumers already read."""
    repo, base, head = repo_with_fix
    _declare(repo, PASSING_DECL)
    body = "no attestation, just checking the test wiring\n"
    data, rc = seal_json("--pr-body-env", "SCPE_PR_BODY", "--repo", str(repo),
                         "--base", base, "--head", head, "--run-tests",
                         "--require", "false", "--level", "2",
                         env_extra={"SCPE_PR_BODY": body, "PR_BODY": body}, cwd=tmp_path)
    assert rc == 0
    assert data["tests"]["ran"] is True
    assert data["tests"]["ok"] is True


def test_without_the_flag_the_seal_says_not_run(repo_with_fix, tmp_path):
    """No `--run-tests` must never render as a pass. "not run" is the honest word and the
    exact string the previous package emitted, so a reader's expectation is unchanged."""
    repo, base, head = repo_with_fix
    _declare(repo, PASSING_DECL)
    body = "no attestation\n"
    data, _ = seal_json("--pr-body-env", "SCPE_PR_BODY", "--repo", str(repo),
                        "--base", base, "--head", head, "--require", "false",
                        "--level", "2",
                        env_extra={"SCPE_PR_BODY": body, "PR_BODY": body}, cwd=tmp_path)
    assert data["tests"] == {"ran": False, "ok": False, "summary": "not run"}
