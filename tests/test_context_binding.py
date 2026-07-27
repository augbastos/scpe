"""A valid envelope must not verify on a pull request it was not signed for.

The manifest carries `subject.target.repo` and `subject.target.base_sha` so that question
can be answered. Before scpe/context.py they were read, copied into results.json, and never
compared with anything — so an attestation lifted off a public pull request produced a
`verified`, `gate_pass: true`, `key_source: forge` seal on an unrelated repository whose
diff happened to normalize to the same bytes. The signature was genuine and the digest
matched; only the context was wrong, and nothing looked at it.

These tests are written against that scenario rather than against the implementation: each
one builds the mismatch and asserts the gate closes with a reason a maintainer can act on.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scpe import context as _context

CODE_CHANGE = {
    "subject": {
        "type": "code-change",
        "target": {"repo": "augbastos/scpe-demo", "base_sha": "a" * 40},
        "change": {"head_sha": "b" * 40},
    }
}


def _check(**kw):
    base = dict(manifest=CODE_CHANGE, repo_dir=Path("."), head=None,
                expect_repo=None, expect_base=False)
    base.update(kw)
    return _context.check(**base)


# --- the replay this exists to stop ------------------------------------------------------

def test_envelope_signed_for_another_repository_is_refused():
    c = _check(expect_repo="attacker/other-repo")
    assert c.mismatch
    assert "augbastos/scpe-demo" in c.detail and "attacker/other-repo" in c.detail


def test_matching_repository_passes_and_says_it_checked():
    c = _check(expect_repo="augbastos/scpe-demo")
    assert c.ok and c.checked and not c.mismatch


def test_repository_comparison_is_case_insensitive():
    """Forges treat Owner/Name and owner/name as one repository. Refusing on case would
    fail honest contributions for a reason no maintainer would ever guess."""
    assert _check(expect_repo="AugBastos/SCPE-Demo").ok


def test_manifest_without_a_target_repo_cannot_satisfy_the_check():
    """Absent is not a pass. An envelope that declares no target repository has nothing to
    compare, and treating "nothing to compare" as "matches" would let an attacker opt out
    of the check by omitting the field."""
    m = {"subject": {"type": "code-change", "target": {}, "change": {}}}
    c = _check(manifest=m, expect_repo="augbastos/scpe-demo")
    assert c.mismatch


def test_target_repo_of_the_wrong_type_is_refused():
    m = {"subject": {"type": "code-change", "target": {"repo": 1234}, "change": {}}}
    assert _check(manifest=m, expect_repo="augbastos/scpe-demo").mismatch


# --- base ancestry, not base equality ----------------------------------------------------

def _repo(tmp_path: Path, run) -> Path:
    run(["git", "init", "-q", str(tmp_path)])
    run(["git", "-C", str(tmp_path), "config", "user.email", "t@example.com"])
    run(["git", "-C", str(tmp_path), "config", "user.name", "t"])
    return tmp_path


@pytest.fixture()
def git(tmp_path):
    import subprocess

    def run(cmd, **kw):
        return subprocess.run(cmd, capture_output=True, check=True, **kw)

    def sha(repo, rev="HEAD"):
        return subprocess.run(["git", "-C", str(repo), "rev-parse", rev],
                              capture_output=True, text=True, check=True).stdout.strip()

    repo = _repo(tmp_path, run)
    (repo / "f.txt").write_text("one\n", encoding="utf-8")
    run(["git", "-C", str(repo), "add", "-A"])
    run(["git", "-C", str(repo), "commit", "-qm", "base"])
    base = sha(repo)
    (repo / "f.txt").write_text("two\n", encoding="utf-8")
    run(["git", "-C", str(repo), "add", "-A"])
    run(["git", "-C", str(repo), "commit", "-qm", "head"])
    return repo, base, sha(repo), run, sha


def test_signed_base_in_this_history_passes(git):
    repo, base, head, _run, _sha = git
    m = {"subject": {"type": "code-change",
                     "target": {"repo": "o/n", "base_sha": base}, "change": {}}}
    c = _context.check(manifest=m, repo_dir=repo, head=head,
                       expect_repo=None, expect_base=True)
    assert c.ok and c.checked


def test_base_check_survives_the_branch_moving_on(git):
    """The reason this is ancestry and not equality. `pull_request.base.sha` is the tip of
    the base branch and advances whenever anything merges; the commit the contributor
    diffed from does not. Equality would fail every open pull request after any merge."""
    repo, base, head, run, sha = git
    run(["git", "-C", str(repo), "checkout", "-q", "-b", "other", base])
    (repo / "unrelated.txt").write_text("moved on\n", encoding="utf-8")
    run(["git", "-C", str(repo), "add", "-A"])
    run(["git", "-C", str(repo), "commit", "-qm", "someone else merged something"])
    assert sha(repo) != base                      # the branch tip really did move
    m = {"subject": {"type": "code-change",
                     "target": {"repo": "o/n", "base_sha": base}, "change": {}}}
    c = _context.check(manifest=m, repo_dir=repo, head=head,
                       expect_repo=None, expect_base=True)
    assert c.ok, "a moved base branch must not invalidate an honest contribution"


def test_signed_base_from_a_foreign_history_is_refused(git):
    repo, _base, head, _run, _sha = git
    m = {"subject": {"type": "code-change",
                     "target": {"repo": "o/n", "base_sha": "c" * 40}, "change": {}}}
    c = _context.check(manifest=m, repo_dir=repo, head=head,
                       expect_repo=None, expect_base=True)
    assert c.mismatch


def test_missing_base_cannot_satisfy_the_check(git):
    repo, _base, head, _run, _sha = git
    m = {"subject": {"type": "code-change", "target": {"repo": "o/n"}, "change": {}}}
    c = _context.check(manifest=m, repo_dir=repo, head=head,
                       expect_repo=None, expect_base=True)
    assert c.mismatch


# --- shape of the contract ---------------------------------------------------------------

def test_artifact_subjects_are_out_of_scope():
    """An `artifact` envelope is about bytes, not about a repository — there is no target to
    compare, and inventing one would fail every artifact contribution."""
    m = {"subject": {"type": "artifact", "artifact": {"sha256": "x"}}}
    c = _context.check(manifest=m, repo_dir=Path("."), head=None,
                       expect_repo="o/n", expect_base=True)
    assert c.ok and not c.checked


def test_no_expectation_means_nothing_was_checked():
    """Callers that supply no expectation must behave exactly as they did before this
    existed — and results.json has to be able to say the target went unexamined, rather
    than implying it matched."""
    c = _check()
    assert c.ok and not c.checked


# --- and the gate actually closes on it --------------------------------------------------

def test_gate_closes_on_a_context_mismatch_and_names_it():
    """The check is worth nothing if the gate ignores it. A mismatch has to reach
    gate_pass, and the message has to distinguish this from the other refusals: everything
    cryptographic is fine here, which is exactly why "not verifiable" would mislead."""
    from reference.standalone.verify_envelope import Result
    from scpe import results as _results

    verified = Result("verified", "", None, profile="SCPE-C", key_source="forge")
    bad = _context.ContextCheck(ok=False, checked=True,
                                detail="signed for a/b, presented on c/d")

    data = _results.build_results(verified, path=Path("nonexistent.zip"),
                                  require=True, context=bad)
    assert data["context_checked"] is True
    assert data["context_ok"] is False
    assert data["gate_pass"] is False, "a replayed envelope must not clear the gate"
    assert "Wrong context" in data["fail_message"]
    assert "signed for a/b, presented on c/d" in data["fail_message"]
    assert data["status"] == "verified", (
        "the envelope IS valid — the seal must not relabel it as broken, only refuse it here")


def test_gate_still_passes_when_the_context_matches():
    from reference.standalone.verify_envelope import Result
    from scpe import results as _results

    verified = Result("verified", "", None, profile="SCPE-C", key_source="forge")
    ok = _context.ContextCheck(ok=True, checked=True)
    data = _results.build_results(verified, path=Path("nonexistent.zip"),
                                  require=True, context=ok)
    assert data["context_ok"] is True
