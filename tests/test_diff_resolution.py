"""Where the diff comes from, and what happens when it cannot come from anywhere.

A SPEC §9 attestation carries a manifest and a signature and NO diff — that is the whole
point of the transport (the change is already in the pull request; shipping it twice would
mean the reviewer reads one copy and the verifier hashes another). So the sealer has to
rebuild the integrity anchor from the checkout, with `git diff <base>...<head>`, the same
three-dot form reference/producer.py:107 packs with.

That makes the checkout part of the verification path, which is a new way for a correct
contribution to look tampered with. `diff_source` exists so that failure is legible.
"""
from __future__ import annotations

import subprocess

from tests.conftest import VECTORS, _git, envelope_from_dir, load_producer, seal_json

producer = load_producer()


def _seal_attestation(*, body: str, repo, base: str, head: str, keys=None, tmp_path):
    args = ["--pr-body-env", "SCPE_PR_BODY", "--repo", str(repo),
            "--base", base, "--head", head, "--require", "true", "--level", "2"]
    if keys is not None:
        args += ["--keys", str(keys)]
    return seal_json(*args, env_extra={"SCPE_PR_BODY": body, "PR_BODY": body},
                     cwd=tmp_path)


def test_attestation_diff_is_recomputed_from_the_checkout(repo_with_fix, signing_key,
                                                          keys_file, tmp_path):
    repo, base, head = repo_with_fix
    env = tmp_path / "e.zip"
    producer.pack(repo=repo, base=base, head=head, out=env, login="octocat-test",
                  key=str(signing_key), created_at="2026-07-21T18:00:00Z",
                  repo_name="octocat-test/calc")
    body = "PR text\n\n" + producer.attest(envelope=env, out=None)

    data, rc = _seal_attestation(body=body, repo=repo, base=base, head=head,
                                 keys=keys_file, tmp_path=tmp_path)
    assert rc == 0
    assert data["status"] == "verified", data
    assert data["diff_source"] == "git"


def test_three_dot_diff_ignores_commits_that_landed_on_the_base_branch(
        repo_with_fix, signing_key, keys_file, tmp_path):
    """The contributor signs `branch-point...head`. By the time CI runs, the base branch
    has usually moved on — GitHub reports the CURRENT base tip as `base.sha`. Two-dot
    (`base..head`) would then fold everything that landed on main in the meantime into the
    diff and report `tampered` on an untouched contribution. Three-dot diffs from the merge
    base, which is what was signed."""
    repo, branch_point, head = repo_with_fix
    env = tmp_path / "e.zip"
    producer.pack(repo=repo, base=branch_point, head=head, out=env, login="octocat-test",
                  key=str(signing_key), created_at="2026-07-21T18:00:00Z",
                  repo_name="octocat-test/calc")
    body = "PR text\n\n" + producer.attest(envelope=env, out=None)

    # main moves on, entirely independently of the PR branch
    _git(repo, "checkout", "main")
    (repo / "UNRELATED.md").write_text("a doc that landed while the PR was open\n",
                                       encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "docs: unrelated")
    new_base = _git(repo, "rev-parse", "HEAD")
    assert new_base != branch_point

    data, _ = _seal_attestation(body=body, repo=repo, base=new_base, head=head,
                                keys=keys_file, tmp_path=tmp_path)
    assert data["status"] == "verified", data
    assert data["files"] == ["calc.py"], "the unrelated commit leaked into the diff"


def test_a_standalone_envelope_uses_its_enclosed_diff(tmp_path):
    """The other transport: an envelope zip carries `diff.patch`, so there is nothing to
    recompute and no repo to point at. The anchor is disclosed either way."""
    vector = VECTORS / "valid-minimal"
    env = envelope_from_dir(vector, tmp_path / "envelope.zip")
    data, rc = seal_json("--envelope", str(env), "--keys", str(vector / "keys"),
                         "--require", "true", "--level", "2", cwd=tmp_path)
    assert rc == 0
    assert data["status"] == "verified"
    assert data["diff_source"] == "enclosed"


def test_a_checkout_without_the_base_commit_says_so(repo_with_fix, signing_key,
                                                    keys_file, tmp_path):
    """actions/checkout defaults to `fetch-depth: 1`, which fetches the head commit and
    nothing else — `git diff base...head` cannot run, so there is no diff to hash and the
    verifier correctly reports `tampered` (§8 step 7 fails closed rather than guessing).

    A maintainer reading "tampered" on a contribution they trust needs to know the cause is
    their own workflow, so the sealer names it: `diff_source: "unavailable"` plus the fix in
    `diff_note` (kept separate from `detail`, which stays the verifier's own words). This
    mirrors the honesty reference/level1_lint.py:41-46 already practices about what a
    shallow checkout cannot see.
    """
    repo, base, head = repo_with_fix
    env = tmp_path / "e.zip"
    producer.pack(repo=repo, base=base, head=head, out=env, login="octocat-test",
                  key=str(signing_key), created_at="2026-07-21T18:00:00Z",
                  repo_name="octocat-test/calc")
    body = "PR text\n\n" + producer.attest(envelope=env, out=None)

    # A checkout that holds the head tree but not the base commit — what depth 1 gives you.
    shallow = tmp_path / "shallow"
    shallow.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(shallow)], check=True,
                   capture_output=True)
    _git(shallow, "config", "user.email", "ci@example.com")
    _git(shallow, "config", "user.name", "CI")
    (shallow / "calc.py").write_text((repo / "calc.py").read_text(encoding="utf-8"),
                                     encoding="utf-8")
    _git(shallow, "add", "-A")
    _git(shallow, "commit", "-m", "head only")

    data, rc = _seal_attestation(body=body, repo=shallow, base=base, head=head,
                                 keys=keys_file, tmp_path=tmp_path)
    assert rc == 0, data                      # a broken checkout is still a reportable state
    assert data["diff_source"] == "unavailable"
    assert data["status"] == "tampered", data
    assert "fetch-depth" in data["diff_note"], data["diff_note"]
    assert data["gate_pass"] is False
