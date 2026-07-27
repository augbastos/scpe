"""Bind a verified envelope to the pull request it is being presented on.

The signature proves the manifest is authentic and the diff digest proves the change was
not altered. Neither proves the contribution is being presented *where it was signed for*.
The manifest carries `subject.target.repo` and `subject.target.base_sha` precisely so that
question can be answered, and until this module existed those two fields were read, copied
into results.json, and never compared with anything.

The gap that leaves is a replay: lift the attestation off a public pull request, open a
pull request on a different repository whose diff normalizes to the same bytes, and the
seal reports `verified` with the original signer's name on it. The signature is genuine,
the digest matches, and the context is wrong. Reproduced before this was written.

Two checks, deliberately of different shapes:

* **repo** — string equality against the repository the workflow is running in, case-folded
  because forges treat `Owner/Name` and `owner/name` as one repository.

* **base** — *ancestry*, not equality. `github.event.pull_request.base.sha` is the tip of
  the base branch at event time and moves whenever anyone merges anything, so demanding it
  equal the signed `base_sha` would fail every open pull request the moment the branch
  advanced. What the signature actually commits to is a commit the contributor diffed from,
  and the honest question is whether that commit is in this pull request's history at all.
  The diff digest already pins *what* changed; ancestry pins *where it came from*.

Both are policy, enforced at the gate, and neither is a SPEC §8 status: the eight statuses
are the conformance contract three implementations agree on, and a context mismatch is a
property of the presentation rather than of the envelope. An envelope that fails these is
still a perfectly valid envelope — somewhere else.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ContextCheck:
    """The outcome of binding an envelope to where it was presented.

    `ok` is True when nothing contradicted the signed context — including when there was
    nothing to check, so callers that never supply expectations behave exactly as before.
    `checked` says whether any comparison actually ran, so a caller can tell "matched" from
    "no expectation given" instead of reading an unqualified pass.
    """

    ok: bool
    checked: bool
    detail: str = ""

    @property
    def mismatch(self) -> bool:
        return self.checked and not self.ok


def _same_repo(signed: str, expected: str) -> bool:
    return signed.strip().casefold() == expected.strip().casefold()


def _is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool | None:
    """True / False, or None when git cannot answer.

    None matters: with a shallow checkout the base commit is simply absent, and treating
    "not in this clone" as "not an ancestor" would fail honest contributions on a
    misconfigured runner. The caller reports the ambiguity instead of guessing.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, descendant],
            capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode == 0:
        return True
    if proc.returncode == 1:
        return False
    return None          # 128: unknown revision, shallow clone, not a repository


def check(*, manifest: dict, repo_dir: Path, head: str | None,
          expect_repo: str | None, expect_base: bool) -> ContextCheck:
    """Compare a manifest's signed target against the checkout it is presented in.

    `manifest` is the SIGNED manifest — call this only after the signature verified, or the
    values are attacker-controlled JSON. Subjects other than `code-change` carry no target
    and are skipped: an `artifact` envelope is about bytes, not about a repository.
    """
    subject = manifest.get("subject")
    subject = subject if isinstance(subject, dict) else {}
    if subject.get("type") != "code-change":
        return ContextCheck(ok=True, checked=False)

    target = subject.get("target")
    target = target if isinstance(target, dict) else {}
    signed_repo = target.get("repo")
    signed_base = target.get("base_sha")

    if expect_repo:
        if not isinstance(signed_repo, str) or not signed_repo:
            return ContextCheck(False, True,
                                "the manifest declares no target repository to check against")
        if not _same_repo(signed_repo, expect_repo):
            return ContextCheck(False, True,
                                f"signed for {signed_repo}, presented on {expect_repo}")

    if expect_base and head:
        if not isinstance(signed_base, str) or not signed_base:
            return ContextCheck(False, True,
                                "the manifest declares no base commit to check against")
        verdict = _is_ancestor(Path(repo_dir), signed_base, head)
        if verdict is None:
            return ContextCheck(
                False, True,
                f"cannot tell whether the signed base {signed_base[:12]} is in this "
                "history — check out with fetch-depth: 0")
        if not verdict:
            return ContextCheck(
                False, True,
                f"the signed base {signed_base[:12]} is not an ancestor of this pull "
                "request; the envelope was made against a different history")

    return ContextCheck(ok=True, checked=bool(expect_repo or (expect_base and head)))
