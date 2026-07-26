"""The closed loop: the official producer writes it, the official verifier reads it, and
the sealer the Action runs turns that verdict into results.json. Offline, no public repo.

This is the test the whole repositioning exists for. Before it, nothing proved that
reference/producer.py and reference/standalone/verify_envelope.py understood each other
through the transport they actually use (SPEC §9 — an attestation block in a PR body),
and nothing proved that the Action's own command line could carry that verdict end to end.

  Phase A (contributor) -> reference/producer.py packs a real fix into a signed envelope
                           and attests it into the exact SCPE-ATTESTATION-v1 block a PR
                           body carries.
  Phase B (runner)      -> `python -m scpe.cli seal` from a checkout: the same command
                           action.yml runs, reading the body out of the environment (never
                           argv), recomputing the base...head diff from the checked-out
                           branch, and deferring the verdict to the one-file verifier.
  Phase C (contract)    -> results.json carries every field action.yml and
                           docs/workflows/scpe.yml read out of it.
  Phase D (gate)        -> require=true decides merge; require=false only reports.

The gate is NOT recomputed here. It used to be — this file modelled `gate_pass` in a local
helper — and a test that reimplements the decision cannot fail when the shipped decision is
wrong. The sealer computes it now; the test only reads it.

Everything is local: a throwaway ed25519 key, a `keys` file standing in for
https://github.com/<subject>.keys, and a git repo in tmp_path. No network, no gh, no
package install.
"""
from __future__ import annotations

from tests.conftest import _git, load_producer, seal_json

producer = load_producer()

# Everything action.yml (:115, :166, :175-181) and docs/workflows/scpe.yml (:126, :131,
# :138) read out of results.json. A field dropped from the sealer is a broken Action, and
# the failure would otherwise surface as a confusing KeyError inside a runner, not here.
ACTION_CONSUMED = ("status", "gate_pass", "require", "verified", "band", "flags",
                   "matched", "rules_checked", "added", "removed", "files", "tests",
                   "provenance", "hook", "login", "level")


def _pr_body(attestation_block: str) -> str:
    return ("## Fix add()\n\n`add(a, b)` was subtracting instead of adding. "
            "One-line fix.\n\n" + attestation_block)


# ---------------------------------------------------------------------- POSITIVE

def test_signed_pr_verifies_seals_and_gate_passes(repo_with_fix, signing_key, keys_file,
                                                  tmp_path):
    repo, base, head = repo_with_fix

    # ---- Phase A: producer (contributor side), fully offline ----
    env = tmp_path / "envelope.zip"
    producer.pack(repo=repo, base=base, head=head, out=env,
                  login="octocat-e2e", key=str(signing_key), ai_mode="assisted",
                  ai_notes="fix add() sign bug", created_at="2026-07-21T18:00:00Z",
                  repo_name="octocat-e2e/calc")
    block = producer.attest(envelope=env, out=None)
    assert "SCPE-ATTESTATION-v1" in block

    # ---- Phase B: the runner's own command line ----
    # The body reaches the sealer through the environment, exactly as action.yml passes
    # it: a hostile PR body must never become a shell word or an argv element.
    data, rc = seal_json(
        "--pr-body-env", "SCPE_PR_BODY",
        "--repo", str(repo), "--base", base, "--head", head,
        "--keys", str(keys_file), "--require", "true", "--level", "2",
        "--render-comment",
        env_extra={"SCPE_PR_BODY": _pr_body(block), "PR_BODY": _pr_body(block)},
        cwd=tmp_path)

    # SPEC §8: a status is a state, not a crash. The sealer exits 0 whenever it produced
    # a result at all — the Action needs the artifact to reach the trusted job even when
    # the verdict is bad.
    assert rc == 0, data

    # ---- Phase C: the verdict, and the fields the Action reads ----
    assert data["status"] == "verified", data
    assert data["verified"] is True
    for field in ACTION_CONSUMED:
        assert field in data, f"results.json lost {field!r}, which the Action reads"

    # The diff was NOT taken from the producer's own zip: an attestation carries no diff,
    # so the sealer had to recompute base...head from the checkout and the verifier had to
    # find that hash inside the signed manifest.
    assert data["diff_source"] == "git"
    assert data["key_source"] == "flag"        # --keys, not a submitter-chosen key set
    assert data["spec_version"] == "scpe/0.1"
    assert data["provider"] == "github"
    assert data["subject"] == "octocat-e2e"
    assert data["login"] == data["subject"]    # deprecated alias, still emitted
    assert data["subject_type"] == "code-change"
    assert data["target_repo"] == "octocat-e2e/calc"
    assert data["base_sha"] == base and data["head_sha"] == head
    assert data["attestations"] == []          # none were packed

    # Provenance now comes from the SIGNED ai_disclosure block, not from an unsigned field.
    assert data["ai_disclosure"]["mode"] == "assisted"
    assert data["disclosure_present"] is True
    assert data["provenance"].startswith("AI-assisted")
    assert "fix add() sign bug" in data["provenance"]

    # Risk + counts describe the recomputed diff (one line changed, one file).
    assert data["band"] == "LOW" and data["flags"] == []
    assert data["added"] == 1 and data["removed"] == 1
    assert data["files"] == ["calc.py"]
    assert data["tests"] == {"ran": False, "ok": False, "summary": "not run"}

    # ---- Phase D: the gate, as computed by the sealer ----
    assert data["require"] is True
    assert data["gate_pass"] is True
    assert not data.get("fail_message")

    # --render-comment pre-renders in the UNTRUSTED job so the trusted job only pastes.
    comment = data["comment"]
    assert comment.startswith("### scpe")
    assert "octocat-e2e" in comment and "```" in comment


# ---------------------------------------------------------------------- NEGATIVE

def test_unsigned_pr_is_unattested_and_gate_rejects(repo_with_fix, tmp_path):
    """The ordinary PR: a contributor who never ran the producer. `unattested` is a
    state (SPEC §8), so the step still succeeds — but require=true must refuse to merge
    it, and must say so in a message the trusted job can post verbatim."""
    repo, base, head = repo_with_fix
    plain_body = "## Fix add()\n\nOne-line fix, no attestation.\n"

    data, rc = seal_json(
        "--pr-body-env", "SCPE_PR_BODY",
        "--repo", str(repo), "--base", base, "--head", head,
        "--require", "true", "--level", "2",
        env_extra={"SCPE_PR_BODY": plain_body, "PR_BODY": plain_body},
        cwd=tmp_path)

    assert rc == 0, data                      # a state, never an error
    assert data["status"] == "unattested"
    assert data["verified"] is False
    assert data["gate_pass"] is False
    assert data["fail_message"], "a failing gate must hand the trusted job a message"
    assert "scpe/0.1" in data["fail_message"]

    # Nothing was VERIFIED, so nothing about the contributor is claimed: no key anchor, no
    # disclosure, no provenance line. The risk band is different in kind — it is scanned
    # from the diff in the checkout, which exists whether or not anyone signed it, so an
    # unattested PR still gets a real band. Asserting it empty here would delete the seal's
    # only useful output on exactly the PRs that arrive carrying no proof at all.
    assert data["key_source"] is None
    assert data["disclosure_present"] is False
    assert "band" in data and data["band"] in ("", "LOW", "MEDIUM", "HIGH")
    assert data["flags"] == []
    assert data["provenance"] == ""


def test_same_unsigned_pr_passes_when_require_is_false(repo_with_fix, tmp_path):
    """require=false is the informational default: the status is still reported honestly,
    the gate simply does not act on it. Gating is policy layered on verification, never
    something baked into the verifier."""
    repo, base, head = repo_with_fix
    plain_body = "## Fix add()\n\nOne-line fix, no attestation.\n"

    data, rc = seal_json(
        "--pr-body-env", "SCPE_PR_BODY",
        "--repo", str(repo), "--base", base, "--head", head,
        "--require", "false", "--level", "2",
        env_extra={"SCPE_PR_BODY": plain_body, "PR_BODY": plain_body},
        cwd=tmp_path)

    assert rc == 0
    assert data["status"] == "unattested"     # informational != silent
    assert data["require"] is False
    assert data["gate_pass"] is True
    # The message is still computed — it is a PREVIEW of what turning the gate on would
    # say. The trusted job only reads it when gate_pass is false, so previewing costs
    # nothing and lets a maintainer see the consequence before opting in.
    assert data["fail_message"]


def test_a_tampered_diff_is_named_not_just_rejected(repo_with_fix, signing_key, keys_file,
                                                    tmp_path):
    """Sign the fix, then push a further commit the signature never covered. The gate must
    fail, and `detail` must say WHICH check failed — "not-verified" told a maintainer
    nothing actionable; "tampered: diff sha256 does not match" tells them everything."""
    repo, base, head = repo_with_fix
    env = tmp_path / "envelope.zip"
    producer.pack(repo=repo, base=base, head=head, out=env, login="octocat-e2e",
                  key=str(signing_key), created_at="2026-07-21T18:00:00Z",
                  repo_name="octocat-e2e/calc")
    body = _pr_body(producer.attest(envelope=env, out=None))

    # a commit added AFTER signing — the classic "sign clean, then slip one in"
    (repo / "calc.py").write_text(
        "def add(a, b):\n    return a + b\n\n\ndef exfil():\n    import socket\n",
        encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "chore: unrelated")
    new_head = _git(repo, "rev-parse", "HEAD")

    data, rc = seal_json(
        "--pr-body-env", "SCPE_PR_BODY",
        "--repo", str(repo), "--base", base, "--head", new_head,
        "--keys", str(keys_file), "--require", "true", "--level", "2",
        env_extra={"SCPE_PR_BODY": body, "PR_BODY": body}, cwd=tmp_path)

    assert rc == 0
    assert data["status"] == "tampered", data
    assert data["gate_pass"] is False
    assert "diff_sha256" in data["detail"] or "diff sha256" in data["detail"], data["detail"]
    assert "tampered" in data["fail_message"]
