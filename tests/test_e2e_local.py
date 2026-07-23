"""End-to-end local proof of the whole SCPE path -- no network, no public repo.

Chains every piece of the real flow together in one process, offline:

  Phase A (producer)    -> reference/producer.py: pack a real fix into a signed
                            envelope, then attest() it into the exact
                            SCPE-ATTESTATION-v1 block a PR body carries.
  Phase B (maintainer)  -> what the GitHub Action's `verify` job actually does:
                            extract the attestation block from the PR body,
                            independently RECOMPUTE the base...head diff from the
                            checked-out branch (never trust the diff.patch a
                            producer chose to embed), and run the reference
                            verifier (reference/standalone/verify_envelope.py,
                            subprocess, --keys local `keys` file standing in for
                            https://github.com/<login>.keys) against it.
  Phase C (seal)         -> render the decision-first PR seal from the verified
                            result via scpe.seal (the SAME box/pill/summary
                            functions the real `scpe seal` CLI renders from).
  Phase D (gate)         -> the require=true GATE decision computed exactly like
                            action.yml / docs/workflows/scpe.yml: an unverified or
                            absent attestation FAILS the check and the seal job
                            posts the literal "Not verifiable" comment; a verified
                            attestation passes it.

Two outcomes are asserted end to end:
  * POSITIVE -- a PR with a valid signed attestation -> verified, a seal renders,
    and the require=true gate PASSES.
  * NEGATIVE -- a PR with NO attestation at all -> unattested -> the require gate
    REJECTS it with the exact "Not verifiable" comment (never silently passes).

Throwaway ed25519 key + a local `keys` file standing in for
https://github.com/<login>.keys -- same offline approach as
tests/test_producer_roundtrip.py and spec/test-vectors. Nothing here touches the
network, git remotes, or `gh`.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scpe.seal import pr_pill, pr_seal, pr_summary_line, risk_band

ROOT = Path(__file__).resolve().parent.parent
PRODUCER_PATH = ROOT / "reference" / "producer.py"
VERIFIER_PATH = ROOT / "reference" / "standalone" / "verify_envelope.py"

# Load reference/producer.py by path, exactly like tests/test_producer_roundtrip.py --
# it lives outside the scpe package on purpose (the spec's auditable reference impl).
_spec = importlib.util.spec_from_file_location("scpe_producer_ref_e2e", PRODUCER_PATH)
producer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(producer)

# The literal comment the trusted "seal" job posts on require-mode rejection
# (docs/workflows/scpe.yml, "Post the seal comment (or the gate failure)" step).
# Written as unicode escapes, not literal bytes, so a failed assertion can still be
# printed on a cp1252 Windows console without crashing the test run.
NOT_VERIFIABLE_COMMENT = (
    "❌ Not verifiable — this repository requires a signed SCPE "
    "contribution (spec scpe/0.1)."
)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args],
                          check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def signing_key(tmp_path: Path) -> Path:
    key = tmp_path / "scpe_e2e_ed25519"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(key), "-N", "", "-q"],
                   check=True, capture_output=True)
    return key


@pytest.fixture
def keys_file(signing_key: Path, tmp_path: Path) -> Path:
    """The local stand-in for https://github.com/<login>.keys -- the bare public key."""
    kf = tmp_path / "keys"
    kf.write_bytes(Path(str(signing_key) + ".pub").read_bytes())
    return kf


@pytest.fixture
def repo_with_fix(tmp_path: Path) -> tuple[Path, str, str]:
    """A throwaway repo: a base commit with a buggy `add`, then a second commit (the
    'PR branch') with the one-line fix. Returns (repo, base_sha, head_sha)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    _git(repo, "config", "user.email", "e2e@example.com")
    _git(repo, "config", "user.name", "E2E")
    (repo / "calc.py").write_text(
        "def add(a, b):\n    return a - b  # BUG: should add\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "base: buggy add()")
    base = _git(repo, "rev-parse", "HEAD")

    _git(repo, "checkout", "-b", "fix/add-arithmetic")
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "fix: add() should add, not subtract")
    head = _git(repo, "rev-parse", "HEAD")
    return repo, base, head


def _recompute_branch_diff(repo: Path, base: str, head: str) -> bytes:
    """What the maintainer/Action side actually has to work with: independently
    git-diff the checked-out base...head and normalize it exactly per SPEC §6 --
    never trust the diff.patch bytes a producer chose to package in the envelope."""
    raw = subprocess.run(["git", "-C", str(repo), "diff", f"{base}...{head}"],
                         check=True, capture_output=True).stdout
    return producer.normalize_diff(raw)


def _run_verifier(path: Path, *, keys: Path | None = None, diff: Path | None = None) -> dict:
    """Exactly the CLI invocation the verify job makes: the standalone reference
    verifier, as a subprocess, --json."""
    args = [sys.executable, str(VERIFIER_PATH), str(path), "--json"]
    if keys is not None:
        args += ["--keys", str(keys)]
    if diff is not None:
        args += ["--diff", str(diff)]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
    assert proc.stdout.strip(), f"no verifier output; stderr: {proc.stderr[-500:]}"
    return json.loads(proc.stdout)


def _gate_decision(status: str, *, require: bool) -> dict:
    """The require-mode GATE decision, computed exactly like action.yml's untrusted
    step (`data["gate_pass"] = status == "verified"`, default require=false ->
    gate_pass=True unconditionally) and posted by docs/workflows/scpe.yml's trusted
    "seal" step (the literal "Not verifiable" comment when gate_pass is False)."""
    gate_pass = (not require) or status == "verified"
    comment = None if gate_pass else NOT_VERIFIABLE_COMMENT
    return {"status": status, "require": require, "gate_pass": gate_pass, "comment": comment}


def _render_seal(*, login: str, verified: bool, diff_text: str,
                 tests_ok: bool = True, tests_summary: str = "1 passed") -> str:
    """Render the decision-first PR seal from already-verified data, reusing the
    SAME box/pill/summary functions the real `scpe seal` CLI renders from
    (scpe/seal.py) -- this test never reimplements the seal, only feeds it real,
    verifier-derived inputs."""
    band = risk_band(diff_text)
    pill = pr_pill(band["band"], login, verified, tests_ok)
    summary = pr_summary_line(band["band"], verified, tests_ok)
    box = pr_seal(login=login, verified=verified, profile=f"https://github.com/{login}",
                 band=band["band"], flags=band["flags"], added=1, removed=1,
                 files=["calc.py"], tests_ok=tests_ok, tests_summary=tests_summary,
                 provenance="human", rules_checked=band["rules_checked"])
    return pill + "\n\n" + summary + "\n\n" + box


# ---------------------------------------------------------------------- POSITIVE

def test_signed_pr_verifies_seals_and_gate_passes(
        repo_with_fix, signing_key, keys_file, tmp_path):
    """Phase A -> B -> C -> D, signed case: pack+attest a real fix, extract from a
    realistic PR body, independently recompute the diff, verify -> "verified", a
    seal renders, and the require=true gate PASSES (no "Not verifiable")."""
    repo, base, head = repo_with_fix

    # ---- Phase A: producer (contributor side), fully offline ----
    env = tmp_path / "envelope.zip"
    producer.pack(repo=repo, base=base, head=head, out=env,
                 login="octocat-e2e", key=str(signing_key), ai_mode="assisted",
                 ai_notes="fix add() sign bug", created_at="2026-07-21T18:00:00Z",
                 repo_name="octocat-e2e/calc")
    attestation_block = producer.attest(envelope=env, out=None)
    assert "SCPE-ATTESTATION-v1" in attestation_block

    pr_body = (
        "## Fix add()\n\n`add(a, b)` was subtracting instead of adding. "
        "One-line fix.\n\n" + attestation_block
    )
    pr_body_file = tmp_path / "pr_body.md"
    pr_body_file.write_text(pr_body, encoding="utf-8")

    # ---- Phase B: maintainer / Action verify job ----
    # extract: the attestation is actually present in the PR body (same regex the
    # standalone verifier itself uses to locate it).
    assert producer.ATTESTATION_RE.search(pr_body), "attestation not found in PR body"
    # recompute: independently diff the checked-out branch, do NOT reuse the
    # diff.patch the producer happened to zip during pack().
    recomputed_diff = _recompute_branch_diff(repo, base, head)
    diff_file = tmp_path / "recomputed.diff"
    diff_file.write_bytes(recomputed_diff)

    result = _run_verifier(pr_body_file, keys=keys_file, diff=diff_file)
    assert result["status"] == "verified", result
    assert result["attestations"] == []  # no attestations were packed

    # ---- Phase C: a seal renders from the verified result ----
    seal_text = _render_seal(login="octocat-e2e", verified=True,
                             diff_text=recomputed_diff.decode("utf-8"))
    assert "octocat-e2e" in seal_text
    assert "verified" in seal_text
    assert "UNVERIFIED" not in seal_text

    # ---- Phase D: require-mode gate ----
    decision = _gate_decision(result["status"], require=True)
    assert decision["gate_pass"] is True
    assert decision["comment"] is None


# ---------------------------------------------------------------------- NEGATIVE

def test_unsigned_pr_is_unattested_and_gate_rejects(repo_with_fix, tmp_path):
    """Same fix, same repo -- but the PR body carries NO SCPE attestation at all
    (the ordinary case: a contributor who never ran the producer). The verify job
    must call it "unattested", and the require=true gate must REJECT it with the
    exact comment the real Action posts -- never silently pass an unsigned PR."""
    repo, base, head = repo_with_fix

    pr_body = ("## Fix add()\n\n`add(a, b)` was subtracting instead of adding. "
               "One-line fix.\n")
    pr_body_file = tmp_path / "pr_body_unsigned.md"
    pr_body_file.write_text(pr_body, encoding="utf-8")
    assert not producer.ATTESTATION_RE.search(pr_body)

    recomputed_diff = _recompute_branch_diff(repo, base, head)
    diff_file = tmp_path / "recomputed_unsigned.diff"
    diff_file.write_bytes(recomputed_diff)

    result = _run_verifier(pr_body_file, diff=diff_file)
    assert result["status"] == "unattested", result

    decision = _gate_decision(result["status"], require=True)
    assert decision["gate_pass"] is False
    assert decision["comment"] == NOT_VERIFIABLE_COMMENT

    # sanity: the SAME unsigned PR passes fine when require=false (today's
    # default, informational-only path) -- the gate is opt-in policy on top of
    # verification, not a hard block baked into the verifier itself.
    lenient = _gate_decision(result["status"], require=False)
    assert lenient["gate_pass"] is True
    assert lenient["comment"] is None
