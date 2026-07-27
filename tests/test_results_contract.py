"""The results.json compatibility lock.

`action.yml` is published on the Marketplace and its level-2 branch used to run
`pipx run --spec scpe-protocol scpe seal` with NO version pin. Every repository still
pinned to an old Action tag therefore starts executing this package the moment it lands on
PyPI. Those callers read a fixed set of keys out of results.json, and one of them
(`_render_comment`) indexes `band` without a default. So the contract here is additive:
new fields are free, a missing old field is a red X on a stranger's pull request.

The assertion is deliberately SUPERSET, never equality. The test this replaces
(test_cli_seal.py:57) asserted `set(data) == {...}`, which froze the format so tightly
that adding `status` — a field the Action already needed — would have failed it.
"""
from __future__ import annotations

import io
import zipfile

from tests.conftest import VECTORS, envelope_from_dir, seal_json

# Exactly the keys a consumer reads today: action.yml (:115, :166, :170-181),
# docs/workflows/scpe.yml (:126, :131, :138), the seal renderer, and pr_seal.
LEGACY_KEYS = {"login", "verified", "band", "flags", "matched", "rules_checked",
               "added", "removed", "files", "tests", "provenance", "hook",
               "status", "require", "gate_pass"}

# Fields the spec format adds. Named here so a rename shows up as a failing test rather
# than as a silently missing column in someone's seal.
SPEC_KEYS = {"spec_version", "provider", "subject", "subject_type", "key_source",
             "key_fingerprint", "profile", "attestations", "ai_disclosure",
             "disclosure_present", "detail", "diff_source", "diff_note", "signed_stats",
             "target_repo", "base_sha", "head_sha", "level", "fail_message"}


def _verified_results(tmp_path) -> dict:
    vector = VECTORS / "valid-minimal"
    env = envelope_from_dir(vector, tmp_path / "envelope.zip")
    data, rc = seal_json("--envelope", str(env), "--keys", str(vector / "keys"),
                         "--require", "true", "--level", "2", cwd=tmp_path)
    assert rc == 0
    return data


def test_every_legacy_field_survives(tmp_path):
    data = _verified_results(tmp_path)
    missing = LEGACY_KEYS - set(data)
    assert not missing, f"results.json dropped {sorted(missing)} — old Action tags read these"


def test_legacy_field_types_are_unchanged(tmp_path):
    data = _verified_results(tmp_path)
    assert isinstance(data["login"], str)
    assert isinstance(data["verified"], bool)
    assert isinstance(data["band"], str)
    assert isinstance(data["flags"], list)
    assert isinstance(data["matched"], list)
    assert isinstance(data["rules_checked"], int)
    assert isinstance(data["added"], int) and isinstance(data["removed"], int)
    assert isinstance(data["files"], list)
    assert isinstance(data["tests"], dict)
    assert set(data["tests"]) == {"ran", "ok", "summary"}
    assert isinstance(data["provenance"], str)
    assert isinstance(data["hook"], str)
    assert isinstance(data["require"], bool) and isinstance(data["gate_pass"], bool)
    assert data["level"] == "2"


def test_the_spec_fields_are_all_present(tmp_path):
    data = _verified_results(tmp_path)
    missing = SPEC_KEYS - set(data)
    assert not missing, f"results.json is missing spec fields {sorted(missing)}"


def test_band_is_always_present_even_when_the_pr_is_unattested(tmp_path, repo_with_fix):
    """`_render_comment` does `results["band"]` with no default, so an absent band is a
    crash inside a maintainer's trusted job — the key must always be there.

    An unattested PR still has a diff: the band is scanned from `--base..--head` in the
    checkout, not from the attestation, so a PR with no envelope is still reported with a
    real risk band. Asserting `band == ""` here would be asserting the opposite of the
    behaviour that makes the seal useful on exactly the PRs that carry no proof.
    """
    repo, base, head = repo_with_fix
    body = "no attestation here\n"
    data, rc = seal_json("--pr-body-env", "SCPE_PR_BODY", "--repo", str(repo),
                         "--base", base, "--head", head, "--require", "false",
                         "--level", "2",
                         env_extra={"SCPE_PR_BODY": body, "PR_BODY": body}, cwd=tmp_path)
    assert rc == 0
    assert data["status"] == "unattested"
    assert "band" in data, "band must never be absent — the renderer indexes it directly"
    assert data["band"] in ("", "LOW", "MEDIUM", "HIGH")
    assert data["flags"] == [] and data["matched"] == []
    assert data["hook"] == ""          # dead field, kept only so old renderers survive


def test_a_format_b_zip_from_an_old_tag_is_unattested_not_a_crash(tmp_path):
    """The pre-0.2 package had its own envelope format (envelope.json + a signature over a
    canonical re-serialization). A repository pinned to an old Action tag still commits one
    and still points `envelope:` at it. That input has to come back as `unattested` and
    exit 0 — a stack trace here would turn every one of those PRs red overnight."""
    legacy = tmp_path / "legacy-envelope.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("envelope.json", '{"manifest": {"protocol_version": "1"}}')
        zf.writestr("signature", "not an SSHSIG")
    legacy.write_bytes(buf.getvalue())

    data, rc = seal_json("--envelope", str(legacy), "--require", "true", "--level", "2",
                         cwd=tmp_path)
    assert rc == 0, data
    assert data["status"] == "unattested"
    assert LEGACY_KEYS <= set(data)
    assert data["gate_pass"] is False       # honest: it is not a verifiable contribution
    assert data["fail_message"]


def test_the_risk_scan_is_labelled_as_an_action_extension(tmp_path):
    """The LOW/MED/HIGH scan is not in SPEC.md. After the cleanup it is most of what the
    package contains besides the adapter, so a reader could easily take it for part of the
    protocol — and a project whose product is provenance clarity cannot ship an unlabelled
    heuristic under the protocol's own name."""
    data = _verified_results(tmp_path)
    assert data["risk_scan"]["in_spec"] is False
    assert data["risk_scan"]["note"]
    # ...and it must never have moved the verdict.
    assert data["status"] == "verified" and data["band"] in {"LOW", "MED", "HIGH"}


def test_ai_recheck_is_gone_and_nothing_pretends_otherwise(tmp_path):
    """The owner-LLM re-check was a stub that never called a model. It is deleted rather
    than kept as an empty field: a key that always says "configured" is worse than no key,
    because a reader takes it for a second opinion that never happened."""
    data = _verified_results(tmp_path)
    assert "ai_recheck" not in data
