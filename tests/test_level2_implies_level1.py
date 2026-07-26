"""docs/LEVELS.md claims level 2 implies level 1: a verified signed contribution has
already disclosed its AI use, "via a stronger, signed mechanism instead of an unsigned
trailer". This file is what makes that claim true instead of merely written down.

It used to be structural in the old format — `Envelope.provenance` was a required
dataclass field with no default, so an envelope without a disclosure could not be parsed.
The spec format has no such property: `ai_disclosure` is REQUIRED by
spec/manifest.schema.json, and that schema says of itself that it is descriptive/advisory
only. reference/standalone/verify_envelope.py never reads the field — so a manifest with
no disclosure at all reaches `verified`.

The verifier is not the place to fix that. Changing it would change the normative meaning
of §8 for the eighteen vectors and for the Go and Rust ports, over a field §8 does not
mention. The claim belongs to the GATE, which is policy: `disclosure_present` reports the
fact and `gate_pass` acts on it. These tests pin both halves — including the part that is
uncomfortable to state out loud, that the verifier alone says `verified` here.
"""
from __future__ import annotations

import io
import json
import zipfile

from tests.conftest import load_producer, run_verifier, seal_json

producer = load_producer()


def _envelope_without_disclosure(repo, base, head, key, out, *, login="octocat-test"):
    """A correctly signed spec envelope whose manifest carries no `ai_disclosure` block.
    Built from the reference producer's own manifest builder so nothing here is a
    hand-rolled near-manifest — only the one field is removed, then it is signed for real."""
    diff_bytes, files, stats, base_sha, head_sha = producer.compute_diff(repo, base, head)
    m = producer.build_manifest(
        login=login, fingerprint=producer.key_fingerprint(key),
        repo="octocat-test/calc", base_sha=base_sha,
        dsha=producer.diff_sha256(diff_bytes), head_sha=head_sha, files=files,
        stats=stats, ai_mode="none", ai_notes=None,
        created_at="2026-07-21T18:00:00Z")
    del m["ai_disclosure"]                       # the whole point of the fixture
    manifest_bytes = producer.serialize_manifest(m)
    sig = producer.sign_manifest(manifest_bytes, key)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zipfile.ZipInfo("manifest.json"), manifest_bytes)
        zf.writestr(zipfile.ZipInfo("manifest.sig"), sig)
        zf.writestr(zipfile.ZipInfo("diff.patch"), diff_bytes)
    out.write_bytes(buf.getvalue())
    return out


def test_the_verifier_alone_calls_it_verified(repo_with_fix, signing_key, keys_file,
                                              tmp_path):
    """The uncomfortable half, asserted rather than assumed. If this ever starts failing,
    the verifier began enforcing a field §8 does not define and the ports have drifted."""
    repo, base, head = repo_with_fix
    env = _envelope_without_disclosure(repo, base, head, signing_key, tmp_path / "e.zip")

    result = json.loads(run_verifier(env, keys=keys_file).stdout)
    assert result["status"] == "verified", result


def test_a_verified_contribution_without_a_disclosure_fails_the_gate(
        repo_with_fix, signing_key, keys_file, tmp_path):
    repo, base, head = repo_with_fix
    env = _envelope_without_disclosure(repo, base, head, signing_key, tmp_path / "e.zip")

    data, rc = seal_json("--envelope", str(env), "--keys", str(keys_file),
                         "--require", "true", "--level", "2", cwd=tmp_path)
    assert rc == 0
    # The signature verdict is reported honestly — the contribution IS signed.
    assert data["status"] == "verified"
    assert data["verified"] is True
    assert data["ai_disclosure"] is None
    assert data["disclosure_present"] is False
    # ...and the gate still refuses it, because level 2 promises level 1.
    assert data["gate_pass"] is False
    assert data["fail_message"]
    assert "disclosur" in data["fail_message"].lower(), data["fail_message"]


def test_require_false_reports_the_missing_disclosure_without_blocking(
        repo_with_fix, signing_key, keys_file, tmp_path):
    """Informational mode still surfaces the gap — a maintainer who has not opted into
    gating should still be able to see that a contribution disclosed nothing."""
    repo, base, head = repo_with_fix
    env = _envelope_without_disclosure(repo, base, head, signing_key, tmp_path / "e.zip")

    data, _ = seal_json("--envelope", str(env), "--keys", str(keys_file),
                        "--require", "false", "--level", "2", cwd=tmp_path)
    assert data["disclosure_present"] is False
    assert data["gate_pass"] is True


def test_mode_none_is_a_disclosure_not_a_missing_one(repo_with_fix, signing_key,
                                                     keys_file, tmp_path):
    """"I used no AI" is an answer. `mode: "none"` is a signed statement and must pass the
    gate — otherwise the level-1 claim would quietly become "you must have used AI"."""
    repo, base, head = repo_with_fix
    env = tmp_path / "declared.zip"
    producer.pack(repo=repo, base=base, head=head, out=env, login="octocat-test",
                  key=str(signing_key), ai_mode="none",
                  created_at="2026-07-21T18:00:00Z", repo_name="octocat-test/calc")

    data, _ = seal_json("--envelope", str(env), "--keys", str(keys_file),
                        "--require", "true", "--level", "2", cwd=tmp_path)
    assert data["status"] == "verified"
    assert data["ai_disclosure"]["mode"] == "none"
    assert data["disclosure_present"] is True
    assert data["gate_pass"] is True
    assert data["provenance"] == "hand-authored"
