"""results.json against the eighteen normative vectors: the sealer REPORTS the verifier's
verdict, it never forms one.

The vectors are the conformance contract of SPEC §8 (tests/test_spec_vectors.py holds the
verifier itself to them). What this file adds is the layer above: for every vector, the
status, key anchor, profile, attestation summary and detail that come out of the packaged
sealer must be the same values the standalone verifier printed — verbatim, not "equivalent",
not re-derived. A sealer that re-implemented any part of §8 would be a second verifier with
its own bugs, and the four ports (Python, Go, Rust, and this adapter) would stop agreeing.

Each vector directory is repacked as an envelope zip so it can be handed to `--envelope`;
the vector's own `keys` file is passed as `--keys`, which is how spec/test-vectors/README.md
says to verify offline.
"""
from __future__ import annotations

import json

import pytest

from tests.conftest import VECTORS, envelope_from_dir, run_verifier, seal_json

VECTOR_DIRS = sorted(
    d for d in VECTORS.iterdir()
    if d.is_dir() and not d.name.startswith("_") and (d / "expected.json").is_file()
)

# The complete §8 status set. `status` is now one of these eight verbatim — the old
# "not-verified"/"n/a" summaries are gone, because "the signature did not verify" and
# "the diff was changed after signing" are different problems for a maintainer.
SPEC_STATUSES = {"unattested", "unsupported-version", "unsupported-provider",
                 "unsupported-subject", "identity-unverifiable", "signature-invalid",
                 "tampered", "verified"}


def test_all_vectors_present():
    assert len(VECTOR_DIRS) == 18, [d.name for d in VECTOR_DIRS]


@pytest.mark.parametrize("vector", VECTOR_DIRS, ids=lambda d: d.name)
def test_results_mirror_the_reference_verifier(vector, tmp_path):
    env = envelope_from_dir(vector, tmp_path / "envelope.zip")
    keys = vector / "keys"
    expected = json.loads((vector / "expected.json").read_text(encoding="utf-8"))

    reference = json.loads(run_verifier(vector, keys=keys).stdout)
    data, rc = seal_json("--envelope", str(env), "--keys", str(keys),
                         "--require", "true", "--level", "2", cwd=tmp_path)

    # A bad status is a state, not a failure of the step (SPEC §8) — the artifact has to
    # reach the trusted job either way, so the sealer exits 0 on all eighteen.
    assert rc == 0, data

    assert data["status"] == expected["status"], data
    assert data["status"] in SPEC_STATUSES
    # ...and it is the verifier's own word, carried through untouched.
    assert data["status"] == reference["status"]
    assert data["key_source"] == reference["key_source"]
    assert data["profile"] == reference["profile"]
    assert data["attestations"] == reference["attestations"]
    assert data["detail"] == reference["detail"]

    # The one derived boolean, and the only rule for reading it.
    assert data["verified"] is (data["status"] == "verified")

    # Every vector's manifest declares an ai_disclosure, so the level-1 claim holds and
    # the gate reduces to the verification verdict alone.
    assert data["disclosure_present"] is True
    assert data["require"] is True
    assert data["gate_pass"] is data["verified"]
    if not data["gate_pass"]:
        assert data["fail_message"], "a failing gate must carry a postable message"
        assert data["status"] in data["fail_message"]


@pytest.mark.parametrize("vector", VECTOR_DIRS, ids=lambda d: d.name)
def test_key_anchor_is_the_operator_flag_not_a_bundled_key(vector, tmp_path):
    """`--keys` must win over anything travelling inside the package. A `bundled` key set
    was chosen by whoever submitted the envelope, so a pass anchored on it means "these
    bytes match a key that came with them", not "the named account signed this" — the
    seal has to be able to tell those apart, which starts with reporting the anchor."""
    env = envelope_from_dir(vector, tmp_path / "envelope.zip")
    data, _ = seal_json("--envelope", str(env), "--keys", str(vector / "keys"),
                        "--require", "false", "--level", "2", cwd=tmp_path)
    # None only where the verdict was reached before any key was in hand.
    assert data["key_source"] in {"flag", None}
    if data["status"] in {"verified", "signature-invalid", "tampered"}:
        assert data["key_source"] == "flag"


@pytest.mark.parametrize("name", ["valid-minimal", "tampered-diff", "unknown-version"])
def test_require_false_reports_the_same_status_but_never_gates(name, tmp_path):
    """require=false is informational, not silent: the real §8 status is still emitted
    (the old code reported "n/a" and threw the information away), only `gate_pass` stops
    depending on it."""
    vector = VECTORS / name
    env = envelope_from_dir(vector, tmp_path / "envelope.zip")
    keys = vector / "keys"
    expected = json.loads((vector / "expected.json").read_text(encoding="utf-8"))

    data, rc = seal_json("--envelope", str(env), "--keys", str(keys),
                         "--require", "false", "--level", "2", cwd=tmp_path)
    assert rc == 0
    assert data["status"] == expected["status"]
    assert data["require"] is False
    assert data["gate_pass"] is True
    # A message is still computed for anything that would not clear a gate — it previews
    # what `require: "true"` would say. Only `gate_pass` decides whether anyone acts on it.
    if data["status"] != "verified":
        assert data["fail_message"]


def test_enclosed_diff_is_used_without_a_repo(tmp_path):
    """A standalone envelope carries its own diff.patch, so the sealer needs no checkout
    and no git — `diff_source` says which anchor the integrity check actually used, so a
    reader never has to guess whether the diff came from the submitter or from the PR."""
    vector = VECTORS / "valid-minimal"
    env = envelope_from_dir(vector, tmp_path / "envelope.zip")
    data, _ = seal_json("--envelope", str(env), "--keys", str(vector / "keys"),
                        "--require", "true", "--level", "2", cwd=tmp_path)
    assert data["status"] == "verified"
    assert data["diff_source"] == "enclosed"
    assert data["added"] >= 1
    assert data["files"], "an enclosed code-change diff must yield a file list"


def test_signed_stats_are_reported_beside_the_counted_ones_never_instead(tmp_path):
    """The manifest's `stats` are the CLAIM (git numstat at pack time); added/removed are
    what this diff actually contains. They can legitimately differ (renames, binaries), so
    both are reported and neither is quietly dropped in favour of the other."""
    vector = VECTORS / "valid-minimal"
    env = envelope_from_dir(vector, tmp_path / "envelope.zip")
    data, _ = seal_json("--envelope", str(env), "--keys", str(vector / "keys"),
                        "--require", "true", "--level", "2", cwd=tmp_path)
    signed = data["signed_stats"]
    assert signed is not None
    assert "insertions" in signed and "deletions" in signed
    assert isinstance(data["added"], int) and isinstance(data["removed"], int)
