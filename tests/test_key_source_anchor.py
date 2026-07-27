"""`key_source` — the §8 step 4 anchor — asserted on every normative vector.

SPEC §8 step 4 resolves keys in a fixed order (`flag` > `bundled` > `forge`) and requires
the result to REPORT which tier won. The three are not the same claim: a `bundled` key set
rode inside the submission and was therefore chosen by whoever submitted it, so `verified`
there means "these bytes match a key that travelled with them", not "the named forge
account signed this". The word in `status` cannot tell them apart, which is the whole
reason the field exists — and why the merge gate refuses a `bundled` anchor
(tests/test_gate_requires_forge_anchor.py).

Until this file, that MUST was checked by inspection only. The two existing assertions on
the field are narrow by design: tests/test_e2e_local.py pins it on envelopes the producer
just made, and tests/test_gate_requires_forge_anchor.py pins the GATE's reaction to values
it constructs itself rather than to anything a verifier returned. Nothing exercised the
anchor across the conformance corpus, so an implementation could invert the precedence —
prefer a submitter-supplied `keys` member over the operator's `--keys` — and the whole
suite would stay green, because the status of all eighteen vectors is unchanged by which
tier supplied the (identical) key bytes.


WHY THIS LIVES IN PYTEST AND NOT IN THE VECTORS' expected.json
--------------------------------------------------------------
Two reasons, and the first is not a matter of convenience.

1. The anchor is not a property of the vector's bytes. It is a property of HOW the verifier
   was invoked. Run `valid-minimal` with `--keys` and the honest answer is `flag`; run the
   same directory without it and the honest answer is `bundled`, because the vector carries
   its own `keys` member. A single expected value in expected.json would necessarily be
   wrong for one of the two invocations — the file has one slot and the correct answer has
   two. Both invocations are asserted below, from the same table, which is the only way to
   state the precedence at all.

2. expected.json is the frozen cross-language conformance contract. The Go harness
   (impl/go/internal/scpe/vectors_test.go) and the Rust one (impl/rust/tests/vectors.rs)
   read these same files and hard-assert the count; both record in their own comments that
   no vector carries an expected `key_source`. Adding the key would either be silently
   ignored there — false comfort, the worst outcome — or force an edit to verifier-side
   test code in three languages to land one Python assertion. Neither is worth it for a
   field that changes no status.

Go and Rust are covered instead by AGREEMENT rather than by an expected value:
tests/test_differential_verifiers.py now compares `key_source` alongside `status` across all
three implementations on every mutated case. That is the right shape for the same reason —
all three are handed the same `--keys` and the same bytes, so the anchor they claim must
match, and it can diverge while the status does not. What no test in either file claims is
an absolute expected anchor for Go or Rust: this file supplies the oracle, that one supplies
the cross-language equality, and neither edits the frozen contract.

`forge` is unreachable offline by construction — it is the live fetch from the provider's
fixed host — so it never appears as an expected value below. It is still covered, by the
assertions being exact equalities rather than membership tests: a precedence bug that
skipped both local tiers would go to the network and answer `forge`, and every case here
would go red instead of quietly turning an offline conformance suite into an online one.
"""
from __future__ import annotations

import json

import pytest

from tests.conftest import VECTORS, run_verifier

VECTOR_DIRS = sorted(
    d for d in VECTORS.iterdir()
    if d.is_dir() and not d.name.startswith("_") and (d / "expected.json").is_file()
)

# The anchor each normative vector reports when the operator names the key set with
# `--keys` — the invocation spec/test-vectors/README.md prescribes and the one every
# conformance harness uses.
#
# `None` is not "unknown": it is the verifier's answer for a verdict reached AT OR BEFORE
# step 4, where no key set was ever in hand. Three vectors return early, each from a
# different step, and each is a real regression target — a verifier that stamped an anchor
# on them would be claiming a key source it never consulted.
EXPECTED_FLAG_ANCHOR = {
    # returns at step 2 — spec_version scpe/9.9, before keys are considered
    "unknown-version": None,
    # returns at step 3 — provider `oidc` is not in the fixed registry
    "unsupported-provider": None,
    # returns at step 3 — subject `evil..traversal` fails the safe-subject rule
    "identity-unverifiable-subject": None,

    # everything else reaches step 4, so the operator's --keys is the anchor. Note that a
    # failing status does NOT mean a missing anchor: a signature checked against real keys
    # and rejected still rests on those keys, and must say so.
    "invalid-signature": "flag",
    "wrong-identity": "flag",
    "tampered-diff": "flag",
    "tampered-artifact": "flag",
    "unsupported-subject": "flag",
    "unknown-trace-format": "flag",
    "multi-attestation": "flag",
    "valid-minimal": "flag",
    "valid-artifact": "flag",
    "valid-local": "flag",
    "valid-gitlab": "flag",
    "valid-codeberg": "flag",
    "valid-agent-trace-real": "flag",
    "valid-agent-trace-gitai": "flag",
    "valid-agent-trace-generic": "flag",
}


def _result(vector, *, keys) -> tuple[dict, int]:
    proc = run_verifier(vector, keys=keys)
    assert proc.stdout.strip(), f"no output; stderr: {proc.stderr[-500:]}"
    return json.loads(proc.stdout), proc.returncode


def _expected_status(vector) -> str:
    return json.loads((vector / "expected.json").read_text(encoding="utf-8"))["status"]


def test_the_anchor_table_covers_every_normative_vector():
    """Same count lock the conformance harness carries. A nineteenth vector must arrive
    with a decision about its anchor, not inherit one by omission."""
    assert len(VECTOR_DIRS) == 18, [d.name for d in VECTOR_DIRS]
    assert set(EXPECTED_FLAG_ANCHOR) == {d.name for d in VECTOR_DIRS}


@pytest.mark.parametrize("vector", VECTOR_DIRS, ids=lambda d: d.name)
def test_an_operator_supplied_key_file_is_reported_as_flag(vector):
    data, rc = _result(vector, keys=vector / "keys")
    # Reporting the anchor is a MUST, so the KEY is checked before its value: an
    # implementation that dropped the field rather than emitting null would break every
    # consumer that reads it — results.json, the seal's identity row, the merge gate —
    # and a bare equality assertion would report that as an unexplained KeyError.
    assert "key_source" in data, data
    assert data["key_source"] == EXPECTED_FLAG_ANCHOR[vector.name], data
    # …and the anchor did not disturb the verdict it is reported alongside.
    assert data["status"] == _expected_status(vector), data
    assert (rc == 0) == (data["status"] == "verified")


@pytest.mark.parametrize("vector", VECTOR_DIRS, ids=lambda d: d.name)
def test_a_keys_file_riding_inside_the_input_is_reported_as_bundled(vector):
    """The same directory, verified WITHOUT `--keys`. Every vector ships a `keys` member,
    so the second tier takes over and the honest answer changes from `flag` to `bundled` —
    while the status stays exactly what it was, because the key bytes are identical.

    That pair is the assertion. It pins the precedence (drop the flag tier and the first
    test goes red; drop the bundled tier and this one does), and it pins the property the
    field was added for: the anchor is DISCLOSURE, never DISPATCH. Two runs, two different
    trust stories, one unchanged verdict — which is precisely why the verdict alone is not
    enough to publish.
    """
    expected_anchor = EXPECTED_FLAG_ANCHOR[vector.name]
    # A verdict reached before step 4 has no anchor under either invocation.
    expected_anchor = "bundled" if expected_anchor is not None else None

    data, rc = _result(vector, keys=None)
    assert data["key_source"] == expected_anchor, data
    assert data["status"] == _expected_status(vector), data
    assert (rc == 0) == (data["status"] == "verified")


def test_a_vector_with_no_anchor_at_all_reports_no_key_source(tmp_path):
    """The third case, and the one that proves `None` is meaningful rather than a default:
    strip the `keys` member and pass no `--keys`, and there is no anchor to report.

    `valid-local` is the only vector that can be asked this offline — the `local` provider
    performs no fetch by definition (SPEC §8 step 4), so the verifier answers from the
    registry instead of reaching for a host. Doing this to a `github` vector would make the
    test suite depend on the network, which is the property the vectors exist to avoid.
    """
    vector = VECTORS / "valid-local"
    work = tmp_path / "no-keys"
    work.mkdir()
    for member in ("manifest.json", "manifest.sig", "diff.patch"):
        (work / member).write_bytes((vector / member).read_bytes())
    assert not (work / "keys").exists()

    data, rc = _result(work, keys=None)
    assert data["status"] == "identity-unverifiable", data
    assert data["key_source"] is None, data
    assert rc == 1
    assert "keys" in data["detail"], data
