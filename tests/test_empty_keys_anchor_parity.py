"""An empty keys file must yield `key_source: null` in every implementation.

SPEC §8 step 4: `key_source` is set whenever a NON-EMPTY key set was obtained, and `null`
when none was. A keys file that exists but holds only whitespace WAS read, yet no key came
out of it — the anchor was never established, so naming one would claim the verdict rests on
a tier it never used.

Regression guard for a real divergence. Until it was fixed the Python reference assigned the
anchor AFTER the empty check while the Go and Rust ports assigned it BEFORE, so the same
empty `--keys` file produced `null` from one implementation and `"flag"` from the other two.
Nothing was red: no vector ships an empty keys file, and the differential harness feeds every
implementation the vector's own (non-empty) keys. "Three implementations, one result" is the
whole claim of this project, and on this input it was false.

Lives beside test_differential_verifiers.py and reuses its runners on purpose — this is a
cross-implementation question, and re-deriving how to invoke three binaries would be a second
place to keep in sync.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest

from tests.test_differential_verifiers import (
    VECTORS, VERIFIER_PY, go_verify_bin, rust_verify_bin,  # noqa: F401 (pytest fixtures)
)

_VECTOR = "valid-minimal"


@pytest.fixture
def vector_with_empty_keys(tmp_path):
    """A copy of a good vector whose `keys` file is present but yields nothing.

    Whitespace rather than zero bytes on purpose: it survives an `exists()` check and only a
    strip-then-test catches it — exactly the shape that slipped past three ports.
    """
    src = VECTORS / _VECTOR
    if not src.is_dir():                                   # pragma: no cover - corpus guard
        pytest.skip(f"{_VECTOR} vector not present")
    dst = tmp_path / _VECTOR
    shutil.copytree(src, dst)
    (dst / "keys").write_text("   \n\t\n", encoding="utf-8")
    return dst


def _verdict(argv, impl):
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if not proc.stdout.strip():
        pytest.fail(f"{impl} produced no stdout; stderr: {proc.stderr[-500:]}")
    data = json.loads(proc.stdout)
    return data["status"], data["key_source"]


def test_python_reports_a_null_anchor_for_an_empty_key_set(vector_with_empty_keys):
    status, anchor = _verdict(
        [sys.executable, str(VERIFIER_PY), str(vector_with_empty_keys),
         "--keys", str(vector_with_empty_keys / "keys"), "--json"], "python")
    assert status == "identity-unverifiable"
    assert anchor is None


def test_go_agrees_with_python_on_an_empty_key_set(vector_with_empty_keys, go_verify_bin):
    if go_verify_bin is None:
        pytest.skip("Go verifier not built — not exercised")
    status, anchor = _verdict(
        [str(go_verify_bin), str(vector_with_empty_keys),
         "--keys", str(vector_with_empty_keys / "keys"), "--json"], "go")
    assert status == "identity-unverifiable"
    assert anchor is None, (
        f"go reported key_source={anchor!r} for an EMPTY keys file; SPEC §8 step 4 "
        "requires null — the file was read, but no key was obtained from it.")


def test_rust_agrees_with_python_on_an_empty_key_set(vector_with_empty_keys, rust_verify_bin):
    if rust_verify_bin is None:
        pytest.skip("Rust verifier not built — not exercised")
    status, anchor = _verdict(
        [str(rust_verify_bin), str(vector_with_empty_keys),
         "--keys", str(vector_with_empty_keys / "keys"), "--json"], "rust")
    assert status == "identity-unverifiable"
    assert anchor is None, (
        f"rust reported key_source={anchor!r} for an EMPTY keys file; SPEC §8 step 4 "
        "requires null — the file was read, but no key was obtained from it.")
