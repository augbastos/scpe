"""Conformance: the standalone reference verifier vs the 18 normative test vectors.

This is the contract of SPEC.md §8 — an implementation conforms iff it produces
every vector's expected status. The standalone verifier is run as a subprocess
(exactly how an auditor would), with --keys substituting the network fetch per
spec/test-vectors/README.md.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "reference" / "standalone" / "verify_envelope.py"
VECTORS = ROOT / "spec" / "test-vectors"

VECTOR_DIRS = sorted(
    d for d in VECTORS.iterdir()
    if d.is_dir() and not d.name.startswith("_") and (d / "expected.json").is_file()
)


def _run(vector: Path) -> tuple[dict, int]:
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(vector),
         "--keys", str(vector / "keys"), "--json"],
        capture_output=True, text=True, timeout=60)
    assert proc.stdout.strip(), f"no output; stderr: {proc.stderr[-500:]}"
    return json.loads(proc.stdout), proc.returncode


def test_all_vectors_present():
    assert len(VECTOR_DIRS) == 18, [d.name for d in VECTOR_DIRS]


@pytest.mark.parametrize("vector", VECTOR_DIRS, ids=lambda d: d.name)
def test_vector_status(vector: Path):
    expected = json.loads((vector / "expected.json").read_text(encoding="utf-8"))
    got, rc = _run(vector)
    assert got["status"] == expected["status"], got
    if "attestations" in expected:
        assert got["attestations"] == expected["attestations"], got
    # exit code contract: 0 iff verified
    assert (rc == 0) == (expected["status"] == "verified")


def test_verifier_is_stdlib_single_file():
    """The auditability promise: one file, no third-party imports."""
    src = VERIFIER.read_text(encoding="utf-8")
    for banned in ("import requests", "import cryptography", "from scpe",
                   "import scpe"):
        assert banned not in src
