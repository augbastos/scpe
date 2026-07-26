"""`scpe verify` is a passthrough, and this is the test that keeps it one.

The package exists so someone can verify without cloning the repo
(`pipx run --spec scpe-protocol scpe verify ...`). The moment its output drifts from
reference/standalone/verify_envelope.py's, there are two verifiers with one name — the
exact failure the whole design is arranged to avoid (three implementations, one result:
Python, Go, Rust, and now a package that must not become a fourth).

So: same flags, same JSON, same exit rule (0 iff `verified`), asserted on all eighteen
normative vectors by running BOTH and comparing bytes.
"""
from __future__ import annotations

import zipfile

import pytest

from tests.conftest import VECTORS, load_producer, run_cli, run_verifier

producer = load_producer()

VECTOR_DIRS = sorted(
    d for d in VECTORS.iterdir()
    if d.is_dir() and not d.name.startswith("_") and (d / "expected.json").is_file()
)


@pytest.mark.parametrize("vector", VECTOR_DIRS, ids=lambda d: d.name)
def test_json_output_is_byte_identical_to_the_reference_verifier(vector, tmp_path):
    keys = vector / "keys"
    direct = run_verifier(vector, keys=keys)
    through = run_cli("verify", str(vector), "--keys", str(keys), "--json", cwd=tmp_path)

    assert through.stdout.strip() == direct.stdout.strip(), (
        f"package output diverged from the reference verifier for {vector.name}:\n"
        f"  reference: {direct.stdout.strip()}\n"
        f"  package:   {through.stdout.strip()}")
    assert through.returncode == direct.returncode


@pytest.mark.parametrize("vector", ["valid-minimal", "tampered-diff"])
def test_exit_code_is_zero_only_for_verified(vector, tmp_path):
    """The exit-code contract is part of the spec, not a convenience: a script that only
    checks `$?` must not be able to read a tampered diff as a pass."""
    path = VECTORS / vector
    proc = run_cli("verify", str(path), "--keys", str(path / "keys"), cwd=tmp_path)
    assert (proc.returncode == 0) == (vector == "valid-minimal")


def test_the_diff_flag_behaves_the_same_through_both_paths(repo_with_fix, signing_key,
                                                           keys_file, tmp_path):
    """The attestation form: the manifest travels in a PR body and the diff comes from
    `--diff`. Both entry points must agree here too, since this is the shape a maintainer
    verifies by hand when they distrust the CI seal."""
    repo, base, head = repo_with_fix
    env = tmp_path / "e.zip"
    producer.pack(repo=repo, base=base, head=head, out=env, login="octocat-test",
                  key=str(signing_key), created_at="2026-07-21T18:00:00Z",
                  repo_name="octocat-test/calc")
    body = tmp_path / "pr_body.md"
    producer.attest(envelope=env, out=body)
    diff = tmp_path / "diff.patch"
    with zipfile.ZipFile(env) as zf:
        diff.write_bytes(zf.read("diff.patch"))

    direct = run_verifier(body, keys=keys_file, diff=diff)
    through = run_cli("verify", str(body), "--keys", str(keys_file), "--diff", str(diff),
                      "--json", cwd=tmp_path)
    assert through.stdout.strip() == direct.stdout.strip()
    assert through.returncode == direct.returncode == 0
