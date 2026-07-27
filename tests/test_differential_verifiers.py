"""Differential test: do the Python, Go, and Rust SCPE verifiers agree?

test_spec_vectors.py is a *conformance* test: it checks the Python reference
verifier against the 18 normative vectors' `expected.json`. It says nothing
about the Go and Rust ports, and even if all three parametrized on the same
18 vectors, a bug shared by all three re-implementations (e.g. all three port
the same off-by-one from the reference, or all three happen to check a step
of SPEC.md §8 in the wrong order) would pass unanimously "wrong" -- three
verifiers agreeing is not evidence they're each individually correct.

This test does not re-derive the "correct" status. Instead it takes each
`valid-*` test vector, applies a small set of structured, deterministic
mutations to it, and asserts Python, Go, and Rust land on the IDENTICAL
verdict for the SAME mutated input. A divergence is a real cross-implementation
bug regardless of which status is "right" -- that is what differential testing
buys you that conformance testing against a shared oracle cannot.

Two mutation families, chosen to stress different parts of SPEC.md §8:

  * manifest.json edits (reorder_keys, flip_byte, truncate, add_unknown_field,
    change_subject_type, tamper_integrity_digest) leave manifest.sig as-is, so
    the byte-exact SSHSIG check (§8 step 6) MUST reject every one of them --
    they exercise whether all three ports (a) parse malformed/edited JSON the
    same way and (b) check the signature *before* anything that reads the
    (now-untrustworthy) parsed content, e.g. subject.type dispatch. A port
    that canonicalizes JSON before hashing, or that dispatches on subject.type
    ahead of the signature check, would diverge here.
  * payload_byte flips one byte inside the enclosed diff.patch / artifact.bin
    and leaves manifest.json/.sig untouched, so the signature still verifies
    and every port must reach the integrity-hash comparison (§8 step 7) --
    this exercises the diff-normalization and SHA-256 comparison logic itself,
    independently re-implemented in three languages.

Two fields are compared, not one. `status` is the verdict; `key_source` is the
SPEC.md §8 step 4 anchor the verdict rests on, and it is the only normative MUST
that no vector's expected.json can express -- the anchor depends on how the
verifier was INVOKED, not on the vector's bytes, so the frozen conformance files
have no slot for it and the Go and Rust ports were emitting it with nothing
checking the value. Every implementation here is handed the same `--keys` and the
same bytes, so a difference in the anchor they claim is a real divergence in step
4 even when all three agree on the status. See tests/test_key_source_anchor.py for
the Python-side value assertions this pairs with.

Go and Rust are each optional: if the toolchain / a prebuilt binary isn't
available, that case is reported as an explicit pytest SKIP -- never silently
dropped from the assertion and never counted as a pass.
"""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
VERIFIER_PY = ROOT / "reference" / "standalone" / "verify_envelope.py"
VECTORS = ROOT / "spec" / "test-vectors"
GO_DIR = ROOT / "impl" / "go"
RUST_DIR = ROOT / "impl" / "rust"
# cargo appends .exe only on Windows. Hardcoding it meant that on any other platform the
# fixture below built the Rust verifier successfully, looked for a name cargo never emits,
# and hit its "built fine but no binary" branch -- which is a pytest.fail, not a skip, by
# design. So every Rust case failed on Linux/macOS for a reason that had nothing to do with
# the Rust port. Mirrors how `go_verify_bin` already picks its output name.
_RUST_EXE = "scpe-verify.exe" if sys.platform == "win32" else "scpe-verify"
RUST_BIN_RELEASE = ROOT / "impl" / "rust" / "target" / "release" / _RUST_EXE
RUST_BIN_DEBUG = ROOT / "impl" / "rust" / "target" / "debug" / _RUST_EXE

VALID_VECTORS = sorted(
    d for d in VECTORS.iterdir() if d.is_dir() and d.name.startswith("valid-")
)


# --------------------------------------------------------------------- mutations
# Each manifest mutation takes the ORIGINAL parsed manifest dict + its raw bytes
# and returns mutated manifest.json bytes, or None if the mutation doesn't apply
# to this particular vector (e.g. tampering diff_sha256 on a vector that has no
# such field) -- such a case is dropped at collection time, never silently
# treated as a no-op pass.

def _dump(data: dict) -> bytes:
    return (json.dumps(data, indent=2) + "\n").encode("utf-8")


def mut_reorder_keys(data: dict, raw: bytes) -> Optional[bytes]:
    """Reverse key order at every dict level. Same content, different bytes --
    a byte-exact SSHSIG MUST reject it even though a JSON-semantic reader sees
    no change; catches an implementation that canonicalizes before verifying."""
    def reorder(obj):
        if isinstance(obj, dict):
            return {k: reorder(obj[k]) for k in reversed(list(obj.keys()))}
        if isinstance(obj, list):
            return [reorder(v) for v in obj]
        return obj

    out = _dump(reorder(data))
    return out if out != raw else None


def mut_flip_byte(data: dict, raw: bytes) -> Optional[bytes]:
    """Bit-complement one byte in the middle of manifest.json."""
    i = len(raw) // 2
    return raw[:i] + bytes([raw[i] ^ 0xFF]) + raw[i + 1:]


def mut_truncate(data: dict, raw: bytes) -> Optional[bytes]:
    """Cut the last fifth of manifest.json -- almost always invalid JSON."""
    cut = max(1, len(raw) * 4 // 5)
    return raw[:cut]


def mut_add_unknown_field(data: dict, raw: bytes) -> Optional[bytes]:
    mutated = copy.deepcopy(data)
    mutated["x_scpe_test_unknown_field"] = "mutation-marker"
    return _dump(mutated)


def mut_change_subject_type(data: dict, raw: bytes) -> Optional[bytes]:
    subj = data.get("subject")
    if not isinstance(subj, dict) or "type" not in subj:
        return None
    mutated = copy.deepcopy(data)
    # An unknown-to-scpe/0.1 type (SPEC §6.3 fail-closed example), same value
    # the `unsupported-subject` normative vector uses.
    mutated["subject"]["type"] = "container-image"
    return _dump(mutated)


def _flip_hex(h: str) -> str:
    last = h[-1]
    return h[:-1] + ("0" if last != "0" else "1")


def mut_tamper_integrity_digest(data: dict, raw: bytes) -> Optional[bytes]:
    """Flip the last hex character of whichever field SPEC §8 step 7 reads:
    subject.change.diff_sha256 for code-change, subject.digest.sha256 for
    artifact."""
    subj = data.get("subject")
    if not isinstance(subj, dict):
        return None
    stype = subj.get("type")
    mutated = copy.deepcopy(data)
    if stype == "code-change":
        change = mutated["subject"].get("change")
        if not isinstance(change, dict) or not change.get("diff_sha256"):
            return None
        change["diff_sha256"] = _flip_hex(change["diff_sha256"])
    elif stype == "artifact":
        digest = mutated["subject"].get("digest")
        if not isinstance(digest, dict) or not digest.get("sha256"):
            return None
        digest["sha256"] = _flip_hex(digest["sha256"])
    else:
        return None
    return _dump(mutated)


MANIFEST_MUTATIONS: dict[str, Callable[[dict, bytes], Optional[bytes]]] = {
    "reorder_keys": mut_reorder_keys,
    "flip_byte": mut_flip_byte,
    "truncate": mut_truncate,
    "add_unknown_field": mut_add_unknown_field,
    "change_subject_type": mut_change_subject_type,
    "tamper_integrity_digest": mut_tamper_integrity_digest,
}

PAYLOAD_FILES = ("diff.patch", "artifact.bin")


def mut_payload_byte(payload: bytes) -> bytes:
    """Flip one byte inside the enclosed diff.patch / artifact.bin, leaving
    manifest.json / manifest.sig untouched -- the signature still verifies, so
    this exercises the integrity-hash comparison (SPEC §8 step 7) itself
    rather than short-circuiting at the signature check."""
    i = len(payload) // 2
    return payload[:i] + bytes([payload[i] ^ 0xFF]) + payload[i + 1:]


# ------------------------------------------------------------------- collection

def _collect_cases() -> list[tuple[str, str]]:
    cases: list[tuple[str, str]] = []
    for vector in VALID_VECTORS:
        raw = (vector / "manifest.json").read_bytes()
        data = json.loads(raw.decode("utf-8"))
        for name, fn in MANIFEST_MUTATIONS.items():
            if fn(data, raw) is not None:
                cases.append((vector.name, name))
        if any((vector / f).is_file() for f in PAYLOAD_FILES):
            cases.append((vector.name, "payload_byte"))
    return cases


CASES = _collect_cases()


def _materialize(vector: Path, mutation: str, tmp_path: Path) -> Path:
    dest = tmp_path / "vector"
    shutil.copytree(vector, dest)
    if mutation == "payload_byte":
        for name in PAYLOAD_FILES:
            p = dest / name
            if p.is_file():
                p.write_bytes(mut_payload_byte(p.read_bytes()))
                break
        else:
            raise AssertionError(f"{vector.name} has no payload file to tamper")
    else:
        raw = (vector / "manifest.json").read_bytes()
        data = json.loads(raw.decode("utf-8"))
        mutated = MANIFEST_MUTATIONS[mutation](data, raw)
        assert mutated is not None, (
            f"{mutation} inapplicable to {vector.name} at materialize time "
            "(collection said it was)")
        (dest / "manifest.json").write_bytes(mutated)
    return dest


# ------------------------------------------------------------------- verifiers

def _verdict_from_json_stdout(proc: subprocess.CompletedProcess,
                              impl: str) -> tuple[str, object]:
    """(status, key_source) -- the two fields SPEC.md §8 requires a result to report.

    `key_source` is read here rather than in a separate pass because it is the one
    normative MUST no vector's expected.json can express (the anchor depends on HOW the
    verifier was invoked, not on the vector's bytes -- see tests/test_key_source_anchor.py),
    which left the Go and Rust ports emitting the field with nothing asserting it. A
    missing key is a failure, not a None: §8 step 4 says report it.
    """
    if not proc.stdout.strip():
        pytest.fail(f"{impl} verifier produced no stdout; stderr: {proc.stderr[-500:]}")
    try:
        data = json.loads(proc.stdout)
        return data["status"], data["key_source"]
    except (json.JSONDecodeError, KeyError) as exc:
        pytest.fail(f"{impl} verifier gave unparsable --json output {proc.stdout!r} "
                    f"(both `status` and `key_source` are required by SPEC §8): {exc}")


def _run_python(vector_dir: Path) -> tuple[str, object]:
    proc = subprocess.run(
        [sys.executable, str(VERIFIER_PY), str(vector_dir),
         "--keys", str(vector_dir / "keys"), "--json"],
        capture_output=True, text=True, timeout=30)
    return _verdict_from_json_stdout(proc, "python")


def _run_go(vector_dir: Path, go_bin: Optional[Path]) -> tuple[str, object]:
    if go_bin is None:
        pytest.skip("go toolchain / `go build ./cmd/scpe-verify` unavailable "
                    "-- Go verifier not exercised")
    proc = subprocess.run(
        [str(go_bin), str(vector_dir), "--keys", str(vector_dir / "keys"), "--json"],
        capture_output=True, text=True, timeout=30)
    return _verdict_from_json_stdout(proc, "go")


def _run_rust(vector_dir: Path, rust_bin: Optional[Path]) -> tuple[str, object]:
    if rust_bin is None:
        pytest.skip("no built impl/rust/target/{release,debug}/scpe-verify "
                    "-- Rust verifier not exercised")
    proc = subprocess.run(
        [str(rust_bin), str(vector_dir), "--keys", str(vector_dir / "keys"), "--json"],
        capture_output=True, text=True, timeout=30)
    return _verdict_from_json_stdout(proc, "rust")


# --------------------------------------------------------------------- fixtures

@pytest.fixture(scope="session")
def go_verify_bin(tmp_path_factory) -> Optional[Path]:
    exe_name = "scpe-verify-go.exe" if sys.platform == "win32" else "scpe-verify-go"
    out = tmp_path_factory.mktemp("go-bin") / exe_name
    try:
        proc = subprocess.run(
            ["go", "build", "-o", str(out), "./cmd/scpe-verify"],
            cwd=str(GO_DIR), capture_output=True, text=True, timeout=180)
    except FileNotFoundError:
        return None
    if proc.returncode != 0 or not out.is_file():
        return None
    return out


@pytest.fixture(scope="session")
def rust_verify_bin() -> Optional[Path]:
    """Auto-build the Rust verifier once per session, mirroring `go_verify_bin` above --
    previously this fixture only PROBED for a pre-built binary and silently skipped every
    Rust case if nobody had run `cargo build` by hand, which meant a fresh clone reported
    green without ever exercising the Rust port.

    A clean pytest SKIP is reserved for the cargo toolchain itself being unavailable
    (mirrors `go_verify_bin`'s `FileNotFoundError` -> unavailable case). If cargo IS
    installed but the build fails, that is a real Rust-port breakage and must show up as a
    failure, not vanish into a skip the way a merely-missing-binary used to.
    """
    try:
        proc = subprocess.run(
            ["cargo", "build", "--release", "--bin", "scpe-verify"],
            cwd=str(RUST_DIR), capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        pytest.skip("cargo toolchain unavailable -- Rust verifier not exercised")
    if proc.returncode != 0:
        pytest.fail(
            "cargo build --release failed in impl/rust (cargo IS installed -- this is a "
            f"real Rust build breakage, not a missing-toolchain skip):\n{proc.stderr[-2000:]}")
    if RUST_BIN_RELEASE.is_file():
        return RUST_BIN_RELEASE
    if RUST_BIN_DEBUG.is_file():
        return RUST_BIN_DEBUG
    pytest.fail(
        "cargo build --release exited 0 but no binary was found at "
        f"{RUST_BIN_RELEASE} or {RUST_BIN_DEBUG}")


# ------------------------------------------------------------------------ tests

def test_all_valid_vectors_found():
    assert len(VALID_VECTORS) == 8, [d.name for d in VALID_VECTORS]


def test_case_count_bounded():
    """Keep the run under a minute: cap the mutation grid."""
    assert 0 < len(CASES) <= 150, len(CASES)


@pytest.mark.parametrize("vector_name,mutation", CASES,
                         ids=[f"{v}__{m}" for v, m in CASES])
def test_mutation_agrees_across_verifiers(vector_name, mutation, tmp_path,
                                          go_verify_bin, rust_verify_bin):
    vector = VECTORS / vector_name
    vector_dir = _materialize(vector, mutation, tmp_path)

    py_status, py_keys = _run_python(vector_dir)
    go_status, go_keys = _run_go(vector_dir, go_verify_bin)
    rust_status, rust_keys = _run_rust(vector_dir, rust_verify_bin)

    assert py_status == go_status == rust_status, (
        f"verifiers diverged on {vector_name}/{mutation}: "
        f"python={py_status!r} go={go_status!r} rust={rust_status!r}")

    # Same differential logic applied to the §8 step 4 anchor. No expected value is
    # asserted -- it varies by mutation (a truncated manifest never reaches step 4 and has
    # no anchor; an edited-but-parseable one does) and deriving it here would just
    # re-implement the verifier. What must hold is AGREEMENT: every implementation was
    # handed the same `--keys` and the same bytes, so any difference in which anchor they
    # claim is a cross-implementation bug in step 4's precedence or in when the field is
    # stamped. That can diverge while `status` matches perfectly, which is why it needs
    # saying separately -- and it is the half of the field no expected.json can cover.
    assert py_keys == go_keys == rust_keys, (
        f"verifiers agree on status ({py_status!r}) but diverge on key_source for "
        f"{vector_name}/{mutation}: python={py_keys!r} go={go_keys!r} rust={rust_keys!r}")
