#!/usr/bin/env python3
"""Generate the SCPE scpe/0.1 ADVERSARIAL test vectors (non-normative probes).

Sibling to spec/test-vectors/, NOT a subdirectory of it. Both impl/go/internal/scpe/
vectors_test.go and impl/rust/tests/vectors.rs hard-assert `len(vectors) == 18` by
scanning every top-level directory of spec/test-vectors/ and skipping only the literal
name "_key". Verified empirically (2026-07-23): dropping so much as one extra, empty
directory under spec/test-vectors/ makes both conformance tests fail on the count,
before a single vector runs — `go test ./...` -> "expected 18 test vectors, found 19",
`cargo test --test vectors` -> the matching panic. Since those two files are frozen
verifier code (impl/), this pack lives at spec/test-vectors-adversarial/ instead: a
sibling, never enumerated by either harness's directory scan of spec/test-vectors/, so
the 18-vector conformance contract needs no edit and neither frozen test is touched.

These seven vectors are NOT additions to the eighteen normative vectors and introduce no
new protocol capability. Each one exercises a check the reference verifier already
implements (reference/standalone/verify_envelope.py); `expected.json` records the
status that verifier ACTUALLY returns for the exact bytes in that directory (confirmed
by running it — see verify_all.py), not an assumed one. Two of the seven surfaced
genuinely surprising behavior; see README.md.

Reuses ../test-vectors/make_vectors.py's manifest builder, `sign()` helper, and the
same throwaway key at ../test-vectors/_key/ — not a second key, not a copy of that
logic. That key is gitignored, never committed: private keys stay out of the repo even
when they are throwaway, so a fresh clone must run make_vectors.py before regenerating
here. Stdlib only. External binary: ssh-keygen (OpenSSH >= 8.2).
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NORMATIVE_DIR = ROOT.parent / "test-vectors"

# Importing make_vectors.py would otherwise write __pycache__/*.pyc INSIDE
# spec/test-vectors/ -- a new top-level directory there, which is exactly what breaks
# the Go/Rust hard-coded 18-vector count this whole layout exists to avoid disturbing
# (see README.md). __pycache__/ is gitignored so it would never reach a commit, but a
# stray local run before `go test`/`cargo test` would still trip the count. Refuse to
# write it at all.
sys.dont_write_bytecode = True

# Import ../test-vectors/make_vectors.py by file path (it is a script, not an
# installed package) to reuse its manifest builder and signer rather than fork them.
_spec = importlib.util.spec_from_file_location(
    "make_vectors", NORMATIVE_DIR / "make_vectors.py")
mv = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(mv)


def write_vector(name: str, manifest_bytes: bytes, key: Path, keys_pub: list[Path],
                 expected: dict, diff: str | None = mv.DIFF,
                 namespace: str | None = None,
                 sig_bytes_override: bytes | None = None) -> Path:
    """Like make_vectors.write_vector, but takes already-serialized manifest bytes
    (so a caller can inject a BOM, a duplicate key, or padding before signing) and can
    sign under a non-standard SSHSIG namespace or substitute the signature outright."""
    d = ROOT / name
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    mp = d / "manifest.json"
    mp.write_bytes(manifest_bytes)
    if sig_bytes_override is not None:
        (d / "manifest.sig").write_bytes(sig_bytes_override)
    else:
        ns = namespace or mv.NAMESPACE
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", ns, str(mp)],
            check=True, capture_output=True, text=True,
        )
        sig = mp.with_suffix(mp.suffix + ".sig")
        sig.replace(d / "manifest.sig")
    if diff is not None:
        (d / "diff.patch").write_bytes(mv.normalize(diff))
    (d / "keys").write_text(
        "".join(p.read_text(encoding="utf-8") for p in keys_pub), encoding="utf-8")
    (d / "expected.json").write_bytes(json.dumps(expected, indent=2).encode("utf-8"))
    print(f"  {name}: {expected['status']}")
    return d


def sign_raw(manifest_bytes: bytes, key: Path, namespace: str) -> bytes:
    """Sign `manifest_bytes` under `namespace` and return the raw .sig bytes, without
    writing a vector. Used by the truncated-signature vector to obtain a genuine
    signature to corrupt."""
    tmp = ROOT / "_tmp_sign"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir()
    try:
        mp = tmp / "manifest.json"
        mp.write_bytes(manifest_bytes)
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", namespace, str(mp)],
            check=True, capture_output=True, text=True,
        )
        return (tmp / "manifest.json.sig").read_bytes()
    finally:
        shutil.rmtree(tmp)


def main() -> int:
    if shutil.which("ssh-keygen") is None:
        print("ssh-keygen not found (OpenSSH >= 8.2 required)", file=sys.stderr)
        return 1

    key = NORMATIVE_DIR / "_key" / "scpe_test_ed25519"
    pub = key.with_suffix(".pub")
    if not key.exists():
        print(f"throwaway key missing: {key} (run ../test-vectors/make_vectors.py first)",
              file=sys.stderr)
        return 1
    fp = mv.fingerprint(pub)

    def base_manifest(**kw) -> dict:
        m = mv.manifest(**kw)
        m["contributor"]["key_fingerprint"] = fp
        return m

    print("Generating ADVERSARIAL vectors (non-normative; run verify_all.py next)")

    # -- 1. duplicate-manifest-keys ----------------------------------------------
    # json.loads (stdlib, default object hook) silently keeps the LAST occurrence of a
    # repeated JSON key; RFC 8259 leaves duplicate-key handling implementation-defined,
    # so a different parser (or a human skimming the file top-to-bottom) can legitimately
    # disagree with the reference verifier about what this manifest even says. The FIRST
    # "spec_version" (visually, at the top) is the supported "scpe/0.1"; a duplicate
    # "spec_version": "scpe/9.9" is appended as the manifest's LAST top-level key before
    # signing, so the signed bytes are unambiguous but their *meaning* depends entirely
    # on which duplicate-key rule the reader implements.
    m1 = base_manifest()
    raw1 = json.dumps(m1, indent=2).encode("utf-8")
    assert raw1.rstrip().endswith(b"}")
    raw1 = raw1.rstrip()[:-1].rstrip() + b',\n  "spec_version": "scpe/9.9"\n}'
    write_vector("duplicate-manifest-keys", raw1, key, [pub],
                 {"status": "TBD-run-verify_all.py",
                  "note": "top-level \"spec_version\" repeated: first occurrence "
                          "scpe/0.1, last occurrence scpe/9.9; RFC 8259 leaves "
                          "duplicate-key resolution implementation-defined"})

    # -- 2. manifest-oversize-rejected -------------------------------------------
    # THREAT_MODEL.md SS3 ("Denial of service"): "the reference implementation caps
    # decompressed manifest size". This vector pads an otherwise-valid manifest past
    # 1 MiB to exercise the directory-path size cap. The cap is now enforced on BOTH
    # the zip form (_from_zip -> _read_zip_member) and the directory form (load_input's
    # `path.is_dir()` branch -> _read_file_capped), so an oversized manifest fails to
    # load and returns `unattested` in all three implementations. Regression guard: if
    # the directory-path cap is dropped, the status flips back to `verified`.
    m2 = base_manifest()
    m2["_conformance_probe_padding"] = "A" * (1_200_000)
    raw2 = json.dumps(m2, indent=2).encode("utf-8")
    assert len(raw2) > (1 << 20), f"padding too small: {len(raw2)} bytes"
    write_vector("manifest-oversize-rejected", raw2, key, [pub],
                 {"status": "TBD-run-verify_all.py",
                  "note": f"manifest.json is {len(raw2)} bytes (> the 1 MiB "
                          "MAX_MANIFEST_BYTES cap); otherwise identical to "
                          "valid-minimal. Probes whether the directory-form read "
                          "path enforces the same cap as the zip-form path."})

    # -- 3. subject-with-slash ----------------------------------------------------
    # The existing normative vector identity-unverifiable-subject covers the `..`
    # substring check. SAFE_SUBJECT_RE ([A-Za-z0-9][A-Za-z0-9._-]{0,63}) separately
    # bars `/` by charset alone, with no `..` present -- a distinct branch of the same
    # safe-subject rule (SPEC S8), exercised here on its own.
    m3 = base_manifest(subject="evil/traversal")
    raw3 = json.dumps(m3, indent=2).encode("utf-8")
    write_vector("subject-with-slash", raw3, key, [pub],
                 {"status": "TBD-run-verify_all.py",
                  "note": "identity.subject contains '/' (no '..'); must be rejected "
                          "by the safe-subject charset alone, not the traversal check"})

    # -- 4. wrong-sshsig-namespace -------------------------------------------------
    # verify_signature() hardcodes `-n NAMESPACE` (scpe/0.1) on the ssh-keygen verify
    # call (SPEC S7). Signing the identical, otherwise-valid manifest under a different
    # SSHSIG namespace tests that namespace binding actually rejects a signature that
    # is cryptographically genuine but scoped to a different protocol/purpose.
    m4 = base_manifest()
    raw4 = json.dumps(m4, indent=2).encode("utf-8")
    write_vector("wrong-sshsig-namespace", raw4, key, [pub],
                 {"status": "TBD-run-verify_all.py",
                  "note": "signed with SSHSIG namespace \"not-scpe\" instead of the "
                          "required \"scpe/0.1\"; manifest bytes are otherwise "
                          "identical to valid-minimal"},
                 namespace="not-scpe")

    # -- 5. utf8-bom-manifest ------------------------------------------------------
    # A UTF-8 BOM (EF BB BF) is prepended to the manifest BEFORE signing, so the
    # signature covers the BOM-prefixed bytes exactly (this is not a mutated-after-
    # signing case like invalid-signature). Some editors/exports prepend a BOM; probes
    # whether the reference verifier's parser accepts it.
    m5 = base_manifest()
    raw5 = b"\xef\xbb\xbf" + json.dumps(m5, indent=2).encode("utf-8")
    write_vector("utf8-bom-manifest", raw5, key, [pub],
                 {"status": "TBD-run-verify_all.py",
                  "note": "manifest.json begins with a UTF-8 BOM (EF BB BF), signed "
                          "as part of the manifest bytes"})

    # -- 6. truncated-signature -----------------------------------------------------
    # A genuine SSHSIG blob for an otherwise-valid manifest, truncated to two-thirds of
    # its length before being written as manifest.sig -- distinct from invalid-signature
    # (which mutates the MANIFEST after signing); here the manifest is untouched and the
    # SIGNATURE FILE itself is corrupted/incomplete, as it might be after a truncated
    # transfer or disk fault.
    m6 = base_manifest()
    raw6 = json.dumps(m6, indent=2).encode("utf-8")
    full_sig = sign_raw(raw6, key, mv.NAMESPACE)
    truncated_sig = full_sig[: (len(full_sig) * 2) // 3]
    assert 0 < len(truncated_sig) < len(full_sig)
    write_vector("truncated-signature", raw6, key, [pub],
                 {"status": "TBD-run-verify_all.py",
                  "note": f"manifest.sig truncated to {len(truncated_sig)} of "
                          f"{len(full_sig)} original bytes"},
                 sig_bytes_override=truncated_sig)

    # -- 7. invalid-utf8-diff -------------------------------------------------------
    # A code-change diff carrying an invalid UTF-8 byte (0xFF). Before diff
    # normalization was pinned to the BYTE level (SPEC §6), Python decoded with
    # errors=replace (0xFF -> U+FFFD) while Go/Rust preserved the byte, so the same
    # signed envelope verified on Go/Rust but tampered on Python. With producer and all
    # three verifiers normalizing at the byte level the anchor is well-defined and all
    # three agree: verified. Regression guard for that cross-implementation alignment.
    import hashlib

    def _norm_bytes(raw: bytes) -> bytes:
        t = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        return t.rstrip(b"\n") + b"\n"

    utf8_diff = (b"diff --git a/x b/x\n--- a/x\n+++ b/x\n"
                 b"@@ -0,0 +1 @@\n+hello \xff world\n")
    m7 = base_manifest()
    m7["subject"]["change"]["diff_sha256"] = hashlib.sha256(_norm_bytes(utf8_diff)).hexdigest()
    raw7 = json.dumps(m7, indent=2).encode("utf-8")
    d7 = write_vector("invalid-utf8-diff", raw7, key, [pub],
                      {"status": "TBD-run-verify_all.py",
                       "note": "diff.patch carries an invalid UTF-8 byte (0xFF); anchor "
                               "computed at the byte level (SPEC §6)"},
                      diff=None)
    (d7 / "diff.patch").write_bytes(utf8_diff)

    print("done: 7 adversarial vectors written with placeholder status; "
          "run verify_all.py to record the real verifier output, then hand-review "
          "each expected.json before treating this pack as final")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
