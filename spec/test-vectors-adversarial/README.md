# SCPE adversarial test vectors (non-normative)

Seven vectors, one directory each, each probing a defense the reference verifier
(`reference/standalone/verify_envelope.py`) already implements. **Not** additions to the
eighteen normative vectors in `../test-vectors/` and not a new protocol capability —
`expected.json` in every directory here records the status the verifier ACTUALLY returns
(confirmed by running it), not an assumed one. Every status here is also confirmed to match
across `reference/standalone/verify_envelope.py`, `impl/go/cmd/scpe-verify`, and `impl/rust`'s
`scpe-verify` binary (see each `expected.json`'s note — free-text `detail` wording differs
between implementations, exactly as `CONTRIBUTING.md` says it may; `status` does not).

## Why this directory is a sibling of `spec/test-vectors/`, not a subdirectory of it

Both `impl/go/internal/scpe/vectors_test.go` and `impl/rust/tests/vectors.rs` scan every
top-level directory of `spec/test-vectors/` (skipping only the literal name `_key`) and
hard-assert the count is exactly 18. Verified empirically: dropping even one empty probe
directory under `spec/test-vectors/` fails both conformance tests on the count before a
single vector runs (`go test` → `expected 18 test vectors, found 19`; `cargo test --test
vectors` → the matching panic). Those two files are frozen verifier code (`impl/`), so this
pack lives at `spec/test-vectors-adversarial/` instead: a sibling directory neither harness's
scan of `spec/test-vectors/` ever sees. The 18-vector conformance contract in
`CONTRIBUTING.md`/`../test-vectors/README.md` is untouched, and neither frozen test file was
edited.

## The vectors

| Vector | What it probes | Real status (all 3 impls) |
|---|---|---|
| `duplicate-manifest-keys` | top-level `spec_version` repeated (first: `scpe/0.1`, last: `scpe/9.9`) | `unsupported-version` |
| `manifest-oversize-rejected` | manifest.json > 1 MiB, otherwise identical to `valid-minimal` | `unattested` |
| `subject-with-slash` | `identity.subject` contains `/` (no `..`) — charset rejection, not the traversal check | `identity-unverifiable` |
| `wrong-sshsig-namespace` | signature produced with SSHSIG namespace `not-scpe` instead of `scpe/0.1` | `signature-invalid` |
| `utf8-bom-manifest` | manifest.json begins with a UTF-8 BOM, signed as part of the bytes | `signature-invalid` |
| `truncated-signature` | genuine SSHSIG blob cut to two-thirds length; manifest untouched | `signature-invalid` |
| `invalid-utf8-diff` | code-change diff carrying an invalid UTF-8 byte (0xFF), anchored at the byte level | `verified` |

Six of the seven confirm an implemented defense does exactly what it is supposed to
(`subject-with-slash`, `wrong-sshsig-namespace`, `utf8-bom-manifest`, `truncated-signature`,
`manifest-oversize-rejected`, and `invalid-utf8-diff`) — no surprises, included for coverage
and as regression guards. One surfaced a cross-implementation ambiguity worth the spec owner's
attention:

### `manifest-oversize-rejected` — the 1 MiB cap now applies to directory-form input too

This vector previously documented a gap: `THREAT_MODEL.md` §3's DoS cap was enforced only on
the **zip-envelope** input form, while the **directory** branch (used by all 18 normative
vectors, and by any consumer reading an unpacked `manifest.json`/`manifest.sig` pair) applied
no size check — an oversized manifest verified clean in all three implementations. The cap fix
closed it: the directory read is now size-checked (`_read_file_capped` / `readFileCapped` /
`read_file_capped`), so a manifest padded past 1 MiB fails to load and returns `unattested`.
This vector is now a **regression guard** — if any implementation stops enforcing the
directory-path cap, its status flips back to `verified` and flags the regression.

### `duplicate-manifest-keys` — duplicate-key resolution is cross-implementation ambiguity, not a spec rule

All three JSON libraries (Python stdlib `json`, Go `encoding/json`, Rust `serde_json`) here
resolve a repeated top-level key to the **last** occurrence, and all three correctly reject
the resulting `scpe/9.9` as unsupported — no implementation was fooled by this vector. But
RFC 8259 leaves duplicate-key handling implementation-defined, and nothing in `SPEC.md`
requires a verifier to reject (or canonicalize) a manifest containing duplicate top-level
keys. The three ports agreeing here is a convention their JSON libraries happen to share, not
something the protocol pins down — a fourth implementation using a first-wins or
error-on-duplicate parser could read the *same signed bytes* and reach a different verdict.
Worth a `SPEC.md`/`THREAT_MODEL.md` note (e.g. "verifiers MUST reject a manifest containing a
duplicate JSON key at any level") if cross-implementation determinism on identical signed
bytes matters to the v1.0 gate.

## Regenerating

```
C:/Python314/python.exe make_adversarial_vectors.py   # (re)writes the 6 vector directories
C:/Python314/python.exe verify_all.py                  # runs the Python reference verifier on each, prints real output
```

Reuses `../test-vectors/make_vectors.py`'s manifest builder and signer, and the same
throwaway key committed at `../test-vectors/_key/` — no second key, no forked logic.
`verify_all.py` only drives the Python reference verifier; the Go/Rust cross-checks recorded
in each `expected.json` were run manually (`go build ./cmd/scpe-verify` /
`cargo build --release`, then invoked directly against each vector directory), since these
vectors are deliberately outside both languages' hard-coded 18-vector test discovery.
