# SCPE adversarial test vectors (non-normative)

Seven vectors, one directory each, each probing a defense the reference verifier
(`reference/standalone/verify_envelope.py`) already implements. **Not** additions to the
eighteen normative vectors in `../test-vectors/` and not a new protocol capability —
`expected.json` in every directory here records the status the verifier ACTUALLY returns
(confirmed by running it), not an assumed one. Every status here is also confirmed to match
across `reference/standalone/verify_envelope.py`, `impl/go/cmd/scpe-verify`, and `impl/rust`'s
`scpe-verify` binary (see each `expected.json`'s note — free-text `detail` wording differs
between implementations, exactly as `CONTRIBUTING.md` says it may; `status` does not).
One exception, flagged in its own note: `duplicate-manifest-keys` was re-expected when the
duplicate-key rule (`SPEC.md` §4.1) landed — read off the three implementations of that rule,
not yet re-run against their built binaries.

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
| `duplicate-manifest-keys` | top-level `spec_version` repeated (first: `scpe/0.1`, last: `scpe/9.9`) — the duplicate-key rejection of SPEC §4.1 | `signature-invalid` † |
| `manifest-oversize-rejected` | manifest.json > 1 MiB, otherwise identical to `valid-minimal` | `unattested` |
| `subject-with-slash` | `identity.subject` contains `/` (no `..`) — charset rejection, not the traversal check | `identity-unverifiable` |
| `wrong-sshsig-namespace` | signature produced with SSHSIG namespace `not-scpe` instead of `scpe/0.1` | `signature-invalid` |
| `utf8-bom-manifest` | manifest.json begins with a UTF-8 BOM, signed as part of the bytes | `signature-invalid` |
| `truncated-signature` | genuine SSHSIG blob cut to two-thirds length; manifest untouched | `signature-invalid` |
| `invalid-utf8-diff` | code-change diff carrying an invalid UTF-8 byte (0xFF), anchored at the byte level | `verified` |

† `duplicate-manifest-keys` is the one row not copied from a verifier run: its status is read
off the three implementations of the `SPEC.md` §4.1 duplicate-key rule and is pending a re-run.
Every other row is observed output.

Five of the seven confirm an implemented defense does exactly what it is supposed to
(`subject-with-slash`, `wrong-sshsig-namespace`, `utf8-bom-manifest`, `truncated-signature`,
and `invalid-utf8-diff`) — no surprises, included for coverage and as regression guards. The
other two each found something real, both since closed; they are kept here, unchanged as
inputs, to guard the fix:

### `manifest-oversize-rejected` — the 1 MiB cap now applies to directory-form input too

This vector previously documented a gap: `THREAT_MODEL.md` §3's DoS cap was enforced only on
the **zip-envelope** input form, while the **directory** branch (used by all 18 normative
vectors, and by any consumer reading an unpacked `manifest.json`/`manifest.sig` pair) applied
no size check — an oversized manifest verified clean in all three implementations. The cap fix
closed it: the directory read is now size-checked (`_read_file_capped` / `readFileCapped` /
`read_file_capped`), so a manifest padded past 1 MiB fails to load and returns `unattested`.
This vector is now a **regression guard** — if any implementation stops enforcing the
directory-path cap, its status flips back to `verified` and flags the regression.

### `duplicate-manifest-keys` — duplicate keys are now a spec rule, not an ambiguity

This vector previously documented an ambiguity: all three JSON libraries (Python stdlib
`json`, Go `encoding/json`, Rust `serde_json`) resolved a repeated key to the **last**
occurrence, so all three read `scpe/9.9` and rejected it as `unsupported-version` — no
implementation was fooled. But that agreement was a convention their parsers happen to
share, not something the protocol pinned down: RFC 8259 leaves duplicate-key handling
implementation-defined, so a fourth implementation with a first-wins or error-on-duplicate
parser could read the *same signed bytes* and reach a different verdict — and here the port
agreement only produced a refusal at all because the duplicated key happened to be
`spec_version`. A duplicated `contributor`, `subject`, or `attestations` would have been
resolved silently, by no rule, on the way to a verdict.

`SPEC.md` §4.1 ("No duplicate keys") now requires rejecting a manifest that repeats a key in
any object at any nesting depth, and §8 step 2 places the rejection at parse time, before the
signature and integrity checks, mapping it to `signature-invalid` — the same status every
other unreadable manifest already gets (see `utf8-bom-manifest` for the same deliberate label
imprecision: the SSHSIG may be intact; the enum has no separate malformed-manifest value, so
`detail` carries the reason). This vector is now a **regression guard** — if an implementation
stops rejecting duplicates, its status falls back to `unsupported-version` here, and for a
duplicate of any key other than `spec_version` it would slip past the check entirely.

## Regenerating

```
python make_adversarial_vectors.py   # (re)writes all 7 vector directories
python verify_all.py                 # runs the Python reference verifier on each, prints real output
```

Reuses `../test-vectors/make_vectors.py`'s manifest builder and signer, and the same
throwaway key at `../test-vectors/_key/` — no second key, no forked logic. That key is
**gitignored, never committed** (`.gitignore` → `spec/test-vectors/_key/`): private keys
stay out of the repo even when they are throwaway. It is minted by `make_vectors.py`, so a
fresh clone must run that before regenerating here. Verifying the vectors needs no key at
all — each directory carries the public half it needs.
`verify_all.py` only drives the Python reference verifier; the Go/Rust cross-checks recorded
in each `expected.json` were run manually (`go build ./cmd/scpe-verify` /
`cargo build --release`, then invoked directly against each vector directory), since these
vectors are deliberately outside both languages' hard-coded 18-vector test discovery.
