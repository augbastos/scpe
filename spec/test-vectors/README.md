# SCPE test vectors (normative)

Eighteen vectors, one directory each. An implementation conforms to SPEC §8 if it
produces the `expected.json` status for all eighteen.

Each directory contains:

| File | Meaning |
|---|---|
| `manifest.json` | the signed manifest, exact bytes |
| `manifest.sig` | SSHSIG over those bytes, namespace `scpe/0.1` |
| `diff.patch` | the normalized diff (standalone-envelope form for a `code-change` subject); absent for a subject that needs no diff |
| `artifact.bin` | the raw artifact bytes (standalone-envelope form for an `artifact` subject, SPEC §6.2); present only for `artifact`-subject vectors |
| `keys` | simulated body of `<provider-host>/octocat-test.keys` — test harnesses MUST substitute this file for the network fetch of SPEC §8 step 4 (and it is the sole key source for the `local` provider) |
| `expected.json` | `{ "status": ..., "attestations": [ {type, status}, ... ] }` — the required verification outcome; `attestations` is checked only when present |

The verifier's JSON output also carries a `profile` field — the advisory domain-convention
label (SPEC §13), surfaced verbatim from the manifest (or `null` when unstamped). It is
**displayed, never dispatched**: it never affects `status`, so these normative vectors do
not assert on it. See `examples/` for a runnable per-profile pack+verify walkthrough.

Identity is a `(provider, username)` pair (SPEC §8). The vectors cover every provider
in the fixed registry, both implemented subject types (`code-change` and `artifact`),
the `unsupported-provider`, `unsupported-subject` (unknown subject type),
`identity-unverifiable` (bad username), multi-attestation, and the signature /
integrity / version / attestation outcomes. The `attestations` column shows the
verifier's per-entry summary:

| Vector | Identity | Expected status |
|---|---|---|
| `valid-minimal` | `github` / `octocat-test` | `verified` (`attestations: []`) |
| `valid-gitlab` | `gitlab` / `octocat-test` | `verified` (`attestations: []`) |
| `valid-codeberg` | `codeberg` / `octocat-test` | `verified` (`attestations: []`) |
| `valid-local` | `local` / `octocat-test` | `verified` (`attestations: []`) |
| `valid-agent-trace-generic` | `github` | `verified` (`agent-trace=present-generic/1`) |
| `valid-agent-trace-gitai` | `github` | `verified` (`agent-trace=present-git-ai/notes`) |
| `valid-agent-trace-real` | `github` | `verified` (`agent-trace=present-agent-trace/1`) |
| `invalid-signature` | `github` | `signature-invalid` (bytes edited after signing) |
| `tampered-diff` | `github` | `tampered` (diff ≠ `subject.change.diff_sha256`) |
| `wrong-identity` | `github` | `signature-invalid` (key absent from `keys`) |
| `unknown-version` | `github` | `unsupported-version` (`scpe/9.9`) |
| `unknown-trace-format` | `github` | `verified` (`agent-trace=present-unverified`) |
| `unsupported-provider` | `oidc` (reserved) / `octocat-test` | `unsupported-provider` |
| `unsupported-subject` | `github`, subject type `container-image` (unknown) | `unsupported-subject` (fails closed despite a valid signature) |
| `identity-unverifiable-subject` | `github` / `evil..traversal` | `identity-unverifiable` |
| `valid-artifact` | `github`, subject type `artifact` | `verified` (`attestations: []`; `artifact.bin` matches `subject.digest.sha256`) |
| `tampered-artifact` | `github`, subject type `artifact` | `tampered` (`artifact.bin` ≠ `subject.digest.sha256`) |
| `multi-attestation` | `github` | `verified` (`agent-trace=present-generic/1`, `timestamp=present-unverified`) |

Each vector carries its own public `keys` file and signature, so the vectors verify
offline with nothing else. The **private** signing keys used to produce them live in
`_key/` and are **gitignored** — never commit SSH private keys, even throwaway ones.
`python make_vectors.py` regenerates `_key/` (fresh throwaway keys) and re-signs every
vector; the committed vectors are the source of truth and normally aren't regenerated.
