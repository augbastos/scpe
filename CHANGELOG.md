# Changelog

Notable changes to this repository — the `scpe/0.1` specification, the three reference
verifiers, the GitHub Action, and the `scpe-protocol` package. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Three things here are versioned on separate axes and none of them is the same number as the
others. Reading a `0.2` in one column as a `0.2` in another is the single easiest mistake to
make with this project:

| Axis | Looks like | Moves when |
|---|---|---|
| **Protocol** — `spec_version` | `scpe/0.1` | the wire format or the verification algorithm changes (SPEC §11, [docs/governance.md §3](docs/governance.md)) |
| **Release** — this file, the PyPI version | `0.2.0` | anything in this repository ships |
| **Action tag** — what a workflow pins | `augbastos/scpe@v0.2` | never — each tag is immutable and a new release gets a new tag |

`0.2.0` does **not** change the protocol. `spec_version` is still `scpe/0.1`, the signing
namespace is still `scpe/0.1`, and every envelope that verified against SPEC.md before this
release still verifies, byte for byte. What changed is which format the *tooling* reads.

---

## [0.2.0] — unreleased

*(dated on publication — the git tag and the PyPI release are not out yet)*

The installable package carried a second, undocumented envelope format, and the Marketplace
Action verified **that** one instead of the one in SPEC.md. This release deletes it, leaving a
single verification path. It is a large removal — roughly 7,600 lines — and the compatibility
story is not the usual one.

> **If your workflow pins `augbastos/scpe@v0.1.x`, read
> [docs/MIGRATION.md](docs/MIGRATION.md) before anything else.** That pin does not break. It
> keeps running against a format this repository no longer produces — passing an envelope built
> by the removed tooling, rejecting a conforming one, and never saying which it did. A silent
> wrong answer is worse than a failed step, so it gets its own document.

### Removed

- **The agent package.** 18 modules and 25 test files inherited from an earlier project:
  an LLM pipeline that cloned a repo, asked a model for a patch, ran it in a sandbox and
  opened a pull request (`analyze.py`, `backends.py`, `contribute.py`, `sandbox.py`,
  `workspace.py`, `prompting.py`, `handshake.py`, `mcp_server.py` and the rest). None of it
  appears in SPEC.md, and it never did.
- **The second envelope format.** `scpe/envelope.py` packed an `envelope.json` carrying
  `PROTOCOL_VERSION "1"`, signed a canonicalised *re-serialisation* of that JSON, and marked
  its PR block `<!-- scpe-envelope:v1`. The protocol signs the exact bytes of `manifest.json`
  with SSHSIG and canonicalises nothing. The two never could read each other — the package
  contained zero occurrences of `manifest.json`, `spec_version` or `SCPE-ATTESTATION`.
  **There is no converter and there cannot be one:** the formats sign different bytes, so an
  old envelope has to be rebuilt and re-signed, not translated.
- **Eleven `scpe` subcommands**: `analyze`, `attest`, `changes`, `contribute`, `extract`,
  `keygen`, `label`, `pack`, `pull`, `submit`, `verify-attest`. Four remain — `verify`,
  `seal`, `inspect`, `init`. `pack`, `attest` and `submit` still exist as verbs on
  `scpe-envelope` (the producer), but they build the *spec* envelope; that is a different
  artifact under a familiar name, not a rename. See the command map in
  [docs/MIGRATION.md](docs/MIGRATION.md).
- **The `scpe-mcp` console script and the `mcp` optional dependency.**
- **The `cryptography` dependency.** The package is stdlib-only now, and a test enforces it.
  Nothing was lost: signatures were always checked by `ssh-keygen -Y verify` (OpenSSH ≥ 8.2),
  never by a Python crypto library. Stdlib-only is what lets the Action run the package
  straight from a pinned checkout with no install step.

### Changed

- **The Action verifies the spec format.** It now calls the same single-file reference
  verifier that the 18 normative vectors run against, so there is one verification algorithm
  in the project rather than two that cannot read each other's output. Previously it invoked
  `scpe seal` from the package, which understood only the removed format.
- **The Action installs nothing at run time, at either level.** Its level-2 path used to shell
  out to `pipx run --spec scpe-protocol scpe seal …`, resolving `scpe-protocol` from PyPI *on
  every run with no version constraint* — an unpinned dependency hiding behind a pinned tag.
  (Level 1 already ran `reference/level1_lint.py` from the Action's own checkout, and still
  does.) Level 2 now runs `PYTHONPATH=<action_path> python3 -m scpe.cli seal …` from that same
  checkout, so the bytes that decide a merge are the bytes of the tag you pinned.
- **`scpe seal` takes `--envelope` as a flag**, not as a positional argument, and the Action's
  `envelope` input now defaults to empty rather than to a fixed path to a committed zip. Empty
  selects the spec's §9 transport: the attestation rides in the PR description and no binary
  blob lands in history.
- **`scpe verify` is a pass-through, not a wrapper.** It forwards argv to
  `reference/standalone/verify_envelope.py`'s own `main()`, so its output bytes and exit code
  are the verifier's rather than a reformatting of them. Parity is by construction. Under
  `0.1.x` this command was an owner-side handshake over the removed format.
- **The gate refuses a self-anchored identity.** With `require: "true"`, a result carrying
  `key_source: "bundled"` no longer passes even when `status` is `verified` — those keys
  arrived inside the submission, so they prove the bytes were signed by a key that travelled
  with them and nothing about the named account. `flag` (keys the repository owner supplied)
  and `forge` still pass. The refusal carries its own message rather than falling through to
  the generic "not verifiable", because a red X next to `status: verified` is otherwise
  unreadable.
- **A duplicate JSON key in a manifest is a parse error** in all three implementations, at any
  nesting depth, before the signature and integrity checks — `signature-invalid`, detail
  `duplicate JSON key '<name>'` (SPEC §4.1). RFC 8259 leaves this implementation-defined, and
  the three ports agreed on last-wins only because their JSON libraries share that convention;
  a fourth reading first-wins would have reached a different verdict on the same signed bytes.
  `spec/test-vectors-adversarial/duplicate-manifest-keys` stops documenting an ambiguity and
  becomes a regression guard.
- **`reference/producer.py` no longer imports from `scpe`.** It absorbed the `gh`-based login
  resolution it used to borrow — the only `reference` → `scpe` edge in the repo, and one that
  contradicted the file's own stdlib-only docstring.

### Added

- **`key_source` on every result** — `"flag" | "bundled" | "forge"` — surfaced in the JSON, in
  the human output, and on the seal the Action posts. SPEC §8 step 4 makes reporting it a MUST.
  Keys resolve in the order `--keys` flag → a `keys` file inside the input → the provider host,
  and until now all three produced a bare `verified` with nothing distinguishing an offline
  conformance run from a real forge check.
- **Continuous integration** (`.github/workflows/ci.yml`) — there was no `.github/` directory
  at all before this release, and the test count in the README was a static badge maintained by
  hand, which stayed green through a red test. Five jobs on push and pull request: `python`
  (pytest on 3.11 and 3.12), `go` (`go build` + `go test`), `rust` (`cargo test --locked`),
  `vectors` (a bare interpreter running the single-file reference verifier over the eighteen
  normative vectors, which is the only arrangement that proves the one-file claim), and
  `adversarial`.
- **Automated coverage of the adversarial vectors.** The seven vectors in
  `spec/test-vectors-adversarial/` are not new, but nothing was running them: the Go and Rust
  harnesses hard-assert a directory count of 18 and cannot see the sibling pack, and pytest
  never referenced it. Their recorded statuses had only ever been confirmed by hand. The new
  `adversarial` job builds all three verifiers and runs every one of the seven against each,
  comparing status and exit code — so the pack is now checked across implementations rather
  than in one language.
- **Three test files** covering what the refactor made checkable:
  `tests/test_retired_envelope_format.py` (the removed format is rejected cleanly rather than
  crashing), `tests/test_key_source_anchor.py` (the anchor a verdict rests on, which no
  vector's `expected.json` can express), and `tests/test_entry_points.py` (every console
  script the package advertises resolves to something callable).

### Fixed

- The status badge read `v0.1` after the version had moved.
- Documentation claims that had drifted from the code, including claims scoped to a key anchor
  that the verifier had not actually used.

---

## Earlier releases

`v0.1`, `v0.1.2` and `v0.1.3` predate this file, and the whole line is **legacy: its level-2
verification implements a format that is not in `spec/`.** Recorded here for provenance, not as
something to upgrade from in place.

| Tag | Commit date | Notes |
|---|---|---|
| `v0.1.3` | 2026-07-24 | Same commit as `v0.1`. Never published to PyPI. |
| `v0.1` | 2026-07-24 | Marketplace listing named *SCPE Seal*. |
| `v0.1.2` | 2026-07-23 | The only release that reached PyPI, as `scpe-protocol`. Its published metadata still advertises `cryptography>=42` and the `mcp` extra; PyPI releases are immutable, so only publishing `0.2.0` corrects that. |

The distribution name has been `scpe-protocol` since `v0.1.2` and does not change in `0.2.0`.
`pip install scpe` has never worked — see [docs/MIGRATION.md](docs/MIGRATION.md).
