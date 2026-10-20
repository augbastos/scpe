<p align="center">
  <img src="docs/assets/scpe-logo.svg" alt="SCPE logo: brackets enclosing a diamond" width="104" height="104">
</p>

<h1 align="center">SCPE</h1>

<p align="center"><i>Merge code, not claims.</i></p>

SCPE is an open protocol for maintainers to check who **signed** a contribution
or file and what they declared about AI use. It binds a signed manifest to a
diff or file digest; it does not prove who authored the content.

**Frozen at v0.2.3; experimental.** The repository preserves a specification,
reference tools, and tests. The author's [retrospective](docs/retrospective.md)
records no external adoption and why the original premise did not hold up.
Level 3 is not implemented or planned. Code is [Apache-2.0](LICENSE);
the specification is [CC-BY-4.0](LICENSE-SPEC).

## What a result means

A signature makes a declaration attributable to a signing key, not true.
SCPE checks the manifest's signature and compares the supplied content with its
signed SHA-256 digest. Diffs use normalized line endings and one trailing newline;
files use their raw bytes. Signed AI-use declarations remain self-reports.

**The key set is the root of trust.** Read `key_source` alongside `status`:

| `key_source` | What backs a `verified` result |
|---|---|
| `forge` | A key fetched from the declared provider's fixed account endpoint signed the manifest. Trust still rests on that provider and account. |
| `flag` | A key from the operator's `--keys` file signed it. The operator must establish whose keys these are. |
| `bundled` | A key supplied with the input signed it. This establishes no connection to the named forge account. |

The verifier tries an explicit keys file, then a directory's bundled keys, then
the forge endpoint. For forge-backed identity, require `key_source == "forge"`;
for an independently trusted key set, supply it yourself and require `"flag"`.
Offline verification is available with local keys, without an SCPE service.

SCPE does not establish code quality, safety, honest disclosure, or human identity.
A compromised key or account undermines the corresponding identity claim.
Read the [threat model](spec/THREAT_MODEL.md) before relying on a result.

## Quick start: verify a fixture offline

From the repository root, with **Python 3.11+** and **OpenSSH 8.2+**
(`ssh-keygen` on `PATH`), run:

```sh
python reference/standalone/verify_envelope.py spec/test-vectors/valid-minimal --keys spec/test-vectors/valid-minimal/keys
```

Expected output:

```text
[OK] verified (attestations: none) [keys: flag]
```

No Python package installation, account, or private key is needed for this
example. The fixture uses public test keys: success checks the example's signature
and content, **not a real account's identity**. Add `--json` for machine-readable
output; the verifier exits zero only for `verified`.

For your own envelope, replace the fixture directory with its directory or ZIP
path and supply a public keys file you trust. A saved PR-body attestation also
needs `--diff` pointing to the independently obtained diff.
[Protocol and usage details](docs/protocol.md) cover production, transport,
artifact profiles, and verification inputs.

## Using the GitHub Action

The Action offers two policies:

- **L1:** look for an AI-disclosure commit trailer or checked PR-template checkbox.
  This is unsigned disclosure lint, not signature verification.
- **L2:** verify a signed envelope. The required gate also checks disclosure,
  accepts only `forge` or `flag` anchors, and, for `code-change` envelopes, checks
  the signed repository and base against the PR context. An `artifact` envelope
  verifies its content, not its relationship to the PR.

`require: "false"` is the informational default. To enforce a decision, set
`require: "true"` and accept only `gate_pass === true` in the result JSON;
the composite Action alone emits the result. Copy both
[verification](docs/workflows/scpe.yml) and
[seal-posting](docs/workflows/scpe-seal.yml) workflows, preserving their separate
jobs and full-history checkout. Protect workflow changes if the gate must resist
a hostile contributor.

See [assurance levels](docs/LEVELS.md) and the
[maintainer setup and version policy](docs/protocol.md#maintainer-setup).
Existing installations should read [security notices](SECURITY.md),
[release history](CHANGELOG.md), and the [legacy migration guide](docs/MIGRATION.md).

## What is included, and its limits

The [Python reference verifier](reference/standalone/verify_envelope.py) is one
standard-library-only file, using `ssh-keygen` for signatures. The
[producer](reference/producer.py) creates signed envelopes; the
[CLI package](scpe/) and Action reuse the reference verifier.

[Go](impl/go/) and [Rust](impl/rust/) ports share the
[normative vectors](spec/test-vectors/) and
[differential tests](tests/test_differential_verifiers.py). Their agreement tests
exercise offline directory inputs with supplied keys; they do not establish
equivalence for every transport or network path. Rust accepts directory inputs
and local keys, with no ZIP, PR-body parsing, or network key fetch.

Standalone verification checks the bytes provided to it; the Action adds PR
context checks for `code-change` envelopes. A standalone `verified` result alone
does not establish that an envelope belongs to the repository where someone presents it. It also does not
require an AI-disclosure field; L2's gate enforces that separately.

The [security policy](SECURITY.md#audit-status) reports no external security audit.
See [verification coverage and CI results](docs/protocol.md#verification-coverage)
and [historical size and timing measurements](docs/protocol.md#historical-size-and-timing-observations).
[Full documentation](docs/README.md) links the specification, design decisions,
comparisons, historical extension proposals, and the author's retrospective.

© 2026 Augusto Bastos.
