# Protocol and usage details

[Back to SCPE](../README.md) · [Documentation index](README.md)

This is a guide to the preserved implementation. [SPEC.md](../spec/SPEC.md) is the
normative format; the [threat model](../spec/THREAT_MODEL.md) defines the trust limits.
Project state and maturity are summarized in the root README.

## Core and profiles

SCPE carries a signed manifest with a hashed artifact. Verification checks its signature
and content digest against a resolved key set; it does not establish who produced the
artifact, whether the signed claims are true, or whether the content is safe.

**One core, many specifications.** *SCPE Core* — the envelope, identity, and verification — is
shared by every domain. Each *SCPE Specification* adds only its domain's conventions on top; the
`profile` label is surfaced but never changes the verify decision.

| Specification | For | Seals | Example |
|---|---|---|---|
| **SCPE-C** | Code | a diff (`code-change`) | a pull request |
| **SCPE-I** | Images | the file's bytes (`artifact`) | `.png`, `.jpg` |
| **SCPE-V** | Video | the file's bytes | `.mp4`, `.mov` |
| **SCPE-A** | Audio | the file's bytes | `.wav`, `.mp3` |
| **SCPE-M** | Models | the file's bytes | `.safetensors`, `.gguf` |
| **SCPE-DATA** | Datasets | the file's bytes | `.csv`, `.parquet` |
| **SCPE-D** | Documents | the file's bytes | `.pdf` |
| **SCPE-AR** | Any artifact | the file's bytes | any file |

Identity is a `(provider, subject)` pair checked against keys from a fixed host table (`github`,
`gitlab`, `codeberg`) or from a keys file — one the verifier's owner supplied, or one bundled
in a directory input. The provider table, rather than a manifest-supplied hostname, chooses
the fetch host. Directory inputs can supply their own keys, which is why the verifier
reports the anchor that answered as `key_source`. ZIP inputs do not accept a `keys` member.

## What SCPE is — and isn't

| **SCPE is** | **SCPE is not** |
|---|---|
| a minimal, transportable, offline-verifiable **evidence format** for a contribution or artifact — which key signed it, whether supplied bytes match its digest, and any *signed attestations* — with one core and thin per-domain profiles. | a code reviewer, a malware scanner, an artifact registry, a CI/CD security system, a compliance framework, or a hosted service. It doesn't judge whether the artifact is *good* or *safe* — only that the evidence checks out. |

For how SCPE relates to code review, build provenance, and attribution records, see
[docs/comparison.md](comparison.md).

**Open, and meant to stay that way.** SCPE is and will remain open source: the
specification and reference implementations are free to read, implement, and fork.
The goal is an open, universal standard for artifact provenance that anyone can
implement without asking permission.

## What ships in this repo

The protocol checks signatures and content integrity. The Action also reports
risk bands and optional test results; those are outside the protocol verdict.

| | What it is |
|---|---|
| [`spec/`](../spec/) | The normative protocol: [SPEC.md](../spec/SPEC.md), the threat model, the manifest schema, and 18 test vectors that are the conformance contract. |
| [`reference/standalone/verify_envelope.py`](../reference/standalone/verify_envelope.py) | **The verifier.** One stdlib-only file that imports nothing else in this repo. |
| [`reference/producer.py`](../reference/producer.py) | The producer (`scpe-envelope pack` / `pack-artifact` / `attest` / `verify` / `submit`) — signs an envelope with a key the contributor already owns. |
| [`impl/go/`](../impl/go/), [`impl/rust/`](../impl/rust/) | Two ports compared by differential tests on offline directory inputs with supplied keys. |
| [`action.yml`](../action.yml) | The maintainer-side GitHub Action. It runs the verifier above, on the same format, out of its own checkout. |
| [`scpe/`](../scpe/) | The `scpe-protocol` package: a stdlib-only CLI over that same verifier, plus the seal the Action renders and the opt-in badge. |

The package is a *distribution* of the protocol, not a second implementation of it: `scpe verify`
is a passthrough whose JSON and exit code are byte-identical to running the single file directly.
The ports have different input and network coverage; see [verification coverage](#verification-coverage).

## The assurance ladder

The Action implements L1 (unsigned disclosure lint) and L2 (signed-envelope policy).
L3 countersignature is an unimplemented historical proposal, not a planned upgrade.
See [LEVELS.md](LEVELS.md) for the supported checks and configuration.

## How it works

1. **Contributor** (human or agent) packs the change into a signed *envelope*: a manifest
   (target repo, base commit, a SHA-256 of the exact diff, an AI-use disclosure, and an
   optional attribution record) signed with the SSH key already on their GitHub profile
   (`ssh-keygen -Y sign -n scpe/0.1`). This path reuses a forge account and its published key.

   > **Check the key endpoint, not just Git's signing configuration.** The verifier
   > fetches `https://<fixed-host>/<subject>.keys`; it does not query GitHub's
   > SSH signing-key API (`/users/{username}/ssh_signing_keys`). GitHub distinguishes
   > authentication keys from signing keys: a signing-only key is not served by
   > `.keys`. For forge-backed verification, register the public key as an
   > authentication key: `gh ssh-key add <key>.pub --title scpe`, without
   > `--type signing`. Git's signing configuration alone does not publish it at
   > the endpoint SCPE uses. Alternatively, supply a trusted public keys file
   > with `--keys` (`flag`), or use a directory's bundled keys (`bundled`, which
   > establishes no forge identity). SCPE does not query `/ssh_signing_keys`.

2. It travels inside a **normal pull request** — the diff in the branch, the signed
   attestation embedded in the PR body. Size observations are recorded below; the
   attestation need not be committed as a binary file.
3. The **owner's side** re-derives everything itself, with no SCPE server involved: the diff's
   SHA-256 is recomputed from the PR and compared, and a seal is posted (or, in require mode, an
   unverifiable PR is rejected). There is **one verifier, not two** — the Action runs the same
   single-file verifier described below, out of its own checkout at the tag you pinned, so there
   is no second implementation to drift. The input and key source affect the result. Read the reported anchor:
   - **Through the Action**, the default PR-body transport supplies no keys of its own. The
     transport carries `manifest.json` and `manifest.sig` (SPEC §9), so there is
     no enclosed key set to find and keys are fetched from the declared provider's fixed endpoint at
     `key_source: forge`. A maintainer running air-gapped can hand it a keys file of their own
     instead — that reports `flag`, and the seal says so, because "the keys this repo supplied"
     is a different claim from "the keys GitHub serves for that account".
   - **Run directly**, the same file is the general tool, available for inspection: it resolves a
     keys file you pass it first, then any `keys` file bundled in a directory input,
     and only if neither is supplied, a fetch from the provider's fixed host.
     It reports which one answered as `key_source`, distinguishing offline
     conformance from a forge check.

## What `verified` proves — and what it doesn't

**What a `verified` result means depends on where the verifier got the keys** — which it reports
as `key_source`. At `forge` it means exactly: *a key the contributor's git host publishes for
this account signed exactly this change and this disclosure, and the diff you're looking at
matches, byte-for-byte after normalizing line endings, what they signed.* At `flag` it means the
same, with the verifier owner's own key set standing in for the host. At `bundled` — keys
carried inside the submission, chosen by whoever sent it — it means only that these exact bytes
were signed by a key that arrived with them, and nothing about the named account. **A consumer
that needs forge-backed identity MUST require `key_source == "forge"`**, or supply the key set
itself and require `"flag"`.

Under every anchor it does **not** prove the code is safe or good (SCPE is not review), that the
disclosure is honest (a signature proves *who claimed*, not that the claim is true), or anything
if the key set that answered is compromised or attacker-chosen — that key set is the trust root.
Read [spec/THREAT_MODEL.md](../spec/THREAT_MODEL.md) before relying on it: §2.1 lays out the three
anchors and what a verdict is worth under each.

This describes a manifest that contains a disclosure. The standalone verifier does
not require that field or check the target against a surrounding PR. L2's gate adds
disclosure checks and, for `code-change` envelopes, PR-context checks; a bare
`verified` is not a passing gate. An `artifact` envelope checks its content and skips
PR-context checks, so it does not establish a relationship to the PR.

## Maintainer setup

Use the two workflow templates to verify PRs and post a seal. With `require` enabled,
the verification job enforces the emitted gate decision. This is optional configuration
for the preserved artifact, not a recommendation to adopt it.

```yaml
# .github/workflows/scpe.yml — the step. Copy BOTH files from docs/workflows/ for the
# fork-safe version: scpe.yml (verify) and its companion scpe-seal.yml (post the seal).
- uses: augbastos/scpe@v0.2.3
  with:
    level: "1"        # 1 = disclosure lint · 2 = signed envelope required
    require: "true"   # the verify job must enforce the emitted gate_pass decision
```

### Version policy

Pin the exact tag while the protocol is pre-1.0.

- **Every tag is immutable.** Each tag keeps pointing at one commit. A fix
  arrives as a *new* tag you adopt by editing the pin, never as a silent change under the one
  you already wrote. The [CHANGELOG](../CHANGELOG.md) records the fixes under separate patch releases.
- **The cost is that fixes do not reach you on their own** — including security fixes. Watch
  the releases, or let Dependabot's `github-actions` ecosystem open the bump as a pull
  request you can read before merging.
- **A patch tag can change behaviour when the old behaviour was wrong.** `v0.2.2` refuses
  contributions that `v0.2.1` accepted, because `v0.2.1` accepted some it should not have.
  Read the [CHANGELOG](../CHANGELOG.md) before moving a pin; "patch" here means the protocol
  did not change, not that nothing did.
- **`spec_version` is a separate number from the tag.** The protocol is `scpe/0.1` across
  every `v0.2.x` release. See [CHANGELOG.md](../CHANGELOG.md) for the three axes and why
  reading one as the other is the easiest mistake to make here.
- **The `v0.1.x` line is legacy, not merely old.** It verifies an envelope format that is not
  in `spec/`, so upgrading from it is a behaviour change and not a patch —
  [docs/MIGRATION.md](MIGRATION.md) has the steps.

**Which tag to be on:** `v0.2.3`. `v0.2.1` and `v0.2` accept a valid envelope replayed from
another repository; `v0.2.2` and earlier write an unregistered domain into your README if you
run `scpe init`. Both are in [SECURITY.md](../SECURITY.md). The second one does not touch the
Action, so a workflow pinned at `v0.2.2` is not exposed to it — but if you ever ran `scpe init`,
open your README and delete the badge block.

The workflow templates use two jobs in **two files**: the verification job in
`scpe.yml` runs contributor code with read-only permissions; the follow-up job in
`scpe-seal.yml` posts the comment with write permission and does not check out the
contribution. The template comments document why the `workflow_run` trigger is in
a separate file. Both verification levels run stdlib-only Python straight out of
the Action's own checkout, rather than installing a verifier from a package index.
The composite Action emits the policy decision without failing on a negative verdict. Use both
[workflow files](workflows/scpe.yml): `verify` uploads `results.json`, then enforces its
`gate_pass` decision with a nonzero exit on failure. The trusted companion also runs after a
failed gate to post the reason. With `require: "false"`, negative verdicts remain
informational and the gate passes. A `pull_request` run uses the workflow file from the PR
itself, so if the gate must hold against a hostile author, protect `.github/workflows/` with
CODEOWNERS or a ruleset.
Check out with `fetch-depth: 0`: level 2 recomputes the diff as `git diff <base>...<head>`, and the
default shallow checkout has no base commit to compare against.

The seal it posts carries more than the verdict — a risk band, a file/line count, an optional test
run. **Those are the Action's own reporting layer, not part of the protocol**: no status, no
`verified`, and nothing in `spec/` depends on them. The verdict is the verifier's; the rest is a
report.

## Verify anything yourself

The reference verifier is one stdlib-only file — read it top to bottom and you know exactly what
a seal means:

```bash
python reference/standalone/verify_envelope.py <envelope.zip> --keys <login.keys>
# → [OK] verified (attestations: none) [keys: flag]
#   (or a precise reject status: tampered, signature-invalid, …)
```

`[keys: …]` names the anchor that answered — `flag` here, because `--keys` supplied the key set.
Without that flag, a `keys` file sitting beside `manifest.json` in the input answers as
`bundled`, and only if neither is present does the verifier fetch from the contributor's host as
`forge`.

The 18 normative [test vectors](../spec/test-vectors) are the conformance contract for **status**:
an implementation that produces their expected statuses conforms to the spec's status behaviour.
They don't pin every normative requirement — no vector carries an expected `key_source`, so
passing all eighteen does not by itself show that the `key_source` MUST is honoured.
[Anchor tests](../tests/test_key_source_anchor.py) separately assert Python's `flag` and
`bundled` results, and [differential tests](../tests/test_differential_verifiers.py)
compare reported anchors as well as statuses and attestation summaries. Every vector ships its own `keys` file so the suite runs offline, and no
vector reaches the `forge` anchor.

## Historical size and timing observations

These historical measurements were recorded on one machine, as order-of-magnitude
observations rather than performance guarantees.

| | Measured |
|---|---|
| PR-body attestation (manifest + sig, base64) | 1.1–1.5 KB |
| Standalone envelope (3-file / 27-line PR, zipped) | ~1.5 KB |
| Verify wall-time | ~200 ms cold process · ~31 ms warm |

An `artifact` subject adds its payload size on top of ~800 B fixed overhead. Order-of-magnitude,
single machine — not a formal benchmark suite. Re-run it yourself rather than taking the number:
`python tests/bench_verify.py <envelope.zip> --keys <login.keys> --runs 15` prints the median of 15 runs
for both paths. The cold figure is a fresh interpreter per run; the warm one re-verifies
in-process, which is what a batch consumer sees after import cost is paid once. Both use the
`flag` anchor, so no network is in the measurement.

## Comparisons recorded in the original README

The comparisons below preserve the original positioning, rather than an independent
check of the named projects' current capabilities. See [comparison.md](comparison.md)
for the repository's longer discussion.

- **Not code review.** Copilot / CodeRabbit judge whether the code is good. SCPE checks a signature and content integrity against a key set.
- **Complements attribution, doesn't compete.** [Agent Trace](https://github.com/cursor/agent-trace)
  and [git-ai](https://github.com/git-ai-project/git-ai) *record* who/what wrote which lines,
  self-reported; SCPE carries that record inside the signed manifest, binding it to
  the signature without proving the record's truth.
- **A different layer from build provenance.** Sigstore / SLSA / in-toto attest *artifacts and
  builds*; SCPE attests a *contribution*, at the pull-request boundary.
- **Direct prior art:** `patatt` + `b4` ([kernel.org](https://github.com/mricon/patatt)) have run
  this shape — the contributor self-signs a patch, the recipient verifies independently, no CA,
  no server — on the Linux kernel's mailing list for years. They differ from SCPE in where the
  key comes from: `patatt` keeps a keyring in the repository, so the project curates who may
  sign; SCPE reads the keys the forge already publishes for the account, so that path delegates identity trust to the forge. Operator-supplied keys instead
  require the operator to establish trust. Same shape, different trust root, applied to
  the pull-request boundary instead of a mailing list.

## Verification coverage

[![CI](https://github.com/augbastos/scpe/actions/workflows/ci.yml/badge.svg)](https://github.com/augbastos/scpe/actions/workflows/ci.yml)

The [CI configuration](../.github/workflows/ci.yml) runs on pushes to `main`,
pull requests, and manual dispatch. It runs the Python suite, including the
[100 synthetic PR scenarios](../tests/test_stress_100prs.py) (50 valid and
50 irregular inputs) and the [local end-to-end tests](../tests/test_e2e_local.py)
that exercise producer → PR-body attestation → sealer → gate decision, plus Go
and Rust checks. [CI results](https://github.com/augbastos/scpe/actions/workflows/ci.yml)
are available directly.

The normative and differential tests compare offline directory inputs with supplied
keys (`flag`). That is not evidence of parity for ZIP, PR-body, or network paths.
Rust has no network fetch, ZIP, or PR-body parser; it accepts directory inputs with
explicit or bundled local keys. Python and Go implement the additional input paths.

**`v0.1.x` is legacy: its original signed-envelope path verified a format that is not in this spec.** The
Action at those tags checked a second envelope format that shipped inside the package and was
deleted in `0.2.0`. Before that release, L2 could silently accept the old format and
reject conforming envelopes. When its unpinned runtime dependency resolves to
`0.2.x`, the legacy positional invocation instead fails argument parsing.
L1 reads disclosure text and is unaffected by the envelope-format change.
[CHANGELOG.md](../CHANGELOG.md) has what moved; [docs/MIGRATION.md](MIGRATION.md)
has what to do about it.

