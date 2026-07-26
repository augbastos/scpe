<p align="center">
  <img src="docs/assets/scpe-logo.svg" alt="SCPE" width="104" height="104">
</p>

<h1 align="center">SCPE</h1>

<p align="center">
  <b>A protocol for verifiable digital artifacts.</b><br>
  A single envelope. Multiple specifications.<br>
  <i>Merge code, not claims.</i>
</p>

<p align="center">
  <a href="https://github.com/augbastos/scpe/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/augbastos/scpe/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="3 impls" src="https://img.shields.io/badge/verifiers-python%20%2B%20go%20%2B%20rust-41c257?style=flat-square&labelColor=0b0b0c">
  <img alt="spec" src="https://img.shields.io/badge/spec-scpe%2F0.1-41c257?style=flat-square&labelColor=0b0b0c">
  <img alt="python" src="https://img.shields.io/badge/python-3.11%2B-41c257?style=flat-square&labelColor=0b0b0c">
  <img alt="license" src="https://img.shields.io/badge/code-Apache--2.0-41c257?style=flat-square&labelColor=0b0b0c">
  <img alt="status" src="https://img.shields.io/badge/v0.1-early-d29922?style=flat-square&labelColor=0b0b0c">
</p>

An open protocol that lets a repository owner verify — with no SCPE server and no new
accounts — *who* made a pull request and that *nothing was tampered with*, then turn on a
policy that only merges contributions they can verify. There is no SCPE server, ever: the
default forge path makes exactly one HTTPS GET, to the contributor's git host, for keys it
already publishes — and even that is avoidable by supplying a local keys file, for
verification with zero network calls.

When a PR arrives from someone you don't know — a person, or increasingly an AI agent — trust
today rests on a GitHub username, the platform, and reading the diff by eye. SCPE adds a
cryptographic answer to two questions the platform doesn't: **who really produced this change**,
and **is the diff exactly what they signed** — carrying a signed AI-use disclosure (and,
optionally, a machine-attribution record) alongside. The owner re-derives everything with
`ssh-keygen`, `git`, and the public keys the contributor's git host already publishes. There is
no SCPE server, so there is nothing to trust and nothing to shut down.

**SCPE standardizes evidence, not content.** It never says an artifact is good, true, or safe —
it standardizes how verifiable evidence (who produced it, that it's untampered, and any signed
attestations) travels with a hashed artifact and is checked offline.

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

Identity is a `(provider, subject)` pair resolved from a fixed host table (`github`, `gitlab`,
`codeberg`) or an offline keys file — the manifest never carries a hostname, so a contribution
can't steer the verifier at an attacker's host.

**Open, and meant to stay that way.** SCPE is — and will always be — open source: the
specification and every reference implementation are free to read, implement, and fork. The
goal is a single, open, *universal* standard for artifact provenance, and a standard only
becomes universal if anyone can implement it without asking permission. So being open isn't a
license choice here; it's the whole point.

> **Attribution tells you *what*. Provenance proves *who* — and that nothing was tampered with.**

## What SCPE is — and isn't

| **SCPE is** | **SCPE is not** |
|---|---|
| a minimal, transportable, offline-verifiable **evidence format** for a contribution or artifact — *who* produced it, proof it's *untampered*, and any *signed attestations* — with one core and thin per-domain profiles. | a code reviewer, a malware scanner, an artifact registry, a CI/CD security system, a compliance framework, or a hosted service. It doesn't judge whether the artifact is *good* or *safe* — only that the evidence checks out. |

For how SCPE relates to code review, build provenance, and attribution records, see
[docs/comparison.md](docs/comparison.md).

## The assurance ladder

Adopt at the level that fits your project, and upgrade later without changing the format.

| Level | What the repo requires | Contributor cost |
|---|---|---|
| **L1 — Disclosure** | An AI-use disclosure is present (an `Assisted-by:` trailer or a PR-template checkbox). | Zero — it's the policy you may already have written, now enforced. |
| **L2 — Signed envelope** | A valid signed SCPE envelope: verifiable identity + an untampered diff. | One command to sign. |
| **L3 — Countersignature** *(roadmap)* | A third party (a reviewer, or the agent platform) co-signs. | — |

Higher levels include the lower ones. Most projects that already require AI disclosure need
**L1** today; the signature is the *mechanism*, the policy is the *product* — the same shape
SLSA uses to sell levels. See [docs/LEVELS.md](docs/LEVELS.md).

## How it works

1. **Contributor** (human or agent) packs the change into a signed *envelope*: a manifest
   (target repo, base commit, a SHA-256 of the exact diff, an AI-use disclosure, and an
   optional attribution record) signed with the SSH key already on their GitHub profile
   (`ssh-keygen -Y sign -n scpe/0.1`). No new account.
2. It travels inside a **normal pull request** — the diff in the branch, the ~1–2 KB signed
   attestation embedded in the PR body. Merging leaves the repo history clean.
3. The **owner's side** — a GitHub Action, or a single-file verifier auditable in ten minutes —
   re-derives everything itself, with no SCPE server involved: the signature is checked against
   `github.com/<login>.keys` (one HTTPS GET to keys the contributor's host already publishes —
   or, with a supplied keys file, no network call at all), the diff's SHA-256 is recomputed from
   the PR and compared, and a seal is posted (or, in require mode, an unverifiable PR is
   rejected).

## What `verified` proves — and what it doesn't

A `verified` result means exactly: *a key published on this GitHub account signed exactly this
change and this disclosure, and the diff you're looking at matches, byte-for-byte after
normalizing line endings, what they signed.* Nothing more.

It does **not** prove the code is safe or good (SCPE is not review), that the disclosure is
honest (a signature proves *who claimed*, not that the claim is true), or anything if the GitHub
account or key is compromised (that's the trust root). Read
[spec/THREAT_MODEL.md](spec/THREAT_MODEL.md) before relying on it — it states the limits plainly.

## For maintainers — turn it on

Add a workflow that verifies every PR and posts a seal. Set `require` to gate merges.

```yaml
# .github/workflows/scpe.yml — see docs/workflows/scpe.yml for the fork-safe full version
- uses: augbastos/scpe@v0.1
  with:
    level: "1"        # 1 = disclosure lint · 2 = signed envelope required
    require: "true"   # fail the check on anything not verifiable
```

The Action uses a fork-safe two-job split: the untrusted job (which runs contributor code) holds
no secrets; only a trusted follow-up job posts the comment.

## Verify anything yourself

The reference verifier is one stdlib-only file — read it top to bottom and you know exactly what
a seal means:

```bash
python reference/standalone/verify_envelope.py <envelope.zip> --keys <login.keys>
# → [OK] verified   (or a precise reject status: tampered, signature-invalid, …)
```

The 18 normative [test vectors](spec/test-vectors) are the conformance contract: any
implementation that produces their expected statuses conforms to the spec.

**Cost** — measured on the Python reference (Ryzen 5 5600H, Python 3.14, `local` provider):

| | Measured |
|---|---|
| PR-body attestation (manifest + sig, base64) | 1.1–1.5 KB |
| Standalone envelope (3-file / 27-line PR, zipped) | ~1.5 KB |
| Verify wall-time | ~210 ms cold CLI · ~39 ms in a warm process |

An `artifact` subject adds its payload size on top of ~800 B fixed overhead. Order-of-magnitude,
single machine — not a formal benchmark suite.

## Where it sits

- **Not code review.** Copilot / CodeRabbit judge whether the code is good. SCPE proves *who*
  and *integrity*.
- **Complements attribution, doesn't compete.** [Agent Trace](https://github.com/cursor/agent-trace)
  and [git-ai](https://github.com/git-ai-project/git-ai) *record* who/what wrote which lines,
  self-reported; SCPE carries that record inside the signed manifest, making it verifiable.
- **A different layer from build provenance.** Sigstore / SLSA / in-toto attest *artifacts and
  builds*; SCPE attests a *contribution*, at the pull-request boundary.
- **Direct prior art:** `patatt` + `b4` ([kernel.org](https://github.com/mricon/patatt)) have run
  this exact pattern — self-sign a patch with a key the platform publishes, verify independently,
  no CA, no server — on the Linux kernel's mailing list for years. SCPE applies the same shape to
  the GitHub pull-request boundary.

## Status

**v0.1 — early.** This is a specification plus a reference implementation (a single-file
verifier, a producer, and a maintainer-side Action) with **441 passing tests**, including a
100-PR stress proof and a local end-to-end — plus two more independent verifiers, in Go and
Rust, that reach the same verdict as the Python reference on every one of the 18 normative
vectors — and a differential test that runs mutated manifests through all three and confirms
they never disagree. There is **no external adoption yet**. It is not a hosted service and
never will be.

## Docs

- [spec/SPEC.md](spec/SPEC.md) — the protocol (`scpe/0.1`)
- [spec/THREAT_MODEL.md](spec/THREAT_MODEL.md) — what it does and does not defend against
- [spec/FAQ.md](spec/FAQ.md) — why SSH, why the PR body, relation to Agent Trace / Sigstore / patatt
- [docs/LEVELS.md](docs/LEVELS.md) — the L1 / L2 / L3 assurance ladder

## License

Code is [Apache-2.0](LICENSE); the specification (everything under `spec/`) is
[CC-BY-4.0](LICENSE-SPEC). © 2026 Augusto Bastos.
