<p align="center">
  <img src="docs/assets/scpe-logo.svg" alt="SCPE" width="104" height="104">
</p>

<h1 align="center">SCPE</h1>

<p align="center">
  <b>Know who signed a contribution — and which AI they said they used.</b><br>
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

An open protocol for two questions a pull request cannot answer today: **who signed this
change**, and **what did they declare about AI use** — with proof that the diff is
byte-for-byte what they signed. No SCPE server, no new accounts, no new keys: the contributor
signs with the SSH key already on their git host, and the owner re-derives everything with
`ssh-keygen` and `git`.

The AI-use disclosure is **signed**, not typed into a form. That is the whole difference. A
signature does not make a claim true — it makes it *attributable* and *tamper-evident*: bound
to one identity and to this exact diff, so it cannot be edited afterwards or quietly attached
to different code. Whether someone told the truth about their tools stays a human judgement;
SCPE makes sure the claim, the author, and the change cannot be separated.

When a PR arrives from someone you don't know — a person, or increasingly an AI agent — trust
today rests on a username, the platform, and reading the diff by eye. SCPE replaces the first
two with something the owner can check locally, and leaves the third where it belongs. There
is no SCPE server, so there is nothing to trust and nothing to shut down.

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

Identity is a `(provider, subject)` pair checked against keys from a fixed host table (`github`,
`gitlab`, `codeberg`) or from a keys file — one the verifier's owner supplied, or one bundled
inside the submission. The manifest never carries a hostname, so a contribution can't steer the
verifier at an attacker's host; it *can* enclose its own keys, which is why the verifier reports
the anchor that answered as `key_source`.

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

## What ships in this repo

A protocol, and the smallest set of things needed to prove it is one. Nothing here writes,
reviews, or generates code — SCPE never looks at what a change *does*, only at who signed it and
whether it still matches.

| | What it is |
|---|---|
| [`spec/`](spec/) | The normative protocol: [SPEC.md](spec/SPEC.md), the threat model, the manifest schema, and 18 test vectors that are the conformance contract. |
| [`reference/standalone/verify_envelope.py`](reference/standalone/verify_envelope.py) | **The verifier.** One stdlib-only file that imports nothing else in this repo. |
| [`reference/producer.py`](reference/producer.py) | The producer (`scpe-envelope pack` / `attest` / `submit`) — signs an envelope with a key the contributor already owns. |
| [`impl/go/`](impl/go/), [`impl/rust/`](impl/rust/) | Two independent ports of the verifier, held to the same verdict by a differential test. |
| [`action.yml`](action.yml) | The maintainer-side GitHub Action. It runs the verifier above, on the same format, out of its own checkout. |
| [`scpe/`](scpe/) | The `scpe-protocol` package: a stdlib-only CLI over that same verifier, plus the seal the Action renders and the opt-in badge. |

The package is a *distribution* of the protocol, not a second implementation of it: `scpe verify`
is a passthrough whose JSON and exit code are byte-identical to running the single file directly.
There is one envelope format, one verification algorithm, and one verdict — everything above is a
different way of reaching the same one.

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
3. The **owner's side** re-derives everything itself, with no SCPE server involved: the diff's
   SHA-256 is recomputed from the PR and compared, and a seal is posted (or, in require mode, an
   unverifiable PR is rejected). There is **one verifier, not two** — the Action runs the same
   single-file verifier described below, out of its own checkout at the tag you pinned, so there
   is no second implementation to drift. What can differ between runs is only which key anchor
   answers, and the result always names it:
   - **Through the Action**, a contribution cannot substitute the keys that judge it. The
     transport carries `manifest.json` and `manifest.sig` and nothing else (SPEC §9), so there is
     no enclosed key set to find and the keys come from `github.com/<login>.keys`, live, at
     `key_source: forge`. A maintainer running air-gapped can hand it a keys file of their own
     instead — that reports `flag`, and the seal says so, because "the keys this repo supplied"
     is a different claim from "the keys GitHub serves for that account".
   - **Run directly**, the same file is the general tool, auditable in ten minutes: it resolves a
     keys file you pass it first, then any `keys` file bundled in the input, and only if neither
     answers, one HTTPS GET to the contributor's host. It reports which one answered as
     `key_source`, so an offline conformance run is never mistaken for a forge check.

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
Read [spec/THREAT_MODEL.md](spec/THREAT_MODEL.md) before relying on it: §2.1 lays out the three
anchors and what a verdict is worth under each.

## For maintainers — turn it on

Add a workflow that verifies every PR and posts a seal. Set `require` to gate merges.

```yaml
# .github/workflows/scpe.yml — see docs/workflows/scpe.yml for the fork-safe full version
- uses: augbastos/scpe@v0.2
  with:
    level: "1"        # 1 = disclosure lint · 2 = signed envelope required
    require: "true"   # fail the check on anything not verifiable
```

Pin the exact tag while the protocol is pre-1.0. `v0.2` is the first release in which the
Action verifies the `scpe/0.1` envelope itself; `v0.1.x` verified a different, now-removed
format, so upgrading from it is a behaviour change and not a patch.

The Action uses a fork-safe two-job split: the untrusted job (which runs contributor code) holds
no secrets; only a trusted follow-up job posts the comment. Neither level installs anything in the
runner — both run stdlib-only Python straight out of the Action's own checkout, so the bytes that
decide a merge are the bytes of the tag you pinned, not whatever a package index serves that day.
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

The 18 normative [test vectors](spec/test-vectors) are the conformance contract for **status**:
an implementation that produces their expected statuses conforms to the spec's status behaviour.
They don't pin every normative requirement — no vector carries an expected `key_source`, so
passing all eighteen does not by itself show that the `key_source` MUST is honoured; that one is
checked by inspection. Every vector ships its own `keys` file so the suite runs offline, and no
vector reaches the `forge` anchor.

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
verifier, a producer, and a maintainer-side Action). The full test suite — including a 100-PR
stress proof and a local end-to-end — runs on every push; the CI badge above is its live
result. Two more independent verifiers, in Go and Rust, reach the same verdict as the Python
reference on every one of the 18 normative vectors, and a differential test runs mutated
manifests through all three and confirms they never disagree. That three-way agreement covers
the path those vectors exercise — a directory input checked offline against a supplied keys
file, the `flag` anchor; no vector exercises the network fetch. The Rust port goes no further: it has no network key fetch (`--keys` is required) and
does not parse the zip-envelope or in-PR-body attestation input shapes that Python and Go both
accept. There is **no external adoption yet**. It is not a hosted service and never will be.

## Docs

- [spec/SPEC.md](spec/SPEC.md) — the protocol (`scpe/0.1`)
- [spec/THREAT_MODEL.md](spec/THREAT_MODEL.md) — what it does and does not defend against
- [spec/FAQ.md](spec/FAQ.md) — why SSH, why the PR body, relation to Agent Trace / Sigstore / patatt
- [docs/LEVELS.md](docs/LEVELS.md) — the L1 / L2 / L3 assurance ladder

## License

Code is [Apache-2.0](LICENSE); the specification (everything under `spec/`) is
[CC-BY-4.0](LICENSE-SPEC). © 2026 Augusto Bastos.
