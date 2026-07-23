# SCPE governance

How the protocol changes, and how it stays trustworthy while it does. `scpe/0.1` today has one
author and no external implementers, so most of this document describes the process the project
commits to running as soon as there is more than one — not a process already exercised by outside
contributors. Read it as a contract for the future, not a report of the past.

The one thing that must survive any governance model: **a verifier that has never heard of a new
registry entry must keep failing safe against it, not guess.** Every extension mechanism below
exists because SPEC.md already made unknown values harmless (`unsupported-provider`,
`present-unverified`, `unsupported-subject`, surfaced-but-ignored profiles). Governance's job is to
keep exercising that property, not to invent a new one.

## 1. Where authority lives today

- The spec (`spec/SPEC.md`), threat model (`spec/THREAT_MODEL.md`), and the eighteen normative
  test vectors (`spec/test-vectors/`) are the source of truth, in that order: the prose in SPEC.md
  governs, the reference verifier (`reference/standalone/verify_envelope.py`) implements it, and
  the vectors are the executable contract between them. If an implementation and SPEC.md disagree,
  SPEC.md wins and the implementation is a bug.
- Until the repository is public, changes land by the author's own review against this document —
  there is no outside maintainer team yet. That will change; §4 describes the process that takes
  over once it does.
- CC BY 4.0 covers the spec text itself (`spec/`); this means anyone can fork, adapt, or propose
  changes to the *document* without asking permission. It says nothing about who controls the
  `scpe/<MAJOR>.<MINOR>` name and registries below — that governance is what this document defines.

## 2. How something new gets reserved and registered

SPEC.md has six closed or semi-closed extension points. Each has a different bar, because each
carries a different amount of risk if the fail-safe fallback is ever wrong. "Reserve" and
"register" are deliberately two different steps everywhere except profiles:

- **Reserve** — name the enum value in SPEC.md and (if relevant) `docs/ROADMAP.md`, so the identifier
  exists and every conforming verifier already returns its documented safe status for it
  (`unsupported-provider`, `present-unverified`, or `unsupported-subject`, depending on the
  registry). No verifier code changes. This step is low-risk by construction: it cannot turn a
  `verified` into anything else, because nothing yet claims to implement the reserved value.
- **Implement** — a reference implementation (producer + verifier) actually resolves/verifies the
  new value, plus new normative test vectors are added under `spec/test-vectors/` that exercise
  both the new success path and that older verifiers still fail safe against it.

| Registry | Reserve | Implement |
|---|---|---|
| **Provider** (`contributor.identity.provider`, SPEC §8/§11.1) | Add the enum name to the §8 table and note it in ROADMAP §1. Must state whether it needs a host mapping (forge-style, like `github`/`gitlab`/`codeberg`) or a different resolution mechanism entirely (like `oidc`), and if a host, that the host is **fixed in the table, never taken from the manifest** — the SSRF invariant is non-negotiable for any new provider, forge or not. | Implement key resolution against real accounts of that kind, add vectors covering a valid signer, a wrong key, and (for a host-based provider) a redirect/host-confusion attempt matching the existing SSRF tests. |
| **Subject type** (`subject.type`, SPEC §6) | Name the type and describe its integrity anchor (what gets hashed, what normalization if any — `code-change`'s LF-normalized diff and `artifact`'s raw-byte digest are the two precedents). This is the highest-bar registry: a bad integrity anchor is a `tampered`/`verified` inversion, not a cosmetic error. | Implement the dispatch branch in the verifier, and vectors covering a match, a tamper, and (if the subject can appear with no payload, as `artifact` can in PR transport) the no-payload case, which must stay `tampered`, never `verified`. |
| **Attestation type** (`attestations[].type`, SPEC §5.1) | Name the type. Lowest structural risk of the three "verification-adjacent" registries, because an attestation's status is never part of the `verified`/`tampered` verdict (§5.3) — worst case a reservation is wrong is a wrong `present-unverified` label, not a wrong verdict. | Implement parsing/surfacing for the type; add a vector with that entry present alongside a normal `verified` subject, confirming the per-entry status and that it does not affect the overall verdict. |
| **`agent-trace` format** (`attestations[].format` when `type: agent-trace`, SPEC §5.2) | Name the format id. Same low structural risk as attestation types — it only changes a `present-<format>` string. | Implement the format's `data` shape; add a vector showing `present-<format>` instead of `present-unverified`. |
| **Profile** (`profile`, SPEC §13.1) | Naming *is* registering — there is no separate "reserve" step. A profile is documentation of a convention (which `subject.type`, which `media_type`, which attestations are conventional) and, by §13.2, changes **no** verification logic. Adding one is a spec-text edit: add a row to the §13.1 table. No reference-verifier change, no new vectors required (the verifier already surfaces any profile string, known or not). | — (reservation and implementation are the same step) |
| **Status code** (SPEC §8) | Not open for casual extension. The eight-code set (`unattested`, `unsupported-version`, `unsupported-provider`, `unsupported-subject`, `identity-unverifiable`, `signature-invalid`, `tampered`, `verified`) is closed by design — every failure mode in the verification algorithm already maps to exactly one of them. A new code is a MAJOR-level spec change (§3) requiring its own proposal that shows the existing eight cannot express the new failure mode; it is not something a provider/subject/attestation addition should ever need. | — |

The provider and subject-type rows are the ones to read twice: they are the only two places a
badly-specified addition could turn a `tampered` diff into a `verified` one. Everything in the
attestation/format/profile rows is, by construction (§5.3, §13.2), incapable of changing a verdict
— which is exactly why their bar is lower.

## 3. Versioning and backward compatibility (SPEC §11)

`spec_version` is `scpe/<MAJOR>.<MINOR>`. The rule from SPEC §11 is the whole policy:

> Verifiers MUST accept an unknown MINOR of a known MAJOR (new optional fields may appear; unknown
> fields are ignored). Verifiers MUST reject an unknown MAJOR with `unsupported-version`.

That single sentence is only safe because of the fail-closed property already built into every
registry in §2. A MINOR bump is allowed to add anything a verifier that has *never seen it* already
handles safely without being told about it in advance:

**Safe as a MINOR (`scpe/0.x` → `scpe/0.x+1`):**
- A new optional `manifest.json` field (an old verifier ignores unknown fields).
- A newly *implemented* provider, subject type, attestation type, or `agent-trace` format — safe
  specifically because an old verifier that doesn't implement it already has a defined, tested
  fallback (`unsupported-provider`, `unsupported-subject`, `present-unverified`) rather than a
  crash or a false `verified`.
- A new profile label (§13.1) — never touches verification at all.
- Clarifying prose in SPEC.md that does not change any verifier's observable behavior.

**Requires a MAJOR (`scpe/0` → `scpe/1`, or later `scpe/N` → `scpe/N+1`):**
- Any change to how the integrity anchor is computed for an *existing* subject type — the diff
  normalization rule in §6.1, or the raw-byte digest rule in §6.2. An old verifier would compute a
  different hash and silently reject something the new producer considers correct (or worse, the
  reverse), which is a compatibility break dressed as a bug.
- Any change to the signing namespace (`scpe/0.1` in `ssh-keygen -Y sign -n ...`) or to the
  verification algorithm's step order in §8. The namespace is part of what the signature covers;
  changing it invalidates old signatures by design, which is exactly the MAJOR-level "on purpose"
  case.
- Removing a field, narrowing a previously-accepted value (e.g. tightening the safe-subject regex
  in a way that rejects previously-valid subjects), or repurposing an existing status code's
  meaning.
- Adding a new top-level status code (§2's status-code row) — the closed eight-code set is a
  contract every caller of a verifier already switches on; adding a ninth changes what "exhaustive"
  means for existing integrations.
- Any change where an *old* verifier, given a *new*-format envelope, would produce `verified` when
  it should not. This is the one invariant that overrides all the others: MINOR-safety is defined
  by what old verifiers do when they *don't* recognize something new, and the one unacceptable
  outcome is a false `verified`.

The test rule, in one line: **if a proposed change requires editing the expected status of an
existing vector under `spec/test-vectors/`, it is a MAJOR change.** If it only requires adding new
vectors while every existing vector's name and expected status stays identical, it is at most a
MINOR.

## 4. RFC-style change process

Once the repository has outside implementers, a change to SPEC.md, THREAT_MODEL.md, or a registry
follows this shape (adapted from the norm-setting style SPEC.md already uses — RFC 2119 keywords,
a single normative document, an executable test contract):

1. **Proposal.** A written amendment against `spec/SPEC.md`: the exact prose diff, which registry
   (if any) it touches from the §2 table, and — this is the part that is not optional — an explicit
   statement of which §3 bucket it falls into (MINOR or MAJOR) and why. A proposal that reserves a
   new provider or subject type MUST also walk through the SSRF invariant (SPEC §8) or the
   integrity-anchor question (§6) explicitly, even if the answer is "not applicable."
2. **Threat-model pass.** Any change that widens what the verifier trusts, fetches, or executes
   (a new provider's key source, a new subject's integrity check) MUST come with a
   `spec/THREAT_MODEL.md` update in the same proposal — not as a follow-up. A registry addition
   that cannot state its new residual risk in THREAT_MODEL §2/§3 terms is not ready to reserve, let
   alone implement.
3. **Vectors before merge.** Per SPEC Appendix A, the test vectors under `spec/test-vectors/` are
   normative, not illustrative — "an implementation that produces the expected status for all
   [vectors] conforms to §8." An "implement" step (§2 above) is not accepted without new vectors
   demonstrating both the new success path and that the fail-safe default still holds for verifiers
   that don't know about the change yet. A "reserve"-only step needs no new vectors, since by
   definition nothing new is being verified.
4. **Reference implementation follows the spec, not the reverse.** SPEC.md is edited first;
   `reference/producer.py` and `reference/standalone/verify_envelope.py` are then brought into line.
   A patch that changes the reference implementation's behavior without a corresponding SPEC.md
   edit is a bug fix, not a protocol change, and should say so.
5. **A second independent implementation is the strongest signal a proposal is ready**, not a
   requirement to open one. `scpe/0.1`'s own extension points were sized around "abstract at the
   second concrete case, not the first" (`docs/ROADMAP.md`); the same discipline applies to
   registry entries. A provider or subject-type addition that only one implementation has ever
   exercised is weaker evidence than one that a second, independently-written verifier (for example
   a non-Python one) also gets right against the same vectors.
6. **Discussion venue.** While the repository is private, proposals are author-reviewed against
   this document. Once public, the venue is the repository's issue tracker — GitHub Issues/
   Discussions on whatever repo hosts SPEC.md at the time — and this section should be updated to
   name it explicitly rather than left as a placeholder. This document does not currently claim a
   process exists that hasn't run yet.

## 5. Registry section

Current state of every named registry in `scpe/0.1`. This table is a convenience index; SPEC.md is
the normative source and wins on any conflict.

| Registry | Implemented | Reserved (format-only) | Open (unclaimed) |
|---|---|---|---|
| Provider (§8, §11.1) | `github`, `gitlab`, `codeberg`, `local` | `oidc`/sigstore, `x509`, `ldap` (ROADMAP §1) | anything else |
| Subject type (§6, §6.3) | `code-change`, `artifact` | none named yet | anything else — no subject type is currently reserved-but-unimplemented; a new kind starts at "propose" |
| Attestation type (§5.1) | `agent-trace` | `timestamp`, `countersignature` (ROADMAP §2, §3) | anything else |
| `agent-trace` format (§5.2) | `agent-trace/1`, `git-ai/notes`, `generic/1` | none | anything else |
| Profile (§13.1) | `SCPE-C`, `SCPE-I`, `SCPE-V`, `SCPE-A`, `SCPE-M`, `SCPE-DATA`, `SCPE-D`, `SCPE-AR` | — (profiles have no reserved-but-unimplemented state; see §2) | anything else |
| Status code (§8) | `unattested`, `unsupported-version`, `unsupported-provider`, `unsupported-subject`, `identity-unverifiable`, `signature-invalid`, `tampered`, `verified` | — | closed; see §2 |

Note on `countersignature`: SPEC §5.1 already flags that this reservation names a *concept*, not a
mechanism — a signature over the manifest cannot be a field of the manifest it signs, so the real
form (a detached co-signature, ROADMAP §3) is still a design question, not just an implementation
one. Its governance path is a full proposal, not a routine "implement" step.
