# ADR 0001 — From pull requests to generation events

**Status:** Accepted
**Date:** 2026-09-01
**Supersedes:** the positioning in [../ROADMAP.md](../ROADMAP.md) §4 (see "The objection
this project raised against itself", below)
**Evidence base:** [../standards-landscape.md](../standards-landscape.md)

---

## Summary

SCPE stops being an envelope format for pull-request contributions and becomes **an in-toto
predicate type for generation events, carried in a DSSE envelope, stored as a detached
sidecar, read by a verifier whose product is saying precisely what the signature established
and what it did not.**

The acronym is re-expanded: **Signed Content Provenance Evidence**. "Contribution" and
"Envelope" both describe things this project is no longer doing.

---

## Context

### What the project was

`scpe/0.1` is a signed `manifest.json` plus a detached SSHSIG `manifest.sig`, carried either
as a standalone zip or as a base64 block in a pull-request body, verified by a stdlib-only
Python verifier with Go and Rust ports. Its subject union is `code-change | artifact`. Its
strongest properties, confirmed by audit, are the exact-bytes signing rule (no
canonicalization), fail-closed dispatch on every unknown input, and `key_source` — a
disclosure of *which trust anchor answered*, which is the one genuinely original idea in the
repository.

Its README already records the outcome honestly: *"This project is frozen, has zero
adopters, and the argument it was built on did not survive contact with the maintainers it
was built for."*

### What the research found

The redesign brief proposed repositioning SCPE as "a file-agnostic, cryptographically
verifiable provenance envelope for AI-generated artifacts." Testing that thesis clause by
clause against primary sources ([standards-landscape.md](../standards-landscape.md) §12)
returned an uncomfortable result: **five of six headline clauses are already shipped by
incumbents.**

The decisive fact is dated. `c2pa-rs` CLI **0.26.46, released 08 April 2026**: *"Allow any
file type to be signed with a sidecar"* (PR #2014), confirmed in the SDK source, not only
the changelog. The brief's headline differentiator shipped in the reference implementation
of the dominant standard roughly five months before the brief was written. Alongside it:
in-toto has bound subjects purely by digest "regardless of content type" since v1; OpenSSF
Model Signing v1.0 already ships a detached, offline-verifiable, file-agnostic `.sig`
sidecar for AI artifacts; `gh attestation verify --bundle --custom-trusted-root` is a
shipped product feature for air-gapped verification; and "not an AI detector" is the
incumbents' published position, stated better than we would state it (§11).

**"File-agnostic provenance envelope" is not a differentiator in 2026. It is table stakes,
and building a fourth envelope is negative value.**

### What survived

Three seams, and they only matter together:

1. **Generation-event semantics.** No registered predicate anywhere says *"model M, version
   V, provider P produced these bytes."* SLSA's `builder.id` models a build platform. OMS
   models the model as the **subject** — a signed weights file — never as the **agent** of
   another artifact's creation. That inversion is the gap.
2. **Typed derivation over arbitrary bytes, asserted by someone who is not the generator.**
   C2PA has the field's best signed derivation graph and it works only inside C2PA, behind a
   conformance-gated CA, in a certified fleet where 166 of 174 products are still on spec
   2.2 and exactly one declares ML formats. SCITT has multi-issuer statements and no edges
   at all. in-toto's `resolvedDependencies` is explicitly *unordered* and cannot distinguish
   "B was produced FROM A" from "A was present." PROV-O, OpenLineage and MLflow have the
   right graph shape and zero cryptography.
3. **The assurance reading layer.** Nothing in the field renders "here is precisely what
   this signature did and did not establish" as a closed, computed, per-facet disclosure.
   `cosign` says PASS/FAIL against a policy you supplied. `gh attestation verify` says
   verified. C2PA says Well-formed / Valid / Trusted — closest, and still one axis. The
   overwhelmingly common real case is *"identity X signed a statement saying model M made
   these bytes, and M signed nothing"* — a notarized claim about a third party — and no
   verifier in the field says that out loud.

### Why now, and not later

The slot has a queue, and the queue formed this year:

| in-toto issue | Opened | Last activity |
|---|---|---|
| **#244** "Attestation for AI-assisted code" — *this project's exact premise* | 2023-06-03 | **2023-07-10** |
| #554 "RFC: agent-decision/v0.1" | 2026-05-19 | no maintainer response |
| #565 / #575 eval-result | 2026-07-03 / 07-23 | open |
| #588 "AI Agent Action predicate v0.1" | 2026-08-19 | 2026-08-30 |
| #591 "AI Agent Decision predicate" | 2026-08-29 | open |

Five AI predicates in four months, none merged, against an issue that asked the question
three years ago and was never answered. That is simultaneously evidence that the slot is the
right one and evidence that it is closing.

Two more datapoints establish demand rather than assuming it. **Agent Trace 0.1.0** — backed
by Cursor, Cognition, Cloudflare, Vercel, git-ai, Google Jules, Amp and OpenCode — holds the
vocabulary half of this problem and **explicitly declines the cryptographic half**; git-ai's
own README says it "does not use AI or heuristics to 'detect' AI code — the Agents report
exactly which lines they wrote." And on **16 April 2026** VS Code enabled the
`Co-authored-by: Copilot` trailer by default, then **reverted it** after it attached to
commits made without Copilot, including installs with AI features disabled. A documented
false-attribution incident on the dominant unsigned mechanism is the strongest empirical
argument for signed rather than conventional attribution that exists.

---

## Decision

**1. SCPE is a predicate, not a format.** An in-toto Statement v1 (`_type`, `subject[]`,
`predicateType`, `predicate`) carried in a DSSE envelope. SCPE writes no envelope, no
canonicalization, no signature construction, no transparency log, no PKI, and no AI-origin
enum.

**2. The predicate describes a generation event, not generic provenance.** Generic artifact
provenance competes with in-toto and C2PA and loses. *"This model, at this version, from
this provider, produced these bytes, and here is what it was derived from"* competes with
nothing, because nobody has registered it.

**3. Derivation edges are typed and first class inside the predicate,** reusing C2PA's
relation words (`parentOf` / `componentOf` / `inputTo`) rather than minting a fourth
vocabulary, and referencing prior artifacts as in-toto `ResourceDescriptor`s so the digest
joins work with existing tooling.

**4. The verifier's output is the product.** `key_source` generalises into a closed set of
computed assurance facets. Every input to a facet must be an observation the verifier made;
a self-declared field may only lower a class, never raise it; and no status may imply a
check that did not run.

**5. Nothing that a signature cannot support is ever asserted.** Adopted structurally, not
rhetorically: a `declared[]` array carries what the signer said, a `proved[]` array carries
what the verifier checked, and `not_checked` is a required, non-empty field on every result
that reached a pass.

**6. Git, GitHub and pull requests become an optional integration** with no presence in the
core, the spec, or the verifier.

### What is deleted

- The `scpe/0.1` envelope: `manifest.json` schema, `manifest.sig`, the zip container, the
  attestation-in-PR-body transport, and the serialization rules that fed them.
- `action.yml` and the GitHub Action, `scpe seal`, the merge-gate logic in
  `scpe/results.py`, `context.py`, `diffinfo.py`, `testrun.py`, `optin.py`.
- The `code-change` subject type and diff normalization.
- The eight profiles (`SCPE-C/I/V/A/M/DATA/D/AR`) as spec-level constructs.
- The Go and Rust envelope-verifier ports in their current form — they port a format that
  will no longer exist. (The audit measured a 4.2x port-drift multiplier and found three
  implementations returning **different statuses for identical bytes**; deleting the format
  deletes the drift.)

### What is kept, and why it survives better

- **Exact-bytes signing** becomes DSSE PAE. Same rule, someone else's specification,
  verify-before-parse enforced by a document with third-party test vectors. This is
  *continuity*: [design-decisions.md §2](../design-decisions.md) already cites JWS and DSSE
  as the model for rejecting canonicalization.
- **Fail-closed dispatch** becomes: refuse an unknown `predicateType`; degrade unknown
  evidence to `present-unverified`; ignore unrecognised digest algorithms.
- **`key_source`** becomes the assurance facet set — promoted from an implementation detail
  to the product.
- **SSHSIG and `allowed_signers`** survive as one registered signature scheme among several.
  Wrapping SSHSIG in DSSE repairs it: of its five known deficiencies as a wire format (no
  content type, no multi-signature, no receipt slot, no post-quantum path, one
  implementation), four are *envelope* deficiencies that DSSE fixes outright, and the fifth
  stops being load-bearing once SSHSIG is one option rather than the only one. Augusto keeps
  `ssh-keygen` and the best offline human-editable trust policy in the field, and gains
  cosign/Sigstore/X.509 interoperability.

---

## The objection this project raised against itself

[ROADMAP.md §4](../ROADMAP.md) contains the strongest argument against this ADR, written by
this project's own maintainer:

> *"Selling the universality first destroys the one thing that makes a protocol adoptable: a
> clear problem it solves. So the positioning is code-first; the format is domain-neutral."*

**That argument was correct, and this ADR does not overturn it — it satisfies it.**

The objection is against selling universality. It is not against changing which specific
problem you lead with. The old answer to "a clear problem it solves" was *"an unreviewed AI
contribution arrived in my pull request."* That answer was tested and failed: the README
records OpenSSL replying "Obviously not and we don't enforce it" and MicroPython replying
"Most authors quickly correct when reminded by a human, less so when CI is showing ❌." The
buyer said no.

The new answer is not "SCPE for everything." It is equally specific and narrower in the
dimension that matters: *"a file arrived and I cannot tell what produced it."* File-agnostic
is a property of the mechanism, exactly as it already was — the ROADMAP's own words are "the
core stayed artifact-agnostic, and the domains arrived as labels." What changes is **which
single problem leads**, and it changes because the old one was empirically rejected by the
people it was built for, while the new one has five competing proposals filed against it in
four months and a documented false-attribution incident driving demand.

A second, subtler line in the same section is now obsolete rather than wrong. ROADMAP §4
says artifact verification is "standalone-only, because the PR transport carries a diff, not
an arbitrary artifact payload." Once the PR transport is deleted, the constraint that
produced that limit is gone with it.

---

## Consequences

### Accepted costs

- **We give up control of the envelope,** and inherit DSSE's refusals: no algorithm
  identifier, no timestamp, no expiry, no revocation, no verification-material carriage. The
  first is mitigated by carrying the signature suite *inside the signed payload* and
  checking it against a verifier allowlist (RFC 8725 §3.1). The rest are addressed by
  optional outer carriage (a Sigstore Bundle, an OpenTimestamps `.ots`, a SCITT receipt),
  each recorded as evidence rather than trusted.
- **The Standards-Track lane is foreclosed today.** DSSE is a Community Specification, not
  an RFC, while RFC 9943 (SCITT) and RFC 9942 (COSE Receipts) are Standards Track and
  published June 2026. This is reclaimable without a break: the predicate is
  envelope-independent, so a COSE_Sign1/SCITT profile carrying the identical statement is
  additive, not a migration.
- **Monotonicity is inherited permanently.** in-toto's monotonic-policy principle means SCPE
  can never express "this file is *not* AI-generated" or "nothing else happened to it."
  This is correct for our ethics and it is not revisitable later.
- **Sidecar stripping has no answer, and we say so.** Every design surveyed binds provenance
  to bytes it cannot make the bytes carry. A stripped sidecar is indistinguishable from a
  file that never had one. The only known mitigations are watermarking and fingerprinting,
  which work for perceptual media only and require a hosted repository.
- **Breaking change with no migration path for envelopes.** Justified by evidence, not
  assumption: zero PyPI adopters, no external repository consuming the format, and the
  project's own README describing itself as frozen. If evidence of a real consumer surfaces,
  this ADR is wrong about the cost and a compatibility path must be added.
- **Demand is still a hypothesis.** It is better-evidenced than the previous one (five
  competing filings, a coalition that declines the crypto half, a documented reverted
  attribution default) but it has not been validated with named readers. See the gate below.

### The validation gate — running in parallel, not blocking

A one-page repositioning note goes to readers who verify provenance today — `c2patool`
maintainers, OMS maintainers, in-toto #244, a C2PA validator implementer, and someone
shipping Sigstore-signed non-code artifacts — asking one question: *do you know which trust
anchor answered when you verify?*

It runs **in parallel with implementation, not before it**, and the reason is the
postmortem. The previous attempt sent an argument without an implementation and the argument
did not survive contact. Sending another argument without code repeats the error. A
registered predicate that `cosign` verifies today, with conformance vectors, is a different
conversation.

### Pre-registered falsification test

Checked into the repository so anyone can run it. **If any of these becomes true, this ADR
is wrong and the project should be archived or folded upstream:**

1. `c2patool` gains a `--mime` flag (or equivalent) making arbitrary-file sidecar signing a
   one-liner from the CLI, **and** the CLI reports which trust anchor answered.
2. The C2PA Conformance Program opens an OIDC-derived or otherwise free path to a
   trust-listed claim-signing certificate for an individual developer.
3. in-toto merges an AI-generation predicate covering model, version and provider before
   this one is filed.
4. Agent Trace adds a signature field to its 0.1.x line.
5. A frontier provider begins signing text output in a way third parties can verify offline.

Item 3 is the live one. Items 4 and 5 would not falsify the predicate so much as make it
easy — they would move the assurance ladder's top rungs from dark to reachable, which is the
outcome this design is built to absorb.

---

## Rejected alternatives

**Keep the SCPE envelope and interoperate through adapters.** Scored last of five on
longevity and second-to-last on differentiation in the architecture panel. Its two
load-bearing arguments do not survive: DSSE does *not* cost multi-signature (`signatures[]`
is an array; the one-signature rule belongs to the optional Sigstore Bundle wrapper), and
key pinning *is* expressible inside the signed payload without violating DSSE's prohibition
on trusting `keyid`. Its export path discards the signature entirely, making interop a
permanent one-way adapter. Post-quantum migration is written into its own roadmap as a MAJOR
bump old verifiers refuse — a format break by design, repeated for every new trust root.

**Become a C2PA profile.** The best answer in the field to provider-signed generation — it
reads Anthropic's C2PA-signed output today and gets stronger as more providers sign. Rejected
as the primary identity because its reason to exist is contingent on two other organisations'
inaction: a one-line MIME-table patch in `c2pa-rs`, or a developer tier in the Conformance
Program, erases it. **Retained as a bridge**, not as the foundation: reading a real
Anthropic-signed C2PA image as an input edge is the day-one demonstration, and it is the only
concrete path that makes the assurance ladder's upper rungs reachable with real files today.

**Dissolve the protocol.** Scored 7.5 on honesty — no judge dismissed it as capitulation.
Rejected because its shipped artifact is a reader for five other stacks, its own upstream
contributions are designed to delete its reason to exist, and it discards the stdlib-only
property that is the most checkable claim this project has. **Its findings are absorbed
rather than shipped separately:** derivation belongs in a predicate; chain completeness is
structurally unfillable; sidecar discovery is a registry note that should be filed upstream
rather than claimed as a contribution; and `not_checked` must be a required field.

**Build the agent-run protocol as the primary design.** Won the cryptographic-soundness axis
outright with the panel's highest single score, and its mechanisms are grafted wholesale (the
signed algorithm identifier with a verifier allowlist, verifier-recomputed assurance with a
fail-closed `assurance-overclaimed` status, the observation axis, multi-signature roles
declared inside the signed payload). Rejected as the *primary* frame for two structural
reasons: its flagship two-signature configuration can never be packaged as a Sigstore Bundle,
so the strong mode gets no free tooling while the weak mode does; and in-toto #588 already
occupies the gateway-observed hash-chain position from a stronger vantage point. Run
semantics are retained as **optional** predicate annotations, never required fields.
