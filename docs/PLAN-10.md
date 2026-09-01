# SCPE — plan to reach 10/10 on design, future-proofness and structural readiness

**Version 3.** Revised after three adversarial review rounds and one measurement that turned a
criterion from aspiration into a requirement with evidence behind it.

**Scoring basis, deliberately narrow:** market adoption, demand validation and commercial
traction are **excluded**. Both prior reviews scored SCPE 3/10 and both got there the same
way — specification 8–9, market 1–2, latter dominates. That question is settled.

The question here is: **if every party in the world decided tomorrow to adopt SCPE, would the
design hold?** A 10 means no technical, structural or governance reason for it not to be the
thing everyone uses.

**Review history.** v1 was scored by two independent reviewers. One returned 10/10 by mapping
my phases onto my criteria — a consistency check on my own reasoning, rejected. Re-run against
the criteria themselves, it returned **6/10** with four specific insufficiencies. The other
returned **9–9.5** and named a structural ceiling: *the format cannot force honest rendering.*
Both sets of findings are incorporated below. Neither reviewer's number is treated as
authoritative; their arguments are.

---

## The twelve criteria

Two were added after review (11, 12). Four were rewritten because they were too weak to mean
what they claimed.

| # | Criterion | Today | Note |
|---|---|---|---|
| 1 | **Zero ambiguity across languages.** A duplicate key at any depth is refused by every conforming implementation, tested per target language. | ✗ | Rewritten |
| 2 | **Envelope independence**, demonstrated by identical facets through a DSSE and a COSE/SCITT binding. | ✗ | |
| 3 | **Algorithm independence.** Post-quantum implemented, not registered-and-refused. | ✗ | |
| 4 | **Trust-root independence.** SSH, Sigstore, X.509/KMS functioning; role separation independent of any one suite. | ✗ | 1 of 5 families |
| 5 | **Author independence.** Registered upstream, governed, URI that outlives the author, written fork policy. | ✗ | |
| 6 | **Honest ladder.** Every facet value reachable with a real file, **and every value whose reachability is structurally rare documented as such.** | ✗ | Rewritten |
| 7 | **Two-way interop** with drift caught by tests. | ✗ | |
| 8 | **No unaddressed threat solvable within the offline-first scope.** Threats solvable only with external infrastructure are acceptable **iff** normatively declared as such, and no weaker than contemporaneous standards. | ✗ | Rewritten twice |
| 9 | **Cheap to implement:** a minimal conforming verifier (REQUIRED fields, one suite, SHA-256) in ≤8 hours by a competent engineer with no prior SCPE knowledge. | ✗ | Rewritten with a threshold |
| 10 | **Graceful degradation.** Everything unknown fails closed and legible. | **✓** | |
| 11 | **Sidecar arrival strategies specified normatively**, following SLSA. Adoption is ecosystem-level and **the format carries no responsibility for it**, stated plainly. | ✗ | **New** |
| 12 | **Renderer conformance is testable**, and dishonest rendering is detectable. | ✗ | **New** |

**One of twelve is met.**

### Why criterion 1 was rewritten — measured, not argued

The specification requires refusing a duplicate JSON key at any nesting depth, because
identical bytes must yield identical verdicts everywhere. I measured what real parsers do with
`{"scpeVersion":"1","scpeVersion":"99"}`:

| Parser | Result |
|---|---|
| Python stdlib, default | **accepts**, last-wins → `"99"` |
| Go `encoding/json` | **accepts**, last-wins → `"99"` |
| Rust `serde_json` | **accepts**, last-wins → `"99"` |
| JavaScript `JSON.parse` | **accepts**, last-wins → `"99"` |
| Python + SCPE's explicit hook | rejects |

**Every standard library accepts what the specification says MUST be refused.** An implementer
who follows the spec faithfully, using their language's default parser, ships a non-conforming
verifier and never finds out.

The consequence is not theoretical. Corpus vector `signed-duplicate-key` is a **valid
signature** over a payload declaring both `digitalCapture` (a human took this photograph) and
`trainedAlgorithmicData` (a model generated it). A conforming verifier refuses it. A
naive-but-plausible verifier accepts it and reports one origin — and the signer chooses which,
by ordering the keys. One signed artifact, two truths, selected per reader.

"Two implementations agree" would not catch this if both authors reached for the default
parser. The criterion now requires the hostile case tested **per language**, and the corpus
carries the vector that does it.

---

## Phase 0 — Make the implementation match the specification

The spec defines five `anchor` values and the verifier emits two; four `attribution` values and
emits two; defines `time: externally-anchored` and `lineage: verified-depth-N` and emits
neither. `--chain` is a no-op. Each is a place where a faithful second implementer disagrees
with the reference.

- ~~Implement `bundled` (ceiling enforced) and `forge` (under §13.4 network rules, double
  opt-in).~~ **Done.** `forge` ports the retired implementation's SSRF invariant rather than
  re-deriving it: fixed provider→host table, charset-checked account as a single path
  segment, TLS and hostname validation on, redirects refused outright, final URL re-checked,
  and a double opt-in (`--forge` **and** `--allow-host`) that prints the host before
  connecting.
- ~~Implement chain resolution.~~ **Done.** Parent lookup, `statementDigest` pin check,
  cycle detection keyed on the signed-payload digest, bounded depth → `verified-depth-N` and
  `broken`. Verified: a substituted parent yields `broken`, and a self-anchored chain is
  capped at `declared`.
- **Still open — implement time anchoring** (RFC 3161 or OpenTimestamps) → `externally-anchored`.
  This is the one remaining Phase 0 item, and until it lands the facet is honestly
  unreachable rather than quietly absent.
- **Implement or delete. No third option.**

**Acceptance:** a script enumerates every enum value in the spec and asserts a vector produces
it. Nothing is specified that nothing can emit.

---

## Phase 1 — Envelope independence, demonstrated

DSSE is a Community Specification; SCITT (RFC 9943) and COSE Receipts (RFC 9942) are Standards
Track, published June 2026. A design welded to the non-RFC dies when the ecosystem moves.

- One envelope-neutral statement, two bindings: DSSE, and COSE_Sign1 with CWT claims.
- **Proof test:** one predicate, both bindings, identical facets, identical `proved[]`,
  identical `not_checked[]`. Envelope choice invisible above the signature layer.
- **Deployment migration, not only spec migration** (review finding): a verifier built for one
  binding must handle a record in the other — accept both, or refuse legibly with
  `unsupported-envelope`. Test the mixed-fleet case, not just interchangeability.

---

## Phase 2 — Real algorithm and trust-root agility

- **Implement `ml-dsa-44`.** PQ readiness that has never executed is not readiness.
- Implement the Sigstore bundle and X.509/KMS suites.
- **Fix role separation, which rides SSHSIG namespaces while three of five registered suites
  have none.** Bind the role inside the signed payload in a suite-independent way, with the
  SSHSIG namespace as one *binding* of that tag rather than the mechanism itself.
- **Suite strength signalling** (review finding): `signature: valid` currently reads identically
  for a current suite and a deprecated one. Express "valid, under a suite you should stop
  accepting" — computed by the verifier from its own policy, never asserted by the signer.
- Define `countersigner` or remove the role and its namespace.

---

## Phase 3 — Make the ladder reachable

- **C2PA importer** (isolated, optional, outside the stdlib core): read an Anthropic-signed
  C2PA image, verify against the trust list, record as an input edge → `provider-attested`
  reachable with a real file.
- **TEE receipt importer** → `tee-attested`.
- Enforce the importer boundary already stated in THREAT_MODEL TB-5: output enters as
  `declared[]`/`present-unverified`; failure is `tooling-error`; process isolation and limits.
- **Document structural rarity** (review finding): `verified-depth-N` requires parents to be
  locally available, and under universal adoption most will not be — different repo, different
  registry, deleted commit. `lineage: declared` is the de-facto ceiling for most artifacts.
  That is a correct consequence of offline-first and must be written down, not discovered.

---

## Phase 4 — Mechanical conformance and a second implementation

- **JSON Schema** for the predicate, generated from the same source that drives validation.
- **Corpus covers every normative MUST**, with a negative vector per fail-closed path and per
  anchor ceiling.
- **Per-language hostile-parser suite** (criterion 1): duplicate keys at every nesting depth, in
  every target language, as a first-class conformance gate rather than an edge case.
- **A language-agnostic conformance runner.**
- **A second implementation written from the specification alone**, in another language, by
  someone who has not read the Python. Every disagreement is a specification bug.
- **Measure and publish criterion 9:** hours and lines for that second implementation. If it
  takes three days, the spec is too complex — a finding, not an embarrassment.

---

## Phase 5 — Two-way interoperability

- **Import:** C2PA, Sigstore bundle, in-toto attestation, OMS `.sig`, OpenTimestamps.
- **Export:** SLSA VSA, OpenTelemetry GenAI spans, Agent Trace record, C2PA custom assertion.
- **Generate `docs/mapping/` from the same table that drives the adapters**, so an upstream
  release breaks a test rather than rotting a document.

---

## Phase 6 — Independence from the author, and from upstream

- **Stable, resolvable `predicateType` URI.** It currently points at a GitHub Pages site that
  does not exist. Publish it, and specify alias equivalence so the URI can migrate without
  invalidating signatures.
- **File the predicate upstream** (in-toto #244 is the natural home).
- **Written fork policy** (review finding): if upstream accepts the predicate but substantially
  changes the schema, does SCPE follow or diverge? Which upstream changes force a version bump?
  Undefined today, and undefined is the wrong answer under universal adoption.
- **Governance:** change process, and what happens if the author stops.
- **Corpus maintenance at scale** (review finding): who maintains the vectors once they are part
  of the standard, and how does a breaking change get tested across every implementation at once?

---

## Phase 7 — Close every threat with a known answer

- **KRL revocation — with the scale problem addressed, not merely adopted** (review finding).
  `ssh-keygen -Y verify` accepts `-r`, but a KRL grows monotonically and an offline verifier
  cannot tell whether its copy is current. Either specify KRL discovery and staleness detection,
  or state normatively that **revocation is time-anchored-only** and stop implying otherwise.
  Adopting the flag without answering distribution is worse than not adopting it, because it
  would look solved. Note honestly which of these is happening: declaring the boundary is
  **accepting** the threat within a stated scope, not solving it, and criterion 8 is worded to
  permit that only when the declaration is normative and no weaker than what other standards
  offer.
- **A transparency receipt over the earliest statement** — the known answer to both chain
  truncation and fork/equivocation, currently listed as undefended.
- **Make key rotation function:** `valid-after`/`valid-before` are inert without a time anchor;
  Phase 0 makes them live.
- **Anchor freshness in the result:** which anchor answered, its digest, **and when it was last
  modified** — observation only, never a facet input.
- **Ecosystem-failure recovery** (review finding): when a transparency service dies, records
  that were `externally-anchored` become uncheckable. The facet must **drop to `unanchored`**,
  not fail closed — the honest statement is "I could not check this today", and failing closed
  would let a dead third party retroactively invalidate valid history. Specify this for every
  facet whose evidence can become unreachable.

---

## Phase 8 — Sidecar arrival, and detectable rendering

The two criteria added by review. Both concern what happens when the design meets the world
rather than a test suite.

### 8a — Sidecar arrival (criterion 11)

§7 specifies how to *find* a sidecar and says nothing about how it *gets there*. Stripping is
correctly named unsolvable; **arrival is not addressed at all**, and under universal adoption a
format whose records never travel with their artifacts is correct and absent.

- Specify distribution strategies as SLSA does: registry sidecars, OCI referrers, release
  attachment, CDN placement, archive conventions.
- Specify immutability and bind-to-artifact-not-release, following SLSA's published guidance
  rather than inventing.
- State plainly that this is convention, not enforcement — and go further: **SCPE MUST NOT
  claim responsibility for sidecar arrival, nor imply that specifying a convention causes it.**
  SLSA's distributing-provenance section is also convention-based and observably does not
  propagate at scale. Specifying the strategy and owning the outcome are different things, and
  conflating them would be the same overclaim this project refuses everywhere else.

### 8b — Detectable rendering (criterion 12)

The ceiling one reviewer named: *the format cannot force honest rendering.* True — and true of
every format ever made. TLS cannot stop a browser lying about the padlock; C2PA is worse here,
shipping a visual badge with no `not_checked[]` equivalent.

But the ceiling is narrower than "unsolvable." The question is not whether a renderer **can** be
dishonest. It is whether dishonesty is **detectable**. Today it is not: a renderer showing
`status: ok` and a model name beside a tick produces output nobody can mechanically distinguish
from an honest one.

**The signed verification receipt.** The verifier signs its own result — facets, `proved[]`,
`declared[]`, `not_checked[]`, bound to the subject digest and the anchor that answered. SLSA's
VSA already has this shape (`verifier`, `timeVerified`, `policy` as uri+digest,
`inputAttestations`, verdict); it moves from Phase 5 interop into the core.

What changes:
- A renderer's output becomes checkable against a signed artifact. Omitting `not_checked[]`
  while showing a tick is a mechanical discrepancy, not an editorial judgement.
- `not_checked[]` becomes signed content: dropping it leaves a trace.
- Auditing works without trusting the renderer — re-run a conforming verifier and diff.

**This is detection, not prevention, and the plan claims nothing more.** Prevention is not
available to anyone.

**The cost, stated rather than buried.** Signing the result gives the *verifier* a key, and key
management is exactly what this design has avoided. Review called this "a philosophical
reversal, not a trade" and it is right to: the verifier's key becomes a new element of the
trusted computing base, and a compromised one emits a signed receipt that looks honest. So the
receipt ships **only** under four conditions, all normative:

1. **The verifier's signing key is operator-supplied, never auto-generated.** An auto-generated
   key has no home, no rotation story and no revocation path. The operator must know they are
   signing and accept that.
2. **It is completely separate from the artifact-verification policy** — different file,
   different threat model, no mixing. An operator who does not want to sign results simply does
   not supply the key, and the receipt is not emitted.
3. **Receipt emission is OPTIONAL and its absence is not a failure.** A verifier that cannot
   sign still verifies; it just cannot make its output independently checkable.
4. **THREAT_MODEL gains TB-8: Verifier → signing key**, covering compromise, custody, rotation
   and what a receipt does and does not attest — namely that *a verifier computed this result*,
   never that the result is true.

**Renderer conformance must be mechanical, not aspirational.** "These presentations conform" is
worthless without a definition, and review is right that questions like field order and colour
have no principled answer. So the corpus tests exactly one property and says so: **does the
presentation omit or contradict a field that the signed receipt contains?** Layout, ordering,
styling and abbreviation are explicitly out of scope. A conforming renderer MUST pass those
vectors, or MUST declare which it does not satisfy.

- Ship a **reference renderer** (CLI, JSON, HTML) with the verifier.
- Ship the **renderer conformance corpus** as normative, versioned spec text — not examples.

---

## Structural ceilings — named, not solved

A 10 requires no *unaddressed solvable* gap. It does not require omniscience. These are
permanent and belong in the specification's own text:

1. **Sidecar stripping.** A removed record is indistinguishable from one that never existed.
2. **Monotonicity.** "This is not AI-generated" is inexpressible, permanently, by inheritance.
3. **Self-assertion is the floor.** Most records will read `self-asserted` for years. Phase 3
   makes the upper rungs reachable; it does not make them common.
4. **A dishonest producer, and a compromised producer environment.** SCPE records what a key
   signed; it cannot know what persuaded the key to sign.
5. **Rendering cannot be prevented, only made detectable.** Phase 8b closes the detection gap;
   the prevention gap stays open for every format, forever.

---

## The question for reviewers

Does completing Phases 0–8 produce a **10/10 on intrinsic quality, future-proofness and
structural readiness for universal adoption**, with market adoption excluded?

If not: name the criterion that still fails and what satisfies it. If a criterion is still too
weak to mean what it claims, rewrite it. If the ceiling is below 10 for a reason no plan fixes,
name it precisely — that answer is worth more than a generous score.
