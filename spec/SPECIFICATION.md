# SCPE — Signed Content Provenance Evidence

**Specification version:** `scpe/1` · **Status:** draft · **Date:** 2026-09-01
**License:** CC BY 4.0

> This document defines the protocol. It is normative.
> The README markets; this specification decides. Where they disagree, this wins.
> Rationale lives in [../docs/adr/0001](../docs/adr/0001-from-pull-requests-to-generation-events.md);
> evidence lives in [../docs/standards-landscape.md](../docs/standards-landscape.md);
> the security boundary lives in [THREAT_MODEL.md](THREAT_MODEL.md).

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY** and **OPTIONAL** are to be interpreted as described
in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all
capitals.

---

## 1. Scope and definition

**SCPE is an in-toto predicate type describing a generation event over an artifact
identified by digest, carried in a DSSE envelope, stored as a detached sidecar, and read by
a verifier that reports which facts the signature established and which it did not.**

### 1.1 What SCPE defines

SCPE defines exactly four things:

1. A predicate schema (§5) describing **what produced these bytes**.
2. A derivation model (§6) describing **what these bytes came from**.
3. A sidecar discovery rule (§7) describing **where to find the record given a file**.
4. A verification algorithm (§9) and an assurance model (§10) describing **what a result
   means and, explicitly, what it does not**.

### 1.2 What SCPE does not define, and MUST NOT

SCPE **MUST NOT** define, and this specification contains no normative text for:

| Concern | Owner |
|---|---|
| Signing envelope, pre-authentication encoding, serialization | DSSE v1.0.2 |
| Subject binding, artifact references, digest registry, bundling | in-toto Attestation v1 |
| Cryptographic primitives and signature algorithms | the registered suites (§8) |
| Key management, PKI, certificate issuance, keyless identity | Sigstore, X.509, OpenSSH |
| Transparency logs, receipts, Merkle proofs | RFC 9942, RFC 9943, Rekor |
| Timestamping | RFC 3161, OpenTimestamps |
| AI-origin taxonomy | IPTC DigitalSourceType, C2PA |
| Derivation relation words | C2PA `c2pa.ingredient.v3` |
| Model, provider, agent and workflow attribute names | OpenTelemetry GenAI semantic conventions |
| Agent and workload identifiers | SPIFFE, WIMSE, OAuth |
| Build and CI provenance | SLSA |
| Model-weight integrity | OpenSSF Model Signing |
| Line-range code attribution and its rebase survival | Agent Trace, git-ai |
| Watermarking, fingerprinting, soft bindings | C2PA soft bindings, Adobe TrustMark |

An implementation that invents any of the above is not conforming.

### 1.3 What SCPE cannot do

Stated here, in normative text and not only in marketing copy, because §12 depends on it:

- SCPE **cannot detect** AI-generated content. It records a signer's assertion. Its truth
  rests entirely on the signer's honesty.
- SCPE **cannot express a negative claim.** It inherits in-toto's monotonic-policy
  principle: attestations only add. "This file is not AI-generated" and "nothing else
  happened to it" are structurally inexpressible, permanently.
- **Absence of an SCPE record proves nothing.** A file with no record either was produced by
  a tool that emits none, or had its sidecar stripped. These are indistinguishable.
- SCPE **cannot prevent sidecar stripping.** Provenance is bound to bytes that cannot be made
  to carry it.
- A verified signature **does not make an artifact trustworthy.** Compromised npm packages
  have shipped cryptographically valid SLSA provenance.

---

## 2. Conformance

An implementation is a **conforming verifier** if it implements §9 in full, computes every
facet in §10 from its own observations only, emits the result shape in §11, and fails closed
per §9.7 on every unrecognised input.

An implementation is a **conforming producer** if it emits statements satisfying §5, §6 and
§8, and asserts no assurance facet at all (§10.1).

An implementation is a **conforming renderer** if it displays the contents of `declared[]`
only within a section labelled as the signer's unverified claims, never inline with a facet
value or a `proved[]` entry; displays each facet as a separate named value without
collapsing them into a single score, grade, boolean or colour; and displays the normative
glosses of §10.5 alongside the `attribution` value. Renderer conformance matters because the
anti-laundering property of §11.3 is defeated by presentation alone: a model name shown next
to a green tick reads as verified no matter which array it came from.

Conformance is testable. The vector corpus in **`spec/test-vectors-v1/`** is normative: a
conforming verifier MUST produce the recorded status and, where `expected.json` names them,
the recorded facets for every vector.

`spec/test-vectors/` holds the retired `scpe/0.1` corpus. It is **not** normative for this
version, and its recorded statuses (`verified`, `tampered`, `unsupported-provider`,
`identity-unverifiable`) do not appear in §11.5 at all. A `scpe/1` verifier presented with
one of those inputs returns `unsupported-version` (§16), which is the correct behaviour and
the reason the two corpora cannot share a directory.

---

## 3. Layering

```
  ┌─────────────────────────────────────────────────────┐
  │ SCPE          predicate · derivation · discovery ·  │  ← this document
  │               verification · assurance              │
  ├─────────────────────────────────────────────────────┤
  │ in-toto v1    Statement · subject · ResourceDescriptor │  ← reused verbatim
  │               DigestSet · Bundle · monotonic policy  │
  ├─────────────────────────────────────────────────────┤
  │ DSSE v1.0.2   payload · payloadType · signatures[]  │  ← reused verbatim
  │               PAE · verify-before-parse · (t,n)     │
  ├─────────────────────────────────────────────────────┤
  │ signature suites   SSHSIG · Ed25519 · ECDSA · …     │  ← registered, not defined
  └─────────────────────────────────────────────────────┘
        optional outer carriage: Sigstore Bundle · .ots · SCITT receipt
```

The boundary is exact: **SCPE owns the `predicate` object and everything the verifier says
about it. It owns nothing below the `predicateType` line.**

"Reused verbatim" means SCPE adds nothing to those layers and changes no byte layout. It
does **narrow** two things that the lower layers deliberately leave open, and both are stated
where they apply rather than left for an implementer to discover:

| Narrowing | Lower layer leaves it open | SCPE requires |
|---|---|---|
| DigestSet matching (§4.5) | in-toto: match if **any** algorithm matches | Every **recognised** algorithm must match |
| Multi-signature policy (§8.4) | DSSE defines no verification policy or threshold | **Every declared signature** must verify |

Both are narrowings a verifier is entitled to make — in-toto explicitly assigns algorithm
filtering to consumers, and DSSE explicitly declines to define verification policy — but
neither is inherited by default, so neither may be left implicit.

---

## 4. Envelope and serialization

### 4.1 Envelope

A conforming record is a **DSSE envelope** ([DSSE v1.0.2]) whose payload is an **in-toto
Statement v1**.

```json
{
  "payload": "<base64 of the serialized Statement>",
  "payloadType": "application/vnd.in-toto+json",
  "signatures": [{"keyid": "…", "sig": "<base64>"}]
}
```

`payloadType` **MUST** be exactly `application/vnd.in-toto+json`.

### 4.2 Signed bytes

The signed bytes are DSSE's PAE, unchanged:

```
PAE(t, b) = "DSSEv1" ‖ SP ‖ LEN(t) ‖ SP ‖ t ‖ SP ‖ LEN(b) ‖ SP ‖ b
Signature = Sign(PAE(UTF8(payloadType), SERIALIZED_BODY))
```

where `SP` is ASCII 0x20 and `LEN()` is ASCII decimal with no leading zeros.

**`t` and `b` are byte sequences, and `LEN()` counts BYTES.** This is stated explicitly
because it is the first thing an implementer gets wrong. `b` is `SERIALIZED_BODY` - the raw
octets - and a verifier **MUST NOT** decode it to a text type, pass it through a lossy or
validating UTF-8 conversion, or measure its length in anything but bytes.

The failure is silent and language-shaped:

- A Rust implementation that reaches for `String::from_utf8_lossy` substitutes replacement
  characters for any non-UTF-8 octet, so the bytes it signs stop being the bytes that were
  signed. *(Observed in an independent implementation written from this document, which is
  why this paragraph exists.)*
- A JavaScript implementation using `String.prototype.length` counts UTF-16 code units, not
  bytes, so any payload containing a non-ASCII character yields a different `LEN(b)` and a
  signature no other implementation can verify.
- Go and Python happen to return byte counts for `len()` over `[]byte`/`bytes`, which is
  precisely why neither reference implementation caught this on its own.

**No canonicalization is performed at any layer.** The bytes that were signed are the bytes
that are verified. A verifier **MUST NOT** normalize, re-serialize, reorder, or re-encode the
payload before verifying, and **MUST NOT** re-parse the envelope after verification to obtain
the payload — the `SERIALIZED_BODY` that was verified is the one passed to the application,
per DSSE `envelope.md` and `protocol.md`.

> **Why this is not a new position.** It is the same rule this project already held under
> `scpe/0.1`, now inherited from a specification with third-party test vectors instead of
> maintained alone. See [design-decisions.md §2](../docs/design-decisions.md), which already
> cited JWS and DSSE as the model.

### 4.3 Statement

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [ { "name": "…", "digest": { "sha256": "…" }, "mediaType": "…" } ],
  "predicateType": "https://augbastos.github.io/scpe/generation/v1",
  "predicate": { … }
}
```

`subject` **MUST** contain at least one element and every element **MUST** carry a `digest`.
Subject elements are in-toto `ResourceDescriptor`s and inherit that type verbatim.

`subject[].name` and `subject[].mediaType` are **declared, never verified** (§11.3). A
verifier **MUST NOT** use either in any trust decision.

### 4.4 Predicate type URI

The `predicateType` for this version is:

```
https://augbastos.github.io/scpe/generation/v1
```

A verifier **MUST** refuse any statement whose `predicateType` it does not recognise, with
status `unsupported-predicate` (§9.7). It **MUST NOT** attempt a partial or best-effort read.

If this predicate is accepted into the in-toto predicate registry under a different URI, a
conforming verifier **MUST** accept both URIs as equivalent. Adding a recognised alias is
**additive** and does not constitute a version change; removing one does.

### 4.5 Digest handling

Digests are in-toto `DigestSet`s. SCPE **narrows** in-toto's matching rule:

- in-toto: two DigestSets match if **any** acceptable field matches.
- **SCPE: for each algorithm that appears in the statement's DigestSet *and* in the
  verifier's recognised set, the digest values MUST match. Algorithms present in the
  statement that the verifier does not recognise are ignored. Any mismatch among the
  recognised ones is `digest-mismatch`. If no algorithm appears in both, the result is
  `unsupported-digest` and the verifier fails closed.**

Worked, because "every algorithm present in both" is easy to read two ways:

| Statement carries | Verifier recognises | Behaviour |
|---|---|---|
| `sha256`, `sha512` | `sha256`, `sha512` | Both must match. |
| `sha256`, `blake2b` | `sha256` | Check `sha256`; ignore `blake2b`. |
| `blake2b` | `sha256` | No overlap → `unsupported-digest`, fail closed. |
| `sha256`, `sha512` | `sha256` | Check `sha256`; ignore `sha512`. |

A verifier's recognised set is its own configuration, and a verifier that admits a weak
algorithm has weakened itself — the AND rule prevents an attacker from *choosing* the weak
one when a strong one is present, which is the attack; it cannot repair a verifier that
recognises nothing else.

Rationale: OR-matching is a downgrade vector. A statement carrying `sha256` and a weak
algorithm matches on the weak one unless the verifier filters, and the in-toto specification
pushes that duty entirely onto consumers. SCPE performs it.

`sha256` **MUST** be supported by every conforming implementation. Support for additional
algorithms is **OPTIONAL**; a verifier **MUST** ignore algorithms it does not recognise
rather than failing, except where that leaves the intersection empty.

### 4.6 No partial hashing

A digest **MUST** cover the artifact's complete byte sequence. Byte-range exclusions,
partial hashes, region hashes and any equivalent construct are **forbidden** and a statement
containing one **MUST** be refused.

Rationale: this eliminates by construction the exclusion-range attack class demonstrated
against C2PA in arXiv 2604.24890 (2026-04-27), where hash exclusion ranges permitted
undetected GPS and metadata edits. SCPE has no exclusion ranges to attack.

### 4.7 Container hygiene

A verifier **MUST**:

- check any declared size against its cap **before** allocating, and additionally bound the
  read at `cap + 1` bytes so a lying length header cannot exceed the cap;
- **reject** a JSON object containing a duplicate key at **any** nesting depth, rather than
  resolving to first-wins or last-wins. Identical bytes must yield an identical verdict
  everywhere, and RFC 8259 leaves duplicate names implementation-defined;
- treat a length prefix, where one exists in a container, as an extraction aid that is
  **never** an input to signature verification.

---

## 5. The generation predicate

### 5.1 Shape

```json
{
  "scpeVersion": "1",

  "generation": {
    "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
    "provider": "anthropic",
    "model": "claude-opus-4-5-20251101",
    "humanOversight": "prompt_guided",
    "producedAt": "2026-09-01T10:04:11Z"
  },

  "signer": [
    { "keyFingerprint": "SHA256:0Xy…",
      "alg": "sshsig-ssh-ed25519",
      "role": "producer" }
  ],

  "derivedFrom": [ … ],
  "evidence":    [ … ],
  "commitments": [ … ],
  "run":         { … }
}
```

### 5.2 Required fields

Exactly three things are **REQUIRED**. The floor is deliberately small so that emitting a
record costs an emitter almost nothing.

| Field | Type | Meaning |
|---|---|---|
| `scpeVersion` | string | `"1"` for this specification. |
| `generation.digitalSourceType` | IPTC/C2PA term URI | What kind of process produced the bytes. |
| `signer[]` | array, ≥1 | Who signed, pinned (§8.2). |

Everything else is **OPTIONAL**. A record carrying only these three fields is valid and
verifiable, and its assurance facets will say so.

### 5.3 `generation`

`digitalSourceType` (**REQUIRED**) **MUST** be a term from the IPTC DigitalSourceType
NewsCodes vocabulary or one of the two C2PA-minted terms. SCPE **MUST NOT** mint its own.
Commonly:

| Term | Use |
|---|---|
| `…/trainedAlgorithmicMedia` | Generative model output that is media. |
| `…/compositeWithTrainedAlgorithmicMedia` | Human work with generated components. |
| `http://c2pa.org/digitalsourcetype/trainedAlgorithmicData` | Generated output that is **not** media — CSV, JSON, source code, a pickle. |
| `…/humanEdits` | Human edits to an existing asset. |
| `…/digitalCapture` | Captured from a device. |

A verifier **MUST** treat an unrecognised term as **declared and unverified** — it is a
controlled vocabulary maintained elsewhere and new terms are expected. It **MUST NOT** fail
on one, and **MUST NOT** infer anything from it.

`provider` and `model` (**SHOULD**) use OpenTelemetry GenAI names: `provider` corresponds to
`gen_ai.provider.name` and `model` to `gen_ai.response.model`. Implementations **MUST NOT**
use the deprecated `gen_ai.system`.

`humanOversight` (**OPTIONAL**) **MUST**, when present, be one of C2PA's
`contentProfile.humanOversightLevel` values: `fully_autonomous`, `prompt_guided`,
`human_validated`.

`producedAt` (**OPTIONAL**) is an RFC 3339 timestamp. It is **declared**, and a verifier
**MUST NOT** treat it as evidence of when anything happened (§10.6).

### 5.4 `signer[]`

Each entry:

| Field | Req. | Meaning |
|---|---|---|
| `keyFingerprint` | **REQUIRED** | The public key's fingerprint, in a form the suite defines. |
| `alg` | **REQUIRED** | A registered signature suite identifier (§8.1). |
| `role` | **REQUIRED** | `producer`, `observer`, or `countersigner`. |
| `identity` | OPTIONAL | A declared identity string (SPIFFE ID, OIDC subject, forge handle). **Declared, never verified by SCPE.** |

`keyFingerprint` is **REQUIRED and non-omissible**. It lives inside the signed payload,
which is what makes it authoritative — DSSE's `keyid` is normatively "an optional,
unauthenticated hint" that "MUST NOT be used for security decisions," so a pin carried there
would be worthless. Carrying it in the payload obeys that prohibition and still closes the
substitution vector: an account publishing keys A and B can no longer name A, sign with B,
and pass.

`alg` is **REQUIRED** because DSSE carries no algorithm identifier and "defines no
negotiation mechanism." Without it, suite selection is out-of-band and unauthenticated. A
verifier **MUST** check `alg` against its own allowlist before verifying, per the principle
in RFC 8725 §3.1, and **MUST** refuse a suite not on that allowlist with
`unsupported-suite`.

### 5.5 `countersigner` (reserved)

The `countersigner` role and its namespace `scpe-cs/1` (§8.3) are **reserved and not defined
in this version**. No facet reads it. A verifier encountering a `countersigner` signature
**MUST** treat it as undeclared (§8.4) — counted, never verified, contributing nothing.

It is named here rather than omitted so that the namespace cannot be claimed for something
else, and so that adding threshold countersignature later is additive. A role with a
namespace and no semantics is a footgun if left implicit; reserving it explicitly is the fix.

### 5.6 `assurance` (reserved, and refused)

`predicate.assurance` is a **reserved field name**. A conforming producer **MUST NOT** emit
it (§10.1).

It is reserved rather than merely undefined for a specific reason: §9 step 8 ignores
unrecognised optional fields, so a producer-asserted facet placed in any *unrecognised* name
would be silently dropped and the anti-overclaim check at step 13 would never fire. Reserving
this one name gives that check an input. A verifier **MUST NOT** ignore it, **MUST** recompute
every facet it names, and **MUST** return `assurance-overclaimed` on any mismatch.

A record that asserts its own assurance correctly is still non-conforming; the verifier's
computation is authoritative either way, so there is no benefit to emitting it and one
guaranteed failure mode.

### 5.7 `run` (optional)

One generation event may produce many artifacts. in-toto's `subject[]` array has no run
semantics, so SCPE records them as annotations:

```json
"run": { "id": "01JC…", "segment": 3, "traceParent": "00-4bf92f…-00f067aa…-01" }
```

All fields **OPTIONAL**. `traceParent` **SHOULD** be a W3C Trace Context header value.
A verifier **MUST NOT** derive any assurance facet from `run`; it is correlation metadata,
and a signer controls all of it.

---

## 6. Derivation

### 6.1 Edges

```json
"derivedFrom": [
  {
    "relationship": "inputTo",
    "resource": {
      "name": "quarterly.csv",
      "digest": { "sha256": "9f2e…" },
      "mediaType": "text/csv"
    },
    "statementDigest": { "sha256": "1c0d…" }
  }
]
```

`relationship` (**REQUIRED**) **MUST** be one of C2PA's three relation words, reused
unchanged:

| Value | Meaning |
|---|---|
| `parentOf` | The prior version this artifact was derived from. |
| `componentOf` | A part composed into this artifact. |
| `inputTo` | Used as input to a computational process, such as an AI model. |

SCPE **MUST NOT** mint a fourth relation. A statement **MUST NOT** carry more than one
`parentOf` edge.

`resource` (**REQUIRED**) is an in-toto `ResourceDescriptor` and **MUST** carry a `digest`.

`statementDigest` is the SHA-256 of the parent statement's **signed payload bytes** — not of
the parent artifact. It is:

- **REQUIRED** on a `parentOf` edge. A prior version of this artifact is the one case where
  a governing record is expected to exist, and it is the case an attacker most wants to
  substitute.
- **RECOMMENDED** on `componentOf` and `inputTo` edges, where the input may legitimately be
  a file nobody ever signed — a CSV, a photograph, a scraped page. Requiring a pin there
  would make honest records unrepresentable.

Where it is absent, the verifier **MUST** record the resulting chain as `lineage: declared`
and **MUST** name the unpinned edge in `not_checked[]`.

### 6.2 Why the parent is pinned by statement, not only by artifact

Pinning a parent only by artifact digest permits **parent-envelope substitution**: any valid
statement about that digest, from any signer, silently becomes the parent. An attacker who
can produce their own record about a widely-published input can insert themselves into
someone else's lineage without breaking a single signature.

When `statementDigest` is present, a verifier resolving the chain **MUST** confirm the
resolved parent statement's signed payload hashes to it, and **MUST** report
`lineage: broken` if it does not. When it is absent, the edge is resolvable only by artifact
digest, and the verifier **MUST** report the resulting chain as `lineage: declared`, never
`verified`.

### 6.3 What chain verification proves, and what it does not

A verified chain of depth *N* proves exactly this: *for each of N edges, a key the verifier
trusted signed a statement asserting that edge, and the parent statement the verifier
resolved is the one the child pinned.*

It does **not** prove:

- that the chain is **complete**. Nothing anywhere can prove completeness; in-toto bundles
  are unauthenticated as a set, and a chain can be silently truncated. SCPE **MUST NOT**
  emit any field named or rendered as "complete".
- that the transformation described actually occurred. The edge is an assertion.
- that an ancestor's own binding still holds. Ancestor bytes are not carried. This is the
  same limit C2PA documents for ingredients, and SCPE handles it the same way: an ancestor's
  status is a **point-in-time snapshot recorded by the parent**, and a verifier that
  re-checks it **MUST** report the snapshot and its own live result **side by side**, so a
  stale or self-serving snapshot is visible rather than authoritative.

### 6.4 Traversal

Chain resolution is **OPTIONAL** and **offline by default**: a verifier resolves an edge only
if the parent's record is already available locally, via §7 discovery from a path the user
supplied. A verifier **MUST NOT** dereference any URI in `resource.uri` or
`resource.downloadLocation` unless the operator passes **both** `--follow-hints` **and**
`--allow-host`, and it **MUST** print the host list before contacting anything (§13.4).

Cycle detection is specified, not left to implementers, because two verifiers that detect
cycles differently return different statuses for identical bytes:

> A verifier **MUST** track the SHA-256 of every parent statement's signed payload as it
> resolves. Encountering a digest already in that set is a cycle → `lineage: broken`, and
> the edge **MUST NOT** be followed. Depth **MUST** be bounded; the bound **MUST** be
> reported in the result; a chain exceeding it is `lineage: broken`, never silently
> truncated. **The RECOMMENDED bound is 32.**

---

## 7. Sidecar and discovery

### 7.1 Form

An SCPE sidecar is an **in-toto bundle**: JSON Lines, one DSSE envelope per line,
order-independent, unrecognised lines ignored. Media type
`application/vnd.in-toto.bundle`.

For an artifact at `<path>`, the sidecar is at:

```
<path>.scpe.jsonl
```

The full name is retained, not the stem: `report.pdf` → `report.pdf.scpe.jsonl`. This follows
C2PA's `<path>.c2pa` convention and SLSA's `<filename>.attestation` guidance rather than
inventing a third shape.

### 7.2 Discovery order

Given a file, a verifier **MUST** look in this order and stop at the first hit:

1. A sidecar path given explicitly by the operator.
2. `<path>.scpe.jsonl`
3. `<path>.scpe`
4. `.scpe/<sha256-of-artifact>.jsonl` in the artifact's own directory.

The sidecar is **not** cryptographically bound to the filename — only the digest binds. A
renamed file keeps its provenance if and only if the sidecar is renamed with it, and a
sidecar found by path whose digest does not match the artifact **MUST** be reported as
`digest-mismatch`, never silently ignored.

### 7.3 Peer sidecars

On any run, a verifier **SHOULD** additionally report the presence of peer provenance files
next to the artifact — `<path>.c2pa`, `<path>.sigstore.json`, `<path>.intoto.jsonl`,
`<path>.sig`, `<path>.ots`, `<path>.asc`, `<path>.minisig` — as **findings**, with status
`present-unverified` unless it verified them.

Reporting a peer file **MUST NOT** influence any assurance facet.

> **This discovery convention is a sixth convention in a field that already has five.** It
> is filed upstream as a registry note rather than claimed as a contribution; see
> [ROADMAP](../docs/ROADMAP.md). It is ~15 lines of rules and could not carry a project.

---

## 8. Signing

### 8.1 Registered suites

| `alg` | Construction | Status |
|---|---|---|
| `sshsig-ssh-ed25519` | SSHSIG (`ssh-keygen -Y sign`), Ed25519 key | **REQUIRED** |
| `sshsig-ecdsa-sha2-nistp256` | SSHSIG, ECDSA P-256 | OPTIONAL |
| `sigstore-bundle` | Sigstore Bundle v0.3 carrying the DSSE envelope | OPTIONAL |
| `x509-ecdsa-p256-sha256` | Raw ECDSA over PAE, key from an X.509 chain | OPTIONAL |
| `ml-dsa-44` | ML-DSA-44 (FIPS 204, RFC 9964; COSE alg -48) | **Registered, not implemented** |

`ml-dsa-44` is registered in this version and implemented in none. It exists here so that
post-quantum migration is an **implementation** change, not a **format** change: a verifier
encountering it today refuses with `unsupported-suite` and fails closed, and a future
verifier accepts it without any change to the predicate, the statement, or any signed byte
layout.

A verifier **MUST** maintain an explicit allowlist of suites it accepts and **MUST** check
`signer[].alg` against it **before** attempting verification.

### 8.2 Key pinning

A verifier **MUST**, for each signature it verifies, confirm that the fingerprint of the key
it used matches a `signer[].keyFingerprint` inside the signed payload. A signature whose key
fingerprint appears in no `signer[]` entry is **counted and reported, never verified, and
never contributes to any facet or verdict** (§8.4).

### 8.3 Domain separation by role

Where the suite carries a namespace — SSHSIG does — the namespace **MUST** encode the role:

| Role | SSHSIG namespace |
|---|---|
| `producer` | `scpe/1` |
| `observer` | `scpe-obs/1` |
| `countersigner` | `scpe-cs/1` |

A verifier **MUST** pass the role's namespace to the signature check and **MUST** treat a
signature made under a different namespace as `signature-invalid`.

This is a mechanism, not a convention, and the mechanism was verified by execution against
OpenSSH 10.3p1 rather than taken from documentation:

- `ssh-keygen -Y verify -n <namespace>` refuses a signature made under a different
  namespace — *"Couldn't verify signature: namespace does not match"*, exit 255.
- `ssh-keygen -Y find-principals` **rejects** `-O namespace=…` as an invalid option. The
  namespace gate is on `verify`. An implementation that tries to filter during the
  principal search will silently find nothing.
- A `namespaces="…"` restriction inside an `allowed_signers` line is enforced by OpenSSH
  itself — *"key is not permitted for use in signature namespace …"*.

That last point has a consequence worth stating plainly: **an operator can bind a key to a
single SCPE role by hand, in a file they own, offline, with no infrastructure.** A key
listed as

```
alice namespaces="scpe/1" ssh-ed25519 AAAA…
```

can sign as a producer and **cannot** sign as an observer, and OpenSSH enforces that without
SCPE parsing anything. Role separation is therefore expressible in the trust policy, not
only in the record.

### 8.4 Multi-signature and the observer statement

DSSE's `signatures[]` is an array, and SCPE uses it — with two narrowings that are stated
here rather than left implicit.

**Narrowing 1 — every declared signature must verify.** If any signature whose key is
declared in `signer[]` fails, the result is `signature-invalid` for the whole statement.

> DSSE itself defines no verification policy: it says an envelope "MAY have more than one
> signature, which is equivalent to separate envelopes with individual signatures," and
> leaves thresholds to the verifier. SCPE's policy is all-declared-must-verify. This is
> deliberately stricter than "at least one verifies," under which a statement carrying one
> good and one bad signature passes by default with the failure demoted to a report line. A
> signature that was offered and does not verify is evidence of a problem, not noise.

Signatures whose keys are **not** declared in `signer[]` are counted and reported under
`undeclared_signatures`. They are never verified and never contribute to any facet.

**Narrowing 2 — an observation is a separate statement, never a co-signature.**

A party that witnessed an artifact cannot honestly endorse the model identity, prompt
commitments, sampling parameters or derivation edges recorded by the producer, because it did
not witness any of them. A second signature over the *producer's* payload would make it do
exactly that.

Therefore: **an `observer` signature MUST NOT appear in the same envelope as a `producer`
signature.** An observation is its own DSSE envelope, on its own line of the bundle, carrying
its own statement whose predicate contains **only**:

```json
{
  "scpeVersion": "1",
  "generation": { "digitalSourceType": "…" },
  "signer": [ { "keyFingerprint": "SHA256:…", "alg": "…", "role": "observer" } ],
  "observed": { "statementDigest": { "sha256": "…" } }
}
```

`observed.statementDigest` (**REQUIRED** in an observer statement) is the SHA-256 of the
producer statement's signed payload bytes. The observer's `subject[]` **MUST** match the
producer's.

A verifier **MUST** reject as `malformed-predicate` an observer statement carrying
`generation.provider`, `generation.model`, `generation.humanOversight`, `derivedFrom`,
`commitments` or `run`. The observer is signing one claim — *"I saw these bytes, and I saw
this producer statement about them"* — and the schema makes any wider claim unrepresentable
rather than merely discouraged.

**Packaging note.** An envelope carrying more than one signature cannot be wrapped in a
Sigstore Bundle, which carries exactly one. Because an observation is a separate envelope
rather than a co-signature, the common SCPE record has a single signature and packages
cleanly; only threshold-style countersignature is affected. A verifier **MUST NOT** reject a
multi-signature envelope on packaging grounds.

### 8.5 Trust policy

SCPE **does not define a trust policy language.** For the SSHSIG suites, the policy is
OpenSSH's `allowed_signers` file, used verbatim — principal patterns, `namespaces=`,
`valid-after=`, `valid-before=`, `cert-authority` — and enforced by `ssh-keygen -Y verify`.
SCPE **MUST NOT** parse it.

Where the policy file came from is itself reported, as the `anchor` facet (§10.4).

---

## 9. Verification algorithm

A conforming verifier performs these steps in order. Any step's failure terminates with that
step's status.

1. **Locate.** Find the record (§7). None found → `no-provenance-found`.
2. **Read the envelope.** Parse the DSSE envelope only far enough to obtain `payload`,
   `payloadType` and `signatures[]`, under §4.7 hygiene. Malformed → `malformed-input`.
3. **Check the payload type.** Not `application/vnd.in-toto+json` → `unsupported-payload`.
4. **Check the suite allowlist, then verify.** These are two operations in a fixed order,
   because they produce different statuses and an implementation that merges them will
   disagree with one that does not:
   - **4a.** For every `signer[].alg`, check it against the verifier's allowlist (§8.1)
     **before** any signature material is passed to a backend. Not on the allowlist →
     `unsupported-suite`, fail closed.
   - **4b.** Verify each signature against PAE (§4.2) under its role's namespace (§8.3),
     using only keys resolved from the anchor (§10.4). Any **declared** signature failing →
     `signature-invalid` (§8.4).

   **If the signing backend is unavailable or errors, the status is `tooling-error` — never
   `signature-invalid`.** The two are not interchangeable: one says a check ran and the
   signature was rejected, the other says no check ran at all.
5. **Pass the verified bytes forward.** The `SERIALIZED_BODY` verified in step 4 is the one
   parsed in step 6. **MUST NOT** re-read it from the envelope.
6. **Parse the Statement.** Check `_type`; check `predicateType` against recognised URIs
   (§4.4) → `unsupported-predicate` if unknown; check `predicate.scpeVersion` →
   `unsupported-version` if unknown.
7. **Check key pinning** (§8.2). Fingerprint mismatch → `signature-invalid`.
8. **Validate the predicate** against §5. Missing a REQUIRED field → `malformed-predicate`.
   Unrecognised **optional** fields are ignored, not errors — **except `assurance` (§5.6),
   which is reserved and MUST be carried forward to step 13.**
9. **Bind the subject.** If artifact bytes were supplied, hash them and compare under §4.5's
   AND rule. Mismatch → `digest-mismatch`. Empty algorithm intersection →
   `unsupported-digest`. **No bytes supplied → the run continues, and `binding` is
   `unbound`** (§10.2) — this is a normal outcome, not an error.
10. **Resolve lineage,** if requested and if parents are locally available (§6.4).
11. **Record evidence** (§5, `evidence[]`) as `present-unverified` unless the verifier
    independently verified it.
12. **Compute the facets** (§10) from observations made in steps 1–11 only.
13. **Recompute any asserted assurance.** If the producer asserted an assurance value and the
    verifier's independent computation differs → `assurance-overclaimed` (§10.1).
14. **Emit** the result shape (§11).

### 9.7 The fail-closed rule

A verifier **MUST** fail closed on every unrecognised input: an unknown `predicateType`, an
unknown `scpeVersion`, an unknown signature suite, an empty digest-algorithm intersection, an
unreadable container. It **MUST NOT** guess, degrade to a partial read, or return a passing
status with a warning.

Three things are deliberately **not** fail-closed, because forward compatibility depends on
them and none can affect a trust decision:

- an unrecognised `digitalSourceType` term → declared, unverified;
- an unrecognised optional predicate field → ignored;
- an unrecognised `evidence[]` entry → `present-unverified`.

This is the three-way extension mechanism, and it maps onto the three ways the ecosystem
moves: new predicate versions are refused, new vocabulary terms pass through, new evidence
kinds degrade.

---

## 10. The assurance model

### 10.1 The two laws

These two rules govern every facet, and violating either is a specification violation:

> **Law 1 — Observation.** Every input to a facet **MUST** be an observation the verifier
> made. A value read out of the statement is never an input to a facet.
>
> **Law 2 — Descent.** A self-declared field **MAY** lower a facet. It **MUST NOT** raise
> one.

A producer **MUST NOT** assert any facet value. If a statement contains one, the verifier
recomputes it independently and, on any mismatch, returns **`assurance-overclaimed`** and
fails closed. No CLI flag may set a facet.

There is **no aggregate score, no letter grade, no percentage, and no colour implying
safety.** Facets are reported separately and **MUST NOT** be collapsed into a single boolean
by a conforming renderer.

### 10.2 `binding` — were the bytes checked?

| Value | Meaning |
|---|---|
| `bound` | The verifier hashed the artifact and every recognised algorithm matched. |
| `unbound` | No artifact bytes were supplied. The signature is over a statement about a digest the verifier never saw. |
| `mismatch` | Bytes were supplied and did not match. |

`unbound` is the single most common non-`bound` outcome in a sidecar world and it has its own
exit code (§11.4) so a shell script need not parse JSON to branch on it.

### 10.3 `signature` — did it verify?

`valid` · `invalid` · `unchecked` (a suite outside the allowlist, or a backend that did not
run — never conflated with `invalid`).

### 10.4 `anchor` — where did the trust come from?

This is the generalisation of `key_source`, and it is the reason this project exists.

| Value | Meaning | Ceiling |
|---|---|---|
| `policy` | The operator's own `allowed_signers` file. | — |
| `flag` | A key file passed on the command line. | — |
| `forge` | Keys published by a code-hosting provider for a named account. | — |
| `bundled` | Keys carried **inside the input being verified**. | **MUST NOT** reach the top trust state. |
| `none` | No anchor; nothing was verified. | — |

`bundled` self-anchoring is legitimate for offline conformance testing and is worthless as
identity evidence: the input is asserting who signed it. Its ceiling is a **protocol
invariant**, not a CI policy, and a passing result anchored this way carries a distinct
status and exit code (§11.5).

> **Implementation status.** The reference verifier implements `policy` and `flag` only.
> `bundled`, `forge` and the `ok-self-anchored` status are specified and emitted by no code
> in this repository, so the corpus carries no vector for them yet.

### 10.5 `attribution` — how strong is the generation claim?

| Value | Requires |
|---|---|
| `self-asserted` | The producer signed a claim about itself. **This is every record today.** |
| `countersigned` | A separate, verified **observer statement** (§8.4) whose `observed.statementDigest` matches this statement's signed payload, whose `subject[]` matches, and whose key resolved from the anchor under a **different principal** than every producer signature. |
| `provider-attested` | Verified evidence from the model provider binding these bytes to a generation request. |
| `tee-attested` | A verified TEE attestation covering the generating workload. |

Every input above is an observation the verifier made: it verified a second signature, it
compared principals, it hashed a payload and compared.

#### Why this facet is named `countersigned` and not `host-observed`

An earlier draft called the second value `host-observed` and required only that the observer
key be "distinct from every producer key." **That was an overclaim, and it was demonstrated
rather than argued.** One party generates a second key in about a second; both keys then sit
in the operator's `allowed_signers` under different principals; the facet reads as
independent corroboration and the evidence supports nothing of the kind.

The root cause does not yield to a stricter check. **No offline verifier can establish that
two keys are two parties.** `allowed_signers` has no concept of party — an operator who lists
a colleague's key and an operator who lists their own laptop key have written the same file.
Distinct principals, distinct fingerprints, distinct namespaces and distinct signatures are
all real observations, and none of them is the observation people want this facet to make.

So the facet reports the mechanical fact it can actually establish — *a second key, under a
different principal, countersigned this exact statement about these exact bytes* — and the
name says exactly that and no more. The gloss, which a conforming renderer **MUST** display
(§2), states the limit:

> **`countersigned` means a second key signed; it does not establish a second party.**

This is the whole discipline of §10 applied to the one facet where the temptation to
overclaim is strongest. A design that says "two parties" because it saw two keys has learned
nothing from the `Co-authored-by: Copilot` incident that motivates this project.

#### Anchor caps the ladder

A facet may never be stronger than the trust that produced it:

> **At `anchor` ∈ {`bundled`, `flag`, `none`}, `attribution` MUST NOT exceed `self-asserted`
> and `lineage` MUST NOT exceed `declared`.**

Without this rule, a producer who supplies the key file also supplies both "parties" and both
ends of the chain, and the facets rise on evidence the producer authored. `anchor` was the
only facet with a ceiling; ceilings belong on every facet a self-supplied key can raise.

Where several signatures contribute to a result, the reported `anchor` **MUST** be the
**weakest** anchor among them, never the strongest.

Two glosses are **normative spec text**, not commentary, and a conforming renderer **MUST**
display them alongside the corresponding value:

> **A TEE receipt attests an enclave, not a model.**
> **A provider receipt binds bytes to an endpoint, not to weights.**

`host-observed` means *a second party vouched that these bytes and this producer statement
existed together.* It does **not** mean that party witnessed the generation, verified the
model, or agrees with anything the producer declared — and it cannot, because §8.4 makes the
wider claim unrepresentable in an observer statement.

### 10.6 `time` — is there an external time reference?

`unanchored` · `externally-anchored`.

**The default value is `unanchored`,** and a verifier transitions to `externally-anchored`
only by performing a check that succeeded — never by finding a field.

`externally-anchored` **MUST** be computed **only** from a time anchor the verifier itself
validated: an RFC 3161 token, an OpenTimestamps proof, or a transparency receipt. **The mere
presence of an entry in `evidence[]` MUST NOT raise this facet**, and neither does
`producedAt`, ever. A time-bearing `evidence[]` entry that was not validated is reported as
`present-unverified` and **MUST NOT** be rendered as establishing a time.

This is the exact laundering the two laws exist to prevent: a facet computed from the
presence of a field is a facet the signer sets.

### 10.7 `lineage`

`none` · `declared` (edges present, parents not resolved) · `verified-depth-N` (N parents
resolved, signatures verified, `statementDigest` pins confirmed) · `broken` (a pin failed, a
cycle was found, or a parent's digest did not match).

There is no `complete` value. See §6.3.

---

## 11. Result shape

### 11.1 Structure

```json
{
  "status": "ok",
  "facets": {
    "binding": "bound",
    "signature": "valid",
    "anchor": "policy",
    "attribution": "self-asserted",
    "time": "unanchored",
    "lineage": "declared"
  },
  "proved": [
    "signature over predicate by SHA256:0Xy… (sshsig-ssh-ed25519, role=producer)",
    "subject[0].digest.sha256 matches the supplied bytes",
    "signer key is listed in the operator's allowed_signers"
  ],
  "declared": [
    "generation.provider = anthropic",
    "generation.model = claude-opus-4-5-20251101",
    "generation.digitalSourceType = …/trainedAlgorithmicMedia",
    "generation.humanOversight = prompt_guided",
    "generation.producedAt = 2026-09-01T10:04:11Z",
    "subject[0].name = report.pdf",
    "subject[0].mediaType = application/pdf",
    "derivedFrom[0] inputTo quarterly.csv"
  ],
  "not_checked": [
    "that the named model produced these bytes — no provider or TEE attestation is present",
    "that the derivation edge occurred — the parent statement was not resolved",
    "when this was signed — no verified time anchor is present",
    "that no other transformation occurred — SCPE cannot express that claim"
  ],
  "undeclared_signatures": 0,
  "peers": [],
  "exit": 0
}
```

### 11.2 `proved[]` — what the verifier checked

Every entry corresponds to an operation the verifier actually performed. Nothing read out of
the statement appears here.

### 11.3 `declared[]` — what the signer said

Every `generation.*` field, `subject[].name`, `subject[].mediaType`, `identity`, `producedAt`,
`run.*` and every derivation edge appears here and **nowhere else**.

**A conforming renderer MUST NOT display a model name, a provider name, or an identity except
by reading it out of `declared[]`.** This is the anti-laundering mechanism, and it is
structural on purpose: a dashboard cannot accidentally present a signer's claim as a verified
fact if the only place that claim exists is a list named `declared`.

### 11.4 `not_checked[]`

**REQUIRED and non-empty** on `ok`, `ok-self-anchored` and `subject-unavailable`. There is
always something a signature did not prove; a passing result that cannot name one is a
broken implementation.

It is derived, not free-form: **every facet not at its strongest value MUST produce at
least one entry naming what that facet did not establish.** A single boilerplate line
satisfying the non-emptiness rule forever would defeat the only honesty mechanism the result
shape has.

On a failing status it **MAY** be omitted or empty — a result that already says the
signature did not verify is not improved by enumerating what else went unchecked.

### 11.5 Statuses and exit codes

| Status | Exit | Meaning |
|---|---|---|
| `ok` | 0 | Everything checked, checked out. |
| `ok-self-anchored` | 10 | Valid, but the anchor came from inside the input (§10.4). |
| `subject-unavailable` | 11 | Record valid; artifact bytes were never supplied (`binding: unbound`). |
| `signature-invalid` | 20 | A declared signature failed. |
| `digest-mismatch` | 21 | Supplied bytes do not match. |
| `assurance-overclaimed` | 22 | The producer asserted a facet the verifier recomputed differently. |
| `unsupported-predicate` | 30 | Unknown `predicateType`. |
| `unsupported-version` | 31 | Unknown `scpeVersion`. |
| `unsupported-suite` | 32 | `alg` not on the allowlist. |
| `unsupported-digest` | 33 | No shared digest algorithm. |
| `malformed-input` | 34 | Container unreadable. |
| `malformed-predicate` | 35 | A REQUIRED field is missing. |
| `no-provenance-found` | 40 | No record located. |
| `tooling-error` | 50 | A backend was unavailable or errored. **No check ran.** |

**No status may imply a check that did not execute.** `tooling-error` exists precisely so
that a missing `ssh-keygen` is never reported as `signature-invalid`.

---

## 12. Privacy

### 12.1 Data minimisation by default

A record **MUST NOT** contain, and a conforming producer **MUST NOT** emit by default:

- raw prompts, system prompts, or any prompt text;
- usernames, e-mail addresses, or account identifiers;
- machine identifiers, hostnames, IP addresses;
- absolute filesystem paths or repository paths;
- session identifiers tied to a person;
- internal model configuration beyond a version string.

Prompts may contain intellectual property, confidential information, personal data and
security-sensitive material. **SCPE MUST NOT require storing a raw prompt, ever.**

### 12.2 Commitments instead of content

When a producer wants to be able to *later prove* what a prompt was, without publishing it
now, it emits a commitment rather than the content:

```json
"commitments": [
  { "name": "prompt",
    "alg": "sha256",
    "value": "…",
    "disclosure": "sd-jwt/1" }
]
```

The committed bytes **MUST** be the SD-JWT (RFC 9901) structured disclosure form —
`[salt, name, value]` — serialized under the same exact-bytes rule as the payload, with
decoys where unlinkability matters.

An unframed `salt ‖ value` concatenation **MUST NOT** be used. Framing is the difference
between a construction that is safe by design and one that is safe only because the salt
happens to be fixed-length.

Salts **MUST** be generated by a cryptographically secure random source and **MUST** be at
least 16 bytes. A commitment is a hash of a low-entropy secret: prompts are guessable, and a
short or predictable salt turns the commitment into a dictionary attack against the very
content §12.1 refused to store.

A verifier that is given a disclosure **MAY** check the commitment and, if it does, records
it in `proved[]`. Otherwise the commitment appears in `declared[]`.

### 12.3 Verification is offline by default

A conforming verifier performs **zero network I/O** unless the operator explicitly opts in.

Network access is a **privacy** requirement before it is an availability one: a verify-time
fetch of a signer's keys tells a third party that someone, somewhere, is verifying an
artifact attributed to a named person — on every check, forever. A verifier **MUST** print
the host list before contacting anything, and **MUST** require both `--follow-hints` and
`--allow-host` before dereferencing any locator carried inside a record (§6.4).

---

## 13. Security considerations

The full analysis is in [THREAT_MODEL.md](THREAT_MODEL.md). This section states what the
protocol structurally defends and what it does not.

### 13.1 Defended by construction

Each row states the mechanism **and its scope**. A row with an unstated scope is an
overclaim, and a "defended by construction" table is the first thing a hostile reader
checks.

| Attack | Mechanism | Scope / limit |
|---|---|---|
| Canonicalization ambiguity | No canonicalization exists; PAE over exact bytes (§4.2). | Complete. |
| Cross-protocol / format confusion | `payloadType` inside the signed data (DSSE). | Complete. |
| Payload re-parse divergence | The verified `SERIALIZED_BODY` is the one parsed (§4.2, §9 step 5). | **Payload only.** The *envelope* is still parsed before any signature check (§9 step 2) — unavoidable, and bounded by §4.7 and §13.3 rather than eliminated. |
| Duplicate-key verdict divergence | Rejected at any depth (§4.7). | Applies to both the envelope parse and the payload parse. |
| Provenance transplant between artifacts | Subject digest inside the signed payload. | **Only when bytes are supplied.** With `binding: unbound` (§10.2) nothing is compared, and that is an ordinary outcome, not an error. |
| Digest downgrade | AND-matching, not OR (§4.5). | Complete against algorithm *choice*; cannot repair a verifier whose recognised set contains only weak algorithms. |
| Exclusion-range editing | Partial hashing forbidden (§4.6). | Complete, by construction. |
| Key substitution within one resolved key set | Fingerprint pinned inside the signed payload, REQUIRED (§8.2). | Complete for the pinning; says nothing about who chose the key set — see `anchor` (§10.4). |
| Algorithm confusion | `alg` inside the signed payload, checked against an allowlist (§8.1). | Complete against confusion; no strength axis (§13.2). |
| Role replay | Namespace domain separation (§8.3). | **SSHSIG suites only.** `sigstore-bundle`, `x509-…` and `ml-dsa-44` carry no namespace; §10.5's `countersigned` is unreachable under them. |
| Signature-count laundering | Every declared signature must verify; undeclared ones never count (§8.4). | Complete for the verdict. A renderer showing `undeclared_signatures` beside a pass is a presentation problem (§11.3). |
| Parent substitution on `parentOf` | Pin REQUIRED on `parentOf` (§6.2). | **`parentOf` only.** `componentOf` and `inputTo` may omit the pin, and are listed as undefended in §13.2. |
| Assurance inflation *inside a record* | `predicate.assurance` is a reserved name the verifier recomputes; mismatch is `assurance-overclaimed` (§10.1, §5.6). | Covers only what the record says. Inflation in a README, badge or dashboard is outside the format entirely. |
| Facets raised by self-supplied keys | `attribution` and `lineage` capped by `anchor`; `anchor` is the weakest of those used (§10.5). | Complete for these two facets. |
| Self-anchored pass read as identity-backed | Distinct status and exit code (§10.4, §11.5). | Complete for the *status*; a consumer branching on an exit-code range rather than on `status` defeats it (§11.5). |
| A missing signing backend reported as a failed check | `tooling-error` is never `signature-invalid` (§11.5). | **Narrow, and deliberately so.** Covers an absent or non-executable backend. It does **not** cover backends that report distinct failures identically: `ssh-keygen -Y verify` returns 255 for a bad signature, a wrong principal (silently, with no stderr), an unreadable policy file and a namespace mismatch alike. A verifier **MUST NOT** parse that stderr to invent a distinction, and **MUST** report the honest, coarse result. |
| Decompression and amplification | Caps before allocation, bounded reads (§4.7), and enumerated limits (§13.3). | Complete once §13.3 is enforced; §4.7 alone is not sufficient. |
| Verification-time tracking | Offline by default; double opt-in and §13.4 for any fetch. | Complete for locators **and** for the `forge` anchor's key fetch, which §13.4 covers explicitly. |

### 13.2 Not defended, stated plainly

- **Sidecar stripping.** A removed sidecar is indistinguishable from a file that never had
  one. No design in the field solves this; the partial mitigations (watermarking,
  fingerprinting, hosted repositories) work only for perceptual media and require network
  access.
- **Replay.** A record carries no nonce and no required timestamp, and `producedAt` raises
  nothing (§10.6). A valid record can therefore be re-presented alongside a different
  production run of byte-identical output, and a verifier cannot tell the two apart. It is
  bounded rather than solved: because the subject digest is inside the signed payload, a
  replayed record can only ever be attached to the **same bytes** it was made for.
  Deployments that care about *when* must attach a verified time anchor, which moves `time`
  to `externally-anchored` and makes a stale record visible.
- **Parent substitution on unpinned edges.** `componentOf` and `inputTo` edges may omit
  `statementDigest` (§6.2), because an input is often a file nobody signed. On such an edge,
  an attacker who publishes their own record about the same input digest can present
  themselves as its provenance. The verifier reports `lineage: declared` and names the
  unpinned edge in `not_checked[]`; it cannot detect the substitution.
- **A dishonest producer.** Every field in `declared[]` can be a lie. `attribution:
  self-asserted` is the machine-readable statement of that fact, and it is the only value
  reachable for the overwhelming majority of records today.
- **Chain truncation and equivocation.** A signer can present whichever of two internally
  valid chains suits them, and can drop trailing history. A transparency receipt over the
  earliest statement is the only known answer and is not required by this version.
- **Key compromise between trust-root refreshes.** Offline verification cannot see a
  revocation. This is the same hole GitHub documents for `gh attestation verify`.
- **Key rotation.** Rotating an SSH key silently invalidates the history signed under the old
  one, unless a time anchor exists to establish that the signature predates the rotation.
  Sharper than it first reads: `allowed_signers` offers `valid-after=` and `valid-before=`,
  which are the correct mechanism — and they are **inert without a verified time anchor**.
  Since `time: unanchored` is the default and near-universal state (§10.6), the one
  rotation-safe control the chosen backend provides does not function in the default
  deployment.
- **Anchor freshness.** The result says which *kind* of anchor answered, not how old it was.
  An `allowed_signers` file last edited years ago and one edited this morning are
  indistinguishable in the output.
- **A compromised producer environment.** §13.2's dishonest producer lies deliberately. An
  honest producer whose signing key is reachable by the process it is attesting is a
  different and, for the stated agentic use case, more likely failure: the agent and the key
  live on the same machine. SCPE records what a key signed; it cannot know what persuaded
  the key to sign.
- **Anyone may make a record about anyone's file.** Monotonicity guarantees this permanently
  (§1.3). An attacker can sign `digitalSourceType: trainedAlgorithmicMedia` over a
  human-authored photograph, anchor it to their own key, and leave the sidecar beside it.
  The verifier will correctly report a valid signature and a *declared* AI-generation claim;
  whether a reader is misled depends entirely on how prominently the renderer shows
  `anchor` and `declared[]`.
- **Signature-suite strength.** `signature: valid` reads identically for every allowlisted
  suite. There is no way to express "valid, under a suite you should stop accepting."

### 13.3 Denial of service, and the limits that bound it

Every count in a record is chosen by its author, and several drive work: `signer[]` and
`signatures[]` drive subprocess spawns, `derivedFrom[]` drives traversal fan-out, and bundle
lines drive both. A verifier **MUST** enforce a bound on each of the following and **MUST**
refuse with `malformed-input` rather than degrade:

| Bound | RECOMMENDED |
|---|---|
| Sidecar size | 4 MiB |
| Bundle lines | 64 |
| Single line | 1 MiB |
| `signatures[]` per envelope | 8 |
| `signer[]` per predicate | 8 |
| `subject[]` per statement | 64 |
| `derivedFrom[]` per predicate | 64 |
| Total statements resolved during traversal | 256 |
| Chain depth | 32 |
| JSON nesting depth | 64 |
| Any single string in `declared[]` | 1 KiB |

A verifier **MUST** refuse a non-regular file as an artifact — a device node, a FIFO or a
symlink to one — rather than reading it. Hashing `/dev/zero` is not a verification.

### 13.4 Network safety

**A conforming verifier performs no network I/O by default** (§12.3). This section governs
the only paths that can ever perform it, and it applies to **both** the dereferencing of a
locator carried inside a record (§6.4) **and** the `forge` anchor's key retrieval (§10.4) —
the latter is a fetch even though no locator came from the record.

When a fetch is enabled, a verifier **MUST**:

- use **HTTPS only**, and refuse any other scheme outright, including `file:`, `http:` and
  anything unrecognised;
- validate the TLS certificate chain **and** the hostname; a validation failure is a fetch
  failure, never a downgrade;
- **refuse redirects entirely.** A 3xx response is a fetch failure. A redirect that is
  followed is a second fetch to a host the operator never allowed;
- re-check the final URL's host against the allowlist after the request completes;
- reject a URL carrying userinfo (`https://allowed.example@attacker.invalid/`), a
  non-default port, or a path that is not a single safe segment;
- bound the response size, the request count and the wall-clock timeout, and treat exceeding
  any of them as a fetch failure;
- print the exact host list **before** contacting anything.

`--allow-host` constrains the **host and nothing else**. Every other component of a URL in a
record is attacker-controlled, and this section exists because the retired `scpe/0.1`
carried no hostname, URL, scheme, port or path in its manifest at all — an invariant that
in-toto's `ResourceDescriptor` (§4.3) gives back to the attacker the moment a locator is
dereferenced. The default remains: **do not dereference.**

---

## 14. Versioning

`scpeVersion` is a single integer. There is no minor version.

**Adding a recognised `predicateType` alias, a signature suite, a digest algorithm, an
`evidence[]` kind, a vocabulary term, or an OPTIONAL field is additive** and does not change
the version.

**Changing the meaning of an existing field, removing a field, changing the signed-byte
construction, or altering a facet's computation is a version change,** and old verifiers
refuse the new version with `unsupported-version` rather than misreading it.

The signing construction (§4.2) is versioned by DSSE, independently of `scpeVersion`. A
change to this specification therefore **does not** invalidate existing signatures.

---

## 15. Interoperability

Interoperability is a feature of this design, not an afterthought, and it runs in three
directions.

### 15.1 Verifiable by tools nobody had to write

Because the record is a plain DSSE envelope carrying an in-toto Statement, an SCPE record's
**envelope signature** is verifiable today by generic in-toto tooling that has never heard of
SCPE. Such a tool reports a valid signature over a subject digest and an **unrecognised
predicate type** — it does not, and must not be described as, verifying the SCPE claim
itself. That degradation is the intended behaviour, not a shortfall: an unknown predicate
should read as unknown.

### 15.2 Import — reading other stacks as lineage

| Source | Read as |
|---|---|
| A C2PA manifest (embedded or `.c2pa`) | A derivation edge, with `digitalSourceType`, `c2pa.ai-disclosure` and ingredient relationships carried into `declared[]`. |
| A Sigstore bundle / in-toto attestation | An `evidence[]` entry and, where a subject digest matches, a derivation edge. |
| An OMS `.sig` | An `inputTo` edge naming the model weights. |
| An OpenTimestamps `.ots` | A time anchor, raising `time` **only if verified**. |

Reading an Anthropic-signed C2PA image as an input edge is the day-one demonstration, and it
is the only path by which `attribution: provider-attested` is reachable with real files
today.

**Import pulls attacker-controlled parsing inside the trust boundary.** Any importer
**MUST** run outside the core verifier's stdlib-only footprint, **MUST** be optional, and its
output **MUST** enter as `declared[]` and `present-unverified`, never as `proved[]`.

### 15.3 Export

| Target | Mapping |
|---|---|
| SLSA VSA (`https://slsa.dev/verification_summary/v1`) | The verification result, with the policy as a ResourceDescriptor and `inputAttestations` naming every record consumed. |
| OpenTelemetry GenAI spans | `generation.*` → `gen_ai.*`, `run.traceParent` → trace context. |
| Agent Trace 0.1.0 | Code subjects, as the signed carrier of a record it does not sign itself. |
| C2PA custom assertion | `org.scpe.*` inside a `.c2pa` sidecar, where a certificate is available. |

The verification result **SHOULD** be emitted as a SLSA VSA in addition to SCPE's own shape,
because VSA is the verdict format that will still exist in five years.

**The mapping tables in `docs/mapping/` MUST be generated from the same source that drives
the adapters,** so that drift against an upstream release is a test failure rather than a
documentation bug.

### 15.4 Composition — letting others sign us

An SCPE record is a file, so anything that signs files can sign it: `cosign sign-blob` over
the sidecar, an OpenTimestamps `.ots` beside it, registration with a SCITT Transparency
Service with `sub` set to the statement digest. Each is recorded as `evidence[]` and is
`present-unverified` until the verifier checks it.

This requires **no format change, ever**, which is why it is the answer to "what happens when
a new trust root arrives."

---

## 16. Retired: `scpe/0.1`

`scpe/0.1` — the `manifest.json` + `manifest.sig` envelope, the zip container, the
attestation-in-pull-request-body transport, the `code-change` subject type and the eight
profiles — is **retired**. There is no migration path.

A conforming `scpe/1` verifier presented with a `scpe/0.1` envelope **MUST** return
`unsupported-version` with a message naming the retired version, and **MUST NOT** attempt to
read it.

The decision, its evidence and the objection raised against it are recorded in
[ADR 0001](../docs/adr/0001-from-pull-requests-to-generation-events.md).

---

## 17. References

**Normative**
- DSSE — envelope v1.0.2, protocol v1.0.0 — `secure-systems-lab/dsse`
- in-toto Attestation Framework v1.2.0 — Statement, ResourceDescriptor, DigestSet, Bundle
- RFC 2119, RFC 8174 — requirement levels
- RFC 3339 — timestamps
- RFC 8259 — JSON
- RFC 9901 — SD-JWT (selective disclosure construction)
- IPTC DigitalSourceType NewsCodes
- C2PA Technical Specification 2.4 — `c2pa.ingredient.v3` relationships,
  `contentProfile.humanOversightLevel`, `http://c2pa.org/digitalsourcetype/trainedAlgorithmicData`
- OpenTelemetry GenAI semantic conventions — `gen_ai.provider.name`, `gen_ai.response.model`
- W3C Trace Context — `traceparent`
- PROTOCOL.sshsig, `ssh-keygen -Y sign`/`-Y verify`, `allowed_signers`

**Informative**
- RFC 8725 §3.1 — algorithm allowlisting
- RFC 9942 — COSE Receipts · RFC 9943 — SCITT architecture
- RFC 9964 / FIPS 204 — ML-DSA
- SLSA v1.2 — Verification Summary Attestation, provenance distribution
- OpenSSF Model Signing v1.0
- arXiv 2604.24890 — independent security analysis of C2PA
- [../docs/standards-landscape.md](../docs/standards-landscape.md) — the survey this
  specification is built on
