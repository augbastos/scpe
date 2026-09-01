# The provenance standards landscape

**Survey date: 31 August 2026.** Every claim below was fetched from a primary source — a
specification, an RFC, a reference implementation's source code, a changelog, or a
machine-readable conformance list — not from secondary commentary. Sources are listed per
section and consolidated at the end. Where a fact contradicts what this project previously
believed, it is flagged.

This document exists because of a single question: **what genuinely useful layer could SCPE
provide that is not already solved better by an established standard?** Answering it
required establishing what is actually shipped, not what is commonly assumed. Several
things this project believed to be open are closed. They are marked **OCCUPIED** below.

A companion, shorter, marketing-adjacent comparison lives in
[comparison.md](comparison.md). This document is the evidence; that one is the summary.

---

## 0. How to read this

Provenance is not one problem. It is at least seven, and most confusion in this space comes
from a standard that solves one being criticised for not solving another:

| # | Problem | Question it answers |
|---|---------|---------------------|
| 1 | **Integrity** | Have these bytes changed since they were signed? |
| 2 | **Authenticity** | Which key signed them? |
| 3 | **Identity** | Who or what does that key represent, and who says so? |
| 4 | **Attestation** | What did a party *claim* about these bytes? |
| 5 | **Lineage** | What did these bytes come from, and through what operation? |
| 6 | **Transparency** | Can a third party detect that this claim was made, and when? |
| 7 | **Authorship / truth** | Is the claim *true*? Did an AI really write it? |

**Nothing in this document solves #7, and nothing can.** Every standard surveyed here is a
record of an assertion by a signer. Its truth rests entirely on the signer's honesty. This
is not a limitation SCPE gets to fix by being cleverer; it is the shape of the problem. The
strongest published statements of this discipline belong to the incumbents, not to us —
see §11.

---

## 1. C2PA / Content Credentials — Technical Specification 2.4 (April 2026)

**Status.** 2.4 is current; `spec.c2pa.org/specifications/` redirects to the 2.4 index and
there is no 2.5. Predecessors: 2.3 (Dec 2025), 2.2 (May 2025), 2.1 (Sep 2024). Supporting
current documents: CAWG Identity Assertion 1.2 (ratified 2025-12-15), the C2PA Conformance
Program (program version 0.2 issuing; the Interim Trust List was frozen and retired
2026-01-01), and Content Credentials Deployment Guidance 1.0 (2026-07-08). Reference
implementations as of 2026-08-27: `c2pa-rs` 0.90.16, `c2patool` 0.27.16, `c2pa-python`
0.37.8.

**Envelope.** `COSE_Sign1` over a CBOR-encoded *claim*, wrapped in JUMBF boxes
(ISO/IEC 19566-5) forming a Manifest Store. Assertions live in an assertion store; the
claim references each by hashed URI, so the signature covers the assertion set by hash
rather than by inclusion. Hash allow-list is exactly SHA2-256/384/512 — SHA-3 is excluded
for COSE alignment, and implementations "shall not support additional algorithms on an
optional basis." Signature allow-list: ES256/384/512, PS256/384/512, Ed25519. There is no
JSON canonicalization scheme; binding is structural (declared-length CBOR byte strings,
JUMBF box layout, byte-range and box-range hashing). Trusted time via RFC 3161 TSA against
a separate TSA trust list. Revocation via OCSP responses carried inside the manifest.

**Artifact scope — this is where the common assumption is most wrong.** The glossary
defines an asset as "a file or stream of data containing digital content," extended
explicitly "to include cloud-native and dynamically generated data." The asset-type
vocabulary (§18) already covers `c2pa.types.dataset.{pytorch,onnx,tensorflow,jax,keras,…}`,
~25 `c2pa.types.model.*` framework identifiers, `c2pa.types.format.{numpy,pickle,protobuf}`,
and `c2pa.types.generator{,.prompt,.seed}`. §9.2.1 states that the `c2pa.hash.data` hard
binding "can be used on any type of asset." §18.8 `c2pa.hash.collection.data` binds a whole
directory of files by relative URI plus per-file hash, with a note naming "each folder of
the training data set of an AI/ML model" as an intended use.

**Detached sidecars are normative-ish and shipped.** §11.4 permits an external manifest for
any asset, and §11.3 states that formats which cannot carry arbitrary data *require* one.
Media type `application/c2pa`. §15.5.3.1 gives a discovery order: HTTP `Link
rel=c2pa-manifest` header → XMP `dcterms:provenance` → font C2PA table URI → "the validator
should look for files at the same path or URI, but with a filename extension of `.c2pa`" →
implementation-defined.

**The finding that matters most to this project.** `c2pa-rs` CLI CHANGELOG, version
0.26.46, released **08 April 2026**: *"Allow any file type to be signed with a sidecar"*
(PR #2014). Its constraint text: `no_embed must be true and remote_urls are not allowed for
unsupported formats`. Before that PR the format list was closed; after it, the list governs
*embedding only* and sidecar signing is format-agnostic. Confirmed in the SDK source, not
just the changelog: in `sdk/src/store.rs::start_save_stream` the no-format-handler branch
comments read *"No format handler — only sidecar mode (no_embed=true, no remote URL) is
allowed"* and *"Sidecar: output is a verbatim copy of the input; JUMBF is returned as
sidecar data"*; `Builder::hash_type("application/octet-stream")` falls back to
`HashType::Data`; and `Reader::with_manifest_data_and_stream(c2pa_data, format, stream)`
accepts an arbitrary format string for detached verification.

**Lineage is first-class and typed.** `c2pa.ingredient.v3` carries
`relationship: parentOf | componentOf | inputTo`, where `inputTo` means "used as input to a
computational process, such as an AI/ML model." Each ingredient carries `activeManifest` and
`claimSignature` hashed URIs to its own manifest, plus `validationResults`, `dataTypes` and
`softBindingsMatched`. `c2pa.actions` carries the verbs, each cross-linked by hashed URI to
its ingredient, and validators *enforce* the cross-link
(`assertion.action.ingredientMismatch`). A manifest may have at most one `parentOf`
ingredient (`manifest.multipleParents`). Update Manifests record metadata-only changes with
exactly one `parentOf` and no hard binding; validators walk the `parentOf` chain back to the
first standard manifest to find the governing binding.

C2PA also documents an honesty constraint that any chain design must confront: an
ingredient's own hard binding **cannot be re-verified downstream**, because the ingredient's
bytes are not carried. The parent records a *point-in-time* `validationResults` snapshot
instead. `allActionsIncluded` flags whether the action list is complete.

**AI semantics are deeper than assumed.** `digitalSourceType` is *mandatory* on every
`c2pa.created` action, drawn from the IPTC DigitalSourceType NewsCodes vocabulary
(`trainedAlgorithmicMedia`, `compositeWithTrainedAlgorithmicMedia`, `compositeSynthetic`,
`digitalCapture`, `humanEdits`, `digitalCreation`), plus two C2PA-minted terms:
`http://c2pa.org/digitalsourcetype/empty` and
`http://c2pa.org/digitalsourcetype/trainedAlgorithmicData`, the latter existing specifically
because "the result isn't a media type … but is a data format (e.g., CSV, pickle)."

New in 2.4: the `c2pa.ai-disclosure` assertion, carrying `modelType` (~25 framework
identifiers), `modelIdentifier` as a PURL
(e.g. `pkg:huggingface/meta-llama/Llama-2-70b-chat-hf@main`), `scientificDomain` (arXiv
taxonomy), and `contentProfile.humanOversightLevel` ∈ {`fully_autonomous`, `prompt_guided`,
`human_validated`}. Also new in 2.4: `digitalSourceType` may appear on an ingredient with no
manifest of its own. Fields `modelFrontier`, `trainingCleared` and `harmEvaluation` are
present but commented out pending definition.

**2.4 signs source code.** Appendix A.9 defines an OpenPGP-style ASCII-armour block —
`-----BEGIN C2PA MANIFEST----- … -----END C2PA MANIFEST-----` — for Python, JavaScript, SQL,
C, YAML, TOML, INI, Markdown, AsciiDoc, LaTeX and XML, with front-matter and shebang-aware
placement, deliberately designed for "format-agnostic discovery: a validator reads the first
and last lines of the file." Comment-less formats such as `text/csv` are excluded.

### Where C2PA is actually weak

These are the honest gaps, and they are ecosystem and assurance gaps, not format gaps:

- **The certified fleet is a media fleet stuck on 2.2.** Of 174 conformant products
  (153 generator, 21 validator), generate-format declarations are overwhelmingly
  `image/jpeg` (124), `image/png` (94), `video/mp4` (85). Exactly **one** declares plain
  text; exactly **one** declares ML formats; two declare `.docx`; **zero** declare source
  code, JSON, CSV or arbitrary binaries. **166 of 174** declare specVersion 2.2 only — so
  the 2.4 features most relevant here are essentially unimplemented in certified products.
  146 sit at `maxAssuranceLevel` 1; only 7 reach level 2 (hardware-backed keys).
- **`c2patool` is less capable than the SDK it wraps.** `reader_from_args` bails with
  "Format for {:?} is unrecognized" when `--external-manifest` is used on an unknown
  extension, and `Builder::sign_file` returns `Error::UnsupportedType` for any extension
  outside a hardcoded MIME table (`sdk/src/utils/mime.rs`) that has no entry for `.py`,
  `.json`, `.csv`, `.parquet`, `.bin`, `.zip` or `.safetensors`.
- **The trust root is a gate, though a cheaper one than in 2025.** Claim-signing certs
  require the Conformance Program plus a trust-listed CA (DigiCert, SSL.com, Tauth Labs,
  Trufo). The live trust list PEM carries 30 anchors. Since June 2026 SSL.com offers a free
  tier: one Level-1 claim-signing certificate per year plus 10,000 timestamps. "Individuals
  are locked out of C2PA" is a materially weaker argument in 2026 than it was in 2025.
- **Certificate expiry silently kills verifiability.** Level-1 certs are commonly one year;
  the first independent security analysis flags that signed media "become unverifiable
  within months," against 22–25-month legal retention needs.
- **The first independent security analysis is damning.** arXiv 2604.24890 (2026-04-27;
  Golaszewski, Krawetz, Sherman et al., with formal-methods analysis) concludes "the current
  C2PA specifications fail to achieve their claimed security goals" and advises against use
  in financial disclosures, journalism or legal evidence. Concrete findings: timestamps not
  covered by the signed data (removable or replaceable undetected); optional revocation
  checking, with conforming validators accepting known-compromised credentials; validator
  disagreement on the same file; and hash exclusion ranges permitting undetected GPS and
  metadata edits, demonstrated on a Pixel 10 Pro image.
- **No transparency log anywhere,** and blockchain is explicitly rejected. The 2.4
  `c2pa.repository-receipt` assertion gestures at one but leaves its proof format
  "repository-specific."
- **JUMBF/CBOR/COSE is heavy.** A from-scratch verifier is a serious project. `crJSON` (new
  in 2.4) is explicitly "a derived view … not independently verifiable."
- **No cryptographic sidecar *discovery* guarantee.** `<path>.c2pa` is a *should*, ordered
  last. A renamed file silently loses its credential; only the byte-level hard binding
  survives, which is correct but unhelpful for discovery.

---

## 2. in-toto Attestation v1.2.0 + DSSE v1.0.2

**Status.** in-toto/attestation v1.2.0 (2026-03-18). DSSE envelope spec v1.0.2 (2024-05-10),
protocol v1.0.0; the repo became a formal Working Group under Community Specification
License 1.0 in July 2026, with the scope document rewritten 2026-07-20. **Any pre-2026
mental model of DSSE as a frozen artifact is stale.**

**DSSE solves exactly one thing:** sign an arbitrary byte string together with an
unambiguous declaration of what those bytes mean, without canonicalization, and let N
parties sign the same thing.

```
{"payload": base64(SERIALIZED_BODY), "payloadType": "<TYPE>",
 "signatures": [{"keyid": "…", "sig": base64(SIG)}]}
```

The signing input is PAE (Pre-Authentication Encoding):

```
PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
Signature       = Sign(PAE(UTF8(PAYLOAD_TYPE), SERIALIZED_BODY))
```

`SP` is ASCII 0x20; `LEN()` is ASCII decimal with no leading zeros.

**Why PAE exists** (from DSSE's `background.md`), because this is the argument SCPE's own
[design-decisions.md §2](design-decisions.md) already made independently: (1) *practical* —
canonical JSON forces payloads to be JSON-convertible, so binary formats are impossible;
(2) *theoretical* — two semantically different payloads could share a canonical encoding,
and historical canonicalization schemes "have failed catastrophically"; (3) *operational* —
canonicalization forces the verifier to **parse the payload before verifying the
signature**. `payloadType` is inside the signed data specifically to prevent cross-protocol
confusion.

Hard rule, stated in both `envelope.md` and `protocol.md`: *"implementations MUST ensure
that the same SERIALIZED_BODY that is verified is the same sent to the application layer."*
Do not re-parse after verification.

**Multi-signature is first class.** "An envelope MAY have more than one signature, which is
equivalent to separate envelopes with individual signatures." A (t,n) envelope verifies when
at least t of n *unique* trusted keys verify. in-toto's `envelope.md` makes multi-signature
support **mandatory**.

**in-toto Statement** binds typed metadata to artifacts identified purely by digest:

```json
{"_type": "https://in-toto.io/Statement/v1",
 "subject": [{"name": "…", "digest": {"sha256": "…"}}],
 "predicateType": "<URI>",
 "predicate": {…}}
```

Every subject element MUST carry a digest. "Subject artifacts are matched purely by digest,
regardless of content type." Semantics are up to producer and consumer. Subjects may be
files, git objects (`gitCommit`/`gitTree`/`gitBlob`/`gitTag`), directory trees (`dirHash1`),
or — explicitly permitted — non-cryptographic immutable identifiers when hashing is
infeasible.

**ResourceDescriptor** is the universal reference type:
`{name?, uri?, digest?, content?, downloadLocation?, mediaType?, annotations?}`, at least one
of uri/digest/content set. `content` permits **inline bytes** (recommended <1 KB), so a
descriptor can *be* the thing rather than point at it. `annotations` is the sanctioned
free-form extension point.

**The monotonic-policy principle**, from `spec/v1/README.md`: policies MUST be monotonic —
"ignoring an attestation … will never turn a DENY decision into an ALLOW." Attestations can
only *add* claims. Absence is never provable. This is the formal version of "never claim
more than a signature can prove," and it is a **permanent inherited limit**: a stack built
on it can never express "this file is *not* AI-generated" or "nothing else happened to it."

### Where in-toto/DSSE is weak

- **No asserter identity in the data model.** DSSE `keyid` is "an optional, unauthenticated
  hint" that "MUST NOT be used for security decisions." The Statement has no issuer field.
  DSSE puts PKI, trust roots and key management explicitly out of scope. Every real
  deployment reinvents identity carriage: Sigstore wrapped DSSE in its own Bundle protobuf
  to carry `verificationMaterial`; SLSA smuggles it into `runDetails.builder.id`; SCAI uses
  `predicate.producer`. **There is no shared field name for "who said this."**
- **No algorithm identification and no negotiation, by explicit scope decision.** The
  envelope does not say how it was signed. Offline verification always needs out-of-band
  knowledge of key *and* algorithm.
- **No timestamp, no expiry, no revocation, no verification material.**
- **Derivation chains are not modeled at all.** No chain object, no parent pointer, no
  ordering, no traversal spec. A chain exists only where attestation A's `subject` digest
  reappears in attestation B's `materials`/`resolvedDependencies` and someone joins them.
  That is literally why GUAC exists.
- **Bundles are unauthenticated as a whole** — no signature over the set, no uniqueness
  constraints, order MUST NOT matter. "Here is the complete provenance chain" is
  structurally unattestable.
- **DigestSet matching is OR, not AND.** "Two DigestSets SHOULD be considered matching if
  ANY acceptable field matches." Including a weak algorithm hands the verifier a downgrade
  unless it filters. Counterintuitive for anyone assuming multi-hash means stronger.
- **The Statement layer is JSON-only in practice** (`application/vnd.in-toto+json`), so no
  compact binary sidecar without leaving in-toto. DSSE alone would permit CBOR or protobuf.
- **The mental model assumes CI.** There is nothing ergonomic for one person on a laptop
  producing one artifact.
- **No sidecar discovery convention** for an arbitrary loose file. Conventions exist for
  bundles (`.intoto.jsonl`, media type `application/vnd.in-toto.bundle`), per-step files
  (`<step-name>.<keyid[0:8]>.json`) and OMS (`.sig`) — but given bytes on disk, nothing
  tells you where the attestation lives.

**Registered predicates** as of 2026-08-31: cyclonedx, link, provenance (SLSA), reference,
release, runtime-trace, scai, spdx, spdx2, spdx3, svr, test-result, vsa, vuln, vulns_02.
**There is no predicate for "this artifact was generated by an AI model."**

**The registry is being colonised right now.** Open, unmerged:

| Issue/PR | Opened | What it proposes |
|---|---|---|
| **#244** "Attestation for AI-assisted code" | 2023-06-03, **last activity 2023-07-10** | Exactly this project's premise: SBOM-level "AI-assisted" flags lack granularity; you cannot tell which code segments were machine-generated. **Three years dormant.** |
| #554 "RFC: agent-decision/v0.1" | 2026-05-19 | `agent_id`, `principal{subject, spiffe_id}`, `policy_evaluations[]`, `tool_calls[{name,args_hash}]`, `decided_at`, optional `trace_parent`. **No maintainer response.** |
| #565 / #575 eval-result | 2026-07-03 / 07-23 | Signed offline-verifiable eval results, dataset/model commitments, Merkle roots. |
| #588 "AI Agent Action predicate v0.1" | 2026-08-19, updated 08-30 | Protocol-layer attestation of agent tool calls observed by gateways/proxies. Uses a **genesis-record hash as a stable chain identifier and a hash-chain for ordering + completeness** — a rival, more rigorous chain model. Its motivation is a sharper version of our own threat model: *"Application logs are insufficient for auditing because the entity writing the log is the same entity whose behavior needs verification."* |
| #591 "AI Agent Decision predicate" | 2026-08-29 | — |

Four AI predicates in four months, none merged. **The window is open and closing.**

---

## 3. SLSA v1.2 (24 November 2025)

Two tracks: Build (L0–L3) and Source (L0–L3 plus a Two-Party Review property). Note the
asymmetry — there is **no Build L4**. The attestation layer is in-toto v1 + DSSE, with
Sigstore as the de-facto identity layer.

Predicate `https://slsa.dev/provenance/v1` — the URI intentionally never changes across
minor versions, so **version-sniffing the URI tells you nothing**. Two halves:
`buildDefinition{buildType, externalParameters, internalParameters, resolvedDependencies[]}`
and `runDetails{builder{id,version,builderDependencies}, metadata{invocationId, startedOn,
finishedOn}, byproducts[]}`.

**Determinism was never required**, and v1.2 actively *demoted* reproducibility to an
optional verified property (`SLSA_BUILD_REPRODUCED`). The assumed blocker for "a generation
event is a build" does not exist. The naive mapping is legal: `buildType` = a generation-task
TypeURI; `externalParameters` = prompt, system prompt, temperature, top_p, seed, tool config;
`internalParameters` = serving-stack details; `resolvedDependencies` = model-weights digest,
retrieved documents, input files; `builder.id` = the inference endpoint;
`metadata.invocationId` = the request id; `byproducts` = token counts, logprobs, safety
verdicts; `subject` = the output bytes. Nothing in the schema breaks.

**What breaks is the level ladder, not the predicate.** L2 requires a hosted build platform
that generates and signs provenance itself; L3 requires strong tenant isolation. A model run
on a laptop, or self-attested by the party that produced the artifact, is permanently capped
at **L1 — "provenance exists."** For "an AI generated this PDF on my machine," SLSA's entire
grading apparatus collapses to its least interesting rung.

**v1.2 opened two extension points** that are directly relevant: Provenance became an
umbrella concept — "the different SLSA tracks may have their own, more specific,
implementations of provenance" — and **Verified Properties** provide a sanctioned slot for a
control that "doesn't fit neatly within existing SLSA levels," so you need not mint a track.

**VSA** (`https://slsa.dev/verification_summary/v1`) is the delegation primitive: a signed
record *of a verification*, carrying `verifier{id,version}`, `timeVerified`, `resourceUri`,
`policy` (uri+digest), `inputAttestations`, `verificationResult` PASSED/FAILED,
`verifiedLevels`, `dependencyLevels`, `slsaVersion`. A thin client verifies one signature
and reads one verdict instead of walking a graph.

**Sidecar distribution is specified, not improvised.** `/spec/v1.2/distributing-provenance`:
"for an artifact `<filename>.<extension>`, the attestation is `<filename>.attestation`" or
`.intoto.jsonl`; "attestations SHOULD be bound to artifacts, not releases"; "attestations
SHOULD be immutable."

**Offline verification is a shipped product, not a research goal:**
`gh attestation download` → `sha256:<hash>.jsonl`; `gh attestation trusted-root` → key
material; `gh attestation verify --bundle … --custom-trusted-root …` inside an air gap.
GitHub's own honest caveat, which any offline design inherits verbatim: *"You will not know
if key material has been revoked since you last generated the trusted root file."* Sigstore
rotates key material several times per year.

**As of 2026-08-31 there is no AI/ML track and no AI item on the roadmap.** Current
activities are the Build Environment track and the Dependency track only. No blog post, no
predicate, no `model.id`, no prompt, no sampling parameters, no human-oversight field
anywhere in SLSA or the vetted in-toto set.

**The load-bearing lesson.** The May 2026 post-mortem of the Mini Shai-Hulud npm worm states
it flatly: compromised packages shipped with cryptographically **valid** SLSA provenance.
*"Build platforms can accurately record what ran within their trust boundary, but they
cannot vouch for whether what ran produced an uncompromised artifact"* — *"A signed artifact
is not necessarily a trustworthy one."*

**Weaknesses.** No first-class derivation edge — `resolvedDependencies` is an *unordered*
collection with only best-effort completeness even at L3, so it cannot distinguish "B was
produced FROM A" from "A happened to be present." No human or organisational asserter: the
signer *is* the asserter and is assumed to be a machine. Nothing survives byte-level
transformation. Trust-root staleness in the offline path is documented and unfixed.

---

## 4. Sigstore

cosign v3.1.3 (2026-08-06), Fulcio v1.8.8, Rekor v1 and Rekor v2 "rekor-tiles" v2.3.0,
protobuf-specs Bundle v0.3, sigstore-go v1.3.0, sigstore-python 4.5.0, sigstore-js 5.0.0.
Public-good instance operated by OpenSSF.

Sigstore is the identity and transparency layer the attestation stack declines to define:
keyless signing via OIDC → Fulcio ephemeral certificate (10 min) → Rekor transparency-log
entry. The **Sigstore Bundle** packs signature + certificate + inclusion proof + signed
timestamp into one file, which is what makes `--offline=true` verification work.
`cosign attest-blob` / `cosign verify-blob-attestation` do detached attestation over any
blob.

If a provenance project builds its own transparency log, it has lost before it starts.

---

## 5. SCITT — RFC 9943 and COSE Receipts — RFC 9942 (both June 2026)

**These are no longer drafts.** Any knowledge that says `draft-ietf-scitt-architecture` is
stale.

RFC 9943, *An Architecture for Trustworthy and Transparent Digital Supply Chains*
(Standards Track): a Transparency Service registers Signed Statements against Registration
Policies, appends to a Statement Sequence, and returns a Receipt. Signed Statement + Receipt
in the unprotected header = a Transparent Statement. Critically: *"It is universally
verifiable without online access to the TS."* Relying parties MAY verify only a Receipt they
trust and skip signatures over payload types they do not understand.

Envelope is `COSE_Sign1` (RFC 9052 / STD 96); the protected header MUST carry CWT Claims with
`iss` (label 1) and `sub` (label 2). **Detached payloads and hash-only signing are explicitly
permitted** for large or sensitive statements — which is exactly the shape needed for "any
bytes are the subject, and the bytes are not carried."

RFC 9942 standardises the Merkle inclusion, consistency and non-inclusion proof encoding.

**SCITT's structural gift, and its structural hole.** It is the only surveyed standard whose
data model natively supports *multiple independent issuers making statements about the same
subject over time* — "an Issuer can make multiple Statements about the same Artifact …
amended Statements … as their view changes over time." That is precisely "someone other than
the generator asserts something about this file later," as a first-class, transparent,
offline-verifiable act.

And it has **no derivation model whatsoever**. Flat statements about a subject. No edges.

---

## 6. OpenSSF Model Signing (OMS) v1.0

The closest existing thing to "a detached, offline-verifiable, file-agnostic signed sidecar
for AI artifacts" — and it is already shipped.

Mandates a Sigstore Bundle carrying a DSSE envelope carrying an in-toto Statement v1.
`payloadType` MUST be exactly `application/vnd.in-toto+json`; `predicateType` is
`https://model_signing/signature/v1.0`; predicate is `{resources, serialization}`. Model
files and shards are listed as descriptors in the **predicate's** `resources` array, **not**
as Statement subjects (shard syntax `filename:start:end`) — a deliberate deviation from
"subject = the artifact," because thousands of shards as subjects is unusable. Useful
precedent for how far the model bends and still gets accepted. SHA-256 default, BLAKE2b also
registered. The sidecar SHOULD carry a `.sig` extension. **Verification is normatively
offline — no external service calls are required.**

OMS supports **four PKIs behind one signature format**: bare keys, self-signed certs,
traditional CA, and Sigstore. That is the right abstraction for "do not force a trust root
on adopters," and it is the pattern any additional signer type should follow.

Its own scope statement is the line worth quoting: OMS covers integrity and authenticity
only; it does **not** define provenance lineage, model cards or metadata, and it notes
explicitly that signing verifies what exists, *"not the quality or fairness of model
behavior."*

It signs the model. **It never signs the model's output.** That inversion —
model-as-artifact versus model-as-generator — is the actual seam.

*Documentation drift worth knowing:* `sigstore/model-transparency`'s README says
`predicateType: https://model_signing/signature/v1.0` while `docs/model_signing_format.md`
shows `https://model_signing/Digests/v0.1` with a placeholder predicate literally containing
an `unused` field. The OMS spec is authoritative. Do not treat reference implementations as
spec.

---

## 7. The agent-identity cluster (2026)

This is a cluster, not a standard, and it solves three problems — none of which is artifact
provenance.

**Request-time actor authentication.** Web Bot Auth
(`draft-meunier-webbotauth-httpsig-protocol-02`, 18 Aug 2026, an *individual* I-D with no
IETF standing; the architecture draft is already marked Replaced) signs
`@authority`/`@target-uri`/`@signature-params` per RFC 9421, Ed25519, keys discovered via
`Signature-Agent` → `/.well-known/http-message-signatures-directory`, keyid = RFC 7638 JWK
thumbprint. Cloudflare verifies it in production; OpenAI signs ChatGPT agent traffic with
published keys. **"No component covers the body,"** and Cloudflare's documentation actively
discourages `Content-Digest` coverage. *The most-deployed agent signature standard of 2026
signs nothing about content, by design.*

`draft-klrc-aiagent-auth-03` (6 Jul 2026; OpenAI, AWS, Okta, Ping, Zscaler authors) builds on
IETF WIMSE and SPIFFE — `spiffe://<trust-domain>/<path>` as a stable, hierarchical,
offline-parseable agent identity, carried in a holder-of-key Workload Identity Token. NIST
CAISI's AI Agent Standards Initiative (17 Feb 2026) and the NCCoE concept paper (5 Feb 2026)
name OAuth 2.0/2.1, OIDC, SPIFFE/SPIRE, SCIM, NGAC and MCP as the load-bearing set. The 2026
consensus was **reuse existing IAM, do not invent agent identifiers.**

A2A v1.0 (Linux Foundation, 12 Mar 2026) signs AgentCards with JWS Compact Serialization over
JCS-canonicalized JSON, with `keyId`/`x5c`. It does **not** sign task Artifacts — `Artifact`
carries `parts` + `metadata` and no signature field.

MCP rev 2026-07-28 carries **no provenance, attestation or signing concept at all**. It is
stateless (the initialize handshake was removed), per-request `_meta`, OAuth 2.1 at
transport. Anyone assuming MCP will carry provenance is wrong.

**Attribution bookkeeping for code — the vocabulary half.** **Agent Trace 0.1.0**
(CC BY 4.0, canonical home `agent-trace.dev`; note that `github.com/cursor/agent-trace`
404s) is backed by **Cursor, Cognition, Cloudflare, Vercel, git-ai, Google Jules, Amp and
OpenCode**. Its model: `files[].conversations[].ranges[]` with `contributor{type, model_id}`
where type ∈ `human | ai | mixed | unknown`, and a position-independent `content_hash`
(e.g. `murmur3:9f2e8a1b`) so attribution survives code movement. Model names follow
models.dev `provider/model-name`. Storage is explicitly implementation-defined — "a data
specification, not a product."

**git-ai** (`authorship/3.0.0`, Apache-2.0, ~2.5k stars) stores notes under `refs/notes/ai`
keyed by commit, with `agent_id{tool,id,model}` and session keys, and solves the hard,
unglamorous part nobody else does: keeping attribution correct through rebase, merge,
cherry-pick, reset, stash and amend.

**Both have zero cryptography.** git-ai's own README: it "does not use AI or heuristics to
'detect' AI code — the Agents report exactly which lines they wrote." Accurate attribution,
zero authenticity. Any claim either carries is forgeable by editing a JSON file or a git
note.

**Observability vocabulary.** OpenTelemetry GenAI semantic conventions give vendor-neutral
names for provider, model, agent, workflow, conversation, tool and operation. **Trap:**
`gen_ai.system` is **deprecated**, renamed `gen_ai.provider.name` in semconv v1.37.0, and the
conventions were split into their own repo which currently has **no tagged releases** — so
pinning a vocabulary version is impossible today. Any field mapping written from memory will
be stale.

**What providers actually sign, as of 31 Aug 2026.** GitHub Copilot's cloud agent has signed
every commit since 3 Apr 2026 — probably the most widely deployed signature over
agent-produced artifacts — but the key is *GitHub's*, attesting "GitHub's agent made this
commit," not AI authorship and not the model. Anthropic began marking Claude output on
2 Aug 2026 under the EU AI Act Art. 50(2) Code of Practice: **C2PA-signed provenance metadata
on `.svg`/`.png`/`.jpg`**, plus a statistical text watermark whose public detection tooling
is still "forthcoming." Anthropic's own warning is the model for claim discipline: a detected
mark "is not fully conclusive," and absence of a mark proves nothing. Anthropic's
Confidential Inference work concedes the harder case is unsolved: the verifier cannot know
the weights, so it cannot recompute outputs to check them.

TEE inference receipts (Phala/RedPill, shipping via OpenRouter) are the strongest available
form: a response signed by a key generated inside the enclave, with a receipt binding
request-hash + response-hash to an attested workload. But that attests an **enclave
measurement, not weights** — "an attested workload emitted these bytes" is not "model X
produced this" — and it exists only at niche providers.

**The empirical argument for signed rather than conventional attribution.** VS Code enabled
the `Co-authored-by: Copilot` trailer by default on 16 Apr 2026 and **reverted it** after it
attached to commits made without Copilot, including installs with AI features disabled. A
documented false-attribution incident on the dominant unsigned mechanism.

---

## 8. The lineage camp — rich graphs, zero cryptography

- **W3C PROV-O.** Entity / Activity / Agent, with `wasDerivedFrom`, `wasGeneratedBy`,
  `wasAttributedTo`. Exactly the right data shape for derivation. **No crypto whatsoever.**
  Free to reuse; no committee to join.
- **OpenLineage 1.47.1** (May 2026; Airflow provider 2.18.1, Jun 2026). OpenAPI spec, custom
  facets, run/job/dataset events. No signing, no PROV-O mapping.
- **MLflow Model Registry.** Run ID, git commit, dataset hash, params per model version.
  Lineage without authenticity — the literature says so explicitly.

**The entire lineage half of this field is unsigned.** Nobody has signed PROV-O-shaped
derivation over arbitrary bytes with third-party asserters.

---

## 9. Adjacent, and deliberately out of scope

- **CycloneDX 1.7 ML-BOM** (ECMA-424 2nd ed., Oct 2025) and **SPDX 3.0.1 AI + Dataset
  profiles** describe what a *model* is made of. They do not bind to an output artifact. An
  AIBOM says what the model contains, not what this particular file is. Reference one by
  digest; do not restate it.
- **OCI Referrers v1.1 + `oras attach`** solve the same sidecar problem for registry-hosted
  artifacts, addressed by subject digest.
- **Hugging Face** is closing the model side quietly: `huggingface-hub` 1.29.0 carries
  sigstore transparency entries dated 27 Aug 2026.
- **OpenTimestamps** gives free, vendor-neutral, permanent Bitcoin anchoring as a `.ots`
  sidecar for any file, verifiable with a client and block headers alone — no account, no
  CA, no server trust. The cheapest credible anchor available.
- **nostr NIP-94** (kind 1063) has quietly carried a one-hop derivation hint for years:
  `x` = SHA-256 of the file as served, `ox` = SHA-256 of the *original* before server
  transformation. Schnorr-signed, key-identity, detached — and it outlived two upload
  protocols (NIP-96, Blossom).
- **Numbers Protocol / Capture / ProofSnap** ship a real dual-layer answer (embedded C2PA +
  ERC-7053 on-chain receipt) aimed at Art. 50 — but require a chain and a token.
  **Truepic** ($26.63M Series B, Sep–Oct 2025) owns the capture-side hardware root of trust.
  **AgenTrust TRACE v0.2** (launched 23 Jun 2026; Linux Foundation / AMD / Intel / Microsoft)
  and **Prova** require TEEs. All trade portability for a stronger claim.
- **TestifySec Witness + Archivista** (donated to in-toto under CNCF) wrap any command and
  emit attestation collections describing "what ran, what it consumed, what it produced" —
  the closest general transform record, scoped to CI/CD steps.

---

## 10. The regulatory frame

EU AI Act **Article 50** became applicable **2 August 2026** (grace to 2 December 2026 for
pre-existing systems). Its Transparency Code of Practice mandates a layered approach and
names, verbatim, *"provenance certificates for content where embedding is difficult"* as one
of the required layers.

The regulator has already written this lane into policy — and the presumed occupant is C2PA.
California SB 942 pushes the same direction.

---

## 11. "Not an AI detector" is the incumbent position, not a differentiator

This project has treated epistemic honesty as a distinguishing stance. It is not. It is
table stakes, and the incumbents state it better:

- **C2PA Explainer 2.4:** provenance "cannot tell you whether the digital content is true,
  accurate or factual"; "no assumption should be made about the trustworthiness of a
  particular asset purely based on its usage of Content Credentials." C2PA also explicitly
  refuses to become a two-tier ecosystem where unsigned means untrusted.
- **Content Credentials Deployment Guidance 1.0 (2026-07-08):** absence of credentials proves
  nothing — the file either was not created with a conformant tool, or the credentials were
  stripped in handling.
- **SLSA:** "A signed artifact is not necessarily a trustworthy one." "SLSA provenance
  records evidence. It answers *what happened?* Policy and verification answer *was that good
  enough?*"
- **OMS:** signing verifies what exists, "not the quality or fairness of model behavior."
- **Anthropic (2 Aug 2026):** a detected mark "is not fully conclusive," and absence of a
  mark proves nothing.
- **in-toto:** the monotonic-policy principle makes the negative claim structurally
  inexpressible.

Adopt this language. Cite it. Do not market it as an insight.

---

## 12. Clause-by-clause: what is occupied and what is open

The redesign thesis was *"a file-agnostic, cryptographically verifiable provenance envelope
for AI-generated artifacts, with first-class derivation chains, verifiable offline against a
detached sidecar."* Tested clause by clause against what shipped:

| Clause | Verdict | Who occupies it |
|---|---|---|
| File-agnostic | **OCCUPIED, twice** | in-toto digest-only subjects since v1; `c2pa-rs` CLI 0.26.46, 8 Apr 2026, "allow any file type to be signed with a sidecar" |
| Cryptographically verifiable envelope | **OCCUPIED** | COSE_Sign1 (SCITT, C2PA), DSSE+PAE (in-toto), Sigstore Bundle. A fourth is negative value. |
| The file (any bytes) is the subject | **OCCUPIED** | in-toto ResourceDescriptor; SCITT `sub` with detached/hash-only payloads; `c2pa.hash.data` |
| What generated it | **OCCUPIED** | `digitalSourceType` + `c2pa.ai-disclosure` (model PURL, scientific domain, human-oversight enum), C2PA 2.4 |
| What happened afterwards | **OCCUPIED** | `c2pa.actions` with per-action AI indicator + ingredient chains; Witness collections |
| Who asserts that | **OCCUPIED, and better** | C2PA trust list + CAWG; Sigstore keyless OIDC; OMS multi-PKI. Three substrates vs. one SSH-key idea. |
| Offline against a detached sidecar | **OCCUPIED** | `gh attestation verify --bundle --custom-trusted-root`; `cosign verify-blob-attestation --offline`; `c2patool --external-manifest`; RFC 9943 receipts "universally verifiable without online access" |
| Not an AI detector | **OCCUPIED AS PUBLISHED POSITION** | see §11 |
| **Derivation chains first class** | **PARTIALLY OPEN** | C2PA does it, signed, today (`parentOf`/`componentOf`/`inputTo`) — but only *inside C2PA*. SCITT has multi-issuer and **no edges**. in-toto/SLSA has materials and **no graph**. PROV-O/OpenLineage/MLflow have graphs and **no crypto**. |

**Five of six headline clauses are shipped by incumbents.** "File-agnostic" is not a
differentiator in 2026; it is table stakes.

### The seams that survived

Three, stated precisely:

1. **Generation-event semantics.** No registered predicate anywhere says *"model M, version
   V, provider P produced these bytes."* SLSA's `builder.id` models a build platform, not a
   generative model. OMS models the model as the **subject** — a signed weights file — never
   as the **agent** of another artifact's creation. That inversion is the actual gap.
   in-toto #244 asks for exactly this and has been untouched since 2023-07-10 — but #554,
   #565, #575, #588 and #591 all landed in the last four months.

2. **Cross-stack lineage stitching.** Each camp holds one half. C2PA has the best signed
   derivation graph in the field and it only works inside C2PA. SCITT has multi-issuer
   statements over time and no derivation model at all. in-toto/SLSA has materials and
   requires a downstream tool (GUAC) to build the graph. PROV-O, OpenLineage and MLflow have
   the right graph shape and no signatures. **Nobody has signed PROV-O-shaped derivation over
   arbitrary bytes with third-party asserters, and nobody does cross-stack lineage
   stitching.**

3. **Signing the trace.** Agent Trace has the vocabulary, an industry coalition (Cursor,
   Cognition, Cloudflare, Vercel, git-ai, Google Jules, Amp, OpenCode) and **explicitly
   declines the crypto half**. git-ai has the rebase-survival machinery and no cryptography.
   Competing with them would be a strategic error. The empty seam is signing what they
   already emit.

And a fourth, weaker but real: **non-CI ergonomics.** Every incumbent's tooling gravity is
package-ecosystem-shaped — npm, PyPI, OCI, cloud CI runners, public packages. There is no
document, no media, no desktop-file, no one-person-on-a-laptop story, and no consumer-facing
verification UX. `c2patool` refusing unknown extensions while its own SDK supports them is a
concrete, ~200-line instance of this.

### The four-way gap, stated as a table

Nothing in the surveyed field combines all four of:

| | (a) artifact as subject | (b) agent/model predicate | (c) signature | (d) derivation chain |
|---|---|---|---|---|
| in-toto / DSSE / SLSA | ✅ | ❌ | ✅ | ⚠️ digest-join only |
| C2PA 2.4 | ✅ | ✅ | ✅ | ✅ *(C2PA-internal only)* |
| SCITT | ✅ | ❌ | ✅ | ❌ |
| Agent Trace / git-ai | ⚠️ code lines only | ✅ | ❌ | ⚠️ one hop |
| Web Bot Auth / A2A / WIMSE | ❌ | ⚠️ actor only | ✅ | ❌ |
| PROV-O / OpenLineage / MLflow | ✅ | ⚠️ | ❌ | ✅ |
| OMS | ✅ *(model as subject)* | ❌ | ✅ | ❌ |

C2PA is the only row that fills all four — and it fills them behind a certificate gate, a
JUMBF/CBOR/COSE stack, an ecosystem that in practice signs JPEGs, and a spec whose first
independent security analysis says it fails its own goals.

---

## 13. What SCPE must not duplicate

Consolidated, and normative for this project's design work:

**Cryptography and serialization**
- The signing envelope. Use DSSE or COSE_Sign1.
- PAE, or any homegrown canonicalization. The whole point is that you never normalize and
  never parse before verifying.
- The no-re-parse rule. Inherit it; do not restate it in weaker words.
- Multi-signature and (t,n) threshold semantics.
- `keyid` semantics — do not invent a keyid that *is* trusted for security decisions.
- Digest algorithm registries, encodings, and the OR-matching rule for DigestSets.
- Signature algorithms. Nothing here calls for new primitives.

**Data model**
- `ResourceDescriptor` — `{name, uri, digest, content, downloadLocation, mediaType,
  annotations}`. Reuse verbatim for every artifact reference, including derivation edges.
- Subject identification by digest.
- Bundle packaging for grouping multiple assertions.
- Media-type and `payloadType` conventions.
- Unknown-field / forward-compatibility rules.
- The monotonic-policy principle — adopt the concept *and the name*.

**Vocabulary**
- The AI-origin taxonomy. IPTC `digitalSourceType` is governed, versioned and externally
  maintained. Minting a parallel enum in the year Article 50 becomes applicable is actively
  harmful to adopters.
- The derivation vocabulary. `parentOf` / `componentOf` / `inputTo` already covers
  derivation, composition and "used as input to an AI process." Do not invent a fourth word.
- Model/provider/agent/workflow attribute names — reuse OTel GenAI verbatim, and **not** the
  deprecated `gen_ai.system`.
- Agent and workload identifiers — reuse SPIFFE ID / WIMSE / OAuth `client_id`/`sub`.
- The lineage ontology — PROV-O already has Entity/Activity/Agent and
  `wasDerivedFrom`/`wasGeneratedBy`/`wasAttributedTo`.
- Line-range code attribution and its rebase survival — that is Agent Trace and git-ai.

**Infrastructure**
- A transparency log. RFC 9942 + RFC 9943 are published; Rekor is running.
- Keyless / short-lived-cert PKI. Sigstore solved it; OMS shows how to accept it as one of
  several signer types.
- Timestamping. OpenTimestamps is free and vendor-neutral; RFC 3161 TSAs are everywhere.
- A CA program or trust list. Consume C2PA's.
- Build/CI provenance semantics — SLSA owns
  `buildDefinition`/`runDetails`/`resolvedDependencies`/`byproducts`.
- Model-weight integrity signing — OMS owns it.
- A maturity-level ladder for CI hardening — SLSA has one; a parallel ladder fragments
  policy for no gain.
- Watermarking, fingerprinting and soft bindings — Adobe owns it, and it only works for
  perceptual media.
- TEE-attested execution — AgenTrust and Prova are there, with hardware this project does
  not have.
- Request-time agent authentication (Web Bot Auth) and agent-to-tool authorization (MCP).

**Rhetoric**
- The "not a detector" disclaimer as if it were an innovation. See §11.
- Any claim of *detecting* AI content. Nothing in this landscape can do it; Anthropic
  explicitly says its own marks are not conclusive. Keep it ruled out in the specification
  text, not only in the README.

---

## 14. Why SCPE should exist

The honest answer has to survive §12's table, so it starts by conceding everything that
table takes away.

**What is gone.** File-agnostic subjects, the verifiable envelope, detached offline sidecars
and the anti-detector ethic are all occupied, three of them by more than one incumbent. Any
version of this project that leads with those four is describing work other people finished.
The single sharpest fact: `c2pa-rs` CLI 0.26.46, 8 April 2026, *"Allow any file type to be
signed with a sidecar."*

**What is left is one sentence, and it is narrow on purpose:**

> **No registered predicate anywhere says "model M, at version V, from provider P, produced
> these bytes" — and the two ecosystems that could say it have each declined one half of the
> problem.**

That is not a rhetorical gap. It is structural, and it shows up the same way from three
directions:

- **OMS models the model as the *subject*** — a signed weights file — and never as the
  *agent* of another artifact's creation. SLSA's `builder.id` models a build platform, not a
  generative model. The inversion is the gap.
- **Agent Trace has the vocabulary and an eight-vendor coalition** (Cursor, Cognition,
  Cloudflare, Vercel, git-ai, Google Jules, Amp, OpenCode) and **explicitly declines the
  cryptographic half**. git-ai says so in its own README. Competing with them would be a
  strategic error; signing what they already emit is an empty seam.
- **in-toto has the substrate and no vocabulary.** Issue #244 asked this exact question on
  2023-06-03 and has been untouched since 2023-07-10.

**Demand is evidenced rather than assumed.** On 16 April 2026 VS Code enabled the
`Co-authored-by: Copilot` trailer by default and **reverted it** after it attached to commits
made without Copilot, including installs with AI features disabled. That is a documented
false-attribution failure on the dominant unsigned mechanism. Separately, EU AI Act Article
50 became applicable on 2 August 2026 and its Code of Practice names "provenance certificates
for content where embedding is difficult" as a required layer.

**The window is open and closing.** Five AI predicates were filed against the in-toto
registry in four months — #554 (May), #565 and #575 (July), #588 (19 Aug, updated 30 Aug),
#591 (29 Aug) — and none is merged. A queue that long is evidence the slot is the right one;
a queue moving that fast is evidence it will not stay empty.

### The second contribution, and the one a user actually touches

The predicate is what could become a standard. The **assurance reading layer** is what makes
it usable, and it is the one idea in this repository with no counterpart in the field.

`cosign` says PASS or FAIL against a policy you supplied. `gh attestation verify` says
verified. C2PA says Well-formed / Valid / Trusted — the closest anything comes, and still one
axis. Meanwhile the overwhelmingly common real case is:

> *identity X signed a statement saying model M made these bytes, and M signed nothing.*

That is a **notarized claim about a third party**, and no verifier in the field says it out
loud. Saying it out loud — as closed, computed facets, offline, on one screen, where every
input is an observation the verifier made and no self-declared field can raise a class — is
the product. This project's existing `key_source` is the seed of it, and it becomes *more*
important as trust anchors multiply, not less.

### What this is not

It is not a cryptographic contribution. Nothing here needs a new primitive, and inventing one
would be a defect. It is a **vocabulary and a verification-honesty layer**, which is
precisely the kind of contribution a solo maintainer can ship, defend and file upstream.

### The condition under which it should not exist

Stated plainly, because §35 requires it and because the previous version of this project
failed for want of this test:

**If the maintainer is unwilling to accept that SCPE is a vocabulary plus a verifier UX
rather than a protocol, then it should not exist**, and the correct action is to file the
predicate against in-toto #244 and stop. A pre-registered falsification test — five external
events that would each retire the project — is checked into
[adr/0001](adr/0001-from-pull-requests-to-generation-events.md#pre-registered-falsification-test).

---

## 15. Facts that contradict what this project previously believed

Recorded plainly, because several shaped earlier design decisions:

1. **"C2PA is media-only" is false and has been since April 2026.** `c2pa-rs` CLI 0.26.46
   (8 Apr 2026) allows any file type to be signed with a sidecar; the SDK's own comments
   confirm the code path. C2PA 2.4 additionally embeds into source code, YAML, Markdown and
   AsciiDoc.
2. **The exact envelope niche is already shipped** by OpenSSF Model Signing v1.0: detached,
   offline-verifiable, file-agnostic, DSSE + in-toto, `.sig` sidecar, zero network calls.
   Only the *semantics* were unclaimed; the plumbing is done.
3. **"No canonicalization" is standard practice, not a distinctive stance.** DSSE's PAE has
   made the same argument since 2021, and this project's own
   [design-decisions.md §2](design-decisions.md) already cites JWS and DSSE as the model —
   so adopting DSSE is *continuity*, not reversal.
4. **SCITT is published, not a draft.** RFC 9943 and RFC 9942, June 2026, Standards Track.
5. **The reputations are backwards.** SCITT — the general-purpose, artifact-agnostic,
   multi-issuer standard — has no derivation model at all. C2PA — the "media" standard
   assumed to be narrow — has the best signed derivation chain in the field.
6. **SLSA never required reproducible builds,** and v1.2 demoted reproducibility to an
   optional property. The assumed blocker for "a generation event is a build" does not
   exist.
7. **The C2PA certificate gate got cheaper, not more exclusive** — SSL.com's free tier since
   June 2026.
8. **SSHSIG's post-quantum story is behind.** PQ signature support is experimental and
   off by default in OpenSSH 10.4 (Jul 2026). Any specification text implying otherwise
   overclaims.
9. **Signing with a key already published on a Git host is genuinely not used by any
   incumbent** in this sweep. It is the one honest novelty found — and it is a *trust-root
   choice*, not a protocol contribution, and weaker than the alternatives (no revocation, no
   timestamp, no transparency log; key rotation silently invalidates history) unless paired
   with one of them.
10. **Compromised npm packages shipped valid SLSA provenance.** A verifiable envelope is not
    a trust signal.
11. **`gen_ai.system` is deprecated** (→ `gen_ai.provider.name`, semconv v1.37.0), and the
    GenAI conventions repo has no tagged releases.
12. **Do not cite the widely-circulated claim of a "W3C Web Bot Auth specification finalized
    in May 2026."** Datatracker shows individual Internet-Drafts with no IETF standing.

---

## Sources

All fetched 2026-08-31 unless noted.

**C2PA** — `spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html`;
`.../2.4/explainer/Explainer.html`; `.../2.4/ai-ml/ai_ml.html`; `.../2.3/specs/…`;
`c2pa.org/conformance/`; Content Credentials Deployment Guidance 1.0 (PDF, 2026-07-08);
`c2pa-org/conformance-public` → `trust-list/C2PA-TRUST-LIST.pem`,
`conforming-products/conforming-products-list.json`; `contentauth/c2pa-rs` →
`cli/CHANGELOG.md`, PR #2014, `sdk/src/store.rs`, `sdk/src/builder.rs`,
`sdk/src/jumbf_io.rs`, `sdk/src/reader.rs`, `sdk/src/utils/mime.rs`; arXiv 2604.24890.

**DSSE / in-toto** — `secure-systems-lab/dsse` → `envelope.md`, `protocol.md`,
`background.md`, `governance/02-scope.md`; `in-toto/attestation` → `README.md`,
`spec/v1/{README,statement,envelope,bundle,resource_descriptor,digest_set}.md`,
`spec/predicates/`, issues #244, #554, #565, #575, #588, #591.

**SLSA** — `slsa.dev/spec/v1.2/{,provenance,build-provenance,build-track-basics,
source-requirements,verification_summary,verifying-artifacts,distributing-provenance,
verified-properties,terminology}`; `slsa.dev/spec/v1.1/provenance`;
`slsa.dev/current-activities`; `slsa.dev/blog/2026/05/mini-shai-hulud-what-slsa-can-and-cannot-do`.

**Sigstore / OMS** — cosign, Fulcio, Rekor and protobuf-specs release pages;
`ossf/model-signing-spec`; `sigstore/model-transparency` README and
`docs/model_signing_format.md`; GitHub `gh attestation` documentation.

**SCITT** — RFC 9943; RFC 9942; `datatracker.ietf.org/doc/draft-ietf-scitt-architecture/`.

**Agent stack** — `draft-meunier-web-bot-auth-architecture`,
`draft-meunier-webbotauth-httpsig-protocol`, `draft-meunier-webbotauth-registry`;
Cloudflare Web Bot Auth docs; `draft-klrc-aiagent-auth`; `a2a-protocol.org/latest/specification/`;
`modelcontextprotocol.io/specification/latest`;
`open-telemetry/semantic-conventions-genai` (`registry.yaml`, releases);
`agent-trace.dev`; `git-ai-project/git-ai` → `specs/git_ai_standard_v3.0.0.md`.

**Lineage / BOM / adjacent** — W3C PROV-O; OpenLineage 1.47.1; MLflow Model Registry docs;
CycloneDX 1.7 / ECMA-424 2nd ed.; SPDX 3.0.1 AI profile; OCI Distribution v1.1 Referrers;
`huggingface-hub` 1.29.0; OpenTimestamps; nostr NIP-94.
