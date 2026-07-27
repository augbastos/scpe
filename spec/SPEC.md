# SCPE — Signed Contribution Provenance Envelope

**Spec version:** `scpe/0.1` · **Status:** draft-pending-review · **License:** CC BY 4.0

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as
described in RFC 2119.

---

> **Core + profiles.** SCPE's core is **artifact-agnostic**: a *subject* identified
> by its cryptographic hash, zero or more signed *attestations*, and one *signature*
> over the `manifest.json` that binds them. Nothing in that core knows or cares
> whether the subject is source code, an image, a model, or a PDF — exactly as a **JWT**
> is a signed set of claims regardless of what the claims mean, and a **DSSE** envelope
> wraps any payload type behind one signature. **Profiles** (§13) are thin *domain
> conventions* layered on that stable core: a profile is a **label** plus a set of
> expectations (which `subject.type` to use, the expected `media_type`, which
> attestations are conventional for the domain). A profile adds **no** verification
> logic and **no** integrity path — the verifier always verifies by `subject.type`
> (§6, §8 step 7), and an unrecognized profile is *surfaced, never an error*. This is
> the JWT/DSSE shape: one small signed core that many domains reuse without forking
> the format.

## 1. Abstract

SCPE is a portable, cryptographically verifiable **evidence container** for a single
contribution. It binds a **subject** (in `scpe/0.1`, a code change — a diff against a
known base commit — or a hash-addressed artifact) to a real **forge identity** — a
`(provider, subject-username)`
pair whose SSH keys the provider already publishes — and to a signed provenance
statement (an AI-usage disclosure and a list of typed, signed **attestations** — e.g.
an [Agent Trace](https://github.com/cursor/agent-trace) record). Every one of those —
the subject, the disclosure, and each attestation — lives inside the one signed
`manifest.json`, so all are signed claims attributable to the contributor. A
verifier — typically the owner of the target repository — re-derives every claim
offline using only `ssh-keygen`, `git`, and a key set: the public keys the contributor's
provider already publishes (GitHub, GitLab, or Codeberg — the last also covering
Gitea/Forgejo), or a keys file for offline and self-hosted use. Which anchor answered is
reported as `key_source`, because only the provider-published one carries a claim about
the forge account (§2.1, §8 step 4). No
SCPE server exists, no new account is required, and no trusted third party is
introduced. Identity is universal from day one: the provider is one enum value from
a fixed registry (§8), not a hardcoded platform.

Structurally, a seal is a stack of nested layers: an opaque *artifact* (the payload
bytes) bound by hash into a typed *subject*, carried with zero or more *attestations*
inside one signed *envelope* (`manifest.json` + `manifest.sig`, §4), on top of which a
repository's *policy* decides what a resulting status *means* — merge, block, comment —
a choice layered on the protocol, never part of it. The inner layers form an
**artifact-agnostic core** — subject-by-hash + attestations + one signature — that many
domains reuse through thin **profiles** (§13) without forking the format, the way a JWT
or a DSSE envelope wraps any payload behind a single signature.

## 2. Scope

SCPE proves **who** produced a contribution and that **nothing was tampered with**
between signing and verification. It deliberately does **not** cover:

- **Code quality or safety.** SCPE is not review. A verified envelope can contain bad
  or malicious code written by its genuine author.
- **Truth of the provenance statement.** The signature proves who *made* the
  disclosure, not that the disclosure is honest (see THREAT_MODEL.md).
- **Key or account compromise, or a self-supplied key set.** The root of trust is
  whichever anchor supplied the keys: the contributor's provider account and the keys it
  publishes, the keys file the verifier's owner supplies, or a keys file carried inside
  the input — the last chosen by the submitter and therefore no evidence of forge
  identity. §8 step 4 defines the precedence and requires the verifier to report which
  one answered.
- **Post-merge lifecycle.** Verification is defined at review time, against the
  pull request's head. See §10 and THREAT_MODEL.md for squash/rebase implications.

### 2.1 Identity: authentication vs authorization vs attribution

Three claims are easy to conflate; SCPE provides exactly one of them.

- **Authentication** — *this principal is present and in control right now.* A login
  session, a fresh challenge-response, a live 2FA prompt. Answers "is the account
  holder here?"
- **Authorization** — *this principal is permitted to do this.* A policy decision:
  merge rights, branch protection, code ownership. Answers "may this actor perform this
  action?"
- **Attribution** — *this specific act was performed with this key.* A durable,
  after-the-fact binding between an artifact and the material that produced it. Answers
  "who signed this, and can they deny it later?"

**SCPE provides attribution, and only attribution.** A seal binds `manifest.sig` to
**verification key material** — an SSH public key the declared provider publishes at
`<host>/<subject>.keys` — together with a provider→subject identity assertion (§8). It
proves exactly: *a key published on this `(provider, subject)` account signed exactly
these bytes.* That is a statement about the **signing act**, not about the signer's
present state.

*Published* is load-bearing there, and it is only earned when the verifier actually
consulted the provider. Keys can also reach a verifier from its operator or from inside
the submitted input (§8 step 4), so the anchor that answered is reported as
`key_source`: `forge` earns the sentence above in full; `flag` earns as much as the
operator's own key set is worth; `bundled` proves the signing act alone, against
material the submitter chose, and asserts nothing about any forge account.

It does **not** provide:

- **Authentication.** SCPE never checks that the account holder is present, in control,
  or even still exists. A key lifted from a compromised account, or one whose owner has
  walked away, verifies identically (THREAT_MODEL §2).
- **Authorization.** SCPE says nothing about whether the signer *may* contribute, merge,
  or touch a path. What a `verified` status is allowed to *mean* — merge, block,
  comment — is repository policy layered on top, never part of the protocol (§1,
  THREAT_MODEL §2).
- **Intent or truth.** Attribution of the signing act is not endorsement of its content:
  the key signed these bytes, not "these bytes are good, honest, or authorized."

This is the sharp form of "a seal proves *who claimed*, not that the claim is true"
(§2, THREAT_MODEL §2): the "who" is an attribution of a signing event to published key
material, and nothing more.

## 3. Terminology

- **Envelope** — the standalone artifact: a zip archive containing `manifest.json`,
  `manifest.sig`, and `diff.patch`.
- **Transport attestation** — the compact transport form of an envelope: the same
  `manifest.json` + `manifest.sig`, without `diff.patch` (the diff travels in the
  pull request branch instead). Distinct from the manifest's `attestations[]` array
  (§5); where ambiguity is possible this document says "transport attestation" for
  the §9 form and "attestation entry" (or `attestations[]`) for a §5 signed claim.
- **Contributor** — the human or agent operator who signs the manifest.
- **Identity** — the `(provider, subject-username)` pair the manifest binds the
  signature to: `provider` names a key-resolution method from the fixed registry (§8),
  and the identity's `subject` field is the username within that provider. (Not to be
  confused with the manifest's top-level `subject` block, §6, which is what is being
  attested.)
- **Provider** — a registered method for resolving a contributor's public keys. The
  registry is fixed in the verifier, not open-ended; §8 defines it and the
  provider→host table it is keyed by.
- **Verifier** — any party re-deriving the envelope's claims; typically the target
  repository's owner or their CI.
- **Subject** — the manifest's top-level `subject` block: *what* is attested,
  dispatched on `subject.type` (§6). `scpe/0.1` implements `code-change` (binds the
  manifest to the exact diff it describes) and `artifact` (binds it to the digest of a
  standalone artifact); any other type fails closed.
- **Attestation entry** — one element of the manifest's optional `attestations[]`
  array: a typed, signed claim carried inside `manifest.json` and therefore covered by
  `manifest.sig` (§5).

## 4. Envelope format

An envelope is a zip archive containing exactly:

| File | Requirement | Content |
|---|---|---|
| `manifest.json` | MUST | UTF-8 JSON object, fields below |
| `manifest.sig` | MUST | SSHSIG signature over the exact bytes of `manifest.json` (§7) |
| `diff.patch` | MUST for a `code-change` standalone envelope; MUST NOT in the attestation | the unified diff, UTF-8, LF line endings |
| `artifact.bin` | MUST for an `artifact` standalone envelope (§6.2); MUST NOT in the attestation | the raw artifact bytes, hashed verbatim |

The standalone envelope carries exactly one payload member — `diff.patch` for a
`code-change` subject, `artifact.bin` for an `artifact` subject — matching
`subject.type`.

`manifest.json` fields:

| Field | Req. | Type | Meaning |
|---|---|---|---|
| `spec_version` | MUST | string | `"scpe/0.1"` |
| `created_at` | MUST | string | RFC 3339 timestamp |
| `contributor` | MUST | object | `{ "identity": { "provider": str, "subject": str }, "key_fingerprint": str }` — the **claimed** forge identity that `manifest.sig` is checked against, and the SHA256 fingerprint of the signing key. Whether that claim was tested against the provider's published keys depends on the anchor the verifier resolved (§8 step 4, reported as `key_source`). `provider` MUST be a value from the fixed registry (§8); the identity's `subject` is the username within that provider and MUST satisfy the safe-subject rule (§8). The manifest carries **no** hostname, URL, port, or path — only the enum `provider` and the username (§8, SSRF invariant). |
| `subject` | MUST | object | `{ "type": str, ... }` — **what** is attested. The verifier's integrity step dispatches on `type` (§6). `scpe/0.1` implements `code-change` and `artifact` (standalone); any other type fails closed. |
| `ai_disclosure` | MUST | object | `{ "mode": "none" \| "assisted" \| "generated", "notes": str? }` |
| `profile` | MAY | string | a **domain-convention label** from the profile registry (§13) — one of `SCPE-C`, `SCPE-I`, `SCPE-V`, `SCPE-A`, `SCPE-M`, `SCPE-DATA`, `SCPE-D`, `SCPE-AR`. The producer stamps it; the verifier **surfaces** it verbatim but still verifies by `subject.type` (§6). Purely advisory: it carries **no** integrity path, and an unrecognized value is surfaced-but-ignored, never an error (§13). Omitted means unstamped. |
| `attestations` | MAY | array | list of typed, signed claims `[ { "type": str, ... }, ... ]` — see §5. All entries are inside the signed manifest, hence signed claims. Omitted or `[]` means none. |
| `extensions` | MAY | object | free-form map; verifiers MUST ignore unknown keys |

Everything above lives inside the one `manifest.json` and is therefore covered by the
single `manifest.sig`: the manifest is a **signed evidence container**. The two
extension points that keep it open without a format break are `subject.type` (§6) and
the `attestations[]` array (§5); both are dispatched by a typed discriminator that
fails safe on anything the verifier does not implement.

A manifest is signed as **exact bytes**. Producers MAY serialize however they like;
verifiers MUST NOT re-serialize, canonicalize, or pretty-print `manifest.json`
before signature verification. This removes any dependency on JSON canonicalization.

### 4.1 Manifest serialization rules

The signature is over the manifest's *bytes*, so the byte encoding is part of the
protocol, not an implementation detail. These constraints make "sign the exact bytes"
precise. None of them adds a verification step beyond §8 — they formalize what §4
already means, and the rationale is recorded in
[../docs/design-decisions.md](../docs/design-decisions.md) §2.

- **UTF-8, no BOM.** `manifest.json` MUST be UTF-8 with no byte-order mark (RFC 8259
  already forbids a BOM in interchanged JSON). A producer MUST NOT prepend a BOM: the
  bytes on disk / in transport *are* the signed message, so a BOM would become part of
  that message like any other byte.
- **Exact bytes, no canonicalization.** The producer emits a byte string and signs
  *that* string; the verifier checks the *same* bytes and MUST NOT re-serialize,
  canonicalize, pretty-print, re-indent, or reorder keys before `ssh-keygen -Y verify`.
  `json.loads` runs only *after* the signature verifies. There is deliberately **no**
  JSON Canonicalization Scheme (RFC 8785): omitting the canonicalizer removes an entire
  class of parser/serializer-divergence signature-bypass bugs — a different tradeoff
  from canonical-JSON designs, not a claim of superiority (design-decisions §2).
- **Byte layout is identity.** Because the signed message is the bytes, two JSON
  documents that are *semantically* equal but differ in byte layout — whitespace,
  indentation, key order, `\uXXXX` escaping, or trailing newline — are **different
  envelopes** with different signatures. This is intended: the manifest travels as
  opaque bytes (a zip member, a base64 blob in a PR body) and is never re-serialized in
  flight, so any reformatting of a signed manifest reads as tampering at §8 step 6 —
  the correct outcome.
- **No duplicate keys.** No object in `manifest.json` may repeat a key, at **any**
  nesting depth, and a verifier MUST reject a manifest that does (§8 step 2 →
  `signature-invalid`). RFC 8259 leaves duplicate-key resolution
  implementation-defined: last-wins, first-wins, and reject are all conforming
  choices, and real JSON libraries ship all three. So a manifest with a repeated key
  is one byte string that two honest verifiers can read as two different documents
  and reach two different verdicts on — which contradicts the property every other
  rule here exists to protect: identical signed bytes yield an identical verdict
  everywhere. Rejecting is the only resolution that does not require this spec to pick
  a winner *and* every implementation's JSON parser to have picked the same one. Note
  the asymmetry with the bullet above: there, differing bytes are deliberately
  different envelopes; here, identical bytes must not be two documents.
- **Defensive size cap.** A verifier MUST bound every member's size before it is parsed
  or used, to refuse a zip-bomb or oversized member (THREAT_MODEL §3). The reference
  verifiers cap the (decompressed) `manifest.json` at **1 MiB** (`1 << 20` bytes,
  `MAX_MANIFEST_BYTES`) and cap each of `manifest.sig` / `diff.patch` / `artifact.bin`
  at **64 MiB** (`MAX_MEMBER_BYTES`) — a decompression-bomb defense — rejecting an
  envelope that exceeds either bound before decoding JSON or otherwise using the
  member. Both caps are enforced on **both** input forms the reference verifiers
  accept: the zip path (checked against the member's declared uncompressed size
  before decompressing) and the directory path (checked against the file's on-disk
  size before reading). The exact bounds are a defensive implementation choice, not
  normative constants.

A producer's whole obligation is to **sign what it stores** — serialize freely, then
sign and transport those identical bytes.

## 5. Attestations

The optional `attestations[]` array is a list of **typed, signed claims**. Each entry
is an object with a `type` discriminator plus type-specific fields:

```json
"attestations": [
  { "type": "agent-trace", "format": "<id>", "data": { ... } }
]
```

Because the whole array sits inside `manifest.json`, every entry is covered by
`manifest.sig` — a signed claim attributable to the contributor. SCPE signs the
claims; it does **not** validate their content (see THREAT_MODEL.md).

### 5.1 Registered attestation types (`scpe/0.1`)

| `type` | Status | Shape |
|---|---|---|
| `agent-trace` | **implemented** | `{ "type": "agent-trace", "format": "<id>", "data": { ... } }` — carries a machine-attribution record; `format` selects the payload (§5.2). |
| `timestamp` | **reserved** (format-only, not implemented) | a future trusted-timestamp payload (RFC 3161 / OpenTimestamps / Rekor). Verifiers surface it as `present-unverified`. |
| `countersignature` | **reserved** (format-only, not implemented) | a future third-party co-signature. Honestly, a countersignature *cannot* live inside the manifest it signs — a signature over the manifest cannot itself be a field of that manifest — so the real mechanism (a detached co-signature, the in-toto builder model) is a roadmap item (docs/ROADMAP.md §3), not this reserved placeholder. |

### 5.2 `agent-trace` payload formats

| `format` | `data` payload |
|---|---|
| `agent-trace/1` | a complete [Agent Trace](https://github.com/cursor/agent-trace) trace record, verbatim: top-level `version`, `id`, `timestamp`, `files[]` (with `conversations[].contributor { type: human\|ai\|mixed\|unknown, model_id }` and `ranges[]`), plus optional `vcs`, `tool`, `metadata` |
| `git-ai/notes` | the raw payload of the `refs/notes/ai` git note(s) covering the commits in the change range, as emitted by [git-ai](https://github.com/git-ai-project/git-ai) |
| `generic/1` | `{ "agent": str?, "model": str?, "session_id": str?, "operator": str?, "tool_version": str? }` — all fields optional |

### 5.3 Status and the unknown-type fail-safe

A verifier assigns each entry a status and reports a **per-entry summary**
`[ { "type", "status" }, ... ]` (§8 step 8):

- An `agent-trace` entry whose `format` is registered (§5.2) → `present-<format>`
  (e.g. `present-generic/1`). Its status logic is exactly the pre-`0.1`
  agent-trace logic, now scoped to this entry.
- An `agent-trace` entry with an unknown `format` → `present-unverified`.
- A reserved type (`timestamp`, `countersignature`) → `present-unverified`.
- **An unknown `type` → `present-unverified`. MUST NOT be an error, and MUST NOT be a
  silent pass.** The verifier records the entry, marks it unverified, and moves on.
- An absent or empty `attestations` array → the summary is `[]`.

An attestation entry's status is never part of the overall `verified`/`tampered`
verdict: attestations are evidence *carried and signed*, not integrity anchors. Any
`content_hash` inside an `agent-trace/1` record is independent of the subject's
integrity (§6); SCPE's integrity anchor never derives from an attestation.

### 5.4 An `agent-trace` is an attested claim, not evidence of model behavior

A signature over an `attestations[]` entry proves **who recorded the claim**, never that
the process it describes occurred as described. This is normative: a verifier MUST NOT
represent, and tooling built on SCPE MUST NOT report, an `agent-trace` (or any
attestation) as evidence of what a model actually did. An attestation is a *signed
assertion by the contributor about their own tooling*, carrying exactly the epistemic
weight of the signer's word — non-repudiable, but self-reported (§2, THREAT_MODEL §2).

The distinction is in how a claim is phrased:

- **BAD** — "AI generated this safely." / "This code was verified AI-free." A statement
  *about the world* that the signature does not support: SCPE never observed the
  generation, cannot attest safety, and cannot confirm a negative.
- **GOOD** — "Agent X claims generation event Y occurred." / "The contributor attests
  `mode: generated` with this trace." A statement *about who asserted what*, which is
  exactly what the signature backs.

An `agent-trace` therefore records provenance the contributor *stands behind*, not
provenance SCPE *witnessed*. Any `content_hash` or `model_id` inside an `agent-trace/1`
record (§5.2) is part of that self-report and is likewise unverified; the subject's
integrity anchor never derives from it (§5.3, §6). Proving what *actually* produced a
change — execution attestation, TEE-backed or provider-signed output — is out of scope
for `scpe/0.1` (THREAT_MODEL §2).

## 6. Subject

The `subject` block says **what** is attested. It is a typed union: `subject.type`
selects how the verifier checks integrity (§8 step 7). This is the second extension
point (the first is `attestations[]`, §5); a new subject kind can arrive in a later
MINOR without a format break, and a verifier that does not implement it **fails
closed**.

### 6.1 `code-change` (implemented)

The primary subject type — a diff against a base commit. It keeps exactly the pre-`0.1`
target + change semantics, now nested under `subject`:

```json
"subject": {
  "type": "code-change",
  "target": { "repo": "<owner/name or URL>", "base_sha": "<full sha>" },
  "change": {
    "diff_sha256": "<hex>",
    "head_sha": "<full sha>",
    "files_changed": ["path", ...],
    "stats": { "insertions": int, "deletions": int }
  }
}
```

- `target.repo` / `target.base_sha` (MUST) — the repository and the full commit SHA
  the diff applies to.
- `change.diff_sha256` (MUST) — the **integrity anchor**: SHA-256 over the bytes of
  `diff.patch` after normalization, applied at the **byte level**: replace
  `b"\r\n"` → `b"\n"` and `b"\r"` → `b"\n"`, strip trailing newlines, then append
  exactly one trailing `\n`. This operates on the raw bytes and **never decodes
  them as UTF-8** — the anchor is therefore well-defined even for a diff that is
  not valid UTF-8, and every conforming implementation agrees on it (line endings
  are ASCII, so byte-level and text-level normalization coincide for a valid-UTF-8
  diff). Producers MUST apply this normalization before hashing; verifiers MUST
  apply it to whatever diff they recompute before comparing. **This normalization
  + integrity check is unchanged from pre-`0.1`.**
- `change.head_sha` (MUST) — the exact commit the contributor produced. Informational:
  it breaks under rebase by design and is recorded for audit, not verified as the anchor.
- `change.files_changed`, `change.stats` (SHOULD) — human-oriented summary; not verified.

`git patch-id` is **not** part of this specification's verification algorithm: it
ignores whitespace, which is semantic in indentation-sensitive languages, so it
cannot serve as a tamper check. Implementations MAY compute it as an informational,
rebase-tolerant *matcher*, but MUST NOT treat a patch-id match as integrity.

### 6.2 `artifact` (implemented — standalone)

The secondary implemented subject type: any digital artifact identified by its
cryptographic digest.

```json
"subject": { "type": "artifact", "digest": { "sha256": "<hex>" }, "media_type": "<mime>" }
```

- `digest.sha256` (MUST) — the **integrity anchor**: SHA-256 over the **raw** artifact
  bytes. Unlike a diff, an artifact is opaque (it may be binary), so **no
  normalization is applied** — the bytes are hashed exactly as carried.
- `media_type` (SHOULD) — the artifact's MIME type; informational, not verified.

The mechanism: in a **standalone envelope** the artifact rides as the `artifact.bin`
member (§4). The verifier hashes those enclosed bytes and compares against
`digest.sha256`: a match is `verified`, a mismatch is `tampered` — the artifact-subject
equivalent of the `code-change` diff check. In **PR transport** there is no artifact
payload to hash, so an `artifact` subject is **standalone-only**;
artifact-verification-in-PR is a roadmap item (docs/ROADMAP.md §4). A verifier that
receives an `artifact` subject with no payload to hash returns `tampered` (nothing to
check the digest against), never `verified`.

### 6.3 Subject-type dispatch and the fail-closed rule

The verifier's integrity step (§8 step 7) dispatches on `subject.type`:

- `code-change` → the diff integrity check of §6.1.
- `artifact` → the digest check of §6.2 (standalone).
- any other type — an entirely unknown subject kind — → status
  **`unsupported-subject`**. **An unknown or unimplemented subject type MUST fail
  closed to this clear status: never `verified`, never `tampered` (which would imply
  a check ran), never a silent pass.** The verifier does not guess an integrity check
  for a subject kind it does not implement. This mirrors the `unsupported-provider`
  fail-safe for identity (§8/§11.1).

## 7. Signing

The contributor signs the exact bytes of `manifest.json` with an SSH key that their
declared identity provider publishes (or, for the `local` provider, a key the
verifier's owner holds):

```
ssh-keygen -Y sign -f <private_key> -n scpe/0.1 manifest.json
```

- Namespace MUST be `scpe/0.1`. The namespace ties the signature to this protocol
  and version; a signature made under any other namespace MUST NOT verify. The
  signing namespace is `scpe/0.1` regardless of which identity provider is used —
  providers change how keys are *resolved*, never how the signature is *made*.
- Requires OpenSSH ≥ 8.2 (SSHSIG support).
- The signing key MUST be resolvable for the declared `(provider, subject)` per §8:
  for a forge provider it MUST appear at that provider's `.keys` endpoint for
  `subject`; for `local` it MUST appear in the owner-supplied keys file. §8 defines
  resolution and the fixed provider→host table. This is a **producer** obligation, and
  a verifier only enforces it when it reaches the `forge` anchor: a run that resolved at
  `flag` or `bundled` can return `verified` without ever consulting the endpoint, so a
  `verified` verdict is not by itself evidence that this MUST was honoured. That is what
  `key_source` is for (§8 step 4, §2.1).

## 8. Verification algorithm

A verifier MUST perform these steps in order. Each failure mode maps to exactly one
status code; verification stops at the first failure.

1. **Locate.** Extract the attestation from the transport (§9) or open the
   standalone envelope. If none is present → **`unattested`** (this is a state, not
   an error: a plain PR without SCPE is simply unattested).
2. **Parse.** Read `manifest.json` as a JSON object. A manifest the verifier cannot
   read unambiguously — not valid UTF-8, not valid JSON, not a JSON object, or
   containing a duplicate key in any object at any nesting depth (§4.1) →
   **`signature-invalid`**, the reason carried in the human-readable detail.
   That status is a reuse, not a claim about the SSHSIG: the signature over those
   bytes may well be intact, but bytes that admit more than one reading are not a
   well-formed signed message, and §8 spends no separate status on a malformed
   manifest. The rejection belongs **here**, ahead of the signature and integrity
   checks, so that ambiguous content never reaches the `subject.type` dispatch of
   step 7 — a duplicated `subject`, `contributor`, or `attestations` would otherwise
   be resolved silently, by a rule the protocol never chose, on the way to a verdict.
   Then, if `spec_version` has an unknown MAJOR (per §11) →
   **`unsupported-version`**.
3. **Resolve the provider.** Read `contributor.identity = { provider, subject }`.
   Look up `provider` in the **fixed provider registry** below.
   - If `provider` is absent from the registry — unknown, or reserved-but-not-yet-
     implemented (§11.1) → **`unsupported-provider`**. This is never an error and
     never a silent pass: an envelope naming a provider the verifier does not
     implement is reported as `unsupported-provider`, distinct from both `verified`
     and `signature-invalid`.
   - Validate `subject` against the **safe-subject rule** below. A malformed
     `subject` → **`identity-unverifiable`**.

   | `provider` | Key source | Host (fixed in the verifier) |
   |---|---|---|
   | `github` | `https://github.com/<subject>.keys` | `github.com` |
   | `gitlab` | `https://gitlab.com/<subject>.keys` | `gitlab.com` |
   | `codeberg` | `https://codeberg.org/<subject>.keys` | `codeberg.org` |
   | `local` | owner-supplied keys file; **no** network fetch | — |

   All four resolve SSH public keys in the same shape (`<host>/<subject>.keys` or a
   local file), which is what keeps the single-file verifier auditable. `codeberg`
   is the Gitea/Forgejo endpoint shape; self-hosted Gitea/Forgejo and other
   enterprise forges are reached by the **verifier owner** adding a provider→host
   mapping in verifier configuration (see the SSRF invariant), not by the manifest.

   > **SSRF invariant (normative).** The host used to fetch keys is taken **only**
   > from this table, keyed by the enum `provider`. The manifest supplies `provider`
   > (an enum value) and `subject` (a username) and **nothing else** — never a
   > hostname, URL, port, scheme, or path. A verifier MUST NOT derive the fetch
   > target from any manifest-supplied string other than substituting `subject`,
   > URL-safe, as a **single path segment** into the fixed URL template for the
   > looked-up host. A contributor therefore cannot point the verifier at an
   > arbitrary host. Self-hosted / enterprise forges (Gitea/Forgejo, GitLab EE,
   > GitHub Enterprise) are supported only by the verifier owner registering an
   > additional provider→host mapping out of band — never by a value inside a signed
   > or unsigned manifest.

   **Safe-subject rule.** `subject` MUST match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`
   **and** MUST NOT contain the substring `..`. A `subject` failing either check →
   **`identity-unverifiable`**. This forbids `/`, whitespace, `@`, `:`, and path
   traversal, so the resolved URL is always exactly one predictable path segment
   under the fixed host — no breakout, no host injection.
4. **Fetch or read keys.** Keys reach the verifier through exactly three **anchors**,
   tried in this precedence order:

   | Order | `key_source` | Anchor | Chosen by |
   |---|---|---|---|
   | 1 | `flag` | keys the verifier's owner supplies out of band (the reference verifiers' `--keys FILE`) | the **verifier's owner** |
   | 2 | `bundled` | a `keys` file carried inside the input, beside `manifest.json` | whoever **submitted** the input |
   | 3 | `forge` | `https://<fixed-host>/<subject>.keys` for a forge provider | the **provider account** |

   - **`flag`** wins over everything: an owner who names a key set for this run has
     already answered the trust question by hand.
   - **`bundled`** is read only when no owner-supplied keys were given. This anchor is
     what lets an envelope verify with no network at all — it is how a consumer checks
     an unpacked directory that carries its own `keys` file beside the manifest, the
     shape the eighteen normative vectors ship in (Appendix A records which anchor the
     conformance harnesses use). **It is not evidence of forge identity.** The `keys`
     file arrives inside the input, from the same party that produced the manifest, so
     a package can declare any `(provider, subject)` it likes and enclose the key that
     matches its own signature — reaching `verified` without `github.com`, or any other
     forge, ever being contacted. That is a legitimate offline verification and an
     illegitimate proof that the named forge account signed anything; the two are
     indistinguishable in the verdict word, which is exactly why `key_source` exists.
   - **`forge`** is reached only when neither anchor above supplied keys, and only for
     `github` / `gitlab` / `codeberg`: fetch `https://<fixed-host>/<subject>.keys`,
     where `<fixed-host>` comes from the registry above. The fetch MUST use **HTTPS
     with TLS certificate and hostname validation**, and MUST **NOT follow HTTP
     redirects**: a 3xx response — or any attempt to redirect to a different host,
     scheme, or port — MUST be treated as a fetch failure (→
     **`identity-unverifiable`**), never followed. The verifier contacts exactly the
     fixed host and no other; the final response URL MUST still be that host over
     HTTPS or the fetch is rejected. This keeps the "SSRF-safe by construction"
     invariant intact even as providers or owner-configured hosts are added.
   - `local` has no host and therefore never reaches the `forge` anchor. With neither
     `flag` nor `bundled` keys it is **`identity-unverifiable`** — no network access
     occurs, which is what makes `local` the fully offline / air-gapped / self-hosted
     path.
   - Keys missing, unreachable, or empty at the anchor that was selected →
     **`identity-unverifiable`**.

   > **`key_source` (normative).** A verifier MUST surface which anchor supplied the
   > keys it used: a top-level `key_source` field in machine-readable output, valued
   > `"flag"`, `"bundled"`, or `"forge"`, and shown in human-readable output whenever
   > it is set. It is set whenever a non-empty key set was obtained — so on `verified`,
   > and on every later failure that got past this step — and `null` when none was,
   > including every status reached before this step. `key_source` MUST NOT change the
   > verdict: all three anchors verify a signature identically and the field adds no
   > check. It exists because the verdict word alone cannot tell a reviewer whether
   > `verified` means "the forge publishes this key for this user" or "the submitter
   > enclosed a key matching its own signature". A consumer that needs the
   > forge-backed claim MUST require `key_source == "forge"` — or supply the key set
   > itself and require `"flag"`; a consumer running offline conformance expects
   > `"bundled"` and is right to. Reporting the anchor is the fix here, not forbidding
   > one: refusing `bundled` keys would take the conformance suite, air-gapped review,
   > and every self-hosted deployment offline with it.
5. **Build the allowed signers file.** One line per fetched key, principal =
   `subject`:
   `<subject> namespaces="scpe/0.1" <key-type> <base64-key>`.
6. **Verify the signature.**
   `ssh-keygen -Y verify -f allowed_signers -I <subject> -n scpe/0.1 -s manifest.sig < manifest.json`
   Failure → **`signature-invalid`**.
7. **Verify subject integrity.** Read `subject.type` (from the now signature-verified
   manifest) and dispatch (§6.3):
   - **`code-change`** — obtain the diff (standalone envelope: the enclosed
     `diff.patch`; PR transport: recompute `git diff <base_sha>...<head>` from the
     pull request), normalize per §6, hash, and compare with
     `subject.change.diff_sha256`. Mismatch → **`tampered`**.
   - **`artifact`** — obtain the artifact bytes (standalone envelope: the enclosed
     `artifact.bin`), hash them **raw** (no normalization), and compare with
     `subject.digest.sha256`. Mismatch → **`tampered`**. No enclosed payload (e.g. PR
     transport, which carries none) → **`tampered`**: nothing to check the digest
     against, so it can never reach `verified`.
   - **any other type** (an unknown subject kind) → **`unsupported-subject`**.
     Fail closed: never `verified`, never a silent pass.
8. **Success** → **`verified`**, with an `attestations` summary: a per-entry list of
   `{ type, status }` (§5.3), where each `status` is `present-<format>` or
   `present-unverified`. An absent or empty `attestations` array yields `[]`.

Statuses: `unattested · unsupported-version · unsupported-provider ·
unsupported-subject · identity-unverifiable · signature-invalid · tampered · verified`.

### 8.1 The algorithm as an ordered state machine (non-normative)

The steps of §8 form a linear, fail-closed state machine: control advances only on
success, and the *first* failing transition halts and fixes the status. This box
restates §8 as a formal-grammar aid — it introduces **no** new step and **no** new
status. §8 remains authoritative on every detail (which host, which redirect rule,
which normalization); where this summary and §8 differ, §8 wins.

```
  locate / parse envelope ......  no envelope present ...... unattested
        |                         manifest unreadable, or .. signature-invalid
        |                         duplicate JSON key (§4.1)
        | ok
  verify version (MAJOR) .......  unknown MAJOR ............ unsupported-version
        | ok
  resolve provider .............  not in fixed registry .... unsupported-provider
        | ok
  verify identity ..............  malformed subject, or .... identity-unverifiable
        | ok                      keys unreachable / empty /
        |                         cross-host redirect
  verify signature .............  SSHSIG check fails ....... signature-invalid
        | ok
  verify subject integrity .....  diff / digest mismatch ... tampered
        | ok                      unknown subject.type ..... unsupported-subject
  collect attestations .........  (never fails the verdict; §5.3)
        | ok
  VERDICT ......................  all steps passed ......... verified
```

Each state maps to §8 as follows:

1. **locate / parse** — §8 steps 1–2: extract the transport attestation or open the
   standalone envelope, then read `manifest.json`. No envelope → `unattested` (a state,
   not an error); a manifest that will not parse, or that repeats a key in any object
   (§4.1), → `signature-invalid` before any key is fetched; unknown MAJOR →
   `unsupported-version`. This state therefore has two failure exits, which is why the
   diagram shows them stacked — the machine is still linear, `signature-invalid` is
   still the same terminal it is further down, and no status is added.
2. **resolve provider** — §8 step 3 (registry lookup): look up
   `contributor.identity.provider` in the fixed registry. Absent — unknown or
   reserved-but-unimplemented — → `unsupported-provider`.
3. **verify identity** — §8 step 3 (safe-subject rule) + step 4 (fetch or read keys): a
   malformed `subject`, or keys that are unreachable, empty, or reached only via a
   cross-host / scheme / port redirect → `identity-unverifiable`. Which of the three
   anchors supplied the keys is recorded as `key_source` and reported (§8 step 4); it
   is not a transition — the machine advances the same way whichever anchor answered.
4. **verify signature** — §8 steps 5–6: build the allowed-signers file and run
   `ssh-keygen -Y verify` under namespace `scpe/0.1`. Failure → `signature-invalid`.
5. **verify subject integrity** — §8 step 7, dispatched on `subject.type` (§6.3): a
   `code-change` / `artifact` hash mismatch → `tampered`; any other type →
   `unsupported-subject`.
6. **collect attestations** — §8 step 8: this transition never fails the verdict — each
   entry is summarized `{ type, status }`, an unknown type is recorded as
   `present-unverified` (§5.3), and the run proceeds.
7. **VERDICT** — reaching the end → `verified`, carrying the attestations summary.

Every terminal except `verified` is a fail-closed refusal: the machine never falls
through to `verified` for an input it did not fully check.

## 9. Transport: GitHub pull request

The code change travels as a normal pull request; the attestation travels in the PR
body so that merging leaves no SCPE artifact in the repository's history.

- The attestation is the envelope zip **without** `diff.patch`, base64-encoded,
  embedded in the PR body inside an HTML comment:

```
<!-- SCPE-ATTESTATION-v1
<base64>
-->
```

- Producers MUST emit exactly one attestation block. Verifiers MUST use only the
  first block and MUST ignore any subsequent ones.
- The attestation (manifest + signature, no diff) is 1–2 KB in base64 and MUST fit
  within GitHub's 65,536-character body limit.
- The full envelope (with `diff.patch`) is the **standalone** form, for transport
  outside pull requests: email, artifact stores, other forges. The two forms verify
  identically except for where the diff in step 6 comes from.

## 10. Verification is at review time

SCPE's guarantees are defined **against the pull request head, before merge**.
After a squash or rebase merge, the repository's final tree is a new object with no
cryptographic link to the signed manifest; the seal comment and the attestation
remain as an auditable historical record of what was verified. Maintainers who need
post-merge traceability SHOULD merge without squashing or SHOULD archive the
standalone envelope. This limitation is deliberate — see THREAT_MODEL.md.

## 11. Versioning

- `spec_version` is `scpe/<MAJOR>.<MINOR>`.
- Verifiers MUST accept an unknown MINOR of a known MAJOR (new optional fields may
  appear; unknown fields are ignored). Verifiers MUST reject an unknown MAJOR with
  `unsupported-version`.
- This document is `scpe/0.1`.

### 11.1 Provider registry

The `contributor.identity.provider` value is drawn from a **fixed, closed registry**,
not an open string. `scpe/0.1` **implements** exactly four providers: `github`,
`gitlab`, `codeberg`, and `local` (§8). The registry is closed so that the set of
hosts a verifier will contact is auditable and fixed at the verifier, never widened
by a manifest (the SSRF invariant, §8).

Heavier identity resolvers — `oidc`/`sigstore`, `x509` (corporate PKI), `ldap` — are
**format-reserved but not implemented** in `scpe/0.1`. They are documented in
[../docs/ROADMAP.md](../docs/ROADMAP.md), item 1. A verifier encountering any
provider it does not implement — reserved or entirely unknown — MUST return
`unsupported-provider` (§8 step 3): never an error, never a silent pass. This lets a
future MINOR add a resolver without a format break, while a current verifier fails
safe and legibly against it.

## 12. Security considerations

See [THREAT_MODEL.md](THREAT_MODEL.md). Summary: SCPE defends against contributor
impersonation, in-transit tampering of the change, and repudiation of the
provenance statement, and — by construction — against verifier-side SSRF (§8: the
key-fetch host comes from a fixed provider→host table, never from the manifest). It
does not defend against a compromised provider account or SSH key, a
malicious-but-genuine author, a false disclosure, or the unavailability of the
provider's key endpoints. The trust root is whichever anchor supplied the keys (§8
step 4): the contributor's provider account at `forge`, the verifier owner's keys file
at `flag`, and a keys file carried inside the input — chosen by the submitter, and
therefore no evidence of forge identity — at `bundled`. A consumer whose decision
depends on the identity being a real forge account MUST require `key_source == "forge"`
(§2.1, THREAT_MODEL §2.1).

Prior art: `patatt` and `b4` ([mricon/patatt](https://github.com/mricon/patatt),
kernel.org) already sign and verify individual email patches against a
contributor's own PGP/SSH key in production, at the Linux kernel's actual scale —
this specification follows the same shape (the contributor self-signs, the
recipient verifies independently, no CA and no server) applied to the GitHub
pull-request boundary instead of a mailing list. Key resolution is where the two
part, and it is this specification's only real addition: `patatt` anchors on a
keyring the project tracks in the repository itself, so a project maintains its own
record of who may sign; §8 step 4 anchors on the keys the provider already publishes
for the account, so there is no record to maintain — at the price of depending on
that provider, which is why the anchor that answered is always reported. Self-signing at this level
(`scpe/0.1` — Level 2 in the tiered adoption model, see
[../docs/LEVELS.md](../docs/LEVELS.md)) proves integrity of the change and
non-repudiation of the disclosure; it does not prove anything about the
contributor beyond what the provider's published keys (e.g.
`github.com/<subject>.keys`) already assert — and it reaches even that ceiling only when
`key_source` is `forge`; a `bundled` result sits below it, asserting nothing about any
forge account (§2.1, §8 step 4). A materially
stronger "who" claim — verified by someone other than the author — is Level 3
(third-party countersignature), which is roadmap, not implemented in `scpe/0.1`.

## 13. Profiles

A **profile** is a thin domain convention layered on the artifact-agnostic core
(a subject by hash + attestations + signature). It is a **label plus conventions**,
nothing more: it names a domain, records which `subject.type` that domain uses, the
`media_type` to expect, and which attestations are conventional there. A profile
**does not** add, replace, or parameterize any verification logic — integrity is
always checked by `subject.type` (§6, §8 step 7), identically to when no profile is
stamped.

The optional top-level `profile` field (§4) carries one registry name. Profiles are
the JWT/DSSE model applied to a domain: the signed core is stable, and each domain
reuses it through a convention rather than a format fork.

### 13.1 Profile registry (`scpe/0.1`)

The registry is a fixed set of eight labels. All are **equal domain conventions** —
the spec privileges none. (Seven ride the `artifact` subject type; `SCPE-C` rides
`code-change`.)

| Profile | Domain | `subject.type` | Expected `media_type` | Conventional attestations |
|---|---|---|---|---|
| `SCPE-C` | code | `code-change` | — (n/a — the subject is a diff, §6.1) | `agent-trace` (AI-use in the change) |
| `SCPE-I` | image | `artifact` | `image/*` (AI images, photos, edits) | `agent-trace` (generation prompt/model) |
| `SCPE-V` | video | `artifact` | `video/*` | `agent-trace` (generation record) |
| `SCPE-A` | audio | `artifact` | `audio/*` (synthetic voice, music, podcast) | `agent-trace` (generation record) |
| `SCPE-M` | model | `artifact` | model weights — `.safetensors` / GGUF / ONNX (`application/octet-stream`) | `agent-trace` (training/derivation record) |
| `SCPE-DATA` | dataset | `artifact` | a training dataset (e.g. `application/x-parquet`, `application/jsonl`, `application/octet-stream`) | `agent-trace` (build/derivation record) |
| `SCPE-D` | document | `artifact` | `application/pdf`, `application/msword`, etc. (contracts, papers) | `agent-trace` (authoring record) |
| `SCPE-AR` | artifact | `artifact` | any distributed binary (the **catch-all**) | `agent-trace` |

The `media_type` column mirrors `subject.digest`'s companion `media_type` field
(§6.2), which is itself informational and unverified. The "conventional attestations"
column is guidance, not a requirement: `attestations[]` remains optional (§5), and in
`scpe/0.1` the one implemented attestation type is `agent-trace` regardless of domain.

### 13.2 A profile is a label, not a verification path

1. **Integrity is by `subject.type`, always.** The verifier's integrity step (§8
   step 7) dispatches solely on `subject.type` (§6). The `profile` field is **never**
   read to decide `verified` / `tampered` / `unsupported-subject`. No profile
   introduces a new hash, check, or trust anchor. A profile is routing metadata, not
   evidence — it does not even reach the attestation ladder's `present-unverified`
   (§5.3), because it is not a signed claim about the subject, only a domain hint.

2. **Producer stamps, verifier surfaces.** A producer MAY set `profile` to one
   registry name to declare which domain convention it followed. A verifier MUST
   surface the stamped `profile` verbatim in its output, and MUST NOT let its value
   change the verdict or any status code (§8). The status set of §8 is unchanged; no
   `profile`-specific status exists.

3. **Unknown profile is surfaced-but-ignored, never an error.** A `profile` value not
   in the registry (§13.1) — or an absent field — MUST NOT cause verification to fail
   or alter any status. The verifier surfaces the raw value (or notes its absence) and
   proceeds. This is the same fail-safe philosophy as an unknown attestation `type`
   (§5.3) and an unknown `subject.type` (§6.3), but weaker still: those two are
   *dispatched*; a profile is only *displayed*.

4. **Conventions are advisory, not constraints.** The registry's `subject.type` and
   `media_type` columns are documentation of intent, not rules the verifier enforces.
   If a manifest stamps `SCPE-I` (image) but carries a `code-change` subject, the
   verifier still verifies the `code-change` by §6.1 and reaches its normal verdict;
   it MAY surface the profile/subject mismatch as an advisory note, but MUST NOT treat
   the mismatch as an error or let it change the verdict.

Because a profile changes nothing the verifier trusts, adding, renaming, or removing a
profile is a documentation change, not a format change: a verifier that has never
heard of a profile name verifies a manifest bearing it exactly as it verifies one
without.

## Appendix A. Reference verifier

A single-file, stdlib-only reference verifier accompanies this spec at
`/reference/standalone/verify_envelope.py`. It implements §8 as written: it reads
`contributor.identity.{provider, subject}`, resolves `provider` through the fixed
registry of §8 (all four of `github`, `gitlab`, `codeberg`, `local`), returns
`unsupported-provider` for any provider outside it, enforces the safe-subject rule,
fetches keys HTTPS-only with no cross-host redirects (§8 step 4), dispatches integrity
on `subject.type` (`code-change` and `artifact` implemented; every other type →
`unsupported-subject`, §6.3), and reports the `attestations[]` per-entry summary
(§5.3, unknown types → `present-unverified`).

The eighteen test vectors under `/spec/test-vectors/` are normative for **status**: an
implementation that produces the expected status for all eighteen conforms to §8's
status behaviour. They do not cover every normative requirement in §8 — no vector
carries an expected `key_source`, so passing all eighteen does not by itself show that
step 4's `key_source` MUST is honoured. That one is checked by inspection, not by the
suite.
They exercise every registry provider (`valid-minimal`/`github`, `valid-gitlab`,
`valid-codeberg`, `valid-local`), both implemented subject types (`code-change`, and
`artifact` via `valid-artifact` + the `tampered-artifact` digest-mismatch reject), the
`unsupported-provider` branch (a reserved-but-unimplemented `oidc`), the
`unsupported-subject` branch (an unknown `container-image` subject type, which fails
closed despite a valid signature), the `identity-unverifiable` safe-subject branch (a
`..` traversal username), a `multi-attestation` envelope (a known agent-trace entry
plus a reserved one surfaced as `present-unverified`), and the signature, integrity,
version, and attestation outcomes.

All eighteen ship their own `keys` file, so the whole suite runs with no network. The
three conformance harnesses hand that file to the verifier as owner-supplied keys, so
they run at the `flag` anchor (§8 step 4); pointing a verifier at the same directory
without that flag runs at `bundled`. Both are offline, and no vector reaches `forge`.
What the suite pins is status and attestation behaviour — the `valid-*` vectors'
`verified` is an offline result, not a claim that any account on `github.com`,
`gitlab.com`, or `codeberg.org` published those keys.

## Appendix B. Algorithm agility

This appendix is rationale, not normative text — the clauses above are the authority.
The choices being migrated *from* are justified in
[../docs/design-decisions.md](../docs/design-decisions.md).

Crypto ages. SHA-1 fell to a practical collision in 2017 ([shattered.io](https://shattered.io)),
and OpenSSH states plainly that "most currently-used signature algorithms (including RSA and
ECDSA) can be broken by a quantum computer" ([openssh.org/pq.html](https://www.openssh.org/pq.html)).
A protocol that hardcodes one scheme forever eventually ships a break. **Algorithm agility** is
the ability to migrate the cryptography *without redefining the envelope*. This appendix shows
where the scheme lives in `scpe/0.1`, what SSHSIG pins today, and the concrete path to
post-quantum and other signature schemes.

### B.1 The scheme lives in two version coordinates

SCPE's cryptographic contract is pinned by two version strings that are already in the format,
and today are deliberately the *same* string, `scpe/0.1`:

1. **`spec_version`** — `scpe/<MAJOR>.<MINOR>` (§11), a field of `manifest.json`, therefore
   covered by the signature.
2. **The SSHSIG `namespace`** — MUST be `scpe/0.1` (§7), bound *into* the signature by
   SSHSIG itself.

That single string names the whole contract: which signature format (SSHSIG), which
message-binding (exact manifest bytes, no canonicalization), which content digest (SHA-256), and
which identity resolution (the fixed provider registry). Changing any of those is a
version-string change, not a re-architecture — that is the entire mechanism, and the rest of this
appendix is what it buys.

### B.2 What SSHSIG pins today — and what it leaves agile

Signing is `ssh-keygen -Y sign -f <key> -n scpe/0.1 manifest.json` (§7), requiring
OpenSSH ≥ 8.2. The SSHSIG blob
([PROTOCOL.sshsig](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig))
contains: a `MAGIC_PREAMBLE` (`"SSHSIG"`), a `SIG_VERSION`, the `publickey`, a **`namespace`**, a
`reserved` field, a **`hash_algorithm`** (`sha256` or `sha512`), and the `signature`. Two agility
levers already sit *inside* that structure:

- **The `namespace` field version-stamps the signature from inside.** Its purpose, per the SSHSIG
  spec, is "to specify an unambiguous interpretation domain for the signature … This prevents
  cross-protocol attacks caused by signatures intended for one intended domain being accepted in
  another"; it "MUST NOT be the empty string." SCPE sets it to `scpe/0.1`, and a signature made
  under any other namespace MUST NOT verify (§7). Because the namespace is part of the signed
  object, an attacker cannot strip it or downgrade it to another version without invalidating the
  signature.
- **The signature *algorithm* is carried by the key type, not by SCPE.** SSHSIG's `publickey` and
  `signature` are whatever the signer's SSH key is — `ssh-ed25519`, `rsa-sha2-256/512`,
  `ecdsa-*`, or a FIDO `sk-*` key. SCPE never names the signature algorithm; it delegates to
  OpenSSH's own algorithm handling. **So SCPE already inherits every SSH signature algorithm
  OpenSSH supports, present and future, for free** — including whatever post-quantum signature
  type OpenSSH ships later.

A third field, `hash_algorithm`, is SSHSIG's own message digest (ssh-keygen defaults to
`sha512`), chosen by OpenSSH and independent of SCPE's *content* digest (§B.5).

**The key distinction:** SCPE gets *signature-algorithm* agility for free from SSHSIG/OpenSSH.
What SCPE version-controls itself is the *envelope contract* — message binding + content digest +
identity resolution — via `spec_version`/`namespace`.

### B.3 The migration mechanism: bump the version, the verifier dispatches

The versioning rules (§8 step 2, §11) are the fail-closed lever that makes migration safe:

- **Verifiers MUST accept an unknown MINOR of a known MAJOR** — new optional fields are ignored.
- **Verifiers MUST reject an unknown MAJOR** with `unsupported-version`.

So there are two grades of change:

- **Backward-compatible (MINOR bump).** Adding an optional field, a new `subject.type`, or a new
  attestation `type`. An old verifier ignores the unknown optional field and fails *closed* on
  the unknown type — `unsupported-subject` (§6.3) or `present-unverified` (§5.3) — never
  a silent accept.
- **Cryptographic-contract change (MAJOR bump).** Swapping the content digest, the message
  binding, or the signature *format*. The version becomes `scpe/1.x`, and the SSHSIG namespace
  moves with it, giving clean cross-version behavior:
  - A new-scheme signature is made under namespace `scpe/1.0`; an old verifier's
    `ssh-keygen -Y verify -n scpe/0.1` refuses it on namespace mismatch — no cross-version
    confusion, no downgrade.
  - An old-scheme envelope reaches a new verifier as `spec_version scpe/0.1`, which the new
    verifier either still supports (dual-stack) or reports as `unsupported-version`.

**One open versioning question, stated honestly.** Today `scpe/0.1` sets the namespace and
`spec_version` to the *same* string, including the MINOR. But §11 requires verifiers to
accept an unknown MINOR of a known MAJOR — which cannot hold for the *signature* if the namespace
tracks the MINOR exactly, since an old verifier calling `-n scpe/0.1` would reject a
`scpe/0.2`-namespaced signature. The clean resolution when the first MINOR ships is to pin the
namespace to the **MAJOR** (`scpe/0` → a single `-n scpe/0` check that spans all MINORs), or to
have verifiers accept a known *set* of namespaces. `scpe/0.1` has not had to decide this yet
because there is exactly one version; it is flagged here so the decision is made deliberately, not
by accident, at the first bump.

### B.4 Post-quantum, concretely — without redefining the envelope

Two axes migrate independently.

**B.4.1 The signature (public-key) axis — the urgent one.**
This is the axis quantum computers threaten (OpenSSH: RSA and ECDSA "can be broken by a quantum
computer"). SCPE's architecture is *already ready* for it, because the signature algorithm rides
on the SSH key type (§B.2), not on SCPE:

- A post-quantum signature arrives the moment (a) OpenSSH ships a PQ SSHSIG key type and (b) the
  provider publishes such a key at `<host>/<subject>.keys`. **No SCPE format change is needed for
  the signature itself** — the manifest still binds `contributor.key_fingerprint`, and
  `manifest.sig` is still SSHSIG over the same bytes under the same namespace. SCPE inherits the
  new algorithm; at most it bumps `spec_version` if it wants to *require* a PQ key rather than
  merely *permit* one.
- **Honest status.** OpenSSH today ships post-quantum *key exchange* only —
  `mlkem768x25519-sha256`, the default since OpenSSH 10.0 (April 2025), and `sntrup761x25519`
  since 9.0 — and states that PQ *signature* support will "add … in the future"
  ([openssh.org/pq.html](https://www.openssh.org/pq.html)). So this axis is *ready in the SCPE
  architecture, waiting on OpenSSH* — not something SCPE must design. OpenSSH's KEX choices are
  **hybrids** (PQ combined with classical, so no regression if the PQ part proves weak); a PQ
  signature type would likely follow the same hybrid shape, and SCPE would inherit whatever
  OpenSSH chooses.
- **If a break forced moving off SSHSIG entirely** — to a different signature *format* such as a
  COSE/JOSE PQ envelope or a detached ML-DSA signature ([NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final),
  finalized 13 August 2024, from CRYSTALS-Dilithium; hash-based SLH-DSA is FIPS 205) — that *is*
  a cryptographic-contract change → MAJOR bump, new namespace, verifier dispatch on
  `spec_version`. Crucially, the **envelope structure does not change**: a signed
  `manifest.json` evidence container + a detached signature + a payload member. Only the bytes in
  `manifest.sig` and the verify command differ. That is the whole point — the container is
  signature-scheme-agnostic, exactly as JWS is agnostic across its `alg` values and DSSE is
  agnostic across signing backends.

**B.4.2 The content-digest axis — the far less urgent one.**
SHA-256 (the diff/artifact anchor, ../docs/design-decisions.md §1) migrates separately. It is much less
pressing under quantum than the signature: Grover's algorithm gives only a *quadratic* speedup on
preimage search, so a 256-bit hash retains ~128-bit security against a quantum preimage attack,
and collision resistance is not meaningfully improved by Grover at all. Public-key signatures,
by contrast, fall to Shor's algorithm outright. So the digest is a slow-clock migration: when it
comes, the manifest would carry a new digest field (or a digest tagged with its algorithm) under
a **MAJOR** bump, and old verifiers fail closed on the unknown version — never a silent accept.

### B.5 Invariants that make agility hold

Migration is only *safe* because the container refuses new crypto legibly instead of guessing.
These properties MUST be preserved across any version change:

- **The fail-closed discriminators.** Unknown MAJOR → `unsupported-version`; unknown provider →
  `unsupported-provider`; unknown `subject.type` → `unsupported-subject`; unknown attestation
  `type` → `present-unverified`. An old verifier meeting new crypto must decline clearly, never
  wave it through (§5.3, §6.3, §8, §11.1).
- **Namespace tracks (at least) the MAJOR.** Keep the SSHSIG namespace bound to the cryptographic
  contract so a signature can never be replayed across contracts. See the open question in §B.3.
- **Exact-bytes signing.** Because there is no canonicalization step (../docs/design-decisions.md §2),
  the *content*'s agility is independent of the *serialization* — there are no canonicalization
  rules that could silently drift between versions and turn a migration into a bypass.

### B.6 Where this sits in the wider landscape

SCPE's `spec_version` + `namespace` pair plays the role JOSE/JWS gives its `alg` header and COSE
gives its algorithm identifiers: a versioned, signed declaration of *which* scheme was used, so a
verifier dispatches rather than assumes. Git is migrating its own hash function the same way — via
an explicit, opt-in `objectFormat` repository extension rather than a silent swap
([git hash-function-transition](https://git-scm.com/docs/hash-function-transition), still
experimental). The common discipline: name the scheme in a versioned field, bind that field into
what you sign, and make an unrecognized value a clean refusal. SCPE keeps that discipline in the
smallest possible surface — one string, two places, both already covered by the signature.

**Agility at a glance:**

| Layer | Pinned by | Migrated via | Old verifier meeting new crypto |
|---|---|---|---|
| Signature algorithm | SSH key type (SSHSIG `publickey`) | New OpenSSH key type — no SCPE change; MAJOR bump only if *required* | Verifies if OpenSSH knows the key type; else SSHSIG-level failure |
| Signature format | SSHSIG under namespace `scpe/0.1` | MAJOR bump + new namespace + new verify path | Namespace mismatch → `signature-invalid`, no downgrade |
| Content digest | SHA-256 in `subject` | New/tagged digest field under a MAJOR bump | `unsupported-version` (fails closed) |
| Message binding | Exact manifest bytes | MAJOR bump (a different binding is a new contract) | `unsupported-version` (fails closed) |
| Identity resolution | Fixed provider registry (enum) | New provider in a later MINOR | `unsupported-provider` (fails closed) |
