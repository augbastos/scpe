# SCPE vs. everything else

The one question a reviewer arrives with is *"why not just extend X?"* Here is the honest,
one-screen answer for each X. Every claim about another project is fetched from its primary
sources (see [Sources](#sources)); where X does something better, we say so.

**The gap none of them fill:** a **portable acceptance policy for verifiable contributions** —
a signed, self-contained envelope over a *hashed artifact* (a diff today; any artifact by
profile) that a repo owner re-verifies **with no SCPE server, no CA, and no new account** — fully
offline if the owner supplies a keys file, or with one HTTPS GET to the contributor's git host
for already-public keys on the default forge path — and can turn into a merge gate. The others
solve identity, artifact signing, build provenance, media authenticity, or attribution — none
solve *this*.

For the "why not JWT / OIDC / X.509 / blockchain / a reputation score" objections, see
[../spec/FAQ.md](../spec/FAQ.md) ("Why not just use X instead?").

## What SCPE contributes

None of SCPE's primitives are new, and claiming otherwise would be dishonest. Offline
self-signing with a key the contributor already owns is patatt's move; the
signed-envelope-over-a-payload shape is the DSSE family's; resolving a signer's key from
what a platform already publishes is the Sigstore insight with the CA taken out; anchoring
the claim to a hash of the artifact is what C2PA and in-toto's `subject.digest` already do.
What SCPE contributes is the **combination, packaged as one portable format**:
deterministic offline verification of a contribution's provenance, where the subject's
*identity* can be resolved through fixed external trust roots — the verifier's own
provider→host table pointing at the SSH keys a forge already publishes, or a keys file the
verifier's owner holds — rather than a CA, trust list, transparency log, or identity
service. ("Can be" is doing real work: keys may also arrive inside the input, which is what
makes fully offline conformance possible and is not identity evidence; the verifier reports
which anchor answered as `key_source`, and a consumer wanting the forge-backed claim
requires `"forge"` — SPEC §8 step 4, THREAT_MODEL §2.1.) Applied at the pull-request
boundary, which none of the cryptographic
protocols below serve (the DCO operates there, but checks the presence of a trailer, not a
signature); and generalized by the same subject-by-hash core to any artifact. Most cells
SCPE fills in the matrix below are filled by someone else too; no other row fills all
five. That is the whole claim — an assembled tradeoff, not a new primitive — and the
tradeoff has a real price, spelled out after the table.

Columns: **Offline verify** — the verification step needs no online CA, log, or
verification service; **No CA / no identity service** — the trust root is not a
certificate authority, trust list, or identity provider; **Arbitrary artifact** — can
attest any hash-addressable artifact, not one fixed domain; **PR-native** — designed to
ride a forge pull request; **Provider-bound identity** — the signer's identity is an
existing forge account, resolved from keys the platform already publishes (SCPE's "yes"
means the protocol defines this resolution and a verifier reaches it at the `forge`
anchor — see note ⁸).

| | Offline verify | No CA / no identity service | Arbitrary artifact | PR-native | Provider-bound identity |
|---|---|---|---|---|---|
| **DCO** | no¹ | yes¹ | no | partial² | no |
| **patatt** | yes | yes | no | no | no |
| **DSSE** | partial³ | yes | yes | no | no |
| **Sigstore** | no⁴ | no | yes | no | partial⁴ |
| **in-toto** | partial³ | yes | yes | no | no |
| **C2PA** | partial⁵ | no | partial | no | no |
| **SCPE** | yes⁶ | yes | yes⁷ | yes | yes⁸ |

*This matrix compares protocol **shape and tradeoffs**, not quality — a "no" is almost
always a deliberate design decision, and several of these protocols are better than SCPE
at the thing they chose.*

¹ The DCO is a presence-only text trailer: it needs no infrastructure, and it verifies
nothing cryptographic — its "yes" is vacuous.
² Commit-trailer mechanism; commonly enforced on PRs by a CI bot checking the trailer
exists.
³ The envelope verifies offline, but the trust root (which keys, whose functionaries)
arrives out of band — the format itself does not say whose keys to check.
⁴ As the keyless flow described below: Fulcio (a CA), Rekor (a transparency log), and an
OIDC provider are required infrastructure; identity binds to an OIDC account — including
forge accounts — but is resolved through CA-issued certificates, not keys the forge
publishes.
⁵ The embedded manifest travels inside the file, but validation runs against the C2PA
Trust List with OCSP revocation — online PKI components.
⁶ Verification needs no service of SCPE's own. A forge provider needs one HTTPS GET to the
already-published `.keys` endpoint — but only when it actually reaches that anchor: with
owner-supplied or input-carried keys present, no network call happens at all, and the
`local` provider never fetches (SPEC §8 step 4).
⁷ Via the `artifact` subject (SPEC §6.2), standalone-envelope-only today —
artifact-verification-in-PR is a roadmap item.
⁸ Earned at `key_source == "forge"`, where the keys come from the account itself. A
verifier can also resolve at `flag` (the owner's keys file) or `bundled` (a keys file
carried inside the input) and return the same verdict word — at `bundled` the row's own
criterion is not met, because the submitter chose the key set. The field is how a consumer
tells the cases apart (THREAT_MODEL §2.1).

Where SCPE's row reads "yes" against another's "no", read it as a **different tradeoff,
not a win**. Going offline-first with no CA means giving up exactly what Sigstore's
infrastructure buys: Rekor's proof-of-existence-at-time-T (SCPE's signed `created_at` is a
claim, not a proof), OIDC-grade identity (SCPE Level 2 proves only what a forge account
asserts), and revocation machinery. SCPE's key model is fetch-time *at the `forge` anchor*:
a verifier that reaches the endpoint checks the keys the provider publishes at verify time,
so removing a compromised key from a forge profile stops that verifier from accepting it
again — but it is not retroactive, a verifier cannot tell rotation from compromise (the key
is simply gone), there is no revocation record or transparency log to consult, and it does
not reach runs that resolved against a supplied or input-carried keys file at all (those
never fetch, so removal changes nothing for them). That is a documented limitation of the
design, not an oversight (see `spec/THREAT_MODEL.md` §8 "Key lifecycle and revocation"
and `spec/FAQ.md` "Why not X.509?"). And in every row, an attestation proves **who
claimed** — never that the claim itself is true.

## Summary

| Protocol | What it is | The gap SCPE fills |
|---|---|---|
| **DSSE** | A signing-envelope *primitive* (`payload` / `payloadType` / `signatures` over a length-prefixed PAE) that deliberately leaves identity, key distribution, subject hashing, and policy "out of band." The signing substrate under in-toto and SLSA. | SCPE **is** that out-of-band layer, filled in for one concrete case: fixed identity resolution, per-type subject hashing, a PR-body transport, and a maintainer acceptance policy. Compatible, not rival — `attestations[]` is a typed slot a DSSE-wrapped statement could occupy under a future registered type, though nothing in `scpe/0.1` emits or verifies one. |
| **Sigstore** | Keyless signing via an online CA (**Fulcio**, OIDC-bound short-lived certs) + a public transparency log (**Rekor**), driven by the **Cosign** client. Built for release-artifact provenance. | SCPE needs **no server, no CA, no transparency log** — it verifies against the SSH keys a forge already publishes (one HTTPS GET at verify time) or, fully offline, against a supplied keys file; it reports which anchor answered as `key_source`, since only the forge one carries the account claim (THREAT_MODEL §2.1). It signs a *contribution* at PR time, before any build. Sigstore as an opt-in signing method is on the `scpe/0.2` roadmap. |
| **patatt / b4** | End-to-end cryptographic attestation for **email patches** (kernel.org): a DKIM-style `X-Developer-Signature` header, ed25519/PGP/OpenSSH keys, an in-repo keyring, verified independently with no CA. b4 is the maintainer-side tool. | Direct prior art, not a new idea — SCPE brings the same trust shape to the **forge pull request** (where patatt explicitly does not reach) with a contribution-shaped, extensible payload (diff + AI disclosure + attribution) and an acceptance policy. |
| **C2PA** | Content Credentials for **media assets** — provenance assertions + a signed claim (COSE/X.509, validated against a Trust List) **embedded inside** the file via byte-range/box hashing. | Media-authenticity standard; its unit is a finished asset with an embedded manifest and a PKI trust list. SCPE's unit is a stranger's **diff** in a PR body, verified before merge with no CA. SCPE names the media domains as future profiles rather than competing. |
| **SLSA / in-toto** | Build- and supply-chain provenance: an in-toto **Statement** (`subject.digest` + `predicateType`) in a **DSSE** envelope, with SLSA's escalating build-provenance levels and the **build platform as the trusted party**. | SCPE attests a *contribution from a stranger before a build exists* — no builder to vouch for it, only the contributor's own published key. It is the layer *before* SLSA begins; SLSA's emerging Source Track is the space to watch for convergence. |
| **Agent Trace** | Cursor's open, vendor-neutral RFC (v0.1.0) for recording per-line, per-conversation, per-model AI attribution. By its own admission: **no signatures, no identity, no verification** — purely self-reported metadata. | SCPE *carries* a full Agent Trace record verbatim as a signed attestation, bound to the exact diff and to a declared forge identity — turning anonymous self-report into signed, tamper-evident self-report, and into an *attributable* one when the verifier resolves keys at the `forge` anchor. Complementary by design. |
| **DCO** | The Developer Certificate of Origin 1.1: a plain-text `Signed-off-by:` trailer certifying the **legal right to contribute**, enforced by a CI bot that checks the line is *present*. Not cryptographic, trivially forgeable. | SCPE proves *who* produced the change and that *nothing was tampered with*, and carries a signed AI disclosure — but makes **no legal/licensing claim at all**. Different questions; a PR can carry both a `Signed-off-by:` trailer and an SCPE seal. |

## DSSE

DSSE (Dead Simple Signing Envelope, v1.0.2, [Secure Systems Lab](https://github.com/secure-systems-lab/dsse))
is a minimal format for a signature over an arbitrary payload: a JSON envelope of `payload`
(base64), `payloadType` (a string identifying interpretation), and `signatures[]` of
`{ sig, keyid? }` — where `keyid` is an *unauthenticated hint*. The bytes actually signed are a
**Pre-Authentication Encoding**, `PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`,
whose length-prefixed framing removes the need to canonicalize the payload. DSSE places no
restriction on signature algorithm or format ("agreed upon out-of-band by the signer and
verifier") and by design specifies **none** of: key identity/distribution, subject hashing, or
policy. It is the signing substrate under in-toto and SLSA. SCPE is exactly that out-of-band
layer for the contribution case: identity as a `(provider, subject)` pair against a fixed
provider→host table (`github.com/<subject>.keys`, GitLab, Codeberg, or a `local` file),
SSRF-safe because the manifest never carries a host; a typed `subject` union with a per-type
integrity anchor (`diff_sha256` for `code-change`, `digest.sha256` for `artifact`); a concrete
PR-body transport plus a standalone zip; and a tiered Levels 1/2/3 acceptance policy. SCPE
signs the **exact bytes of `manifest.json` with SSHSIG** (`ssh-keygen -Y sign`, namespace
`scpe/0.1`) rather than base64-wrapping under PAE — reusing keys a forge already publishes and
keeping canonicalization out of a single stdlib-only verifier. This is a trade, not a claim of
superiority: DSSE is more general (algorithm- and payload-agnostic) and carries the ecosystem
gravity of in-toto/SLSA. The two are compatible rather than exclusive: `scpe/0.1` emits and
verifies no DSSE envelope of its own — it implements exactly one attestation type
(`agent-trace`) — but `attestations[]` is the typed slot a DSSE-wrapped statement could ride
in later, as a registry entry rather than a format break (`docs/governance.md` §2).

## Sigstore

Sigstore is an open framework for signing and verifying software artifacts (containers,
binaries, SBOMs, releases). Its keyless flow uses three cooperating services: **Cosign** (the
sign/verify client), **Fulcio** (a code-signing CA that issues short-lived certificates bound
to an OIDC identity), and **Rekor** (an immutable, append-only transparency log). The flow:
Cosign generates an *ephemeral* keypair, sends the public key + an OIDC token to Fulcio, which
issues a short-lived cert binding the identity to the key; the artifact is signed, the private
key is discarded immediately, and the digest/signature/cert are recorded in Rekor. Identity
derives from the OIDC token (email, service account, or CI workflow); verification relies on the
transparency log rather than long-lived managed keys. Required infrastructure: an online CA, a
public transparency log, and an OIDC provider. SCPE fills a different need: **no server, no CA,
no transparency log** — a verifier needs only `ssh-keygen`, `git`, and an HTTPS GET to a forge's
existing `.keys` endpoint, or with the `local` provider no network at all. It signs a
*contribution* — a stranger's diff at the PR boundary, before it is built — against a key that
*already exists* at `github.com/<login>.keys`, with no OIDC round-trip. Honest scope: SCPE
Level 2 self-signing proves integrity and non-repudiation of the disclosure, not "who" beyond
what the forge account asserts; Sigstore's OIDC identity is a different and sometimes stronger
claim, and SCPE's answer to a stronger "who" (Level 3 third-party countersignature) is roadmap,
not shipped. Sigstore also does better on keyless UX at scale, transparency by default (Rekor
gives proof-of-existence-at-time-T that SCPE's signed `created_at` does not — SCPE lists
RFC 3161 / OpenTimestamps / Rekor timestamping as a *reserved* attestation type), org/workflow
identity, and maturity. Sigstore as an alternative signing method is on the `scpe/0.2` roadmap.

## patatt / b4

**patatt** ([mricon/patatt](https://github.com/mricon/patatt), by Konstantin Ryabitsev of
kernel.org) adds end-to-end cryptographic attestation to **email patches**, adapting the DKIM
email-signature standard: signatures ride in an `X-Developer-Signature` header that does not
corrupt patch content. It supports **ed25519, OpenPGP, and OpenSSH** keys, and its
distinguishing idea is to **track contributor public keys in the git repository itself** (an
in-repo keyring), so there is no external key infrastructure and no single point of failure. It
integrates with `git send-email` via a `sendemail-validate` hook, and its scope is explicit:
*"If your project workflow doesn't use patches sent via email, then you don't need this."*
**b4** ([b4.docs.kernel.org](https://b4.docs.kernel.org/)) is the maintainer-side tool —
retrieving patch threads, applying them, comparing series versions — and as of 0.7 it
integrates patatt to verify patches were not modified in transit. This is SCPE's closest
sibling and SCPE cites it as **direct prior art, not a new idea**: the same trust shape
(self-sign with your own key, verify independently, no CA/server/account) and the same refusal
of a parallel PKI. SCPE retargets it to the **GitHub-style PR** — a boundary patatt explicitly
does not serve — carrying the attestation in the **PR body** (the one channel that arrives with
every PR and survives force-pushes, leaving merged history clean), over a
contribution-shaped **evidence container**: `subject` (a diff *or* a hash-addressed artifact),
`ai_disclosure`, and `attestations[]` under one signature with fail-closed discriminators. It
standardizes identity to a `(provider, subject)` enum through a fixed provider→host table
(HTTPS-only, no redirects), and layers a Levels 1/2/3 maintainer acceptance policy. In fairness,
patatt/b4 are battle-tested at the Linux kernel's scale (SCPE is a draft), offer broader
key-type flexibility, have a fully decentralized in-repo keyring (a stronger availability story
than depending on a forge `.keys` endpoint, a residual risk SCPE mitigates with the `local`
provider), and fit mailing-list projects with zero impedance.

## C2PA

C2PA (Coalition for Content Provenance and Authenticity) defines **Content Credentials**:
verifiable provenance metadata attached to a **media asset**. Its blocks: an **Assertion**
(labelled data, typically CBOR, declaring metadata/actions/thumbnails/bindings/ingredients), a
**Claim** (gathers the assertions, references the hard binding, is cryptographically signed —
current label `c2pa.claim.v2`), a **Claim signature**, and a **Manifest** (assertions + one
claim + its signature; the user-facing term is Content Credentials). It hard-binds provenance
by hashing asset content — **byte-range hashing** (data-hash assertion), **box-based hashing**
(JPEG, PNG, ISO BMFF), or BMFF bindings — then **embeds the manifest directly into the file**
(JPEG APP11, MP4 `mdat`, PDF). Claims are signed with **COSE** over **X.509 certificate
chains**, validated against the **C2PA Trust List** with OCSP revocation and RFC 3161
timestamps. Targets are all common media types (images, video/audio, documents, even fonts) to
disclose how an asset was created and edited, including AI generation — **not source-code
contributions**. SCPE and C2PA share a motive (signed, tamper-evident AI disclosure bound to a
hash) but target different subjects: SCPE's unit is a **diff against a base commit from a
stranger**, carried in a PR body, verified *before* it is merged or built, with **no CA and no
trust list** (identity is a forge account's already-published SSH keys, a much smaller trust
surface), plus a PR-body transport and a maintainer acceptance policy C2PA has no notion of.
SCPE's `artifact` subject and its `SCPE-I`/`SCPE-V`/`SCPE-A`/`SCPE-D` media profiles
deliberately name the same domains C2PA covers — as future territory to show the core is
artifact-agnostic, not a fight it is picking. C2PA does better on its home turf: embedded hard
bindings, edit-history/ingredient chains, format-specific hashing, consumer-facing trust
infrastructure (Trust List, OCSP, timestamps), standards adoption, and in-asset persistence
(C2PA travels inside the file; SCPE's PR-body attestation is review-time and becomes historical
record after a squash merge).

## SLSA / in-toto

**in-toto** ([in-toto.io](https://in-toto.io/), a CNCF graduated project) secures software
supply-chain integrity by making visible what steps were performed, by whom, and in what order.
Its Attestation Framework is layered: an **Envelope** (a DSSE wrapper providing the signature),
a **Statement** (`_type` = `"https://in-toto.io/Statement/v1"`, a `subject` array of artifacts
each with a `digest` and optional `name`, and a `predicateType` URI), and a **Predicate** (the
substantive content — SLSA Provenance, an SBOM, vuln data). **SLSA** ([slsa.dev](https://slsa.dev/),
current spec v1.2; v1.0 retired) is Supply-chain Levels for Software Artifacts: escalating
**build-provenance** levels (L0–L3) whose provenance predicate documents builder identity,
source, and build parameters as an in-toto Statement wrapped in DSSE, with the **build platform
as the trusted verification point**. SLSA v1.2's Build Track is mature; a Source Track is under
development. SCPE borrows this shape — in-toto's `subject.digest` + `predicateType` is
structurally close to SCPE's `subject` + `attestations[]`, close enough that an in-toto
Statement could be carried verbatim under a future registered attestation type, though
`scpe/0.1` implements only `agent-trace` and produces no in-toto/DSSE output itself — and
mirrors the level laddering (Levels 1/2/3, explicitly crediting the SLSA-levels model). But
SCPE fills a **pre-build** gap: its
subject is a diff from a stranger at PR time with **no build and no builder** in the loop (the
fetched SLSA v1.0 summary states it "does not address pre-build contributions, pull request
review processes, or evaluation of individual code changes from external contributors"). It
needs no CI/builder trust root — just the contributor's SSH key and the forge's `.keys`
endpoint, verified offline — and ships a maintainer-facing acceptance gate for incoming PRs. In
fairness, SLSA/in-toto are the standard for the build story, a mature CNCF-graduated ecosystem,
and already have third-party attestation built in (in-toto's functionary/builder model is the
"stronger who" SCPE only reaches at roadmap Level 3), with a broad adopted `predicateType`
extension space. SLSA's emerging Source Track is the space to watch for convergence.

## Agent Trace

Agent Trace ([cursor/agent-trace](https://github.com/cursor/agent-trace)) is an open,
vendor-neutral **specification (RFC, v0.1.0)** for recording AI contributions alongside human
authorship in version-controlled code. Its record: required `version`, `id` (UUID), `timestamp`
(RFC 3339), and `files[]`; each file has a `path` and `conversations[]`; each conversation has a
`url`, `contributor`, `ranges[]` (1-indexed line spans), and optional `related`. The
`contributor` type is one of `human` / `ai` / `mixed` / `unknown` with optional `model_id`
(models.dev convention). Optional fields: `content_hash`, `vcs`, `tool`, `metadata`. Its stated
non-goals: it does not track legal ownership/copyright, does not track training data, and does
not evaluate whether AI contributions are good or bad — and critically it specifies **no
cryptographic integrity and no identity verification**, being "purely descriptive metadata,"
entirely self-reported by the generating tool. SCPE supplies exactly that missing layer: its
`agent-trace/1` attestation carries a **complete Agent Trace record verbatim** inside
`manifest.json`, covered by `manifest.sig` (an SSHSIG bound to a `(provider, subject)` identity)
and bound to the exact diff via the signed `subject.change.diff_sha256`, so the trace cannot be
silently detached from the code. Whether an attacker can also attach a fabricated trace *on
behalf of someone else* depends on the key anchor: at `key_source == "forge"` the signature is
checked against the published `.keys` of the declared account and the forgery fails; at
`bundled` the submitter supplied the key set, so a consumer that needs this property must
require `"forge"` (SPEC §8 step 4, THREAT_MODEL §2.1). Unknown formats are carried
fail-safe (`present-unverified`, never a silent pass), and the record becomes part of a
maintainer-facing `verified` verdict with Levels. Honest boundary: SCPE **signs the claim; it
does not validate the claim's content** — a contributor can sign a fabricated trace, so SCPE
converts anonymous self-report into *signed, attributable* self-report and nothing stronger. In
fairness, Agent Trace is the purpose-built, richer schema for the attribution *content* SCPE
carries but does not define, has broader vendor-neutral reach with zero signing friction, and
keeps a clear, narrow scope. The two are a stack, not a choice.

## DCO

The **Developer Certificate of Origin 1.1** (created by The Linux Foundation for the Linux
kernel) is a short legal affirmation a contributor makes by adding a `Signed-off-by: Name
<email>` trailer to a commit message. By signing off, the contributor certifies one of: (a) they
created the contribution and may submit it under the project's license; (b) it is based on prior
appropriately-licensed work they may submit with modifications under the same license; (c) it
was given to them by someone who certified (a)/(b)/(c) and they have not modified it; and (d)
they understand the contribution and its record are public and kept indefinitely. It is **purely
a text declaration — not cryptographically signed** — and its enforcement is a **DCO bot / CI
check** that verifies each commit *contains* a `Signed-off-by:` trailer, checking the presence
of a line, not the identity of the signer. SCPE fills the cryptographic gap: its `manifest.sig`
is an SSHSIG, so after-the-fact edits always fail; impersonation fails too when the verifier
resolves keys at the `forge` anchor and checks them against the ones the contributor's forge
**already publishes** — a check a consumer opts into by requiring `key_source == "forge"`, since
a submission may otherwise carry its own key set (THREAT_MODEL §2.1). It binds the normalized diff via
`subject.change.diff_sha256` so mid-flight tampering is caught (the DCO makes no integrity claim
— edit the diff after sign-off and the trailer is unchanged); it carries a signed `ai_disclosure`
(`none` / `assisted` / `generated`) plus optional machine-attribution `attestations[]` (the DCO
is silent on AI); and it produces a typed verdict (`verified` / `tampered` /
`identity-unverifiable` / …) rather than "trailer present/absent." But the DCO certifies the one
thing SCPE deliberately does not: **legal right to contribute** — SCPE's scope explicitly
excludes code quality, copyright, and licensing, so for the legal question the DCO is the right
instrument and SCPE is irrelevant. The DCO also has zero friction and near-universal adoption
(nothing beyond `git commit -s`) and is human-legible and durable in `git log` forever, whereas
SCPE's PR-body attestation is review-time and becomes historical record after a squash merge. A
project that wants both licensing assurance and verifiable, tamper-evident, AI-disclosed
provenance uses the DCO for the former and SCPE for the latter, side by side on the same PR.

## Sources

- **DSSE** — [protocol.md, secure-systems-lab/dsse](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
- **Sigstore** — [overview, docs.sigstore.dev](https://docs.sigstore.dev/about/overview/)
- **patatt / b4** — [mricon/patatt](https://github.com/mricon/patatt) · [b4.docs.kernel.org](https://b4.docs.kernel.org/en/latest/) · [Introducing b4 and patch attestation](https://people.kernel.org/monsieuricon/introducing-b4-and-patch-attestation) · [End-to-end patch attestation](https://people.kernel.org/monsieuricon/end-to-end-patch-attestation-with-patatt-and-b4)
- **C2PA** — [C2PA Specification 2.1, spec.c2pa.org](https://spec.c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html)
- **SLSA / in-toto** — [in-toto Statement v1 spec](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) · [in-toto.io](https://in-toto.io/) · [slsa.dev/spec/v1.0](https://slsa.dev/spec/v1.0/) · [slsa.dev/spec/v1.2](https://slsa.dev/spec/v1.2/)
- **Agent Trace** — [cursor/agent-trace](https://github.com/cursor/agent-trace)
- **DCO** — [Developer Certificate of Origin 1.1, developercertificate.org](https://developercertificate.org/)
- **SCPE (this repo)** — `spec/SPEC.md`, `spec/THREAT_MODEL.md`, `spec/FAQ.md`, `docs/LEVELS.md`, `docs/ROADMAP.md`
