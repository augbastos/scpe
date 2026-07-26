# SCPE Roadmap — designed, deliberately deferred

`scpe/0.1` is intentionally small: a subject identified by a digest, verifiable evidence about
it, and a signature — verified offline against a key set from one of three anchors, at best the
keys the platform already publishes, with the verifier reporting which one answered as
`key_source` (SPEC §8 step 4, THREAT_MODEL §2.1). Everything
below is a **designed extension point**, not a missing feature. Each is deferred on purpose,
because the guiding principle for a young protocol is:

> **Abstract at the second concrete case, not the first.** Generalizing from one implementation
> is guessing what the abstraction should be. The real shape comes from a second real user
> pulling against the first. Until then, the extension point stays a one-line note, not code.

The one thing `scpe/0.1` gets right *now* — because spec shape is cheap to change before
adoption and expensive after — is that the format does not paint itself into a corner. The
container (a **typed `subject` block** + a **`zero-or-more attestations[]` array**, all inside
the one signed `manifest.json`) is what lets each item below arrive later without redefining the
protocol.

**Implemented in the format as of `scpe/0.1` (structure only — extension slots, not new
guarantees):**

- **`attestations[]` array** (SPEC §5). The single `agent_trace` field is now a *list* of typed,
  signed claims. `agent-trace` is the one implemented type (carrying the `agent-trace/1`,
  `git-ai/notes`, `generic/1` formats with the same present-`<format>` / present-unverified
  status logic). An unknown `type` is surfaced as `present-unverified` — never an error, never a
  silent pass. This is what lets items 2 and 3 below land as *one more entry*.
- **Generic `subject` block** (SPEC §6). The code-specific `target` + `change` are now nested
  under a typed `subject` whose `type` the verifier dispatches on. `code-change` keeps exactly
  today's semantics (the §6 diff-normalization + integrity check is unchanged). An unimplemented
  or unknown `subject.type` fails **closed** to `unsupported-subject` — never `verified`. This is
  what lets item 4 below land without a format break.
- **Profile registry — the `core + profiles` model** (SPEC §13). Eight domain **profiles** are
  now **defined** as thin conventions over the artifact-agnostic core (a subject by hash +
  attestations + signature): `SCPE-C` (code), `SCPE-I` (image), `SCPE-V` (video), `SCPE-A`
  (audio), `SCPE-M` (model weights), `SCPE-DATA` (dataset), `SCPE-D` (document), and `SCPE-AR`
  (artifact — the catch-all). A profile is a **label** the producer stamps in the optional
  `profile` field and the verifier **surfaces** — it adds *no* verification logic and *no*
  integrity path: integrity is always by `subject.type`, and an unknown profile is
  surfaced-but-ignored, never an error. This is the **JWT/DSSE shape** — one small signed core,
  many domain conventions, no per-domain format fork. `SCPE-C` and `SCPE-AR` map onto the two
  already-implemented subject types (`code-change`, `artifact`); the other six are conventions
  over the same `artifact` machinery, so they needed no new code to become defined.

**Reserved, not implemented** (format placeholders that fail safe today): the `timestamp` and
`countersignature` attestation types (items 2 and 3), and artifact-verification-in-PR (item 4).
The `artifact` subject type itself is now **implemented for the standalone envelope** (SPEC §6.2);
what remains reserved is verifying an artifact carried through the PR transport, which has no
artifact payload.

---

## 1. Pluggable identity providers

**Implemented in `scpe/0.1`:** identity is a `(provider, subject)` pair resolved through a
**fixed provider registry**, not a hardcoded platform. Four providers ship: `github`
(`github.com/<subject>.keys`), `gitlab` (`gitlab.com/<subject>.keys`), `codeberg`
(`codeberg.org/<subject>.keys` — the Gitea/Forgejo endpoint shape, which also covers
self-hosted Gitea/Forgejo instances the verifier owner maps in), and `local` (an
owner-supplied keys file: fully offline / air-gapped / self-hosted, no network fetch). All four
resolve SSH public keys the same way — `<host>/<subject>.keys` or a local file — so the
verifier stays single-file auditable. The forge providers are universal from day one, not a
future promise. **The host for each forge provider comes from the verifier's fixed provider→host
table, never from the manifest** (SSRF-safe; see THREAT_MODEL §5 and SPEC §8).

**Reserved, not implemented:** heavier enterprise resolvers — `oidc`/`sigstore`, `x509` /
corporate PKI, `ldap`. These are **format-reserved**: an unknown or unimplemented `provider`
verify-resolves to status `unsupported-provider` (never an error, never a silent pass; SPEC
§11.1), so any of them can arrive in a later MINOR without a format break.

**Why the enterprise resolvers are deferred:** X.509 / OIDC / Sigstore / LDAP each multiply the
attack surface and threaten the single-file-auditable verifier — for demand that hasn't appeared
yet. The forge-plus-`local` set already makes the protocol platform-independent; add an
enterprise resolver when a second, enterprise, real demand actually asks for one.

## 2. Trusted timestamping

**Today:** the signed `created_at` is a non-repudiable *claim* of time — the author says when,
and can't alter it after signing.

**Direction:** a trusted third-party timestamp (RFC 3161, OpenTimestamps, or a Sigstore/Rekor
transparency log) turns the claim into a *proof of existence at time T* — the thing an audit or
a court asks for. The slot already exists: `timestamp` is a **reserved attestation type** in the
`attestations[]` array (SPEC §5.1), format-only and not implemented — a verifier surfaces it as
`present-unverified` today. Implementing it is adding one payload + one status check, never a
special feature and never mandatory (mandatory timestamping would kill the offline property,
which is a core value).

**Why deferred:** it unlocks the evidence/forensic use case, which belongs to the enterprise /
high-assurance segment — a hypothesis to validate, not yet a validated demand.

## 3. Level 3 — third-party countersignature

**Today:** the assurance ladder ships L1 (disclosure lint) and L2 (author-signed envelope).

**Direction:** author self-signing proves integrity and makes the disclosure non-repudiable,
but proves little about *who* — at best only what the GitHub account already asserts, and that
much only when the verifier resolved keys at the `forge` anchor (THREAT_MODEL §2.1). The strong
identity claim is a **third party** co-signing — a reviewer, or the agent platform attesting
"this came from session X of agent Y" (the in-toto model: the builder attests, not the author).
This is the real long-term moat. `countersignature` is a **reserved attestation type** (SPEC
§5.1), but honestly it is a placeholder that names the concept, not the mechanism: a signature
*over* the manifest cannot also be a *field of* the manifest it signs. The real form is a
**detached** co-signature transported alongside the envelope (or a Rekor-style log entry) — so
the substance of L3 is genuinely roadmap, and the reserved type only reserves the name so a
future MINOR can reference it without churn.

**Why deferred:** it depends on L1/L2 being adopted first, and on agent platforms being willing
to emit a countersignature — neither of which is proven yet.

## 4. Non-code subjects

**Today:** the spec and every example are about a software contribution (a diff).

**Direction:** the core — "a subject identified by its cryptographic digest + verifiable
evidence + a signature" — does not care whether the subject is a diff, an image, a PDF, an
`.onnx` model, or a dataset. Like Git (born for code, versions any file) and HTTP (born for
hypertext, carries anything), the generality is latent in the architecture. The `subject` block
is now the typed slot for it (SPEC §6): `artifact` = `{ digest: {sha256}, media_type }` is an
**implemented subject type for the standalone envelope** — the verifier hashes the enclosed
`artifact.bin` and compares to `digest.sha256` (match → `verified`, mismatch → `tampered`). One
honest limit remains: the check is **standalone-only**, because the PR transport carries a diff,
not an arbitrary artifact payload (**artifact-verification-in-PR is itself reserved**). An unknown
subject type still fails **closed** to `unsupported-subject`.

**Profiles name these domains without forking the format.** The eight profiles (SPEC §13) put a
name to each non-code domain — `SCPE-I` image, `SCPE-V` video, `SCPE-A` audio, `SCPE-M` model,
`SCPE-DATA` dataset, `SCPE-D` document, plus `SCPE-AR` as the catch-all — as *conventions* over
the existing `artifact` subject type, not as new subject kinds. That is exactly the "core +
profiles" discipline: the core stayed artifact-agnostic, and the domains arrived as labels, so
none of them cost a verification path.

**Launch positioning — code-first, spec-neutral.** The SPEC treats the eight profiles as **equal**
domain conventions and privileges none. The *product*, separately, leads with **`SCPE-C` (code)**
as the concrete entry point — the one problem with a clear buyer today — while the other seven
demonstrate the core's universality without being marketed as "SCPE for everything". Selling the
universality first destroys the one thing that makes a protocol adoptable: a clear problem it
solves. So the positioning is code-first; the format is domain-neutral. Someone can apply SCPE to
AI-generated images today by supplying an artifact, a media type, and (optionally) the `SCPE-I`
label — not by changing the container.

## 5. Multi-forge transport

**Today:** the polished transport (attestation in the PR body + a GitHub Action) is
GitHub-specific; the **standalone envelope** already works anywhere (email, artifact stores,
any forge) — a one-file verifier can check it today.

**Direction:** first-class transports for GitLab merge requests (attestation in the MR body +
GitLab CI), Gitea/Forgejo, and email (as `patatt`/`b4` already do for the kernel).

**Why deferred:** the envelope portability that matters is already there; the convenience
integrations follow real demand on a second forge.

---

## The gate for all of the above

Nothing here moves the number that decides the protocol's fate. That number is **adoption** —
whether anyone other than the author turns a level on. Each item is a *good* idea; building any
of them before the demand test would be more engineering aimed at a market that hasn't answered
yet. The order is: prove someone wants L1, then let the pull of real use — not the pull of a
clean design — decide what gets built next.
