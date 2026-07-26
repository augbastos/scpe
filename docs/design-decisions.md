# SCPE Design Decisions

**Spec:** `scpe/0.1` · **Status:** draft-pending-review · **License:** CC BY 4.0

This document records *why* the `scpe/0.1` container is shaped the way it is. It is
rationale, not normative text — [SPEC.md](../spec/SPEC.md) is the authority and
[THREAT_MODEL.md](../spec/THREAT_MODEL.md) is the security boundary. Each decision below
names the alternative it rejected and the cost it accepts, so a reviewer can check the
reasoning rather than take it on faith. Crypto migration (changing any of these choices
later) is covered in [SPEC.md Appendix B — Algorithm agility](../spec/SPEC.md#appendix-b-algorithm-agility).

---

## 1. SHA-256 for the diff / artifact digest

**Decision.** The integrity anchor is a SHA-256 digest: `subject.change.diff_sha256` for a
`code-change` subject (over the normalized diff bytes, SPEC §6.1) and `subject.digest.sha256`
for an `artifact` subject (over the raw bytes, SPEC §6.2).

**What the digest has to survive.** The digest is not a checksum for accidental corruption —
it is an adversarial anchor. The signed `manifest.json` carries the *hex digest*; the
signature covers the manifest; so the signature binds the contributor's identity to that
digest and, transitively, to the exact bytes it names. The verifier recomputes the hash from
the diff/artifact in front of it and compares (SPEC §8 step 7). Two attacks bound the hash
requirement:

- **Third-party tamper (second-preimage).** An attacker who edits the diff after signing must
  find a different input with the *same* already-signed digest — a second preimage of a fixed
  message.
- **Author bait-and-switch (collision).** The party who chooses the content is the party who
  signs it. A malicious contributor who could produce *two* diffs sharing one digest could get
  a benign one reviewed and sealed `verified`, then present the malicious one bearing an
  identical seal. This needs a full collision, and the attacker controls both messages — the
  stronger requirement.

The second attack is why **collision resistance**, not merely second-preimage resistance, is
the bar. That immediately rules out MD5 and SHA-1: the SHAttered attack demonstrated a
practical SHA-1 collision on 23 February 2017 ([shattered.io](https://shattered.io)), and
chosen-prefix SHA-1 collisions have since been shown, which is exactly the author-chosen
bait-and-switch shape. Git is transitioning its own object naming off SHA-1 for the same
reason ([git hash-function-transition](https://git-scm.com/docs/hash-function-transition)).

**Why SHA-256 specifically** — over SHA-512, SHA-3, or BLAKE2/3:

- **Zero-dependency ubiquity.** SCPE's reference verifier is a single stdlib-only file
  (SPEC Appendix A). SHA-256 is in every language's standard library (Python `hashlib`), in
  coreutils (`sha256sum`), and it is a hash SSHSIG itself can use for its message digest. A
  more exotic hash would add a dependency to a verifier whose auditability is its point.
- **256-bit output = ~128-bit collision resistance**, the current commodity security level.
  This is the same trade Git made when it picked SHA-256 as its SHA-1 successor: 256-bit
  length, widely available implementations, collision and second-preimage resistance, good
  performance (git hash-function-transition, verified).
- **Ecosystem alignment.** SCPE rides on Git, and Git's chosen successor hash is SHA-256.
  Picking the same hash keeps the two aligned as Git's transition matures (that transition is
  still experimental and opt-in, with protocol interop incomplete — an honest caveat, not a
  reason to pick differently).

**Scope and honesty.** This digest is an *application-level* content hash, distinct from the
message hash SSHSIG computes internally (`sha256`/`sha512`, ssh-keygen's choice). And a bare
digest proves nothing on its own — it is the *signature over the manifest that contains the
digest* that binds content to a real identity. Migrating the digest later (to SHA-3, BLAKE3, or
a quantum-hardened parameter) is a versioned change, covered in
[SPEC.md Appendix B — Algorithm agility](../spec/SPEC.md#appendix-b-algorithm-agility).

---

## 2. Sign the exact manifest bytes — no JSON canonicalization

**Decision.** `manifest.sig` is an SSHSIG over the *exact bytes* of `manifest.json` as they sit
in the envelope zip and travel in the PR. Producers MAY serialize however they like; verifiers
MUST NOT re-serialize, canonicalize, or pretty-print the manifest before checking the signature
(SPEC §4, §7). `json.loads` runs only *after* `ssh-keygen -Y verify` succeeds.

**The alternative we rejected: canonical JSON.** The obvious other design is to canonicalize the
JSON (e.g. [RFC 8785, JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)) so
that logically equal objects produce identical bytes, then sign the canonical form. RFC 8785
exists precisely because "cryptographic operations like hashing and signing need the data to be
expressed in an invariant format so that the operations are reliably repeatable." We decline it
for three reasons:

- **It makes every verifier carry a byte-exact canonicalizer.** JCS pins IEEE 754 number
  serialization, Unicode escaping, and property sorting by **UTF-16 code units** — and RFC 8785
  itself flags the hazards: IEEE 754 precision loss, the UTF-16 sort requirement, and
  stream-parser mishandling of string-encoded numbers/dates. Any divergence between two
  implementations yields either a valid signature that fails to verify, or — worse — two
  different documents that canonicalize to the same bytes.
- **It adds a security-critical dependency to the one file that must stay auditable.** A JCS
  bug is a signature-bypass bug. Signing raw bytes has no canonicalization step whose rules
  could drift, so an entire class of parser/serializer-divergence vulnerabilities simply does
  not exist here.
- **It is the proven shape.** JWS signs the encoded octets of the header and payload exactly as
  transmitted (never a re-serialization), and DSSE signs a byte-framed payload; both freeze the
  bytes and sign the bytes rather than canonicalize a structure. SCPE follows that family: the
  signed message is the bytes on disk.

**Cost accepted.** The manifest must *travel as bytes*, not be rebuilt from a parsed object. A
middlebox that pretty-prints or re-emits the JSON breaks the signature. That is acceptable, and
even desirable: SCPE's transports carry opaque bytes (a zip member; a base64 blob in a PR body),
and any reformatting of a signed manifest *should* read as tampering. Producers keep full
freedom over indentation and key order — the reference producer emits `json.dumps(indent=2)` and
signs those exact bytes — as long as they sign what they store.

---

## 3. The fixed provider→host table

**Decision.** Identity is a `(provider, subject)` pair. The host contacted to fetch a
contributor's keys comes **only** from a table baked into the verifier, keyed by the enum
`provider` (`github`→`github.com`, `gitlab`→`gitlab.com`, `codeberg`→`codeberg.org`, `local`→no
network). The manifest supplies the enum `provider` and a charset-validated `subject`, and
**nothing else** — no hostname, URL, scheme, port, or path (SPEC §8; THREAT_MODEL §5).

**Why.** The manifest is fully attacker-controlled: an envelope can name any provider and any
subject. If the fetch host could be *derived* from any manifest string, a crafted envelope could
point the verifier at a cloud metadata endpoint (`169.254.169.254`), a LAN address, or an
attacker-run host serving attacker keys — and the signature would then "verify" against those
keys, laundering a forged identity into a `verified` verdict. That is verifier-side SSRF, and it
is closed **by construction**: the set of hosts a verifier will ever contact is finite,
enumerable, and fixed *at the verifier*, never widened by input. The enum is reinforced by the
rest of the §8 fetch rules — the safe-subject charset `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` with no
`..`, substituted as a single URL path segment; HTTPS-only with TLS validation; no redirects
followed; and a final-URL recheck that the host is still the fixed one.

**Why an enum and not a URL allowlist in the manifest.** Even an allowlist checked against a
manifest-supplied URL is more attack surface than a lookup keyed by a closed enum: it is a
validator that can be gotten wrong. An enum cannot express a host at all — so there is nothing to
validate and nothing to mis-validate. This is "make invalid states unrepresentable" applied to
the SSRF surface.

**Cost accepted.** A closed registry means self-hosted and enterprise forges (Gitea/Forgejo
instances, GitLab EE, GitHub Enterprise) are **not** reachable from a manifest. That is the
point: adding a host is a *verifier-owner* decision, made out of band in verifier configuration,
never by the party submitting an envelope. The `local` provider (an owner-supplied keys file, no
network fetch) covers offline, air-gapped, and self-hosted verification. Heavier resolvers
(`oidc`/`sigstore`, `x509`, `ldap`) are format-reserved and fail closed to `unsupported-provider`
(SPEC §11.1) until a verifier owner opts in.

---

## 4. The PR body carries the attestation

**Decision.** In GitHub transport, the code change travels as a normal pull request and the
attestation — the envelope *without* `diff.patch`, base64-encoded — rides in the PR body inside
an HTML comment `<!-- SCPE-ATTESTATION-v1 … -->`. Producers emit exactly one block; verifiers use
only the first and ignore any others (SPEC §9).

**Rejected alternatives, and why the PR body wins:**

- **Git notes (`refs/notes/*`).** Notes are not pushed by default and are *not* included in a
  fork's PR branch — precisely the cross-trust-boundary path SCPE exists for (FAQ). The
  attestation would not arrive with the contribution.
- **A committed file in the tree.** It would land in the merged history (polluting the repo) and
  would be rewritten or dropped by a squash/rebase merge. The PR body keeps the merged tree
  clean: nothing SCPE-related lands in it.
- **A commit trailer.** Trailers are on commit objects, which fork PRs routinely rebase, squash,
  or edit on merge into new, unsigned objects — the same problem that makes commit signing
  insufficient here (FAQ).

**Why the PR body is the right channel.** It is the one place guaranteed to arrive with every
PR; it survives force-pushes to the branch (the branch objects change, the body does not); and it
fits GitHub's 65,536-character body limit — the transport attestation is only 1–2 KB in base64,
because the diff travels in the branch, not the body. The HTML comment is invisible in rendered
Markdown, so it does not clutter the human-readable description, yet is trivially
machine-extractable. The *exactly-one, first-only* rule stops an attacker appending a second
block to confuse extraction.

**Not a GitHub dependency.** The **standalone envelope** (with `diff.patch`) is the form for
every other transport — email, artifact stores, other forges — and the two verify identically
except for where the diff in step 7 comes from. The PR-body choice is a transport *convenience*
for GitHub; the protocol's integrity does not rest on GitHub. The honest limit is that
verification is defined at review time against the PR head (SPEC §10): after a squash or rebase
merge the final tree has no cryptographic link to the signed manifest, and the body comment
remains an auditable historical record. That is deliberate — see THREAT_MODEL §3.

---

## 5. No server

**Decision.** No SCPE-operated service participates in signing or verification. A verifier
re-derives every claim offline using only tools it already trusts: `ssh-keygen`, `git`, and a
key set from one of three anchors — a keys file the owner holds, a keys file carried inside the
input, or the provider's *existing* public-key endpoint (`<host>/<subject>.keys`), in that
precedence order (SPEC §8 step 4). No SCPE account, no SCPE API, no trusted third party
(SPEC §1; FAQ). Which anchor answered is reported as `key_source`, because removing the server
did not remove the trust question — it moved it to whoever supplied the keys (THREAT_MODEL §2.1).

**Why.** A verification service would not remove trust — it would *relocate* it to whoever runs
the service, creating a new trusted third party, a new availability dependency, a new attack
target, and a thing that can be compromised, subpoenaed, or shut down. SCPE's guarantee is that
the owner re-derives the result themselves from public inputs. In the repo's own words: "There is
nothing to run, so there is nothing to trust — and nothing to shut down" (FAQ).

**Cost accepted, stated plainly.** No central revocation, no key-transparency log, and no trusted
timestamp in `scpe/0.1`. Those properties are either delegated to whichever anchor answered —
trust-on-first-use at the provider's key endpoint when the run reaches `forge`, and trust in a
file the owner or the submitter supplied otherwise (THREAT_MODEL §2.1, §4) —
or deferred to the roadmap: trusted timestamping (RFC 3161 / OpenTimestamps / a Rekor-style log)
is a *reserved* `timestamp` attestation type, surfaced as `present-unverified` until implemented
(SPEC §5.1; ROADMAP §2). This is the same trade the FAQ makes against Sigstore's keyless flow:
Sigstore is excellent but introduces an online CA and a transparency log — infrastructure
`scpe/0.1` deliberately avoids, with Sigstore-as-an-alternative-signing-method left to the
roadmap. SCPE makes the provider-trust delegation *explicit* rather than papering over it with a
server that would still have to be trusted.

---

## Decisions at a glance

| Decision | Chosen | Rejected | Cost accepted |
|---|---|---|---|
| Content digest | SHA-256 (collision-resistant, stdlib-ubiquitous) | MD5/SHA-1 (broken); exotic hashes (dependency) | Migration needs a versioned change (SPEC.md Appendix B) |
| Signed message | Exact manifest bytes | Canonical JSON (RFC 8785) | Manifest must travel as bytes; reformatting breaks the seal |
| Key-fetch host | Fixed provider→host enum table | Manifest-supplied host/URL/allowlist | Enterprise forges need owner-side config, not a manifest field |
| Attestation transport | PR body HTML comment (+ standalone envelope) | Git notes; committed file; commit trailer | No cryptographic link after squash/rebase merge |
| Infrastructure | None (offline re-derivation) | A verification service | No central revocation / transparency / timestamp in v0.1 |

---

## Non-goals

What SCPE deliberately does not try to do. Not "not yet" — see [ROADMAP.md](ROADMAP.md) for the
deferred items that *are* on a path. This is the other list: things outside the protocol's job on
purpose, because trying to do them would either duplicate a tool that already exists, or turn a
small, auditable, offline-verifiable format into something that isn't. Each item points back to
where the spec, threat model, or FAQ already says so — this section collects the scattered "SCPE
does not..." statements in one place rather than asserting anything new.

**1. Code review, quality, or safety.** SCPE is not a linter, a static analyzer, or a review tool.
A `verified` result means the named key signed exactly this diff and this disclosure — it says
nothing about whether the diff is good, correct, or safe code. **A verified envelope can carry
verified malware, written by its real, verified author.** (SPEC §2, THREAT_MODEL §2: "Verified ≠
safe. Review still exists for a reason.") Deterministic risk-banding or test runs some tooling
layers on top of a seal are conveniences, not part of the protocol's guarantee.

**2. Truth of the provenance statement.** The signature proves *who made the claim*, not that the
claim is true. A contributor can sign `"mode": "none"` for fully AI-generated code, or an operator
can sign a fabricated attestation. SCPE converts an unsigned, anonymous self-report into a signed,
attributable self-report — that is the entire upgrade (THREAT_MODEL §2, SPEC §2: "The signature
proves who *made* the disclosure, not that the disclosure is honest").

**3. Defense against a compromised key or account — or a self-supplied one.** If an attacker
controls the private key behind `github.com/<subject>.keys` (or, for `local`, the owner's keys
file), SCPE verifies whatever they sign, because as far as the protocol can see, that *is* the
identity. There is no second factor, no anomaly detection, no revocation check beyond "is this key
still listed." And the cheaper version of the same non-goal: an attacker need not compromise
anything at all. Keys can also reach the verifier from *inside the input* — the `bundled` anchor,
SPEC §8 step 4 — so a submission can declare any `(provider, subject)` and enclose a key matching
its own signature, reaching `verified` with one `ssh-keygen` run and no forge contacted. That
anchor exists so offline conformance and air-gapped review work at all; the defense is not to
forbid it but to read the reported `key_source`, and to require `"forge"` when the decision
depends on the account being real. (SPEC §2, §2.1, THREAT_MODEL §2, §2.1, §4.) See
[THREAT_MODEL §6 "Known limitations"](../spec/THREAT_MODEL.md) for the residual-risk framing.

**4. A guarantee that outlives the merge.** SCPE's claims are defined **at review time, against the
pull request head** — not against whatever the repository's history looks like afterward. A squash
or rebase merge produces a new commit object with no cryptographic link back to the signed manifest;
the seal and the attestation remain as a historical record, not a live guarantee (SPEC §10, §2:
"Post-merge lifecycle" is out of scope). SCPE does not re-verify, re-derive, or re-attach provenance
after the tree changes shape.

**5. Proof of *what* produced the code, beyond a self-report.** An `agent-trace` attestation records
what the contributor (or their tooling) *claims* about which model or session wrote which lines.
SCPE signs and seals that claim; it does not independently verify it. Proving what actually produced
a change — execution attestation, a TEE-backed or provider-signed model output — is out of scope for
`scpe/0.1` (THREAT_MODEL §2). Same boundary as item 2, from the machine-attribution side.

**6. A trusted-timestamp / proof-of-existence service.** `created_at` in the manifest is a
non-repudiable *claim* of time — the signer asserts it and can't later deny having claimed it — not
a third-party-attested proof that the signature existed at that time. `timestamp` is a reserved,
unimplemented attestation type for exactly this reason (SPEC §5.1, ROADMAP §2); until it lands, do
not read `created_at` as forensic-grade.

**7. A key-transparency or certificate-authority system.** When a run reaches the `forge` anchor,
SCPE trusts whatever keys the declared provider publishes *at verification time* — trust-on-first-use
at the key endpoint, with no independent log of what a key was at some earlier point; when it
resolves at `flag` or `bundled` the endpoint is never consulted and the trust sits in the supplied
file instead (THREAT_MODEL §2.1). No log stands behind any of the three (see
[THREAT_MODEL §6 "Known limitations"](../spec/THREAT_MODEL.md)). SCPE introduces no CA, no online signing service, and
no transparency log of its own — that absence is the point (FAQ: "Why is there no server?").

**8. A replacement for commit signing.** Git commit signing and GitHub's "Verified" badge answer a
different question. A commit signature covers the commit object, which routinely doesn't survive a
fork PR's rebase/squash path; SCPE signs the *contribution as a unit* (diff + base + disclosure +
attestations) and travels with the PR rather than the commit objects (FAQ). SCPE targets the
pull-request boundary specifically, not a better commit-signing scheme.

**9. A build- or artifact-provenance system (SLSA / in-toto / Sigstore's usual job).** Those systems
attest what produced a *release build*, from which sources, on which builder. SCPE attests a
*contribution* — a diff from a stranger, at the pull-request boundary, before any build happens
(FAQ). SCPE's audit-attestation format borrows the in-toto Statement/DSSE shape where it fits, but
does not attest builder identity, build environment, or supply-chain steps downstream of the merge.

**10. An EU AI Act compliance solution.** SCPE's signed AI-usage disclosure is *adjacent* to Article
50's machine-readable-disclosure obligation, not a solution for it — Article 50 concerns marking
AI-generated content for consumers, a different problem from attesting a code contribution's
provenance to a repository owner (FAQ). Do not represent an SCPE seal as legal compliance with any
specific regulation.

**11. An independent judgment of "who this contributor is".** A Level 2 (self-signed) seal proves
the change wasn't altered after signing and that the disclosure is non-repudiable. It proves
**nothing about the contributor beyond what the provider's published keys already assert** — no
background check, no "verified human," no reputation signal independent of the account itself
([LEVELS.md](LEVELS.md), THREAT_MODEL §4). That is the *ceiling*, reached only when the verifier
resolved keys at the `forge` anchor; a `bundled` pass sits below it and asserts nothing about the
published keys at all (THREAT_MODEL §2.1). A materially stronger identity claim requires a second,
independent signer (Level 3 / countersignature), which is roadmap, not shipped.

**12. Universal artifact verification through every transport.** The `artifact` subject type verifies
a hash-addressed file, but only in a **standalone envelope** that actually carries the bytes
(`artifact.bin`). PR transport carries a diff, not an arbitrary artifact payload, so artifact
verification over a pull request is not implemented — a manifest that claims one there fails closed
to `tampered`, never `verified` (SPEC §6.2, §9). SCPE offers no way to attest a non-code artifact
*through* a GitHub PR the way it does for code.

**13. Multi-forge, first-class CI integration everywhere.** The polished transport — attestation in
the PR body plus a maintained GitHub Action — is GitHub-specific today. The standalone envelope
already verifies anywhere with a single-file verifier, but GitLab, Gitea/Forgejo, and email
transports (in the `patatt`/`b4` style) are not built; they are [ROADMAP.md](ROADMAP.md) item 5,
gated on real demand from a second forge, not a promise with a date.
