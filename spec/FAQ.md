# SCPE FAQ

**Spec:** `scpe/0.1` · **License:** CC BY 4.0

---

**Why SSH signatures and not GPG or Sigstore?**
Because the keys already exist. Nearly every GitHub contributor has an SSH key on
their profile, published at `github.com/<login>.keys`; `ssh-keygen -Y sign/verify`
ships with OpenSSH ≥ 8.2. GPG requires a parallel key ecosystem most contributors
never set up. Sigstore's keyless flow (OIDC via Fulcio) is excellent but introduces
an online CA and a transparency log — infrastructure SCPE deliberately avoids in
v0.1. Sigstore as an *alternative signing method* is on the `scpe/0.2` roadmap for
multi-forge and self-hosted use, where GitHub's key endpoint doesn't exist.

**Git already has signed commits, and GitHub shows a "Verified" badge. Why isn't
that enough?**
Commit signing proves *the committer signed that commit object*. It does not
survive the contribution path SCPE targets: fork PRs are routinely rebased,
squashed, or edited on merge, producing new, unsigned objects; and a commit
signature covers the commit — not the *contribution as a unit*: diff + base +
AI disclosure + attribution record. SCPE signs exactly that unit, travels with the
PR rather than the objects, and verifies against the contributor's published keys
without requiring the maintainer to trust GitHub's badge UI.

**Why does the attestation ride in the PR body instead of git notes?**
Because git notes don't travel with fork pull requests. Notes live in a separate
ref (`refs/notes/*`) that is not pushed by default and is not included in a fork's
PR branch — precisely the cross-trust-boundary path SCPE exists for. The PR body is
the one channel guaranteed to arrive with every PR, survives force-pushes to the
branch, and keeps the merged history clean (nothing SCPE-related lands in the tree).
The standalone envelope exists for every other transport.

**What is the relationship with Agent Trace and git-ai?**
Complementary, by design. Agent Trace (and git-ai, which implements it) records
*attribution*: which agent, model, and session produced which lines — self-reported.
SCPE carries that record inside the signed manifest as an `agent-trace` entry in the
`attestations[]` array (SPEC §5), converting "self-reported" into "signed and
attributable to a real GitHub identity, tamper-evident". Attribution tells you what;
SCPE proves who made the claim and that nothing was altered. SCPE does not validate
the record's content (see THREAT_MODEL §2).

**Why is the manifest an "evidence container" with a `subject` block and an
`attestations[]` array, instead of just a diff + an agent-trace field?**
Because the shape is cheap to get right *before* adoption and expensive after, and two
small generalizations make the format open without making it a framework. (1) The
`subject` block is a typed union (`subject.type`): `code-change` is a diff and
`artifact` is a hash-addressed file (standalone); a further kind slots in without a
format break. (2) `attestations[]` is a *list* of typed, signed claims, so a trusted
`timestamp` or a third-party `countersignature` becomes "one more entry", never a
special case. Both discriminators fail safe: an unknown `subject.type` returns
`unsupported-subject` and an unknown attestation `type` returns `present-unverified` —
never a silent pass. Everything still lives in the one `manifest.json` under the one
`manifest.sig`, and the reference verifier stays a single auditable file. `scpe/0.1`
*implements* `code-change`, `artifact` (standalone), and `agent-trace`; the rest is
reserved (docs/ROADMAP.md).

**What is the relationship with Sigstore, SLSA, and in-toto?**
Different layer. Those attest *artifacts and builds*: what produced a release, from
which sources, on which builder. SCPE attests a *contribution*: a diff from a
stranger, at the pull-request boundary, before it ever becomes part of a build.
SCPE's audit attestations already use in-toto Statement/DSSE formats where they fit.

**What's the relationship with `patatt` and `b4`?**
Direct prior art, not a new idea. `patatt` ([mricon/patatt](https://github.com/mricon/patatt))
signs individual email patches with a contributor's own PGP or SSH key, and `b4`
carries that attestation through the Linux kernel's actual patch-review pipeline at
kernel.org — this exact pattern (self-sign a contribution with a key the platform
already publishes, verify independently, no CA, no server) has been running in
production for years. SCPE applies the same shape to the GitHub pull-request
boundary instead of a mailing list, and standardizes on SSH signing against
`github.com/<login>.keys` instead of patatt's PGP/SSH duality. Honestly: self-signing
(Level 2 of the tiered model — see [../docs/LEVELS.md](../docs/LEVELS.md)) proves the
change wasn't tampered with and makes the disclosure non-repudiable; it does not prove
anything about "who" beyond what the GitHub account itself already asserts
(THREAT_MODEL §2, §4). A stronger identity claim — verified by someone other than the
author — is Level 3 (third-party countersignature), which is on the roadmap and not
implemented in `scpe/0.1`.

**Why is there no server?**
Because the entire point is that the owner re-verifies everything with their own
tooling: `ssh-keygen`, `git`, and GitHub's public key endpoint. A verification
service would just move the trust to whoever runs it. There is nothing to run, so
there is nothing to trust — and nothing to shut down.

**Does this make AI-generated code safe?**
No. SCPE proves origin and integrity, not quality or intent (THREAT_MODEL §2).
It gives maintainers a verified answer to "who sent this and was it altered?" —
review still decides "is it good?".

**Does SCPE help with the EU AI Act?**
SCPE is adjacent to — not a solution for — Article 50's machine-readable disclosure
obligations: it makes an AI-usage disclosure signed and tamper-evident, which is a
useful property, but Article 50 concerns marking AI-generated *content for
consumers*, which is a different problem.

**Why would a contributor bother?**
The cost is one command; the payoff is a verifiable identity on the contribution
(credited natively via GitHub Contributors) and a seal on the PR that the
maintainer didn't have to take on faith. As agent-authored PRs grow, "verified
origin" is the difference between a PR that gets read and one that gets closed.

**What does `verified` actually promise?**
Exactly this: *a key published on this GitHub account signed exactly this change
and this provenance statement, and the change you're looking at is byte-identical
to what was signed, after normalizing line endings.* Nothing else. See
THREAT_MODEL §2 before relying on it.

---

## "Why not just use X instead?"

These are the *"you should have used X"* objections. The alternatives are real and correct for
their own problems; each note says only why it isn't what `scpe/0.1` is — never that SCPE is
better, only that it aims at a smaller problem. The protocols with a full side-by-side (DSSE,
Sigstore, patatt/b4, C2PA, SLSA/in-toto, Agent Trace, DCO) are one-lined here and covered in
depth in [../docs/comparison.md](../docs/comparison.md).

**Why not DSSE?**
DSSE is a signing-envelope *primitive* that deliberately leaves identity, key distribution, and
subject hashing out of band; SCPE *is* that out-of-band layer, and SSHSIG already gives it DSSE's
byte-exact framing (SCPE reuses DSSE for audit-side attestations). Full comparison:
[../docs/comparison.md](../docs/comparison.md).

**Why not Sigstore?**
Sigstore's keyless flow needs an online CA (Fulcio) and public transparency log (Rekor), which
breaks v0.1's verify-offline / no-server property; it's on the `scpe/0.2` roadmap as an optional
signer. Full comparison: [../docs/comparison.md](../docs/comparison.md).

**Why not C2PA?**
C2PA is the standard for consumer *media* provenance — X.509 / trust-list, manifest embedded in
the asset — a different subject, trust model, and audience from a stranger's code diff; SCPE names
the media domains as future profiles, not a fight it's picking. Full comparison:
[../docs/comparison.md](../docs/comparison.md).

**Why not JWT?**
SCPE is deliberately *shaped like* a JWT (one small signed set of typed claims) but avoids a
literal one: JWT names its own algorithm in the token (the `alg:none` and RS256↔HS256 footguns)
and still needs identity out-of-band (JWKS/issuer). SCPE fixes the method to the SSHSIG namespace
`scpe/0.1` (SPEC §7) and resolves identity from the forge's `.keys` endpoint (SPEC §8).

**Why not OIDC?**
OIDC proves "a live session authenticated to an IdP" — ambient, online, and about a session, not
a signature over content. SCPE needs a durable artifact re-verifiable offline months later against
a published key. OIDC is reserved as the future `oidc`/`sigstore` provider; a verifier that meets
it today returns `unsupported-provider`, never a silent pass (SPEC §11.1).

**Why not X.509?**
X.509 buys a CA hierarchy, chains, and revocation — power SCPE's trust model doesn't use, paid for
in ASN.1 parsing surface the single-file verifier avoids. SCPE's root of trust is "whatever key the
forge publishes for this username" (THREAT_MODEL §2, §4), not a CA; "revocation" is simply the key
leaving the account. Reserved as the `x509` provider for real enterprise demand (SPEC §11.1).

**Why not blockchain?**
The claim is already tamper-evident from its SSHSIG signature (SPEC §7) — a ledger only publishes
it, and reintroduces the always-online dependency SCPE removes. The real gap,
proof-of-existence-at-time-T, is answered by the reserved `timestamp` attestation (RFC 3161,
OpenTimestamps, or Rekor), never a mandatory chain. A ledger does nothing for the *who* question.

**Why not a reputation or score system?**
A score would blur the guarantee — SCPE keeps *who signed / was it altered* (a cryptographic fact)
rigorously separate from *is it good* (a judgment, out of scope) — and any scorer reintroduces the
trusted third party the design removes. **Verified ≠ safe:** SCPE happily verifies malware signed
by its real author (THREAT_MODEL §2). Review decides quality; maintainer policy layers on top.

**Why GitHub as the first provider?**
The *format* isn't GitHub-specific — `scpe/0.1` implements `github`, `gitlab`, `codeberg`, and
`local`, all resolving keys the same `<host>/<subject>.keys`-or-file way (SPEC §8, §11.1) — but a
protocol needs one concrete buyer, and the fork-PR boundary on GitHub is the sharpest instance of
the problem. The set of hosts a verifier will contact is fixed at the verifier, never widened by a
manifest (the SSRF invariant, THREAT_MODEL §5).

**Why is the disclosure a signed claim, not a proof?**
A signature proves *who said it and that it wasn't altered* — not that the statement is *true*.
`manifest.sig` makes the AI disclosure non-repudiable and tamper-evident, converting an anonymous
self-report into a signed one; it can't prove what *actually* produced the code. SCPE signs
attestations, it does not validate their content (SPEC §5, THREAT_MODEL §2); the stronger
third-party claim is Level 3 countersignature (roadmap, not in `scpe/0.1`).
