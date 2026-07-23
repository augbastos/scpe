# SCPE Threat Model

**Spec:** `scpe/0.1` · **Status:** draft-pending-review · **License:** CC BY 4.0

SCPE's security claims are narrow on purpose. This document states exactly what the
protocol defends against, what it explicitly does not, and the residual risks a
verifier accepts. If you read only one section, read §2.

---

## 1. What SCPE defends against

| Threat | Defense |
|---|---|
| **Contributor impersonation** — "this PR is from alice" when it is not | `manifest.sig` verifies only against the keys the contributor's declared provider publishes for `subject` (e.g. `github.com/alice.keys`, `gitlab.com/alice.keys`, or the owner's `local` keys file), resolved through the fixed provider→host table (SPEC §8; SSHSIG, namespace `scpe/0.1`). Whoever signed controls a key on that `(provider, subject)` identity. |
| **Verifier-side SSRF** — a crafted manifest tries to make the verifier fetch keys from an attacker-controlled host | The key-fetch host comes **only** from the verifier's fixed provider→host table, keyed by an enum `provider`. The manifest carries no hostname/URL/path; `subject` is charset-validated and used as a single path segment. See §5. |
| **In-transit tampering of the change** — the diff is altered after signing (by a platform, a middlebox, or an attacker editing the branch) | `subject.change.diff_sha256` binds the signed manifest to the exact normalized diff bytes; for a `code-change` subject the verifier recomputes the hash from the PR head and compares (§8 step 7). Whitespace-only attacks are caught: the hash is over exact bytes, not a whitespace-insensitive digest. |
| **Tampering of the provenance statement** — someone edits the AI disclosure or an attestation entry in the PR body | The `subject`, `ai_disclosure`, and every `attestations[]` entry all live inside `manifest.json`, which is covered by `manifest.sig`. Any edit invalidates the signature. |
| **A forged or swapped subject/attestation type** — a crafted manifest names a subject or attestation `type` the verifier does not implement, hoping it is waved through | Typed discriminators fail safe. An unimplemented `subject.type` → `unsupported-subject` (§6.3), never `verified`; an unknown `attestations[]` `type` → `present-unverified` (§5.3), never a silent pass. The verifier never guesses a check for a type it does not implement. |
| **Repudiation** — the contributor later denies having made the disclosure | The disclosure is signed with the contributor's own key; the signature is non-repudiable evidence of *who claimed what*. |
| **Forged disclosure by third parties** — attacker attaches an AI disclosure "on behalf of" someone else | The attestation only verifies against the declared login's published keys. |

## 2. What SCPE does NOT defend against — read this

**A valid seal means: "a key published for this `(provider, subject)` identity signed
exactly this change and this statement." It means nothing more.** In particular:

- **Compromised provider account or stolen SSH key.** Whoever controls the keys the
  provider publishes for `subject` (or, for `local`, the owner's keys file) *is* that
  identity, as far as SCPE can see. The root of trust is the provider's key endpoint,
  delegated entirely.
- **A malicious but genuine author.** SCPE happily verifies malware signed by its
  real author. Verified ≠ safe. Review still exists for a reason.
- **A false disclosure.** The signature proves *who made the claim*, not that the
  claim is true. A contributor can sign `"mode": "none"` for fully generated code;
  an agent operator can sign a fabricated Agent Trace attestation. SCPE converts
  "anonymous self-report" into "signed, attributable self-report" — that is the
  entire claim, and nothing stronger. Proving *what actually produced* the code
  (execution attestation, TEE-backed or provider-signed model output) is out of
  scope for `scpe/0.1`.
- **Provider availability and integrity.** If the provider's `.keys` endpoint (e.g.
  `github.com/<subject>.keys`) is unreachable, verification degrades to
  `identity-unverifiable`; if the provider itself served attacker-controlled keys,
  SCPE would verify against them. This delegation is per-provider and identical in
  shape across `github`/`gitlab`/`codeberg`; `local` moves the same trust to the
  keys file the verifier's owner controls.
- **Anything about code quality.** SCPE is not review, not a scanner, not a policy
  engine. Deterministic risk bands and test runs shipped alongside seals are
  conveniences layered on top, not part of the protocol's guarantees.

## 3. Residual risks and accepted limitations

- **TOFU at the key endpoint.** SCPE trusts whatever keys the provider publishes at
  verification time. There is no independent key-transparency log in `scpe/0.1`.
- **Key rotation breaks old attestations.** When a key leaves the contributor's
  provider account, envelopes signed with it become `identity-unverifiable`. Historical
  verifiability (witness logs, archived allowed-signers snapshots) is a `scpe/0.2`
  roadmap item. Verifiers who need durable evidence SHOULD archive the verification
  result (the seal) at review time, not just the envelope.
- **Squash/rebase merges sever the post-merge link.** Verification is defined at
  review time against the PR head (SPEC §10). After a squash merge, the final tree
  has no cryptographic connection to the signed manifest; the seal and attestation
  remain as historical record only. Maintainers needing post-merge traceability
  should merge without squashing or archive the standalone envelope.
- **The `unattested` state is not a failure.** Ordinary PRs remain ordinary. A
  policy that *requires* attestations is the owner's choice, outside the protocol.
- **Replay across targets.** A `code-change` manifest pins `subject.target.repo` and
  `subject.target.base_sha`; replaying an envelope against another repo or base fails
  at §8 step 7 because the recomputed diff context differs — but an identical diff
  applying cleanly to an identical base in a *fork* of the same project verifies
  identically. That is by design (the envelope is portable), and verifiers MUST check
  `subject.target.repo` matches the repository they are actually protecting.
- **Denial of service.** Oversized or malformed members MUST be size-capped and
  parsed defensively by implementations. The reference implementation caps every
  member — `manifest.json` at 1 MiB, and each of `manifest.sig` / `diff.patch` /
  `artifact.bin` at 64 MiB — as a decompression-bomb defense, and enforces both
  caps on **both** input paths it accepts: the zip path (checked against the
  member's declared size before decompressing) and the directory path (checked
  against the file's on-disk size before reading); it also rejects unexpected zip
  members. This closes what was previously a gap on the directory path (an
  oversized manifest there used to reach `verified`).

## 4. Trust chain, explicitly

```
Provider account  (provider, subject)          [ local: owner-supplied keys file ]
  └─ publishes → <fixed-host>/<subject>.keys      host from the verifier's fixed
        │           (github.com | gitlab.com |    provider→host table, NOT the manifest
        │            codeberg.org)
        └─ contains → SSH public key
              └─ verifies → manifest.sig  (SSHSIG, namespace scpe/0.1)
                    └─ covers → manifest.json (exact bytes) — the signed evidence container
                          ├─ binds → subject          (type-dispatched; code-change →
                          │            subject.change.diff_sha256 → the exact diff)
                          ├─ binds → ai_disclosure    (signed claim)
                          └─ binds → attestations[]   (each entry a signed claim)
```

Every link above the provider's endpoint is cryptographic; the top link is delegated
provider trust. SCPE makes that delegation explicit instead of pretending it away.
Crucially, *which* endpoint is contacted is chosen by the verifier's fixed table, not
by the manifest (§5).

## 5. Provider resolution is SSRF-safe

Identity in `scpe/0.1` is a `(provider, subject)` pair (SPEC §8). The manifest is
attacker-controllable — an envelope can name any provider and subject — so provider
resolution is treated as a request-forgery surface and closed by construction:

- **Fixed provider→host table.** The host contacted for keys is looked up from a
  table baked into the verifier, keyed by the enum `provider` (`github`→`github.com`,
  `gitlab`→`gitlab.com`, `codeberg`→`codeberg.org`). The manifest never carries a
  hostname, URL, scheme, port, or path — only the enum `provider` and the `subject`.
  A contributor therefore cannot steer the verifier at an internal metadata endpoint,
  a LAN address, or any host not already in the table.
- **Charset-validated subject as a single path segment.** `subject` must match
  `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` and must not contain `..`. This bars `/`,
  whitespace, `@`, `:`, and path traversal, so the fetched URL is always exactly one
  predictable segment (`<fixed-host>/<subject>.keys`) — no breakout, no host
  injection, no request smuggling via the username.
- **HTTPS-only, no-redirect fetch.** The key fetch (SPEC §8 step 4) MUST use HTTPS
  with TLS certificate and hostname validation and MUST NOT follow HTTP redirects: a
  3xx — or any redirect to a different host, scheme, or port — is a fetch failure,
  not a hop the verifier takes. Otherwise a compromised or misconfigured forge (or a
  future owner-registered self-hosted host) could bounce the verifier onto an
  internal address or downgrade the transport, re-opening the SSRF surface the fixed
  table closes. The reference verifier installs a redirect-refusing handler, pins an
  explicit TLS-validating context, and re-checks that the final response URL is still
  the fixed host over HTTPS.
- **Self-hosted / enterprise forges are an owner decision, out of band.** Gitea/
  Forgejo instances, GitLab EE, or GitHub Enterprise are reached only by the
  **verifier owner** adding a provider→host mapping in their own verifier
  configuration. This authority lives with the party running the verifier, never
  with the party submitting a manifest — so the trust boundary stays where it
  belongs.
- **Unknown providers fail safe.** A provider outside the implemented registry —
  unknown, or format-reserved-but-unimplemented (`oidc`, `x509`, `ldap`; SPEC §11.1)
  — resolves to status `unsupported-provider`: never an error the caller can mistake
  for a transport hiccup, and never a silent pass. The verifier declines to guess a
  host for a provider it does not implement.
- **`local` performs no network fetch at all.** For air-gapped, offline, or
  self-hosted verification the owner supplies a keys file directly; there is no
  outbound request to forge, which is the strongest form of this defense.

## 6. Known limitations — and what a verifier owner can do

Every residual risk in §2 and §3 is a deliberate boundary of a self-signed, offline,
no-server protocol, not a bug to fix in `scpe/0.1`. This section does not restate those
failure modes; it attaches the mitigation a verifier's *owner* can apply **today**, and
records one further limitation that §2–§3 do not yet name. All of them share one root:
**SCPE's trust chain terminates at the provider's key endpoint** (§4). The mitigations
below are things the verifier's owner does, not something the protocol will silently
start doing.

- **Key or account compromise** (§2, §4). Treat a `verified` result as "this account's
  key signed it," not as identity assurance beyond what the provider already vouches for.
  The actual mitigation — 2FA and key rotation on suspicion — lives on the *contributor's*
  side, outside SCPE entirely.
- **False disclosure** (§2). Weight a signed disclosure as "this person is now
  non-repudiably on the hook for this specific claim" — useful for accountability and
  dispute resolution after the fact — not as a truth oracle at merge time. Nothing in
  SCPE substitutes for reading the diff.
- **Squash/rebase post-merge gap** (§3, SPEC §10). Maintainers who need post-merge
  traceability should merge without squashing, or archive the standalone envelope (the
  full zip, `diff.patch` included) alongside the merge, so the original signed record
  survives independently of what the tree does afterward.
- **TOFU and key rotation** (§3). §3 already states the owner action: archive the
  verification result (the seal) at review time, not just the envelope. A seal recorded
  while the key was still valid stays meaningful even after the key later disappears from
  the account.

**No trusted timestamp.** `created_at` in the manifest is whatever the signer wrote,
covered by the signature — non-repudiable ("you can't later claim you didn't say this was
the time"), but not independently attested. Nothing stops a signer from backdating or
postdating it, and nothing in `scpe/0.1` catches that. A real answer (RFC 3161,
OpenTimestamps, or a transparency log like Rekor) needs a third party or a public log —
exactly the infrastructure a v0.1 that prizes offline, no-server verification defers
deliberately. The extension point already exists and is empty on purpose: `timestamp` is
a **reserved** attestation type (SPEC §5.1) that a verifier surfaces as `present-unverified`
(ROADMAP §2) — the slot is real, the implementation is not. *Owner action:* do not treat
`created_at` as forensic-grade evidence of *when* something happened until a `timestamp`
attestation is present and its format implemented; corroborate timing out of band (e.g.
the PR's own creation time on the platform) if it matters to your decision.

## 7. Malicious maintainer / compromised key model

§1 is a table of *external* attackers — impersonators, SSRF, a middlebox editing a
branch. That is the smaller half of the supply-chain picture. The party best placed to do
harm is usually not an outsider forging an identity but an *insider using a real one*: a
maintainer holding a genuine, provider-published key, or an attacker who has *become* that
maintainer by taking the key. SCPE verifies every scenario below as `verified`, because in
each the signature is genuine and the diff is exactly what was signed. That is the whole
point of stating this separately from §1: **`verified` is a statement about the key, not
about the person or the code.**

| Insider scenario | What a `verified` seal proves | What it does **not** prove |
|---|---|---|
| **A legitimate maintainer signs malware.** A trusted contributor knowingly ships a backdoor under their own key. | The backdoor diff is byte-for-byte what this account's key signed; the author cannot later deny it. | That the code is safe. SCPE is not review and not a scanner (§2). |
| **A legitimate key is stolen and used.** An attacker exfiltrates the SSH key (or takes over the provider account) and signs as the victim. | A key the provider publishes for `subject` signed this change. | That the *human* `subject` signed it. Whoever controls the key *is* the identity, as far as SCPE can see (§2, §4). |
| **An intentionally bad release.** A maintainer signs a real, even fully disclosed change whose *intent* is hostile — a deliberately weakened check, a data-exfil path, a licensing trap. | Provenance and integrity of that exact change. | Anything about intent; SCPE has no notion of "good" or "hostile" (§2). |
| **A false-but-signed attestation.** The signer stamps `"mode": "none"` over AI-generated code, or attaches a fabricated `agent-trace` entry. | *Who* non-repudiably made that claim. | That the claim is *true*. An attestation proves who claimed, never that the claim holds; SCPE signs claims, it does not validate their content (§2, §5, SPEC §5). |

Stated centrally, so it is not left scattered across §2's bullets: **SCPE proves
PROVENANCE, not SAFETY.** A `verified` result means *this diff is exactly what a key
published for this `(provider, subject)` identity signed, and nothing was altered
afterward* — nothing about whether the code is correct, whether it is safe, or whether the
signer is honest. Against a malicious insider the value SCPE adds is **attribution after
the fact**: the signature binds the bad change non-repudiably to a key, which is what an
incident response or a dispute needs — not prevention at merge time. Prevention is review,
and review still exists for a reason (§2). None of this is peculiar to SCPE — every signing
system that roots trust in a key the signer controls inherits the same boundary; SCPE's
part is to make the boundary explicit (§4) rather than imply a safety it cannot deliver.

## 8. Key lifecycle and revocation

**SCPE has no server and carries no revocation list.** No CRL, no OCSP, no
key-transparency log, no "this key was compromised as of date D" signal exists anywhere in
the format — by construction, because a v0.1 that verifies offline against nothing but the
provider's `.keys` endpoint has no third party to publish such a list and deliberately
declines to introduce one (§2, §3). What partially stands in for revocation is not a
mechanism SCPE builds but a property of *when* keys are read.

**Fetch-time keys.** Identity is checked against the keys the provider publishes **at
verify time** (SPEC §8 step 4), never against a key list frozen into the envelope. That one
property does most of what a revocation list would:

- **Removing a key from the account stops future verification.** When a key leaves the
  contributor's `<host>/<subject>.keys` — rotated on suspicion, revoked after compromise,
  or dropped when the person offboards — the next verifier to fetch that endpoint no longer
  finds it, and any envelope relying on it resolves to `identity-unverifiable` (§3). No
  coordination and no push: the account owner deletes the key, and verification of anything
  it signed simply stops the next time a verifier fetches. This is the *only* "revocation"
  `scpe/0.1` has, and it is implicit.

Three honest limits keep that from being a real revocation mechanism:

- **It is not retroactive.** A seal already emitted while the key was live is **not**
  invalidated by the key's later removal. That is deliberate — an archived seal records
  that verification *did* succeed at review time (§3, §6) and stays a true record — but it
  means removing a compromised key does **not** distrust what that key signed *before* the
  compromise was noticed. A real revocation list can say "distrust everything after date
  D"; SCPE cannot. Removal only bites *future* fetches.
- **It cannot tell rotation from compromise.** A key vanishing from the endpoint carries no
  reason, no timestamp, no scope. "Rotated for hygiene" and "revoked because stolen" are
  the same event to a verifier: the key is gone, verification stops, nothing says why or
  as-of-when.
- **An offline snapshot is only as fresh as the snapshot.** The `local` provider (and any
  archived `.keys` copy) reads the keys the owner supplied, not the live endpoint — so it
  never sees a later removal at all. An air-gapped verifier trusts its snapshot until the
  owner refreshes it. That freshness is the owner's operational responsibility, and the
  offline property that makes `local` valuable is precisely what forgoes live revocation —
  a tradeoff, not an oversight.

**Roadmap, explicitly out of scope for `scpe/0.1`.** The durable direction is not a
revocation list SCPE would host, but a stronger *positive* claim that does not hinge on a
single self-managed key: a **third-party countersignature / delegation** (Level 3), where a
reviewer or the agent platform co-signs, so trust no longer rests on one account's key
hygiene (LEVELS.md L3; ROADMAP §3). `countersignature` is a reserved attestation type (SPEC
§5.1) that today surfaces as `present-unverified` — the name is reserved; the mechanism (a
*detached* co-signature, since a signature over the manifest cannot be a field of it) is
roadmap, not built. Historical verifiability — a witness log or archived allowed-signers
snapshot that lets an old seal be re-checked after key removal — is the matching `scpe/0.2`
item already named in §3. Until either lands, the owner action is unchanged and already
stated in §3 and §6: **archive the verification result (the seal) at review time**, so a
check made while the key was valid stays meaningful after the key is gone.
