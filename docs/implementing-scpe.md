# Implementing an SCPE verifier in a weekend

**Spec:** `scpe/0.1` · **Status:** draft-pending-review · normative source:
[`../spec/SPEC.md`](../spec/SPEC.md) §8

This is a build guide for someone porting the verifier to a new language — Go,
Rust, TypeScript, whatever you've got a weekend for. It walks the same eight steps
as SPEC §8, in the same order, alongside the exact shell commands, byte rules, and
status codes the reference implementation
([`../reference/standalone/verify_envelope.py`](../reference/standalone/verify_envelope.py))
uses, so you can build against this document and check yourself against that file
line by line whenever something is ambiguous. If this guide and SPEC.md ever
disagree, **SPEC.md wins** — file a discrepancy, don't silently follow this doc.

Read [`../spec/SPEC.md`](../spec/SPEC.md) §1 first if you haven't — it explains *why*
the format is shaped this way (subject/attestations/profile as three independent
axes). This document is the *how*.

You do not need to implement a producer (the signing side) to conform — the 18 test
vectors (§9 below) already carry pre-signed manifests. A minimal weekend project is
**verify-only**.

---

## Prerequisites

- A way to shell out to `ssh-keygen` (OpenSSH ≥ 8.2 — check `ssh-keygen -Y verify`
  exists; older OpenSSH doesn't have SSHSIG's `-Y` subcommands). SCPE deliberately
  does not reimplement Ed25519/RSA/ECDSA signature verification or the SSHSIG
  wire format in-language — it shells out, same as the reference verifier does.
  Budget for this: your language's process-spawning ergonomics matter more here
  than its crypto library.
- A zip reader (every mainstream language has one in its standard library or a
  one-dependency package).
- A SHA-256 implementation (standard library, everywhere).
- An HTTPS client with **working TLS certificate and hostname validation by
  default**, and the ability to disable redirect-following. Confirm both before you
  start — some minimal HTTP clients follow redirects with no easy opt-out.
- Not required: a JSON canonicalizer. SCPE signs exact bytes; you will never
  re-serialize JSON for signature purposes (SPEC §4). Read the manifest bytes once,
  feed those same bytes to `ssh-keygen`, and only decode them into an object for
  field access afterward.

## Day 1 — locate, parse, resolve identity, verify the signature

### Step 1. Locate the envelope (SPEC §8 step 1)

Accept three input shapes, matching the reference verifier's `load_input`:

1. **A directory** containing `manifest.json` + `manifest.sig` (required), and
   optionally `diff.patch`, `artifact.bin`, `keys` — this is the shape every test
   vector directory uses (§9).
2. **An envelope zip** — a file starting with the `PK` zip magic bytes. Open it and
   check its member set is a subset of exactly
   `{manifest.json, manifest.sig, diff.patch, artifact.bin}`, and that it contains
   at least `manifest.json` and `manifest.sig`. Reject anything with an unexpected
   member name — that's cheap defensive parsing against a malformed or hostile zip
   (THREAT_MODEL §3 requires implementations to parse attestations defensively and
   cap size; the reference verifier caps manifest size at 1 MiB before it even
   decodes JSON — pick a similar cap, the exact number isn't normative).
3. **A text blob containing a compact attestation** — e.g. a saved PR body. Search
   for `<!-- SCPE-ATTESTATION-v1 ... -->` and base64-decode the interior. It must
   itself be a zip (`PK` magic) containing `manifest.json` + `manifest.sig` and
   **no** payload member (SPEC §9 — the compact form omits the diff/artifact).
   **Producers MUST emit exactly one block; verifiers MUST use only the first and
   ignore any subsequent ones** — use a non-greedy match and take the first hit,
   don't error on extras.

If none of the three match — no manifest, no attestation block, unreadable input —
that is not an error. Return **`unattested`**. An ordinary PR with no SCPE material
is a normal state, not a failure (SPEC §8 step 1, THREAT_MODEL §3).

### Step 2. Parse and check the version (SPEC §8 step 2)

Decode `manifest.json` as UTF-8 JSON. If it isn't valid JSON, or isn't a JSON
object, treat the manifest as unparsable — the reference verifier reports
`signature-invalid` here rather than a separate parse-error status, since an
unparsable manifest can never be checked against its signature either way; either
choice is defensible, but be consistent and document which one you picked.

`spec_version` is `"scpe/<MAJOR>.<MINOR>"`. Compare only the `scpe/<MAJOR>` prefix:

```
known_major = "scpe/0"
ok = (spec_version == known_major) or spec_version.startswith(known_major + ".")
```

An unknown MINOR of a known MAJOR (e.g. a hypothetical `scpe/0.7`) **MUST** verify
— new optional fields may have appeared and you should ignore ones you don't
recognize. An unknown MAJOR (`scpe/1.0`, `scpe/9.9`) **MUST** fail closed to
**`unsupported-version`** (SPEC §11). This is the `unknown-version` vector's exact
shape: a `scpe/9.9` manifest, otherwise valid, must stop here.

While you're in the manifest, read `profile` if present. If it's a string, hold
onto it — you'll surface it verbatim on every later outcome, success or failure.
It **never** affects any status decision (SPEC §13.2); it's purely something you
report alongside the result. An absent or non-string `profile` means unstamped;
surface that as absence, not an error.

### Step 3. Resolve the provider and validate the subject username (SPEC §8 step 3)

Read `contributor.identity = { provider, subject }`. `provider` is looked up in a
**fixed table baked into your verifier** — not read from any configuration the
manifest influences:

| `provider` | Host | Key URL |
|---|---|---|
| `github` | `github.com` | `https://github.com/<subject>.keys` |
| `gitlab` | `gitlab.com` | `https://gitlab.com/<subject>.keys` |
| `codeberg` | `codeberg.org` | `https://codeberg.org/<subject>.keys` |
| `local` | — | no network fetch; owner-supplied keys file |

Any other value — `oidc`, `x509`, `ldap` (reserved but not implemented, SPEC
§11.1), a typo, anything not in this table — is **`unsupported-provider`**. This is
never an error and never a silent pass: report it as its own status, distinct from
both `verified` and `signature-invalid`. This is the exact shape of the
`unsupported-provider` vector (an `oidc` identity).

Then validate `subject` (the username) against the **safe-subject rule** — this is
the SSRF guard, so get it exactly right (THREAT_MODEL §5):

```
regex:        ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$
additionally: the string must NOT contain the substring ".."
```

Both conditions, full match (not "contains a match" — the whole `subject` string
must satisfy the charset regex). A `subject` failing either check is
**`identity-unverifiable`** — this is the `identity-unverifiable-subject` vector
(a `subject` of `evil..traversal`). Do this check **before** you ever build a URL
from `subject` — the point of the rule is that a validated `subject` can only ever
occupy one predictable path segment, so there is nothing left for a hostile
manifest to break out of.

**Why this matters more than it looks like it should:** the manifest is entirely
attacker-controlled. `provider` is an enum, never a hostname — a contributor cannot
name a host at all, only pick one of four fixed values. `subject` is
charset-restricted to a single path segment. Between those two constraints, the URL
your verifier fetches is always exactly `https://<fixed-host>/<validated-subject>.keys`
— never anything a manifest chose end-to-end. If your implementation ever builds
the fetch URL from a manifest field *other* than substituting the validated
`subject` into the fixed per-provider template, you have reopened the SSRF hole
this design exists to close.

### Step 4. Fetch or read the keys (SPEC §8 step 4)

For `github` / `gitlab` / `codeberg`: fetch `https://<host>/<subject>.keys` with
every one of these properties — each is normative, not a nice-to-have:

- **HTTPS only**, with TLS certificate *and* hostname validation on (the default
  behavior of a correctly configured client — don't disable it for convenience).
- **MUST NOT follow redirects.** Any 3xx response is a fetch *failure*, not a hop
  to take. This matters because a redirect is exactly how an attacker (or a
  compromised/misconfigured forge) could bounce your verifier onto an internal
  address or downgrade the connection — the fixed-host guarantee from Step 3 is
  worthless if a redirect can silently retarget the request afterward
  (THREAT_MODEL §5).
- **Re-check the final URL** after the fetch completes: scheme still `https`,
  host still exactly the one you looked up. Some HTTP client libraries only expose
  "don't follow redirects" as "stop and return the 3xx", which is fine and
  equivalent — just make sure nothing in your stack quietly follows one anyway
  (proxies, DNS-level tricks, or a library default you didn't check).
- **Timeout and size-cap the response.** The reference verifier uses a 10-second
  timeout and caps the read at 1 MiB; pick comparable defensive limits — a slow or
  giant `.keys` response shouldn't be able to hang or exhaust your verifier
  (THREAT_MODEL §3).
- Unreachable, non-2xx (after the no-redirect rule already rejected 3xx), or an
  empty body → **`identity-unverifiable`**.

For `local`: perform **no network access at all**. Read the keys file your
verifier's own owner supplied out of band (e.g. a `--keys FILE` flag). Missing or
empty → **`identity-unverifiable`**. This is the fully offline / air-gapped path —
there is nothing to fetch, which is the strongest form of the SSRF defense.

If you're running the conformance vectors (§9), note that every vector ships its
own `keys` file precisely so your harness can substitute it for the network fetch
in this step — you should design your verifier to accept an override (a `--keys`
flag or equivalent) from day one, not bolt it on later. Real forge fetches and
vector conformance use the *same* code path with a different key source.

### Step 5. Build the allowed-signers file (SPEC §8 step 5)

`ssh-keygen -Y verify` needs an "allowed signers" file: one line per candidate key,
naming the principal that key is allowed to sign for. A `.keys` endpoint or a keys
file can list multiple keys (a user can have several SSH keys); emit one line per
key, all with the same principal:

```
<subject> namespaces="scpe/0.1" <key-type> <base64-key>
```

`<subject>` is the identity's username (from Step 3) — this is the **principal**,
not a filename. `<key-type> <base64-key>` is copied verbatim from each non-blank
line of the fetched/read keys body (a GitHub `.keys` response is already one
`<type> <base64>` pair per line — split on newlines, strip blank lines, done). If
the keys body has zero usable lines after that, treat it the same as an empty
fetch: **`identity-unverifiable`**.

Write this to a temp file. Clean it up when you're done — it contains no secrets
(these are all *public* keys), but there's no reason to litter the filesystem.

### Step 6. Verify the signature (SPEC §8 step 6)

```
ssh-keygen -Y verify \
  -f allowed_signers \
  -I <subject> \
  -n scpe/0.1 \
  -s manifest.sig \
  < manifest.json
```

- `-f allowed_signers` — the file from Step 5.
- `-I <subject>` — the principal you're checking the signature *for*; must match
  the identity's `subject`, not some other string.
- `-n scpe/0.1` — the SSHSIG namespace. **This is a fixed literal, not a variable**
  — it does not change per provider, per subject, or per anything else. A
  signature made under any other namespace must not verify (SPEC §7). This is what
  stops an SSH key that happens to also sign git commits or other SSHSIG-namespaced
  material from being replayed here.
- `-s manifest.sig` — the signature file.
- The manifest bytes go to **stdin**, exactly as read in Step 1/2 — the same bytes,
  not a re-encoded or pretty-printed copy.

Check the process exit code. Zero means the signature checked out; anything
non-zero (including "command not found" or a crash) means
**`signature-invalid`**. Don't try to parse `ssh-keygen`'s stderr for a more
specific reason — the status set doesn't distinguish "wrong key" from "corrupted
signature" from "wrong namespace"; they're all `signature-invalid`. (This is also
what the `invalid-signature` vector, `wrong-identity` vector, and a namespace
mismatch all reduce to — one status, several causes.)

**Everything before this point can be attacker-influenced with zero cost** — the
input, the claimed provider, the claimed subject, the manifest's contents. This is
the first point where you have cryptographic proof that whoever holds a key
published for `(provider, subject)` produced these exact bytes. Nothing you read
out of the manifest before this line should be treated as trustworthy for anything
beyond deciding *how to check the signature itself* (which provider table entry to
use, which subject to verify against). After this line, the manifest's fields are
authenticated.

---

## Day 2 — subject integrity, attestations, and the finish line

### Step 7. Dispatch subject integrity by `subject.type` (SPEC §8 step 7, §6)

Only now — after the signature has already checked out — read `subject.type` and
branch:

**`code-change`:**

1. Obtain the diff bytes: the enclosed `diff.patch` (standalone envelope), or an
   externally supplied diff (attestation form — normally `git diff
   <base_sha>...<head>` recomputed from the pull request; a CLI flag for manual/
   test use). No diff available at all → **`tampered`** (there's nothing to check
   the anchor against, so it can never default to `verified`).
2. Normalize it — **exactly** this transform, order matters:
   - Decode as UTF-8.
   - Replace every `\r\n` with `\n`, then every remaining `\r` with `\n`.
   - Strip trailing newlines, then append exactly one `\n`.
   - Re-encode to UTF-8 bytes.
3. SHA-256 the normalized bytes, hex-encode. The reference verifier compares the
   resulting hex string to `subject.change.diff_sha256` with plain string equality
   — it does not lowercase either side first. Standard hex digest output is
   lowercase in virtually every language's standard library, and every conformance
   vector's manifest was produced that way, so exact-match is what you should
   implement to match the reference byte-for-byte. (Lowercasing both sides first is
   a harmless hardening you may add on top, against a hypothetical producer that
   emits uppercase hex — just don't rely on the vectors to catch you if you get
   this wrong, since none of them exercise mixed case.)
4. Match → integrity holds, continue to Step 8. Mismatch, or `diff_sha256` missing/
   empty → **`tampered`**.

Do **not** use `git patch-id` or any whitespace-insensitive diff comparison as a
substitute — SPEC §6.1 explicitly forbids it as an integrity anchor, because it
ignores whitespace, which is semantic in indentation-sensitive languages. It's fine
as an *informational*, non-normative matcher if you want one; it must never gate
`tampered`/`verified`.

**`artifact`:**

1. Obtain the raw bytes: the enclosed `artifact.bin` (standalone only — an
   `artifact` subject has no PR-transport payload) or an externally supplied file.
   No bytes available → **`tampered`** (same reasoning as above: nothing to check,
   never defaults to `verified`).
2. SHA-256 the bytes **exactly as given — no normalization of any kind**. An
   artifact may be binary; there is no canonical line-ending or encoding to impose.
3. Hex-encode and compare against `subject.digest.sha256` with plain string
   equality — same rule as the diff case above (no case-folding in the reference
   verifier). Match → continue. Mismatch or missing digest → **`tampered`**.

**Anything else** (a `subject.type` that is neither of the above — a typo, a
future type your verifier hasn't implemented yet, an attacker's made-up string):
**`unsupported-subject`**. This is the fail-closed branch (SPEC §6.3): never guess
an integrity check for a kind of subject you don't understand, never fall through
to `verified`, never conflate it with `tampered` (which would wrongly imply a check
actually ran). This is what the `unsupported-subject` vector exercises — a
`container-image` subject type, under an otherwise-valid signature, must still stop
here.

### Step 8. Summarize attestations, then return `verified` (SPEC §8 step 8, §5.3)

If subject integrity held, you're done with checks — build the per-entry
attestation summary and return. For each entry in `attestations[]` (an absent or
non-array field means the summary is `[]`):

```
if entry.type == "agent-trace" and entry.format in {"agent-trace/1", "git-ai/notes", "generic/1"}:
    status = "present-" + entry.format
else:
    status = "present-unverified"
```

That covers: a recognized `agent-trace` format, an `agent-trace` entry with an
unrecognized `format`, either reserved type (`timestamp`, `countersignature`), and
any entirely unknown `type` — all four of the last three cases collapse to
`present-unverified`, never an error, never silently dropped from the summary
(SPEC §5.3). Return the list as `[{type, status}, ...]`, preserving the manifest's
entry order.

Final result: **`verified`**, carrying the attestation summary and the `profile`
string you held onto back in Step 2 (surfaced verbatim, unconditionally — it never
changed anything, it's just along for the ride now).

## The status table

Eight statuses total, verification stops at the first one reached (SPEC §8):

| Status | Reached at | Meaning |
|---|---|---|
| `unattested` | Step 1 | No SCPE material found in the input. Not a failure — a plain PR is simply unattested. |
| `unsupported-version` | Step 2 | `spec_version`'s MAJOR isn't one you implement. |
| `unsupported-provider` | Step 3 | `contributor.identity.provider` isn't in your fixed table. |
| `identity-unverifiable` | Step 3 or 4 | Malformed/unsafe `subject` username, or keys unreachable/empty. |
| `signature-invalid` | Step 6 | SSHSIG verification failed. |
| `unsupported-subject` | Step 7 | `subject.type` isn't one you implement — fail-closed. |
| `tampered` | Step 7 | Recomputed hash doesn't match the signed anchor (or no payload to check). |
| `verified` | Step 8 | Every check above passed. Carries the attestations summary + surfaced profile. |

A verifier's exit code / boolean success should be `true` **iff** the status is
exactly `verified` — every other status is a form of "no", even the harmless-looking
`unattested`.

## 9. Run the 18 conformance vectors to prove you match

You do not get to declare conformance by reading SPEC §8 carefully — you prove it
by running your verifier against
[`../spec/test-vectors/`](../spec/test-vectors/), which is normative (SPEC Appendix
A): **an implementation that produces the expected status for all eighteen
conforms to §8.**

Each vector is a directory with:

```
manifest.json    the signed manifest, exact bytes
manifest.sig     SSHSIG over those bytes, namespace scpe/0.1
diff.patch       (code-change vectors only) the normalized diff
artifact.bin     (artifact vectors only) the raw artifact bytes
keys             simulated <provider-host>/octocat-test.keys body — substitute
                 this for the network fetch (also the sole key source for `local`)
expected.json    { "status": "...", "attestations": [ {type, status}, ... ] }
```

Write a small harness — a shell loop, a table-driven test in your language's test
framework, whatever fits — that for each vector directory:

1. Runs your verifier against the directory, passing `keys` as the key-source
   override (never hit the real network for these — they're offline by design).
2. Compares the returned `status` against `expected.json`'s `status`.
3. Where `expected.json` includes an `attestations` array, compares your per-entry
   `{type, status}` summary against it too (order-sensitive, per SPEC §5's list
   semantics).

The eighteen vectors, and what each one is actually checking:

| Vector | Exercises |
|---|---|
| `valid-minimal` | The baseline happy path — `github` identity, no attestations. |
| `valid-gitlab` | The `gitlab` provider entry in your table. |
| `valid-codeberg` | The `codeberg` provider entry. |
| `valid-local` | The `local` provider — no network fetch, owner-supplied keys file. |
| `valid-agent-trace-generic` | An `agent-trace` entry, `format: generic/1` → `present-generic/1`. |
| `valid-agent-trace-gitai` | `format: git-ai/notes` → `present-git-ai/notes`. |
| `valid-agent-trace-real` | `format: agent-trace/1`, a full Agent Trace record → `present-agent-trace/1`. |
| `invalid-signature` | Manifest bytes edited after signing → `signature-invalid`. |
| `tampered-diff` | Diff doesn't hash to `subject.change.diff_sha256` → `tampered`. |
| `wrong-identity` | A valid signature, but the signing key isn't in `keys` → `signature-invalid`. |
| `unknown-version` | `spec_version: "scpe/9.9"` → `unsupported-version`. |
| `unknown-trace-format` | An `agent-trace` entry with an unregistered `format` → `verified`, `present-unverified`. |
| `unsupported-provider` | `provider: "oidc"` (reserved, not implemented) → `unsupported-provider`. |
| `unsupported-subject` | `subject.type: "container-image"` under a *valid* signature → `unsupported-subject`, fail-closed. |
| `identity-unverifiable-subject` | `subject: "evil..traversal"` → `identity-unverifiable`, safe-subject rule. |
| `valid-artifact` | An `artifact` subject, `artifact.bin` matches `digest.sha256` → `verified`. |
| `tampered-artifact` | An `artifact` subject, bytes don't match the digest → `tampered`. |
| `multi-attestation` | Two entries: one known `agent-trace` (`present-generic/1`) and one reserved `timestamp` (`present-unverified`) in the same manifest — proves entries are judged independently. |

If your verifier passes all eighteen, you match §8. If it fails one, the vector
name tells you which step to re-read — that's why they're organized this way
rather than as one opaque batch. A useful sequencing if you're building
incrementally: get `valid-minimal` green first (that alone forces you through
Steps 1–8 for the easy path), then `invalid-signature` and `tampered-diff` (proves
your two hash/signature failure paths actually fail), then the remaining
provider/version/subject-dispatch vectors, which mostly exercise Step 3 and Step 7
branches you'll already have written.

Two things the vectors deliberately do **not** cover, because they're not part of
`status` and aren't normative on their own: the exact wording of any human-readable
`detail`/error message you attach, and the `profile` field (SPEC §13 — advisory,
never asserted on by the normative vectors; see
[`../spec/test-vectors/README.md`](../spec/test-vectors/README.md) and the
per-profile walkthrough in `examples/`). Match `status` — and `attestations` where
given — exactly; everything else is yours to design.

## What you don't need to build

Worth saying plainly, since "implement SCPE" can sound bigger than it is: you do
not need a JSON canonicalizer, a custom crypto implementation, a server, an
account system, or a database. The entire trust chain is `ssh-keygen` (already on
your system if you have OpenSSH ≥ 8.2), a zip reader, SHA-256, and an HTTPS client
you've configured correctly. That's what "single-file, stdlib-only" in the Python
reference verifier's own docstring is claiming, and it's true of a from-scratch
implementation in any language with those four things in its standard library.
