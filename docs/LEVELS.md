# SCPE assurance levels

The `augbastos/scpe` Action supports a `level` input, `"1"` or `"2"` today
(`"3"` is roadmap — see below). Levels are **cumulative**: each one implies
everything the level below it checks. This mirrors how
[SLSA](https://slsa.dev/spec/v1.0/levels) sells its own build-provenance
levels — start at the free tier, ratchet up as the friction becomes worth it —
applied here to the *contribution*, at the pull-request boundary, instead of
the *build*.

| Level | What it checks | Friction | Assurance | Status |
|---|---|---|---|---|
| **1** | An AI-disclosure signal is present: an `Assisted-by:` commit trailer or a checked PR-template checkbox in the free text a contributor already writes. | Zero — no install, no signing key, not even `pipx install scpe`. Runs a stdlib-only lint straight out of the Action's own checkout. | Low. Self-reported, unsigned free text — trivially forgeable, and not tamper-evident. | **Implemented** (`level: "1"`) |
| **2** | A valid, signed SCPE envelope: identity verified against `github.com/<login>.keys` — the Action always fetches those keys live and accepts no substitute — the diff matches byte-for-byte what was signed, and the envelope's `provenance` field (the AI-disclosure) is a required part of the signed manifest. | Low–medium — one command (`scpe pack` / `scpe seal`) against a GitHub SSH key most contributors already have. | Medium–high. Cryptographically bound, non-repudiable, tamper-evident — but still self-signed: it proves *who signed*, not an independent judgment of *who is trustworthy*. | **Implemented** (`level: "2"`, default) |
| **3** | Everything level 2 checks, **plus** an independent countersignature from a maintainer or reviewer — not the contributor. | Higher — needs a second signer in the loop before the seal is complete. | High. The one lever that adds a claim beyond "this GitHub account produced this," because the second signature comes from someone other than the author. | **Roadmap — not implemented.** Setting `level: "3"` fails the Action step immediately with a clear error; it never silently falls back to level 2. |

## Why "higher implies lower"

Level 2 does not skip level 1's question — it answers it more strongly.
`scpe/envelope.py`'s `Envelope` dataclass requires a `provenance` field with no
default; an envelope missing it fails to parse at all, long before signature
verification runs. So a `verified` level-2 result has *already* re-proven "was
AI use disclosed?" — the same question level 1's lint asks — except the answer
is a signed field inside a manifest bound to the exact diff, not an unsigned
line of PR-body text a contributor could edit after the fact. Level 3, when it
lands, will not replace level 2's checks either: it adds a second, independent
signer on top of everything level 2 already verifies.

## What level 2 does *not* prove about "who"

Read this before treating a `verified` level-2 seal as more than it is. Self-signing
proves two things and nothing more: the change wasn't altered after signing
(integrity), and the disclosure is non-repudiable (the contributor can't later deny
having made that specific claim). It does **not** prove anything about the
contributor beyond what `github.com/<login>.keys` already asserts — no
background check, no "verified human," no judgment independent of the GitHub
account itself.

One scoping note, because it is easy to carry this sentence too far. The ladder on this
page describes the **`augbastos/scpe` Action**, whose verification path is GitHub-only
and always fetches `github.com/<login>.keys` live — so at level 2 the account really was
consulted. The protocol is broader: a SPEC §8 verifier can also resolve keys from a file
the verifier's owner supplied or one carried inside the input, and reports which anchor
answered as `key_source`. A `verified` from such a verifier is worth what its anchor is
worth, and only `key_source == "forge"` reaches the ceiling described above
([`spec/THREAT_MODEL.md`](../spec/THREAT_MODEL.md) §2.1). If you build your own gate on
the SPEC verifier rather than this Action, check that field.

See [`spec/THREAT_MODEL.md`](../spec/THREAT_MODEL.md) §2 and §4 for
the full trust chain, and `spec/FAQ.md` for how this compares to `patatt`/`b4`, the
Linux kernel's own prior art for signed-patch attestation. The genuinely stronger
"who" claim — verified by someone other than the author — is level 3, and it is not
implemented yet.

## Adopting the ladder

Same order SLSA recommends for its own levels: start cheap, prove the workflow
works, then tighten.

1. **Start at level 1, `require: "false"`.** Zero friction, informational only —
   see whether contributors are disclosing AI use at all, with no gate blocking
   anyone.
2. **Turn on the gate at level 1: `require: "true"`.** Now an undisclosed PR fails
   the check. Still no signing key needed from contributors.
3. **Move to level 2 (the default), `require: "false"` first.** Let contributors
   who want the full signed envelope opt in and see the seal render, before it can
   block a merge.
4. **Gate on level 2: `require: "true"`.** Only a verified, signed SCPE envelope
   merges. This is "today's require/verify path" and is where most repositories
   that adopt SCPE seriously should land.
5. **Level 3, when it ships**, adds the independent countersignature on top —
   nothing below it changes.

Configure both inputs on the `augbastos/scpe@v0.1.2` step in
[`docs/workflows/scpe.yml`](workflows/scpe.yml); see
[`docs/action.md`](action.md) for the full two-job security model these levels
sit on top of.
