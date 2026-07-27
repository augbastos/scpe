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
| **1** | An AI-disclosure signal is present: an `Assisted-by:` commit trailer or a checked PR-template checkbox in the free text a contributor already writes. | Zero — no install, no signing key, nothing fetched into the runner. Runs a stdlib-only lint straight out of the Action's own checkout. | Low. Self-reported, unsigned free text — trivially forgeable, and not tamper-evident. | **Implemented** (`level: "1"`) |
| **2** | A valid, signed SCPE envelope: identity verified against `github.com/<login>.keys` — through the Action a contribution cannot substitute the key set that judges it, because the transport carries no keys file to find (SPEC §9) — the diff matches byte-for-byte what was signed, and the manifest's signed `ai_disclosure` block is present. | Low–medium — one command (`scpe-envelope pack`, or `submit` to open the PR with the attestation already in the body) against a GitHub SSH key most contributors already have. | Medium–high. Cryptographically bound, non-repudiable, tamper-evident — but still self-signed: it proves *who signed*, not an independent judgment of *who is trustworthy*. | **Implemented** (`level: "2"`, default) |
| **3** | Everything level 2 checks, **plus** an independent countersignature from a maintainer or reviewer — not the contributor. | Higher — needs a second signer in the loop before the seal is complete. | High. The one lever that adds a claim beyond "this GitHub account produced this," because the second signature comes from someone other than the author. | **Roadmap — not implemented.** Setting `level: "3"` fails the Action step immediately with a clear error; it never silently falls back to level 2. |

## Why "higher implies lower"

Level 2 does not skip level 1's question — it answers it more strongly. The
mechanism is worth stating precisely, because it is not the one you would guess.

`ai_disclosure` is a MUST in the manifest (SPEC §3), and the reference producer
always writes it. What it is *not* is a step in the verification algorithm: SPEC
§8 never reads the field, and neither do any of the three verifiers. A hand-built
manifest that omits it can still reach `verified` — the signature covers whatever
the manifest contains, and an absent field is simply absent.
`spec/manifest.schema.json` does list it as required, but that file says of itself
that it is "DESCRIPTIVE / ADVISORY ONLY"; the normative check is §8.

So the implication is enforced where it belongs — **in the gate, not in the
verifier**. The Action's level-2 step reports `disclosure_present` alongside the
status, and under `require: "true"` a signed envelope carrying no disclosure fails
the check with a message that names the missing field. That keeps the protocol's
job small (prove who signed these exact bytes) and the policy's job explicit
(decide what this repository accepts), instead of smuggling a policy check into a
verification algorithm three independent implementations have to agree on.

The result is what the ladder claims: a passing level-2 check has *already*
answered "was AI use disclosed?" — the same question level 1's lint asks — except
the answer is a signed field inside a manifest bound to the exact diff, not an
unsigned line of PR-body text a contributor could edit after the fact. Level 3,
when it lands, will not replace level 2's checks either: it adds a second,
independent signer on top of everything level 2 already verifies.

## What level 2 does *not* prove about "who"

Read this before treating a `verified` level-2 seal as more than it is. Self-signing
proves two things and nothing more: the change wasn't altered after signing
(integrity), and the disclosure is non-repudiable (the contributor can't later deny
having made that specific claim). It does **not** prove anything about the
contributor beyond what `github.com/<login>.keys` already asserts — no
background check, no "verified human," no judgment independent of the GitHub
account itself.

One scoping note, because it is easy to carry this sentence too far. The ladder on this
page describes the **`augbastos/scpe` Action**, which runs the same SPEC §8 verifier as
everything else in this repo, over a transport that carries no keys file of its own — so
at level 2 the `forge` anchor is the one that answers and the account really was consulted.
The protocol is broader: a SPEC §8 verifier can also resolve keys from a file the
verifier's owner supplied or one carried inside the input, and reports which anchor
answered as `key_source`. A `verified` from such a run is worth what its anchor is
worth, and only `key_source == "forge"` reaches the ceiling described above
([`spec/THREAT_MODEL.md`](../spec/THREAT_MODEL.md) §2.1). The Action reaches the same
breadth through its `keys` input: hand it a keys file and it anchors at `flag` instead —
an air-gapped or `provider: local` run, chosen by the repository rather than by the
contributor. The seal prints that field either way — read it rather than the verdict
word alone, whatever produced it.

See [`spec/THREAT_MODEL.md`](../spec/THREAT_MODEL.md) §2 and §4 for
the full trust chain, and `spec/FAQ.md` for how this compares to `patatt`/`b4`, the
Linux kernel's own prior art for signed-patch attestation. The genuinely stronger
"who" claim — verified by someone other than the author — is level 3, and it is not
implemented yet.

## What the seal reports that the protocol does not

The Action's comment carries more than a status: a deterministic risk band, added/removed
line counts, the files touched, and an optional test run. **None of that is in SPEC.md.**
It is the Action's reporting layer, rule-based and reproducible — a report, not an
approval, and never an input to the verdict. `status`, `key_source`, `profile`, and the
attestation summary come from the verifier and mean exactly what SPEC §8 says they mean;
everything else on the seal is the Action's own convenience and can change without a
protocol version bump. If you are building a gate, gate on `status` (and, if identity is
the point, `key_source`) — not on the band.

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

Configure both inputs on the `augbastos/scpe` step in
[`docs/workflows/scpe.yml`](workflows/scpe.yml), which is also where the two-job
security model these levels sit on top of is written out in full: the job that
runs contributor code holds no secrets, and the job that posts the comment —
[`docs/workflows/scpe-seal.yml`](workflows/scpe-seal.yml) — never checks the
contribution out. Copy **both** files rather than the four-line snippet in the
README: the trusted half has to be a separate file (a workflow cannot name itself
in `workflow_run`), and the untrusted half checks out with `fetch-depth: 0`,
without which level 2 has no base commit to recompute the diff against.
