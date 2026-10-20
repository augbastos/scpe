# SCPE assurance levels

The `augbastos/scpe` Action supports a `level` input, `"1"` or `"2"`.
See the [project state](../README.md) before adopting it. Level 3 was on the roadmap;
with the project frozen it remains an unimplemented historical proposal (not
implemented, not a planned release). Levels are **cumulative**: each one implies
everything the level below it checks. This mirrors how
[SLSA](https://slsa.dev/spec/v1.0/levels) presents its build-provenance levels,
applied here to the *contribution* at the pull-request boundary instead of the
*build*. Under `require: "true"`, level 2 also requires a signed AI disclosure; the
checks are described below.

| Level | What it checks | Friction | Assurance | Status |
|---|---|---|---|---|
| **1** | An AI-disclosure signal is present: an `Assisted-by:` commit trailer or a checked PR-template checkbox in the free text a contributor already writes. | Zero — no install, no signing key, nothing fetched into the runner. Runs a stdlib-only lint straight out of the Action's own checkout. | Low. Self-reported, unsigned free text — trivially forgeable, and not tamper-evident. | **Implemented** (`level: "1"`) |
| **2** | A valid signed envelope, a recognized `ai_disclosure.mode`, a `forge` or operator-supplied `flag` key anchor, and matching PR context for `code-change` envelopes. The diff digest is checked after line-ending normalization. An `artifact` verifies its content, not its relationship to the PR. | Requires an SSH signing key and an envelope from `scpe-envelope pack` or equivalent tooling. | Binds the manifest and content digest to the signing key. Identity assurance depends on the key source; authorship and truthfulness are not established. | **Implemented** (`level: "2"`, default); the workflow enforces the decision when `require: "true"`. |
| **3 (historical proposal)** | Proposed: level 2 plus an independent countersignature from a maintainer or reviewer. | Would require a second signer. | No implemented assurance; the mechanism was not completed. | **Not implemented or planned.** Setting `level: "3"` fails the Action step. |

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
unsigned line of PR-body text a contributor could edit after the fact. The
historical L3 proposal would have added an independent signer to those checks.

## What level 2 does *not* prove about "who"

Read this before treating a `verified` level-2 seal as more than it is. Verification
checks that the supplied content matches the signed digest and that the manifest's
signature matches the resolved keys. It does **not** prove anything about the
contributor beyond that key source — no background check, no "verified human,"
and no independent judgment of authorship. A compromised key or provider account
undermines the corresponding identity claim.

One scoping note, because it is easy to carry this sentence too far. The ladder on this
page describes the **`augbastos/scpe` Action**, which runs the same SPEC §8 verifier as
everything else in this repo. Its default PR-body transport carries no keys file of
its own, so without an explicit `keys` input it attempts the `forge` anchor.
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
Linux kernel's prior art for signed-patch attestation. An independent
countersignature was the intent of level 3; no such check is implemented.

## What the seal reports that the protocol does not

The Action's comment carries more than a status: a deterministic risk band, added/removed
line counts, the files touched, and an optional test run. **None of that is in SPEC.md.**
It is the Action's reporting layer, rule-based and reproducible — a report, not an
approval, and never an input to the verdict. `status`, `key_source`, `profile`, and the
attestation summary come from the verifier and mean exactly what SPEC §8 says they mean;
everything else on the seal is the Action's own convenience and can change without a
protocol version bump. To build a gate, set `require: "true"` and accept only
`gate_pass === true` in the result JSON (the Action exposes it as the string
output `gate-pass`, which must equal `"true"`). `status` and `key_source` alone
do not implement L2 policy: a `verified` result with an accepted anchor still
fails the gate if disclosure is missing or the `code-change` context does not
match. With `require: "false"`, `gate_pass` is always true; the risk band never
decides acceptance.

## Configuring the supported levels

The existing Action can report findings or supply a gate decision. These are
configuration options for L1 and L2, not a development roadmap.

1. **Start at level 1, `require: "false"`.** Zero friction, informational only —
   see whether contributors are disclosing AI use at all, with no gate blocking
   anyone.
2. **Turn on the gate at level 1: `require: "true"`.** Now an undisclosed PR fails
   the check. Still no signing key needed from contributors.
3. **Move to level 2 (the default), `require: "false"` first.** Let contributors
   who want the full signed envelope opt in and see the seal render, before it can
   fail the verification job.
4. **Gate on level 2: `require: "true"`.** Only a verified, signed SCPE envelope
   can pass, with disclosure, an accepted key anchor, and matching PR context
   for `code-change` envelopes. Artifact envelopes skip PR-context checks.
   The verification job must enforce `gate_pass`; the composite Action emits
   the decision without failing on a negative verdict.

Configure both inputs on the `augbastos/scpe` step in
[`docs/workflows/scpe.yml`](workflows/scpe.yml), which is also where the two-job
security model these levels sit on top of is written out in full: the job that
runs contributor code holds no secrets, and the job that posts the comment —
[`docs/workflows/scpe-seal.yml`](workflows/scpe-seal.yml) — never checks the
contribution out. Copy **both** files rather than only the Action step in the
[setup guide](protocol.md#maintainer-setup): the trusted half has to be a separate file (a workflow cannot name itself
in `workflow_run`), and the untrusted half checks out with `fetch-depth: 0`,
without which level 2 has no base commit to recompute the diff against.
