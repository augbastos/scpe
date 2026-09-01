# SCPE Threat Model

**Spec:** `scpe/1` · **Status:** draft · **License:** CC BY 4.0
**Date:** 2026-09-01

The subject of this threat model is **a file found on disk**, not a submission arriving at a
gate. That is the change from `scpe/0.1`, whose model assumed a known verifier owner, a known
repository, and an identity resolved through a fixed provider→host table. None of those
exist now, and several defences that depended on them had to be rebuilt rather than
inherited. The archived `scpe/0.1` model is at
[../docs/THREAT_MODEL-scpe-0.1-archived.md](../docs/THREAT_MODEL-scpe-0.1-archived.md).

Normative requirements live in [SPECIFICATION.md](SPECIFICATION.md). This document explains
what those requirements defend and, at greater length, what they do not.

---

## 1. What SCPE is trying to protect

One property, stated precisely:

> **A reader of a verification result is never misled about what was established.**

Note what that is *not*. It is not "the file is genuine", not "the model really produced
this", and not "the provenance is complete". SCPE cannot deliver any of those, and a design
that appears to is more dangerous than one that delivers nothing — which is why the failure
mode this model treats as most severe is **a result that reads stronger than its evidence**,
not a signature that fails to verify.

---

## 2. Trust boundaries

### TB-1 · Producer → verifier

Everything in the record crosses this boundary and the producer controls all of it. The
important part is not that the data may lie — §1.3 admits that — but that the record also
**steers the verifier**: how many signatures are checked, how many edges are traversed, how
much is parsed.

Two mitigations, both structural:

- **The role is discovered, not read.** A signature is tried under each registered namespace
  and the one it verifies under *is* its role (§8.3). The payload's `role` field cannot
  choose which namespace the verifier uses, so a record claiming `observer` while carrying a
  producer-namespace signature is not treated as an observation.
- **The payload is not parsed until a trusted key has vouched for it.** Signature
  verification precedes statement parsing, so attacker JSON is never interpreted on the
  strength of its own claims (§9 steps 4–6).

Everything countable is bounded (§13.3), because counts drive work: signatures spawn
subprocesses, edges drive traversal.

### TB-2 · Verifier → trust anchor

Four anchors, and they are **not** equally trustworthy. This is the boundary the whole
project is about.

| Anchor | Who chose the key set | Consequence |
|---|---|---|
| `policy` | The operator, in their own `allowed_signers`. | The only anchor where a lie requires compromising the operator's own file. |
| `forge` | A code-hosting provider, for a named account. | Requires a network fetch; governed by §13.4. |
| `flag` | The operator named a path — but often the *producer* wrote the file. | **Measures ceremony, not evidence.** |
| `bundled` | The producer. | The input asserts who signed it. Worthless as identity evidence. |

`flag` deserves the blunt statement it now gets in the spec: pointing a verifier at a key
file the producer supplied, and pointing it at the same directory without the flag, differ by
one command-line argument and not by one bit of evidence.

**Mitigation:** `attribution` and `lineage` are capped by `anchor` (§10.5). Where several
signatures contribute, the reported anchor is the **weakest** of them.

### TB-3 · Verifier → artifact bytes

Arbitrary bytes, hashed. Bounded by size, and non-regular files (device nodes, FIFOs) are
refused rather than read — hashing `/dev/zero` is not a verification (§13.3).

### TB-4 · Verifier → parent records

In the ordinary distribution case — artifact, sidecar and parents in one directory tree — the
producer assembled everything the verifier will consult. A producer shipping five self-signed
parent records is resolving its own claims against its own files.

**Mitigation:** `lineage` is capped by `anchor`, and there is no `complete` value at any depth
(§6.3, §10.7).

### TB-5 · Verifier → importers (C2PA, Sigstore, OMS)

This is the largest attack surface in the design and it is opt-in for a reason: reading a
C2PA manifest means running JUMBF, CBOR, COSE and X.509 parsers over attacker bytes.

**The trusted computing base of the core verifier is: the Python standard library, plus
`ssh-keygen`.** Importers are outside it. Their output enters as `declared[]` and
`present-unverified`, never as `proved[]`, and an importer failure is `tooling-error` — never
a silently lower facet.

There is an uncomfortable consequence worth naming: today, the only path to an
`attribution` value above `self-asserted` with real files runs through the C2PA importer.
**The one route to a stronger claim is the one that maximises parsing attack surface.** That
is a real tension in this design and not a solved problem.

### TB-6 · Verifier → `ssh-keygen`

The verifier passes a policy path, a principal, a namespace, a signature file and the payload;
it receives an exit code and English stderr.

**The principal is never taken from the record.** It is read out of the operator's own policy
by `ssh-keygen -Y find-principals`, and no attacker-controlled string is ever interpolated
into a policy line. For anchors where a policy file must be synthesised, principals are
synthetic (`k0`, `k1`, …) and derive from nothing in the input. The retired implementation
interpolated a caller-supplied subject into a policy line; that seam is gone.

**A limit that cannot be engineered away:** `ssh-keygen -Y verify` returns 255 for a bad
signature, a wrong principal (silently, with no stderr at all), an unreadable policy file and
a namespace mismatch alike. A verifier **MUST NOT** parse that English to invent a
distinction it does not have, and **MUST** report the honest, coarse result. §13.1's
`tooling-error` row is scoped to an *absent* backend for exactly this reason.

### TB-7 · Verifier → renderer

`declared[]` is attacker-authored text that §11.3 **requires** a renderer to display. Strings
are length-capped, and a conforming renderer must never emit them as active content, must
label them as unverified claims, and must not place them beside `proved[]` entries.

This boundary exists because the anti-laundering property is defeated by presentation alone:
a model name shown next to a green tick reads as verified no matter which array it came from.

---

## 3. Adversaries

### ADV-1 · The dishonest producer
Signs `generation.model = "claude-opus-4-5"` having called nothing. **Undefended, and
correctly so** — no signature scheme can establish what a signer did before signing.

The residual value is non-repudiation, and it exists **only at `anchor: policy` or `forge`**.
At `bundled` or `flag` the producer also supplied the key, so there is nobody to repudiate to.
`self-asserted` at `policy` and `self-asserted` at `bundled` are different claims, which is
why the anchor is a first-class facet and not a footnote.

### ADV-2 · The transplanter
Takes one valid record and attaches it to different bytes. Defeated by the subject digest
inside the signed payload — **when bytes are supplied**. With `binding: unbound` nothing is
compared, and that is an ordinary outcome, not an error.

### ADV-3 · The lineage squatter
Controls a widely-published input file and wants to appear in other people's lineage.
Defeated on `parentOf`, where the pin to the parent's signed statement is REQUIRED.
**Undefended on `componentOf` and `inputTo`**, where a pin may legitimately be absent because
the input is often a file nobody ever signed. The verifier reports `lineage: declared` and
names the unpinned edge in `not_checked[]`; it cannot detect the substitution.

### ADV-4 · The false countersigner
Wants a record to look independently corroborated. This adversary defeated an earlier draft
of this design, and the fix was to stop making the claim:

An earlier `attribution: host-observed` required only that the observer key differ from every
producer key. One person generates a second key in about a second, lists both in their own
`allowed_signers`, countersigns their own record, and the facet reads as independent
corroboration. **This was demonstrated, not theorised.**

No stricter offline check repairs it. Nothing in `allowed_signers` distinguishes a
colleague's key from a second laptop key, so **no offline verifier can tell two keys from two
parties.** The facet was therefore renamed to `countersigned` and reports only the mechanical
fact — a second key, under a different principal, signed this statement about these bytes —
with a gloss that says it does not establish a second party. Anchor caps close the
`bundled`/`flag` variants.

### ADV-5 · The network position
Only reachable if the operator opts in twice. §13.4 requires HTTPS-only, certificate and
hostname validation, **outright refusal of redirects**, a final-URL host recheck, refusal of
userinfo and non-default ports, and caps on size, count and time.

The starting position is worse than `scpe/0.1`'s, and honestly so: that version carried no
hostname, URL, scheme, port or path in its manifest at all. in-toto's `ResourceDescriptor`
carries `uri` and `downloadLocation`, so the invariant had to be rebuilt as rules rather than
inherited from the data model. **The default remains: do not dereference.**

### ADV-6 · The compromised producer environment
Distinct from ADV-1 and, for the stated agentic use case, more likely. An honest producer
whose signing key is reachable by the process it is attesting: a signing oracle, a key file
readable by an agent with filesystem access, an agent induced to emit a record for output it
did not generate. The agent and the key live on the same machine.

**Undefended.** SCPE records what a key signed; it cannot know what persuaded the key to sign.

### ADV-7 · The malicious sidecar author
Attacks the parser rather than the semantics. Bounded by §4.7 (caps checked before
allocation, bounded reads, duplicate keys refused at any depth) and §13.3 (explicit limits on
every count). Base64 decoding is strict, so the envelope's bytes cannot be made malleable
while the decoded payload stays stable.

### ADV-8 · The unsolicited claimant
Signs `digitalSourceType: trainedAlgorithmicMedia` over someone else's human-authored
photograph, anchors it to their own key, and leaves the sidecar beside it. Monotonicity
guarantees this is always possible (§1.3): anyone may make a record about anyone's file.

A conforming verifier correctly reports a valid signature and a **declared** AI-generation
claim. Whether a reader is misled depends entirely on how prominently `anchor` and
`declared[]` are shown — which is why renderer conformance (§2) is a normative requirement
and not a style guide.

---

## 4. What SCPE cannot defend

Stated without hedging, because the project's only real asset is that this list is complete.

1. **Sidecar stripping.** A removed record is indistinguishable from one that never existed.
   Related and equally undefended: **substitution** (a valid record from a different signer
   replaces yours) and **discovery downgrade** (deleting `<path>.scpe.jsonl` promotes
   whatever sits at a lower slot in §7.2's search order — deletion is an upgrade primitive
   for whoever controls one).

2. **A dishonest producer.** Every entry in `declared[]` may be false.
   `attribution: self-asserted` is the machine-readable statement of that fact.

3. **Chain truncation and equivocation.** A signer may present whichever of two internally
   valid chains suits them, and may drop trailing history. A transparency receipt over the
   earliest statement is the only known answer and is not required by this version.

4. **Replay.** No nonce, no required timestamp, and `producedAt` raises nothing. A valid
   record can be re-presented for a different production run of byte-identical output.
   *Bounded, not solved:* because the subject digest is inside the signed payload, a replayed
   record can only ever attach to **the same bytes** it was made for.

5. **Key rotation.** `allowed_signers` offers `valid-after=` and `valid-before=`, which are
   the correct mechanism — **and they are inert without a verified time anchor.** Since
   `time: unanchored` is the near-universal state, the one rotation-safe control the chosen
   backend provides does not function in the default deployment.

6. **Revocation between anchor refreshes.** Offline verification cannot see a revocation.
   This is the same hole GitHub documents for `gh attestation verify`. *Not yet evaluated:*
   `ssh-keygen -Y verify` accepts `-r <revocation_file>`, and an operator-maintained KRL
   would be an offline, CA-free revocation surface that fits this project's constraints. It
   is not implemented and its end-to-end semantics over SSHSIG have not been tested here.

7. **Anchor freshness.** The result says which *kind* of anchor answered, not how old it was.
   An `allowed_signers` last edited years ago and one edited this morning look identical.

8. **Signature-suite strength.** `signature: valid` reads identically for every allowlisted
   suite. There is no way to say "valid, under a suite you should stop accepting."

9. **Role separation outside SSHSIG.** Namespace domain separation is what makes
   `countersigned` meaningful, and `sigstore-bundle`, `x509-…` and `ml-dsa-44` carry no
   namespace. Under those suites the facet is not reachable.

10. **Assurance inflation outside the record.** A README, a badge, a dashboard or a filename
    can claim anything. §10.1 defends the channel the format controls; it cannot reach the
    others.

---

## 5. Residual risk for the current deployment

One maintainer, no CA, no transparency log, offline by default, public repo.

- **The reachable facet vector is a floor:** `anchor: policy|flag|bundled`,
  `attribution: self-asserted`, `time: unanchored`, `lineage: none|declared`. Every rung above
  it needs either a genuinely separate operator-listed principal, or an importer (TB-5), or a
  provider that does not currently sign text output.
- **The blast radius is reputational, not operational.** No user data, no money, no
  production system depends on this. The realistic cost of a mistake is publishing a claim a
  hostile reader can falsify by reading the specification against itself, which is why
  §13.1's table states the **scope** of every defence rather than asserting completeness.
- **This document is expected to be wrong somewhere.** Findings are welcome per
  [../SECURITY.md](../SECURITY.md). Two of the sharpest entries above — ADV-4 and the
  `ssh-keygen` exit-code limit in TB-6 — came from adversarial review of an earlier draft,
  and one of them was proved by execution rather than argument.
