# Your project has an AI policy. Who enforces it?

*Launch essay for SCPE. Status: spec `scpe/0.1`, tooling `v0.2.2`, **no external adoption**.
Every claim here is meant to survive a stranger checking it.*

---

In 2026, open source started writing rules for AI. OpenSSL now asks contributors to name the
tool in the commit itself — `Assisted-by: {agent}:{model}`, so `Assisted-by: Claude:claude-sonnet-4-6`,
one trailer per tool. MicroPython added a checkbox to its pull request template: *I did not use
generative AI tools when creating this PR* / *I used generative AI tools, but a human has checked
the code and is responsible for it.* Fedora, the EFF, and others published their own policies.
And curl ended a bug-bounty that had run since April 2019, after the confirmed-vulnerability
rate on incoming reports fell below one in twenty — "an explosion in AI slop reports combined
with a lower quality even in the reports that were not obvious slop."

Writing the policy is the easy part. The question underneath it is:

**When a pull request comes in, who checks that the disclosure is actually there?**

I assumed the answer was "a human, eventually, if they remember." Then I asked two of the
projects named above, in public, and was told otherwise. This section is what they said, because
publishing the guess after being corrected would be a strange thing for a provenance tool to do.

**OpenSSL checks.** Every pull request triggers their CLA service, which reads each non-trivial
commit, looks for the `Assisted-by:` trailer — with `Co-authored-by:` naming a known AI tool as
a backstop — and posts a `cla-check` commit status. What it enforces is the *consequence*: an
AI-assisted commit from a signer still on CLA 1.0 fails and is held under a `hold: cla required`
label until they re-sign 1.1. Signers already on 1.1 pass either way. So the trailer is
load-bearing for the licensing decision rather than for presence, and whether presence itself is
checked for 1.1 signers is a question I have open with them.

**MicroPython does it by eye, and says it works.** A collaborator there told me omission is rare,
and that the few cases he can recall were contributors circumventing the template rather than
leaving the box blank — which a lint on the box would not catch anyway. He also reads past the
box, because some authors add context a checkbox cannot hold.

Then he said the thing that should worry anyone building a gate: *"most authors quickly correct
when reminded by a human, less so when CI is showing ❌."* That is the strongest argument against
this essay's original framing, and it came from someone with more evidence than I have. If a red
check produces **less** compliance than a person asking, automating the reminder is not
self-evidently an improvement, and the word *gate* is worse than unnecessary.

What survives is narrower than what I started with. A policy in `CONTRIBUTING.md` is still a
request rather than a gate, and a contributor can still open a pull request that never mentions
the tool that wrote most of it. What I can no longer claim is that nobody noticed the problem:
one of the first two projects I asked had already built the automation I was guessing did not
exist, and the other has data suggesting it would not help them.

## The smallest thing that might help

**Level 1** is a GitHub Action that does one thing: check that the AI-use disclosure is present —
the `Assisted-by` trailer, or the checkbox your template already has. No signing, no new tools,
zero cost to the contributor.

Whether that is worth turning on looks like a question about your project rather than a general
truth, which is not how this paragraph originally read. At MicroPython's volume, with reviewers
who read past the box, the answer appears to be no — and the reason is not "we haven't got to
it", it is that a human's reminder works better than a red check. The case for it is a project
without that reviewer bandwidth, or one where the volume already exceeds what noticing can
cover.

So: a reviewer aid, not a gate. `require: "false"` — report, never block a merge — is the
default for that reason, and stays the default.

That's it. That's the whole first level. It's deliberately boring, because boring is what gets
adopted.

## Then you can climb

Enforcing *presence* is useful, but a disclosure is still just a claim. A contributor can type
`Assisted-by: none` over fully generated code. So there's a ladder:

- **Level 1 — Disclosure.** The declaration is present. Zero friction.
- **Level 2 — Signed.** The contribution rides inside a signed envelope: the change is bound to
  a claimed GitHub identity and to a SHA-256 of the exact diff. The *tamper-evidence* half is
  unconditional — recompute the diff, compare the hash, done, with no server. The *who* half
  depends on where the keys came from, and the verifier always says which: `forge` means it
  fetched them from the account's own git host, `flag` means the maintainer supplied them,
  `bundled` means they arrived inside the submission. Only the first two say anything about the
  named account. A `bundled` pass proves a signing act and nothing about who performed it — so
  the disclosure is non-repudiable at `forge` and `flag`, and merely signed at `bundled`. The
  Action fetches from the forge by default.
- **Level 3 — Countersigned** *(roadmap, not implemented)*. A third party — a reviewer, or the
  agent platform itself — co-signs. That's the strong claim, because a self-signature only
  proves what the account already asserts.

Adopt at the level that fits. Most projects need Level 1 today. The signature is the mechanism;
the policy is the product — the same move SLSA made by selling *levels* instead of a metadata
format.

## What a maintainer actually sees

Not a mock-up. This is the verifier's output on a real signed contribution, checked against the
keys github.com publishes for that account:

```
+--<+> scpe -------------------------- VERIFIED / LOW RISK --+
|                                                            |
| contributor  @augbastos   identity verified                |
| change       +27 / -1,  2 files                            |
| risk         LOW   (0 of 13 rules matched)                 |
| tests        no test runner detected   [none]              |
| made with    AI-assisted                                   |
| keys         forge - fetched live from the provider        |
| profile      SCPE-C  (advisory, not checked)               |
|                                                            |
+------ rule-based, reproducible - a report, not an approval +
```

Read the `keys` row before the verdict word. It is the difference between "the account GitHub
knows as @augbastos signed this" and "something signed this". The seal never collapses the two,
because a tool that did would be worth less than no tool.

That seal is live on a public pull request: **[scpe-demo#3](https://github.com/augbastos/scpe-demo/pull/3)**.
Real change, real diff — the Action re-derived the diff from the branch, hashed it, and checked
the signature against the keys github.com publishes for that account. Go and read it rather than
taking the block above on faith; that is the entire point of the thing.

To be exact about what it is: the contribution was signed by this project's own author and
verified by its own verifier. It proves the path works end to end, in public. It does not prove
anyone else has used it, because nobody has.

One row on that seal is worth a sentence. `tests` reads *no test runner detected*, and the demo
repository does have passing tests — but no Python manifest, so the tool declines to guess
`pytest`. Guessing would score every non-Python contribution as a correctness failure. A
provenance tool that reports a result it did not measure is worth less than no tool.

## What this is not

Be clear about the limits, because overclaiming is how trust tools lose trust.

This does not judge whether the code is good — it's not review. It does not prove a disclosure
is honest — a signature proves *who claimed*, not that the claim is true. And it proves nothing
about identity if the GitHub account or key is compromised: at `key_source: forge` the platform
is the root of trust, delegated on purpose. On the other anchors the root is whoever supplied
the keys. A key file the maintainer handed the verifier is worth what that maintainer's own
vetting is worth; a key file that came inside the submission proves the signing act and nothing
about the named account. Same verdict word, different root — which is why the verifier reports
which one it used.

None of this is a new invention, either. `patatt` and `b4` have run this shape — the contributor
self-signs, the recipient verifies independently, no certificate authority, no server — on the
Linux kernel's mailing list for years. They resolve the signer against a keyring the project
keeps in its own repository; SCPE resolves against the keys the forge already publishes for the
account. That is the whole delta, and it cuts both ways: nothing for a project to curate, and a
forge to depend on. The other half of the idea here is meeting the current moment — the
AI-policy wave, where the rules arrived first and the question of what to do about them is
still open, including whether anything automatic should be done at all.

## Why now

Attribution tools are arriving fast — Cursor's Agent Trace, git-ai, and others record which
agent and model wrote which lines. But they record it by self-report. As agent-authored PRs
grow, the gap between *"the record says it was this agent"* and *"prove it, and prove the diff
wasn't altered"* stops being academic. Someone has to own the verifiable layer. It doesn't have
to be a company; it can be a protocol.

SCPE is that attempt: an open protocol — `scpe/0.1` — with a specification, a single-file
verifier you can audit in ten minutes, two independent ports in Go and Rust held to the same
verdict on 18 normative vectors, and a maintainer-side Action. No hosted service, and there
never will be one.

Turning it on is two files and one pinned step:

```yaml
- uses: augbastos/scpe@v0.2.2
  with:
    level: "1"        # 1 = disclosure lint · 2 = signed envelope required
    require: "true"   # fail the check on anything not verifiable
```

If your project wrote an AI policy this year, the honest next question is whether you'd turn on
the check that enforces it — and that's exactly the question worth answering with real
maintainers, not more code.

---

*SCPE — Signed Contribution Provenance Envelope. Spec + reference implementation, open source
(code Apache-2.0, spec CC-BY-4.0). No adoption yet; this is early, and said plainly on purpose.*
