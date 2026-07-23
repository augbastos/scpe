# Your project has an AI policy. Who enforces it?

*Draft — launch essay for SCPE. Status: v0.1, no external adoption. Keep every claim honest.*

---

In 2026, open source started writing rules for AI. OpenSSL now asks contributors to declare
AI use in each commit with an `Assisted-by` trailer. MicroPython added a checkbox to its pull
request template: *I did not use generative AI* / *I used it, but a human checked the code.*
Fedora, the EFF, and others published their own policies. curl's maintainer shut down a
six-year bug-bounty program after a flood of AI-generated security reports.

The policies are the easy part. Here's the uncomfortable question none of them answer:

**When a pull request comes in, who checks that the disclosure is actually there?**

Right now, the answer is: a human, eventually, if they remember. A policy in `CONTRIBUTING.md`
is a request, not a gate. A contributor can skip the trailer, leave the checkbox blank, or open
a PR that never mentions the tool that wrote most of it — and nothing stops the merge except
someone noticing. That worked when a maintainer got three PRs a day. It does not scale to a
world where agents open them by the hundred.

## The smallest thing that helps

You don't need cryptography to close the first gap. You need enforcement of the policy you
already wrote.

So start there. **Level 1** is a GitHub Action that does one thing: check that the AI-use
disclosure is present — the `Assisted-by` trailer, or the checkbox your template already has. No
signing, no new tools, zero cost to the contributor. If your repository already *asks* for
disclosure, this is the check that makes the ask real. A PR without it gets flagged before a
human spends a minute on it.

That's it. That's the whole first level. It's deliberately boring, because boring is what gets
adopted.

## Then you can climb

Enforcing *presence* is useful, but a disclosure is still just a claim. A contributor can type
`Assisted-by: none` over fully generated code. So there's a ladder:

- **Level 1 — Disclosure.** The declaration is present. Zero friction.
- **Level 2 — Signed.** The contribution rides inside a signed envelope: the change is bound to
  a verifiable GitHub identity (an SSH key the account already publishes) and to a SHA-256 of
  the exact diff, so the maintainer can prove *who* produced it and that *nothing was tampered
  with* — offline, with no server. The disclosure becomes non-repudiable: signed, you can't
  later deny you made it.
- **Level 3 — Countersigned** *(on the roadmap)*. A third party — a reviewer, or the agent
  platform itself — co-signs. That's the strong claim, because a self-signature only proves what
  the account already asserts.

Adopt at the level that fits. Most projects need Level 1 today. The signature is the mechanism;
the policy is the product — the same move SLSA made by selling *levels* instead of a metadata
format.

## What this is not

Be clear about the limits, because overclaiming is how trust tools lose trust.

This does not judge whether the code is good — it's not review. It does not prove a disclosure
is honest — a signature proves *who claimed*, not that the claim is true. And it proves nothing
if the GitHub account or key is compromised; that's the root of trust, delegated to the platform
on purpose.

None of this is a new invention, either. `patatt` and `b4` have run almost exactly this pattern
— self-sign a contribution with a key the platform publishes, verify it independently, no
certificate authority, no server — on the Linux kernel's mailing list for years. The idea here
is to bring that shape to the GitHub pull-request boundary, and to meet the current moment: the
AI-policy wave that gave every project a rule and no way to enforce it.

## Why now

Attribution tools are arriving fast — Cursor's Agent Trace, git-ai, and others record which
agent and model wrote which lines. But they record it by self-report. As agent-authored PRs
grow, the gap between *"the record says it was this agent"* and *"prove it, and prove the diff
wasn't altered"* stops being academic. Someone has to own the verifiable layer. It doesn't have
to be a company; it can be a protocol.

SCPE is that attempt: an open protocol, v0.1, with a specification, a single-file verifier you
can audit in ten minutes, and a maintainer-side Action. No hosted service, and there never will
be one. If your project wrote an AI policy this year, the honest next question is whether you'd
turn on the check that enforces it — and that's exactly the question worth answering with real
maintainers, not more code.

---

*SCPE — Signed Contribution Provenance Envelope. Spec + reference implementation, open source.
No adoption yet; this is early, and said plainly on purpose.*
