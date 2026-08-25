# Contributing to SCPE as an automated agent

You are reading this because you are an AI coding agent — Jules, Claude Code, Codex,
Copilot, CodeRabbit, or anything like them — about to open or review a pull request on
this repository. This file is short and it is binding.

## The one rule

**Every pull request must disclose whether AI was used, in a form a parser can find.**

A check enforces it (`.github/workflows/scpe.yml`, SCPE level 1). Without a disclosure
the check FAILS — this is a gate, not a report.

Two accepted forms. Either is enough:

**A commit trailer** — preferred for agents, because it travels with the commit:

```
build: pin actions/checkout to a commit sha

Pin the action to a commit so the workflow cannot change under us.

Assisted-by: google-labs-jules
```

**A checked box in the PR body**, from `.github/pull_request_template.md`:

```
- [x] I used generative AI for part of this change
```

`Assisted-by: none` (or `no`) is equally valid when no AI was involved. Declaring the
absence is a disclosure; saying nothing is not.

## What does NOT count, and why

Prose in the PR body does not count. This is not pedantry — it was measured. On
2026-08-25, `reference/disclosure.py` was run against PR #2, opened by Jules, whose body
reads *"PR created automatically by Jules for task …"*. The result:

```
{'present': False, 'form': 'none', 'value': ''}
```

The sentence is true, human-readable, and invisible to every tool that has to make a
decision. That is precisely the gap this project exists to close: a claim a machine
cannot locate is a claim a maintainer cannot check at scale.

## Why this repository, of all repositories

SCPE specifies how a project answers two questions about a contribution: **who signed
it**, and **what did they declare about AI use**. A project that specifies that and does
not do it is worth less than one that never wrote the spec.

Agents are welcome here. The README says so in its own words: trust today rests on a
username, the platform, and reading the diff by eye — *"a person, or increasingly an AI
agent"*. Agent contributions are not an edge case for this protocol; they are the reason
it exists. What is refused is the question going unanswered.

## Level 1 today, level 2 when you can sign

The gate runs at **level 1**: disclosure only. No envelope, no key, no install.

It is not at **level 2** — a signed SCPE envelope — for one concrete reason: level 2
anchors the signature to a key the forge publishes for the signing account, and no
coding agent available today has one. Gating at level 2 now would not raise the bar; it
would ban agent contributions outright and make this repository quieter and less honest.

The day an agent can hold its own forge-published key and sign, this repository flips a
single line in `.github/workflows/scpe.yml` (`level: "1"` → `"2"`). Everything else —
`fetch-depth: 0`, the two-job split, the artifact hand-off — is already in place for it.
See [docs/LEVELS.md](docs/LEVELS.md) for the full trade-off table.

## For reviewers (CodeRabbit, Strix, and humans)

Reviews are not contributions and are not gated. Post them.

If your review results in a commit, that commit follows the rule above.
