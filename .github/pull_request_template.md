<!--
  This repository gates on its own protocol. The AI-use disclosure below is not a
  formality: a check fails without it (SCPE level 1, .github/workflows/scpe.yml).
  Tick exactly one box, or add an Assisted-by trailer to a commit message instead —
  either form satisfies the gate. See AGENTS.md if you are an automated contributor.
-->

## What this changes

<!-- One or two sentences. What is different after this merge, and why. -->

## AI use

<!-- Tick ONE. Both answers are welcome; only silence fails the check. -->

- [ ] I used generative AI for part of this change
- [ ] I did not use generative AI for this change

<!--
  If you used AI, naming the tool helps a reviewer calibrate — e.g. "Claude Code for the
  test scaffolding, hand-written elsewhere". Put it in the line above, or as a commit
  trailer in the form `Assisted-by: <tool>` (see AGENTS.md for a full example).

  Note for whoever edits this template: do NOT write that trailer at the start of a line
  anywhere in this file, comments included. reference/disclosure.py scans the raw PR body
  and does not skip HTML comments, so an example trailer here would satisfy the gate for
  every PR that leaves the template untouched. Caught by _local/test-gate-level1.py on
  2026-08-25, before this file ever reached a pull request.

  A disclosure is not a confession. This project takes the position that AI-assisted
  contributions are normal and welcome; what it refuses is the question going unanswered.
  Whether the answer is TRUE stays a human judgement — see SPEC.md §2 and THREAT_MODEL.md.
  The signature (level 2) makes the claim attributable and tamper-evident, not true.
-->

## Checks

- [ ] Tests pass locally, or this change carries no code
- [ ] I read [CONTRIBUTING.md](../CONTRIBUTING.md)
