# Security policy

SCPE's entire purpose is to let someone check a claim instead of trusting it. A flaw here is
not an ordinary bug: it makes a maintainer believe something a verifier did not actually
establish. Please report one, and please do it privately first.

## Reporting

**Use GitHub's private advisory form:**
[github.com/augbastos/scpe/security/advisories/new](https://github.com/augbastos/scpe/security/advisories/new).
It is the only channel that keeps the report private while it is being fixed, and it does
not require an email address from either of us.

Do not open a public issue for a vulnerability. Do not post a proof of concept anywhere
public until a fix is released.

What helps most, in rough order:

- the exact bytes — a manifest, a signature, a `keys` file, a diff — that reproduce it;
- which implementation you used (`reference/standalone/verify_envelope.py`, `impl/go`,
  `impl/rust`, the Action) and at which tag;
- what the verifier reported and what it should have reported.

A vector directory (`manifest.json`, `manifest.sig`, `keys`, `diff.patch`,
`expected.json`) is the ideal form, because it drops straight into
`spec/test-vectors-adversarial/` as the regression guard.

## What this project treats as a vulnerability

Anything that makes a verdict say more than it should:

- an envelope reaching `verified` when the signature, the diff digest, or the identity does
  not hold;
- `key_source: forge` reported for keys that did not come from the provider;
- a contribution passing a `require: "true"` gate that should have closed it — including
  presenting an envelope on a repository or a history it was not signed for;
- the untrusted CI job reaching a secret or a write-scoped token, or contributor-controlled
  text escaping into the shell of either job;
- the key fetch being steered anywhere other than the fixed provider host (SSRF), or a
  redirect, downgrade or oversized response getting through;
- the three implementations disagreeing on the same input — a split verdict is a
  vulnerability in a protocol whose selling point is that they cannot.

## What is not a vulnerability

These are documented properties, not defects. Reporting them is welcome as an issue; they
will not be treated as an advisory.

- **A `bundled` key set proving nothing about a forge account.** Keys that arrive inside a
  submission were chosen by whoever sent it. The verifier says so (`key_source`), and
  `require: "true"` refuses them. See [spec/THREAT_MODEL.md](spec/THREAT_MODEL.md) §2.1.
- **A dishonest AI-use disclosure.** A signature proves *who claimed*, never that the claim
  is true.
- **Bad or malicious code in a verified contribution.** SCPE is not review and does not read
  what the diff does.
- **A compromised account or key.** At `key_source: forge` the provider is the root of
  trust, delegated deliberately.
- **Level 3 being absent.** Third-party countersignature is on the roadmap and is documented
  as unimplemented; `level: "3"` fails loudly rather than pretending.

## Supported versions

| Version | Supported |
|---|---|
| `v0.2.1` and later `0.2.x` | yes |
| `v0.2` | no — superseded; the fixes ship as new tags, tags are never moved |
| `v0.1.x` | **no.** Its level-2 path verifies an envelope format that is not in `spec/`. See [docs/MIGRATION.md](docs/MIGRATION.md). |

Every tag is immutable. A fix arrives as a new tag you adopt by editing your pin, never as
a silent change under one you already wrote.

## What you can expect

This is a one-person project with no external adoption yet, so promising a corporate SLA
would be theatre. What is promised instead:

- an acknowledgement that the report was read, within a few days;
- an honest assessment of whether it is exploitable, said plainly either way;
- a fix and a new tag for anything that holds up, with the finding named in the
  [CHANGELOG](CHANGELOG.md) and a regression vector added;
- credit in the advisory unless you ask otherwise.

## Audit status

**No external security audit has been performed.** The protocol has a written threat model,
26 test vectors (18 normative, 8 adversarial) checked against three independent
implementations, and adversarial review by the author. That is not the same thing as review
by someone with no stake in the answer, and this file will say so until it changes.

If you are the kind of person who reads a verifier for fun: the whole decision path is one
stdlib-only file, [`reference/standalone/verify_envelope.py`](reference/standalone/verify_envelope.py),
and it is meant to be read in a sitting. Tell me what it gets wrong.
