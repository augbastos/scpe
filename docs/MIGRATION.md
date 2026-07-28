# Migrating from `v0.1.x` to `v0.2`

`0.2.0` deleted a second envelope format that shipped inside the installable package, and the
Marketplace Action had been verifying *that* format rather than the one in
[SPEC.md](../spec/SPEC.md). See [CHANGELOG.md](../CHANGELOG.md) for the full list of changes.

This document exists because the compatibility story runs backwards from the usual one. Nothing
here breaks loudly. A workflow pinned at `v0.1.x` keeps running and keeps posting seals — for a
format this repository no longer produces and no conforming verifier can read. It will pass an
envelope built by the removed tooling and reject a conforming one, and at no point does it say
so. **A wrong answer that looks right is worse than a failed step**, so the upgrade is worth
doing even though nothing is demanding it.

---

## 1. If you pin the Action

This is the case that matters. Everything else in this document is a footnote to it.

```yaml
- uses: augbastos/scpe@v0.1.3    # or @v0.1, or @v0.1.2
```

How badly it affects you depends on the `level` you set.

**`level: "1"` (disclosure lint) is barely affected.** That path never read an envelope. It ran
`reference/level1_lint.py` out of the Action's own checkout at your pinned tag, over the PR body
and commit messages already present, and it still does. Move the pin for the fixes and the CI, but
nothing is quietly lying to you.

**`level: "2"` (the default — the path that actually verifies a signature) is the problem.** It
did not run a verifier out of its own checkout. It shelled out to:

```bash
pipx run --spec scpe-protocol scpe seal "${{ inputs.envelope }}" --repo … --json
```

That resolves `scpe-protocol` from PyPI **on every run, with no version constraint** — an
unpinned dependency hiding behind a pinned tag. That pin has had two distinct failure modes,
and it is now in the second one.

**Today.** PyPI serves `0.2.3`, so the unconstrained resolve picks up `0.2.x`, where
`scpe seal` takes `--envelope` as a flag and accepts no positional argument. The `v0.1.x`
invocation is rejected by the argument parser and the step exits non-zero. **A workflow nobody
edited is already red.** That is the good failure: it is loud, and it points at the pin.

**Before `0.2.0` was published**, the same pin failed silently instead. PyPI served `0.1.2`, so
the step verified the removed format — an `envelope.json` carrying `PROTOCOL_VERSION "1"`,
signed over a canonicalised re-serialisation. A conforming SCPE contribution
(`manifest.json` signed byte-for-byte with SSHSIG, in an `SCPE-ATTESTATION-v1` block) is not
something that code can parse, so with `require: "true"` it was rejected as unattested: a wrong
answer that looked right. If you saw that and concluded SCPE was broken, this is why.

### What to do

Move the pin, and take the `envelope` input with you — its default changed from a fixed path
to a committed zip to empty, and empty now means "read the attestation from the pull request
body" (the spec's §9 transport), not "check nothing". If your workflow sets `envelope:`
explicitly, drop the line unless you really do commit an envelope file.

```yaml
- uses: augbastos/scpe@v0.2.3
  with:
    level: "1"        # 1 = disclosure lint · 2 = signed envelope required
    require: "true"   # fail the check on anything not verifiable
```

The full fork-safe workflow is **two files** — [workflows/scpe.yml](workflows/scpe.yml) (the
untrusted verify job) and [workflows/scpe-seal.yml](workflows/scpe-seal.yml) (the trusted job
that posts the seal). If you copied the earlier single-file template, replace it with both: a
workflow that names itself in its own `workflow_run` trigger never registers with GitHub, so
that template could not run. Check out with `fetch-depth: 0`: level 2 recomputes the diff as
`git diff <base>...<head>`, and the default shallow checkout has no base commit to compare
against.

`v0.2` installs nothing, at either level. It runs `python3 -m scpe.cli seal` out of the Action's
own checkout, stdlib-only, so the bytes that decide a merge are the bytes of the tag you pinned
rather than whatever a package index serves that day.

### Two behaviour changes to expect after the move

- **`require: "true"` now refuses `key_source: "bundled"`**, even when `status` is `verified`.
  Those keys arrived inside the submission, so they prove these exact bytes were signed by a key
  that travelled with them — nothing about the named account. `flag` (keys your repository
  supplied) and `forge` still pass. Under the §9 PR-body transport this is unreachable anyway:
  that path carries `manifest.json` and `manifest.sig` and nothing else, so there is no enclosed
  key set to find.
- **The seal names the key anchor.** Every result now carries
  `key_source: "flag" | "bundled" | "forge"`. A seal that says `flag` is not claiming what a
  seal that says `forge` claims, and the wording differs on purpose.

---

## 2. What `@v0.2` means

**`v0.2` is an immutable alias: it points at one commit and will never be moved.** A fix ships
as a new tag — `v0.2.1`, `v0.3` — that you adopt by editing your pin. It is not a floating
pointer that tracks the `0.2.x` line.

The reason is section 1. This release exists because a pinned tag quietly changed what it
verified; a tag that can be re-pointed reintroduces exactly that, one layer up. Pre-1.0, with no
external adoption to protect, "the bytes you pinned are the bytes that ran" is worth more than
picking up patches automatically.

The cost is that a fix does not reach you on its own — **including a security fix**. `v0.2.2`
exists because `v0.2.1` accepted a valid envelope replayed from a different repository, and a
workflow still pinned at `v0.2.1` keeps accepting it, silently, for as long as the pin stands.
That is the price of "the bytes you pinned are the bytes that ran", and it is paid on purpose.

So do one of these, rather than assuming a patch will arrive:

- watch the repository's releases, or
- let Dependabot's `github-actions` ecosystem open the bump as a pull request you read before
  merging.

And read the [CHANGELOG](../CHANGELOG.md) entry before you merge one. A patch tag here can
refuse a contribution the previous tag accepted, when the previous tag was wrong to accept it.
`0.2.2` does exactly that. The protocol number is not what moved: `spec_version` is `scpe/0.1`
across the whole `0.2.x` line, and every envelope that verified still verifies.

---

## 3. If you produced envelopes with `0.1.x`

They cannot be verified by `0.2.0`, and **there is no converter — there cannot be one.** The two
formats sign different bytes: the removed one signed a canonicalised re-serialisation of
`envelope.json`, the protocol signs the exact bytes of `manifest.json`. Translating the payload
would leave a signature over bytes that no longer exist.

Rebuild and re-sign with the producer — `scpe-envelope`, or
[`reference/producer.py`](../reference/producer.py) run directly if you would rather not install
anything:

```bash
scpe-envelope pack --repo <checkout> --base <sha>   # --base is required
scpe-envelope attest envelope.zip                   # the PR-body block
```

Nothing about your key changes. It is the same SSH key already on your git host, and the same
`ssh-keygen -Y sign -n scpe/0.1` namespace.

---

## 4. If you install from PyPI

**The distribution is `scpe-protocol`. It has been since `v0.1.2` and it does not change in
`0.2.0`,** so there is no rename to handle.

`pip install scpe` has never worked and never will. The short name is registered to another
account that publishes no files, so pip reports no matching distribution — it will not silently
install someone else's code, but it will not install this one either.

The zero-install paths (`pipx run`, `uvx`) resolve to the newest release, which is `0.2.3`.
Constrain the version anyway, so a later release cannot silently change what decides your pull
requests:

```bash
pipx run --spec 'scpe-protocol>=0.2' scpe verify <path> --keys <login.keys>
uvx --from 'scpe-protocol>=0.2' scpe verify <path> --keys <login.keys>
```

If that fails to resolve you are offline or behind an index mirror — run the single file straight
out of a checkout instead, which is the canonical and cheaper path regardless:

```bash
python reference/standalone/verify_envelope.py <path> --keys <login.keys>
```

One thing cannot be fixed at all: `0.1.2`'s published metadata still advertises
`cryptography>=42` and an `mcp` extra, both removed. PyPI releases are immutable, so that record
stands forever. Publishing `0.2.0` and `0.2.1` is what makes the index's *current* answer right;
the old release's own page keeps lying about its dependencies, and nothing can change that.

---

## 5. Command map

`scpe` kept four subcommands. Eleven were removed with the package that owned them.

| `0.1.x` | `0.2.0` | |
|---|---|---|
| `scpe verify` | `scpe verify` | Same name, different job. It was an owner-side handshake over the removed format; it is now a pass-through that forwards argv to the reference verifier, so output bytes and exit code are the verifier's. |
| `scpe seal` | `scpe seal` | Verifies the spec format. `--envelope` is a flag now, not a positional. |
| `scpe inspect` | `scpe inspect` | Reads what a manifest claims; proves nothing. |
| `scpe init` | `scpe init` | Stamps the opt-in badge. |
| `scpe pack` | `scpe-envelope pack` | **Not a rename.** Same verb, different artifact: the producer builds the spec envelope. |
| `scpe attest` | `scpe-envelope attest` | Same — re-wraps a spec envelope as the compact PR-body block. |
| `scpe submit` | `scpe-envelope submit` | Same — opens the PR with the attestation in the body. |
| `scpe contribute` | — | Removed. Clone, prompt a model, sandbox, open a PR. Never part of the protocol. |
| `scpe analyze` | — | Removed with the agent. |
| `scpe pull` | — | Removed with the agent. |
| `scpe keygen` | — | Removed. Use `ssh-keygen`, and a key your git host already publishes. |
| `scpe verify-attest` | — | Removed. `scpe verify` reads an `SCPE-ATTESTATION-v1` block directly. |
| `scpe changes` | — | Removed. |
| `scpe extract` | — | Removed. |
| `scpe label` | — | Removed. |
| `scpe-mcp` | — | Removed, along with the `mcp` extra. |

---

## 6. What did not change

Worth stating plainly, because the size of the removal suggests otherwise:

- **The protocol.** `spec_version` is still `scpe/0.1`. Nothing in [SPEC.md](../spec/SPEC.md)
  moved to a new MAJOR or MINOR.
- **The signing namespace.** Still `ssh-keygen -Y sign -n scpe/0.1`. Signatures made before this
  release still verify.
- **The 18 normative [test vectors](../spec/test-vectors/)** and every expected status in them.
  A conforming verifier written against `v0.1` is still conforming.
- **The eight status codes** of §8, which are a closed set.
- **The §9 PR-body transport** and the `SCPE-ATTESTATION-v1` block.
- **`reference/standalone/verify_envelope.py`**, which was always the spec's verifier. It is now
  the only verifier *in the Python package* — the Action, `scpe verify` and the Python vector
  run all reach it, where before there were two. The independent Go and Rust ports in `impl/`
  are untouched by this and still run the vectors themselves in CI; "one verifier" means one per
  language, not one in the repository.

One vector expectation did change, in the adversarial pack rather than the normative one:
`spec/test-vectors-adversarial/duplicate-manifest-keys` moved from `unsupported-version` to
`signature-invalid`. That vector used to pass for the wrong reason — all three implementations
resolved the duplicated key last-wins and rejected the *resulting* `scpe/9.9` as an unsupported
MAJOR. SPEC §4.1 now requires rejecting a repeated key at any nesting depth at parse time, so it
is refused before the version is ever read.
