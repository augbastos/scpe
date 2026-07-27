# SCPE documentation

Don't read all of this. Start with the three, and reach for the rest only when a specific
question sends you there.

### Start here
- [../spec/SPEC.md](../spec/SPEC.md) — the protocol (`scpe/0.1`): envelope, subject, attestations, verification algorithm.
- [../spec/THREAT_MODEL.md](../spec/THREAT_MODEL.md) — what SCPE defends against, and (§2) what it explicitly does **not**. Read §2 before relying on a seal.
- [comparison.md](comparison.md) — "why not just extend DSSE / Sigstore / patatt / C2PA / SLSA / Agent Trace / DCO?" in one file.

### Reference (each answers one question)
- [MIGRATION.md](MIGRATION.md) — upgrading a `v0.1.x` pin to `v0.2`. Read this first if you already run the Action: the old tag keeps working and keeps returning a green check, for an envelope format no conforming verifier reads. Change history is in [../CHANGELOG.md](../CHANGELOG.md).
- [design-decisions.md](design-decisions.md) — why SHA-256, why sign exact bytes, why the fixed provider table, why no server; the honest edges and the objections a skeptic arrives with.
- [governance.md](governance.md) — how the protocol evolves: registering providers / attestation types / profiles / statuses; the versioning + compatibility policy.
- [LEVELS.md](LEVELS.md) — the L1/L2/L3 ladder: what the maintainer-side Action actually gates on, why level 2 implying level 1 is a *gate* property and not a verifier one, and which parts of the seal it posts are the Action's reporting layer rather than the protocol.
- [ROADMAP.md](ROADMAP.md) — what is deliberately deferred, and the extension slot each deferred item will land in.
- [../spec/FAQ.md](../spec/FAQ.md) — why SSH, why the PR body, relation to Agent Trace / Sigstore / patatt.

### Prove it yourself
- [../spec/test-vectors/](../spec/test-vectors/) — the normative conformance vectors. Pass them and you conform.
- [../spec/test-vectors-adversarial/](../spec/test-vectors-adversarial/) — adversarial vectors (duplicate keys, oversized manifest, subject traversal, UTF-8 BOM, wrong namespace, truncated signature). Each records the real status all three verifiers agree on. `manifest-oversize-rejected` is now a **regression guard**, not an open gap: the 1 MiB manifest cap is enforced on the directory-input path as well as the zip path, so the vector expects `unattested`. If any implementation regresses to accepting an oversized directory manifest, that vector flips to `verified` and says so.
- [../spec/manifest.schema.json](../spec/manifest.schema.json) — a JSON Schema (draft 2020-12) for the manifest structure. Advisory: the normative check is SPEC §8, not the schema.
- [../reference/](../reference/), [../impl/go/](../impl/go/), and [../impl/rust/](../impl/rust/) — three independent verifiers, in Python, Go, and Rust, that reach the same verdict (status + attestation summary) on the same vectors. Three implementations, one result — that's the point.
- [implementing-scpe.md](implementing-scpe.md) — implement your own verifier in a weekend.
