# SCPE profiles — one core, every domain

A runnable demonstration of SCPE **profiles** (SPEC §13): the same artifact-agnostic
core (a subject by hash + attestations + one signature) reused across domains through a
thin **label + convention**, never a format fork — the JWT/DSSE shape applied to a
domain.

```
python examples/demo.py
```

## What it does

For each profile family it packs a **real tiny file** and verifies it through the one
stdlib reference verifier (`reference/standalone/verify_envelope.py`):

| Profile | Domain | Subject | Demo file |
|---|---|---|---|
| `SCPE-C` | code | `code-change` (a diff) | a two-commit git repo |
| `SCPE-I` | image | `artifact` | a real 1×1 PNG |
| `SCPE-M` | model | `artifact` | a minimal empty `.safetensors` |
| `SCPE-DATA` | dataset | `artifact` | a two-record `.jsonl` |
| `SCPE-D` | document | `artifact` | a minimal PDF |

Every envelope verifies to `verified` on the **same** verifier, and the verifier
**surfaces** the stamped `profile` verbatim in its output.

## The one invariant this proves

A profile is a **label plus conventions**, not a verification path (SPEC §13.2):

- **Integrity is by `subject.type`, always** — `code-change` (diff hash) or `artifact`
  (raw-bytes digest), identical to a manifest with no profile stamped. No profile adds a
  hash, check, or trust anchor.
- **Producer stamps, verifier surfaces** — the producer's `--profile` writes
  `manifest.profile`; for `artifact` subjects it also supplies the convention
  `media_type` when `--media-type` is omitted (media_type is informational, SPEC §6.2).
  The verifier echoes the label but the verdict never depends on it.
- **Unknown/absent profile is surfaced-but-ignored, never an error** — dropping,
  renaming, or not recognizing a profile changes nothing the verifier trusts.

## Offline, throwaway keys

Like the normative test vectors, everything runs offline: a throwaway ed25519 key and a
local `keys` file stand in for `github.com/<login>.keys`. No network, no `gh`, no
committed private key — the key lives only in a temp dir and is deleted on exit.

The same flow is exercised as a pytest in `tests/test_profiles_demo.py`.
