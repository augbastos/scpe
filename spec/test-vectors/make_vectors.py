#!/usr/bin/env python3
"""Generate the normative SCPE scpe/0.1 test vectors.

Reproducible generator: running it rewrites every vector directory from scratch.
The signing keys under _key/ are THROWAWAY test keys, committed on purpose so the
vectors verify offline; they grant access to nothing. Key fetching (SPEC §8.3) is
simulated: each vector ships a `keys` file standing in for the body of
https://github.com/<login>.keys — conforming verifier test harnesses substitute it
for the network fetch.

Stdlib only. External binary: ssh-keygen (OpenSSH >= 8.2).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NAMESPACE = "scpe/0.1"
SUBJECT = "octocat-test"      # the username within the provider (SPEC §8)

DIFF = (
    "diff --git a/calc.py b/calc.py\n"
    "index 3f8e7a1..9c2b4d0 100644\n"
    "--- a/calc.py\n"
    "+++ b/calc.py\n"
    "@@ -1,4 +1,4 @@\n"
    " def add(a, b):\n"
    "-    return a - b\n"
    "+    return a + b\n"
    " \n"
)


def normalize(diff: str) -> bytes:
    """SPEC §6: UTF-8, CRLF/CR -> LF, exactly one trailing newline."""
    text = diff.replace("\r\n", "\n").replace("\r", "\n")
    return (text.rstrip("\n") + "\n").encode("utf-8")


def diff_sha256(diff: str) -> str:
    return hashlib.sha256(normalize(diff)).hexdigest()


def ensure_key(path: Path, comment: str) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path)],
        check=True, capture_output=True, text=True,
    )


def sign(manifest_path: Path, key: Path) -> Path:
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", NAMESPACE, str(manifest_path)],
        check=True, capture_output=True, text=True,
    )
    sig = manifest_path.with_suffix(manifest_path.suffix + ".sig")
    out = manifest_path.parent / "manifest.sig"
    sig.replace(out)
    return out


def at_att(agent_trace: dict) -> dict:
    """Wrap a bare agent-trace {format,data} record as an `agent-trace` attestation
    (SPEC §5). Every attestation in these vectors is of type `agent-trace`."""
    return {"type": "agent-trace", **agent_trace}


def manifest(spec_version: str = NAMESPACE, agent_trace: dict | None = None,
             diff: str = DIFF, provider: str = "github",
             subject: str = SUBJECT, attestations: list | None = None) -> dict:
    # The manifest is a signed evidence container (SPEC §4): a `subject` block (WHAT is
    # attested, dispatched on `subject.type` — here `code-change`), the contributor
    # identity, an `ai_disclosure`, and an optional `attestations[]` list (SPEC §5).
    m = {
        "spec_version": spec_version,
        "created_at": "2026-07-21T18:00:00Z",
        "contributor": {
            "identity": {"provider": provider, "subject": subject},
            "key_fingerprint": "",
        },
        "subject": {
            "type": "code-change",
            "target": {"repo": "octocat-test/calc", "base_sha": "a" * 40},
            "change": {
                "diff_sha256": diff_sha256(diff),
                "head_sha": "b" * 40,
                "files_changed": ["calc.py"],
                "stats": {"insertions": 1, "deletions": 1},
            },
        },
        "ai_disclosure": {"mode": "assisted", "notes": "test vector"},
    }
    # `attestations` (a full list of typed entries) wins over the single-agent-trace
    # convenience `agent_trace`; both are omitted when None (a MAY field, SPEC §5).
    if attestations is not None:
        m["attestations"] = attestations
    elif agent_trace is not None:
        m["attestations"] = [at_att(agent_trace)]
    return m


AGENT_TRACE_REAL = {
    "format": "agent-trace/1",
    "data": {
        "version": "1.0.0",
        "id": "0b8e7a30-1111-4222-8333-444455556666",
        "timestamp": "2026-07-21T17:59:00Z",
        "tool": {"name": "test-agent", "version": "0.0.1"},
        "files": [{
            "path": "calc.py",
            "conversations": [{
                "url": "https://example.invalid/session/1",
                "contributor": {"type": "ai", "model_id": "anthropic/claude-test"},
                "ranges": [{"start_line": 2, "end_line": 2}],
            }],
        }],
    },
}

AGENT_TRACE_GENERIC = {
    "format": "generic/1",
    "data": {"agent": "test-agent", "model": "test-model", "session_id": "s-1"},
}

AGENT_TRACE_GITAI = {
    "format": "git-ai/notes",
    "data": {"refs/notes/ai": "authors:\n  - model: test-model\n    lines: [2]\n"},
}

AGENT_TRACE_UNKNOWN = {
    "format": "vendorx/9",
    "data": {"whatever": True},
}

# A reserved attestation type (SPEC §5.1) the verifier surfaces as present-unverified —
# used in the multi-attestation vector alongside a known agent-trace entry.
RESERVED_ATTESTATION = {
    "type": "timestamp",
    "format": "rfc3161",
    "data": {"note": "reserved trusted-timestamp payload, not implemented in scpe/0.1"},
}

# The bytes of an `artifact` subject (SPEC §6.2). Deliberately includes a NUL and other
# non-text bytes: an artifact is opaque and hashed RAW (no diff-style normalization).
ARTIFACT_BYTES = (
    b"SCPE artifact test payload\n\x00\x01\x02\x03 binary-ish trailing bytes\n")
ARTIFACT_SHA256 = hashlib.sha256(ARTIFACT_BYTES).hexdigest()
ARTIFACT_MEDIA_TYPE = "application/octet-stream"


def fingerprint(pub: Path) -> str:
    out = subprocess.run(["ssh-keygen", "-lf", str(pub)],
                         check=True, capture_output=True, text=True).stdout
    return out.split()[1]  # SHA256:...


def write_vector(name: str, m: dict, key: Path, keys_pub: list[Path],
                 expected: dict, diff: str | None = DIFF,
                 mutate_after_sign: bool = False,
                 artifact_bytes: bytes | None = None) -> None:
    d = ROOT / name
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    mp = d / "manifest.json"
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))
    sign(mp, key)
    if mutate_after_sign:
        raw = mp.read_bytes().replace(b"test vector", b"test vector EDITED")
        mp.write_bytes(raw)
    if diff is not None:
        (d / "diff.patch").write_bytes(normalize(diff))
    # An `artifact` subject carries its opaque payload as artifact.bin instead of a diff
    # (SPEC §4/§6.2); written RAW, exactly as it is hashed.
    if artifact_bytes is not None:
        (d / "artifact.bin").write_bytes(artifact_bytes)
    (d / "keys").write_text(
        "".join(p.read_text(encoding="utf-8") for p in keys_pub), encoding="utf-8")
    (d / "expected.json").write_bytes(
        json.dumps(expected, indent=2).encode("utf-8"))
    print(f"  {name}: {expected['status']}")


def main() -> int:
    if shutil.which("ssh-keygen") is None:
        print("ssh-keygen not found (OpenSSH >= 8.2 required)", file=sys.stderr)
        return 1

    key = ROOT / "_key" / "scpe_test_ed25519"
    rogue = ROOT / "_key" / "scpe_rogue_ed25519"
    ensure_key(key, "scpe-test-vector-key (throwaway)")
    ensure_key(rogue, "scpe-rogue-key (throwaway, NOT in keys file)")
    pub, rogue_pub = key.with_suffix(".pub"), rogue.with_suffix(".pub")
    fp = fingerprint(pub)

    def m(**kw):
        base = manifest(**kw)
        base["contributor"]["key_fingerprint"] = fp
        return base

    def at_expect(status: str) -> list[dict]:
        """The verifier's per-attestation summary for a single agent-trace entry
        (SPEC §8 step 8)."""
        return [{"type": "agent-trace", "status": status}]

    print(f"Generating vectors (namespace {NAMESPACE}, subject {SUBJECT})")

    # github provider (the PR-transport default)
    write_vector("valid-minimal", m(), key, [pub],
                 {"status": "verified", "attestations": []})

    # one valid vector per remaining registry provider (SPEC §8). Offline, the
    # `keys` file substitutes the network fetch for every forge provider, so these
    # exercise provider resolution + subject validation + signature, not the host.
    write_vector("valid-gitlab", m(provider="gitlab"), key, [pub],
                 {"status": "verified", "attestations": []})

    write_vector("valid-codeberg", m(provider="codeberg"), key, [pub],
                 {"status": "verified", "attestations": []})

    # `local` performs no fetch: the owner-supplied keys file (shipped as `keys`) is
    # the sole key source.
    write_vector("valid-local", m(provider="local"), key, [pub],
                 {"status": "verified", "attestations": []})

    write_vector("valid-agent-trace-generic", m(agent_trace=AGENT_TRACE_GENERIC),
                 key, [pub],
                 {"status": "verified", "attestations": at_expect("present-generic/1")})

    write_vector("valid-agent-trace-gitai", m(agent_trace=AGENT_TRACE_GITAI),
                 key, [pub],
                 {"status": "verified", "attestations": at_expect("present-git-ai/notes")})

    write_vector("valid-agent-trace-real", m(agent_trace=AGENT_TRACE_REAL),
                 key, [pub],
                 {"status": "verified", "attestations": at_expect("present-agent-trace/1")})

    write_vector("invalid-signature", m(), key, [pub],
                 {"status": "signature-invalid",
                  "note": "manifest bytes edited after signing"},
                 mutate_after_sign=True)

    tampered = m()
    tampered["subject"]["change"]["diff_sha256"] = diff_sha256(DIFF.replace("a + b", "a * b"))
    write_vector("tampered-diff", tampered, key, [pub],
                 {"status": "tampered",
                  "note": "diff.patch does not match change.diff_sha256"})

    rogue_m = m()
    rogue_m["contributor"]["key_fingerprint"] = fingerprint(rogue_pub)
    write_vector("wrong-identity", rogue_m, rogue, [pub],
                 {"status": "signature-invalid",
                  "note": "signed by a key not present in the login's keys file"})

    write_vector("unknown-version", m(spec_version="scpe/9.9"), key, [pub],
                 {"status": "unsupported-version"})

    write_vector("unknown-trace-format", m(agent_trace=AGENT_TRACE_UNKNOWN),
                 key, [pub],
                 {"status": "verified", "attestations": at_expect("present-unverified")})

    # A provider outside the fixed registry — here the format-reserved-but-
    # unimplemented `oidc` (SPEC §11.1) — MUST resolve to `unsupported-provider`:
    # never an error, never a silent pass. Signed with a good key so the status
    # cannot be confused with signature-invalid; resolution stops before signing.
    write_vector("unsupported-provider", m(provider="oidc"), key, [pub],
                 {"status": "unsupported-provider"})

    # A malformed subject (path traversal via `..`) MUST fail the safe-subject rule
    # (SPEC §8) with `identity-unverifiable`, before any fetch or signature check.
    # NOTE: here `subject` is the identity username; the manifest `subject` BLOCK below
    # is a different field (SPEC §6).
    write_vector("identity-unverifiable-subject",
                 m(subject="evil..traversal"), key, [pub],
                 {"status": "identity-unverifiable"})

    # An UNKNOWN subject BLOCK type (SPEC §6.3) that scpe/0.1 does not implement MUST
    # fail CLOSED to `unsupported-subject` — never `verified`, never `tampered` — even
    # with a perfect signature and identity. The verifier never guesses an integrity
    # check for a kind it does not implement. Signed with the good key so the verdict
    # cannot be mistaken for signature-invalid; no payload, because integrity dispatch
    # declines before any payload is needed. (`artifact` is now IMPLEMENTED, see the
    # valid-artifact / tampered-artifact vectors below; this uses a genuinely unknown
    # `container-image` type to exercise the fail-closed branch.)
    unknown_subject_m = m()
    unknown_subject_m["subject"] = {
        "type": "container-image",
        "digest": {"sha256": ARTIFACT_SHA256},
        "media_type": "application/vnd.oci.image.manifest.v1+json",
    }
    write_vector("unsupported-subject", unknown_subject_m, key, [pub],
                 {"status": "unsupported-subject"}, diff=None)

    # A valid `artifact` subject (SPEC §6.2): a standalone envelope whose enclosed
    # artifact.bin hashes to subject.digest.sha256. Fully verified, no diff involved.
    valid_artifact_m = m()
    valid_artifact_m["subject"] = {
        "type": "artifact",
        "digest": {"sha256": ARTIFACT_SHA256},
        "media_type": ARTIFACT_MEDIA_TYPE,
    }
    write_vector("valid-artifact", valid_artifact_m, key, [pub],
                 {"status": "verified", "attestations": []},
                 diff=None, artifact_bytes=ARTIFACT_BYTES)

    # A tampered `artifact`: the enclosed artifact.bin does NOT hash to the signed
    # subject.digest.sha256 -> `tampered`, the artifact-subject equivalent of the
    # code-change diff mismatch. The signature is valid; only the payload disagrees.
    tampered_artifact_m = m()
    tampered_artifact_m["subject"] = {
        "type": "artifact",
        "digest": {"sha256": hashlib.sha256(b"a different artifact entirely").hexdigest()},
        "media_type": ARTIFACT_MEDIA_TYPE,
    }
    write_vector("tampered-artifact", tampered_artifact_m, key, [pub],
                 {"status": "tampered",
                  "note": "artifact.bin does not match subject.digest.sha256"},
                 diff=None, artifact_bytes=ARTIFACT_BYTES)

    # A multi-attestation envelope (SPEC §5): a known agent-trace entry PLUS a reserved
    # `timestamp` entry. The verifier reports a per-entry summary; the known entry is
    # present-<format> and the reserved/unknown entry is present-unverified — never an
    # error, never a silent pass, and never part of the overall verdict.
    write_vector("multi-attestation",
                 m(attestations=[at_att(AGENT_TRACE_GENERIC), RESERVED_ATTESTATION]),
                 key, [pub],
                 {"status": "verified",
                  "attestations": [
                      {"type": "agent-trace", "status": "present-generic/1"},
                      {"type": "timestamp", "status": "present-unverified"}]})

    print("done: 18 vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
