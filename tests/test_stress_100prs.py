"""STRESS PROOF — 100 synthetic pull-request scenarios through the REAL SCPE
verification stack: the standalone reference verifier
(reference/standalone/verify_envelope.py), the require DECISION (action.yml:149
`gate_pass = status == "verified"` — replicated verbatim below since that line
lives inline in the composite action's bash/python, not as an importable
module), and the L1 disclosure lint (reference/level1_lint.py).

50 VALID cases (must end "verified"): every agent_trace format x every
ai_disclosure mode, plus the tricky-but-still-valid ones — CRLF and CR-only
diffs that MUST verify because SPEC §6 normalizes to LF, multi-file diffs, a
"large" many-file diff, and an agent_trace block with empty `data`.

50 IRREGULAR cases (must be rejected with the CORRECT status), ~4-5 per
category: tampered-diff, manifest-edited-after-signing, signed-by-a-key-absent
-from-the-keys-file, rotated/removed-key (empty keys), unsupported spec_version
MAJOR, malformed envelope zip, no attestation at all, corrupted base64 in a
PR-body attestation, two attestation blocks in one body (verifier MUST use only
the first), an oversized manifest beyond the 1 MiB cap, a wrong-target/base
replay (recomputed diff mismatch), and — for L1 — a PR with no disclosure
signal under `require: "true"`.

Every envelope is a REAL signed artifact: throwaway ed25519 keys (ssh-keygen)
+ a local `keys` file standing in for https://github.com/<login>.keys, exactly
like spec/test-vectors/make_vectors.py, minted through reference/producer.py's
own manifest/sign/zip machinery, then mutated for the bad cases.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import pytest

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "reference" / "standalone" / "verify_envelope.py"
LEVEL1_LINT = ROOT / "reference" / "level1_lint.py"
PY = sys.executable

_spec = importlib.util.spec_from_file_location(
    "scpe_producer_stress", ROOT / "reference" / "producer.py")
producer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(producer)

MAX_MANIFEST_BYTES = 1 << 20  # mirrors verify_envelope.py's defensive cap

LOGIN = "octocat-test"
REPO = "octocat-test/calc"
BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
CREATED_AT = "2026-07-21T18:00:00Z"


def require_decision(status: str) -> bool:
    """The require DECISION, verbatim from action.yml:149
    (`data["gate_pass"] = status == "verified"`). The full-envelope path has no
    importable module for this — it is one line inline in the composite
    action's bash/python — so it is mirrored here rather than re-derived."""
    return status == "verified"


# --------------------------------------------------------------------- diffs

DIFF_LF = (
    "diff --git a/calc.py b/calc.py\n"
    "index 3f8e7a1..9c2b4d0 100644\n"
    "--- a/calc.py\n"
    "+++ b/calc.py\n"
    "@@ -1,4 +1,4 @@\n"
    " def add(a, b):\n"
    "-    return a - b\n"
    "+    return a + b\n"
    " \n"
).encode("utf-8")

DIFF_MULTIFILE = (
    "diff --git a/calc.py b/calc.py\n"
    "index 3f8e7a1..9c2b4d0 100644\n"
    "--- a/calc.py\n"
    "+++ b/calc.py\n"
    "@@ -1,4 +1,4 @@\n"
    " def add(a, b):\n"
    "-    return a - b\n"
    "+    return a + b\n"
    " \n"
    "diff --git a/util.py b/util.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/util.py\n"
    "+++ b/util.py\n"
    "@@ -1,2 +1,2 @@\n"
    "-def helper():\n"
    "-    pass\n"
    "+def helper():\n"
    "+    return True\n"
).encode("utf-8")


def _big_diff(n_files: int) -> bytes:
    parts = []
    for i in range(n_files):
        parts.append(
            f"diff --git a/mod_{i}.py b/mod_{i}.py\n"
            f"index {i:07x}..{i + 1:07x} 100644\n"
            f"--- a/mod_{i}.py\n+++ b/mod_{i}.py\n"
            "@@ -1,2 +1,2 @@\n"
            f"-def f_{i}():\n-    return {i}\n"
            f"+def f_{i}():\n+    return {i + 1}\n")
    return "".join(parts).encode("utf-8")


DIFF_LARGE = _big_diff(25)
DIFF_CRLF_RAW = DIFF_LF.replace(b"\n", b"\r\n")   # normalizes back to DIFF_LF
DIFF_CR_ONLY_RAW = DIFF_LF.replace(b"\n", b"\r")  # old-Mac line endings
DIFF_MUTATED = DIFF_LF.replace(b"a + b", b"a * b")  # a DIFFERENT, unrelated diff

FILES_SINGLE = ["calc.py"]
FILES_MULTI = ["calc.py", "util.py"]
FILES_LARGE = [f"mod_{i}.py" for i in range(25)]

# ------------------------------------------------------------- agent_trace

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

# (label, agent_trace dict-or-None, expected verifier agent_trace sub-status)
AGENT_TRACE_VARIANTS = [
    ("absent", None, "absent"),
    ("generic1", {"format": "generic/1",
                  "data": {"agent": "a", "model": "m", "session_id": "s-1"}}, "present-generic/1"),
    ("gitai", {"format": "git-ai/notes",
               "data": {"refs/notes/ai": "authors:\n  - model: m\n    lines: [2]\n"}},
     "present-git-ai/notes"),
    ("agenttrace1", AGENT_TRACE_REAL, "present-agent-trace/1"),
    ("unknownfmt", {"format": "vendorx/9", "data": {"whatever": True}}, "present-unverified"),
    ("emptydata", {"format": "generic/1", "data": {}}, "present-generic/1"),  # "empty agent_trace"
]

# ai_disclosure.mode variants (mode with/without notes)
DISCLOSURE_VARIANTS = [
    {"mode": "none"},
    {"mode": "assisted", "notes": "paired with an AI coding assistant"},
    {"mode": "generated", "notes": "diff generated by an agent, human-reviewed"},
    {"mode": "assisted"},
    {"mode": "none", "notes": "n/a"},
]


# ------------------------------------------------------------------- infra

@dataclass
class Ctx:
    files_dir: Path
    main_key: Path
    rogue_key: Path
    main_fp: str
    rogue_fp: str
    keys_file: Path
    empty_keys_file: Path
    _n: dict = field(default_factory=lambda: {"i": 0})

    def path(self, ext: str = ".dat") -> Path:
        self._n["i"] += 1
        return self.files_dir / f"c{self._n['i']:03d}{ext}"


def _keygen(path: Path, comment: str) -> None:
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path)],
                   check=True, capture_output=True, text=True)


def _manifest(*, key_fp: str, diff_normalized: bytes, files: list[str],
              agent_trace: dict | None, ai: dict, login: str = LOGIN, repo: str = REPO,
              base_sha: str = BASE_SHA, head_sha: str = HEAD_SHA) -> dict:
    # An agent_trace {format,data} variant becomes a single agent-trace attestation in
    # the new evidence-container manifest (SPEC §5). None -> no attestations at all.
    attestations = None if agent_trace is None else [{"type": "agent-trace", **agent_trace}]
    return producer.build_manifest(
        login=login, fingerprint=key_fp, repo=repo, base_sha=base_sha,
        dsha=producer.diff_sha256(diff_normalized), head_sha=head_sha, files=files,
        stats={"insertions": 1, "deletions": 1}, ai_mode=ai["mode"], ai_notes=ai.get("notes"),
        created_at=CREATED_AT, attestations=attestations)


def _sign_and_zip(manifest: dict, key: Path, diff_stored: bytes | None, *,
                  extra: dict[str, bytes] | None = None, omit: set[str] = frozenset(),
                  mutate_after_sign: bool = False) -> tuple[bytes, bytes]:
    """Returns (envelope_zip_bytes, manifest_bytes) — the manifest bytes are
    returned too so callers can build an attestation block from the same
    signed material without re-signing."""
    mbytes = producer.serialize_manifest(manifest)
    sig = producer.sign_manifest(mbytes, key)
    if mutate_after_sign:
        obj = json.loads(mbytes)
        obj["ai_disclosure"]["notes"] = (obj["ai_disclosure"].get("notes") or "") + " EDITED-AFTER-SIGNING"
        mbytes = json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")
    members = {"manifest.json": mbytes, "manifest.sig": sig}
    if diff_stored is not None:
        members["diff.patch"] = diff_stored
    if extra:
        members.update(extra)
    for k in omit:
        members.pop(k, None)
    # Reuses producer's own deterministic zip builder — byte-identical to what
    # a real producer emits, no hand-rolled zip format.
    return producer._zip_bytes(list(members.items())), mbytes


def _verify(path: Path, keys: Path | None = None, diff: Path | None = None) -> dict:
    args = [PY, str(VERIFIER), str(path), "--json"]
    if keys is not None:
        args += ["--keys", str(keys)]
    if diff is not None:
        args += ["--diff", str(diff)]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=60)
    assert proc.stdout.strip(), f"no verifier output for {path}: stderr={proc.stderr[-800:]}"
    return json.loads(proc.stdout)


def _run_l1(cwd: Path, env_overrides: dict) -> dict:
    env = dict(os.environ)
    env.update({"PR_BODY": "", "BASE_SHA": "", "HEAD_SHA": "", "REPO_DIR": ".", "REQUIRE": "false"})
    env.update(env_overrides)
    proc = subprocess.run([PY, str(LEVEL1_LINT)], cwd=str(cwd), env=env,
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, f"level1_lint.py must always exit 0: stderr={proc.stderr}"
    return json.loads((cwd / "results.json").read_text(encoding="utf-8"))


@dataclass
class Case:
    case_id: str
    group: str       # "valid" | "irregular"
    category: str
    expected: str
    run: Callable[[], str]


# --------------------------------------------------------------- 50 VALID

def build_valid_cases(ctx: Ctx) -> list[Case]:
    cases: list[Case] = []
    normalized_simple = producer.normalize_diff(DIFF_LF)

    # 30: the full agent_trace x ai_disclosure grid, plain LF diff.
    i = 0
    for at_label, at, _at_expect in AGENT_TRACE_VARIANTS:
        for ai in DISCLOSURE_VARIANTS:
            i += 1
            case_id = f"valid-grid-{i:02d}-{at_label}-{ai['mode']}"
            m = _manifest(key_fp=ctx.main_fp, diff_normalized=normalized_simple,
                          files=FILES_SINGLE, agent_trace=at, ai=ai)

            def run(m=m, diff=DIFF_LF) -> str:
                blob, _ = _sign_and_zip(m, ctx.main_key, diff)
                p = ctx.path(".zip")
                p.write_bytes(blob)
                return _verify(p, keys=ctx.keys_file)["status"]

            cases.append(Case(case_id, "valid", "grid(agent_trace x disclosure)", "verified", run))

    # 20 tricky-but-valid: 5 CRLF-normalized, 5 CR-only-normalized, 5 multi-file,
    # 5 large (25-file) diffs — cycling through agent_trace/disclosure combos.
    tricky = [
        ("crlf-normalizes", DIFF_CRLF_RAW, normalized_simple, FILES_SINGLE),
        ("cr-only-normalizes", DIFF_CR_ONLY_RAW, normalized_simple, FILES_SINGLE),
        ("multifile", DIFF_MULTIFILE, producer.normalize_diff(DIFF_MULTIFILE), FILES_MULTI),
        ("large-25-files", DIFF_LARGE, producer.normalize_diff(DIFF_LARGE), FILES_LARGE),
    ]
    j = 0
    for kind, stored, normalized, files in tricky:
        for rep in range(5):
            j += 1
            at_label, at, _ = AGENT_TRACE_VARIANTS[(j + rep) % len(AGENT_TRACE_VARIANTS)]
            ai = DISCLOSURE_VARIANTS[(j * 2 + rep) % len(DISCLOSURE_VARIANTS)]
            case_id = f"valid-tricky-{j:02d}-{kind}"
            m = _manifest(key_fp=ctx.main_fp, diff_normalized=normalized, files=files,
                          agent_trace=at, ai=ai)

            def run(m=m, diff=stored) -> str:
                blob, _ = _sign_and_zip(m, ctx.main_key, diff)
                p = ctx.path(".zip")
                p.write_bytes(blob)
                return _verify(p, keys=ctx.keys_file)["status"]

            cases.append(Case(case_id, "valid", f"tricky-{kind}", "verified", run))

    assert len(cases) == 50, len(cases)
    return cases


# ---------------------------------------------------------- 50 IRREGULAR

def build_irregular_cases(ctx: Ctx) -> list[Case]:
    cases: list[Case] = []
    normalized_simple = producer.normalize_diff(DIFF_LF)
    grid = [(at, ai) for _l, at, _e in AGENT_TRACE_VARIANTS for ai in DISCLOSURE_VARIANTS]

    def base_manifest(idx: int, **kw) -> dict:
        at, ai = grid[idx % len(grid)]
        kw.setdefault("key_fp", ctx.main_fp)
        return _manifest(diff_normalized=normalized_simple,
                         files=FILES_SINGLE, agent_trace=at, ai=ai, **kw)

    # a) tampered-diff (hash mismatch) -> "tampered"  (5)
    tampered_diffs = [
        DIFF_MUTATED,
        DIFF_MULTIFILE,
        b"",
        DIFF_LF.replace(b"return a + b", b"return b + a"),
        DIFF_LF[:-3] + b"XX\n",
    ]
    for k, bad_diff in enumerate(tampered_diffs):
        m = base_manifest(k)

        def run(m=m, bad_diff=bad_diff) -> str:
            blob, _ = _sign_and_zip(m, ctx.main_key, bad_diff)
            p = ctx.path(".zip")
            p.write_bytes(blob)
            return _verify(p, keys=ctx.keys_file)["status"]

        cases.append(Case(f"tampered-diff-{k}", "irregular", "tampered-diff", "tampered", run))

    # b) manifest edited after signing -> "signature-invalid"  (4)
    for k in range(4):
        m = base_manifest(k + 10)

        def run(m=m) -> str:
            blob, _ = _sign_and_zip(m, ctx.main_key, DIFF_LF, mutate_after_sign=True)
            p = ctx.path(".zip")
            p.write_bytes(blob)
            return _verify(p, keys=ctx.keys_file)["status"]

        cases.append(Case(f"edited-after-signing-{k}", "irregular",
                          "manifest-edited-after-signing", "signature-invalid", run))

    # c) signed by a key absent from the keys file -> "signature-invalid"  (4)
    for k in range(4):
        m = base_manifest(k + 20, key_fp=ctx.rogue_fp)

        def run(m=m) -> str:
            blob, _ = _sign_and_zip(m, ctx.rogue_key, DIFF_LF)
            p = ctx.path(".zip")
            p.write_bytes(blob)
            return _verify(p, keys=ctx.keys_file)["status"]  # keys_file has only the main pubkey

        cases.append(Case(f"rogue-key-{k}", "irregular",
                          "signed-by-key-absent-from-keys-file", "signature-invalid", run))

    # d) rotated/removed key: empty keys file -> "identity-unverifiable"  (4)
    for k in range(4):
        m = base_manifest(k + 30)

        def run(m=m) -> str:
            blob, _ = _sign_and_zip(m, ctx.main_key, DIFF_LF)
            p = ctx.path(".zip")
            p.write_bytes(blob)
            return _verify(p, keys=ctx.empty_keys_file)["status"]

        cases.append(Case(f"rotated-key-{k}", "irregular",
                          "rotated-removed-key-empty-keys", "identity-unverifiable", run))

    # e) spec_version unknown MAJOR -> "unsupported-version"  (4)
    for k, bad_version in enumerate(["scpe/9.9", "scpe/1.0", "scpe/2.0", "scpe/10.5"]):
        m = base_manifest(k + 40)
        m["spec_version"] = bad_version

        def run(m=m) -> str:
            blob, _ = _sign_and_zip(m, ctx.main_key, DIFF_LF)
            p = ctx.path(".zip")
            p.write_bytes(blob)
            return _verify(p, keys=ctx.keys_file)["status"]

        cases.append(Case(f"unsupported-version-{k}", "irregular",
                          "spec-version-unknown-major", "unsupported-version", run))

    # f) malformed envelope zip -> handled ("unattested"), never a crash  (4)
    m = base_manifest(50)
    mbytes = producer.serialize_manifest(m)
    sig = producer.sign_manifest(mbytes, ctx.main_key)
    normal_members = {"manifest.json": mbytes, "manifest.sig": sig, "diff.patch": DIFF_LF}

    def make_zip(members: dict) -> bytes:
        return producer._zip_bytes(list(members.items()))

    malformed = {
        "missing-sig": {k: v for k, v in normal_members.items() if k != "manifest.sig"},
        "missing-manifest": {k: v for k, v in normal_members.items() if k != "manifest.json"},
        "extra-member": {**normal_members, "extra.txt": b"not part of the spec"},
    }
    for name, members in malformed.items():
        def run(members=members) -> str:
            p = ctx.path(".zip")
            p.write_bytes(make_zip(members))
            return _verify(p, keys=ctx.keys_file)["status"]

        cases.append(Case(f"malformed-zip-{name}", "irregular", "malformed-envelope-zip",
                          "unattested", run))

    def run_garbage() -> str:
        p = ctx.path(".zip")
        p.write_bytes(b"PK\x03\x04this is not a real zip, just garbage bytes with a PK prefix")
        return _verify(p, keys=ctx.keys_file)["status"]

    cases.append(Case("malformed-zip-garbage-bytes", "irregular", "malformed-envelope-zip",
                      "unattested", run_garbage))

    # g) no attestation at all, i.e. a plain PR -> "unattested"  (5)
    plain_bodies = [
        "",
        "This PR fixes the off-by-one bug in the pagination helper.",
        "<!-- NOT-SCPE-ATTESTATION\nsome unrelated html comment\n-->",
        '{"just": "some json text that is not an attestation block"}',
        "## Summary\n- refactors calc.py\n- no AI was involved, just me and coffee",
    ]
    for k, body in enumerate(plain_bodies):
        def run(body=body) -> str:
            p = ctx.path(".md")
            p.write_text(body, encoding="utf-8")
            return _verify(p, keys=ctx.keys_file)["status"]

        cases.append(Case(f"no-attestation-{k}", "irregular", "no-attestation-plain-pr",
                          "unattested", run))

    # h) corrupted base64 in the PR-body attestation -> handled, "unattested"  (4)
    good_m = base_manifest(60)
    good_blob, good_mbytes = _sign_and_zip(good_m, ctx.main_key, None)  # attestation form (no diff)

    def h_body(payload: str) -> str:
        return f"<!-- SCPE-ATTESTATION-v1\n{payload}\n-->\n"

    corrupt_cases = {
        "truncated-base64": h_body(base64.b64encode(good_blob).decode("ascii")[:-6]),
        "invalid-characters": h_body("!!!not-valid-base64-at-all***"),
        "decodes-to-non-zip": h_body(base64.b64encode(b"hello world, not a zip").decode("ascii")),
        "truncated-zip-bytes": h_body(base64.b64encode(good_blob[:-30]).decode("ascii")),
    }
    for name, body in corrupt_cases.items():
        def run(body=body) -> str:
            p = ctx.path(".md")
            p.write_text(body, encoding="utf-8")
            return _verify(p, keys=ctx.keys_file)["status"]

        cases.append(Case(f"corrupted-base64-{name}", "irregular",
                          "corrupted-base64-attestation", "unattested", run))

    # i) two attestation blocks -> verifier MUST use only the first (rejected
    #    for the FIRST block's own reason, even though the second is good)  (4)
    good_block = producer.attestation_block(good_mbytes,
                                            producer.sign_manifest(good_mbytes, ctx.main_key))

    def two_blocks_case(name: str, expected: str, first_block: str, keys: Path):
        body = (f"Some PR description.\n\n{first_block}\n\nmore text in between\n\n"
                f"{good_block}\n\nend of body\n")

        def run(body=body, keys=keys) -> str:
            p = ctx.path(".md")
            p.write_text(body, encoding="utf-8")
            return _verify(p, keys=keys)["status"]

        cases.append(Case(f"two-attestations-{name}", "irregular",
                          "two-attestation-blocks-uses-first", expected, run))

    bad_version_m = dict(base_manifest(70))
    bad_version_m["spec_version"] = "scpe/9.9"
    bv_bytes = producer.serialize_manifest(bad_version_m)
    bv_sig = producer.sign_manifest(bv_bytes, ctx.main_key)
    two_blocks_case("first-unsupported-version", "unsupported-version",
                    producer.attestation_block(bv_bytes, bv_sig), ctx.keys_file)

    edited_m = base_manifest(71)
    e_bytes = producer.serialize_manifest(edited_m)
    e_sig = producer.sign_manifest(e_bytes, ctx.main_key)
    e_obj = json.loads(e_bytes)
    e_obj["ai_disclosure"]["notes"] = (e_obj["ai_disclosure"].get("notes") or "") + " EDITED"
    e_bytes_edited = json.dumps(e_obj, indent=2, ensure_ascii=False).encode("utf-8")
    two_blocks_case("first-signature-invalid-edited", "signature-invalid",
                    producer.attestation_block(e_bytes_edited, e_sig), ctx.keys_file)

    rogue_m = base_manifest(72, key_fp=ctx.rogue_fp)
    r_bytes = producer.serialize_manifest(rogue_m)
    r_sig = producer.sign_manifest(r_bytes, ctx.rogue_key)
    two_blocks_case("first-signature-invalid-rogue-key", "signature-invalid",
                    producer.attestation_block(r_bytes, r_sig), ctx.keys_file)

    empty_keys_m = base_manifest(73)
    ek_bytes = producer.serialize_manifest(empty_keys_m)
    ek_sig = producer.sign_manifest(ek_bytes, ctx.main_key)
    two_blocks_case("first-identity-unverifiable-empty-keys", "identity-unverifiable",
                    producer.attestation_block(ek_bytes, ek_sig), ctx.empty_keys_file)

    # j) oversized manifest beyond the 1 MiB cap -> handled, "unattested" (no DoS)  (4)
    pad = "A" * (MAX_MANIFEST_BYTES + 4096)

    def oversized_manifest(idx: int, where: str) -> dict:
        at, ai = grid[idx % len(grid)]
        m = _manifest(key_fp=ctx.main_fp, diff_normalized=normalized_simple,
                     files=FILES_SINGLE, agent_trace=at, ai=dict(ai))
        if where == "extensions":
            m["extensions"] = {"pad": pad}
        elif where == "ai_disclosure.notes":
            m["ai_disclosure"]["notes"] = pad
        elif where == "attestations":
            m["attestations"] = [{"type": "agent-trace", "format": "generic/1",
                                  "data": {"operator": pad}}]
        elif where == "files_changed":
            m["subject"]["change"]["files_changed"] = [f"file_{i}.py" for i in range(80_000)]
        return m

    for k, where in enumerate(["extensions", "ai_disclosure.notes", "attestations", "files_changed"]):
        m = oversized_manifest(k + 80, where)

        def run(m=m) -> str:
            blob, _ = _sign_and_zip(m, ctx.main_key, DIFF_LF)
            p = ctx.path(".zip")
            p.write_bytes(blob)
            return _verify(p, keys=ctx.keys_file)["status"]

        cases.append(Case(f"oversized-manifest-{where}", "irregular",
                          "oversized-manifest-cap", "unattested", run))

    # k) wrong target/base replay: recomputed diff no longer matches -> "tampered" (4)
    replay_diffs = [DIFF_MUTATED, DIFF_MULTIFILE, _big_diff(2),
                    DIFF_LF.replace(b"calc.py", b"other_repo_file.py")]
    for k, wrong_diff in enumerate(replay_diffs):
        m = base_manifest(k + 90)  # signed against BASE_SHA/REPO's real diff (normalized_simple)

        def run(m=m, wrong_diff=wrong_diff) -> str:
            mbytes = producer.serialize_manifest(m)
            sig = producer.sign_manifest(mbytes, ctx.main_key)
            att = producer.attestation_block(mbytes, sig)  # attestation form, no diff.patch
            body_path = ctx.path(".md")
            body_path.write_text(att, encoding="utf-8")
            diff_path = ctx.path(".patch")
            diff_path.write_bytes(wrong_diff)
            return _verify(body_path, keys=ctx.keys_file, diff=diff_path)["status"]

        cases.append(Case(f"wrong-target-replay-{k}", "irregular",
                          "wrong-target-base-replay", "tampered", run))

    assert len(cases) == 46, len(cases)  # + 4 l) cases below == 50
    return cases


def build_l1_cases(ctx: Ctx) -> list[Case]:
    """l) a PR with NO disclosure signal, require=true -> L1 must REJECT
    (status "unattested", gate_pass False) — the require DECISION for level 1,
    computed by reference/level1_lint.py's build_results()."""
    cases: list[Case] = []
    tmp_root = ctx.files_dir

    def expect_reject(results: dict) -> str:
        if (results["status"] == "unattested" and results["gate_pass"] is False
                and results["disclosure"]["present"] is False):
            return "l1-reject-missing-disclosure"
        return f"l1-unexpected:{results}"

    def run_empty() -> str:
        cwd = tmp_root / "l1-empty"
        cwd.mkdir()
        r = _run_l1(cwd, {"REQUIRE": "true"})
        return expect_reject(r)

    def run_unrelated_body() -> str:
        cwd = tmp_root / "l1-unrelated"
        cwd.mkdir()
        r = _run_l1(cwd, {"REQUIRE": "true", "PR_BODY": "Fixes the pagination bug, no big deal."})
        return expect_reject(r)

    def run_unchecked_checkbox() -> str:
        cwd = tmp_root / "l1-unchecked"
        cwd.mkdir()
        r = _run_l1(cwd, {"REQUIRE": "true",
                          "PR_BODY": "- [ ] I used generative AI\n- [ ] I did not use generative AI"})
        return expect_reject(r)

    def run_commits_no_trailer() -> str:
        repo = tmp_root / "l1-repo"
        repo.mkdir()
        run_git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True,
                                            capture_output=True, text=True)
        run_git("init", "-b", "main")
        run_git("config", "user.email", "fixture@example.com")
        run_git("config", "user.name", "Fixture")
        (repo / "a.txt").write_text("base\n", encoding="utf-8")
        run_git("add", "-A")
        run_git("commit", "-m", "base commit")
        base = run_git("rev-parse", "HEAD").stdout.strip()
        (repo / "a.txt").write_text("base\nplain change, no trailer at all\n", encoding="utf-8")
        run_git("add", "-A")
        run_git("commit", "-m", "plain commit, definitely no disclosure trailer")
        head = run_git("rev-parse", "HEAD").stdout.strip()
        cwd = tmp_root / "l1-commits-cwd"
        cwd.mkdir()
        r = _run_l1(cwd, {"REQUIRE": "true", "BASE_SHA": base, "HEAD_SHA": head, "REPO_DIR": str(repo)})
        return expect_reject(r)

    for name, fn in [("empty-pr-no-commits", run_empty),
                     ("unrelated-body-text", run_unrelated_body),
                     ("unchecked-checkbox-not-a-signal", run_unchecked_checkbox),
                     ("real-commit-range-no-trailer", run_commits_no_trailer)]:
        cases.append(Case(f"l1-no-disclosure-{name}", "irregular",
                          "l1-no-disclosure-signal", "l1-reject-missing-disclosure", fn))

    assert len(cases) == 4, len(cases)
    return cases


# --------------------------------------------------------------------- test

def test_stress_100_prs(tmp_path_factory):
    files_dir = tmp_path_factory.mktemp("scpe_stress")
    main_key = files_dir / "_main_ed25519"
    rogue_key = files_dir / "_rogue_ed25519"
    _keygen(main_key, "scpe-stress-main (throwaway, not used for anything real)")
    _keygen(rogue_key, "scpe-stress-rogue (throwaway, NOT in the keys file)")
    keys_file = files_dir / "_keys"
    keys_file.write_bytes(main_key.with_suffix(".pub").read_bytes())
    empty_keys_file = files_dir / "_keys_empty"
    empty_keys_file.write_text("", encoding="utf-8")

    ctx = Ctx(files_dir=files_dir, main_key=main_key, rogue_key=rogue_key,
             main_fp=producer.key_fingerprint(main_key), rogue_fp=producer.key_fingerprint(rogue_key),
             keys_file=keys_file, empty_keys_file=empty_keys_file)

    valid_cases = build_valid_cases(ctx)
    irregular_cases = build_irregular_cases(ctx) + build_l1_cases(ctx)
    assert len(valid_cases) == 50 and len(irregular_cases) == 50

    all_cases = valid_cases + irregular_cases
    assert len(all_cases) == 100

    results: list[tuple[Case, str, bool]] = []
    for case in all_cases:
        actual = case.run()
        results.append((case, actual, actual == case.expected))

    # The require DECISION, exercised again on every verifier-backed case's
    # resulting status (action.yml:149): valid cases MUST gate-pass, every
    # "irregular" case whose expected value is a bare verifier status MUST
    # gate-fail. L1 cases already assert their own require decision internally
    # (gate_pass is part of `expect_reject` above).
    require_mismatches = []
    for case, actual, ok in results:
        if case.category == "l1-no-disclosure-signal":
            continue
        want_pass = case.group == "valid"
        got_pass = require_decision(actual)
        if got_pass != want_pass:
            require_mismatches.append((case.case_id, actual, got_pass, want_pass))

    valid_ok = sum(1 for c, _a, ok in results if c.group == "valid" and ok)
    irregular_ok = sum(1 for c, _a, ok in results if c.group == "irregular" and ok)
    total_ok = valid_ok + irregular_ok

    by_category = Counter()
    ok_by_category = Counter()
    for c, _a, ok in results:
        by_category[c.category] += 1
        if ok:
            ok_by_category[c.category] += 1

    summary_lines = [
        f"{total_ok}/100 classified correctly "
        f"({valid_ok}/50 valid -> pass, {irregular_ok}/50 irregular -> correct reject status)",
    ]
    for cat in sorted(by_category):
        summary_lines.append(f"  {cat}: {ok_by_category[cat]}/{by_category[cat]}")
    summary = "\n".join(summary_lines)
    print(summary)

    failed = [(c, a) for c, a, ok in results if not ok]
    if failed or require_mismatches:
        detail = "\n".join(f"  {c.case_id} [{c.category}]: expected {c.expected!r}, got {a!r}"
                           for c, a in failed)
        req_detail = "\n".join(
            f"  {cid}: status={status!r} gate_pass={got!r} want={want!r}"
            for cid, status, got, want in require_mismatches)
        pytest.fail(
            f"{len(failed)}/100 misclassified; {len(require_mismatches)} require-decision "
            f"mismatches\n{detail}\n{req_detail}\n\n{summary}")

    assert total_ok == 100
    assert not require_mismatches
