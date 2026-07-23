#!/usr/bin/env python3
"""SCPE profiles demo — one core, every domain (SPEC §13).

Runnable end-to-end: `python examples/demo.py`. It packs a REAL tiny file per profile
family and verifies each through the ONE stdlib reference verifier, showing that:

  * SCPE-C  (code)     rides a `code-change` subject (a diff)          -> verified
  * SCPE-I  (image)    rides an `artifact` subject (a real 1x1 PNG)    -> verified
  * SCPE-M  (model)    rides an `artifact` subject (a tiny safetensors)-> verified
  * SCPE-DATA (dataset)rides an `artifact` subject (a tiny JSONL)      -> verified
  * SCPE-D  (document) rides an `artifact` subject (a tiny PDF)        -> verified

Every envelope verifies on the SAME verify_envelope.py — a profile is a label plus a
media_type convention, never a new verification path (SPEC §13.2). The verifier surfaces
the stamped profile verbatim; the verify DECISION is still by subject.type (SPEC §6).

Fully offline, like the normative test vectors: a throwaway ed25519 key and a local
`keys` file stand in for github.com/<login>.keys. Nothing touches the network or `gh`.
The private key lives only in a TemporaryDirectory and is deleted on exit.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRODUCER_PATH = ROOT / "reference" / "producer.py"
VERIFIER = ROOT / "reference" / "standalone" / "verify_envelope.py"

# Load reference/producer.py by path — it lives outside the scpe package on purpose.
_spec = importlib.util.spec_from_file_location("scpe_producer_ref", PRODUCER_PATH)
producer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(producer)

LOGIN = "octocat-test"
CREATED_AT = "2026-07-22T00:00:00Z"

# A real 1x1 transparent PNG (67 bytes) — a genuine image file, not a placeholder.
PNG_1x1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def make_signing_key(td: Path) -> tuple[Path, Path]:
    """A throwaway ed25519 key + a local `keys` file (the public half), exactly the
    offline stand-in for github.com/<login>.keys the test vectors use."""
    key = td / "scpe_demo_ed25519"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(key), "-N", "", "-q"],
                   check=True, capture_output=True)
    keys = td / "keys"
    keys.write_bytes(Path(str(key) + ".pub").read_bytes())
    return key, keys


def make_code_repo(td: Path) -> tuple[Path, str, str]:
    """A tiny git repo with a base and a head commit — the SCPE-C `code-change` subject."""
    repo = td / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    _git(repo, "config", "user.email", "demo@example.com")
    _git(repo, "config", "user.name", "Demo")
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "fix add()")
    head = _git(repo, "rev-parse", "HEAD")
    return repo, base, head


def make_artifact_files(td: Path) -> dict[str, Path]:
    """A REAL tiny file per artifact-family profile."""
    png = td / "pixel.png"
    png.write_bytes(PNG_1x1)

    # A minimal, structurally-valid empty safetensors: 8-byte LE header length + JSON.
    model = td / "tiny.safetensors"
    header = b'{"__metadata__":{"demo":"scpe"}}'
    model.write_bytes(struct.pack("<Q", len(header)) + header)

    # A tiny JSONL training dataset (two records).
    dataset = td / "train.jsonl"
    dataset.write_text(
        '{"prompt":"hi","completion":"hello"}\n'
        '{"prompt":"bye","completion":"goodbye"}\n', encoding="utf-8")

    # A tiny, well-formed minimal PDF document.
    doc = td / "note.pdf"
    doc.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n")
    return {"SCPE-I": png, "SCPE-M": model, "SCPE-DATA": dataset, "SCPE-D": doc}


def run_verifier(path: Path, keys: Path, diff: Path | None = None) -> dict:
    """Run the ONE stdlib verifier as a subprocess (exactly how an auditor runs it)."""
    args = [sys.executable, str(VERIFIER), str(path), "--keys", str(keys), "--json"]
    if diff is not None:
        args += ["--diff", str(diff)]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if not proc.stdout.strip():
        raise RuntimeError(f"verifier produced no output; stderr: {proc.stderr[-500:]}")
    return json.loads(proc.stdout)


def demo() -> int:
    with tempfile.TemporaryDirectory(prefix="scpe-demo-") as _td:
        td = Path(_td)
        key, keys = make_signing_key(td)
        repo, base, head = make_code_repo(td)
        artifacts = make_artifact_files(td)

        rows: list[tuple[str, str, str, str]] = []
        all_ok = True

        # --- SCPE-C: a code-change subject (a diff) -----------------------------------
        env = td / "scpe-c.zip"
        producer.pack(repo=repo, base=base, head=head, out=env,
                      login=LOGIN, key=str(key), ai_mode="assisted",
                      ai_notes="demo: SCPE-C code change", created_at=CREATED_AT,
                      profile="SCPE-C",
                      attestations=[{"type": "agent-trace", "format": "generic/1",
                                     "data": {"agent": "demo"}}])
        res = run_verifier(env, keys)
        ok = res["status"] == "verified" and res.get("profile") == "SCPE-C"
        all_ok &= ok
        rows.append(("SCPE-C", "code-change", res["status"], res.get("profile") or "-"))

        # --- SCPE-I / SCPE-M / SCPE-DATA / SCPE-D: artifact subjects ------------------
        # No --media-type passed: each profile's convention (SPEC §13.1) supplies it.
        for profile, artifact in artifacts.items():
            env = td / f"{profile.lower()}.zip"
            producer.pack_artifact(artifact=artifact, out=env, media_type=None,
                                   login=LOGIN, key=str(key), ai_mode="generated",
                                   ai_notes=f"demo: {profile} artifact",
                                   created_at=CREATED_AT, profile=profile)
            # Confirm the profile's convention media_type was stamped.
            with zipfile.ZipFile(env) as zf:
                man = json.loads(zf.read("manifest.json"))
            media = man.get("subject", {}).get("media_type", "-")
            res = run_verifier(env, keys)
            ok = res["status"] == "verified" and res.get("profile") == profile
            all_ok &= ok
            rows.append((profile, f"artifact ({media})", res["status"], res.get("profile") or "-"))

    print("\nSCPE profiles demo — one core, every domain (SPEC §13)\n")
    print(f"  {'profile':<10} {'subject':<28} {'status':<12} surfaced-profile")
    print(f"  {'-'*10} {'-'*28} {'-'*12} {'-'*16}")
    for prof, subj, status, surfaced in rows:
        mark = "OK" if status == "verified" and surfaced == prof else "!!"
        print(f"  {prof:<10} {subj:<28} {status:<12} {surfaced}   [{mark}]")
    print()
    if all_ok:
        print("All profiles packed and verified on the ONE verifier, profile surfaced. "
              "A profile is a label + convention, never a verification path (SPEC §13.2).\n")
        return 0
    print("FAIL: at least one profile did not verify or surface as expected.\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(demo())
