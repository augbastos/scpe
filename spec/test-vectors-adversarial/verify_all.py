#!/usr/bin/env python3
"""Run the reference verifier against every vector in this directory and print its
real output. Companion to make_adversarial_vectors.py: run this AFTER generating (or
regenerating) the vectors and copy the real `status`/`detail` into each vector's
expected.json by hand -- expected.json must record what the verifier actually says,
never an assumed status. Stdlib only.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERIFIER = ROOT.parent.parent / "reference" / "standalone" / "verify_envelope.py"


def main() -> int:
    vector_dirs = sorted(
        p for p in ROOT.iterdir()
        if p.is_dir() and not p.name.startswith("_"))
    if not vector_dirs:
        print("no vector directories found", file=sys.stderr)
        return 1
    for d in vector_dirs:
        proc = subprocess.run(
            [sys.executable, str(VERIFIER), str(d), "--keys", str(d / "keys"), "--json"],
            capture_output=True, text=True)
        print(f"== {d.name} ==")
        print(f"  exit code: {proc.returncode}")
        if proc.stdout.strip():
            try:
                out = json.loads(proc.stdout)
                print(f"  status: {out['status']}")
                print(f"  attestations: {out['attestations']}")
                print(f"  detail: {out['detail']}")
            except json.JSONDecodeError:
                print(f"  stdout (unparsable as json): {proc.stdout.strip()!r}")
        if proc.stderr.strip():
            print(f"  stderr: {proc.stderr.strip()!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
