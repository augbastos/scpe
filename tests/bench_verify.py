"""Reproduce the verify wall-time figure the README quotes.

Not a test — nothing here asserts a timing, because a number that fails CI on a slow runner
teaches people to ignore CI. It exists so the published figure is checkable: a benchmark
nobody can re-run is exactly the kind of unsourced claim this project argues against.

    python tests/bench_verify.py

Measures the cold-process path: a fresh interpreter per run, verifying a real signed envelope
against a supplied keys file (`--keys`, the `flag` anchor), so no network is involved and the
number is about this code rather than about DNS. The warm figure re-verifies in-process, which
is what a batch consumer sees after import cost is paid once.
"""
from __future__ import annotations

import argparse
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "reference" / "standalone" / "verify_envelope.py"


def cold(envelope: Path, keys: Path, runs: int) -> list[float]:
    cmd = [sys.executable, str(VERIFIER), str(envelope), "--keys", str(keys)]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    subprocess.run(cmd, capture_output=True, env=env)  # prime the OS file cache
    out = []
    for _ in range(runs):
        t0 = time.perf_counter()
        r = subprocess.run(cmd, capture_output=True, env=env)
        out.append((time.perf_counter() - t0) * 1000)
        if r.returncode != 0:
            raise SystemExit(f"verifier exited {r.returncode}: "
                             f"{r.stderr.decode(errors='replace')[:200]}")
    return out


def warm(envelope: Path, keys: Path, runs: int) -> list[float]:
    sys.path.insert(0, str(VERIFIER.parent))
    import verify_envelope as ve  # noqa: E402

    out = []
    for _ in range(runs):
        t0 = time.perf_counter()
        result = ve.verify(envelope, keys, None)
        out.append((time.perf_counter() - t0) * 1000)
    if result.status != "verified":
        raise SystemExit(f"warm run did not verify: {result.status}")
    return out


def report(label: str, samples: list[float]) -> None:
    print(f"{label:<22} n={len(samples):<3} median={statistics.median(samples):6.0f} ms   "
          f"min={min(samples):6.0f}   max={max(samples):6.0f}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("envelope", type=Path, help="a signed SCPE envelope zip")
    ap.add_argument("--keys", type=Path, required=True, help="authorized-keys file to verify against")
    ap.add_argument("--runs", type=int, default=15)
    args = ap.parse_args()

    print(f"python {sys.version.split()[0]}  ·  {sys.platform}")
    report("cold process", cold(args.envelope, args.keys, args.runs))
    try:
        report("warm in-process", warm(args.envelope, args.keys, args.runs))
    except AttributeError:
        print("warm in-process       skipped (no reusable entry point in this verifier build)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
