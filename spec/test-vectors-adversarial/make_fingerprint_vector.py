#!/usr/bin/env python3
"""Generate the `fingerprint-names-another-key` adversarial vector, on its own.

Separate from make_adversarial_vectors.py on purpose. That script regenerates the whole
pack from the throwaway key at ../test-vectors/_key/, which is gitignored and therefore
absent in every fresh clone — re-running it mints a new key and rewrites all the committed
vectors and their signatures. This vector needs no relationship to any other vector: it is
self-contained by construction, because its entire subject is two keys published by one
account. So it makes its own pair, and touches nothing else.

    python spec/test-vectors-adversarial/make_fingerprint_vector.py

What it builds: the account publishes keys A and B. The manifest names A in
`contributor.key_fingerprint`. The signature is made with B. Both keys are genuinely the
account's, so verifying against the published set succeeds — and the audit record then
names a key that did not sign this manifest.

Until this existed, no vector in either pack had more than one key in its `keys` file,
which is exactly why the gap survived eighteen normative vectors and seven adversarial
ones: with a single published key, naming it and signing with it are the same act.

Stdlib only. External binary: ssh-keygen (OpenSSH >= 8.2).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NAME = "fingerprint-names-another-key"


def _load_make_vectors():
    """Reuse the normative generator's manifest builder and diff normalizer.

    Imported by path with bytecode writing off, so importing it never drops a
    __pycache__ into spec/test-vectors/ — that directory's contents are the conformance
    contract and two harnesses count its entries.
    """
    path = ROOT.parent / "test-vectors" / "make_vectors.py"
    spec = importlib.util.spec_from_file_location("_mv", path)
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(module)
    return module


def fingerprint(pub: Path) -> str:
    out = subprocess.run(["ssh-keygen", "-lf", str(pub)],
                         check=True, capture_output=True, text=True)
    return out.stdout.split()[1]


def main() -> int:
    if shutil.which("ssh-keygen") is None:
        print("ssh-keygen not found (OpenSSH >= 8.2 required)", file=sys.stderr)
        return 1

    mv = _load_make_vectors()
    out = ROOT / NAME
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    tmp = ROOT / "_tmp_keys"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir()
    try:
        named, signer = tmp / "key_a", tmp / "key_b"
        for path, comment in ((named, "key A - named by the manifest"),
                              (signer, "key B - the one that actually signs")):
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(path),
                            "-N", "", "-q", "-C", comment],
                           check=True, capture_output=True, text=True)

        diff = mv.normalize(mv.DIFF)
        manifest = mv.manifest()
        manifest["contributor"]["key_fingerprint"] = fingerprint(named.with_suffix(".pub"))
        manifest["subject"]["change"]["diff_sha256"] = hashlib.sha256(diff).hexdigest()

        mp = out / "manifest.json"
        mp.write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(signer),
                        "-n", mv.NAMESPACE, str(mp)],
                       check=True, capture_output=True, text=True)
        mp.with_suffix(".json.sig").replace(out / "manifest.sig")

        (out / "diff.patch").write_bytes(diff)
        # BOTH keys published by the account — that is the whole point.
        (out / "keys").write_text(
            named.with_suffix(".pub").read_text(encoding="utf-8")
            + signer.with_suffix(".pub").read_text(encoding="utf-8"),
            encoding="utf-8")
        (out / "expected.json").write_text(json.dumps({
            "status": "signature-invalid",
            "note": (
                "The account publishes two keys; the manifest names the first in "
                "contributor.key_fingerprint and the signature was made with the second. "
                "Before the three verifiers read that field, `ssh-keygen -Y verify` "
                "against the full published set succeeded and this returned `verified` — "
                "a genuine signature under an audit record naming a key that did not "
                "produce it. key_fingerprint is a MUST and SPEC §14 states the manifest "
                "binds it, but nothing compared it to anything. Restricting the allowed "
                "signers to the named key makes the mismatch signature-invalid: the "
                "signature cannot be validated against the key the manifest declares. "
                "Same status the wrong-identity normative vector already expects, so the "
                "eighteen normative expectations are unchanged. This is the only vector "
                "in either pack whose keys file holds more than one key, which is why "
                "the gap survived all twenty-five."),
        }, indent=2) + "\n", encoding="utf-8")
    finally:
        shutil.rmtree(tmp)

    print(f"wrote {out.relative_to(ROOT.parent.parent)} (expected: signature-invalid)")
    print("now confirm all three implementations agree — verify_all.py, the Go binary, "
          "and the Rust binary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
