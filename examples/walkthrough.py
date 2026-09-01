#!/usr/bin/env python3
"""The canonical SCPE walkthrough — one story, end to end, actually executed.

Run it:  python examples/walkthrough.py

Everything happens in a temporary directory and nothing touches your keys or your machine's
configuration. Each step prints the real command and its real output; no output in this
script is transcribed or invented.

The story: an analyst generates a summary from a spreadsheet using a model, signs a record
of that, and a colleague later verifies it — first with no trust anchor of their own, then
with one, then after someone edits the file. The point of the walkthrough is not that
verification succeeds. It is watching what the verifier is willing to claim at each stage.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SIGN = REPO / "reference" / "scpe_sign.py"
VERIFY = REPO / "reference" / "scpe_verify.py"


def narrate(number: str, title: str, body: str) -> None:
    print(f"\n\033[1m{number}. {title}\033[0m")
    for line in body.strip().splitlines():
        print(f"   {line.strip()}")
    print()


def run(cmd: list[str], cwd: Path, *, expect_failure: bool = False) -> subprocess.CompletedProcess:
    shown = " ".join(Path(c).name if str(c).endswith(".py") else str(c) for c in cmd[1:])
    print(f"   $ scpe {shown}")
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    for line in (proc.stdout + proc.stderr).rstrip().splitlines():
        print(f"   {line}")
    print(f"   [exit {proc.returncode}]")
    if not expect_failure and proc.returncode not in (0, 10, 11):
        raise SystemExit(f"unexpected failure: {proc.returncode}")
    return proc


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="scpe-walkthrough-") as tmp:
        d = Path(tmp)

        print("\033[1mSCPE walkthrough\033[0m — every command below really runs.")

        # ---------------------------------------------------------------- setup
        narrate("0", "Two people, two keys", """
            Alice is an analyst. Bob is a colleague who will later verify her work.
            Neither of them registers anything, pays a CA, or contacts a server.
        """)
        for name in ("alice", "bob"):
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"{name}@example",
                            "-f", str(d / name)], check=True, capture_output=True)
        print("   $ ssh-keygen -t ed25519 -f alice   # and one for bob")
        print("   (two keypairs created)")

        (d / "quarterly.csv").write_text("region,revenue\nEMEA,182000\nAPAC,97000\n")
        (d / "summary.md").write_text(
            "# Q3 summary\n\nEMEA led at 182k, APAC followed at 97k.\n")

        # ---------------------------------------------------------------- sign
        narrate("1", "Alice signs a record of what produced the summary", """
            She names the model and the provider. She does NOT store the prompt --
            she commits to it, so she can prove its contents later without publishing
            confidential text now.
        """)
        (d / "prompt.txt").write_text("Summarise the quarterly figures in two sentences.\n")
        run([sys.executable, str(SIGN), "summary.md",
             "--key", "alice",
             "--provider", "anthropic",
             "--model", "claude-opus-4-5-20251101",
             "--source-type", "trainedAlgorithmicData",
             "--oversight", "prompt_guided",
             "--media-type", "text/markdown",
             "--derived-from", "quarterly.csv:inputTo",
             "--commit-prompt", "prompt.txt"], d)

        print("   The record sits next to the file, as one line of JSON:")
        record = (d / "summary.md.scpe.jsonl").read_text()
        print(f"   summary.md.scpe.jsonl  ({len(record)} bytes)")

        # ------------------------------------------------------- verify, no anchor
        narrate("2", "Bob verifies with a key file Alice sent him", """
            This works -- and the verifier refuses to pretend it means much. Alice
            supplied both the record and the keys, so the trust anchor is `flag`:
            the input is vouching for itself.
        """)
        (d / "alice-key").write_text((d / "alice.pub").read_text())
        run([sys.executable, str(VERIFY), "summary.md", "--keys", "alice-key"], d)

        # ------------------------------------------------------ verify with policy
        narrate("3", "Bob adds Alice to his OWN trust policy", """
            Now the anchor is `policy` -- a file Bob controls, in OpenSSH's own
            allowed_signers format. Same record, same signature, and a materially
            stronger result, because the trust came from somewhere Alice cannot edit.
        """)
        (d / "allowed_signers").write_text(
            f'alice namespaces="scpe/1" {(d / "alice.pub").read_text().strip()}\n')
        run([sys.executable, str(VERIFY), "summary.md", "--policy", "allowed_signers"], d)

        narrate("4", "Read the bottom of that output again", """
            The model name is under "Declared by the signer (NOT verified)".
            Alice's word is all that supports it. The verifier checked a signature and
            a digest; it did not, and cannot, check that Claude wrote this.
            That distinction is the entire product.
        """)

        # ---------------------------------------------------------------- tamper
        narrate("5", "Someone edits the summary", """
            One character. The signature still verifies -- it always would, it covers
            the record, not the file -- but the digest binding breaks.
        """)
        (d / "summary.md").write_text(
            "# Q3 summary\n\nEMEA led at 1820000, APAC followed at 97k.\n")
        run([sys.executable, str(VERIFY), "summary.md", "--policy", "allowed_signers"],
            d, expect_failure=True)

        # ------------------------------------------------------------ countersign
        narrate("6", "Bob countersigns what he saw", """
            Bob restores the file and signs a NARROW statement: these bytes, and this
            statement about them, existed together. He cannot sign that Claude wrote
            it -- the schema will not let him claim anything he did not witness.
        """)
        (d / "summary.md").write_text(
            "# Q3 summary\n\nEMEA led at 182k, APAC followed at 97k.\n")
        run([sys.executable, str(SIGN), "summary.md", "--key", "bob",
             "--observe", "summary.md.scpe.jsonl"], d)
        (d / "allowed_signers").write_text(
            f'alice namespaces="scpe/1" {(d / "alice.pub").read_text().strip()}\n'
            f'bob namespaces="scpe-obs/1" {(d / "bob.pub").read_text().strip()}\n')
        run([sys.executable, str(VERIFY), "summary.md", "--policy", "allowed_signers"], d)

        narrate("7", "What just changed, and what did not", """
            `attribution` moved from self-asserted to countersigned. Read the gloss:
            a second KEY signed -- that does not establish a second PARTY. Nothing
            offline can. Alice could have generated Bob's key herself, and no verifier
            in the world could tell.

            The claim about Claude is exactly as unverified as it was in step 3.
            A countersignature corroborates that a record existed, never that it is true.
        """)

        print("\n\033[1mThat is the whole protocol.\033[0m")
        print("   No CA. No server. No account. No network call at any point above.")
        print("   The verifier's job was never to say yes -- it was to say precisely")
        print("   what 'yes' covers, and what it leaves untouched.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
