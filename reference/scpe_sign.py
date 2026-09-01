#!/usr/bin/env python3
"""SCPE `scpe/1` reference producer — standard library only.

Emits a DSSE envelope carrying an in-toto Statement with an SCPE generation predicate, as a
detached `<artifact>.scpe.jsonl` sidecar (spec/SPECIFICATION.md §4, §5, §7).

A conforming producer asserts NO assurance facet (SPEC §10.1). There is deliberately no flag
in this tool that can set one: facets are the verifier's output, computed from what it
observed, and a producer that could write one could inflate it.

Usage:
    scpe_sign.py ARTIFACT --key ~/.ssh/id_ed25519 \
        [--source-type trainedAlgorithmicData] [--provider anthropic] [--model NAME]
        [--oversight prompt_guided] [--derived-from FILE:inputTo] [--commit-prompt FILE]
        [--observe SIDECAR] [--out PATH]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scpe_verify import (  # noqa: E402  (single source of truth for the shared constants)
    PAYLOAD_TYPE, PREDICATE_TYPES, RELATIONSHIPS, ROLE_NAMESPACES, SPEC_VERSION,
    STATEMENT_TYPE, pae,
)

PREDICATE_TYPE = sorted(PREDICATE_TYPES)[0]

IPTC = "http://cv.iptc.org/newscodes/digitalsourcetype/"
C2PA = "http://c2pa.org/digitalsourcetype/"

#: Shorthands for the vocabulary SCPE reuses rather than mints (SPEC §5.3). The full URI may
#: always be passed instead; unknown values are allowed through, because the vocabulary is
#: maintained elsewhere and new terms are expected.
SOURCE_TYPES = {
    "trainedAlgorithmicMedia": IPTC + "trainedAlgorithmicMedia",
    "compositeWithTrainedAlgorithmicMedia": IPTC + "compositeWithTrainedAlgorithmicMedia",
    "compositeSynthetic": IPTC + "compositeSynthetic",
    "digitalCapture": IPTC + "digitalCapture",
    "humanEdits": IPTC + "humanEdits",
    "digitalCreation": IPTC + "digitalCreation",
    "trainedAlgorithmicData": C2PA + "trainedAlgorithmicData",
    "empty": C2PA + "empty",
}

SALT_BYTES = 16          # SPEC §12.2 floor


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def key_fingerprint(private_key: Path) -> str:
    """`SHA256:…` for the public half, via ssh-keygen -l."""
    exe = shutil.which("ssh-keygen")
    if exe is None:
        raise SystemExit("ssh-keygen not found on PATH")
    pub = private_key.with_suffix(private_key.suffix + ".pub")
    target = pub if pub.is_file() else private_key
    out = subprocess.run([exe, "-l", "-f", str(target)], capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"could not read key fingerprint: {out.stderr.strip()}")
    for token in out.stdout.split():
        if token.startswith("SHA256:"):
            return token
    raise SystemExit("ssh-keygen -l returned no SHA256 fingerprint")


def key_algorithm(private_key: Path) -> str:
    """Map the key type to a registered suite identifier (SPEC §8.1)."""
    exe = shutil.which("ssh-keygen")
    pub = private_key.with_suffix(private_key.suffix + ".pub")
    target = pub if pub.is_file() else private_key
    out = subprocess.run([exe, "-l", "-f", str(target)], capture_output=True, text=True)
    text = out.stdout.upper()
    if "ED25519" in text:
        return "sshsig-ssh-ed25519"
    if "ECDSA" in text:
        return "sshsig-ecdsa-sha2-nistp256"
    raise SystemExit("unsupported key type; SCPE registers Ed25519 and ECDSA P-256")


def sshsig_sign(signed_bytes: bytes, private_key: Path, namespace: str) -> bytes:
    """`ssh-keygen -Y sign` over the PAE bytes, under the role's namespace (SPEC §8.3)."""
    exe = shutil.which("ssh-keygen")
    if exe is None:
        raise SystemExit("ssh-keygen not found on PATH")
    with tempfile.TemporaryDirectory(prefix="scpe-sign-") as tmp:
        message = Path(tmp) / "m"
        message.write_bytes(signed_bytes)
        run = subprocess.run(
            [exe, "-Y", "sign", "-f", str(private_key), "-n", namespace, str(message)],
            capture_output=True)
        if run.returncode != 0:
            raise SystemExit(f"ssh-keygen -Y sign failed: {run.stderr.decode(errors='replace')}")
        return (message.with_suffix(".sig")).read_bytes()


def build_envelope(statement: dict, private_key: Path, namespace: str) -> dict:
    """Serialize once, sign those exact bytes, and carry the same bytes in the envelope.

    `body` is produced here and never regenerated. If this function serialized twice — once
    to sign and once to emit — a dict-ordering or separator difference between the two calls
    would produce an envelope whose signature does not cover its own payload. Serializing
    once is the producer-side half of the exact-bytes rule (SPEC §4.2).
    """
    body = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = sshsig_sign(pae(PAYLOAD_TYPE, body), private_key, namespace)
    return {
        "payload": base64.b64encode(body).decode("ascii"),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [{"sig": base64.b64encode(signature).decode("ascii")}],
    }


def parse_edge(spec: str) -> tuple[Path, str]:
    """`FILE:relationship`, defaulting to inputTo."""
    if ":" in spec and spec.rsplit(":", 1)[1] in RELATIONSHIPS:
        path, relationship = spec.rsplit(":", 1)
    else:
        path, relationship = spec, "inputTo"
    return Path(path), relationship


def statement_digest(sidecar: Path) -> str:
    """SHA-256 of a record's signed payload bytes — the pin a parentOf edge requires."""
    first = [ln for ln in sidecar.read_bytes().splitlines() if ln.strip()][0]
    envelope = json.loads(first)
    return hashlib.sha256(base64.b64decode(envelope["payload"])).hexdigest()


def build_commitment(name: str, path: Path) -> tuple[dict, bytes]:
    """SD-JWT structured disclosure `[salt, name, value]` (SPEC §12.2).

    Returns (commitment_for_the_record, disclosure_bytes_to_keep).

    The framing is the point. A bare `salt || value` concatenation is safe only by accident
    of fixed-length salts; a structured, unambiguously delimited encoding is safe by design.
    The raw value is never written into the record — that is the whole reason a commitment
    exists rather than a field.

    The disclosure MUST be returned to the caller and stored somewhere the signer controls.
    An earlier version built the disclosure, hashed it, and let the salt fall out of scope,
    which meant no commitment could ever be opened — by anyone, including its author. A
    commitment nobody can open is not a privacy feature; it is a hash of nothing checkable,
    and it makes the README's "prove it later" claim false.
    """
    salt = base64.urlsafe_b64encode(secrets.token_bytes(SALT_BYTES)).decode("ascii").rstrip("=")
    value = path.read_text(encoding="utf-8", errors="replace")
    disclosure = json.dumps([salt, name, value], separators=(",", ":"),
                            ensure_ascii=False).encode("utf-8")
    commitment = {
        "name": name,
        "alg": "sha256",
        "value": hashlib.sha256(disclosure).hexdigest(),
        "disclosure": "sd-jwt/1",
    }
    return commitment, disclosure


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SCPE scpe/1 reference producer")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--key", type=Path, required=True, help="SSH private key to sign with")
    parser.add_argument("--source-type", default="trainedAlgorithmicData",
                        help="IPTC/C2PA digitalSourceType term or shorthand")
    parser.add_argument("--provider", default=None, help="OTel gen_ai.provider.name")
    parser.add_argument("--model", default=None, help="OTel gen_ai.response.model")
    parser.add_argument("--oversight", default=None,
                        choices=["fully_autonomous", "prompt_guided", "human_validated"])
    parser.add_argument("--media-type", default=None)
    parser.add_argument("--derived-from", action="append", default=[],
                        metavar="FILE[:relationship]")
    parser.add_argument("--commit-prompt", type=Path, default=None,
                        help="commit to a prompt file WITHOUT storing its text")
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--observe", type=Path, default=None,
                        help="emit an observer statement about an existing record")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    if not args.artifact.is_file():
        raise SystemExit(f"artifact not found: {args.artifact}")

    digest = sha256_file(args.artifact)
    subject = [{"name": args.artifact.name, "digest": {"sha256": digest}}]
    if args.media_type:
        subject[0]["mediaType"] = args.media_type

    fingerprint = key_fingerprint(args.key)
    algorithm = key_algorithm(args.key)
    source_type = SOURCE_TYPES.get(args.source_type, args.source_type)

    if args.observe is not None:
        # An observation is its own envelope carrying only what an observer can witness:
        # these bytes, and this producer statement about them (SPEC §8.4).
        role = "observer"
        predicate = {
            "scpeVersion": SPEC_VERSION,
            "generation": {"digitalSourceType": source_type},
            "signer": [{"keyFingerprint": fingerprint, "alg": algorithm, "role": role}],
            "observed": {"statementDigest": {"sha256": statement_digest(args.observe)}},
        }
    else:
        role = "producer"
        generation = {"digitalSourceType": source_type}
        if args.provider:
            generation["provider"] = args.provider
        if args.model:
            generation["model"] = args.model
        if args.oversight:
            generation["humanOversight"] = args.oversight

        predicate = {
            "scpeVersion": SPEC_VERSION,
            "generation": generation,
            "signer": [{"keyFingerprint": fingerprint, "alg": algorithm, "role": role}],
        }

        edges = []
        for spec in args.derived_from:
            path, relationship = parse_edge(spec)
            if not path.is_file():
                raise SystemExit(f"derived-from file not found: {path}")
            edge = {
                "relationship": relationship,
                "resource": {"name": path.name, "digest": {"sha256": sha256_file(path)}},
            }
            sidecar = Path(str(path) + ".scpe.jsonl")
            if sidecar.is_file():
                edge["statementDigest"] = {"sha256": statement_digest(sidecar)}
            elif relationship == "parentOf":
                # REQUIRED on parentOf, and unforgeable without the parent's record — so a
                # parent with no provenance simply cannot be declared as one (SPEC §6.2).
                raise SystemExit(
                    f"a parentOf edge requires the parent's record; none found at {sidecar}")
            edges.append(edge)
        if edges:
            predicate["derivedFrom"] = edges

        if args.commit_prompt is not None:
            commitment, disclosure = build_commitment("prompt", args.commit_prompt)
            predicate["commitments"] = [commitment]
            # The disclosure is the ONLY way this commitment can ever be opened. It is
            # written beside the signer, never into the record, and never published.
            disclosure_path = Path(str(args.artifact) + ".scpe.disclosures.jsonl")
            with disclosure_path.open("a", encoding="utf-8") as fh:
                fh.write(disclosure.decode("utf-8") + "\n")
            print(f"{disclosure_path}  <- KEEP PRIVATE: without it the commitment "
                  f"cannot be opened", file=sys.stderr)
        if args.run_id:
            predicate["run"] = {"id": args.run_id}

    statement = {
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }

    envelope = build_envelope(statement, args.key, ROLE_NAMESPACES[role])
    line = json.dumps(envelope, separators=(",", ":")) + "\n"

    out = args.out or Path(str(args.artifact) + ".scpe.jsonl")
    if args.observe is not None and args.out is None:
        out = args.observe
        with out.open("a", encoding="utf-8") as fh:      # append: a bundle is JSON Lines
            fh.write(line)
    else:
        out.write_text(line, encoding="utf-8")

    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
