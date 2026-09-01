#!/usr/bin/env python3
"""SCPE `scpe/1` reference verifier — one file, standard library only.

Implements spec/SPECIFICATION.md §9 (algorithm), §10 (assurance facets) and §11 (result
shape). The only external binary is `ssh-keygen`, and only for the SSHSIG suites.

Design rules this file is written to obey, all of them normative:

  * No canonicalization, ever. The bytes that were signed are the bytes that are verified,
    and the bytes verified in step 4 are the ones parsed in step 6 (SPEC §4.2, §9 step 5).
  * Fail closed on every unrecognised input (SPEC §9.7).
  * Every assurance facet is computed from an observation THIS PROCESS made. Nothing read
    out of a statement is ever an input to a facet (SPEC §10.1, Law 1).
  * No status may imply a check that did not run. A missing backend is `tooling-error`,
    never `signature-invalid` (SPEC §11.5).
  * Zero network I/O BY DEFAULT. Exactly one code path can open a socket — the `forge`
    anchor's key fetch — and it is unreachable without two explicit operator flags
    (`--forge` and `--allow-host`), prints the host before connecting, and is governed by
    SPEC §13.4: HTTPS only, TLS and hostname validation on, redirects refused outright,
    final URL re-checked, host from a fixed table that no record can influence.

Usage:
    scpe_verify.py ARTIFACT [--sidecar PATH] [--policy allowed_signers]
                            [--keys FILE] [--forge PROVIDER:ACCOUNT --allow-host HOST]
                            [--chain] [--json]
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

# ------------------------------------------------------------------ constants

SPEC_VERSION = "1"

#: SPEC §2.1. This implementation resolves chains, validates observer statements and
#: supports every registered anchor, so it declares `full`. A Core verifier is equally
#: conforming; it must refuse what it does not implement rather than ignore it.
PROFILE = "full"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"

#: Recognised predicate type URIs. Adding an alias here is additive and does NOT change
#: `scpeVersion` (SPEC §4.4, §14) — which is exactly how an upstream in-toto registry URI
#: would be adopted later without breaking a single existing signature.
PREDICATE_TYPES = frozenset({
    "https://augbastos.github.io/scpe/generation/v1",
})

#: Signature suites this verifier will attempt. Checked BEFORE verification, per RFC 8725
#: §3.1 (SPEC §8.1). `ml-dsa-44` is registered in the spec and deliberately absent here:
#: encountering it must fail closed today and must not require a format change tomorrow.
SUITE_ALLOWLIST = frozenset({
    "sshsig-ssh-ed25519",
    "sshsig-ecdsa-sha2-nistp256",
})

SSHSIG_SUITES = frozenset({"sshsig-ssh-ed25519", "sshsig-ecdsa-sha2-nistp256"})

#: SSHSIG namespace per signer role. A signature made under one role's namespace does not
#: verify under another's, which is what stops a producer signature being replayed as an
#: independent observation (SPEC §8.3).
ROLE_NAMESPACES = {
    "producer": "scpe/1",
    "observer": "scpe-obs/1",
    "countersigner": "scpe-cs/1",
}

#: Digest algorithms this verifier can recompute. Anything else in a DigestSet is ignored;
#: an empty intersection is fail-closed (SPEC §4.5).
DIGEST_ALGS = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

RELATIONSHIPS = frozenset({"parentOf", "componentOf", "inputTo"})
ROLES = frozenset({"producer", "observer", "countersigner"})
OVERSIGHT = frozenset({"fully_autonomous", "prompt_guided", "human_validated"})

#: SPEC 13.3. Every count in a record is chosen by its author and several drive real work:
#: signatures spawn subprocesses, edges drive traversal fan-out. Unbounded means one small
#: file can spawn thousands of ssh-keygen processes, which is the cheapest DoS in the design.
MAX_SIDECAR_BYTES = 4 << 20
MAX_LINE_BYTES = 1 << 20
MAX_ARTIFACT_BYTES = 2 << 30
MAX_CHAIN_DEPTH = 32
MAX_BUNDLE_LINES = 64
MAX_SIGNATURES = 8
MAX_SIGNERS = 8
MAX_SUBJECTS = 64
MAX_EDGES = 64
MAX_JSON_DEPTH = 64
MAX_DECLARED_STRING = 1 << 10

#: Fixed provider -> host table (SPEC §13.4). A record never supplies a hostname, scheme,
#: port or path; the operator names a provider from this closed set and nothing else.
FORGE_HOSTS = {
    "github": "github.com",
    "gitlab": "gitlab.com",
    "codeberg": "codeberg.org",
}

#: A forge account is one safe path segment. No dots-dot, no slashes, no encoded anything.
SAFE_ACCOUNT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,38}")

MAX_KEYS_BYTES = 1 << 20

PEER_SIDECAR_SUFFIXES = (
    ".c2pa", ".sigstore.json", ".intoto.jsonl", ".sig", ".ots", ".asc", ".minisig",
)

#: Statuses, paired with their exit codes (SPEC §11.5). One table, so a status can never
#: exist without an exit code or drift from one.
EXIT_CODES = {
    "ok": 0,
    "ok-self-anchored": 10,
    "subject-unavailable": 11,
    "signature-invalid": 20,
    "digest-mismatch": 21,
    "assurance-overclaimed": 22,
    "unsupported-predicate": 30,
    "unsupported-version": 31,
    "unsupported-suite": 32,
    "unsupported-digest": 33,
    "malformed-input": 34,
    "malformed-predicate": 35,
    "no-provenance-found": 40,
    "tooling-error": 50,
}

PASSING = frozenset({"ok", "ok-self-anchored", "subject-unavailable"})

#: Required glosses. SPEC §10.5 makes these normative spec text rather than commentary, so
#: they are data here and a renderer cannot drop them.
ATTRIBUTION_GLOSS = {
    "self-asserted": "the producer signed a claim about itself; nothing independent corroborates it",
    "countersigned": "a second key signed; this does NOT establish a second party",
    "provider-attested": "a provider receipt binds bytes to an endpoint, not to weights",
    "tee-attested": "a TEE receipt attests an enclave, not a model",
}


class Refuse(Exception):
    """A fail-closed refusal carrying the status it maps to."""

    def __init__(self, status: str, detail: str = "") -> None:
        super().__init__(detail or status)
        self.status = status
        self.detail = detail


# ------------------------------------------------------------------ JSON hygiene


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    """`object_pairs_hook` that REFUSES a repeated key rather than resolving one.

    RFC 8259 leaves duplicate names implementation-defined; first-wins, last-wins and
    reject are all conforming, and real parsers ship all three. A statement with a repeated
    key is one byte string that two honest verifiers can read as two different documents
    and reach two different verdicts on — which contradicts the property the whole design
    exists to protect. Rejecting is the only resolution that does not require every
    implementation to have independently picked the same winner (SPEC §4.7).
    """
    seen: set[str] = set()
    for k, _ in pairs:
        if k in seen:
            raise ValueError(f"duplicate JSON key: {k!r}")
        seen.add(k)
    return dict(pairs)


def _loads(raw: bytes) -> dict:
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, ValueError) as exc:
        raise Refuse("malformed-input", str(exc)) from exc
    if not isinstance(obj, dict):
        raise Refuse("malformed-input", "top-level value is not an object")
    return obj


def _b64(value: str, what: str) -> bytes:
    """Strict base64. DSSE permits standard or URL-safe (RFC 4648); both are accepted, and
    nothing else is — `validate=True` refuses stray characters rather than silently
    dropping them, so two verifiers cannot disagree about what the payload bytes are."""
    if not isinstance(value, str):
        raise Refuse("malformed-input", f"{what} is not a string")
    data = value.encode("ascii", errors="replace")
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(data, validate=True)
        except (binascii.Error, ValueError):
            continue
    raise Refuse("malformed-input", f"{what} is not valid base64")


# ------------------------------------------------------------------ DSSE


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding, protocol.md v1.0.0:

        PAE(t, b) = "DSSEv1" SP LEN(t) SP t SP LEN(b) SP b

    SP is ASCII 0x20 and LEN() is ASCII decimal with no leading zeros. Length-prefixing is
    what removes the canonicalization problem: nothing is normalized and nothing is parsed
    before the signature is checked.
    """
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


@dataclass
class Envelope:
    payload_b64: str
    payload_type: str
    signatures: list[dict]
    body: bytes           # the verified bytes; never re-derived from payload_b64 again


def parse_envelope(raw: bytes) -> Envelope:
    """Parse only far enough to obtain payload, payloadType and signatures (SPEC §9 step 2)."""
    obj = _loads(raw)
    for key in ("payload", "payloadType", "signatures"):
        if key not in obj:
            raise Refuse("malformed-input", f"envelope missing {key!r}")
    if not isinstance(obj["signatures"], list) or not obj["signatures"]:
        raise Refuse("malformed-input", "signatures must be a non-empty array")
    if len(obj["signatures"]) > MAX_SIGNATURES:
        raise Refuse("malformed-input",
                     f"more than {MAX_SIGNATURES} signatures; each one costs a subprocess")
    if obj["payloadType"] != PAYLOAD_TYPE:
        raise Refuse("unsupported-payload" if obj["payloadType"] else "malformed-input",
                     f"payloadType is {obj['payloadType']!r}, expected {PAYLOAD_TYPE!r}")
    return Envelope(payload_b64=obj["payload"], payload_type=obj["payloadType"],
                    signatures=obj["signatures"], body=_b64(obj["payload"], "payload"))


# ------------------------------------------------------------------ signature backend


@dataclass
class SignatureCheck:
    """The outcome of one signature verification, recorded as an observation."""
    index: int
    declared: bool                  # does the payload name a signer in this role?
    verified: bool
    principal: str | None = None
    fingerprint: str | None = None
    role: str | None = None         # DISCOVERED from the namespace, never read from JSON
    error: str | None = None


def _run(cmd: list[str], stdin: bytes) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=stdin, capture_output=True, timeout=60)


def _ssh_keygen() -> str:
    exe = shutil.which("ssh-keygen")
    if exe is None:
        # A missing backend is not a failed check. Conflating the two would assert that a
        # verification ran and rejected the signature, which is false (SPEC §11.5).
        raise Refuse("tooling-error", "ssh-keygen not found on PATH")
    return exe


def _fingerprint(pubkey_line: str) -> str | None:
    """`SHA256:…` fingerprint of one public key line, computed locally."""
    parts = pubkey_line.split()
    if len(parts) < 2:
        return None
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        return None
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def sshsig_verify(signed: bytes, signature: bytes, allowed_signers: Path,
                  namespace: str) -> tuple[bool, str | None, str | None]:
    """Verify one SSHSIG signature. Returns (verified, principal, error).

    Two steps, and the split matters. `-Y find-principals` asks the policy file which
    principals hold the key that made this signature; `-Y verify` then checks the signature
    against that principal under the required namespace. Because the principal is READ OUT
    of the operator's own policy file rather than taken from the statement, no
    attacker-controlled string is ever interpolated into a policy line.

    Verified against OpenSSH 10.3p1, by execution, because all three of these are load
    bearing and none is documented in a way worth trusting second-hand:

      * `-Y find-principals` rejects `-O namespace=…` outright ("Invalid option"). The
        namespace gate lives on `verify`, not on the search.
      * `-Y verify -n NS` refuses a signature made under a different namespace
        ("namespace does not match", exit 255). This is what makes role separation real
        rather than conventional.
      * A `namespaces="…"` restriction in the allowed_signers line is enforced by OpenSSH
        itself ("key is not permitted for use in signature namespace …"). An operator can
        therefore bind a key to one SCPE role by hand, in a file they own, offline.
    """
    exe = _ssh_keygen()
    with tempfile.TemporaryDirectory(prefix="scpe-") as tmp:
        sig_path = Path(tmp) / "sig"
        sig_path.write_bytes(signature)

        found = _run([exe, "-Y", "find-principals", "-s", str(sig_path),
                      "-f", str(allowed_signers)], signed)
        principals = [ln.strip() for ln in found.stdout.decode("utf-8", "replace").splitlines()
                      if ln.strip()]
        if not principals:
            err = found.stderr.decode("utf-8", "replace").strip()
            return False, None, err or "no principal in the policy holds this key"

        # `find-principals` answers "who holds this key"; it does NOT enforce the namespace.
        # `verify` does both, so every candidate is re-checked under the role's namespace
        # and a principal that is not permitted for it simply does not verify.
        last_error = None
        for principal in principals:
            checked = _run([exe, "-Y", "verify", "-s", str(sig_path),
                            "-f", str(allowed_signers), "-I", principal,
                            "-n", namespace], signed)
            if checked.returncode == 0:
                return True, principal, None
            last_error = checked.stderr.decode("utf-8", "replace").strip()
        return False, principals[0], last_error or "signature did not verify"


def _synthetic_policy(pubkeys: list[str], namespace: str, out: Path) -> Path:
    """Build an allowed_signers file for keys that arrived by flag or inside the input.

    The principals are synthetic (`k0`, `k1`, …) and never derive from statement content.
    That is deliberate: an earlier implementation interpolated a caller-supplied subject
    into a policy line, which is an injection seam. Nothing here is attacker-controlled
    except the key blob itself, which OpenSSH parses.
    """
    every = ",".join(ROLE_NAMESPACES.values())
    lines = []
    for i, key in enumerate(pubkeys):
        key = key.strip()
        if not key or key.startswith("#"):
            continue
        if "\n" in key or "\r" in key:
            raise Refuse("malformed-input", "public key line contains a newline")
        lines.append(f'k{i} namespaces="{every}" {key}\n')
    if not lines:
        raise Refuse("malformed-input", "no usable public keys supplied")
    out.write_text("".join(lines), encoding="utf-8")
    return out


# ------------------------------------------------------------ network (SPEC §13.4)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every 3xx. A redirect is a second fetch to a host the operator never allowed,
    and following one is the SSRF escape §13.4 exists to close. A redirect is a fetch
    failure, never a hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code,
            f"redirect to {newurl!r} refused (SSRF-safe fetch: no cross-host redirects)",
            headers, fp)


def fetch_forge_keys(host: str, account: str) -> bytes:
    """Fetch `https://<host>/<account>.keys` under every rule in SPEC §13.4.

    `host` comes from the fixed table below and never from a record; `account` is
    charset-checked and re-quoted as a single path segment. TLS certificate and hostname
    validation are on explicitly, redirects are refused outright, and the final URL is
    re-checked — so the verifier only ever talks to the one host the operator allowed.

    This is ported from the retired implementation rather than rewritten. The old format
    carried no hostname, URL, scheme, port or path in its manifest at all; in-toto's
    ResourceDescriptor hands those back to the attacker, so the invariant has to be
    reasserted as rules here instead of being a property of the data model.
    """
    if not SAFE_ACCOUNT_RE.fullmatch(account):
        raise Refuse("malformed-input", f"unsafe forge account name: {account!r}")
    url = f"https://{host}/{urllib.parse.quote(account, safe='')}.keys"

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": "scpe-verify"})
    try:
        with opener.open(req, timeout=10) as resp:
            final = urllib.parse.urlsplit(resp.geturl())
            if final.scheme != "https" or final.hostname != host:
                raise Refuse("tooling-error",
                             f"fetch reached an unexpected URL: {resp.geturl()!r}")
            return resp.read(MAX_KEYS_BYTES)
    except Refuse:
        raise
    except Exception as exc:                       # network failure is not a failed check
        raise Refuse("tooling-error", f"key fetch failed: {exc}") from exc


# ------------------------------------------------------------------ predicate


@dataclass
class Statement:
    subject: list[dict]
    predicate_type: str
    predicate: dict


@dataclass
class Observation:
    """A verified observer statement: a second party saying it saw these bytes alongside
    this producer statement, and saying nothing wider (SPEC §8.4)."""
    verified: bool
    observed_digest: str | None
    subject: list[dict] = field(default_factory=list)
    keys: set[str] = field(default_factory=set)
    principals: set[str] = field(default_factory=set)


#: Fields an observer statement may not carry. The observer did not witness generation, so
#: it must not be able to endorse anything about it — enforced by schema, not by etiquette.
OBSERVER_FORBIDDEN = ("provider", "model", "humanOversight", "producedAt")


def parse_statement(body: bytes) -> Statement:
    """Parse the ALREADY-VERIFIED bytes. Never call this on unverified input."""
    obj = _loads(body)
    if obj.get("_type") != STATEMENT_TYPE:
        raise Refuse("malformed-input", f"_type is {obj.get('_type')!r}")

    ptype = obj.get("predicateType")
    if ptype not in PREDICATE_TYPES:
        raise Refuse("unsupported-predicate", f"unrecognised predicateType: {ptype!r}")

    subject = obj.get("subject")
    if not isinstance(subject, list) or not subject:
        raise Refuse("malformed-input", "subject must be a non-empty array")
    if len(subject) > MAX_SUBJECTS:
        raise Refuse("malformed-input", f"more than {MAX_SUBJECTS} subjects")
    for element in subject:
        if not isinstance(element, dict) or not isinstance(element.get("digest"), dict):
            raise Refuse("malformed-input", "every subject element requires a digest object")

    predicate = obj.get("predicate")
    if not isinstance(predicate, dict):
        raise Refuse("malformed-predicate", "predicate must be an object")

    version = predicate.get("scpeVersion")
    if version != SPEC_VERSION:
        raise Refuse("unsupported-version",
                     f"scpeVersion {version!r}; this verifier implements {SPEC_VERSION!r}")
    return Statement(subject=subject, predicate_type=ptype, predicate=predicate)


def validate_predicate(predicate: dict) -> list[dict]:
    """Check the REQUIRED fields (SPEC §5.2) and return the normalised signer list.

    Unrecognised OPTIONAL fields are ignored rather than rejected — that is the forward
    compatibility half of the three-way extension rule (SPEC §9.7).
    """
    generation = predicate.get("generation")
    if not isinstance(generation, dict):
        raise Refuse("malformed-predicate", "generation is required and must be an object")
    if not isinstance(generation.get("digitalSourceType"), str):
        raise Refuse("malformed-predicate", "generation.digitalSourceType is required")

    oversight = generation.get("humanOversight")
    if oversight is not None and oversight not in OVERSIGHT:
        raise Refuse("malformed-predicate", f"humanOversight {oversight!r} is not a C2PA value")

    signers = predicate.get("signer")
    if not isinstance(signers, list) or not signers:
        raise Refuse("malformed-predicate", "signer must be a non-empty array")
    if len(signers) > MAX_SIGNERS:
        raise Refuse("malformed-predicate", f"more than {MAX_SIGNERS} signer entries")

    for entry in signers:
        if not isinstance(entry, dict):
            raise Refuse("malformed-predicate", "signer entries must be objects")
        for required in ("keyFingerprint", "alg", "role"):
            if not isinstance(entry.get(required), str) or not entry[required]:
                raise Refuse("malformed-predicate", f"signer[].{required} is required")
        if entry["role"] not in ROLES:
            raise Refuse("malformed-predicate", f"unknown signer role {entry['role']!r}")
        if entry["alg"] not in SUITE_ALLOWLIST:
            # Checked BEFORE any verification is attempted (SPEC §8.1).
            raise Refuse("unsupported-suite", f"suite {entry['alg']!r} is not on the allowlist")

    if len(predicate.get("derivedFrom") or []) > MAX_EDGES:
        raise Refuse("malformed-predicate", f"more than {MAX_EDGES} derivedFrom edges")
    for edge in predicate.get("derivedFrom", []) or []:
        if not isinstance(edge, dict):
            raise Refuse("malformed-predicate", "derivedFrom entries must be objects")
        if edge.get("relationship") not in RELATIONSHIPS:
            raise Refuse("malformed-predicate",
                         f"relationship {edge.get('relationship')!r} is not one of "
                         f"{sorted(RELATIONSHIPS)}")
        resource = edge.get("resource")
        if not isinstance(resource, dict) or not isinstance(resource.get("digest"), dict):
            raise Refuse("malformed-predicate", "every derivedFrom edge requires resource.digest")

    parents = [e for e in (predicate.get("derivedFrom") or [])
               if e.get("relationship") == "parentOf"]
    if len(parents) > 1:
        raise Refuse("malformed-predicate", "a statement may carry at most one parentOf edge")
    for parent in parents:
        # REQUIRED on parentOf only. A prior version is the one case where a governing
        # record is expected to exist, and the one an attacker most wants to substitute.
        # Requiring it on inputTo would make honest records unrepresentable, because an
        # input is often a file nobody ever signed (SPEC §6.2).
        pin = parent.get("statementDigest")
        if not isinstance(pin, dict) or not isinstance(pin.get("sha256"), str):
            raise Refuse("malformed-predicate",
                         "a parentOf edge requires statementDigest.sha256")

    roles = {s["role"] for s in signers}
    if "observer" in roles:
        if roles != {"observer"}:
            raise Refuse("malformed-predicate",
                         "an observer signature may not share an envelope with another role")
        observed = predicate.get("observed")
        if not isinstance(observed, dict) or not isinstance(
                (observed.get("statementDigest") or {}).get("sha256"), str):
            raise Refuse("malformed-predicate",
                         "an observer statement requires observed.statementDigest.sha256")
        for forbidden in OBSERVER_FORBIDDEN:
            if forbidden in generation:
                raise Refuse("malformed-predicate",
                             f"an observer statement may not carry generation.{forbidden}")
        for forbidden in ("derivedFrom", "commitments", "run"):
            if predicate.get(forbidden):
                raise Refuse("malformed-predicate",
                             f"an observer statement may not carry {forbidden}")

    return signers


# ------------------------------------------------------------------ digest binding


def digest_file(path: Path, algs: list[str]) -> dict[str, str]:
    hashers = {name: DIGEST_ALGS[name]() for name in algs}
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            size += len(chunk)
            if size > MAX_ARTIFACT_BYTES:
                raise Refuse("malformed-input", "artifact exceeds size cap")
            for hasher in hashers.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def bind_subject(subject: list[dict], artifact: Path | None) -> tuple[str, list[str]]:
    """Return (facet, proved_lines). SPEC §4.5 AND-matching and §10.2.

    in-toto matches DigestSets if ANY recognised algorithm matches. SCPE narrows that to
    ALL, because OR-matching is a downgrade vector: a set carrying sha256 and something
    weak matches on the weak one unless the verifier filters, and the in-toto spec pushes
    that duty onto consumers rather than performing it.
    """
    if artifact is None:
        return "unbound", []

    for element in subject:
        declared = {k: v for k, v in element["digest"].items() if isinstance(v, str)}
        shared = [a for a in declared if a in DIGEST_ALGS]
        if not shared:
            continue
        actual = digest_file(artifact, shared)
        if all(actual[a].lower() == declared[a].lower() for a in shared):
            return "bound", [
                f"subject digest matches the supplied bytes ({', '.join(sorted(shared))})"
            ]
        return "mismatch", []

    raise Refuse("unsupported-digest",
                 "no subject digest uses an algorithm this verifier can recompute")


# ------------------------------------------------------------------ discovery


def find_sidecar(artifact: Path, explicit: Path | None) -> Path | None:
    """SPEC §7.2, first hit wins."""
    if explicit is not None:
        return explicit if explicit.is_file() else None
    for candidate in (Path(str(artifact) + ".scpe.jsonl"), Path(str(artifact) + ".scpe")):
        if candidate.is_file():
            return candidate
    by_digest = artifact.parent / ".scpe"
    if by_digest.is_dir():
        try:
            digest = digest_file(artifact, ["sha256"])["sha256"]
        except Refuse:
            return None
        candidate = by_digest / f"{digest}.jsonl"
        if candidate.is_file():
            return candidate
    return None


def find_peers(artifact: Path) -> list[dict]:
    """Report neighbouring provenance files (SPEC §7.3). Reporting one MUST NOT influence
    any facet — a peer file is a finding, not evidence."""
    peers = []
    for suffix in PEER_SIDECAR_SUFFIXES:
        candidate = Path(str(artifact) + suffix)
        if candidate.is_file():
            peers.append({"path": candidate.name, "status": "present-unverified"})
    return peers


def read_bundle(path: Path) -> list[bytes]:
    """An in-toto bundle: JSON Lines, order-independent, unreadable lines ignored."""
    size = path.stat().st_size
    if size > MAX_SIDECAR_BYTES:                       # checked BEFORE reading (SPEC §4.7)
        raise Refuse("malformed-input", "sidecar exceeds size cap")
    with path.open("rb") as fh:
        raw = fh.read(MAX_SIDECAR_BYTES + 1)           # bounded read: a lying stat cannot win
    if len(raw) > MAX_SIDECAR_BYTES:
        raise Refuse("malformed-input", "sidecar exceeds size cap")
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    if not lines:
        raise Refuse("malformed-input", "sidecar is empty")
    if len(lines) > MAX_BUNDLE_LINES:
        raise Refuse("malformed-input", f"bundle exceeds {MAX_BUNDLE_LINES} lines")
    for line in lines:
        if len(line) > MAX_LINE_BYTES:
            raise Refuse("malformed-input", "bundle line exceeds size cap")
    return lines


# ------------------------------------------------------------------ result


@dataclass
class Result:
    status: str
    facets: dict = field(default_factory=dict)
    proved: list[str] = field(default_factory=list)
    declared: list[str] = field(default_factory=list)
    not_checked: list[str] = field(default_factory=list)
    undeclared_signatures: int = 0
    peers: list[dict] = field(default_factory=list)
    detail: str = ""

    @property
    def exit_code(self) -> int:
        return EXIT_CODES.get(self.status, 34)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "facets": self.facets,
            "proved": self.proved,
            "declared": self.declared,
            "not_checked": self.not_checked,
            "undeclared_signatures": self.undeclared_signatures,
            "peers": self.peers,
            "detail": self.detail,
            "exit": self.exit_code,
        }


def collect_declared(statement: Statement) -> list[str]:
    """Everything the signer SAID, and it appears nowhere else in the output.

    SPEC §11.3: a conforming renderer may not display a model name, provider or identity
    except by reading it out of this list. Keeping the claim in exactly one place, under a
    name that says what it is, is the anti-laundering mechanism.
    """
    out: list[str] = []
    generation = statement.predicate.get("generation", {})
    for key in ("digitalSourceType", "provider", "model", "humanOversight", "producedAt"):
        if key in generation:
            out.append(f"generation.{key} = {generation[key]}")

    for i, element in enumerate(statement.subject):
        if element.get("name"):
            out.append(f"subject[{i}].name = {element['name']}")
        if element.get("mediaType"):
            out.append(f"subject[{i}].mediaType = {element['mediaType']}")

    for entry in statement.predicate.get("signer", []):
        if entry.get("identity"):
            out.append(f"signer identity = {entry['identity']} (declared, never verified)")

    for edge in statement.predicate.get("derivedFrom", []) or []:
        name = (edge.get("resource") or {}).get("name", "<unnamed>")
        out.append(f"derivedFrom: {edge.get('relationship')} {name}")

    run = statement.predicate.get("run") or {}
    for key in ("id", "segment", "traceParent"):
        if key in run:
            out.append(f"run.{key} = {run[key]}")

    for item in statement.predicate.get("commitments", []) or []:
        if isinstance(item, dict) and item.get("name"):
            out.append(f"commitment: {item['name']} ({item.get('alg', 'unknown alg')})")
    return out


def build_not_checked(facets: dict, statement: Statement) -> list[str]:
    """REQUIRED and non-empty on any passing result (SPEC §11.4).

    There is always something a signature did not prove. A result that cannot name one is a
    broken implementation, so the final clause below is unconditional.
    """
    out: list[str] = []
    generation = statement.predicate.get("generation", {})
    attribution = facets.get("attribution")
    model = generation.get("model")

    # Every facet below its strongest value owes an entry (SPEC §11.4). The generation claim
    # in particular stays unverified at BOTH self-asserted and countersigned: a second key
    # corroborates that a record existed, never that what it says is true. An earlier version
    # dropped this line as soon as a countersignature appeared, which is precisely the
    # moment a reader is most likely to over-read the result.
    if attribution in ("self-asserted", "countersigned"):
        because = ("the claim is signed by the producer about itself"
                   if attribution == "self-asserted" else
                   "a countersignature attests that the record existed, not that it is true")
        out.append(
            f"that {model or 'the named model'} produced these bytes - {because}, "
            "and no provider or TEE attestation is present"
        )
    if attribution == "countersigned":
        out.append("that a second PARTY was involved - a second key signed, and no offline "
                   "verifier can tell two keys from two people")
    if facets.get("binding") == "unbound":
        out.append("that any file matches this record - no artifact bytes were supplied")
    if facets.get("time") == "unanchored":
        out.append("when this was signed - no verified time anchor is present")
    if facets.get("lineage") == "declared":
        out.append("that any derivation edge occurred - no parent statement was resolved")
    if statement.predicate.get("commitments"):
        out.append("what the committed values are - commitments were carried, not opened")

    out.append("that no other transformation occurred - SCPE cannot express that claim")
    return out


# ------------------------------------------------------------------ verification


def verify(artifact: Path | None, sidecar: Path | None = None, policy: Path | None = None,
           keys: Path | None = None, resolve_chain: bool = False, forge: str | None = None,
           allow_host: str | None = None) -> Result:
    """SPEC §9, steps 1-14."""
    peers = find_peers(artifact) if artifact is not None else []

    # 1. Locate.
    if artifact is not None and sidecar is None:
        sidecar = find_sidecar(artifact, None)
    if sidecar is None or not sidecar.is_file():
        return Result(status="no-provenance-found", peers=peers,
                      detail="no .scpe.jsonl sidecar found next to the artifact")

    chain_policy: Path | None = None
    try:
        lines = read_bundle(sidecar)
        # `bundled` keys ride in the sidecar itself, as lines a bundle may carry alongside
        # its envelopes. Only consulted when the operator supplied no anchor of their own.
        bundled = [ln.decode("utf-8", "replace") for ln in lines
                   if ln.lstrip()[:1] not in (b"{", b"")]
        anchor, policy_path, tmpdir = _resolve_anchor(policy, keys, forge, allow_host, bundled)
        lines = [ln for ln in lines if ln.lstrip()[:1] == b"{"]
        try:
            # 2-8. A bundle is order-independent, so classify before deciding anything:
            # exactly one producer statement governs, and observer statements are separate
            # envelopes about it (SPEC §8.4).
            producer_env: Envelope | None = None
            producer_stmt: Statement | None = None
            producer_signers: list[dict] = []
            observer_lines: list[tuple[Envelope, Statement, list[dict]]] = []

            producer_checks: list[SignatureCheck] = []
            observer_bits: list[tuple[Envelope, Statement, list[dict],
                                      list[SignatureCheck]]] = []

            for raw in lines:
                envelope = parse_envelope(raw)

                # VERIFY FIRST. The role is discovered from the namespace the signature
                # actually verified under, never read from the payload, so the payload is
                # not parsed until a trusted key has vouched for those exact bytes.
                line_checks = _verify_blind(envelope, policy_path)
                verified = [c for c in line_checks if c.verified]
                if not verified:
                    if producer_env is None and len(lines) == 1:
                        raise Refuse("signature-invalid",
                                     line_checks[0].error if line_checks else "no signature verified")
                    continue        # an unverifiable sibling line contributes nothing

                statement = parse_statement(envelope.body)
                signers = validate_predicate(statement.predicate)
                _match_declared(line_checks, signers)

                roles = {c.role for c in verified}
                if roles == {"observer"}:
                    observer_bits.append((envelope, statement, signers, line_checks))
                elif producer_env is None:
                    producer_env, producer_stmt = envelope, statement
                    producer_signers, producer_checks = signers, line_checks
                else:
                    raise Refuse("malformed-input",
                                 "bundle carries more than one producer statement")

            if producer_env is None or producer_stmt is None:
                raise Refuse("signature-invalid",
                             "no producer statement in the bundle verified against the anchor")

            checks = producer_checks
            observations = [_observation_from(stmt, chk)
                            for _env, stmt, _sgn, chk in observer_bits]
            chain_policy = None
            if resolve_chain:
                # Facets are computed after the anchor tempdir is torn down, so a synthetic
                # policy would vanish before the chain pass. Keep a durable copy.
                chain_policy = Path(tempfile.mkdtemp(prefix="scpe-chain-")) / "allowed_signers"
                chain_policy.write_bytes(policy_path.read_bytes())
        finally:
            if tmpdir is not None:
                tmpdir.cleanup()

        statement = producer_stmt
        declared_checks = [c for c in checks if c.declared]
        undeclared = sum(1 for c in checks if not c.declared)

        if not declared_checks:
            return Result(status="signature-invalid", peers=peers,
                          detail="no signature was made by a key declared in signer[]")

        failed = [c for c in declared_checks if not c.verified]
        if failed:
            # Every declared signature must verify. An at-least-one rule would let a
            # statement carrying one good and one bad signature pass by default (SPEC §8.4).
            reason = failed[0].error or "signature did not verify"
            return Result(status="signature-invalid", peers=peers,
                          detail=f"declared signature {failed[0].index} failed: {reason}",
                          undeclared_signatures=undeclared)

        # 9. Bind the subject.
        binding, binding_proof = bind_subject(statement.subject, artifact)
        if binding == "mismatch":
            return Result(status="digest-mismatch", peers=peers,
                          undeclared_signatures=undeclared,
                          detail="supplied bytes do not match the signed subject digest")

        # 12. Compute facets — from observations made above, and nothing else.
        producer_keys = {s["keyFingerprint"] for s in producer_signers}
        # Principals come from the operator's own policy file via find-principals, not from
        # the record - so this is an observation, not a claim (SPEC 10.5).
        producer_principals = {c.principal for c in declared_checks if c.principal}
        facets = {
            "binding": binding,
            "signature": "valid",
            "anchor": anchor,
            "attribution": _attribution(producer_env.body, statement.subject,
                                        producer_keys, producer_principals,
                                        observations, anchor),
            "time": _time_facet(statement),
            "lineage": _lineage(statement, resolve_chain, anchor,
                                artifact.parent if artifact else None,
                                chain_policy),
        }

        # 13. Recompute any asserted assurance.
        asserted = statement.predicate.get("assurance")
        if isinstance(asserted, dict):
            differing = [k for k, v in asserted.items() if facets.get(k) != v]
            if differing:
                return Result(status="assurance-overclaimed", facets=facets, peers=peers,
                              undeclared_signatures=undeclared,
                              detail="producer asserted "
                                     + ", ".join(f"{k}={asserted[k]!r}" for k in differing)
                                     + "; the verifier computed otherwise")

        proved = binding_proof + [
            f"signature over the predicate by {c.fingerprint or 'a declared key'} "
            f"(principal {c.principal}, role-scoped namespace)"
            for c in declared_checks
        ]
        if anchor == "policy":
            proved.append("the signing key is listed in the operator's allowed_signers file")

        status = "ok"
        if binding == "unbound":
            status = "subject-unavailable"
        elif anchor == "bundled":
            # A pass anchored on keys carried inside the input is not identity evidence:
            # the input is asserting who signed it. It gets its own status and exit code so
            # a CI gate testing `$? == 0` cannot mistake it for a forge-backed pass.
            status = "ok-self-anchored"

        return Result(status=status, facets=facets, proved=proved,
                      declared=collect_declared(statement),
                      not_checked=build_not_checked(facets, statement),
                      undeclared_signatures=undeclared, peers=peers)

    except Refuse as exc:
        return Result(status=exc.status, peers=peers, detail=exc.detail)


def _resolve_anchor(policy: Path | None, keys: Path | None, forge: str | None = None,
                    allow_host: str | None = None, bundled_keys: list[str] | None = None
                    ) -> tuple[str, Path, tempfile.TemporaryDirectory | None]:
    """Decide where trust came from, and report it. This is the generalisation of the old
    `key_source` and the reason the project exists (SPEC §10.4)."""
    if policy is not None:
        if not policy.is_file():
            raise Refuse("malformed-input", f"policy file not found: {policy}")
        return "policy", policy, None
    if keys is not None:
        if not keys.is_file():
            raise Refuse("malformed-input", f"keys file not found: {keys}")
        tmp = tempfile.TemporaryDirectory(prefix="scpe-anchor-")
        pubkeys = keys.read_text(encoding="utf-8", errors="replace").splitlines()
        built = _synthetic_policy(pubkeys, ROLE_NAMESPACES["producer"],
                                  Path(tmp.name) / "allowed_signers")
        return "flag", built, tmp

    if forge is not None:
        # Double opt-in (SPEC §12.3, §13.4): naming the account is not consent to reach the
        # network. The operator must also name the host, and it is printed before contact.
        provider, _, account = forge.partition(":")
        host = FORGE_HOSTS.get(provider)
        if host is None:
            raise Refuse("malformed-input",
                         f"unknown forge provider {provider!r}; known: "
                         f"{', '.join(sorted(FORGE_HOSTS))}")
        if allow_host != host:
            raise Refuse("malformed-input",
                         f"--forge {provider} would contact {host}; pass --allow-host {host} "
                         f"to permit it")
        print(f"scpe: contacting https://{host}/ to fetch keys for {account!r}",
              file=sys.stderr)
        tmp = tempfile.TemporaryDirectory(prefix="scpe-anchor-")
        pubkeys = fetch_forge_keys(host, account).decode("utf-8", "replace").splitlines()
        built = _synthetic_policy(pubkeys, ROLE_NAMESPACES["producer"],
                                  Path(tmp.name) / "allowed_signers")
        return "forge", built, tmp

    if bundled_keys:
        # Keys carried INSIDE the input being verified. Legitimate for offline conformance
        # testing and worthless as identity evidence: the input asserts who signed it. The
        # ceiling on this anchor is a protocol invariant (SPEC §10.4, §10.5).
        tmp = tempfile.TemporaryDirectory(prefix="scpe-anchor-")
        built = _synthetic_policy(bundled_keys, ROLE_NAMESPACES["producer"],
                                  Path(tmp.name) / "allowed_signers")
        return "bundled", built, tmp

    raise Refuse("malformed-input",
                 "no trust anchor: pass --policy, --keys, or --forge with --allow-host")


def _verify_blind(envelope: Envelope, policy_path: Path) -> list[SignatureCheck]:
    """Verify every signature in one envelope BEFORE its payload has been parsed.

    This exists to close a hole rather than for convenience. The obvious implementation reads
    `signer[].role` out of the payload to choose the SSHSIG namespace and
    `signer[].keyFingerprint` to know which signatures are declared. Both live *inside* the
    payload — so the obvious implementation parses attacker-controlled JSON before checking
    any signature, and lets the record choose which namespace the verifier uses. The
    predicate stops being data and becomes a small program the verifier runs.

    So the role is not read; it is DISCOVERED. Each signature is tried under every registered
    namespace, and the namespace it verifies under *is* its role — established by
    cryptography, not by assertion. A record claiming `role: observer` while carrying a
    signature made under the producer namespace does not verify as an observation, and the
    payload is never parsed until a key the operator trusts has vouched for those exact bytes.

    `envelope.body` is the buffer decoded once at parse time and never re-derived, per DSSE's
    rule that the SERIALIZED_BODY verified is the one handed to the application (SPEC §4.2).

    Cost is bounded at three `ssh-keygen` invocations per signature, and `MAX_SIGNATURES`
    caps how many signatures may be offered (SPEC §13.3).
    """
    checks: list[SignatureCheck] = []
    signed = pae(envelope.payload_type, envelope.body)

    for i, sig_entry in enumerate(envelope.signatures):
        if not isinstance(sig_entry, dict) or "sig" not in sig_entry:
            raise Refuse("malformed-input", f"signatures[{i}] has no sig")
        raw_sig = _b64(sig_entry["sig"], f"signatures[{i}].sig")

        outcome = SignatureCheck(index=i, declared=False, verified=False,
                                 error="no registered namespace verified this signature")
        for role, namespace in ROLE_NAMESPACES.items():
            ok, principal, err = sshsig_verify(signed, raw_sig, policy_path, namespace)
            if ok:
                outcome = SignatureCheck(index=i, declared=False, verified=True,
                                         principal=principal, role=role)
                break
            if err and "namespace does not match" not in err:
                # Keep the substantive reason (bad signature, key not in policy) rather than
                # the noise from namespaces this signature was never made under.
                outcome.error = err
        checks.append(outcome)
    return checks


def _match_declared(checks: list[SignatureCheck], signers: list[dict]) -> None:
    """Bind each verified signature to the `signer[]` entry that claims it (SPEC §8.2).

    Runs only on already-verified bytes. A signature counts as *declared* when the payload
    names a signer whose role matches the namespace the signature actually verified under —
    so a payload cannot claim credit for a signature made in a different capacity.
    """
    by_role: dict[str, list[dict]] = {}
    for entry in signers:
        by_role.setdefault(entry["role"], []).append(entry)

    for check in checks:
        if not check.verified or check.role is None:
            continue
        candidates = by_role.get(check.role, [])
        if not candidates:
            continue          # verified, but the payload claims no signer in that role
        check.declared = True
        check.fingerprint = candidates[0]["keyFingerprint"]


def _observation_from(statement: Statement, checks: list[SignatureCheck]) -> Observation:
    """Build an observation from an already-verified observer line (SPEC §8.4)."""
    verified = [c for c in checks if c.declared and c.verified]
    observed = ((statement.predicate.get("observed") or {}).get("statementDigest") or {})
    return Observation(
        verified=bool(verified),
        observed_digest=observed.get("sha256"),
        subject=statement.subject,
        keys={c.fingerprint for c in verified if c.fingerprint},
        principals={c.principal for c in verified if c.principal},
    )




def _same_subject(a: list[dict], b: list[dict]) -> bool:
    """Two subject arrays name the same bytes. Compared by digest only — `name` and
    `mediaType` are declared and must never enter a decision (SPEC §4.3)."""
    def digests(subject: list[dict]) -> set[tuple[str, str]]:
        return {(alg, value.lower())
                for element in subject
                for alg, value in (element.get("digest") or {}).items()
                if isinstance(value, str)}
    shared = digests(a) & digests(b)
    return bool(shared)


def _attribution(producer_payload: bytes, producer_subject: list[dict],
                 producer_keys: set[str], producer_principals: set[str],
                 observations: list[Observation], anchor: str) -> str:
    """SPEC §10.5.

    `countersigned` is reachable only through a SEPARATE observer statement (SPEC §8.4),
    never through a co-signature, and only under an anchor the operator controls.

    The facet deliberately does NOT claim a second party. An earlier draft required only that
    the observer key differ from every producer key, and that was shown by execution to be
    forgeable in about a minute: one person generates a second key, lists both in their own
    allowed_signers under different principals, and countersigns their own record. No stricter
    offline check repairs it, because nothing in `allowed_signers` distinguishes a colleague's
    key from a second laptop key — so no verifier can tell two keys from two people. What this
    function establishes is the mechanical fact it can actually observe, and the facet name and
    its gloss say only that.
    """
    if anchor not in ("policy", "forge"):
        # A producer who supplied the key file supplied both ends of the "corroboration".
        # Cap the ladder at what the anchor can support (SPEC §10.5, anchor caps).
        return "self-asserted"

    want = hashlib.sha256(producer_payload).hexdigest()
    for obs in observations:
        if not obs.verified:
            continue
        if (obs.observed_digest or "").lower() != want:
            continue                       # observes some other statement
        if not _same_subject(obs.subject, producer_subject):
            continue                       # vouches for some other bytes
        if obs.keys & producer_keys:
            continue                       # same key: not a countersignature at all
        if obs.principals and not (obs.principals & producer_principals):
            return "countersigned"
    return "self-asserted"


def _time_facet(statement: Statement) -> str:
    """`externally-anchored` requires an anchor THIS verifier checked. The mere presence of
    an evidence entry must not raise it, and `producedAt` never does (SPEC §10.6).

    This verifier validates no time anchors, so the honest answer is always `unanchored`.
    """
    return "unanchored"


def _resolve_parent(edge: dict, artifact_dir: Path, policy_path: Path,
                    seen: set[str], depth: int) -> tuple[bool, int, str | None]:
    """Resolve one derivation edge offline. Returns (verified, depth_reached, problem).

    Offline-only and by design: a parent is consulted only if its record is already on disk
    beside a file the operator gave us. Nothing is fetched, and an unresolvable parent is
    not an error — it is the ordinary case (SPEC §6.4).
    """
    if depth > MAX_CHAIN_DEPTH:
        return False, depth, f"chain exceeds the depth bound of {MAX_CHAIN_DEPTH}"

    resource = edge.get("resource") or {}
    name = resource.get("name")
    if not isinstance(name, str) or "/" in name or "\\" in name or name.startswith("."):
        return False, depth, None            # not a resolvable local name; not an error

    parent_art = artifact_dir / name
    parent_side = find_sidecar(parent_art, None)
    if parent_side is None or not parent_side.is_file():
        return False, depth, None            # parent has no record here; ordinary

    try:
        parent_lines = read_bundle(parent_side)
    except Refuse:
        return False, depth, "parent record is unreadable"

    pin = ((edge.get("statementDigest") or {}).get("sha256") or "").lower()

    for raw in parent_lines:
        if raw.lstrip()[:1] != b"{":
            continue
        try:
            env = parse_envelope(raw)
        except Refuse:
            continue

        # Statement identity is the SHA-256 of the SIGNED PAYLOAD BYTES, never the envelope
        # or the line — an envelope is malleable around the same payload, so keying a cycle
        # check on it would be bypassable (SPEC §6.4).
        ident = hashlib.sha256(env.body).hexdigest()
        if ident in seen:
            return False, depth, "cycle detected in the derivation chain"

        if pin and ident != pin:
            continue                          # not the pinned parent; keep looking
        if not pin:
            continue                          # unpinned edges are never counted as verified

        checks = _verify_blind(env, policy_path)
        if not any(c.verified for c in checks):
            return False, depth, "the pinned parent statement did not verify"

        seen.add(ident)
        try:
            parent_stmt = parse_statement(env.body)
            validate_predicate(parent_stmt.predicate)
        except Refuse:
            return False, depth, "the pinned parent statement is malformed"

        deepest = depth
        for grand in (parent_stmt.predicate.get("derivedFrom") or []):
            ok, reached, problem = _resolve_parent(
                grand, artifact_dir, policy_path, seen, depth + 1)
            if problem:
                return False, reached, problem
            if ok:
                deepest = max(deepest, reached)
        return True, deepest, None

    if pin:
        return False, depth, "the pinned parent statement was not found in the parent record"
    return False, depth, None


def _lineage(statement: Statement, resolve_chain: bool, anchor: str,
             artifact_dir: Path | None = None,
             policy_path: Path | None = None) -> str:
    """SPEC §10.7. There is deliberately no `complete` value — see §6.3."""
    edges = statement.predicate.get("derivedFrom") or []
    if not edges:
        return "none"
    if not resolve_chain or artifact_dir is None or policy_path is None:
        return "declared"
    if anchor not in ("policy", "forge"):
        # A producer who supplied the keys can sign every parent in the chain, so a
        # self-anchored chain corroborates nothing (SPEC §10.5, anchor caps).
        return "declared"

    seen: set[str] = set()
    depth = 0
    verified_any = False
    for edge in edges:
        ok, reached, problem = _resolve_parent(edge, artifact_dir, policy_path, seen, 1)
        if problem:
            return "broken"
        if ok:
            verified_any = True
            depth = max(depth, reached)
    return f"verified-depth-{depth}" if verified_any else "declared"


# ------------------------------------------------------------------ rendering


def render(result: Result) -> str:
    lines: list[str] = []
    mark = "OK" if result.status in PASSING else "NO"
    lines.append(f"[{mark}] {result.status}")
    if result.detail:
        lines.append(f"     {result.detail}")

    if result.facets:
        lines.append("")
        lines.append("  What this result is:")
        for name, value in result.facets.items():
            gloss = ATTRIBUTION_GLOSS.get(value, "") if name == "attribution" else ""
            suffix = f"  - {gloss}" if gloss else ""
            lines.append(f"    {name:<12} {value}{suffix}")

    if result.proved:
        lines.append("")
        lines.append("  Proved (checks this verifier performed):")
        lines.extend(f"    + {item}" for item in result.proved)

    if result.declared:
        lines.append("")
        lines.append("  Declared by the signer (NOT verified):")
        lines.extend(f"    ~ {item}" for item in result.declared)

    if result.not_checked:
        lines.append("")
        lines.append("  Not checked:")
        lines.extend(f"    ? {item}" for item in result.not_checked)

    if result.undeclared_signatures:
        lines.append("")
        lines.append(f"  {result.undeclared_signatures} signature(s) present whose key is not "
                     "declared in signer[]; counted, not verified.")

    if result.peers:
        lines.append("")
        lines.append("  Other provenance files found next to this artifact:")
        lines.extend(f"    - {p['path']} ({p['status']})" for p in result.peers)

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SCPE scpe/1 reference verifier (offline; no network I/O)")
    parser.add_argument("artifact", type=Path, nargs="?",
                        help="the file whose provenance is being checked")
    parser.add_argument("--sidecar", type=Path, default=None,
                        help="explicit path to the .scpe.jsonl record")
    parser.add_argument("--policy", type=Path, default=None,
                        help="an OpenSSH allowed_signers file (anchor: policy)")
    parser.add_argument("--keys", type=Path, default=None,
                        help="a public key file (anchor: flag)")
    parser.add_argument("--forge", default=None, metavar="PROVIDER:ACCOUNT",
                        help="fetch keys a code host publishes for an account "
                             "(anchor: forge). REQUIRES --allow-host.")
    parser.add_argument("--allow-host", default=None, metavar="HOST",
                        help="explicitly permit contacting this host; the second half of "
                             "the double opt-in required before any network access")
    parser.add_argument("--chain", action="store_true",
                        help="resolve derivation parents already present on disk")
    parser.add_argument("--profile", action="store_true",
                        help="print the conformance profile this build implements and exit")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.profile:
        print(PROFILE)
        return 0

    if args.artifact is None and args.sidecar is None:
        parser.error("give an artifact, a --sidecar, or both")

    result = verify(artifact=args.artifact, sidecar=args.sidecar, policy=args.policy,
                    keys=args.keys, resolve_chain=args.chain, forge=args.forge,
                    allow_host=args.allow_host)

    if args.json:
        print(json.dumps(result.to_dict()))
    else:
        print(render(result))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
