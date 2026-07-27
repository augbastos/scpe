#!/usr/bin/env python3
"""SCPE scpe/0.1 reference verifier — one file, stdlib only.

This is the auditable heart of SCPE: read it top to bottom in ten minutes and you
know exactly what a "verified" seal means. It implements SPEC.md §8 verbatim and
nothing else. No imports beyond the standard library; the only external binary is
`ssh-keygen` (OpenSSH >= 8.2).

Identity is a `(provider, subject)` pair (SPEC §8). `provider` is one value from a
**fixed** registry baked into this file — `github`, `gitlab`, `codeberg`, `local` —
and it alone selects the host contacted for keys. The manifest never carries a
hostname, URL, port, scheme, or path, so it cannot steer the fetch at an arbitrary
target (the SSRF invariant, SPEC §8 / THREAT_MODEL §5).

Usage:
    verify_envelope.py <path> [--keys FILE] [--diff FILE] [--artifact FILE] [--json]

<path> is one of:
    a directory containing manifest.json + manifest.sig (+ diff.patch, keys)
    an envelope zip containing exactly those members
    a file holding an SCPE-ATTESTATION-v1 block (e.g. a saved PR body)

--keys FILE  use FILE as the body of <provider-host>/<subject>.keys instead of
             fetching (offline verification; required by the test vectors, and the
             only key source for the `local` provider).
--diff FILE  verify integrity against this diff (attestation form, where the diff
             is not enclosed and normally comes from the pull request).
--artifact FILE  verify an `artifact` subject against these bytes (standalone form,
             where the artifact is not enclosed).
--json       machine-readable output.

Exit code 0 iff the result is `verified`.

The signed manifest is an EVIDENCE CONTAINER (SPEC §4): a `subject` block (what is
being attested, dispatched on `subject.type`) plus a `contributor` identity, an
`ai_disclosure`, and an `attestations[]` list of typed, signed claims. Two structural
generalizations over a code-only envelope, both entirely inside the signed bytes:

  * `subject.type` dispatch (SPEC §6). `code-change` (target + diff integrity) and
    `artifact` (SHA-256 of the enclosed artifact bytes vs subject.digest.sha256, for
    the standalone envelope) are implemented in scpe/0.1. Any other type is unknown
    and fails CLOSED to `unsupported-subject` — never `verified`, never a silent pass.
  * `attestations[]` (SPEC §5). Each entry has a `type`; `agent-trace` is verified
    for its format (present-<format>), `timestamp`/`countersignature` are reserved,
    and any unknown type is surfaced as `present-unverified` — never an error. The
    result reports a per-attestation `{type, status}` summary.

Statuses (SPEC §8): unattested · unsupported-version · unsupported-provider ·
unsupported-subject · identity-unverifiable · signature-invalid · tampered · verified

Alongside the status every result discloses `key_source` — which of the three §8 step 4
anchors supplied the keys the verdict rests on: `flag` (the operator's --keys), `bundled`
(a `keys` file carried inside the input) or `forge` (fetched from the provider's fixed
host). All three can end in `verified` and they are not the same claim: a `bundled` key
set is chosen by whoever SUBMITTED the package, so `verified` there means "these bytes
match a key that travelled with them", not "the named forge account signed this". The
field changes no status — it only stops three different trust stories from looking alike.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

SPEC_MAJOR = "scpe/0"          # known MAJOR; scpe/0.x verifies, anything else does not
NAMESPACE = "scpe/0.1"         # SSHSIG namespace (SPEC §7)

# The IMPLEMENTED subject types in scpe/0.1 (SPEC §6): `code-change` (diff integrity)
# and `artifact` (digest of the enclosed bytes, standalone). Every other type is
# unknown; the integrity step (§8 step 7) dispatches on subject.type and fails CLOSED
# (`unsupported-subject`) for anything not listed here — it never guesses an integrity
# check, so it can never reach `verified` by accident.
IMPLEMENTED_SUBJECT_TYPES = ("code-change", "artifact")

# agent-trace payload formats (SPEC §5, `agent-trace` attestation type). An unknown
# format is surfaced as present-unverified, never an error.
REGISTERED_TRACE_FORMATS = ("agent-trace/1", "git-ai/notes", "generic/1")

MAX_MANIFEST_BYTES = 1 << 20   # 1 MiB defensive cap (THREAT_MODEL §3)
MAX_MEMBER_BYTES = 64 << 20    # 64 MiB cap on sig/diff/artifact members (decompression-bomb defense)
MAX_KEYS_BYTES = 1 << 20       # 1 MiB defensive cap on a fetched .keys body

# The fixed provider registry (SPEC §8 / §11.1). This table — and nothing in the
# manifest — decides which host is contacted for keys. `local` performs no network
# fetch: the verifier's owner supplies the keys file out of band (--keys). Providers
# that are format-reserved-but-unimplemented (`oidc`, `x509`, `ldap`; SPEC §11.1) are
# deliberately ABSENT here, so they resolve to `unsupported-provider` just like any
# unknown provider — never an error, never a silent pass.
PROVIDER_HOSTS: dict[str, str | None] = {
    "github": "github.com",
    "gitlab": "gitlab.com",
    "codeberg": "codeberg.org",
    "local": None,
}

# Safe-subject rule (SPEC §8): one predictable path segment, no traversal.
SAFE_SUBJECT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

ATTESTATION_RE = re.compile(
    r"<!--\s*SCPE-ATTESTATION-v1\s*\n(.*?)\n\s*-->", re.DOTALL)


class Result:
    def __init__(self, status: str, detail: str = "",
                 attestations: list[dict] | None = None,
                 profile: str | None = None,
                 key_source: str | None = None):
        # `attestations` is a per-entry [{type, status}] summary (SPEC §5/§8 step 8);
        # an empty list means the manifest carried no attestations.
        # `profile` is the advisory domain-convention label (SPEC §13), surfaced verbatim
        # from the manifest. It NEVER influences status: it is displayed, not dispatched
        # (SPEC §13.2). None means the manifest stamped no profile (or was unparsable).
        # `key_source` is the §8 step 4 anchor that supplied the keys this verdict rests
        # on — "flag", "bundled" or "forge" (see step 4). None means no usable key set was
        # ever obtained, i.e. the verdict was reached at or before that step. Like
        # `profile` it is disclosure, not dispatch: it never changes the status.
        self.status, self.detail = status, detail
        self.attestations = attestations or []
        self.profile = profile
        self.key_source = key_source


# ---------------------------------------------------------------- locate (§8.1)

def _read_file_capped(p: Path, cap: int) -> bytes:
    """Read a file, rejecting it if it exceeds `cap` bytes (directory-input DoS cap,
    THREAT_MODEL §3). Checked before the read so an oversized member never loads."""
    if p.stat().st_size > cap:
        raise ValueError(f"{p.name} exceeds size cap")
    return p.read_bytes()


def load_input(path: Path) -> tuple[bytes, bytes, bytes | None, bytes | None, bytes | None]:
    """Return (manifest_bytes, sig_bytes, diff_bytes|None, artifact_bytes|None, keys_bytes|None).

    Accepts a vector directory, an envelope zip, or a text file containing an
    SCPE-ATTESTATION-v1 block. The payload member depends on the subject: `diff.patch`
    for a `code-change` subject, `artifact.bin` for an `artifact` subject (SPEC §6).
    Raises FileNotFoundError with a message that maps to `unattested` when no SCPE
    material is present.
    """
    if path.is_dir():
        man, sig = path / "manifest.json", path / "manifest.sig"
        if not man.is_file() or not sig.is_file():
            raise FileNotFoundError("no manifest.json/manifest.sig in directory")
        diff = path / "diff.patch"
        artifact = path / "artifact.bin"
        keys = path / "keys"
        return (_read_file_capped(man, MAX_MANIFEST_BYTES),
                _read_file_capped(sig, MAX_MEMBER_BYTES),
                _read_file_capped(diff, MAX_MEMBER_BYTES) if diff.is_file() else None,
                _read_file_capped(artifact, MAX_MEMBER_BYTES) if artifact.is_file() else None,
                _read_file_capped(keys, MAX_KEYS_BYTES) if keys.is_file() else None)

    raw = path.read_bytes()
    if raw[:2] == b"PK":                                  # envelope zip
        return _from_zip(raw) + (None,)
    m = ATTESTATION_RE.search(raw.decode("utf-8", errors="replace"))
    if m:                                                  # attestation in a body
        blob = base64.b64decode(m.group(1).strip().encode("ascii"), validate=True)
        if blob[:2] != b"PK":
            raise ValueError("attestation payload is not a zip")
        return _from_zip(blob) + (None,)
    raise FileNotFoundError("no SCPE attestation found in input")


def _read_zip_member(zf: zipfile.ZipFile, name: str, cap: int) -> bytes:
    """Read a zip member, bounding the DECOMPRESSED size to `cap` bytes. The declared
    uncompressed size is checked first (rejects a bomb before allocating), then at most
    cap+1 bytes are read so a lying header cannot exceed the cap either (decompression-bomb
    defense, THREAT_MODEL §3)."""
    if zf.getinfo(name).file_size > cap:
        raise ValueError(f"{name} exceeds size cap")
    with zf.open(name) as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        raise ValueError(f"{name} exceeds size cap")
    return data


def _from_zip(blob: bytes) -> tuple[bytes, bytes, bytes | None, bytes | None]:
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        names = set(zf.namelist())
        # A standalone envelope carries exactly one payload: `diff.patch` for a
        # code-change subject or `artifact.bin` for an artifact subject (SPEC §4/§6).
        allowed = {"manifest.json", "manifest.sig", "diff.patch", "artifact.bin"}
        if not {"manifest.json", "manifest.sig"} <= names or not names <= allowed:
            raise ValueError(f"unexpected zip members: {sorted(names)}")
        return (_read_zip_member(zf, "manifest.json", MAX_MANIFEST_BYTES),
                _read_zip_member(zf, "manifest.sig", MAX_MEMBER_BYTES),
                _read_zip_member(zf, "diff.patch", MAX_MEMBER_BYTES) if "diff.patch" in names else None,
                _read_zip_member(zf, "artifact.bin", MAX_MEMBER_BYTES) if "artifact.bin" in names else None)


# ----------------------------------------------------------------- parse (§8.2)

def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    """`object_pairs_hook` that REFUSES a repeated key instead of resolving one (SPEC §4.1).

    RFC 8259 leaves duplicate names implementation-defined — last-wins, first-wins and
    reject are all conforming, and real JSON libraries ship all three. So a manifest with
    a repeated key is ONE byte string that two honest verifiers can read as two different
    documents and reach two different verdicts on. That contradicts the property the whole
    protocol is built to protect: the signature covers bytes, so identical bytes must yield
    an identical status everywhere. Rejecting is the only resolution that does not require
    this spec to pick a winner AND every implementation's parser to have picked the same
    one. `json` calls this hook once per object, so every nesting depth is covered by
    construction — a duplicated `subject` or `contributor` is caught as surely as a
    duplicated `spec_version`.
    """
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"duplicate JSON key {key!r}")
        seen.add(key)
    return dict(pairs)


def parse_manifest(manifest_bytes: bytes) -> dict:
    m = json.loads(manifest_bytes.decode("utf-8"),
                   object_pairs_hook=_no_duplicate_keys)
    if not isinstance(m, dict):
        raise ValueError("manifest is not a JSON object")
    return m


def version_supported(m: dict) -> bool:
    v = m.get("spec_version", "")
    return isinstance(v, str) and (v == SPEC_MAJOR or v.startswith(SPEC_MAJOR + "."))


# ------------------------------------------------------- resolve identity (§8.3)

def subject_ok(subject: str) -> bool:
    """Safe-subject rule (SPEC §8): full match of the charset AND no `..` substring.
    Bars `/`, whitespace, `@`, `:`, and path traversal, so the fetched URL is always
    exactly one predictable path segment under the fixed host."""
    return bool(SAFE_SUBJECT_RE.fullmatch(subject)) and ".." not in subject


# ------------------------------------------------------------ fetch keys (§8.4)

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every 3xx redirect. The fetch target is a single fixed host from the
    provider registry; following a redirect could cross to another host or downgrade
    the scheme, which is exactly the SSRF/host-injection escape SPEC §8 forbids. Any
    redirect is therefore treated as a fetch failure, not followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise urllib.error.HTTPError(
            req.full_url, code,
            f"redirect to {newurl!r} refused (SSRF-safe fetch: no cross-host redirects)",
            headers, fp)


def fetch_keys(host: str, subject: str) -> bytes:
    """Fetch `https://<host>/<subject>.keys` — HTTPS only, TLS validated, no redirects.

    `host` comes solely from the fixed provider registry; `subject` is already
    charset-validated (subject_ok) and is re-quoted as a single path segment for
    defense in depth. TLS certificate + hostname validation is on (an explicit
    default SSL context). Redirects are refused outright, and the final URL is
    re-checked to be the same https host — so the verifier only ever talks to the
    one fixed host, never a manifest-chosen one.
    """
    seg = urllib.parse.quote(subject, safe="")
    url = f"https://{host}/{seg}.keys"
    ctx = ssl.create_default_context()          # cert + hostname verification ON
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": "scpe-verify"})
    with opener.open(req, timeout=10) as resp:      # https only; redirects refused
        final = urllib.parse.urlsplit(resp.geturl())
        if final.scheme != "https" or final.hostname != host:
            raise OSError(f"fetch reached unexpected URL {resp.geturl()!r}")
        return resp.read(MAX_KEYS_BYTES)


# --------------------------------------------- allowed signers + SSHSIG (§8.5-6)

def key_fingerprint(key_line: str) -> str | None:
    """The SHA256 fingerprint OpenSSH reports for one authorized-keys line, or None."""
    with tempfile.TemporaryDirectory(prefix="scpe-fp-") as td:
        pub = Path(td) / "k.pub"
        pub.write_text(key_line.strip() + "\n", encoding="utf-8")
        proc = subprocess.run(["ssh-keygen", "-lf", str(pub)], capture_output=True)
    if proc.returncode != 0:
        return None
    parts = proc.stdout.decode("utf-8", "replace").split()
    return parts[1] if len(parts) > 1 else None


def verify_signature(manifest_bytes: bytes, sig_bytes: bytes,
                     subject: str, keys_bytes: bytes,
                     declared_fingerprint: str | None = None) -> bool:
    key_lines = [ln.strip() for ln in keys_bytes.decode("utf-8").splitlines()
                 if ln.strip()]
    if not key_lines:
        return False
    # `contributor.key_fingerprint` is a MUST field, and §14 says the manifest *binds* it —
    # but nothing read it, so a signed field could say anything without consequence. An
    # account publishing keys A and B could ship a manifest naming A, sign with B, and
    # verify: the audit record then names a key that did not sign it. Restricting the
    # allowed signers to the declared key makes the field load-bearing, and a pass then
    # means "the key this manifest names is published by this account AND produced this
    # signature" rather than "some key it publishes did".
    #
    # A declared fingerprint absent from the published set yields `signature-invalid`, not
    # a new status: the signature cannot be validated against the key the manifest names.
    # That is what the `wrong-identity` vector already expects, so none of the eighteen
    # normative expectations move.
    if declared_fingerprint:
        key_lines = [ln for ln in key_lines
                     if key_fingerprint(ln) == declared_fingerprint]
        if not key_lines:
            return False
    signers = "".join(
        f'{subject} namespaces="{NAMESPACE}" {ln}\n' for ln in key_lines)
    with tempfile.TemporaryDirectory(prefix="scpe-verify-") as td:
        tdp = Path(td)
        (tdp / "allowed_signers").write_text(signers, encoding="utf-8")
        (tdp / "manifest.sig").write_bytes(sig_bytes)
        proc = subprocess.run(
            ["ssh-keygen", "-Y", "verify",
             "-f", str(tdp / "allowed_signers"),
             "-I", subject, "-n", NAMESPACE,
             "-s", str(tdp / "manifest.sig")],
            input=manifest_bytes, capture_output=True)
    return proc.returncode == 0


# ------------------------------------------------------------- integrity (§8.7)

def normalize_diff(raw: bytes) -> bytes:
    """SPEC §6: CRLF/CR -> LF, exactly one trailing newline, at the BYTE level.
    Normalization operates on raw bytes and never decodes, so every conforming verifier
    agrees on the integrity anchor even for a diff that is not valid UTF-8 (line endings
    are ASCII, so byte-level and text-level normalization are identical for valid UTF-8)."""
    text = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return text.rstrip(b"\n") + b"\n"


def code_change_integrity_ok(subject: dict, diff_bytes: bytes) -> bool:
    """Integrity for a `code-change` subject (SPEC §6): the SHA-256 of the normalized
    diff MUST equal subject.change.diff_sha256. Byte-exact; whitespace is significant."""
    change = subject.get("change") if isinstance(subject.get("change"), dict) else {}
    want = change.get("diff_sha256", "")
    got = hashlib.sha256(normalize_diff(diff_bytes)).hexdigest()
    return bool(want) and got == want


def artifact_integrity_ok(subject: dict, artifact_bytes: bytes) -> bool:
    """Integrity for an `artifact` subject (SPEC §6.2): the SHA-256 of the RAW enclosed
    artifact bytes MUST equal subject.digest.sha256. No normalization — an artifact is
    opaque bytes (it may be binary), so it is hashed exactly as carried."""
    digest = subject.get("digest") if isinstance(subject.get("digest"), dict) else {}
    want = digest.get("sha256", "")
    got = hashlib.sha256(artifact_bytes).hexdigest()
    return bool(want) and got == want


# ---------------------------------------------------- attestation status (§8 step 8)

def _one_attestation_status(att: dict) -> str:
    """The signed status of a single attestation (SPEC §5). An `agent-trace` entry is
    resolved by its `format`; the reserved `timestamp`/`countersignature` types and any
    unknown type are surfaced as `present-unverified` — never an error, never a pass."""
    if not isinstance(att, dict):
        return "present-unverified"
    if att.get("type") == "agent-trace" and att.get("format") in REGISTERED_TRACE_FORMATS:
        return f"present-{att['format']}"
    return "present-unverified"


def attestations_summary(m: dict) -> list[dict]:
    """The per-attestation [{type, status}] summary (SPEC §8 step 8). An absent or empty
    `attestations` list yields []; a non-list is treated as no attestations."""
    atts = m.get("attestations")
    if not isinstance(atts, list):
        return []
    out: list[dict] = []
    for att in atts:
        atype = att.get("type") if isinstance(att, dict) else None
        out.append({"type": atype, "status": _one_attestation_status(att)})
    return out


# ------------------------------------------------------------------ verify (§8)

def verify(path: Path, keys_file: Path | None, diff_file: Path | None,
           artifact_file: Path | None = None) -> Result:
    # 1. locate
    try:
        manifest_bytes, sig_bytes, diff_bytes, artifact_bytes, keys_bytes = load_input(path)
    except FileNotFoundError as exc:
        return Result("unattested", str(exc))
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        return Result("unattested", f"unreadable input: {exc}")

    # 2. parse + version
    try:
        m = parse_manifest(manifest_bytes)
    except (ValueError, UnicodeDecodeError) as exc:
        return Result("signature-invalid", f"manifest unparsable: {exc}")

    # The advisory `profile` label (SPEC §13) is surfaced verbatim on EVERY post-parse
    # outcome but never dispatched: it changes no status. An absent or non-string value
    # is surfaced as None (unstamped); an unrecognized string is surfaced as-is (SPEC
    # §13.2 clause 3 — surfaced-but-ignored, never an error). `R` stamps it on each
    # Result so the single decision path below stays untouched.
    prof = m.get("profile")
    prof = prof if isinstance(prof, str) else None

    # The §8 step 4 anchor that ends up supplying keys, stamped on every Result from that
    # point on. It stays None until a non-empty key set is actually in hand, so no verdict
    # ever claims an anchor it did not use. `R` reads it at call time, which is why the
    # single decision path below needs no extra plumbing.
    key_source: str | None = None

    def R(status: str, detail: str = "", attestations: list[dict] | None = None) -> Result:
        return Result(status, detail, attestations, profile=prof, key_source=key_source)

    if not version_supported(m):
        return R("unsupported-version",
                 f"spec_version {m.get('spec_version')!r}")

    # 3. resolve the provider (§8 step 3). The provider is looked up in the FIXED
    #    registry; nothing else in the manifest influences the fetch host.
    contributor = m.get("contributor")
    identity = contributor.get("identity") if isinstance(contributor, dict) else None
    provider = identity.get("provider") if isinstance(identity, dict) else None
    subject = identity.get("subject") if isinstance(identity, dict) else None
    if not isinstance(provider, str) or provider not in PROVIDER_HOSTS:
        return R("unsupported-provider",
                 f"provider {provider!r} is not in the fixed registry")
    if not isinstance(subject, str) or not subject_ok(subject):
        return R("identity-unverifiable", "missing or malformed subject")
    host = PROVIDER_HOSTS[provider]     # None for the `local` provider

    # 4. keys — --keys flag > keys file shipped beside the manifest > network.
    #    `local` never fetches: its keys MUST be supplied out of band by the owner.
    #
    #    Which tier won is recorded as `key_source`, because the three are not the same
    #    claim and the verdict word cannot tell them apart. A `keys` file riding INSIDE
    #    the input was chosen by whoever submitted it, so a manifest naming a `github`
    #    identity can reach `verified` against a key github.com never published —
    #    self-anchored, yet spelled exactly like a forge-anchored pass. That path is not
    #    a bug and is not removed here: it is what lets the eighteen normative vectors
    #    verify offline, and what `local` exists for. Disclosing the anchor is the fix;
    #    refusing one would take the conformance suite, air-gapped review and every
    #    self-hosted deployment down with it.
    if keys_file is not None:
        source = "flag"                    # the verifier's owner named the key set by hand
        keys_bytes = keys_file.read_bytes()
    elif keys_bytes is not None:
        source = "bundled"                 # carried inside the input: submitter-controlled
    else:
        if host is None:
            return R("identity-unverifiable",
                     "local provider requires an owner-supplied keys file")
        try:
            keys_bytes = fetch_keys(host, subject)
        except OSError as exc:
            return R("identity-unverifiable", f"key fetch failed: {exc}")
        source = "forge"                   # live from the provider's fixed host
    if not keys_bytes.strip():
        return R("identity-unverifiable", "no published keys")
    # Past the empty check, and only here: an anchor that yielded nothing usable is not an
    # anchor this verdict rests on, so `no published keys` above reports no key_source.
    key_source = source

    # 5-6. allowed signers + SSHSIG, restricted to the key the manifest names.
    #      The declared fingerprint is inside the signed bytes, so an attacker cannot point
    #      it at a different key without invalidating the very signature it gates.
    declared_fp = contributor.get("key_fingerprint") if isinstance(contributor, dict) else None
    declared_fp = declared_fp if isinstance(declared_fp, str) and declared_fp.strip() else None
    if not verify_signature(manifest_bytes, sig_bytes, subject, keys_bytes,
                            declared_fingerprint=declared_fp):
        return R("signature-invalid",
                 "SSHSIG verification failed"
                 if declared_fp else
                 "SSHSIG verification failed (manifest declares no key_fingerprint)")

    # 7. subject integrity — dispatch on the SIGNED subject.type (SPEC §6). The
    #    signature (step 5-6) already proved the subject block is authentic, so we now
    #    check integrity for the *kind* of subject it declares. `code-change` (diff)
    #    and `artifact` (digest of the enclosed bytes, standalone) are implemented in
    #    scpe/0.1; any other type is unknown and fails CLOSED to `unsupported-subject` —
    #    never `verified`, never a silent pass.
    subject_block = m.get("subject")   # the §6 subject block (distinct from the identity username above)
    stype = subject_block.get("type") if isinstance(subject_block, dict) else None
    if stype == "code-change":
        if diff_file is not None:
            diff_bytes = diff_file.read_bytes()
        if diff_bytes is None:
            return R("tampered", "no diff available to check integrity against")
        if not code_change_integrity_ok(subject_block, diff_bytes):
            return R("tampered", "diff sha256 does not match subject.change.diff_sha256")
    elif stype == "artifact":
        # Artifact integrity is standalone-only: the bytes ride in the envelope as
        # `artifact.bin` (or --artifact). PR transport carries no artifact payload
        # (SPEC §6.2), so a missing payload cannot be checked -> tampered.
        if artifact_file is not None:
            artifact_bytes = artifact_file.read_bytes()
        if artifact_bytes is None:
            return R("tampered", "no artifact payload to check integrity against")
        if not artifact_integrity_ok(subject_block, artifact_bytes):
            return R("tampered", "artifact sha256 does not match subject.digest.sha256")
    else:
        return R("unsupported-subject",
                 f"subject type {stype!r} is not implemented in scpe/0.1")

    # 8. verified — with the per-attestation {type, status} summary (SPEC §5/§8 step 8).
    #    The advisory `profile` label (SPEC §13) rides along, surfaced but not dispatched.
    return R("verified", "", attestations_summary(m))


# -------------------------------------------------------------------------- cli

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SCPE scpe/0.1 reference verifier")
    ap.add_argument("path", type=Path)
    ap.add_argument("--keys", type=Path, default=None)
    ap.add_argument("--diff", type=Path, default=None)
    ap.add_argument("--artifact", type=Path, default=None,
                    help="artifact bytes to check an `artifact` subject against "
                         "(standalone; normally the enclosed artifact.bin)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    res = verify(args.path, args.keys, args.diff, args.artifact)
    if args.json:
        print(json.dumps({"status": res.status, "attestations": res.attestations,
                          "key_source": res.key_source, "profile": res.profile,
                          "detail": res.detail}))
    else:
        mark = "OK" if res.status == "verified" else "NO"
        line = f"[{mark}] {res.status}"
        if res.status == "verified":
            if res.attestations:
                summ = ", ".join(f"{a['type']}={a['status']}" for a in res.attestations)
                line += f" (attestations: {summ})"
            else:
                line += " (attestations: none)"
        # Surface the key anchor (SPEC §8 step 4) on every result that had one, so a
        # self-anchored `bundled` pass never reads on screen like a forge-backed one.
        if res.key_source:
            line += f" [keys: {res.key_source}]"
        # Surface the advisory profile label (SPEC §13.2): displayed, never dispatched.
        if res.profile:
            line += f" [profile: {res.profile}]"
        if res.detail:
            line += f" — {res.detail}"
        print(line)
    return 0 if res.status == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
