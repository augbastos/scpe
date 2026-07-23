"""Attestation — a signed AUDIT record, not a contribution. Where `contribute` ships
diffs for the owner to apply and credit, `attest` ships NO diff and credits nobody:
"repo X at commit Y was read by key Z on date D with backend B; verdict clean/N
findings." A clean attestation turns "I found nothing wrong" into a positive,
portable, independently-verifiable deliverable.

The format is deliberately NOT scpe's own `envelope.py`/`signing.py` scheme.
It is the industry-standard supply-chain attestation format — an in-toto Statement
wrapped in a DSSE (Dead Simple Signing Envelope) envelope, signed with Ed25519 — so
ANY standard tool (cosign, any DSSE library, in any language) can verify it with zero
knowledge of scpe. No bespoke canonicalization, no scpe-specific trust
root. This module is a REFERENCE implementation of that public format, not the format
itself; a third party should never need to import it.

WIRE FORMAT — for anyone implementing an independent verifier
================================================================

1. The Statement (in-toto Statement v1 — https://in-toto.io/Statement/v1):

   {
     "_type": "https://in-toto.io/Statement/v1",
     "subject": [{"name": "<repo URL or path>", "digest": {"gitCommit": "<40-hex sha>"}}],
     "predicateType": "https://scpe.dev/attestation/audit/v1",
     "predicate": {
       "tool": {"name": "scpe", "version": "<scpe __version__>"},
       "auditor": {"name": "<str>", "email": "<str>", "publicKey": "<64-hex Ed25519 raw pubkey>"},
       "backend": "<LLM backend label, e.g. 'mock' or 'openai-compat:gpt-4o'>",
       "createdAt": "<ISO 8601 UTC timestamp>",
       "verdict": "clean" | "findings",
       "findingsCount": <int>,
       "report": {"grade": <str|int|null>, "summary": "<str>",
                  "findings": [{"title": "<str>", "rationale": "<str>", "files": ["<str>", ...]}]},
       "checks": [{"tool": "<str>", "ran": <bool>, "passed": <bool|null>,
                   "summary": "<str>", "tail": "<str>"}, ...]   # OPTIONAL, see below
     }
   }

   `predicate.checks`, when present, is the SIGNED evidence from running recognized
   tools (the repo's own test suite, bandit, ruff/pyflakes — see checks.py) against
   the audited commit, inside the same sandboxed isolation `verify` uses. It is
   evidence alongside the LLM verdict above, not a replacement for it, and it is
   OMITTED entirely (not an empty list) when the caller skipped checks (e.g.
   `attest --no-checks`) — an omitted key means "we didn't look", an empty list
   would be indistinguishable from "we looked and there was nothing to run".
   `passed` is `null` whenever `ran` is `false`: a check that never executed has no
   pass/fail verdict, and this format never fabricates one. This still does NOT
   make the attestation a formal certification — see the module docstring above and
   `cli._ATTESTATION_DISCLAIMER`.

   The predicate ALSO carries an additive, GitHub-bound AUDITOR identity, mirroring the
   contributor identity an Envelope carries (see envelope.attach_ssh_identity). Five
   OPTIONAL predicate fields — `github_login`, `github_id`, `ssh_pubkey` ("<type>
   <base64>"), `ssh_sig` (an armored SSH signature), and `sig_method` ("ssh-github") —
   let a verifier prove WHO audited: `ssh_sig` covers the whole Statement minus itself
   (see `auditor_identity_digest`) and verifies against `github.com/<login>` keys. This
   is layered ON TOP of, and never replaces, the DSSE/Ed25519 signature above — the
   attestation still verifies with any standard DSSE tool that ignores these fields.

   The Statement is serialized as JSON with `separators=(",", ":")` and `sort_keys=True`
   (compact, deterministic — but canonicalization of the bytes does NOT matter for
   verification: the exact serialized bytes are what got signed and are carried
   unmodified inside the envelope's base64 `payload`, so a verifier never re-serializes).

2. The DSSE envelope (https://github.com/secure-systems-lab/dsse/blob/master/protocol.md):

   {
     "payloadType": "application/vnd.in-toto+json",
     "payload": "<base64-standard of the exact Statement JSON bytes from step 1>",
     "signatures": [{"keyid": "<sha256 hex of the raw 32-byte Ed25519 public key>",
                      "sig": "<base64-standard of the raw Ed25519 signature bytes>"}]
   }

3. What gets signed — the DSSE Pre-Authentication Encoding (PAE), verbatim per spec:

     PAE(payload_type, payload) =
       "DSSEv1" + " " + LEN(UTF8(payload_type)) + " " + UTF8(payload_type)
                + " " + LEN(payload) + " " + payload

   where LEN(x) is the decimal ASCII length of x in bytes, `payload_type` is the
   literal string "application/vnd.in-toto+json", and `payload` is the RAW Statement
   JSON bytes (NOT base64 — the base64 in the envelope is only a JSON-safe transport
   encoding of those same bytes). The signature is a raw Ed25519 signature of
   PAE(payload_type, payload) using the auditor's private key. This is exactly what
   `cosign verify-blob-attestation`, `sigstore`, and every conformant DSSE library
   compute — nothing here is scpe-specific.

4. Verification (independent of this module): base64-decode `payload`; recompute the
   PAE over (`payloadType`, decoded payload bytes); base64-decode each `sig`; Ed25519-
   verify it against PAE using the public key (either pinned out-of-band, e.g. from a
   known-good `publicKey`, or the one embedded in `predicate.auditor.publicKey` for a
   self-describing/keyless-style check). Any signature that verifies makes the envelope
   valid; verifying against a *specific* expected key additionally proves *who* signed.

This is an LLM-based read of the repo, using the named backend — NOT a formal security
certification and NOT a claim of exhaustiveness. It carries no diff and credits no one;
it is provenance for a claim ("this repo was looked at"), not proof of correctness."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from scpe import __version__
from scpe import identity as _identity
from scpe.envelope import sanitize_text
from scpe.signing import public_key_hex, sign_bytes, verify_bytes

PAYLOAD_TYPE = "application/vnd.in-toto+json"
PREDICATE_TYPE = "https://scpe.dev/attestation/audit/v1"

# An attestation is a small JSON document (a handful of findings, no diffs). Cap both
# the on-disk file and the decoded payload so `verify-attest` on an UNTRUSTED file
# can't be OOM'd/DoS'd the same way an untrusted envelope.zip is guarded in envelope.py.
_MAX_ATTESTATION_FILE = 2 * 1024 * 1024  # 2 MiB
_MAX_PAYLOAD_BYTES = 2 * 1024 * 1024  # 2 MiB


class AttestationFormatError(ValueError):
    pass


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding, verbatim per spec. This — not any JSON
    serialization — is the exact byte string that gets Ed25519-signed/verified."""
    payload_type_utf8 = payload_type.encode("utf-8")
    return (b"DSSEv1" + b" " + str(len(payload_type_utf8)).encode() + b" " + payload_type_utf8
            + b" " + str(len(payload)).encode() + b" " + payload)


def build_statement(repo_url: str, base_sha: str, *, auditor_name: str = "",
                    auditor_email: str = "", auditor_pubkey_hex: str = "",
                    backend_label: str, created_at_iso: str,
                    report_dict: dict, checks: list[dict] | None = None) -> dict:
    """Build an in-toto Statement v1 from an `analyze()` report. Pure — does not sign.

    `auditor_name`/`auditor_email` are OPTIONAL and expected to be DERIVED from the
    resolved GitHub identity, not free-typed: the caller passes the account's display
    name and its `identity.noreply_email(login, id)` so the "who audited" field is the
    same verifiable GitHub identity the SSH auditor layer proves, never a spoofable
    hand-typed string. `attach_ssh_auditor` then stamps the signed identity fields.

    `checks`, if given, is the list of structured tool-check results from
    `checks.run_checks()` — signed evidence alongside the LLM verdict (see the module
    docstring's WIRE FORMAT section). Left as `None` (the default) it is OMITTED from
    the predicate entirely, not stored as an empty list — that distinguishes "no
    checks were attempted" (e.g. `attest --no-checks`) from "checks ran and none were
    runnable", which is instead an explicit list of `ran: false` entries."""
    issues = report_dict.get("issues") or []
    findings = [
        {"title": str(i.get("title", "")), "rationale": str(i.get("rationale", "")),
         "files": [str(f) for f in (i.get("files") or [])]}
        for i in issues
    ]
    predicate = {
        "tool": {"name": "scpe", "version": __version__},
        "auditor": {"name": auditor_name, "email": auditor_email,
                    "publicKey": auditor_pubkey_hex},
        "backend": backend_label,
        "createdAt": created_at_iso,
        "verdict": "clean" if not findings else "findings",
        "findingsCount": len(findings),
        "report": {"grade": report_dict.get("grade"), "summary": report_dict.get("summary"),
                   "findings": findings},
    }
    if checks is not None:
        predicate["checks"] = checks
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": repo_url, "digest": {"gitCommit": base_sha}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def auditor_identity_digest(statement: dict) -> bytes:
    """The canonical bytes the auditor's GitHub SSH signature covers: the WHOLE Statement
    with `predicate.ssh_sig` removed — so the signature covers everything except itself, and
    sign + verify recompute the exact same bytes (exactly as envelope.identity_digest drops
    the signature it is about to write). The DSSE/Ed25519 signature seals the payload bytes
    separately and is untouched by this. Non-mutating: the caller's `statement` is unchanged."""
    d = dict(statement)
    pred = d.get("predicate")
    if isinstance(pred, dict):
        d["predicate"] = {k: v for k, v in pred.items() if k != "ssh_sig"}
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def attach_ssh_auditor(statement: dict, *, login: str, user_id: str | int,
                       pubkey: str, key_path) -> dict:
    """Stamp the verified GitHub AUDITOR identity into the in-toto predicate and SSH-sign the
    auditor identity digest with the auditor's key. Mirrors envelope.attach_ssh_identity, for
    an attestation Statement. Call BEFORE sign_attestation so the DSSE Ed25519 seal also
    covers `ssh_sig`. `ssh_pubkey` is bared to the "<type> <base64>" line the signature
    verifies under; `github_id` is stringified."""
    predicate = statement["predicate"]
    predicate["github_login"] = login
    predicate["github_id"] = str(user_id)
    predicate["ssh_pubkey"] = " ".join(pubkey.split()[:2])
    predicate["sig_method"] = "ssh-github"
    predicate["ssh_sig"] = _identity.sign_digest(
        auditor_identity_digest(statement), key_path=key_path)
    return statement


def verify_auditor_identity(statement: dict, *, keys: list[str] | None = None):
    """Return the verified auditor Identity iff this Statement carries an `ssh-github` auditor
    identity whose `ssh_sig` is a good signature over its auditor identity digest by a key
    GitHub lists for `github_login` (pinned to the predicate's `ssh_pubkey`). Fail-closed:
    legacy/malformed/tampered/wrong-key -> None. Mirrors envelope.verify_envelope_identity."""
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return None
    if (predicate.get("sig_method") != "ssh-github"
            or not predicate.get("ssh_sig") or not predicate.get("github_login")):
        return None
    return _identity.verify_digest(
        auditor_identity_digest(statement), predicate["ssh_sig"], predicate["github_login"],
        keys=keys, expected_pubkey=predicate.get("ssh_pubkey") or None)


def sign_attestation(statement: dict, private_pem: bytes) -> dict:
    """Wrap `statement` in a signed DSSE envelope. Reuses signing.py's Ed25519
    primitives (hex in/out) — this is the ONLY place that translates to/from the
    raw bytes + standard-base64 that the DSSE wire format requires."""
    payload_bytes = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode("utf-8")
    msg = pae(PAYLOAD_TYPE, payload_bytes)
    sig_bytes = bytes.fromhex(sign_bytes(private_pem, msg))
    pub_bytes = bytes.fromhex(public_key_hex(private_pem))
    keyid = hashlib.sha256(pub_bytes).hexdigest()  # standard fingerprint: sha256 of raw pubkey
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.standard_b64encode(payload_bytes).decode("ascii"),
        "signatures": [{"keyid": keyid,
                         "sig": base64.standard_b64encode(sig_bytes).decode("ascii")}],
    }


def verify_attestation(envelope: dict, *, expected_pubkey_hex: str | None = None) -> bool:
    """Fail-closed: any malformed/missing field, bad base64, or verification failure
    returns False rather than raising. Verifies against `expected_pubkey_hex` when
    given (pin a known auditor key); otherwise falls back to the key the Statement
    itself declares in predicate.auditor.publicKey (self-describing check — proves
    internal consistency, not identity, unless the caller pins a key)."""
    try:
        payload_type = envelope["payloadType"]
        payload_bytes = base64.b64decode(envelope["payload"], validate=True)
        msg = pae(payload_type, payload_bytes)
        statement = json.loads(payload_bytes)
        pubkey_hex = expected_pubkey_hex
        if pubkey_hex is None:
            pubkey_hex = statement["predicate"]["auditor"]["publicKey"]
        signatures = envelope["signatures"]
        if not signatures:
            return False
        for entry in signatures:
            sig_bytes = base64.b64decode(entry["sig"], validate=True)
            if verify_bytes(pubkey_hex, msg, sig_bytes.hex()):
                return True
        return False
    except Exception:
        return False


def parse_statement(envelope: dict) -> dict:
    """Decode + return the Statement from a DSSE envelope, size-capped. Sanitizes every
    attacker-controlled free-text field (auditor name/email, report summary, finding
    title/rationale, check tool/summary/tail) the same way envelope.py sanitizes a
    contribution's free text — a crafted attestation must never smuggle control chars
    into a terminal/log/commit. Does NOT verify the signature; call verify_attestation
    separately."""
    try:
        payload_bytes = base64.b64decode(envelope["payload"], validate=True)
        if len(payload_bytes) > _MAX_PAYLOAD_BYTES:
            raise AttestationFormatError(
                f"attestation payload is {len(payload_bytes)} bytes "
                f"(cap {_MAX_PAYLOAD_BYTES}) — refusing")
        statement = json.loads(payload_bytes)
        if not isinstance(statement, dict):
            raise AttestationFormatError("attestation payload is not a JSON object")
    except AttestationFormatError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise AttestationFormatError(f"cannot parse attestation payload: {exc}") from exc

    predicate = statement.get("predicate")
    if isinstance(predicate, dict):
        # Additive GitHub auditor-identity fields are attacker-controlled too; sanitize the
        # single-line ones. `ssh_sig` is deliberately NOT sanitized — it is a multi-line
        # armored signature fed only to ssh-keygen (malformed -> verify fails), never to a
        # terminal/commit string, so it must keep its newlines intact (same rule as
        # envelope.from_dict for the contributor identity).
        for _k in ("github_login", "github_id", "ssh_pubkey", "sig_method"):
            if isinstance(predicate.get(_k), str):
                predicate[_k] = sanitize_text(predicate[_k])
        auditor = predicate.get("auditor")
        if isinstance(auditor, dict):
            if "name" in auditor:
                auditor["name"] = sanitize_text(str(auditor["name"]))
            if "email" in auditor:
                auditor["email"] = sanitize_text(str(auditor["email"]))
        report = predicate.get("report")
        if isinstance(report, dict):
            if "summary" in report:
                report["summary"] = sanitize_text(str(report["summary"]))
            findings = report.get("findings")
            if isinstance(findings, list):
                for f in findings:
                    if isinstance(f, dict):
                        if "title" in f:
                            f["title"] = sanitize_text(str(f["title"]))
                        if "rationale" in f:
                            f["rationale"] = sanitize_text(str(f["rationale"]))
        checks = predicate.get("checks")
        if isinstance(checks, list):
            for c in checks:
                if isinstance(c, dict):
                    for key in ("tool", "summary", "tail"):
                        if key in c:
                            c[key] = sanitize_text(str(c[key]))
    return statement


def save_attestation(envelope: dict, path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(envelope, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_attestation(path) -> dict:
    """Load a DSSE envelope JSON file that may point at an UNTRUSTED path. Rejects
    oversized files (checked from the declared size, before reading the body — same
    guard style as envelope.unpack's zip-bomb check) and anything not shaped like a
    DSSE envelope. Does NOT verify the signature."""
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise AttestationFormatError(f"cannot read attestation: {exc}") from exc
    if size > _MAX_ATTESTATION_FILE:
        raise AttestationFormatError(
            f"attestation file is {size} bytes (cap {_MAX_ATTESTATION_FILE}) — refusing")
    try:
        raw = path.read_text(encoding="utf-8")
        envelope = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttestationFormatError(f"cannot parse attestation: {exc}") from exc
    if not isinstance(envelope, dict):
        raise AttestationFormatError("attestation is not a JSON object")
    sigs = envelope.get("signatures")
    if not (isinstance(envelope.get("payloadType"), str) and envelope["payloadType"]
            and isinstance(envelope.get("payload"), str) and envelope["payload"]
            and isinstance(sigs, list) and sigs):
        raise AttestationFormatError(
            "not a DSSE envelope (need non-empty payloadType/payload/signatures)")
    for sig in sigs:
        if not (isinstance(sig, dict) and isinstance(sig.get("keyid"), str)
                and isinstance(sig.get("sig"), str)):
            raise AttestationFormatError("malformed DSSE signature entry")
    return envelope
