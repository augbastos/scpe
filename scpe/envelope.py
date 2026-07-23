"""The Envelope — the portable, signed contribution package. The contract between
two independent councils is THIS object plus the receiver's re-prove, never the agents."""
from __future__ import annotations

import json
import re
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from scpe import identity as _identity
from scpe.signing import public_key_hex, sign_bytes, verify_bytes

PROTOCOL_VERSION = "1"

# Hard cap on the DECOMPRESSED size of envelope.json. An envelope is a small JSON
# manifest (a few diffs + provenance), never megabytes. Capping here stops a zip-bomb
# member from OOM-crashing the owner who runs `scpe verify` on an untrusted zip.
_MAX_ENVELOPE_JSON = 8 * 1024 * 1024  # 8 MiB

# Collapses CR/LF/TAB and other control chars to a single space. A crafted envelope's
# free-text fields (piece title, sender name/email) are attacker-controlled and get
# copied verbatim into places that treat a newline as structure — most dangerously
# `git commit -m` in cli.py, where an embedded "\n\nSigned-off-by: ...\nCo-authored-by:
# ..." forges trailers that look like they came from someone else. Sanitizing centrally
# here (every field goes through this on the way OUT of untrusted JSON) means every
# consumer downstream — inspect, cli's commit message/author string — sees a clean value.
_CONTROL_CHARS_RE = re.compile(r"[\r\n\t\x00-\x1f\x7f]+")


def sanitize_text(value: str) -> str:
    """Collapse control chars (CR/LF/TAB/NUL/DEL/etc.) to a single space and strip.
    Applied to every attacker-controlled free-text field parsed from an envelope."""
    return _CONTROL_CHARS_RE.sub(" ", value).strip()


class EnvelopeFormatError(ValueError):
    pass


@dataclass
class Piece:
    id: str
    title: str
    rationale: str
    diff: str
    target_files: list[str]


@dataclass
class Manifest:
    protocol_version: str
    repo_url: str
    base_sha: str
    sender_public_key: str
    sender_name: str
    sender_email: str
    created_at: str
    # GitHub-bound contributor identity. Empty on legacy envelopes; populated by
    # attach_ssh_identity() for `sig_method == "ssh-github"` packs. The ssh_sig proves
    # the login signed this envelope, verifiable against github.com/<login> keys.
    github_login: str = ""
    github_id: str = ""
    ssh_pubkey: str = ""   # the "<type> <base64>" line ssh_sig verifies under
    ssh_sig: str = ""      # armored SSH signature over identity_digest (multi-line)
    sig_method: str = ""   # "ssh-github" for identity envelopes; "" for legacy


@dataclass
class Envelope:
    manifest: Manifest
    briefing_md: str
    pieces: list[Piece]
    provenance: dict
    signature: str = ""


def to_dict(env: Envelope) -> dict:
    return asdict(env)


def from_dict(d: dict) -> Envelope:
    try:
        # Sanitize free-text fields as they come OUT of attacker-controlled JSON — every
        # object built here (and everything derived from it, e.g. canonical_payload) is
        # then always clean, so there is no code path that ever sees the raw control chars.
        manifest_kwargs = dict(d["manifest"])
        manifest_kwargs["sender_name"] = sanitize_text(manifest_kwargs["sender_name"])
        manifest_kwargs["sender_email"] = sanitize_text(manifest_kwargs["sender_email"])
        # Identity display fields are attacker-controlled too; sanitize the single-line
        # ones. ssh_sig is deliberately NOT sanitized — it is a multi-line armored
        # signature fed only to ssh-keygen (malformed -> verify fails), never to a
        # commit-message/author string, so it must keep its newlines intact.
        for _k in ("github_login", "github_id", "ssh_pubkey", "sig_method"):
            if isinstance(manifest_kwargs.get(_k), str):
                manifest_kwargs[_k] = sanitize_text(manifest_kwargs[_k])
        pieces = []
        for p in d["pieces"]:
            piece_kwargs = dict(p)
            piece_kwargs["title"] = sanitize_text(piece_kwargs["title"])
            piece_kwargs["rationale"] = sanitize_text(piece_kwargs["rationale"])
            pieces.append(Piece(**piece_kwargs))
        return Envelope(
            manifest=Manifest(**manifest_kwargs),
            briefing_md=d["briefing_md"],
            pieces=pieces,
            provenance=d["provenance"],
            signature=d.get("signature", ""),
        )
    except (KeyError, TypeError) as exc:
        raise EnvelopeFormatError(f"malformed envelope: {exc}") from exc


def canonical_payload(env: Envelope) -> bytes:
    d = to_dict(env)
    d.pop("signature", None)
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def identity_digest(env: Envelope) -> bytes:
    """The canonical bytes the GitHub SSH identity signature covers: the whole envelope
    minus BOTH signatures — the Ed25519 `signature` and the identity `ssh_sig` itself.
    Excluding ssh_sig lets sign and verify recompute the exact same bytes; the Ed25519
    `signature` (added AFTER identity, over everything incl. ssh_sig) still seals it."""
    d = to_dict(env)
    d.pop("signature", None)
    m = d.get("manifest", {})
    m.pop("ssh_sig", None)
    # sender_public_key is written by the LATER Ed25519 sign_envelope step, so it is empty
    # when the identity is signed but populated at verify time — exclude it so the digest
    # is stable across that ordering. The Ed25519 signature covers it separately.
    m.pop("sender_public_key", None)
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def attach_ssh_identity(env: Envelope, *, login: str, user_id: str | int,
                        pubkey: str, key_path) -> Envelope:
    """Stamp the verified GitHub identity onto `env` and sign the identity digest with the
    contributor's SSH key. Call BEFORE sign_envelope so the Ed25519 seal covers ssh_sig."""
    env.manifest.github_login = login
    env.manifest.github_id = str(user_id)
    env.manifest.ssh_pubkey = " ".join(pubkey.split()[:2])
    env.manifest.sig_method = "ssh-github"
    env.manifest.ssh_sig = _identity.sign_digest(identity_digest(env), key_path=key_path)
    return env


def verify_envelope_identity(env: Envelope, *, keys: list[str] | None = None):
    """Return the verified Identity iff this is an `ssh-github` envelope whose ssh_sig is a
    good signature over its identity digest by a key GitHub lists for github_login (pinned
    to the manifest's ssh_pubkey). Fail-closed: legacy/malformed/tampered -> None."""
    m = env.manifest
    if m.sig_method != "ssh-github" or not m.ssh_sig or not m.github_login:
        return None
    return _identity.verify_digest(identity_digest(env), m.ssh_sig, m.github_login,
                                   keys=keys, expected_pubkey=m.ssh_pubkey or None)


def sign_envelope(env: Envelope, private_pem: bytes) -> Envelope:
    env.manifest.sender_public_key = public_key_hex(private_pem)
    env.signature = sign_bytes(private_pem, canonical_payload(env))
    return env


def verify_signature(env: Envelope) -> bool:
    if not env.signature or not env.manifest.sender_public_key:
        return False
    return verify_bytes(env.manifest.sender_public_key, canonical_payload(env), env.signature)


def pack(env: Envelope, path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("envelope.json", json.dumps(to_dict(env), indent=2, ensure_ascii=False))
    return path


def unpack(path) -> Envelope:
    try:
        with zipfile.ZipFile(Path(path)) as z:
            names = z.namelist()
            if names != ["envelope.json"]:
                raise EnvelopeFormatError(
                    f"envelope must contain exactly one member 'envelope.json', got {names}")
            info = z.getinfo("envelope.json")
            # Reject on the DECLARED size before decompressing a single byte…
            if info.file_size > _MAX_ENVELOPE_JSON:
                raise EnvelopeFormatError(
                    f"envelope.json declares {info.file_size} bytes decompressed "
                    f"(cap {_MAX_ENVELOPE_JSON}) — refusing (possible zip bomb)")
            # …and bound the actual read, in case the zip header lies about file_size.
            with z.open("envelope.json") as fh:
                raw = fh.read(_MAX_ENVELOPE_JSON + 1)
            if len(raw) > _MAX_ENVELOPE_JSON:
                raise EnvelopeFormatError(
                    "envelope.json exceeds size cap while decompressing (possible zip bomb)")
            env = from_dict(json.loads(raw))
    except (OSError, KeyError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        raise EnvelopeFormatError(f"cannot read envelope: {exc}") from exc
    if env.manifest.protocol_version != PROTOCOL_VERSION:
        raise EnvelopeFormatError(
            f"protocol {env.manifest.protocol_version!r} unsupported (expected {PROTOCOL_VERSION!r})")
    # Duplicate piece ids let a malicious piece ride an unrelated piece's verdict wherever
    # anything looks a verdict up BY id (first-match-wins). Reject outright at parse time —
    # id uniqueness is an invariant every downstream consumer is entitled to assume.
    ids = [p.id for p in env.pieces]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise EnvelopeFormatError(f"envelope has duplicate piece id(s): {dupes}")
    return env
