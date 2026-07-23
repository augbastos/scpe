#!/usr/bin/env python3
"""SCPE scpe/0.1 reference PRODUCER — the signing side of the reference impl.

Companion to reference/standalone/verify_envelope.py (the verifier). Everything this
module emits MUST verify, byte for byte, through that file. Like the verifier this is
a small, self-contained module: stdlib only, the only external binaries are
`ssh-keygen` (OpenSSH >= 8.2), `git`, and — for `submit` — `gh`.

Subcommands (see main()):
    pack     compute a diff, normalize (SPEC §6), sign the manifest (SPEC §7),
             zip -> envelope (manifest.json + manifest.sig + diff.patch)  (SPEC §4)
    pack-artifact  seal a file as an `artifact` subject (SPEC §6.2): sign the manifest,
             zip -> standalone envelope (manifest.json + manifest.sig + artifact.bin)
    attest   re-wrap an envelope as the compact PR-body attestation (SPEC §9):
             manifest + sig WITHOUT the diff, base64, in an SCPE-ATTESTATION-v1 block
    verify   run the standalone reference verifier on an envelope/attestation
    submit   open a native PR via `gh`, attestation in the body + diff applied

The manifest is signed as EXACT bytes (SPEC §4/§7): the same bytes are written to the
zip and fed to `ssh-keygen -Y sign`, and the verifier checks those bytes without any
re-serialization. No JSON canonicalization is involved anywhere.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

NAMESPACE = "scpe/0.1"          # SSHSIG namespace (SPEC §7); MUST match the verifier
SPEC_VERSION = "scpe/0.1"
VERIFIER = Path(__file__).resolve().parent / "standalone" / "verify_envelope.py"

# Profile registry (SPEC §13.1). A profile is a LABEL + domain conventions layered on
# the artifact-agnostic core — nothing more. It adds NO verification logic: the verifier
# always checks integrity by subject.type (SPEC §6, §8 step 7), and surfaces the stamped
# label verbatim (SPEC §13.2). Here the producer uses each profile for two conventions:
# which subject.type it rides, and — for `artifact` subjects — a default `media_type` to
# stamp when the caller does not pass an explicit one (media_type is itself informational
# and unverified, SPEC §6.2). `SCPE-C` rides `code-change`, whose subject is a diff with
# no media_type. Stamping a profile is optional; an omitted profile means unstamped.
PROFILE_REGISTRY: dict[str, dict] = {
    "SCPE-C":    {"subject_type": "code-change", "media_type": None},
    "SCPE-I":    {"subject_type": "artifact",    "media_type": "image/png"},
    "SCPE-V":    {"subject_type": "artifact",    "media_type": "video/mp4"},
    "SCPE-A":    {"subject_type": "artifact",    "media_type": "audio/mpeg"},
    "SCPE-M":    {"subject_type": "artifact",    "media_type": "application/octet-stream"},
    "SCPE-DATA": {"subject_type": "artifact",    "media_type": "application/octet-stream"},
    "SCPE-D":    {"subject_type": "artifact",    "media_type": "application/pdf"},
    "SCPE-AR":   {"subject_type": "artifact",    "media_type": "application/octet-stream"},
}
PROFILES = tuple(PROFILE_REGISTRY)
ATTESTATION_RE = re.compile(
    r"<!--\s*SCPE-ATTESTATION-v1\s*\n(.*?)\n\s*-->", re.DOTALL)


class ProducerError(RuntimeError):
    """A precondition failed (git/ssh-keygen missing, bad input) — never a silent default."""


def _run(args: list[str], *, cwd: str | None = None,
         stdin: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(args, cwd=cwd, input=stdin, capture_output=True)
    except FileNotFoundError as exc:
        raise ProducerError(f"{args[0]} not found — install it and retry") from exc
    if check and proc.returncode != 0:
        raise ProducerError(
            f"{' '.join(args[:3])} failed: {proc.stderr.decode('utf-8', 'replace').strip()}")
    return proc


# ---------------------------------------------------------- normalization (SPEC §6)

def normalize_diff(raw: bytes) -> bytes:
    """SPEC §6: CRLF/CR -> LF, exactly one trailing newline, at the BYTE level.
    Byte-identical to the verifier's normalize_diff — the two MUST agree or nothing
    round-trips. Operates on raw bytes (never decodes) so the anchor is well-defined
    even for a diff that is not valid UTF-8."""
    text = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return text.rstrip(b"\n") + b"\n"


def diff_sha256(diff_normalized: bytes) -> str:
    return hashlib.sha256(diff_normalized).hexdigest()


# ---------------------------------------------------------------- diff from git (§6)

def compute_diff(repo: Path, base: str, head: str | None) -> tuple[bytes, list[str], dict, str, str]:
    """Return (normalized_diff_bytes, files_changed, stats, base_sha, head_sha).

    base...head (three-dot, matching the verifier's `git diff <base_sha>...<head>`) when
    `head` is given; otherwise base -> working tree. The diff is normalized per SPEC §6
    before it is ever hashed or written, so the enclosed diff.patch and change.diff_sha256
    are derived from the same bytes.
    """
    if not (repo / ".git").exists():
        raise ProducerError(f"{repo} is not a git repository")
    spec = f"{base}...{head}" if head else base
    diff_raw = _run(["git", "-C", str(repo), "diff", spec]).stdout
    numstat = _run(["git", "-C", str(repo), "diff", "--numstat", spec]).stdout
    files: list[str] = []
    insertions = deletions = 0
    for line in numstat.decode("utf-8", "replace").splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        add, rem, path = parts
        insertions += int(add) if add.isdigit() else 0
        deletions += int(rem) if rem.isdigit() else 0
        files.append(path)
    base_sha = _run(["git", "-C", str(repo), "rev-parse", base]).stdout.decode().strip()
    head_ref = head if head else "HEAD"
    head_sha = _run(["git", "-C", str(repo), "rev-parse", head_ref]).stdout.decode().strip()
    return (normalize_diff(diff_raw), files,
            {"insertions": insertions, "deletions": deletions}, base_sha, head_sha)


# ------------------------------------------------------------------ identity (§7-8)

def key_fingerprint(key_path: Path) -> str:
    """The `SHA256:...` fingerprint of the signing key, for change.contributor. Reads the
    public half (<key>.pub) when present, else the key itself."""
    pub = Path(str(key_path) + ".pub")
    target = pub if pub.exists() else key_path
    out = _run(["ssh-keygen", "-lf", str(target)]).stdout.decode("utf-8", "replace")
    return out.split()[1]  # "256 SHA256:... comment" -> "SHA256:..."


def resolve_login_and_key(login: str | None, key: str | None) -> tuple[str, Path]:
    """Explicit --login/--key run fully offline (tests, CI, air-gapped signing). When
    omitted, fall back to the well-tested gh-CLI resolver in the legacy package, which
    confirms the key is actually published on the account before it lets you sign."""
    if login and key:
        return login, Path(key)
    try:
        from scpe.identity import resolve_local_identity  # lazy: offline path never imports it
    except Exception as exc:  # pragma: no cover - only when scpe unavailable
        raise ProducerError(
            "pass --login and --key for offline signing (gh-based resolution unavailable: "
            f"{exc})") from exc
    ident = resolve_local_identity(key_path=key)
    return ident.login, Path(ident.key_path)


# ------------------------------------------------------------------- manifest (§4)

def _build_envelope_manifest(*, login: str, fingerprint: str, provider: str,
                             subject: dict, ai_mode: str, ai_notes: str | None,
                             created_at: str,
                             attestations: list[dict] | None = None,
                             profile: str | None = None) -> dict:
    # The manifest is a signed EVIDENCE CONTAINER (SPEC §4). Identity is a
    # (provider, subject-username) pair (SPEC §8): `login` is the identity username and
    # `provider` names the key-resolution method from the fixed registry (default
    # `github`). The top-level `subject` BLOCK (SPEC §6) says WHAT is attested and is
    # type-dispatched by the verifier (`code-change` or `artifact` in scpe/0.1).
    # `attestations` is a list of typed, signed claims (SPEC §5); omitted when empty.
    m: dict = {
        "spec_version": SPEC_VERSION,
        "created_at": created_at,
        "contributor": {
            "identity": {"provider": provider, "subject": login},
            "key_fingerprint": fingerprint,
        },
        "subject": subject,
        "ai_disclosure": {"mode": ai_mode},
    }
    if ai_notes is not None:
        m["ai_disclosure"]["notes"] = ai_notes
    # `profile` (SPEC §4/§13) is an advisory domain-convention LABEL. It carries no
    # integrity path: the producer stamps it, the verifier surfaces it but verifies by
    # subject.type. Omitted -> unstamped. Placed after ai_disclosure, before attestations,
    # matching the SPEC §4 field order.
    if profile is not None:
        m["profile"] = profile
    if attestations:
        m["attestations"] = attestations
    return m


def build_manifest(*, login: str, fingerprint: str, repo: str, base_sha: str,
                   dsha: str, head_sha: str, files: list[str], stats: dict,
                   ai_mode: str, ai_notes: str | None, created_at: str,
                   attestations: list[dict] | None = None,
                   provider: str = "github", profile: str | None = None) -> dict:
    # A `code-change` subject (SPEC §6.1): the implemented default. Nests today's
    # target + change verbatim under the typed `subject` block.
    subject = {
        "type": "code-change",
        "target": {"repo": repo, "base_sha": base_sha},
        "change": {
            "diff_sha256": dsha,
            "head_sha": head_sha,
            "files_changed": files,
            "stats": stats,
        },
    }
    return _build_envelope_manifest(
        login=login, fingerprint=fingerprint, provider=provider, subject=subject,
        ai_mode=ai_mode, ai_notes=ai_notes, created_at=created_at,
        attestations=attestations, profile=profile)


def build_artifact_manifest(*, login: str, fingerprint: str, digest_sha256: str,
                            media_type: str, ai_mode: str, ai_notes: str | None,
                            created_at: str, attestations: list[dict] | None = None,
                            provider: str = "github", profile: str | None = None) -> dict:
    # An `artifact` subject (SPEC §6.2): a hash-addressed digital artifact. The
    # standalone envelope carries the bytes as `artifact.bin`; the verifier hashes them
    # RAW and compares to subject.digest.sha256.
    subject = {
        "type": "artifact",
        "digest": {"sha256": digest_sha256},
        "media_type": media_type,
    }
    return _build_envelope_manifest(
        login=login, fingerprint=fingerprint, provider=provider, subject=subject,
        ai_mode=ai_mode, ai_notes=ai_notes, created_at=created_at,
        attestations=attestations, profile=profile)


def serialize_manifest(m: dict) -> bytes:
    """The EXACT bytes that get signed AND zipped (SPEC §4). Any stable serialization is
    conformant; we mirror the test vectors (indent=2, UTF-8, no trailing newline)."""
    return json.dumps(m, indent=2, ensure_ascii=False).encode("utf-8")


def sign_manifest(manifest_bytes: bytes, key_path: Path) -> bytes:
    """SSHSIG over the exact manifest bytes, namespace scpe/0.1 (SPEC §7). Returns the
    armored .sig bytes. Signs the very bytes passed in — never a re-serialization."""
    with tempfile.TemporaryDirectory(prefix="scpe-sign-") as td:
        mp = Path(td) / "manifest.json"
        mp.write_bytes(manifest_bytes)
        _run(["ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", NAMESPACE, str(mp)])
        sig = Path(str(mp) + ".sig")
        if not sig.is_file():
            raise ProducerError("ssh-keygen produced no signature")
        return sig.read_bytes()


def _zip_bytes(members: list[tuple[str, bytes]]) -> bytes:
    """Deterministic zip of exactly `members` (name, bytes) — flat, no directories, so it
    passes the verifier's strict membership check (SPEC §4)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zi = zipfile.ZipInfo(name)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, data)
    return buf.getvalue()


# -------------------------------------------------------------------------- pack (§4)

def pack(*, repo: Path, base: str, head: str | None, out: Path,
         login: str | None, key: str | None, ai_mode: str = "none",
         ai_notes: str | None = None, created_at: str,
         repo_name: str | None = None, attestations: list[dict] | None = None,
         provider: str = "github", profile: str | None = None) -> Path:
    login, key_path = resolve_login_and_key(login, key)
    fpr = key_fingerprint(key_path)
    diff_bytes, files, stats, base_sha, head_sha = compute_diff(repo, base, head)
    dsha = diff_sha256(diff_bytes)
    target_repo = repo_name or _origin_slug(repo) or repo.name
    m = build_manifest(login=login, fingerprint=fpr, repo=target_repo, base_sha=base_sha,
                       dsha=dsha, head_sha=head_sha, files=files, stats=stats,
                       ai_mode=ai_mode, ai_notes=ai_notes, created_at=created_at,
                       attestations=attestations, provider=provider, profile=profile)
    manifest_bytes = serialize_manifest(m)
    sig_bytes = sign_manifest(manifest_bytes, key_path)
    envelope = _zip_bytes([
        ("manifest.json", manifest_bytes),
        ("manifest.sig", sig_bytes),
        ("diff.patch", diff_bytes),
    ])
    out.write_bytes(envelope)
    return out


def resolve_media_type(media_type: str | None, profile: str | None) -> str:
    """Resolve the `media_type` to stamp on an `artifact` subject. An explicit
    --media-type always wins; otherwise a stamped profile supplies its convention default
    (SPEC §13.1). media_type is informational and unverified (SPEC §6.2) — this only
    decides what advisory label is recorded, never the verify decision."""
    if media_type:
        return media_type
    conv = PROFILE_REGISTRY.get(profile or "", {}).get("media_type")
    if conv:
        return conv
    raise ProducerError(
        "no media type: pass --media-type, or a --profile whose convention supplies one")


def pack_artifact(*, artifact: Path, media_type: str | None = None, out: Path,
                  login: str | None, key: str | None, ai_mode: str = "none",
                  ai_notes: str | None = None, created_at: str,
                  attestations: list[dict] | None = None,
                  provider: str = "github", profile: str | None = None) -> Path:
    """Pack an `artifact` subject (SPEC §6.2) into a standalone envelope: the raw
    artifact bytes ride as `artifact.bin`, and subject.digest.sha256 binds them. Verifies
    through the standalone verifier exactly like a code-change envelope, only the payload
    member differs. Artifact subjects are standalone-only (no PR-transport form).

    `profile` (SPEC §13) is an advisory label stamped verbatim; when `media_type` is not
    passed, the profile's convention (SPEC §13.1) supplies the default media_type. Neither
    the profile nor the media_type affects verification — integrity is the raw-bytes digest
    check of SPEC §6.2, unchanged."""
    login, key_path = resolve_login_and_key(login, key)
    fpr = key_fingerprint(key_path)
    resolved_media = resolve_media_type(media_type, profile)
    data = artifact.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    m = build_artifact_manifest(login=login, fingerprint=fpr, digest_sha256=digest,
                                media_type=resolved_media, ai_mode=ai_mode, ai_notes=ai_notes,
                                created_at=created_at, attestations=attestations,
                                provider=provider, profile=profile)
    manifest_bytes = serialize_manifest(m)
    sig_bytes = sign_manifest(manifest_bytes, key_path)
    envelope = _zip_bytes([
        ("manifest.json", manifest_bytes),
        ("manifest.sig", sig_bytes),
        ("artifact.bin", data),
    ])
    out.write_bytes(envelope)
    return out


def _origin_slug(repo: Path) -> str | None:
    """owner/name from `git remote get-url origin`, or None (local-only fixture repos)."""
    proc = _run(["git", "-C", str(repo), "remote", "get-url", "origin"], check=False)
    if proc.returncode != 0:
        return None
    return _repo_slug(proc.stdout.decode("utf-8", "replace").strip())


def _repo_slug(repo_url: str) -> str:
    s = repo_url.strip().replace("https://", "").replace("http://", "")
    s = s.replace("git@github.com:", "github.com/").rstrip("/")
    if s.endswith(".git"):
        s = s[:-4]
    if s.startswith("github.com/"):
        s = s[len("github.com/"):]
    parts = s.split("/")
    return f"{parts[0]}/{parts[1]}" if len(parts) == 2 and all(parts) else ""


# ------------------------------------------------------------------ attestation (§9)

def _read_envelope(path: Path) -> tuple[bytes, bytes, bytes | None]:
    """(manifest_bytes, sig_bytes, diff_bytes|None) from an envelope zip."""
    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        if not {"manifest.json", "manifest.sig"} <= names:
            raise ProducerError(f"envelope missing manifest.json/manifest.sig: {sorted(names)}")
        return (zf.read("manifest.json"), zf.read("manifest.sig"),
                zf.read("diff.patch") if "diff.patch" in names else None)


def attestation_block(manifest_bytes: bytes, sig_bytes: bytes) -> str:
    """The SPEC §9 attestation: the envelope zip WITHOUT diff.patch, base64, wrapped in
    exactly one SCPE-ATTESTATION-v1 HTML comment. Verifies identically to the standalone
    envelope; only the diff (step 6) has to come from elsewhere (the PR / --diff)."""
    inner = _zip_bytes([("manifest.json", manifest_bytes), ("manifest.sig", sig_bytes)])
    b64 = base64.b64encode(inner).decode("ascii")
    return f"<!-- SCPE-ATTESTATION-v1\n{b64}\n-->\n"


def attest(*, envelope: Path, out: Path | None) -> str:
    manifest_bytes, sig_bytes, _ = _read_envelope(envelope)
    block = attestation_block(manifest_bytes, sig_bytes)
    if out is not None:
        out.write_text(block, encoding="utf-8", newline="\n")
    return block


# ----------------------------------------------------------------------- verify (§8)

def verify(path: Path, *, keys: Path | None = None, diff: Path | None = None) -> dict:
    """Run the standalone reference verifier as a subprocess (exactly how an auditor runs
    it) and return its JSON result. This is the SAME verifier the test vectors use — the
    producer never re-implements verification, it defers to the one auditable file."""
    args = [sys.executable, str(VERIFIER), str(path), "--json"]
    if keys is not None:
        args += ["--keys", str(keys)]
    if diff is not None:
        args += ["--diff", str(diff)]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if not proc.stdout.strip():
        raise ProducerError(f"verifier produced no output; stderr: {proc.stderr[-500:]}")
    return json.loads(proc.stdout)


# ----------------------------------------------------------------------- submit (§9)

def submit(*, envelope: Path, repo: str | None, gh: str = "gh") -> str:
    """Open a native PR: the diff applied to a fresh branch (a real, reviewable PR) and the
    SPEC §9 attestation embedded in the PR body. Mirrors scpe.cli._cmd_submit's clean-merge
    approach — the envelope never lands in the tree, so merging leaves the repo clean.

    Returns the PR URL. Every git/gh call goes through subprocess.run, so tests mock it.
    """
    import shutil
    if shutil.which(gh) is None:
        raise ProducerError(
            f"{gh} CLI not found — install GitHub CLI (https://cli.github.com) and "
            "`gh auth login`, then retry.")
    manifest_bytes, sig_bytes, diff_bytes = _read_envelope(envelope)
    if diff_bytes is None:
        raise ProducerError("envelope has no diff.patch to apply")
    m = json.loads(manifest_bytes.decode("utf-8"))
    identity = (m.get("contributor") or {}).get("identity") or {}
    login = identity.get("subject") or ""   # GitHub PR transport: subject == login
    subject = m.get("subject") or {}        # SPEC §6 evidence-container subject block
    target = repo or _repo_slug((subject.get("target") or {}).get("repo") or "")
    if not target:
        raise ProducerError(
            "could not determine the target repo from the envelope — pass --repo owner/name")
    env_sha = hashlib.sha256(envelope.read_bytes()).hexdigest()
    branch = f"scpe/{login}-{env_sha[:8]}" if login else f"scpe/{env_sha[:8]}"
    files = (subject.get("change") or {}).get("files_changed") or []
    title = f"scpe: contribution to {', '.join(files) or target}"[:100]
    block = attestation_block(manifest_bytes, sig_bytes)
    body = (
        "The change is in **Files changed** above, like any PR.\n\n"
        "It carries a signed SCPE scpe/0.1 attestation (below): portable proof of who "
        f"authored it. Re-verify offline against github.com/{login}.keys with the "
        "standalone `verify_envelope.py`. Nothing lands until you merge.\n\n"
        + block
    )
    with tempfile.TemporaryDirectory(prefix="scpe-submit-") as td:
        work = Path(td) / "repo"
        _run([gh, "repo", "clone", target, str(work)])
        _run(["git", "-C", str(work), "checkout", "-b", branch])
        patch = Path(td) / "contribution.patch"
        patch.write_bytes(normalize_diff(diff_bytes))  # LF, exactly as signed
        ap = _run(["git", "-C", str(work), "apply", "--index", str(patch)], check=False)
        if ap.returncode != 0:
            raise ProducerError(
                f"the contribution does not apply cleanly onto {target}: "
                f"{ap.stderr.decode('utf-8', 'replace').strip()}")
        _run(["git", "-C", str(work), "commit", "-m", title])
        same_owner = bool(login) and target.split("/")[0].lower() == login.lower()
        if same_owner:
            _run(["git", "-C", str(work), "push", "--force", "origin", branch])
            head = branch
        else:
            _run([gh, "repo", "fork", target, "--remote", "--remote-name", "fork"], cwd=str(work))
            _run(["git", "-C", str(work), "push", "--force", "fork", branch])
            head = f"{login}:{branch}" if login else branch
        proc = _run([gh, "pr", "create", "--repo", target, "--head", head,
                     "--title", title, "--body", body], cwd=str(work), check=False)
        if proc.returncode != 0:
            raise ProducerError(
                f"gh pr create failed: {proc.stderr.decode('utf-8', 'replace').strip()}")
        return proc.stdout.decode("utf-8", "replace").strip()


# -------------------------------------------------------------------------------- cli

def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_attestations(attestations_path: str | None,
                       agent_trace_path: str | None) -> list[dict] | None:
    """Assemble the signed `attestations[]` list (SPEC §5) from the CLI.

    `--attestations FILE` carries a JSON array of ready-made attestation objects (each
    with its own `type`). `--agent-trace FILE` is convenience for the common case: a
    single agent-trace `{format, data}` record, wrapped here as an `agent-trace`
    attestation. Both may be given; the results concatenate. Empty -> None (omit)."""
    out: list[dict] = []
    if attestations_path:
        data = json.loads(Path(attestations_path).read_text(encoding="utf-8"))
        if not isinstance(data, list) or not all(isinstance(a, dict) for a in data):
            raise ProducerError(
                "--attestations file must contain a JSON array of attestation objects")
        out.extend(data)
    if agent_trace_path:
        obj = json.loads(Path(agent_trace_path).read_text(encoding="utf-8"))
        if not isinstance(obj, dict):
            raise ProducerError("--agent-trace file must contain a JSON object")
        out.append(obj if obj.get("type") == "agent-trace"
                   else {"type": "agent-trace", **obj})
    return out or None


def _cmd_pack(args) -> int:
    out = pack(repo=Path(args.repo), base=args.base, head=args.head, out=Path(args.out),
               login=args.login, key=args.key, ai_mode=args.mode, ai_notes=args.notes,
               created_at=args.created_at or _iso_now(), repo_name=args.repo_name,
               attestations=_load_attestations(args.attestations, args.agent_trace),
               provider=args.provider, profile=args.profile)
    print(f"envelope written: {out}", file=sys.stderr)
    return 0


def _cmd_pack_artifact(args) -> int:
    out = pack_artifact(
        artifact=Path(args.artifact), media_type=args.media_type, out=Path(args.out),
        login=args.login, key=args.key, ai_mode=args.mode, ai_notes=args.notes,
        created_at=args.created_at or _iso_now(),
        attestations=_load_attestations(args.attestations, args.agent_trace),
        provider=args.provider, profile=args.profile)
    print(f"artifact envelope written: {out}", file=sys.stderr)
    return 0


def _cmd_attest(args) -> int:
    block = attest(envelope=Path(args.envelope),
                   out=Path(args.out) if args.out else None)
    if args.out:
        print(f"attestation written: {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(block)
    return 0


def _cmd_verify(args) -> int:
    res = verify(Path(args.path),
                 keys=Path(args.keys) if args.keys else None,
                 diff=Path(args.diff) if args.diff else None)
    if args.json:
        print(json.dumps(res))
    else:
        mark = "OK" if res["status"] == "verified" else "NO"
        line = f"[{mark}] {res['status']}"
        if res["status"] == "verified":
            atts = res.get("attestations") or []
            summ = ", ".join(f"{a['type']}={a['status']}" for a in atts) or "none"
            line += f" (attestations: {summ})"
        if res.get("profile"):
            line += f" [profile: {res['profile']}]"
        if res.get("detail"):
            line += f" — {res['detail']}"
        print(line)
    return 0 if res["status"] == "verified" else 1


def _cmd_submit(args) -> int:
    url = submit(envelope=Path(args.envelope), repo=args.repo)
    print(f"opened PR: {url}" if url else "opened PR")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scpe-producer",
        description="SCPE scpe/0.1 reference producer (pack / attest / verify / submit)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("pack", help="compute a diff, sign the manifest, emit an envelope zip")
    pk.add_argument("--repo", default=".", help="git working copy (default .)")
    pk.add_argument("--base", required=True, help="base commit the diff applies to")
    pk.add_argument("--head", default=None,
                    help="head commit (base...head); omit to diff base -> working tree")
    pk.add_argument("--out", default="envelope.zip")
    pk.add_argument("--login", default=None,
                    help="subject/username within the provider (offline; else resolved via gh)")
    pk.add_argument("--provider", default="github",
                    choices=["github", "gitlab", "codeberg", "local"],
                    help="identity provider from the fixed registry (SPEC §8; default github)")
    pk.add_argument("--key", default=None, help="SSH signing private key")
    pk.add_argument("--repo-name", default=None,
                    help="target repo slug for the manifest (default: origin, else dir name)")
    pk.add_argument("--profile", default=None, choices=PROFILES,
                    help="stamp an advisory domain-convention label (SPEC §13; e.g. SCPE-C "
                         "for code). Surfaced by the verifier, never changes the verdict. "
                         "Omit to leave the manifest unstamped.")
    pk.add_argument("--ai-disclosure", "--mode", dest="mode", default="none",
                    choices=["none", "assisted", "generated"],
                    help="ai_disclosure.mode (SPEC §4); --mode is a back-compat alias")
    pk.add_argument("--notes", default=None, help="ai_disclosure.notes")
    pk.add_argument("--attestations", default=None,
                    help="JSON file: array of signed attestation objects (SPEC §5)")
    pk.add_argument("--agent-trace", default=None,
                    help="JSON file: a single agent-trace {format,data} record, wrapped "
                         "as an agent-trace attestation (convenience for --attestations)")
    pk.add_argument("--created-at", default=None, help="RFC3339 timestamp (default: now)")
    pk.set_defaults(fn=_cmd_pack)

    pa = sub.add_parser("pack-artifact",
        help="pack an artifact (a file + media type) as a standalone artifact-subject envelope")
    pa.add_argument("--artifact", required=True, help="path to the artifact file to seal")
    pa.add_argument("--media-type", default=None,
                    help="the artifact's media (MIME) type, e.g. application/zip. Optional "
                         "when --profile is given (the profile's convention supplies a "
                         "default); required otherwise.")
    pa.add_argument("--profile", default=None, choices=PROFILES,
                    help="stamp an advisory domain-convention label (SPEC §13; e.g. SCPE-I "
                         "image, SCPE-M model, SCPE-DATA dataset, SCPE-D document, SCPE-AR "
                         "catch-all). Surfaced by the verifier, never changes the verdict; "
                         "also supplies the default --media-type when that is omitted.")
    pa.add_argument("--out", default="envelope.zip")
    pa.add_argument("--login", default=None,
                    help="subject/username within the provider (offline; else resolved via gh)")
    pa.add_argument("--provider", default="github",
                    choices=["github", "gitlab", "codeberg", "local"],
                    help="identity provider from the fixed registry (SPEC §8; default github)")
    pa.add_argument("--key", default=None, help="SSH signing private key")
    pa.add_argument("--ai-disclosure", "--mode", dest="mode", default="none",
                    choices=["none", "assisted", "generated"],
                    help="ai_disclosure.mode (SPEC §4); --mode is a back-compat alias")
    pa.add_argument("--notes", default=None, help="ai_disclosure.notes")
    pa.add_argument("--attestations", default=None,
                    help="JSON file: array of signed attestation objects (SPEC §5)")
    pa.add_argument("--agent-trace", default=None,
                    help="JSON file: a single agent-trace {format,data} record")
    pa.add_argument("--created-at", default=None, help="RFC3339 timestamp (default: now)")
    pa.set_defaults(fn=_cmd_pack_artifact)

    at = sub.add_parser("attest", help="re-wrap an envelope as the compact PR-body attestation")
    at.add_argument("envelope")
    at.add_argument("--out", default=None, help="write the block to a file (default: stdout)")
    at.set_defaults(fn=_cmd_attest)

    vf = sub.add_parser("verify", help="run the standalone reference verifier and surface status")
    vf.add_argument("path", help="envelope zip, vector dir, or a file with an attestation block")
    vf.add_argument("--keys", default=None, help="offline .keys body (else network fetch)")
    vf.add_argument("--diff", default=None, help="diff to check integrity against (attestation)")
    vf.add_argument("--json", action="store_true")
    vf.set_defaults(fn=_cmd_verify)

    sm = sub.add_parser("submit", help="open a native PR (attestation in body + diff applied)")
    sm.add_argument("envelope")
    sm.add_argument("--repo", default=None, help="target owner/name (default: from envelope)")
    sm.set_defaults(fn=_cmd_submit)

    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except ProducerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
