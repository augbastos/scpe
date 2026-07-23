"""MCP server — a SECOND thin frontend over the scpe protocol library (the
CLI in cli.py is the first). Lets an AI agent inside an editor (Cursor / VS Code /
Claude Code) call analyze/contribute/attest/verify/pack/inspect NATIVELY as tools,
instead of shelling out to `scpe ...` subprocesses.

Every tool handler below is a PURE function: plain-Python args in, a JSON-serializable
dict out, calling the SAME hardened library paths the CLI uses (repo_snapshot's
protocol pinning, envelope's zip-bomb/size caps, sandbox's cleaned env, attestation's
DSSE format) — nothing here re-implements or bypasses a security fix. A handler never
returns raw private-key material: signing happens locally with the loaded PEM, and
only the derived PUBLIC key (hex) goes back in the response. Expected library
failures (bad envelope, repo clone failure, unparseable backend reply, malformed
workspace/attestation, unconfigured backend) are caught and returned as
`{"error": "..."}` rather than raised, so a caller never has to catch an exception
across the MCP transport.

`apply` (turning an accepted envelope into a real commit) is deliberately NOT exposed
here: it is a human's git-authorship decision, not something an editor agent should
trigger autonomously. Use `scpe verify --apply` for that step.

The `mcp` SDK is an OPTIONAL extra (`pip install scpe-protocol[mcp]`). Importing this
module and calling any `cc_*` handler NEVER requires it — only `build_server()`/
`main()` (i.e. actually running the server) does, so the core package and its test
suite do not gain a hard dependency on `mcp`."""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from scpe import backends as _backends
from scpe.analyze import analyze as _analyze
from scpe.changes import summarize as _summarize_changes
from scpe.attestation import (
    AttestationFormatError, attach_ssh_auditor, build_statement, load_attestation,
    parse_statement, save_attestation, sign_attestation, verify_attestation,
    verify_auditor_identity,
)
from scpe.checks import run_checks
from scpe.backends import BackendConfigError
from scpe.contribute import ContributeError
from scpe.envelope import EnvelopeFormatError, unpack, verify_envelope_identity
from scpe.handshake import TRUST_LEVELS, run_handshake
from scpe.inspect import inspect_envelope
from scpe.identity import IdentityError, noreply_email, resolve_local_identity
from scpe.repo_snapshot import RepoError
from scpe.signing import load_or_create_key, public_key_hex
from scpe.workspace import WorkspaceError
from scpe.workspace import pack as _ws_pack

DEFAULT_KEY = Path.home() / ".scpe" / "key.pem"

# Expected, user-facing library failures. Handlers catch exactly these — never a
# bare `except Exception` — so a genuine bug in a handler still surfaces as a real
# traceback instead of being silently swallowed into an {"error": ...} dict.
_KNOWN_ERRORS = (EnvelopeFormatError, RepoError, ContributeError, WorkspaceError,
                 AttestationFormatError, BackendConfigError, IdentityError, ValueError)


def _resolve_key(key: str | None) -> bytes:
    return load_or_create_key(Path(key) if key else DEFAULT_KEY)


def _identity_summary(env) -> dict:
    """Compact GitHub-identity status for MCP callers: status is verified | failed |
    unchecked | legacy. Fail-closed — never asserts a login the signature doesn't prove."""
    m = env.manifest
    base = {"login": m.github_login,
            "profile": f"https://github.com/{m.github_login}" if m.github_login else ""}
    if m.sig_method != "ssh-github":
        return {**base, "status": "legacy"}
    try:
        verified = verify_envelope_identity(env) is not None
    except IdentityError as exc:
        return {**base, "status": "unchecked", "detail": str(exc)}
    return {**base, "status": "verified" if verified else "failed"}


def _auditor_identity_summary(statement: dict) -> dict:
    """Compact GitHub-auditor identity status for MCP callers (verified/failed/unchecked/
    legacy), mirroring _identity_summary for a contribution. Fail-closed."""
    pred = statement.get("predicate") or {}
    login = pred.get("github_login") or ""
    base = {"login": login, "profile": f"https://github.com/{login}" if login else ""}
    if pred.get("sig_method") != "ssh-github":
        return {**base, "status": "legacy"}
    try:
        verified = verify_auditor_identity(statement) is not None
    except IdentityError as exc:
        return {**base, "status": "unchecked", "detail": str(exc)}
    return {**base, "status": "verified" if verified else "failed"}


def _split_test_cmd(test_cmd: str | None) -> list[str] | None:
    """Shell-style string -> arg list, same posix-mode quirk as the CLI's --test-cmd:
    shlex's default posix mode mangles a plain `C:\\Python\\python.exe`-style path on
    Windows even with no quoting involved."""
    if not test_cmd:
        return None
    return shlex.split(test_cmd, posix=(os.name != "nt"))


def _tmp_out(name: str) -> Path:
    """Default output location when the caller doesn't pin one: a fresh temp dir —
    never the MCP server process's cwd, which an editor/agent host controls and a
    tool call should not silently litter."""
    return Path(tempfile.mkdtemp(prefix="cc-mcp-")) / name


# --------------------------------------------------------------------------- #
# Tool handlers
# --------------------------------------------------------------------------- #

def cc_pack(workspace: str, key: str | None = None, out: str | None = None) -> dict:
    """Seal a `scpe pull`-ed workspace's hand-made changes into ONE signed
    Envelope piece. AI-free: the human/agent editing the workspace files is the diff's
    author; no LLM is called. Credit is bound to a VERIFIABLE GitHub identity — the
    authenticated gh CLI login plus the scpe SSH signing key (`key`, default
    ~/.ssh/scpe_ed25519), which must be registered on the GitHub account, else
    this refuses. Returns {out_path, pieces, github_login, signer_pubkey} — never a
    private key."""
    ws = Path(workspace)
    try:
        ident = resolve_local_identity(key_path=key)
        out_path = Path(out) if out else _tmp_out("envelope.zip")
        result_path = _ws_pack(ws, out_path=out_path, identity=ident, backend=None)
        env = unpack(result_path)
        return {
            "out_path": str(result_path),
            "pieces": [{"id": p.id, "title": p.title, "files": list(p.target_files)}
                      for p in env.pieces],
            "github_login": env.manifest.github_login,
            "signer_pubkey": env.manifest.ssh_pubkey,
        }
    except _KNOWN_ERRORS as exc:
        return {"error": str(exc)}


def cc_verify(envelope_path: str, repo: str, trust: str = "strict",
             test_cmd: str | None = None) -> dict:
    """Owner handshake: RE-PROVE a signed envelope's pieces against `repo` at the
    chosen trust level (strict = full safety+sandbox+fit re-audit; trusted = safety
    audit only, no sandbox; direct = signature check only). Read-only — this tool
    NEVER applies or commits a piece; that stays a deliberate human action via
    `scpe verify --apply` on the CLI. `test_cmd`, if given, is a shell-style
    string overriding sandbox test-runner auto-detection."""
    if trust not in TRUST_LEVELS:
        return {"error": f"trust must be one of {TRUST_LEVELS}"}
    try:
        backend = _backends.make_backend(None)
        with tempfile.TemporaryDirectory(prefix="cc-mcp-verify-") as wd:
            report = run_handshake(envelope_path, repo, backend, trust=trust,
                                   workdir=Path(wd), test_cmd=_split_test_cmd(test_cmd))
        return {
            "trust": report.trust,
            "envelope_ok": report.envelope_ok,
            "identity": _identity_summary(unpack(envelope_path)),
            "pieces": [asdict(p) for p in report.pieces],
        }
    except _KNOWN_ERRORS as exc:
        return {"error": str(exc)}


def cc_attest(repo: str, backend: str | None = None, key: str | None = None,
             out: str | None = None, no_checks: bool = False) -> dict:
    """Analyze `repo` with an LLM backend and sign a standard in-toto/DSSE audit
    attestation: no diff, credits nobody — "repo X at commit Y was read by key Z,
    verdict clean/N findings". An analysis that finds ZERO issues signs a "clean"
    verdict; that is a positive, portable deliverable, never a failure. This is an
    LLM-based read, NOT a formal security certification.

    Unless `no_checks` is set, also runs the repo's own test suite plus bandit/ruff
    (whichever are installed) inside the same sandbox isolation `verify` uses, and
    signs those results into the predicate as `checks` — SIGNED evidence alongside
    the LLM verdict, honestly reported (a tool that never ran is never reported as
    passed). `no_checks=True` is the fast/offline path: the attestation still signs
    fine, it just carries no `checks` evidence."""
    try:
        be = _backends.make_backend(backend)
        # Auditor bound to a VERIFIABLE GitHub identity (gh CLI + the scpe SSH key,
        # `key`), same rule as cc_pack — never a free-typed auditor name. The Ed25519 key at
        # DEFAULT_KEY keeps the DSSE signature cosign/standard-verifiable; the SSH GitHub key
        # is who a reader confirms.
        ident = resolve_local_identity(key_path=key)
        pem = _resolve_key(None)
        checks_result = None
        with tempfile.TemporaryDirectory(prefix="cc-mcp-attest-") as wd:
            report = _analyze(repo, be, workdir=Path(wd))
            if not no_checks:
                # `analyze()` clones the repo to workdir/"clone" (see analyze.py) —
                # still on disk here, before this `with` block's tempdir is discarded.
                checks_result = run_checks(Path(wd) / "clone")
        statement = build_statement(
            repo_url=report["repo"], base_sha=report["base_sha"], auditor_name=ident.name,
            auditor_email=noreply_email(ident.login, ident.user_id),
            auditor_pubkey_hex=public_key_hex(pem), backend_label=report["backend"],
            created_at_iso=datetime.now(timezone.utc).isoformat(), report_dict=report,
            checks=checks_result)
        attach_ssh_auditor(statement, login=ident.login, user_id=ident.user_id,
                           pubkey=ident.pubkey, key_path=ident.key_path)
        envelope = sign_attestation(statement, pem)
        out_path = Path(out) if out else _tmp_out("attestation.intoto.json")
        saved = save_attestation(envelope, out_path)
        predicate = statement["predicate"]
        return {
            "out_path": str(saved),
            "verdict": predicate["verdict"],
            "findings_count": predicate["findingsCount"],
            "github_login": predicate.get("github_login"),
            "checks": checks_result,
            "statement_summary": {
                "repo": report["repo"], "base_sha": report["base_sha"],
                "grade": report.get("grade"), "summary": report.get("summary"),
            },
        }
    except _KNOWN_ERRORS as exc:
        return {"error": str(exc)}


def cc_verify_attest(path: str, repo: str | None = None, key: str | None = None) -> dict:
    """Verify a DSSE-signed audit attestation — standard in-toto/DSSE, independent of
    scpe. `key`, if given, PINS the expected 64-hex auditor public key instead
    of trusting the key embedded in the attestation. `repo`, if given and a local git
    checkout, notes whether its HEAD has drifted from the audited commit."""
    try:
        envelope = load_attestation(path)
        valid = verify_attestation(envelope, expected_pubkey_hex=key)
        statement = parse_statement(envelope)
    except _KNOWN_ERRORS as exc:
        return {"error": str(exc)}

    subject = (statement.get("subject") or [{}])[0]
    predicate = statement.get("predicate") or {}
    auditor = predicate.get("auditor") or {}
    report = predicate.get("report") or {}
    base_sha = (subject.get("digest") or {}).get("gitCommit")

    commit_note = None
    if repo:
        repo_path = Path(repo)
        if (repo_path / ".git").exists():
            proc = subprocess.run(["git", "-C", str(repo_path), "rev-parse", "HEAD"],
                                  capture_output=True, text=True)
            head = proc.stdout.strip()
            if proc.returncode == 0 and head and base_sha and head != base_sha:
                commit_note = f"local HEAD {head} differs from audited commit {base_sha}"

    return {
        "valid": valid,
        "repo": subject.get("name"),
        "base_sha": base_sha,
        "auditor": auditor,
        "auditor_identity": _auditor_identity_summary(statement),
        "verdict": predicate.get("verdict"),
        "findings": report.get("findings") or [],
        "findings_count": predicate.get("findingsCount"),
        "grade": report.get("grade"),
        # None (omitted from the signed predicate) if the attester ran with
        # --no-checks / no_checks=True — never fabricated as an empty pass.
        "checks": predicate.get("checks"),
        "commit_note": commit_note,
    }


def cc_inspect(envelope_path: str) -> dict:
    """Read an envelope safely: no clone, no sandbox, no backend call — the whole
    attack surface is parsing + a signature check, so this is safe to point at an
    UNTRUSTED envelope.zip."""
    try:
        return inspect_envelope(envelope_path)
    except EnvelopeFormatError as exc:
        return {"error": str(exc)}


def cc_changes(envelope_path: str) -> dict:
    """Owner-facing: a human-readable summary of what an envelope MODIFIES, so the
    owner reads the changes without diffing by hand — the contributor's briefing,
    then per piece the title, the why, the files, the +/- counts, and the functions
    touched. Read-only: no clone, no sandbox, no backend."""
    try:
        return {"summary": _summarize_changes(envelope_path)}
    except EnvelopeFormatError as exc:
        return {"error": str(exc)}


# --------------------------------------------------------------------------- #
# MCP wiring — only touched by build_server()/main(), never by importing this
# module or calling a cc_* handler directly.
# --------------------------------------------------------------------------- #

_TOOLS = (cc_pack, cc_verify, cc_attest, cc_verify_attest, cc_inspect, cc_changes)


def build_server():
    """Construct the FastMCP server and register every handler above as a tool.
    Raises ImportError with an actionable install hint if the optional `mcp` SDK
    isn't installed."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise ImportError(
            "the `mcp` SDK is required to run the scpe MCP server — install "
            "the optional extra: pip install scpe-protocol[mcp]"
        ) from exc

    server = FastMCP(
        "scpe",
        instructions=(
            "Owner-verified crowd contributions and audits: analyze a repo with your "
            "own LLM, seal a signed Envelope, the owner's own agents re-prove it "
            "before merge. Tools: cc_pack (seal hand-edited workspace changes, "
            "AI-free), cc_verify (owner handshake re-proof, read-only — never "
            "applies/commits), cc_attest (sign a clean/findings audit attestation, "
            "no diff, no credit), cc_verify_attest (verify one), cc_inspect (read an "
            "envelope safely, no clone/sandbox/backend), cc_changes (owner-readable "
            "summary of what an envelope modifies)."
        ),
    )
    for fn in _TOOLS:
        server.tool(name=fn.__name__, description=fn.__doc__)(fn)
    return server


def main() -> None:
    server = build_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
