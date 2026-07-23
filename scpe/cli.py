"""SCPE CLI. contribute → signed envelope; verify → owner handshake (+ --apply
with automatic contributor credit). Zero-setup for the receiver: uvx scpe verify."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from scpe import __version__
from scpe import backends as _backends
from scpe.analyze import analyze as _analyze
from scpe.attestation import (
    AttestationFormatError, attach_ssh_auditor, build_statement, load_attestation,
    parse_statement, save_attestation, sign_attestation, verify_attestation,
    verify_auditor_identity,
)
from scpe.checks import run_checks, summarize_checks
from scpe.contribute import ContributeError, contribute
from scpe.envelope import (
    EnvelopeFormatError, sanitize_text, unpack, verify_envelope_identity,
)
from scpe.handshake import TRUST_LEVELS, run_handshake
from scpe.identity import IdentityError, noreply_email, resolve_local_identity
from scpe.changes import summarize as _summarize_changes
from scpe.inspect import _count_changes, inspect_envelope
from scpe.optin import init_repo
from scpe.repo_snapshot import RepoError
from scpe.sandbox import detect_test_cmd, run_in_sandbox
from scpe.seal import pr_pill, pr_seal, pr_summary_line, risk_band
from scpe.signing import load_or_create_key, public_key_hex
from scpe.workspace import WorkspaceError
from scpe.workspace import pack as _ws_pack
from scpe.workspace import pull as _ws_pull

DEFAULT_KEY = Path.home() / ".scpe" / "key.pem"


def _cmd_keygen(args) -> int:
    pem = load_or_create_key(Path(args.key))
    print(public_key_hex(pem))
    return 0


def _cmd_contribute(args) -> int:
    backend = _backends.make_backend(args.backend)
    with tempfile.TemporaryDirectory(prefix="cc-contrib-") as wd:
        try:
            # Credit is bound to a verifiable GitHub identity — same rule as `pack`, so a
            # contribution carries a GitHub identifier regardless of path (AI-drafted here).
            ident = resolve_local_identity(key_path=args.key)
            out = contribute(args.repo, backend, identity=ident,
                             workdir=Path(wd), out_path=Path(args.out))
        except (ContributeError, IdentityError) as exc:
            print(f"contribute failed: {exc}", file=sys.stderr)
            return 1
    if out is None:
        # Analysis found zero issues — a positive result, not a failure: no envelope to
        # emit, no diff to sign. Exit 0 so a CI gate doesn't treat "clean" as an error.
        print("nothing to contribute — repo looks clean (analysis found no fixable issues)",
              file=sys.stderr)
        return 0
    env = unpack(out)
    # Status/diagnostic goes to stderr; stdout stays reserved for machine-parseable data.
    print(f"envelope drafted: {out}  ({len(env.pieces)} piece(s), "
          f"signed as @{env.manifest.github_login})", file=sys.stderr)
    # Anti-slop: the AI drafted these — the human MUST review before this goes anywhere.
    # Each piece already self-verified in the sandbox (broken fixes were dropped), and
    # nothing is sent: a draft envelope is just a local file until you act on it.
    print("\n" + _summarize_changes(out), file=sys.stderr)
    print("\nREVIEW the diffs above before sending. Nothing was sent — a draft envelope is\n"
          "just a local file, and the owner will re-verify it with their own model.",
          file=sys.stderr)
    return 0


def _commit_message(disclosure: str, titles: str, ai_label, env, env_sha: str) -> str:
    """Build the commit body, adapting the trailers to the TARGET repo's AI-contribution
    policy — projects genuinely disagree: the Linux kernel wants a human `Signed-off-by:`
    plus an `Assisted-by:` disclosure tag, while Kubernetes BANS any assisted-by/co-developed
    trailer that attributes work to the AI. In every mode the contributor is the git
    `--author`; `SCPE-Signer` + `Envelope` are provenance of the human's *signed*
    envelope (verify_signature proved the key), not a claim of AI authorship.

    `ai_label` is the backend the CONTRIBUTOR used, read from the envelope's provenance.
    A hand-authored `pack` envelope has no AI (label 'none'/None), so we must NOT stamp an
    `Assisted-by` line on it — claiming AI help that never happened is a false disclosure."""
    subject = f"scpe: {titles}"
    prov = [f"SCPE-Signer: {env.manifest.sender_public_key}",
            f"Envelope: {env_sha}"]
    ai_used = bool(ai_label) and str(ai_label).lower() != "none"
    if disclosure == "bare":            # strictest — subject only, no trailers at all
        return subject
    if disclosure == "minimal":         # provenance only — no AI-attribution trailer (K8s-style ban)
        return subject + "\n\n" + "\n".join(prov)
    if disclosure == "signoff":         # kernel-style: human sign-off, AI disclosed as a tool
        author = f"{env.manifest.sender_name} <{env.manifest.sender_email}>"
        lines = [f"Signed-off-by: {author}"]
        if ai_used:
            lines.append(f"Assisted-by: scpe/{ai_label}")
        return subject + "\n\n" + "\n".join(lines + prov)
    # full (default): explicit disclosure + provenance — but only claim AI if AI was used
    lines = [f"Assisted-By: scpe/{ai_label}"] if ai_used else []
    return subject + "\n\n" + "\n".join(lines + prov)


def _identity_status(env) -> dict:
    """Classify an envelope's GitHub identity for the owner: verified (signature checks out
    against the account's public keys), failed (claimed but does NOT verify — a spoof/tamper
    red flag), unchecked (couldn't reach GitHub), or legacy (no identity claimed)."""
    m = env.manifest
    login = m.github_login
    profile = f"https://github.com/{login}" if login else ""
    if m.sig_method != "ssh-github":
        return {"status": "legacy", "login": "", "profile": "",
                "detail": "no GitHub identity claimed (legacy/unsigned contributor)"}
    try:
        ident = verify_envelope_identity(env)
    except IdentityError as exc:
        return {"status": "unchecked", "login": login, "profile": profile,
                "detail": f"could not reach GitHub ({exc})"}
    if ident is None:
        return {"status": "failed", "login": login, "profile": profile,
                "detail": "signature did NOT verify against the account's GitHub keys"}
    return {"status": "verified", "login": ident.login,
            "profile": f"https://github.com/{ident.login}", "detail": ""}


def _print_identity(ids: dict) -> None:
    if ids["status"] == "legacy":
        print(f"  identity: none — {ids['detail']}")
    elif ids["status"] == "verified":
        print(f"  contributor: @{ids['login']} — {ids['profile']}  "
              f"(github identity: verified ✓)")
    elif ids["status"] == "failed":
        print(f"  contributor: @{ids['login']} — {ids['profile']}  "
              f"(github identity: UNVERIFIED — {ids['detail']})")
    else:  # unchecked
        print(f"  contributor: @{ids['login']} — {ids['profile']}  "
              f"(github identity: unchecked — {ids['detail']})")


def _cmd_verify(args) -> int:
    backend = _backends.make_backend(args.backend)
    # Owner override for the sandbox test command (shell-style string -> arg list); None
    # means "let run_handshake auto-detect" (.scpe/verify.json, then language markers).
    # posix=False on Windows: shlex's default posix mode treats `\` as an escape char and
    # mangles a plain `C:\Python\python.exe`-style path even with no quoting involved.
    test_cmd = (shlex.split(args.test_cmd, posix=(os.name != "nt"))
               if args.test_cmd else None)
    with tempfile.TemporaryDirectory(prefix="cc-verify-") as wd:
        try:
            report = run_handshake(args.envelope, args.repo, backend,
                                   trust=args.trust, workdir=Path(wd), test_cmd=test_cmd)
        except EnvelopeFormatError as exc:
            print(f"invalid envelope: {exc}", file=sys.stderr)
            return 1
    env = unpack(args.envelope)
    ids = _identity_status(env)
    if args.json:
        print(json.dumps({"trust": report.trust, "envelope_ok": report.envelope_ok,
                          "identity": ids,
                          "pieces": [asdict(p) for p in report.pieces]}, indent=2))
    else:
        print(f"trust={report.trust} envelope_ok={report.envelope_ok}")
        _print_identity(ids)
        for v in report.pieces:
            # verdict rendered as stored (lowercase), matching the --json output.
            print(f"  {v.piece_id}: {v.verdict}  confidence={v.confidence}")
            print(f"     {v.evidence[:200]}")
    # `all([])` is vacuously True — an envelope with zero pieces must NOT read as "all accepted"
    # (it would green-light a no-op envelope in a CI gate keyed on the exit code).
    accepted_all = (report.envelope_ok and bool(report.pieces)
                    and all(v.verdict == "accept" for v in report.pieces))

    if args.apply:
        repo = Path(args.repo)
        if not repo.is_dir():
            print("--apply needs --repo to be a LOCAL working copy", file=sys.stderr)
            return 1
        # A claimed-but-failed GitHub identity means the credit is a spoof/tamper — refuse to
        # apply. Legacy (no claim) and unchecked (offline) still apply, with the status above.
        if ids["status"] == "failed":
            print(f"--apply refused: contributor identity failed verification "
                  f"(@{ids['login']}: {ids['detail']})", file=sys.stderr)
            return 1
        # Pair each piece with its verdict by POSITION, never by id lookup: the handshake
        # emits exactly one verdict per piece, in envelope order (see run_handshake), so
        # zip is the correct and only pairing — an id-keyed `next(...)` lookup let a
        # malicious piece with a DUPLICATE id ride an earlier, unrelated piece's "accept"
        # verdict (first match wins). unpack() now also rejects duplicate ids outright, so
        # this is defense in depth, not the sole guard.
        if len(env.pieces) != len(report.pieces):
            print("piece/verdict count mismatch — refusing to apply", file=sys.stderr)
            return 1
        accepted = [p for p, v in zip(env.pieces, report.pieces) if v.verdict == "accept"]
        if not accepted:
            print("nothing accepted — nothing applied")
            return 2
        # Apply ALL accepted pieces as ONE patch with `git apply --index`:
        #   * atomic — git apply is all-or-nothing, so a conflicting piece leaves the working
        #     tree untouched instead of a half-applied dirty tree (no manual rollback needed);
        #   * scoped staging — --index stages ONLY the patched paths, so we can `git commit`
        #     without `-a` and never sweep the owner's unrelated uncommitted WIP into the commit.
        combined = "".join(p.diff if p.diff.endswith("\n") else p.diff + "\n" for p in accepted)
        with tempfile.TemporaryDirectory(prefix="cc-apply-") as pd:
            patch = Path(pd) / "accepted.patch"
            patch.write_text(combined, encoding="utf-8", newline="\n")
            proc = subprocess.run(["git", "apply", "--index", str(patch)],
                                  cwd=repo, capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"apply failed — no changes made (atomic); {len(accepted)} piece(s) not "
                  f"applied:\n{proc.stderr.strip()}", file=sys.stderr)
            return 1
        env_sha = hashlib.sha256(Path(args.envelope).read_bytes()).hexdigest()
        titles = "; ".join(p.title for p in accepted)
        # The disclosure mode adapts the trailers to the target repo's AI policy; the Signer
        # key is the strongest provenance anchor (verify_signature proved it), unlike --author
        # which is spoofable and therefore credit, not authority. The AI label comes from the
        # ENVELOPE's provenance (what the contributor used), not this side's --backend, so a
        # hand-authored `pack` (backend 'none') never gets a false Assisted-by stamp.
        prov = env.provenance if isinstance(env.provenance, dict) else {}
        msg = _commit_message(args.disclosure, titles, prov.get("backend"), env, env_sha)
        # No `-a`: commit exactly the staged piece paths. --author records the contributor as
        # advertised (the Signer key + Envelope SHA above are the real provenance anchors; git
        # authorship is spoofable by design, so it is credit, not authority). sender_name/email
        # are already sanitized by unpack() (envelope.sanitize_text) — strip again here as
        # defense in depth, so a newline can never reach `git commit --author` even if a future
        # caller builds `env` some other way.
        author = sanitize_text(f"{env.manifest.sender_name} <{env.manifest.sender_email}>")
        subprocess.run(["git", "commit", "-m", msg, "--author", author],
                       cwd=repo, check=True, capture_output=True, text=True)
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                              capture_output=True, text=True)
        print(f"applied + committed {len(accepted)} piece(s), author credited to "
              f"{env.manifest.sender_name}")
        # The owner's VERIFIED receipt — asserted only now, after a real verify+apply.
        from scpe import label as _label
        print(_label.verified_receipt(env, commit=head.stdout.strip(),
                                      identity_ok=(ids["status"] == "verified")))
    return 0 if accepted_all else 2


def _repo_name(source: str) -> str:
    """Last path/URL component of a repo source, `.git` stripped — the default `pull` dest."""
    tail = source.replace("\\", "/").rstrip("/").split("/")[-1]
    if tail.endswith(".git"):
        tail = tail[:-4]
    return tail or "workspace"


def _cmd_analyze(args) -> int:
    backend = _backends.make_backend(args.backend)
    with tempfile.TemporaryDirectory(prefix="cc-analyze-") as wd:
        try:
            report = _analyze(args.repo, backend, workdir=Path(wd))
        except (ContributeError, RepoError) as exc:
            print(f"analyze failed: {exc}", file=sys.stderr)
            return 1
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"repo:    {report['repo']}")
        print(f"base:    {report['base_sha']}")
        print(f"backend: {report['backend']}")
        print(f"grade:   {report['grade']}")
        print(f"summary: {report['summary']}")
        print(f"issues ({len(report['issues'])}):")
        for i, issue in enumerate(report["issues"], start=1):
            print(f"  {i}. {issue.get('title', '')}")
            files = issue.get("files") or []
            if files:
                print(f"     files: {', '.join(str(f) for f in files)}")
    return 0


_ATTESTATION_DISCLAIMER = (
    "An AI review by the named backend plus any checks it ran (the repo's own test "
    "suite, bandit, ruff — see the signed `checks` field), NOT a formal security "
    "certification — carries no diff and credits nobody. Standard in-toto Statement "
    "in a DSSE envelope, verifiable by any DSSE tool (e.g. cosign) without scpe "
    "installed. Honesty note: the repo under audit can embed prompt-injection text "
    "aimed at nudging the model's own verdict — no wrapping can make an LLM audit "
    "immune to that. The real backstops are scpe's deterministic gates (never "
    "a clean 'accept' on high-signal added code alone), the owner's own independent "
    "re-verify, and the sandbox — not the model's word."
)


def _cmd_attest(args) -> int:
    backend = _backends.make_backend(args.backend)
    try:
        # Auditor credit is bound to a VERIFIABLE GitHub identity — the same rule the
        # contributor's envelope follows (resolve_local_identity): every attestation carries
        # a GitHub identifier, never a free-typed auditor name. --key is the SSH signing key.
        ident = resolve_local_identity(key_path=args.key)
    except IdentityError as exc:
        print(f"attest failed: {exc}", file=sys.stderr)
        return 1
    # The DSSE/Ed25519 seal is unchanged: a persistent Ed25519 key at the default path
    # (--key is now the SSH key). The GitHub SSH identity, not this key, is who the verifier
    # confirms; the Ed25519 signature keeps the attestation cosign/standard-DSSE verifiable.
    pem = load_or_create_key(DEFAULT_KEY)
    checks = None
    with tempfile.TemporaryDirectory(prefix="cc-attest-") as wd:
        try:
            report = _analyze(args.repo, backend, workdir=Path(wd))
        except (ContributeError, RepoError) as exc:
            print(f"attest failed: {exc}", file=sys.stderr)
            return 1
        if not args.no_checks:
            # `analyze()` clones the repo to workdir/"clone" (see analyze.py) — the
            # clone is still on disk here, inside this `with` block, before the
            # tempdir is discarded when it exits.
            checks = run_checks(Path(wd) / "clone")
    statement = build_statement(
        repo_url=report["repo"], base_sha=report["base_sha"], auditor_name=ident.name,
        auditor_email=noreply_email(ident.login, ident.user_id),
        auditor_pubkey_hex=public_key_hex(pem), backend_label=report["backend"],
        created_at_iso=datetime.now(timezone.utc).isoformat(), report_dict=report,
        checks=checks)
    try:
        # Stamp + SSH-sign the auditor identity BEFORE the DSSE seal, so the Ed25519
        # signature also covers ssh_sig (mirrors pack's attach-then-seal ordering).
        attach_ssh_auditor(statement, login=ident.login, user_id=ident.user_id,
                           pubkey=ident.pubkey, key_path=ident.key_path)
    except IdentityError as exc:
        print(f"attest failed: {exc}", file=sys.stderr)
        return 1
    envelope = sign_attestation(statement, pem)
    out = save_attestation(envelope, Path(args.out))
    predicate = statement["predicate"]
    print(f"attestation written: {out}  (repo={report['repo']} verdict={predicate['verdict']} "
          f"findings={predicate['findingsCount']} backend={report['backend']})", file=sys.stderr)
    print(f"attested as @{ident.login}", file=sys.stderr)
    if checks is not None:
        print(f"checks: {summarize_checks(checks)}", file=sys.stderr)
    print(_ATTESTATION_DISCLAIMER, file=sys.stderr)
    return 0


def _auditor_identity_status(statement: dict) -> dict:
    """Classify an attestation's AUDITOR GitHub identity for the reader, mirroring
    _identity_status for a contribution: verified (ssh_sig checks out against the account's
    GitHub keys), failed (claimed but does NOT verify — spoof/tamper), unchecked (couldn't
    reach GitHub), or legacy (no identity claimed). Fail-closed."""
    predicate = statement.get("predicate") or {}
    login = predicate.get("github_login") or ""
    profile = f"https://github.com/{login}" if login else ""
    if predicate.get("sig_method") != "ssh-github":
        return {"status": "legacy", "login": "", "profile": "",
                "detail": "no GitHub identity claimed (legacy attestation)"}
    try:
        ident = verify_auditor_identity(statement)
    except IdentityError as exc:
        return {"status": "unchecked", "login": login, "profile": profile,
                "detail": f"could not reach GitHub ({exc})"}
    if ident is None:
        return {"status": "failed", "login": login, "profile": profile,
                "detail": "signature did NOT verify against the account's GitHub keys"}
    return {"status": "verified", "login": ident.login,
            "profile": f"https://github.com/{ident.login}", "detail": ""}


def _print_auditor_identity(ids: dict) -> None:
    if ids["status"] == "legacy":
        print(f"auditor id: none - {ids['detail']}")
    elif ids["status"] == "verified":
        print(f"auditor:    @{ids['login']} - {ids['profile']}  "
              f"(github identity: verified)")
    elif ids["status"] == "failed":
        print(f"auditor:    @{ids['login']} - {ids['profile']}  "
              f"(github identity: UNVERIFIED - {ids['detail']})")
    else:  # unchecked
        print(f"auditor:    @{ids['login']} - {ids['profile']}  "
              f"(github identity: unchecked - {ids['detail']})")


def _cmd_verify_attest(args) -> int:
    try:
        envelope = load_attestation(args.file)
    except AttestationFormatError as exc:
        print(f"invalid attestation: {exc}", file=sys.stderr)
        return 1
    valid = verify_attestation(envelope, expected_pubkey_hex=args.key)
    try:
        statement = parse_statement(envelope)
    except AttestationFormatError as exc:
        print(f"invalid attestation: {exc}", file=sys.stderr)
        return 1
    subject = (statement.get("subject") or [{}])[0]
    predicate = statement.get("predicate") or {}
    auditor = predicate.get("auditor") or {}
    report = predicate.get("report") or {}
    base_sha = (subject.get("digest") or {}).get("gitCommit")
    key = auditor.get("publicKey") or ""
    auditor_ids = _auditor_identity_status(statement)

    commit_note = None
    if args.repo:
        repo = Path(args.repo)
        if (repo / ".git").exists():
            proc = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                  capture_output=True, text=True)
            head = proc.stdout.strip()
            if proc.returncode == 0 and head and base_sha and head != base_sha:
                commit_note = f"local HEAD {head} differs from audited commit {base_sha}"

    checks = predicate.get("checks")  # None (omitted) if the attester skipped checks

    result = {
        "signature_valid": valid,
        "repo": subject.get("name"),
        "base_sha": base_sha,
        "auditor_name": auditor.get("name"),
        "auditor_key": (key[:16] + "…") if key else "",
        "auditor_identity": auditor_ids,
        "created_at": predicate.get("createdAt"),
        "backend": predicate.get("backend"),
        "grade": report.get("grade"),
        "verdict": predicate.get("verdict"),
        "findings_count": predicate.get("findingsCount"),
        "checks": checks,
        "commit_note": commit_note,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"signature_valid: {valid}")
        print(f"repo:       {result['repo']}")
        print(f"base_sha:   {result['base_sha']}")
        _print_auditor_identity(auditor_ids)
        print(f"signer:     {result['auditor_name']}  key={result['auditor_key']}")
        print(f"created_at: {result['created_at']}")
        print(f"backend:    {result['backend']}")
        print(f"grade:      {result['grade']}")
        print(f"verdict:    {result['verdict']}  ({result['findings_count']} finding(s))")
        if isinstance(checks, list):
            print(f"checks:     {summarize_checks(checks)}")
        if commit_note:
            print(f"note:       {commit_note}")
    print(_ATTESTATION_DISCLAIMER, file=sys.stderr)
    return 0 if valid else 2


def _cmd_pull(args) -> int:
    dest = Path(args.dest) if args.dest else Path(_repo_name(args.repo))
    try:
        ws = _ws_pull(args.repo, dest)
    except (WorkspaceError, RepoError) as exc:
        print(f"pull failed: {exc}", file=sys.stderr)
        return 1
    print(f"workspace: {ws}")
    print(f"edit your files, then seal them with: scpe pack --workspace {ws}")
    return 0


def _cmd_pack(args) -> int:
    # AI-free by default: a backend is built ONLY when asked, and even then it just writes
    # the owner-facing briefing — the human is the author of the diff. Credit is bound to a
    # verifiable GitHub identity (gh CLI login + the scpe SSH signing key, which must
    # be registered on GitHub); pack refuses to seal without one.
    backend = _backends.make_backend(args.backend) if args.backend else None
    try:
        ident = resolve_local_identity(key_path=args.key)
        out = _ws_pack(Path(args.workspace), out_path=Path(args.out),
                       identity=ident, backend=backend)
    except (WorkspaceError, IdentityError) as exc:
        print(f"pack failed: {exc}", file=sys.stderr)
        return 1
    env = unpack(out)
    print(f"envelope written: {out}  ({len(env.pieces)} piece(s), "
          f"signed as @{env.manifest.github_login})", file=sys.stderr)
    return 0


def _cmd_inspect(args) -> int:
    try:
        report = inspect_envelope(args.envelope)
    except EnvelopeFormatError as exc:
        print(f"invalid envelope: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"repo:       {report['repo']}")
        print(f"base:       {report['base_sha']}")
        if report.get("identity_method") == "ssh-github" and report.get("github_login"):
            print(f"contributor: @{report['github_login']} - {report['github_profile']}  "
                  f"(claimed; run `verify` to confirm)")
        else:
            print(f"sender:     {report['sender']}")
        print(f"key:        {report['sender_key']}")
        print(f"created_at: {report['created_at']}")
        print(f"protocol:   {report['protocol']}")
        print(f"backend:    {report['backend']}")
        print(f"signature_valid: {report['signature_valid']}")
        risk = report.get("risk") or {}
        flags = "; ".join(sorted({f"{f['pattern']} ({f['file']}:{f['line']})"
                                  for f in risk.get("flags") or []}))
        print(f"risk:       {risk.get('band', '?')}" + (f"  [{flags}]" if flags else ""))
        print(f"pieces ({len(report['pieces'])}):")
        for p in report["pieces"]:
            files = ", ".join(p["files"])
            line = f"  {p['id']}: {p['title']}  +{p['added']}/-{p['removed']}  risk={p.get('risk_band', '?')}"
            print(line + (f"  [{files}]" if files else ""))
    # Exit 2 (not 0, not 1) is a distinct signal for CI: the envelope PARSED fine but its
    # signature does not verify — a tampered/unsigned envelope, not an operational error.
    return 0 if report["signature_valid"] else 2


# ---- seal (the verification seal + machine results.json) --------------------

def _derive_provenance(env) -> str:
    """The 'made with' line, read offline from the envelope's provenance. A hand-authored
    pack (backend 'none') must NEVER read as AI-assisted; only claim AI when AI was used."""
    prov = env.provenance if isinstance(env.provenance, dict) else {}
    backend = prov.get("backend")
    base = f"AI-assisted ({backend})" if backend and str(backend).lower() != "none" \
        else "hand-authored"
    sv = prov.get("self_verify")
    if isinstance(sv, dict) and sv.get("passed") is True:
        base += ", self-verified"
    return base


def _pytest_summary(output_tail: str) -> str:
    """Pull the runner's own summary line (e.g. '35 passed in 0.1s') from its output, so
    the seal reports the real counts, not a made-up phrase."""
    for line in reversed([ln.strip() for ln in output_tail.splitlines() if ln.strip()]):
        low = line.lower()
        if ("passed" in low or "failed" in low or "error" in low) and any(c.isdigit() for c in line):
            return line.strip("= ").strip()
    return ""


def _diff_already_applied(repo: Path, diff: str) -> bool:
    """True if `diff` reverse-applies to `repo` — i.e. the change is already present. The
    native-PR flow checks out a branch that already contains the contribution, so applying
    the diff again fails; this lets the seal test the branch as-is instead of failing false."""
    if not diff.strip():
        return False
    with tempfile.TemporaryDirectory(prefix="cc-revcheck-") as td:
        patch = Path(td) / "p.patch"
        patch.write_bytes(diff.encode("utf-8"))
        proc = subprocess.run(
            ["git", "-C", str(repo), "apply", "--reverse", "--check", str(patch)],
            capture_output=True, text=True)
    return proc.returncode == 0


def _seal_tests_field(args, env) -> dict:
    """Run the target's OWN suite over the envelope's diff in the sandbox when --run-tests is
    set; otherwise stay honest — a test that never ran is reported 'not run', never 'passed'."""
    if not args.run_tests:
        return {"ran": False, "ok": False, "summary": "not run"}
    combined = "".join(p.diff if p.diff.endswith("\n") else p.diff + "\n" for p in env.pieces)
    repo = Path(args.repo)
    res = run_in_sandbox(repo, combined, test_cmd=detect_test_cmd(repo))
    if not res.applied and _diff_already_applied(repo, combined):
        # native PR: the branch already carries the change — run its tests as-is.
        res = run_in_sandbox(repo, "", test_cmd=detect_test_cmd(repo))
    if not res.applied:
        return {"ran": False, "ok": False, "summary": "diff did not apply to --repo"}
    if not res.tests_ran:
        return {"ran": False, "ok": False, "summary": "no test runner detected"}
    summary = _pytest_summary(res.output_tail) or ("passed" if res.passed else "failed")
    return {"ran": True, "ok": res.passed, "summary": summary}


def _seal_results(env, args) -> dict:
    """The machine-readable seal the Action hands between its untrusted and trusted jobs.
    `verified` describes the PERSON (identity vs GitHub keys), never the code; the risk band
    is computed deterministically over the diff and can be HIGH on a verified contributor."""
    # verify_envelope_identity is the module-level name so a test can inject the check offline.
    ident = verify_envelope_identity(env)
    login = getattr(ident, "login", None) or env.manifest.github_login
    combined = "\n".join(p.diff for p in env.pieces)
    band = risk_band(combined)
    added = removed = 0
    files: list[str] = []
    for p in env.pieces:
        a, r = _count_changes(p.diff)
        added += a
        removed += r
        for f in p.target_files:
            if f not in files:
                files.append(f)
    return {
        "login": login,
        "verified": ident is not None,
        "band": band["band"],
        "flags": band["flags"],
        "matched": band["matched"],
        "rules_checked": band["rules_checked"],
        "added": added,
        "removed": removed,
        "files": files,
        "tests": _seal_tests_field(args, env),
        "provenance": _derive_provenance(env),
        "hook": "",
    }


def _render_comment(results: dict) -> str:
    """The PR comment, SHORT by default: the shields pill + a one-line verdict a maintainer
    reads in 5 seconds. The full ASCII seal box is collapsed behind <details> so it never
    becomes wall-of-text spam (the #1 reason a maintainer removes a bot)."""
    tests = results.get("tests") or {}
    tests_ok = bool(tests.get("ok"))
    login = results.get("login") or ""
    verified = bool(results.get("verified"))
    band = results["band"]
    box = pr_seal(
        login=login, verified=verified,
        profile=f"https://github.com/{login}" if login else "",
        band=band, flags=results.get("flags") or [],
        added=results.get("added", 0), removed=results.get("removed", 0),
        files=results.get("files") or [], tests_ok=tests_ok,
        tests_summary=tests.get("summary", "not run"),
        provenance=results.get("provenance", ""), hook=results.get("hook", ""))
    comment = (
        pr_pill(band, login, verified, tests_ok) + "\n\n"
        + pr_summary_line(band, verified, tests_ok)
        + "\n\n<details><summary>full report</summary>\n\n```\n" + box + "\n```\n\n"
        + "Risk is a published, weightless rule set — reproduce every band with "
        + "`scpe seal <envelope> --repo . --json`.\n</details>")
    ai = results.get("ai_recheck")
    if isinstance(ai, dict) and ai.get("verdict"):
        comment += f"\n\n_AI re-check ({ai.get('backend', '')}): {ai['verdict']}_"
    return comment


def _ai_recheck_stub(results: dict) -> dict | None:
    """Owner-LLM re-check — a STUB that only fires when a real backend is configured (not the
    default mock). It never fabricates a pass/fail verdict; a clean 'accept' from the model
    alone is exactly the thing scpe refuses to lean on. Offline: it constructs the
    backend to confirm it's wired, but makes no model call in this build."""
    kind = os.environ.get("SCPE_BACKEND", "").lower()
    if not kind or kind == "mock":
        return None
    try:
        backend = _backends.make_backend(kind)
    except _backends.BackendConfigError:
        return None
    return {"backend": backend.label,
            "verdict": "configured (stub — no model call in this build)"}


def _cmd_seal(args) -> int:
    # --from-results: operate on a prior results.json (the trusted job's render/re-check),
    # no envelope needed. Kept separate from the envelope path so the untrusted job produces
    # the JSON and the trusted job only ever consumes it.
    if args.from_results:
        try:
            results = json.loads(Path(args.from_results).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"cannot read results: {exc}", file=sys.stderr)
            return 1
        if args.ai_recheck:
            verdict = _ai_recheck_stub(results)
            if verdict is not None:
                results["ai_recheck"] = verdict
                print(json.dumps(results))
            # No backend configured -> no-op, nothing appended (honest, not a fake verdict).
            return 0
        if args.render_comment:
            print(_render_comment(results))
            return 0
        print(json.dumps(results))
        return 0

    if not args.envelope:
        print("seal needs an <envelope> (or --from-results FILE)", file=sys.stderr)
        return 1
    try:
        env = unpack(args.envelope)
    except EnvelopeFormatError as exc:
        print(f"invalid envelope: {exc}", file=sys.stderr)
        return 1
    results = _seal_results(env, args)
    if args.json:
        print(json.dumps(results))
    else:
        print(_render_comment(results))
    return 0


# ---- submit (open a native PR carrying the envelope) ------------------------

def _repo_slug(repo_url: str) -> str:
    """owner/name from a GitHub repo URL (or an already-slug string); '' if not derivable."""
    s = repo_url.strip().replace("https://", "").replace("http://", "")
    s = s.replace("git@github.com:", "github.com/").rstrip("/")
    if s.endswith(".git"):
        s = s[:-4]
    if s.startswith("github.com/"):
        s = s[len("github.com/"):]
    parts = s.split("/")
    return f"{parts[0]}/{parts[1]}" if len(parts) == 2 and all(parts) else ""


def _cmd_submit(args) -> int:
    if shutil.which("gh") is None:
        print("gh CLI not found — install GitHub CLI (https://cli.github.com) and run "
              "`gh auth login`, then re-run `scpe submit`.", file=sys.stderr)
        return 1
    try:
        env = unpack(args.envelope)
    except EnvelopeFormatError as exc:
        print(f"invalid envelope: {exc}", file=sys.stderr)
        return 1
    m = env.manifest
    login = m.github_login
    if m.sig_method != "ssh-github" or not login:
        print("submit needs a GitHub-signed (ssh-github) envelope — repack with "
              "`scpe pack`.", file=sys.stderr)
        return 1
    repo = args.repo or _repo_slug(m.repo_url)
    if not repo:
        print("could not determine the target repo from the envelope — pass --repo owner/name.",
              file=sys.stderr)
        return 1
    env_sha = hashlib.sha256(Path(args.envelope).read_bytes()).hexdigest()
    branch = f"scpe/{login}-{env_sha[:8]}"
    # The commit is authored with the contributor's GitHub no-reply email so GitHub links the
    # PR to their account without leaking a real address. sanitize as defense in depth.
    author = sanitize_text(f"{m.sender_name} <{noreply_email(login, m.github_id)}>")
    titles = "; ".join(p.title for p in env.pieces) or "contribution"
    title = f"scpe: {titles}"[:100]
    import base64
    from scpe import label as _label
    bands = [risk_band(p.diff)["band"] for p in env.pieces]
    band = "HIGH" if "HIGH" in bands else ("MED" if "MED" in bands else "LOW")
    card = _label.contribution_label(env, filename=Path(args.envelope).name, risk=band)
    env_b64 = base64.b64encode(Path(args.envelope).read_bytes()).decode()
    body = (
        "The change is in **Files changed** above, like any PR.\n\n"
        "```\n" + card + "\n```\n\n"
        "It carries a signed scpe envelope: portable proof of who authored it and how. "
        "The maintainer-side scpe Action re-verifies the identity against "
        f"github.com/{login}.keys and posts a seal. Nothing lands until you merge.\n\n"
        "<!-- scpe-envelope:v1\n" + env_b64 + "\n-->\n"
    )
    with tempfile.TemporaryDirectory(prefix="cc-submit-") as td:
        work = Path(td) / "repo"
        subprocess.run(["gh", "repo", "clone", repo, str(work)],
                       check=True, capture_output=True, text=True)
        subprocess.run(["git", "-C", str(work), "checkout", "-b", branch],
                       check=True, capture_output=True, text=True)
        # Apply the contribution's diff onto the branch so the PR shows the REAL code change
        # in "Files changed" — a native, reviewable PR — instead of an opaque envelope blob.
        combined = "".join(p.diff if p.diff.endswith("\n") else p.diff + "\n" for p in env.pieces)
        patch = Path(td) / "contribution.patch"
        # Write bytes, not text: on Windows `write_text` translates \n -> \r\n, which corrupts
        # the unified diff and makes `git apply` fail. The diff must keep its LF line endings.
        patch.write_bytes(combined.encode("utf-8"))
        ap = subprocess.run(["git", "-C", str(work), "apply", "--index", str(patch)],
                            capture_output=True, text=True)
        if ap.returncode != 0:
            print(f"the contribution does not apply cleanly onto {repo} (its base may have "
                  f"moved): {ap.stderr.strip()}", file=sys.stderr)
            return 1
        # The envelope is NOT committed to the branch — it rides in the PR body (base64) so the
        # merge keeps the owner's repo CLEAN (no binary blob in their history). The Action
        # extracts it from the PR body to verify; the durable credit is the authored commit +
        # this PR record. `git apply --index` already staged the code change.
        subprocess.run(["git", "-C", str(work), "commit", "-m", title, "--author", author],
                       check=True, capture_output=True, text=True)
        # A repo the contributor OWNS takes the branch directly; anyone else's goes through a
        # fork + cross-fork PR (you cannot fork your own repo).
        same_owner = repo.split("/")[0].lower() == login.lower()
        if same_owner:
            subprocess.run(["git", "-C", str(work), "push", "--force", "origin", branch],
                           check=True, capture_output=True, text=True)
            head = branch
        else:
            subprocess.run(["gh", "repo", "fork", repo, "--remote", "--remote-name", "fork"],
                           cwd=str(work), check=True, capture_output=True, text=True)
            subprocess.run(["git", "-C", str(work), "push", "--force", "fork", branch],
                           check=True, capture_output=True, text=True)
            head = f"{login}:{branch}"
        proc = subprocess.run(
            ["gh", "pr", "create", "--repo", repo, "--head", head,
             "--title", title, "--body", body],
            cwd=str(work), capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"gh pr create failed: {proc.stderr.strip()}", file=sys.stderr)
        return 1
    url = proc.stdout.strip()
    print(f"opened PR: {url}" if url else "opened PR")
    return 0


def _cmd_label(args) -> int:
    from scpe import label as _label
    name = Path(args.artifact).name
    try:
        if name.endswith(".json"):
            stmt = parse_statement(load_attestation(args.artifact))
            print(_label.attestation_label(stmt, filename=name))
        else:
            env = unpack(args.artifact)
            bands = [risk_band(p.diff)["band"] for p in env.pieces]
            band = "HIGH" if "HIGH" in bands else ("MED" if "MED" in bands else "LOW")
            print(_label.contribution_label(env, filename=name, risk=band))
    except (EnvelopeFormatError, AttestationFormatError) as exc:
        print(f"cannot read {args.artifact}: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_extract(args) -> int:
    """Explode an envelope into the open, any-language-readable form: envelope.json (the
    full manifest + pieces) and contribution.patch (the combined unified diff). No scpe
    needed to read the result — see docs/format.md."""
    from scpe.envelope import to_dict
    try:
        env = unpack(args.envelope)
    except EnvelopeFormatError as exc:
        print(f"cannot read {args.envelope}: {exc}", file=sys.stderr)
        return 1
    out = Path(args.dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "envelope.json").write_text(
        json.dumps(to_dict(env), indent=2, ensure_ascii=False), encoding="utf-8")
    combined = "".join(p.diff if p.diff.endswith("\n") else p.diff + "\n" for p in env.pieces)
    (out / "contribution.patch").write_text(combined, encoding="utf-8", newline="\n")
    print(f"extracted to {out}: envelope.json + contribution.patch", file=sys.stderr)
    print(f"  read it in any language; apply with:  git apply "
          f"{out / 'contribution.patch'}", file=sys.stderr)
    return 0


def _cmd_changes(args) -> int:
    try:
        print(_summarize_changes(args.envelope))
    except EnvelopeFormatError as exc:
        print(f"invalid envelope: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_init(args) -> int:
    changed = init_repo(Path(args.repo), repo_url=args.url)
    print("badge added" if changed else "already opted in")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scpe",
        description="Owner-verified crowd contributions via a signed Envelope + zero-trust handshake.")
    parser.add_argument("--version", action="version", version=f"scpe {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="create (or show) your signing key; prints the PUBLIC key")
    kg.add_argument("--key", default=str(DEFAULT_KEY))
    kg.set_defaults(fn=_cmd_keygen)

    ct = sub.add_parser("contribute", help="analyze a repo and emit a signed envelope of fixes")
    ct.add_argument("repo")
    ct.add_argument("--out", default="envelope.zip")
    ct.add_argument("--backend", default=None, choices=[None, "mock", "openai"])
    ct.add_argument("--key", default=None,
                    help="SSH signing key (default ~/.ssh/scpe_ed25519); must be "
                         "registered on your GitHub account")
    ct.set_defaults(fn=_cmd_contribute)

    vf = sub.add_parser("verify", help="owner handshake: re-prove an envelope before accepting")
    vf.add_argument("envelope")
    vf.add_argument("--repo", required=True)
    vf.add_argument("--trust", default="strict", choices=list(TRUST_LEVELS))
    vf.add_argument("--backend", default=None, choices=[None, "mock", "openai"])
    vf.add_argument("--json", action="store_true")
    vf.add_argument("--apply", action="store_true")
    vf.add_argument("--test-cmd", default=None,
                    help="owner override for the sandbox test command, as a shell-style "
                         "string (e.g. --test-cmd 'npm test --silent'); default: auto-detect "
                         "from the repo (.scpe/verify.json, then language markers — "
                         "pyproject.toml/package.json/Cargo.toml/go.mod/Makefile)")
    vf.add_argument("--disclosure", default="full",
                    choices=["full", "signoff", "minimal", "bare"],
                    help="commit-trailer style to match the target repo's AI policy: "
                         "full (Assisted-By + provenance); signoff (kernel-style human "
                         "Signed-off-by + Assisted-by); minimal (provenance only, no AI "
                         "trailer — for repos that ban them, e.g. Kubernetes); bare (no "
                         "trailers). The contributor is always the git author.")
    vf.set_defaults(fn=_cmd_verify)

    an = sub.add_parser("analyze",
        help="read-only council: grade a repo and brief its top issues (no fix, no envelope)")
    an.add_argument("repo")
    an.add_argument("--backend", default=None, choices=[None, "mock", "openai"])
    an.add_argument("--json", action="store_true")
    an.set_defaults(fn=_cmd_analyze)

    at = sub.add_parser("attest",
        help="sign a universal, tool-independent audit record (in-toto+DSSE) — no diff, "
             "no credit; an LLM-based read, not a formal security certification",
        description="Analyze a repo and sign a standard in-toto Statement in a DSSE "
             "envelope: '<repo> at <commit> was audited by <key> on <date>, verdict "
             "clean/N-findings'. Ships no diff and credits nobody — the opposite of "
             "`contribute`. This is an AI review plus any checks it ran, NOT a formal "
             "security certification. By default also signs a `checks` field with "
             "results from the repo's own test suite plus bandit/ruff (whichever are "
             "installed), run in a sandbox — a check that never ran is never reported "
             "as passed; see --no-checks. Verifiable by any DSSE tool (e.g. cosign), "
             "independent of scpe.")
    at.add_argument("repo")
    at.add_argument("--out", default="attestation.intoto.json")
    at.add_argument("--backend", default=None, choices=[None, "mock", "openai"])
    at.add_argument("--key", default=None,
                    help="SSH signing key for the auditor's GitHub identity (default "
                         "~/.ssh/scpe_ed25519); must be registered on your GitHub "
                         "account. The DSSE Ed25519 seal uses the default scpe key.")
    at.add_argument("--no-checks", action="store_true",
                    help="skip running bandit/ruff/the repo's own test suite as "
                         "signed evidence (fast path / offline) — the attestation "
                         "still signs fine, it just carries no `checks` evidence")
    at.set_defaults(fn=_cmd_attest)

    va = sub.add_parser("verify-attest",
        help="verify a DSSE-signed audit attestation (standard in-toto/DSSE — no "
             "scpe-specific trust needed)")
    va.add_argument("file")
    va.add_argument("--repo", default=None,
                    help="local git repo to compare HEAD against the audited commit")
    va.add_argument("--json", action="store_true")
    va.add_argument("--key", default=None,
                    help="expected auditor public key (64-hex); pin it instead of trusting "
                         "the key embedded in the attestation")
    va.set_defaults(fn=_cmd_verify_attest)

    pl = sub.add_parser("pull", help="clone a repo into a local workspace to edit by hand")
    pl.add_argument("repo")
    pl.add_argument("--dest", default=None, help="workspace dir (default ./<repo-name>)")
    pl.set_defaults(fn=_cmd_pull)

    pk = sub.add_parser("pack",
        help="seal your workspace's manual changes into a signed envelope (AI-free)")
    pk.add_argument("--workspace", default=".")
    pk.add_argument("--out", default="envelope.zip")
    pk.add_argument("--key", default=None,
                    help="SSH signing key (default ~/.ssh/scpe_ed25519); must be "
                         "registered on your GitHub account")
    pk.add_argument("--backend", default=None, choices=[None, "mock", "openai"],
                    help="optional: only used to write the owner-facing briefing")
    pk.set_defaults(fn=_cmd_pack)

    ins = sub.add_parser("inspect", help="read an envelope safely: no clone, no sandbox, no backend")
    ins.add_argument("envelope")
    ins.add_argument("--json", action="store_true")
    ins.set_defaults(fn=_cmd_inspect)

    sl = sub.add_parser("seal",
        help="render the verification seal for an envelope (human seal + machine results.json)")
    sl.add_argument("envelope", nargs="?", help="envelope .zip (omit when using --from-results)")
    sl.add_argument("--repo", default=".",
                    help="local checkout the diff/tests run against (default: .)")
    sl.add_argument("--json", action="store_true",
                    help="emit the machine-readable results.json instead of the human seal")
    sl.add_argument("--run-tests", action="store_true",
                    help="apply the envelope in a sandbox and run the repo's own test suite")
    sl.add_argument("--from-results", default=None,
                    help="render/re-check from a prior results.json instead of an envelope")
    sl.add_argument("--render-comment", action="store_true",
                    help="with --from-results: print the full markdown PR comment")
    sl.add_argument("--ai-recheck", action="store_true",
                    help="with --from-results: append an owner-LLM verdict IF a backend is set")
    sl.set_defaults(fn=_cmd_seal)

    sm = sub.add_parser("submit",
        help="open a native GitHub PR carrying the signed envelope (requires the gh CLI)")
    sm.add_argument("envelope")
    sm.add_argument("--repo", default=None,
                    help="target owner/name (default: derived from the envelope's repo_url)")
    sm.set_defaults(fn=_cmd_submit)

    lb = sub.add_parser("label",
        help="print a standardized plain-text confirmation label for an envelope or "
             "attestation — the ASCII card that rides with the artifact for easy "
             "by-eye verification")
    lb.add_argument("artifact", help="envelope .zip or attestation .json")
    lb.set_defaults(fn=_cmd_label)

    ex = sub.add_parser("extract",
        help="explode an envelope into the open, any-language form: envelope.json + "
             "contribution.patch (no scpe needed to read it — see docs/format.md)")
    ex.add_argument("envelope")
    ex.add_argument("--dir", default="extracted", help="output directory (default ./extracted)")
    ex.set_defaults(fn=_cmd_extract)

    ch = sub.add_parser("changes",
        help="human-readable summary of what an envelope modifies (read-only, owner-facing)")
    ch.add_argument("envelope")
    ch.set_defaults(fn=_cmd_changes)

    it = sub.add_parser("init", help="add the machine-detectable opt-in badge to a repo's README")
    it.add_argument("--repo", default=".")
    it.add_argument("--url", default=None, help="repo URL for the badge link (default: origin)")
    it.set_defaults(fn=_cmd_init)

    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except subprocess.CalledProcessError as exc:
        print(f"git failed: {exc.stderr}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
