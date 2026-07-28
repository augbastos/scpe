"""SCPE CLI — four commands over one verifier.

    scpe verify    prove a contribution (a pass-through to the reference verifier)
    scpe seal      the CI engine: verify, scan, test, and emit results.json
    scpe inspect   read what a manifest claims, prove nothing
    scpe init      stamp the machine-detectable opt-in badge on a repo

`verify` is deliberately a pass-through and not a wrapper: it forwards argv to
reference/standalone/verify_envelope.py's own `main()`, so its output bytes and its exit
code are the verifier's, not a reformatting of them. It exists only to give a zero-install
path (`pipx run --spec 'scpe-protocol>=0.2' scpe verify`) to someone who does not want to
clone the repo — running the single file directly stays the canonical, and cheaper, way.

Pin the floor. An unconstrained `--spec scpe-protocol` resolves to whatever is newest on
PyPI, and 0.1.2 is a different program: it carries the removed agent layer and verifies an
envelope format this repository no longer produces. It would not error — it would answer
about the wrong thing.

Stdlib only. That is what lets a CI job run this straight from a checkout
(`PYTHONPATH=<action_path> python3 -m scpe.cli seal ...`) with no install step, so the
bytes doing the verifying are the bytes of the tag the caller pinned.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from reference.standalone import verify_envelope as _ref
from scpe import (__version__, context as _context, results as _results, seal as _seal,
                  testrun, verify as _verify)
from scpe.optin import _DEFAULT_SITE, init_repo


# ---------------------------------------------------------------------------- verify

def _cmd_verify(args) -> int:
    """Forward to the reference verifier's own CLI. Nothing is re-formatted, re-judged or
    re-worded on the way through: same flags in, same bytes out, same exit code (0 if and
    only if the result is a pass). A test pins this parity, because the moment this command
    starts producing its own answer there are two verifiers to keep in step."""
    argv: list[str] = [args.path]
    for flag, value in (("--keys", args.keys), ("--diff", args.diff),
                        ("--artifact", args.artifact)):
        if value:
            argv += [flag, value]
    if args.json:
        argv.append("--json")
    return _ref.main(argv)


# ------------------------------------------------------------------------------ seal

def _tests_field(args, repo: str) -> dict:
    """Run the repo's own suite when asked, and stay honest when not: a suite that never
    ran is reported `not run`, never `passed`."""
    if not args.run_tests:
        return dict(testrun.NOT_RUN)
    return testrun.run_tests(Path(repo))


def _cmd_seal(args) -> int:
    """Produce results.json for the pull request in the current checkout.

    Exit code is 0 whenever a result was produced — including for a plain PR with no SCPE
    material at all, which SPEC §8 calls a STATE and not an error. The untrusted CI job that
    runs this has no write token; its only job is to hand a decision to the trusted job, so
    exiting non-zero here would destroy the artifact instead of reporting on it. Exit 1 is
    reserved for the operational failures that mean no result exists: an unreadable
    --from-results file, or output that cannot be written.
    """
    if args.from_results:
        try:
            data = json.loads(Path(args.from_results).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            print(f"cannot read results: {exc}", file=sys.stderr)
            return 1
        if args.json:
            if args.render_comment:
                data["comment"] = _seal.render_comment(data)
            print(json.dumps(data))
        else:
            print(_seal.render_comment(data))
        return 0

    with tempfile.TemporaryDirectory(prefix="scpe-seal-") as td:
        workdir = Path(td)
        resolved = _verify.resolve(
            workdir, envelope=args.envelope, attestation=args.attestation,
            pr_body_env=args.pr_body_env, repo=args.repo, base=args.base, head=args.head)
        result = _verify.run(resolved, keys=args.keys, artifact=args.artifact)
        diff = ""
        if resolved.diff is not None:
            diff = resolved.diff.read_text(encoding="utf-8", errors="replace")
        # Read the manifest for context ONLY after the signature verified. Before that it is
        # attacker-controlled JSON, and comparing an unauthenticated `target.repo` against
        # the checkout would be theatre — the attacker picks both sides.
        ctx = None
        if result.status == _results.VERIFIED and (args.expect_repo or args.expect_base):
            ctx = _context.check(
                manifest=_results.signed_manifest(resolved.path),
                repo_dir=Path(args.repo), head=args.head,
                expect_repo=args.expect_repo, expect_base=args.expect_base)
        data = _results.build_results(
            result, path=resolved.path, diff=diff, diff_source=resolved.diff_source,
            diff_note=resolved.note, context=ctx,
            # Parsed exactly like reference/level1_lint.py parses $REQUIRE, and deliberately
            # NOT an argparse `choices=` list: a caller who writes `require: True` in YAML
            # must get an informational run, not an argparse exit 2 that kills the untrusted
            # step and takes the whole artifact with it.
            require=str(args.require).strip().lower() == "true",
            level=args.level, tests=_tests_field(args, args.repo))

    # Rendered HERE, in the untrusted job, and carried inside results.json. This does not
    # weaken the fork-safe split: the trusted job already posts a string derived from
    # attacker-controlled input (that is exactly what the level-1 path does today), so the
    # trust level of the CONTENT is unchanged — only the place it is built moves. What moves
    # with it is the obligation to escape, which now sits in scpe/seal.py, where every
    # untrusted value passes through one sanitizer and one sized code fence.
    comment = _seal.render_comment(data) if (args.render_comment or not args.json) else ""
    if args.render_comment:
        data["comment"] = comment
    print(json.dumps(data) if args.json else comment)
    return 0


# --------------------------------------------------------------------------- inspect

def _cmd_inspect(args) -> int:
    """Read a manifest and report what it CLAIMS. No network, no signature check, no verdict.

    The difference from `verify` is the whole point of the command: this prints the claim, so
    it always exits 0 even when the claim is worthless. It cannot tell you the signature is
    good, and it says so on every run rather than letting a green-looking dump imply it."""
    path = Path(args.path)
    try:
        manifest_bytes, _sig, diff_bytes, _artifact, _keys = _ref.load_input(path)
        manifest = _ref.parse_manifest(manifest_bytes)
    except Exception as exc:                # noqa: BLE001 - report, never raise, never judge
        if args.json:
            print(json.dumps({"readable": False, "detail": str(exc)}))
        else:
            print(f"no readable SCPE manifest in {path}: {exc}")
        return 0

    identity = manifest.get("contributor") or {}
    identity = identity.get("identity") if isinstance(identity, dict) else {}
    identity = identity if isinstance(identity, dict) else {}
    subject_block = manifest.get("subject") if isinstance(manifest.get("subject"), dict) else {}
    diff = (diff_bytes or b"").decode("utf-8", errors="replace")
    band = _seal.risk_band(diff) if diff else {"band": "", "flags": [], "matched": []}
    out = {
        "readable": True,
        "spec_version": manifest.get("spec_version"),
        "provider": identity.get("provider"),
        "subject": identity.get("subject"),
        "subject_type": subject_block.get("type"),
        "ai_disclosure": manifest.get("ai_disclosure"),
        "profile": manifest.get("profile"),
        "attestations": _ref.attestations_summary(manifest),
        "risk": {"band": band["band"], "matched": band["matched"]},
        "signature": "not checked — run `scpe verify`",
    }
    if args.json:
        print(json.dumps(out))
        return 0

    print(f"spec_version   {out['spec_version']}")
    print(f"identity       {out['provider']}:{out['subject']}  (claimed, not verified)")
    print(f"subject.type   {out['subject_type']}")
    print(f"ai_disclosure  {json.dumps(out['ai_disclosure'])}")
    print(f"profile        {out['profile']}  (advisory, SPEC §13 — displayed, not dispatched)")
    for att in out["attestations"]:
        print(f"attestation    {att['type']} = {att['status']}")
    if diff:
        matched = ", ".join(band["matched"]) or "no rules matched"
        print(f"risk           {band['band']}  ({matched}; Action-layer aid, not the spec)")
    print("signature      not checked — run `scpe verify` for a verdict")
    return 0


# ------------------------------------------------------------------------------ init

def _cmd_init(args) -> int:
    changed = init_repo(Path(args.repo), site=args.site)
    print("badge added to README.md" if changed else "already opted in — README unchanged")
    return 0


# ------------------------------------------------------------------------------- cli

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scpe",
        description="SCPE — verifiable provenance for a contribution: who produced it, "
                    "and that it was not altered. Offline, no server, no new account.")
    parser.add_argument("--version", action="version", version=f"scpe {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    vf = sub.add_parser("verify",
        help="verify a contribution (pass-through to the single-file reference verifier)")
    vf.add_argument("path", help="envelope zip, vector directory, or a file holding an "
                                 "SCPE-ATTESTATION-v1 block (e.g. a saved PR body)")
    vf.add_argument("--keys", default=None,
                    help="use this file as the published key list instead of fetching "
                         "(offline verification; the only key source for provider=local)")
    vf.add_argument("--diff", default=None,
                    help="verify integrity against this diff (attestation form, where the "
                         "diff is not enclosed and comes from the pull request)")
    vf.add_argument("--artifact", default=None,
                    help="artifact bytes to check an `artifact` subject against")
    vf.add_argument("--json", action="store_true")
    vf.set_defaults(fn=_cmd_verify)

    sl = sub.add_parser("seal",
        help="the CI engine: verify a PR, scan its diff, run its tests, emit results.json")
    sl.add_argument("--envelope", default=None,
                    help="path to an SCPE envelope zip committed on the PR")
    sl.add_argument("--attestation", default=None,
                    help="path to a file holding an SCPE-ATTESTATION-v1 block")
    sl.add_argument("--pr-body-env", default=_verify.PR_BODY_ENV,
                    help=f"environment variable holding the PR body, read when neither "
                         f"--envelope nor --attestation is given (default: "
                         f"{_verify.PR_BODY_ENV}). The body travels by environment and "
                         f"never as an argument.")
    sl.add_argument("--repo", default=".", help="the checkout to diff and test (default: .)")
    sl.add_argument("--base", default="", help="base commit of the pull request")
    sl.add_argument("--head", default="", help="head commit of the pull request")
    sl.add_argument("--keys", default=None,
                    help="offline key list; forces key_source=flag, which the seal displays")
    sl.add_argument("--artifact", default=None, help="artifact bytes for an `artifact` subject")
    sl.add_argument("--expect-repo", default=None, metavar="OWNER/NAME",
                    help="require the manifest's signed target.repo to be this repository, "
                         "case-insensitively. Without it the signed target is reported and "
                         "never compared, which lets a valid envelope from another "
                         "repository verify here. CI should always pass it.")
    sl.add_argument("--expect-base", action="store_true",
                    help="require the manifest's signed base_sha to be an ancestor of "
                         "--head. Ancestry rather than equality: the base branch tip moves "
                         "whenever anything merges, while the commit the contributor "
                         "diffed from does not.")
    sl.add_argument("--run-tests", action="store_true",
                    help="run the repo's own test suite in this checkout")
    sl.add_argument("--require", default="false",
                    help="gate mode: 'true' makes anything short of a verified, disclosed "
                         "contribution a failing check. The DECISION is computed here and "
                         "handed over in results.json; the trusted job only reads it.")
    sl.add_argument("--level", default="2", choices=["1", "2"],
                    help="assurance level stamped into results.json. Level 1 (disclosure "
                         "lint) is produced by reference/level1_lint.py, not by this command.")
    sl.add_argument("--json", action="store_true", help="emit results.json on stdout")
    sl.add_argument("--render-comment", action="store_true",
                    help="also build the markdown PR comment (into the `comment` field "
                         "with --json, else printed)")
    sl.add_argument("--from-results", default=None,
                    help="render from a prior results.json instead of verifying again")
    sl.set_defaults(fn=_cmd_seal)

    ins = sub.add_parser("inspect",
        help="read what a manifest claims — no network, no signature check, no verdict")
    ins.add_argument("path")
    ins.add_argument("--json", action="store_true")
    ins.set_defaults(fn=_cmd_inspect)

    it = sub.add_parser("init", help="add the machine-detectable opt-in badge to a repo's README")
    it.add_argument("--repo", default=".")
    it.add_argument("--site", default=_DEFAULT_SITE,
                    help="where the badge image is served from. No reason to change it unless "
                         "you mirror the project; it exists so no domain is welded in without "
                         "an escape hatch.")
    it.set_defaults(fn=_cmd_init)

    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except subprocess.CalledProcessError as exc:
        print(f"git failed: {exc.stderr}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
