"""Smoke test for the scpe GitHub Action wiring, including require/gate mode.

The load-bearing security property is the two-job untrusted/trusted split:
the `pull_request`-triggered job runs the contributor's code with NO secrets,
and the `workflow_run`-triggered job (which never runs untrusted code) is the
one that holds write access and posts the seal comment. This test parses both YAML
files and asserts that split holds, so a careless edit can't quietly wire a
secret into the untrusted job.

require/gate mode ("only verifiable contributions merge") sits ON TOP of that
split and must not weaken it: the require DECISION is computed in the
untrusted job (from the verification result, no secrets involved) and handed
to the trusted job purely as data (results.json); the trusted job only ever
READS that decision to post a pass/fail comment — it never re-derives a
security-relevant verdict from raw contributor input, and it never gives the
untrusted job write access to get there.

Two things changed with the move to the spec format, and both are asserted below.
The Action no longer downloads anything: it runs the package straight out of its own
checkout (`PYTHONPATH=${{ github.action_path }}`), so the bytes that verify are the
bytes of the tag the caller pinned rather than whatever the index served that minute.
And the comment is now rendered in the untrusted job. That does not move the trust
boundary — the trusted job already posted a string derived from attacker-controlled
data (that is exactly what level 1 does) — it moves the ESCAPING obligation onto the
renderer, which tests/test_seal_render.py holds to it.
"""
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_ACTION = _ROOT / "action.yml"
# The split is TWO FILES, not two jobs in one file, and that is load-bearing: a workflow
# that names itself in `workflow_run.workflows` fails to REGISTER — GitHub shows the file
# path where the name belongs and every run dies at the workflow level with zero jobs.
# Measured on a live repo. So the untrusted and trusted halves are asserted separately,
# each against the file it actually ships in.
_WORKFLOW = _ROOT / "docs" / "workflows" / "scpe.yml"
_SEAL_WORKFLOW = _ROOT / "docs" / "workflows" / "scpe-seal.yml"


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _dump(obj) -> str:
    return yaml.safe_dump(obj)


def _run_script() -> str:
    return _load(_ACTION)["runs"]["steps"][0]["run"]


def _level_1_block(run_script: str) -> str:
    start = run_script.find('if [ "${{ inputs.level }}" = "1" ]')
    assert start >= 0, "the level==1 branch disappeared"
    end = run_script.find("\nfi", start)
    assert end > start
    return run_script[start:end]


def _level_2_block(run_script: str) -> str:
    """Everything after the `level != 2` guard closes — the signed-envelope path."""
    guard = run_script.find('if [ "${{ inputs.level }}" != "2" ]')
    assert guard >= 0, "the unsupported-level guard disappeared"
    end = run_script.find("\nfi", guard)
    assert end > guard
    return run_script[end:]


def _seal_invocation_pos(run_script: str) -> int:
    """Where the sealer is actually invoked. It used to be findable by searching for
    `inputs.require`, but require now rides in through the step's env: block like every
    other attacker-adjacent value, so the anchor is the command itself."""
    pos = run_script.find("scpe.cli")
    assert pos >= 0, "the level-2 branch no longer runs the packaged sealer"
    return pos


def test_both_files_are_valid_yaml():
    action = _load(_ACTION)
    workflow = _load(_WORKFLOW)
    assert isinstance(action, dict)
    assert isinstance(workflow, dict)


def test_composite_action_loads_and_is_a_thin_wrapper():
    action = _load(_ACTION)
    assert action["runs"]["using"] == "composite"
    # The action delegates to the CLI, not a bespoke CI script. The invocation is now
    # `python3 -m scpe.cli seal` rather than a `scpe seal` console script, because a
    # console script implies an install and an install implies a package index.
    dump = _dump(action)
    assert "scpe.cli" in dump
    assert "seal" in dump


def _triggers(workflow: dict) -> dict:
    """The `on:` block. PyYAML reads a bare `on:` key as the boolean True (YAML 1.1
    treats on/off as booleans), so it is not reachable under the string "on"."""
    block = workflow.get("on", workflow.get(True))
    assert isinstance(block, dict), "the workflow must declare a trigger block"
    return block


def _one_job(workflow: dict, trigger: str) -> dict:
    """The single job in a file whose only trigger is `trigger`. The trigger lives on
    the FILE now — a job-level `if: github.event_name == ...` would be dead weight."""
    triggers = _triggers(workflow)
    assert list(triggers) == [trigger], (
        f"expected this file to be triggered only by {trigger}, got {list(triggers)}")
    jobs = workflow["jobs"]
    assert len(jobs) == 1, f"expected exactly one job in the {trigger} file"
    return next(iter(jobs.values()))


def _pull_request_job() -> dict:
    return _one_job(_load(_WORKFLOW), "pull_request")


def _workflow_run_job() -> dict:
    return _one_job(_load(_SEAL_WORKFLOW), "workflow_run")


def test_pull_request_job_has_no_secret_reference():
    workflow = _load(_WORKFLOW)
    untrusted = _pull_request_job()
    # Match the Actions `secrets.` context, not the prose "no secrets" in a step
    # name. The untrusted job must never touch a secret.
    assert "secrets." not in _dump(untrusted)


def test_pull_request_job_runs_seal_json_and_uploads_an_artifact():
    workflow = _load(_WORKFLOW)
    untrusted = _pull_request_job()
    steps = untrusted["steps"]
    # The seal runs either inline (`... seal ... --json`) or via the published
    # Marketplace composite action, which runs exactly that internally and emits
    # results.json. Either form satisfies "the untrusted job computes the verdict".
    ran_seal = any(
        ("seal" in str(s.get("run", "")) and "--json" in str(s.get("run", "")))
        or "augbastos/scpe@" in str(s.get("uses", ""))
        for s in steps
    )
    assert ran_seal, "untrusted job must run the scpe seal (inline --json or the Action)"
    uploads = any("upload-artifact" in str(s.get("uses", "")) for s in steps)
    assert uploads, "untrusted job must upload an artifact"


def test_untrusted_job_checks_out_deep_enough_to_recompute_the_diff():
    """A SPEC §9 attestation carries no diff: integrity is checked against
    `git diff <base>...<head>` recomputed from the checkout. actions/checkout defaults to
    `fetch-depth: 1`, which does not contain the base commit — so with the default, every
    signed PR would report `tampered` and the level-2 seal would be structurally incapable
    of proving anything. The sample workflow has to say so out loud."""
    workflow = _load(_WORKFLOW)
    untrusted = _pull_request_job()
    checkouts = [s for s in untrusted["steps"] if "actions/checkout" in str(s.get("uses", ""))]
    assert checkouts, "the untrusted job must check the repository out"
    with_block = checkouts[0].get("with") or {}
    assert str(with_block.get("fetch-depth")) == "0", (
        "checkout needs fetch-depth: 0 so the base commit exists locally")
    # ...and it still must not persist the token into .git/config.
    assert with_block.get("persist-credentials") is False


def test_workflow_run_job_is_the_trusted_comment_poster():
    trusted = _workflow_run_job()
    # It is the job that holds write access ...
    assert (trusted.get("permissions") or {}).get("pull-requests") == "write"
    # ... and the job that posts the PR comment. (It no longer references `secrets.` at
    # all: the optional owner-LLM re-check was a stub that never called a model, and it
    # was the only secret in the file.)
    posts_comment = any(
        "gh pr comment" in str(s.get("run", "")) for s in trusted["steps"]
    )
    assert posts_comment, "workflow_run job must post the seal comment"


def test_trusted_job_never_runs_contributor_code_or_installs_anything():
    """Its whole safety argument is that it holds a write token and executes nothing from
    the PR. Downloading a package at run time would break that: `pipx run --spec` resolves
    the newest release at that moment, inside the job that can comment as the repository."""
    trusted = _workflow_run_job()
    blob = _dump(trusted)
    assert "pipx" not in blob
    assert "pip install" not in blob
    assert "actions/checkout" not in blob


def test_the_two_jobs_are_distinct():
    assert _pull_request_job() is not _workflow_run_job()


# ---- require/gate mode ------------------------------------------------------


def test_require_input_exists_and_defaults_to_false():
    action = _load(_ACTION)
    require = action["inputs"]["require"]
    assert require["default"] == "false", "gate mode must be opt-in, not opt-out"


def test_verify_job_wires_require_input_to_the_composite_action():
    workflow = _load(_WORKFLOW)
    untrusted = _pull_request_job()
    seal_steps = [s for s in untrusted["steps"]
                  if "augbastos/scpe@" in str(s.get("uses", ""))]
    assert len(seal_steps) == 1, "expected exactly one call into the scpe Action"
    assert "require" in (seal_steps[0].get("with") or {}), \
        "the require input must be explicitly wired through, not silently dropped"


def test_require_decision_is_computed_in_the_untrusted_action_not_the_trusted_job():
    # The gate decision is made where the verification result is: the untrusted step
    # hands `--require` to the sealer, which writes gate_pass into results.json...
    run_script = _run_script()
    assert "--require" in run_script
    assert "gate_pass" in _dump(_load(_ACTION))

    # ...and the trusted job must never re-derive that verdict itself: it may
    # only ever READ a precomputed gate_pass out of the artifact.
    trusted_blob = _dump(_workflow_run_job())
    assert "unattested" not in trusted_blob, \
        "trusted job must not recompute the verification status"
    assert "gate_pass" in trusted_blob, \
        "trusted job must read the precomputed require decision"


def test_trusted_job_fails_the_check_and_posts_the_not_verifiable_comment():
    trusted = _workflow_run_job()
    blob = _dump(trusted)
    assert "Not verifiable" in blob
    assert "scpe/0.1" in blob
    # Gating on gate_pass must actually fail the job (not just comment), or the
    # "check" never blocks a merge.
    assert "exit 1" in blob


def test_untrusted_job_never_holds_pull_requests_write():
    workflow = _load(_WORKFLOW)
    untrusted = _pull_request_job()
    # Neither the job's own permissions block nor (by extension, since the job
    # doesn't override it) the workflow-level default may grant write access to
    # pull requests — require mode must never need the untrusted job to post.
    job_perms = untrusted.get("permissions") or {}
    assert job_perms.get("pull-requests") != "write"
    workflow_perms = workflow.get("permissions") or {}
    if "permissions" not in untrusted:
        assert workflow_perms.get("pull-requests") != "write"


def test_require_is_passed_as_a_value_not_branched_on():
    """require used to fork the script into two nearly identical `pipx` calls, one of
    which hardcoded `status=n/a` and threw the real verdict away. The sealer now always
    emits the §8 status and computes the gate itself, so there is one code path and
    `require` is data."""
    run_script = _run_script()
    assert '$REQUIRE' in run_script, "require must reach the sealer through env"
    assert 'if [ "${{ inputs.require }}"' not in run_script
    assert "status=n/a" not in run_script


# ---- level 1: zero-friction AI-disclosure lint -------------------------------


def test_level_input_exists_and_defaults_to_the_full_seal():
    action = _load(_ACTION)
    level = action["inputs"]["level"]
    # "2" (the full envelope/signature seal) must stay the DEFAULT, so every
    # existing caller that never set `level` keeps today's exact behavior.
    assert level["default"] == "2"


def test_level_1_branch_exists_and_is_checked_before_the_existing_flow():
    run_script = _run_script()
    assert 'inputs.level' in run_script
    assert '"1"' in run_script
    # The level==1 check must come BEFORE the sealer runs, so a level=1 caller never
    # falls through into the envelope-based flow at all.
    level_pos = run_script.find('inputs.level')
    assert 0 <= level_pos < _seal_invocation_pos(run_script), \
        "level must be branched on before the signed-envelope flow runs"


def test_no_level_ever_invokes_pipx():
    """Level 1 never needed an install; level 2 no longer does either. The Action runs the
    package from its own checkout, so a runner executes the exact bytes of the pinned tag
    instead of the newest thing on the index — inside a job that runs a stranger's code.

    The word "pipx" may still appear in an explanatory comment; what must never appear is
    a shell invocation of it, at any level.
    """
    for line in _run_script().splitlines():
        stripped = line.strip()
        assert not stripped.startswith("pipx"), f"the Action must never invoke pipx: {line!r}"
        assert not stripped.startswith("pip "), f"the Action must never pip install: {line!r}"


def test_the_sample_workflow_never_invokes_pipx_either():
    """docs/workflows/*.yml is what people copy. The trusted job used to `pipx run` the
    package twice — once for the AI re-check stub, once to render the comment."""
    for path in (_WORKFLOW, _SEAL_WORKFLOW):
        assert "pipx" not in path.read_text(encoding="utf-8"), path.name


def test_no_workflow_names_itself_in_workflow_run():
    """A workflow listed in its OWN `workflow_run.workflows` never registers: GitHub
    fails to parse it, displays the file path where the workflow name should be, and
    every run fails at the workflow level with zero jobs and "This run likely failed
    because of a workflow file issue". The shipped template did exactly that, so the
    fork-safe pattern the README tells people to copy could not run at all. Nothing in
    the suite caught it — `yaml.safe_load` is happy, and the failure only exists on
    GitHub's side. This is the cheap local guard for it."""
    for path in (_WORKFLOW, _SEAL_WORKFLOW):
        workflow = _load(path)
        named = _triggers(workflow).get("workflow_run", {}).get("workflows", [])
        assert workflow["name"] not in named, (
            f"{path.name} lists its own name ({workflow['name']!r}) in "
            "workflow_run.workflows — GitHub will refuse to register the file")


def test_the_seal_workflow_is_triggered_by_the_verify_workflow_by_name():
    """The two halves are coupled by NAME, not by filename. Renaming `name:` in one file
    without the other silently breaks the seal: the verify job still runs green and no
    comment is ever posted."""
    verify_name = _load(_WORKFLOW)["name"]
    seal = _load(_SEAL_WORKFLOW)
    assert verify_name in _triggers(seal)["workflow_run"]["workflows"], (
        "scpe-seal.yml must trigger on the workflow named in scpe.yml")


def test_the_trusted_job_can_read_the_sibling_runs_artifact():
    """download-artifact@v4 reaching ACROSS runs (`run-id:`) needs `actions: read`. A
    job-level permissions block REPLACES the workflow default rather than merging with
    it, so omitting it here sets actions to none, the download fails, and the gate never
    runs — a failure mode that looks like "the seal is flaky", not like a typo."""
    trusted = _workflow_run_job()
    downloads = [s for s in trusted["steps"]
                 if "download-artifact" in str(s.get("uses", ""))]
    assert downloads, "the trusted job must fetch the untrusted job's results"
    assert "run-id" in (downloads[0].get("with") or {}), \
        "the artifact lives in the sibling run, so run-id is required"
    assert (trusted.get("permissions") or {}).get("actions") == "read"


def test_level_1_runs_from_the_action_checkout():
    block = _level_1_block(_run_script())
    assert "level1_lint.py" in block
    assert "github.action_path" in block


def test_level_2_runs_the_package_from_the_action_checkout():
    """The same anchor level 1 has always used. This is only possible because the package
    is stdlib-only now (tests/test_package_is_stdlib_only.py) — with a dependency it would
    need an install step and the guarantee would be gone."""
    block = _level_2_block(_run_script())
    assert "github.action_path" in block
    assert "scpe.cli" in block
    assert "results.json" in block


def test_level_1_never_holds_secrets_either():
    # The level-1 branch is part of the same untrusted composite action step as
    # the existing full-seal flow — it must uphold the same "no secrets" property.
    action_blob = _dump(_load(_ACTION))
    assert "secrets." not in action_blob


def test_level_1_fail_message_is_exact_and_present_in_the_action():
    action_blob = _dump(_load(_ACTION))
    assert "Missing AI-use disclosure" in action_blob


def test_level_1_reference_scripts_exist_on_disk():
    # github.action_path resolution depends on these files actually shipping in the
    # repo at the paths action.yml references.
    assert (_ROOT / "reference" / "disclosure.py").is_file()
    assert (_ROOT / "reference" / "level1_lint.py").is_file()


def test_level_2_scripts_exist_on_disk_too():
    assert (_ROOT / "scpe" / "cli.py").is_file()
    assert (_ROOT / "reference" / "standalone" / "verify_envelope.py").is_file()


def test_trusted_job_reads_optional_fail_message_and_comment_without_recomputing():
    # The FAIL message and the informational comment are both computed upstream in the
    # untrusted action (fail_message / comment keys in results.json) — the trusted job
    # must only ever READ them. Level 2 now fills both in as well, so the trusted job's
    # fallback path is a safety net rather than the normal case.
    trusted = _workflow_run_job()
    blob = _dump(trusted)
    assert "fail_message" in blob
    assert "get('comment')" in blob or 'get("comment")' in blob


def test_seal_step_never_inlines_pull_request_context_into_the_shell_script():
    # Attacker-controlled PR fields (body, base/head SHA) come from a fork and must
    # NEVER be interpolated directly into the run: script text — GitHub substitutes
    # `${{ ... }}` unescaped before bash parses it, so a PR body like  x"; rm -rf /; echo "
    # would break out of the string literal and run arbitrary shell inside the
    # untrusted `verify` job (which then writes the results.json the trusted, write-
    # scoped `seal` job posts verbatim). They may reach the script ONLY via env,
    # exactly like docs/workflows/scpe.yml's envelope-extraction step. This mirrors
    # the "no secrets." guard above.
    seal_step = _load(_ACTION)["runs"]["steps"][0]
    run_script = seal_step["run"]
    assert "github.event.pull_request" not in run_script, (
        "PR context must be passed through the step's env: block and referenced as "
        "$PR_BODY / $BASE_SHA / $HEAD_SHA — never inlined into the run: script, which "
        "would let a hostile PR body inject shell into the untrusted job"
    )
    # And it must actually be wired through env instead — the safe idiom, not dropped.
    step_env = seal_step.get("env") or {}
    assert step_env.get("PR_BODY") == "${{ github.event.pull_request.body }}"
    assert step_env.get("BASE_SHA") == "${{ github.event.pull_request.base.sha }}"
    assert step_env.get("HEAD_SHA") == "${{ github.event.pull_request.head.sha }}"


def test_the_pr_body_never_becomes_an_argv_element():
    """Env is necessary but not sufficient: `--pr-body "$PR_BODY"` would put a megabyte of
    attacker-controlled text on the command line, visible in process listings and subject
    to every quoting rule in between. The sealer takes the NAME of the variable and reads
    it itself."""
    # The env: block still DEFINES PR_BODY — that is the point. What must not appear is
    # the expansion of its VALUE anywhere in the script.
    assert "$PR_BODY" not in _run_script()


def test_level_1_gate_pass_output_is_read_from_results_json_not_hardcoded():
    # Level 1's outputs must be READ from the results.json level1_lint.py wrote, since
    # level 1 can fail its own gate (require=true + disclosure absent).
    block = _level_1_block(_run_script())
    assert "results.json" in block
    assert "gate_pass" in block


def test_gate_pass_output_is_read_from_results_json_at_level_2_too():
    """It used to be hardcoded `true` on the require=false path, which meant the Action's
    own output disagreed with the file it emitted."""
    block = _level_2_block(_run_script())
    assert "gate_pass" in block
    assert "gate-pass=true" not in block


# ---- level contract: 1 / 2 implemented, 3 is roadmap ------------------------


def test_level_input_documents_the_cumulative_contract():
    # The input description is the contract callers actually read — it must state
    # that levels are cumulative (higher implies lower) and name all three levels,
    # including that 3 is roadmap/not implemented.
    action = _load(_ACTION)
    desc = action["inputs"]["level"]["description"]
    assert "cumulative" in desc or "implies" in desc
    assert "\"3\"" in desc or "level 3" in desc.lower()
    assert "roadmap" in desc.lower()
    assert "not implemented" in desc.lower()


def test_level_3_is_rejected_with_a_clear_roadmap_error_not_silently_treated_as_level_2():
    # A caller who sets level: "3" expecting third-party countersignature must get
    # an explicit, fatal failure — never a silent fall-through into the level-2
    # envelope flow, which would give a false sense of an assurance this Action
    # does not provide.
    run_script = _run_script()
    level1_start = run_script.find('if [ "${{ inputs.level }}" = "1" ]')
    level1_end = run_script.find("\nfi", level1_start)
    guard_start = run_script.find('if [ "${{ inputs.level }}" != "2" ]', level1_end)
    assert guard_start > level1_end >= 0, \
        "the level != 2 guard must exist and come after the level == 1 branch"
    guard_end = run_script.find("\nfi", guard_start)
    guard_block = run_script[guard_start:guard_end]
    assert "exit 1" in guard_block, "an unsupported level must fail the step, not just warn"
    assert "roadmap" in guard_block.lower()
    assert "docs/LEVELS.md" in guard_block
    # And this guard must run BEFORE any envelope work, i.e. before the sealer.
    assert _seal_invocation_pos(run_script) > guard_end >= 0


def test_level_2_implies_level_1_is_enforced_by_the_gate_not_by_the_verifier():
    """This used to be a structural property of the old envelope format: `provenance` was
    a required dataclass field with no default, so an envelope without a disclosure could
    not be parsed at all. The spec format has no such property — spec/manifest.schema.json
    requires `ai_disclosure`, but that schema is descriptive/advisory only, and
    reference/standalone/verify_envelope.py never reads the field.

    The claim is therefore re-imposed one layer up, where policy belongs: results.json
    carries `disclosure_present` and the gate acts on it. The behaviour itself is proved
    end to end in tests/test_level2_implies_level1.py — including the uncomfortable half,
    that the verifier alone WILL say `verified` for a manifest with no disclosure. All
    that is asserted here is that the documentation still describes the mechanism that
    actually exists."""
    levels_doc = (_ROOT / "docs" / "LEVELS.md").read_text(encoding="utf-8")
    assert "disclosure_present" in levels_doc, \
        "the doc must name the field the gate actually reads"
    # And it must not claim the verifier is what enforces it.
    assert "required part of the signed manifest" not in levels_doc, (
        "docs/LEVELS.md claims the verifier requires the disclosure; it does not — "
        "the gate does. See tests/test_level2_implies_level1.py")


def test_level_3_never_appears_as_a_working_path_only_as_documentation():
    # Level 3 (third-party countersignature) must never be wired into the actual
    # verification logic — it is roadmap-only. It may appear in comments/error
    # text (already asserted above), but not as a functioning branch that does
    # anything besides fail fast.
    run_script = _run_script()
    assert 'inputs.level }}" = "3"' not in run_script
    assert 'inputs.level }}" == "3"' not in run_script


# ---- fork-safety holds at every level ----------------------------------------


def test_fork_safety_holds_regardless_of_which_level_is_selected():
    # The whole point of levels is to vary WHAT gets checked, never WHO gets
    # write access. None of the three level branches (1, the level != 2 guard,
    # or the existing 2/require flow) may reference a secret or run with
    # elevated permissions — the untrusted job stays untrusted no matter which
    # level a caller picks.
    action = _load(_ACTION)
    action_blob = _dump(action)
    assert "secrets." not in action_blob
    assert "permissions" not in action, \
        "a composite action must never declare its own permissions block " \
        "(it would attempt to elevate beyond whatever the calling job grants)"

    workflow = _load(_WORKFLOW)
    untrusted = _pull_request_job()
    job_perms = untrusted.get("permissions") or {}
    assert job_perms.get("pull-requests") != "write"
    workflow_perms = workflow.get("permissions") or {}
    if "permissions" not in untrusted:
        assert workflow_perms.get("pull-requests") != "write"
    # This holds independent of the `level`/`require` values the caller passes
    # in `with:` — the untrusted job's permissions are fixed at the job level,
    # not derived from action inputs.
    seal_steps = [s for s in untrusted["steps"] if "augbastos/scpe@" in str(s.get("uses", ""))]
    assert len(seal_steps) == 1
    with_block = seal_steps[0].get("with") or {}
    # Sanity: the sample workflow's `with:` block only ever carries the inputs
    # this contract defines (require/level/etc.) — never a permissions escape
    # hatch such as a token override.
    assert "token" not in with_block and "github-token" not in with_block


# ---- docs/LEVELS.md -----------------------------------------------------------


def test_levels_doc_exists_and_covers_all_three_levels():
    levels_doc = (_ROOT / "docs" / "LEVELS.md").read_text(encoding="utf-8")
    assert "SLSA" in levels_doc
    assert "roadmap" in levels_doc.lower()
    for marker in ("level 1", "level 2", "level 3"):
        assert marker in levels_doc.lower()
    # It must be honest about what level 2 does NOT prove about "who" — the same
    # scoping THREAT_MODEL.md already states, not a stronger claim.
    assert "not implemented" in levels_doc.lower()
