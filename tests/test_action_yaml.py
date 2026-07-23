"""Smoke test for the scpe GitHub Action wiring, including require/gate mode.

The load-bearing security property is the two-job untrusted/trusted split:
the `pull_request`-triggered job runs the contributor's code with NO secrets,
and the `workflow_run`-triggered job (which never runs untrusted code) is the
one that holds secrets and posts the seal comment. This test parses both YAML
files and asserts that split holds, so a careless edit can't quietly wire a
secret into the untrusted job.

require/gate mode ("only verifiable contributions merge") sits ON TOP of that
split and must not weaken it: the require DECISION is computed in the
untrusted job (from the verification result, no secrets involved) and handed
to the trusted job purely as data (results.json); the trusted job only ever
READS that decision to post a pass/fail comment — it never re-derives a
security-relevant verdict from raw contributor input, and it never gives the
untrusted job write access to get there.
"""
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_ACTION = _ROOT / "action.yml"
_WORKFLOW = _ROOT / "docs" / "workflows" / "scpe.yml"


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _dump(obj) -> str:
    return yaml.safe_dump(obj)


def test_both_files_are_valid_yaml():
    action = _load(_ACTION)
    workflow = _load(_WORKFLOW)
    assert isinstance(action, dict)
    assert isinstance(workflow, dict)


def test_composite_action_loads_and_is_a_thin_wrapper():
    action = _load(_ACTION)
    assert action["runs"]["using"] == "composite"
    # The action delegates to the CLI, not a bespoke CI script.
    assert "scpe seal" in _dump(action)


def _pull_request_job(workflow: dict) -> dict:
    jobs = workflow["jobs"]
    matches = [j for j in jobs.values()
               if "pull_request" in str(j.get("if", ""))]
    assert len(matches) == 1, "expected exactly one pull_request-triggered job"
    return matches[0]


def _workflow_run_job(workflow: dict) -> dict:
    jobs = workflow["jobs"]
    matches = [j for j in jobs.values()
               if "workflow_run" in str(j.get("if", ""))]
    assert len(matches) == 1, "expected exactly one workflow_run-triggered job"
    return matches[0]


def test_pull_request_job_has_no_secret_reference():
    workflow = _load(_WORKFLOW)
    untrusted = _pull_request_job(workflow)
    # Match the Actions `secrets.` context, not the prose "no secrets" in a step
    # name. The untrusted job must never touch a secret.
    assert "secrets." not in _dump(untrusted)


def test_pull_request_job_runs_seal_json_and_uploads_an_artifact():
    workflow = _load(_WORKFLOW)
    untrusted = _pull_request_job(workflow)
    steps = untrusted["steps"]
    # The seal runs either inline (`scpe seal ... --json`) or via the published
    # Marketplace composite action, which runs exactly that internally and emits
    # results.json. Either form satisfies "the untrusted job computes the verdict".
    ran_seal = any(
        ("scpe seal" in str(s.get("run", "")) and "--json" in str(s.get("run", "")))
        or "augbastos/scpe@" in str(s.get("uses", ""))
        for s in steps
    )
    assert ran_seal, "untrusted job must run the scpe seal (inline --json or the Action)"
    uploads = any("upload-artifact" in str(s.get("uses", "")) for s in steps)
    assert uploads, "untrusted job must upload an artifact"


def test_workflow_run_job_is_the_trusted_comment_poster():
    workflow = _load(_WORKFLOW)
    trusted = _workflow_run_job(workflow)
    blob = _dump(trusted)
    # It holds a secret (the optional owner-LLM re-check) ...
    assert "secrets." in blob
    # ... and it is the job that posts the PR comment.
    posts_comment = any(
        "gh pr comment" in str(s.get("run", "")) for s in trusted["steps"]
    )
    assert posts_comment, "workflow_run job must post the seal comment"


def test_the_two_jobs_are_distinct():
    workflow = _load(_WORKFLOW)
    assert _pull_request_job(workflow) is not _workflow_run_job(workflow)


# ---- require/gate mode ------------------------------------------------------


def test_require_input_exists_and_defaults_to_false():
    action = _load(_ACTION)
    require = action["inputs"]["require"]
    assert require["default"] == "false", "gate mode must be opt-in, not opt-out"


def test_verify_job_wires_require_input_to_the_composite_action():
    workflow = _load(_WORKFLOW)
    untrusted = _pull_request_job(workflow)
    seal_steps = [s for s in untrusted["steps"]
                  if "augbastos/scpe@" in str(s.get("uses", ""))]
    assert len(seal_steps) == 1, "expected exactly one call into the scpe Action"
    assert "require" in (seal_steps[0].get("with") or {}), \
        "the require input must be explicitly wired through, not silently dropped"


def test_require_decision_is_computed_in_the_untrusted_action_not_the_trusted_job():
    # The classification logic ("unattested" vs "verified" vs "not-verified" and
    # the gate_pass boolean derived from it) lives in the untrusted composite
    # action — the one step that actually sees the verification result...
    action_blob = _dump(_load(_ACTION))
    assert "unattested" in action_blob
    assert "gate_pass" in action_blob

    # ...and the trusted job must never re-derive that verdict itself: it may
    # only ever READ a precomputed gate_pass out of the artifact.
    workflow = _load(_WORKFLOW)
    trusted_blob = _dump(_workflow_run_job(workflow))
    assert "unattested" not in trusted_blob, \
        "trusted job must not recompute the verification status"
    assert "gate_pass" in trusted_blob, \
        "trusted job must read the precomputed require decision"


def test_trusted_job_fails_the_check_and_posts_the_not_verifiable_comment():
    workflow = _load(_WORKFLOW)
    trusted = _workflow_run_job(workflow)
    blob = _dump(trusted)
    assert "Not verifiable" in blob
    assert "scpe/0.1" in blob
    # Gating on gate_pass must actually fail the job (not just comment), or the
    # "check" never blocks a merge.
    assert "exit 1" in blob


def test_untrusted_job_never_holds_pull_requests_write():
    workflow = _load(_WORKFLOW)
    untrusted = _pull_request_job(workflow)
    # Neither the job's own permissions block nor (by extension, since the job
    # doesn't override it) the workflow-level default may grant write access to
    # pull requests — require mode must never need the untrusted job to post.
    job_perms = untrusted.get("permissions") or {}
    assert job_perms.get("pull-requests") != "write"
    workflow_perms = workflow.get("permissions") or {}
    if "permissions" not in untrusted:
        assert workflow_perms.get("pull-requests") != "write"


def test_informational_default_path_is_unchanged_when_require_is_false():
    # require=false must still be the exact "informational seal" behavior: the
    # composite action's default-path branch calls `scpe seal --json` the same
    # way it always has, with no gate-only side effects gated behind it.
    action = _load(_ACTION)
    run_script = action["runs"]["steps"][0]["run"]
    assert 'inputs.require' in run_script
    assert '!= "true"' in run_script or "!= 'true'" in run_script


# ---- level 1: zero-friction AI-disclosure lint -------------------------------


def test_level_input_exists_and_defaults_to_the_full_seal():
    action = _load(_ACTION)
    level = action["inputs"]["level"]
    # "2" (the full envelope/signature seal) must stay the DEFAULT, so every
    # existing caller that never set `level` keeps today's exact behavior.
    assert level["default"] == "2"


def test_level_1_branch_exists_and_is_checked_before_the_existing_flow():
    action = _load(_ACTION)
    run_script = action["runs"]["steps"][0]["run"]
    assert 'inputs.level' in run_script
    assert '"1"' in run_script
    # The level==1 check must come BEFORE the require check that follows it, so a
    # level=1 caller never falls through into the envelope-based flow at all.
    level_pos = run_script.find('inputs.level')
    require_pos = run_script.find('inputs.require')
    assert 0 <= level_pos < require_pos, \
        "level must be branched on before the require/envelope flow runs"


def test_level_1_never_calls_pipx_or_installs_the_scpe_package():
    # The whole point of level 1 is zero friction: no envelope, no signing key, and
    # (unlike level 2) no `pipx run scpe` at all — just a stdlib script read
    # straight out of the action's own checkout.
    action = _load(_ACTION)
    run_script = action["runs"]["steps"][0]["run"]
    level_block_start = run_script.find('if [ "${{ inputs.level }}" = "1" ]')
    level_block_end = run_script.find("fi", level_block_start)
    level_block = run_script[level_block_start:level_block_end]
    # The word "pipx" may appear in an explanatory comment (see action.yml); what
    # must never appear is an actual shell invocation of the pipx binary — i.e. a
    # non-comment line whose first token is "pipx".
    for line in level_block.splitlines():
        stripped = line.strip()
        assert not stripped.startswith("pipx"), f"level 1 must never invoke pipx: {line!r}"
    assert "level1_lint.py" in level_block
    assert "github.action_path" in level_block


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


def test_trusted_job_reads_optional_fail_message_and_comment_without_recomputing():
    # For level=1, the FAIL message and the informational comment are both computed
    # upstream in the untrusted action (fail_message / comment keys in results.json)
    # — the trusted job must only ever READ them, falling back to the unchanged
    # level-2 defaults when those keys are absent (covered by
    # test_trusted_job_fails_the_check_and_posts_the_not_verifiable_comment).
    workflow = _load(_WORKFLOW)
    trusted = _workflow_run_job(workflow)
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


def test_level_1_gate_pass_output_is_read_from_results_json_not_hardcoded():
    # Unlike the require=false level-2 branch (which hardcodes gate-pass=true),
    # level 1's outputs must be READ from the results.json level1_lint.py wrote,
    # since level 1 can fail its own gate (require=true + disclosure absent).
    action = _load(_ACTION)
    run_script = action["runs"]["steps"][0]["run"]
    level_block_start = run_script.find('if [ "${{ inputs.level }}" = "1" ]')
    level_block_end = run_script.find("\n        fi", level_block_start)
    level_block = run_script[level_block_start:level_block_end]
    assert "results.json" in level_block
    assert "gate_pass" in level_block


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
    action = _load(_ACTION)
    run_script = action["runs"]["steps"][0]["run"]
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
    # And this guard must run BEFORE any envelope/pipx work, i.e. before the
    # require branches that follow.
    require_pos = run_script.find('inputs.require', guard_end)
    assert require_pos > guard_end >= 0


def test_level_2_structurally_requires_the_disclosure_field_no_default():
    # The claim "level 2 implies level 1 (L2 also checks disclosure)" has to be
    # true in code, not just prose: scpe.envelope.Envelope's `provenance` field
    # (the signed AI-disclosure) must be a required field with NO default, so a
    # `verified` level-2 envelope can never lack the equivalent of level 1's
    # disclosure signal.
    import dataclasses

    from scpe.envelope import Envelope

    fields = {f.name: f for f in dataclasses.fields(Envelope)}
    assert "provenance" in fields
    provenance_field = fields["provenance"]
    assert provenance_field.default is dataclasses.MISSING
    assert provenance_field.default_factory is dataclasses.MISSING  # type: ignore[comparison-overlap]

    # And from_dict() must actually enforce that at parse time — an envelope
    # missing "provenance" fails to load at all, before signature verification
    # ever runs, exactly like a missing manifest field would.
    from scpe.envelope import EnvelopeFormatError, from_dict

    incomplete = {
        "manifest": {
            "protocol_version": "1",
            "repo_url": "https://github.com/x/y",
            "base_sha": "0" * 40,
            "sender_public_key": "",
            "sender_name": "x",
            "sender_email": "x@example.com",
            "created_at": "2026-01-01T00:00:00Z",
        },
        "briefing_md": "",
        "pieces": [],
        # "provenance" deliberately omitted
    }
    try:
        from_dict(incomplete)
        raised = False
    except EnvelopeFormatError:
        raised = True
    assert raised, "an envelope missing provenance (the disclosure) must fail to parse"


def test_level_3_never_appears_as_a_working_path_only_as_documentation():
    # Level 3 (third-party countersignature) must never be wired into the actual
    # verification logic — it is roadmap-only. It may appear in comments/error
    # text (already asserted above), but not as a functioning branch that does
    # anything besides fail fast.
    action = _load(_ACTION)
    run_script = action["runs"]["steps"][0]["run"]
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
    untrusted = _pull_request_job(workflow)
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
