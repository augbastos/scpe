"""The envelope format that 0.2 removed must be REFUSED, cleanly, on every entry point.

Before 0.2 the installable package carried a second envelope format that was never in
SPEC.md: a zip built around `envelope.json` with its own `PROTOCOL_VERSION`, a signature
computed over a canonicalized *re-serialization* of the manifest, and a
`<!-- scpe-envelope:v1` marker for the pull-request-body transport. The protocol signs the
EXACT bytes of `manifest.json` with SSHSIG and canonicalizes nothing (SPEC §4/§7), so the
two formats were never interoperable — the Marketplace Action simply ran the old package
and therefore checked the old format.

That is not a hypothetical migration. Every repository still pinned to `@v0.1.x` keeps
emitting the retired shape, and its next run reaches a verifier that has never heard of it.
The one outcome this suite has to guarantee for those inputs is an HONEST STATE: status
`unattested`, the documented exit code, and no traceback. A stack trace here is a red X on
a stranger's pull request for a reason nobody in that repository can act on, and a crash in
the untrusted job destroys the results artifact the trusted job was waiting for.

Nothing is imported from the retired format — it does not exist any more. The fixtures are
literal bytes, built here, which is also why they stay valid: the verifier rejects them
through an ALLOWLIST (`_from_zip` accepts exactly manifest.json, manifest.sig, diff.patch,
artifact.bin), so what is being pinned is the rule, not a museum copy of dead member names.

A neighbour covers one slice of this already — test_results_contract.py asserts that a
retired-format zip handed to `scpe seal --envelope` still yields the full legacy
results.json. This file covers the other entry points (the reference verifier itself, the
`scpe verify` pass-through, `scpe inspect`, and the §9 body transport) and the signing
model, which is where the two formats actually disagree.
"""
from __future__ import annotations

import base64
import io
import json
import zipfile

from tests.conftest import ROOT, VECTORS, run_cli, run_verifier, seal_json

# The marker the retired format wrote into a pull request body. The spec's block is
# `<!-- SCPE-ATTESTATION-v1` and the verifier's scanner is case-sensitive, so this string
# matches nothing — which is the entire point of quoting it verbatim.
RETIRED_MARKER = "<!-- scpe-envelope:v1"

# Executable sources that ship. Scanned for residue of the retired format because a string
# literal HERE means running code still knows the shape — which is how the Marketplace
# Action ended up verifying the wrong format in the first place. Deliberately code-only:
# prose that names the retired format is exactly what migration notes are supposed to do,
# so documentation is not scanned and this test cannot punish someone for writing it down.
SHIPPED_SOURCES = (
    sorted((ROOT / "scpe").glob("*.py"))
    + sorted((ROOT / "reference").glob("*.py"))
    + sorted((ROOT / "reference" / "standalone").glob("*.py"))
)


def _retired_zip() -> bytes:
    """A zip in the retired shape: `envelope.json` carrying PROTOCOL_VERSION "1", plus a
    detached signature member. Member names are reconstructed, and deliberately so — the
    verifier never looks for these names, it refuses anything that is not the spec member
    set, so the assertion holds for any variant an old tag might have written."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("envelope.json", json.dumps({
            "PROTOCOL_VERSION": "1",
            "manifest": {"login": "octocat-test", "diff_sha256": "0" * 64},
            "signed_over": "canonicalized re-serialization",
        }))
        zf.writestr("signature", "not an SSHSIG")
    return buf.getvalue()


def _retired_body() -> str:
    """A pull request body as the retired producer wrote it: the same zip, base64'd inside
    the `scpe-envelope:v1` HTML comment. Real base64 of a real zip, so the fixture fails
    for the reason that matters (the block is not an SCPE attestation) and not because the
    payload was gibberish."""
    blob = base64.b64encode(_retired_zip()).decode("ascii")
    return ("## Fix add()\n\nOne-line fix.\n\n"
            f"{RETIRED_MARKER}\n{blob}\n-->\n")


def _clean(proc) -> None:
    """No traceback, on any path. An exception escaping the verifier is the failure mode
    this whole file exists to prevent, and it is invisible to a status assertion alone."""
    assert "Traceback" not in proc.stderr, proc.stderr[-2000:]


# ------------------------------------------------------------------ the zip transport

def test_a_retired_zip_is_unattested_through_the_reference_verifier(tmp_path):
    path = tmp_path / "contribution.zip"
    path.write_bytes(_retired_zip())

    proc = run_verifier(path)
    _clean(proc)
    data = json.loads(proc.stdout)
    assert data["status"] == "unattested", data
    assert proc.returncode == 1                  # exit 0 iff verified (SPEC §8)
    assert data["detail"], "an unreadable input must say what was wrong with it"
    # No key set was ever consulted, so no anchor may be claimed.
    assert data["key_source"] is None


def test_the_package_cli_reports_a_retired_zip_exactly_as_the_verifier_does(tmp_path):
    """`scpe verify` is a pass-through (test_verify_cli_parity pins that on the eighteen
    vectors). Parity on WELL-FORMED input is the easy half: a wrapper diverges on the
    inputs that fail early, where one path can raise while the other reports. So the same
    byte-for-byte comparison is made here, on the input an old pinned tag actually sends."""
    path = tmp_path / "contribution.zip"
    path.write_bytes(_retired_zip())

    direct = run_verifier(path)
    through = run_cli("verify", str(path), "--json", cwd=tmp_path)
    _clean(through)
    assert through.stdout.strip() == direct.stdout.strip()
    assert through.returncode == direct.returncode == 1


def test_a_retired_zip_is_not_rescued_by_a_real_keys_file(tmp_path):
    """The failure is structural, not a key problem. Pointing --keys at a key set that
    genuinely verifies other vectors must not move the verdict one step — otherwise a
    maintainer debugging a pinned repository would conclude the anchor was the issue."""
    path = tmp_path / "contribution.zip"
    path.write_bytes(_retired_zip())

    proc = run_verifier(path, keys=VECTORS / "valid-minimal" / "keys")
    _clean(proc)
    data = json.loads(proc.stdout)
    assert data["status"] == "unattested", data
    assert proc.returncode == 1


# ----------------------------------------------------------------- the body transport

def test_a_body_carrying_the_retired_marker_is_unattested(tmp_path):
    """SPEC §9 transport. The verifier scans for `SCPE-ATTESTATION-v1`; the retired marker
    is a different string, so the body reads as a pull request that carries no SCPE
    material at all — which is precisely what it is."""
    body = tmp_path / "pr_body.md"
    body.write_text(_retired_body(), encoding="utf-8")

    proc = run_verifier(body)
    _clean(proc)
    data = json.loads(proc.stdout)
    assert data["status"] == "unattested", data
    assert proc.returncode == 1
    assert data["key_source"] is None


def test_the_sealer_calls_a_retired_marker_body_a_state_not_an_error(tmp_path):
    """The runner's own command line, gate on. `unattested` is a §8 STATE: the step exits 0
    so the results artifact still reaches the trusted job, the gate closes because nothing
    was proven, and the trusted job is handed a message it can post verbatim."""
    body = _retired_body()
    data, rc = seal_json("--pr-body-env", "SCPE_PR_BODY", "--require", "true",
                         "--level", "2",
                         env_extra={"SCPE_PR_BODY": body, "PR_BODY": body}, cwd=tmp_path)

    assert rc == 0, data
    assert data["status"] == "unattested", data
    assert data["verified"] is False
    assert data["gate_pass"] is False
    assert data["fail_message"], "a closed gate must hand the trusted job a reason"
    assert data["key_source"] is None


# -------------------------------------------------------------------------- inspect

def test_inspect_reads_neither_retired_shape_and_says_so(tmp_path):
    """`scpe inspect` reports claims and never judges, so it exits 0 even here — but it has
    to answer `readable: false` rather than print an empty dump that a reader could mistake
    for "nothing to declare"."""
    zip_path = tmp_path / "contribution.zip"
    zip_path.write_bytes(_retired_zip())
    body_path = tmp_path / "pr_body.md"
    body_path.write_text(_retired_body(), encoding="utf-8")

    for path in (zip_path, body_path):
        proc = run_cli("inspect", str(path), "--json", cwd=tmp_path)
        _clean(proc)
        data = json.loads(proc.stdout)
        assert data["readable"] is False, (path.name, data)
        assert data["detail"]
        assert proc.returncode == 0


# ------------------------------------------------------------------- the signing model

def test_a_manifest_reserialized_the_way_the_retired_format_signed_it_is_invalid(tmp_path):
    """The deepest difference between the two formats, stated as a test.

    The retired format signed a canonicalized re-serialization, so re-emitting the manifest
    with different whitespace or key order left its signature intact. SCPE signs the exact
    bytes: `json.dumps(json.loads(...))` preserves every value and still breaks the
    signature. If this ever passes again, the old signing model has come back — and with it
    the class of attack where two byte strings that verify identically carry different JSON.
    """
    vector = VECTORS / "valid-minimal"
    work = tmp_path / "reserialized"
    work.mkdir()
    original = (vector / "manifest.json").read_bytes()
    reserialized = json.dumps(json.loads(original.decode("utf-8"))).encode("utf-8")
    assert reserialized != original, "fixture is void unless the bytes actually differ"

    (work / "manifest.json").write_bytes(reserialized)
    (work / "manifest.sig").write_bytes((vector / "manifest.sig").read_bytes())
    (work / "diff.patch").write_bytes((vector / "diff.patch").read_bytes())

    proc = run_verifier(work, keys=vector / "keys")
    _clean(proc)
    data = json.loads(proc.stdout)
    assert data["status"] == "signature-invalid", data
    assert proc.returncode == 1


# ------------------------------------------------------------------------ no residue

def test_no_shipped_source_still_knows_the_retired_format():
    """Rejection by allowlist, not by a branch someone can relax later. If `envelope.json`
    or the retired marker reappears in shipped code, a second format is being read again —
    which is exactly how the Marketplace Action ended up verifying the wrong one."""
    assert SHIPPED_SOURCES, "the source scan found nothing to scan — check the globs"
    for source in SHIPPED_SOURCES:
        text = source.read_text(encoding="utf-8")
        for residue in ("scpe-envelope:v1", "envelope.json", "PROTOCOL_VERSION"):
            assert residue not in text, (
                f"{source.name} still references {residue!r}. If this is running code, a "
                f"second format is being read again. If it is only a note about the "
                f"migration, it belongs in the release notes or under docs/ — shipped "
                f"modules should not have to explain a format they no longer implement.")


def test_the_fixture_marker_is_not_the_spec_block():
    """Guards the fixture itself: if someone 'fixes' RETIRED_MARKER into the real block,
    every test above would start feeding the verifier genuine material and quietly stop
    testing anything at all."""
    assert "SCPE-ATTESTATION-v1" not in RETIRED_MARKER
    assert "SCPE-ATTESTATION-v1" not in _retired_body()
