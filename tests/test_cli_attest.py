"""CLI wiring for `attest` / `verify-attest`. Same shape as test_cli_commands.py:
monkeypatch `backends.make_backend` to a canned MockBackend, drive everything through
`main([...])`, assert on exit code + the artifact produced. The auditor is now a verifiable
GitHub identity (not free-typed): `_patch_attest` injects a throwaway one and stubs the
auditor-identity check so the whole path runs offline."""
import base64
import json
import subprocess
from pathlib import Path

from scpe import cli
from scpe.cli import main
from scpe.identity import Identity
from tests.conftest import patch_cli_identity


def _canned_analyze(monkeypatch):
    from scpe import backends
    canned = {
        "ANALYZE": json.dumps({"issues": [
            {"title": "add() subtracts", "rationale": "planted bug", "files": ["demo/calc.py"]},
        ]}),
        "GRADE": json.dumps({"grade": "B", "summary": "solid, one real bug"}),
    }
    monkeypatch.setattr(backends, "make_backend", lambda kind=None: backends.MockBackend(canned))


def _patch_attest(monkeypatch, tmp_path: Path) -> str:
    """Inject a throwaway GitHub auditor identity (name 'Alice Auditor') and stub the
    verify-attest auditor check to 'verified' offline (no gh, no network). Returns the pubkey."""
    _ident, pub = patch_cli_identity(monkeypatch, tmp_path, login="alice-auditor",
                                     name="Alice Auditor")
    monkeypatch.setattr(cli, "verify_auditor_identity",
                        lambda statement, **k: Identity(login="alice-auditor", pubkey=pub))
    return pub


def test_cli_attest_writes_valid_dsse_envelope(fixture_repo: Path, tmp_path: Path, monkeypatch, capsys):
    _canned_analyze(monkeypatch)
    _patch_attest(monkeypatch, tmp_path)
    out = tmp_path / "a.intoto.json"
    rc = main(["attest", str(fixture_repo), "--out", str(out)])
    assert rc == 0
    assert out.exists()
    envelope = json.loads(out.read_text(encoding="utf-8"))
    assert envelope["payloadType"] == "application/vnd.in-toto+json"
    assert len(envelope["signatures"]) == 1
    err = capsys.readouterr().err
    assert "attestation written" in err
    assert "verdict=findings" in err
    assert "attested as @alice-auditor" in err


def test_cli_attest_clean_repo_signs_clean_verdict(fixture_repo: Path, tmp_path: Path,
                                                     monkeypatch, capsys):
    """The whole point of attestation: 'found nothing' is a positive signed deliverable,
    not a crash. A mock that reports zero issues must still produce a signed attestation
    with verdict 'clean' end-to-end."""
    from scpe import backends
    canned = {
        "ANALYZE": json.dumps({"issues": []}),
        "GRADE": json.dumps({"grade": "A", "summary": "nothing to flag"}),
    }
    monkeypatch.setattr(backends, "make_backend", lambda kind=None: backends.MockBackend(canned))
    _patch_attest(monkeypatch, tmp_path)
    out = tmp_path / "clean.intoto.json"
    rc = main(["attest", str(fixture_repo), "--out", str(out)])
    assert rc == 0
    assert out.exists()
    envelope = json.loads(out.read_text(encoding="utf-8"))
    assert len(envelope["signatures"]) == 1
    err = capsys.readouterr().err
    assert "verdict=clean" in err
    assert "findings=0" in err

    # Independently verifiable too.
    rc2 = main(["verify-attest", str(out), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert rc2 == 0
    assert data["signature_valid"] is True
    assert data["verdict"] == "clean"
    assert data["findings_count"] == 0


def test_cli_attest_and_verify_attest_roundtrip(fixture_repo: Path, tmp_path: Path, monkeypatch, capsys):
    _canned_analyze(monkeypatch)
    _patch_attest(monkeypatch, tmp_path)
    out = tmp_path / "a.intoto.json"
    assert main(["attest", str(fixture_repo), "--out", str(out)]) == 0
    capsys.readouterr()

    rc = main(["verify-attest", str(out)])
    out_text = capsys.readouterr().out
    assert rc == 0
    assert "signature_valid: True" in out_text
    assert "@alice-auditor" in out_text          # the verifiable GitHub auditor
    assert "Alice Auditor" in out_text           # display name in the signer line
    assert "verdict:    findings" in out_text


def test_cli_verify_attest_json(fixture_repo: Path, tmp_path: Path, monkeypatch, capsys):
    _canned_analyze(monkeypatch)
    _patch_attest(monkeypatch, tmp_path)
    out = tmp_path / "a.intoto.json"
    main(["attest", str(fixture_repo), "--out", str(out)])
    capsys.readouterr()
    assert main(["verify-attest", str(out), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["signature_valid"] is True
    assert data["findings_count"] == 1
    assert data["auditor_name"] == "Alice Auditor"
    assert data["auditor_identity"]["login"] == "alice-auditor"
    assert data["auditor_identity"]["status"] == "verified"


def test_cli_verify_attest_tampered_exit2(fixture_repo: Path, tmp_path: Path, monkeypatch):
    _canned_analyze(monkeypatch)
    _patch_attest(monkeypatch, tmp_path)
    out = tmp_path / "a.intoto.json"
    main(["attest", str(fixture_repo), "--out", str(out)])
    envelope = json.loads(out.read_text(encoding="utf-8"))
    envelope["signatures"][0]["sig"] = envelope["signatures"][0]["sig"][:-4] + "AAAA"
    out.write_text(json.dumps(envelope), encoding="utf-8")
    assert main(["verify-attest", str(out)]) == 2


def test_cli_verify_attest_wrong_expected_key_exit2(fixture_repo: Path, tmp_path: Path, monkeypatch):
    _canned_analyze(monkeypatch)
    _patch_attest(monkeypatch, tmp_path)
    out = tmp_path / "a.intoto.json"
    main(["attest", str(fixture_repo), "--out", str(out)])
    assert main(["verify-attest", str(out), "--key", "00" * 32]) == 2


def test_cli_verify_attest_bad_file_exit1(tmp_path: Path):
    junk = tmp_path / "junk.json"
    junk.write_bytes(b"not json at all")
    assert main(["verify-attest", str(junk)]) == 1


def test_cli_verify_attest_notes_commit_drift(fixture_repo: Path, tmp_path: Path, monkeypatch, capsys):
    _canned_analyze(monkeypatch)
    _patch_attest(monkeypatch, tmp_path)
    out = tmp_path / "a.intoto.json"
    main(["attest", str(fixture_repo), "--out", str(out)])
    capsys.readouterr()
    # Advance the repo past the audited commit.
    (fixture_repo / "demo" / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(fixture_repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(fixture_repo), "commit", "-m", "fix"],
                   check=True, capture_output=True)

    assert main(["verify-attest", str(out), "--repo", str(fixture_repo)]) == 0
    text = capsys.readouterr().out
    assert "differs from audited commit" in text


def test_cli_attest_runs_checks_by_default_and_prints_evidence_line(
        fixture_repo: Path, tmp_path: Path, monkeypatch, capsys):
    """Default path: attest signs the LLM verdict PLUS real, signed evidence from
    running the repo's own test suite (fixture_repo declares pytest.ini, see
    conftest.py) — the whole point of this feature."""
    _canned_analyze(monkeypatch)
    _patch_attest(monkeypatch, tmp_path)
    out = tmp_path / "a.intoto.json"
    rc = main(["attest", str(fixture_repo), "--out", str(out)])
    assert rc == 0
    err = capsys.readouterr().err
    assert "checks: tests=" in err

    envelope = json.loads(out.read_text(encoding="utf-8"))
    payload = json.loads(base64.standard_b64decode(envelope["payload"]))
    checks = payload["predicate"]["checks"]
    assert {c["tool"] for c in checks} == {"tests", "bandit", "ruff"}
    tests_check = next(c for c in checks if c["tool"] == "tests")
    assert tests_check["ran"] is True
    assert tests_check["passed"] in (True, False)
    for c in checks:
        if not c["ran"]:
            assert c["passed"] is None


def test_cli_attest_no_checks_flag_skips_evidence(fixture_repo: Path, tmp_path: Path,
                                                    monkeypatch, capsys):
    _canned_analyze(monkeypatch)
    _patch_attest(monkeypatch, tmp_path)
    out = tmp_path / "a.intoto.json"
    rc = main(["attest", str(fixture_repo), "--out", str(out), "--no-checks"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "checks:" not in err

    envelope = json.loads(out.read_text(encoding="utf-8"))
    payload = json.loads(base64.standard_b64decode(envelope["payload"]))
    assert "checks" not in payload["predicate"]

    rc2 = main(["verify-attest", str(out), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert rc2 == 0
    assert data["signature_valid"] is True
    assert data["checks"] is None


def test_cli_verify_attest_surfaces_checks_summary_line(
        fixture_repo: Path, tmp_path: Path, monkeypatch, capsys):
    _canned_analyze(monkeypatch)
    _patch_attest(monkeypatch, tmp_path)
    out = tmp_path / "a.intoto.json"
    main(["attest", str(fixture_repo), "--out", str(out)])
    capsys.readouterr()
    rc = main(["verify-attest", str(out)])
    text = capsys.readouterr().out
    assert rc == 0
    assert "checks:     tests=" in text


def test_cli_attest_no_credit_no_diff_help_text():
    """The attest command must be honest about scope in --help: it's an LLM read, not a
    certification, and it never ships a diff/credits nobody."""
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            main(["attest", "--help"])
    except SystemExit:
        pass
    text = buf.getvalue()
    assert "no diff" in text
    assert "credits nobody" in text
