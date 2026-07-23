"""MCP server tool handlers — exercised DIRECTLY as plain functions, no live MCP
transport (mirrors test_cli_commands.py's canned-MockBackend pattern). Handlers must
import and run fine whether or not the optional `mcp` SDK is installed; only the
server-wiring tests at the bottom require it and skip cleanly when it's absent."""
import json
import subprocess
from pathlib import Path

import pytest

from scpe import mcp_server
from scpe.envelope import unpack, verify_envelope_identity, verify_signature
from scpe.identity import LocalIdentity
from scpe.signing import generate_private_key_pem
from scpe.workspace import pull as _ws_pull
from tests.conftest import FIX_DIFF, make_test_identity


def _patch_identity(monkeypatch, tmp_path: Path) -> tuple[LocalIdentity, str]:
    """Replace cc_pack's GitHub-identity resolution (gh CLI + network) with a throwaway
    SSH key, so the MCP pack handler is exercised fully offline."""
    kp = tmp_path / "sk"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(kp), "-N", "", "-q"],
                   check=True, capture_output=True)
    pub = " ".join((tmp_path / "sk.pub").read_text(encoding="utf-8").split()[:2])
    ident = LocalIdentity(login="bob", user_id="7", name="Bob Hand", pubkey=pub, key_path=str(kp))
    monkeypatch.setattr(mcp_server, "resolve_local_identity", lambda **kw: ident)
    return ident, pub


def _patch_attest_identity(monkeypatch, tmp_path: Path) -> tuple[LocalIdentity, str]:
    """cc_attest's auditor identity: same throwaway resolution as _patch_identity, plus an
    offline stub for the auditor verification cc_verify_attest does (no gh, no network)."""
    from scpe.identity import Identity
    ident, pub = _patch_identity(monkeypatch, tmp_path)
    monkeypatch.setattr(mcp_server, "verify_auditor_identity",
                        lambda statement, **k: Identity(login=ident.login, pubkey=pub))
    return ident, pub


ANALYZE_ONE = json.dumps({"issues": [
    {"title": "add() subtracts", "rationale": "planted bug", "files": ["demo/calc.py"]},
]})
ANALYZE_CLEAN = json.dumps({"issues": []})
GRADE_OK = json.dumps({"grade": "B", "summary": "solid, one real bug"})
GRADE_CLEAN = json.dumps({"grade": "A", "summary": "nothing to flag"})


def _canned_analyze_backend(monkeypatch, issues=ANALYZE_ONE, grade=GRADE_OK):
    from scpe import backends
    canned = {"ANALYZE": issues, "GRADE": grade}
    monkeypatch.setattr(backends, "make_backend", lambda kind=None: backends.MockBackend(canned))


def _make_envelope(fixture_repo: Path, tmp_path: Path, out_name: str = "e.zip") -> Path:
    from scpe.backends import MockBackend
    from scpe.contribute import contribute
    backend = MockBackend({
        "ANALYZE": ANALYZE_ONE, "FIXGEN": f"```diff\n{FIX_DIFF}```", "BRIEFING": "# fix",
    })
    return contribute(str(fixture_repo), backend,
                      identity=make_test_identity(tmp_path, key_name=f"k-{out_name}")[0],
                      workdir=tmp_path / f"w-{out_name}", out_path=tmp_path / out_name)


# ---- cc_attest -----------------------------------------------------------------

def test_cc_attest_returns_valid_attestation(fixture_repo: Path, tmp_path: Path, monkeypatch):
    _canned_analyze_backend(monkeypatch)
    _patch_attest_identity(monkeypatch, tmp_path)
    result = mcp_server.cc_attest(str(fixture_repo), out=str(tmp_path / "a.intoto.json"))
    assert "error" not in result
    assert Path(result["out_path"]).exists()
    assert result["verdict"] == "findings"
    assert result["findings_count"] == 1
    assert result["github_login"] == "bob"
    assert result["statement_summary"]["repo"] == str(fixture_repo)
    assert result["statement_summary"]["grade"] == "B"

    verified = mcp_server.cc_verify_attest(result["out_path"])
    assert verified["valid"] is True
    assert verified["verdict"] == "findings"
    assert verified["auditor"]["name"] == "Bob Hand"
    assert verified["auditor_identity"]["login"] == "bob"
    assert verified["auditor_identity"]["status"] == "verified"


def test_cc_attest_runs_checks_by_default(fixture_repo: Path, tmp_path: Path, monkeypatch):
    _canned_analyze_backend(monkeypatch)
    _patch_attest_identity(monkeypatch, tmp_path)
    result = mcp_server.cc_attest(str(fixture_repo))
    assert "error" not in result
    assert {c["tool"] for c in result["checks"]} == {"tests", "bandit", "ruff"}

    verified = mcp_server.cc_verify_attest(result["out_path"])
    # `verified["checks"]` went through parse_statement's sanitize_text (control
    # chars in `tail` collapsed to spaces), so compare on the semantic fields rather
    # than exact tail bytes — tool/ran/passed must survive the sign->save->load
    # round trip unchanged.
    by_tool = {c["tool"]: c for c in result["checks"]}
    for vc in verified["checks"]:
        rc = by_tool[vc["tool"]]
        assert vc["ran"] == rc["ran"]
        assert vc["passed"] == rc["passed"]
        assert vc["summary"] == rc["summary"]


def test_cc_attest_no_checks_skips_evidence(fixture_repo: Path, tmp_path: Path, monkeypatch):
    _canned_analyze_backend(monkeypatch)
    _patch_attest_identity(monkeypatch, tmp_path)
    result = mcp_server.cc_attest(str(fixture_repo), no_checks=True)
    assert "error" not in result
    assert result["checks"] is None

    verified = mcp_server.cc_verify_attest(result["out_path"])
    assert verified["valid"] is True
    assert verified["checks"] is None


def test_cc_attest_clean_repo_signs_clean_verdict(fixture_repo: Path, tmp_path: Path, monkeypatch):
    """The point of attestation: 'found nothing' is a positive signed deliverable."""
    _canned_analyze_backend(monkeypatch, issues=ANALYZE_CLEAN, grade=GRADE_CLEAN)
    _patch_attest_identity(monkeypatch, tmp_path)
    result = mcp_server.cc_attest(str(fixture_repo))
    assert "error" not in result
    assert result["verdict"] == "clean"
    assert result["findings_count"] == 0


def test_cc_attest_default_out_uses_temp_dir_not_cwd(fixture_repo: Path, tmp_path: Path, monkeypatch):
    _canned_analyze_backend(monkeypatch)
    _patch_attest_identity(monkeypatch, tmp_path)
    result = mcp_server.cc_attest(str(fixture_repo))
    assert Path(result["out_path"]).name == "attestation.intoto.json"
    assert Path(result["out_path"]).exists()


def test_cc_attest_never_leaks_private_key(fixture_repo: Path, tmp_path: Path, monkeypatch):
    _canned_analyze_backend(monkeypatch)
    ident, _ = _patch_attest_identity(monkeypatch, tmp_path)
    result = mcp_server.cc_attest(str(fixture_repo))
    dumped = json.dumps(result)
    # The SSH signing key's private half must never surface in the response.
    private_key = Path(ident.key_path).read_bytes().decode()
    assert "PRIVATE KEY" not in dumped
    assert private_key not in dumped


# ---- cc_pack ---------------------------------------------------------------

def test_cc_pack_seals_and_signs(fixture_repo: Path, tmp_path: Path, monkeypatch):
    ident, pub = _patch_identity(monkeypatch, tmp_path)
    ws = _ws_pull(str(fixture_repo), tmp_path / "ws")
    (ws / "demo" / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    result = mcp_server.cc_pack(str(ws))
    assert "error" not in result
    assert Path(result["out_path"]).exists()
    assert len(result["pieces"]) == 1
    assert result["pieces"][0]["id"] == "p1"
    assert result["github_login"] == "bob"
    assert result["signer_pubkey"] == pub

    env = unpack(result["out_path"])
    assert verify_signature(env)
    assert verify_envelope_identity(env, keys=[pub]).login == "bob"
    assert env.manifest.sender_name == "Bob Hand"


def test_cc_pack_no_changes_returns_error_not_raise(fixture_repo: Path, tmp_path: Path, monkeypatch):
    _patch_identity(monkeypatch, tmp_path)
    ws = _ws_pull(str(fixture_repo), tmp_path / "ws2")
    result = mcp_server.cc_pack(str(ws))
    assert "error" in result


def test_cc_pack_not_a_workspace_returns_error(tmp_path: Path, monkeypatch):
    _patch_identity(monkeypatch, tmp_path)
    not_ws = tmp_path / "plain-dir"
    not_ws.mkdir()
    result = mcp_server.cc_pack(str(not_ws))
    assert "error" in result


def test_cc_pack_nonexistent_workspace_path_returns_error_not_raise(tmp_path: Path, monkeypatch):
    """A workspace path that doesn't exist at all must degrade to the handler's
    error-dict contract, never raise across the MCP transport."""
    _patch_identity(monkeypatch, tmp_path)
    missing = tmp_path / "nope" / "does-not-exist"
    result = mcp_server.cc_pack(str(missing))
    assert "error" in result


# ---- cc_verify ---------------------------------------------------------------

def test_cc_verify_returns_verdict(fixture_repo: Path, tmp_path: Path, monkeypatch):
    from scpe import backends
    envp = _make_envelope(fixture_repo, tmp_path, "e_verify.zip")

    owner_backend = backends.MockBackend({
        "SAFETY": json.dumps({"safe": True, "reasons": []}),
        "FIT": json.dumps({"fits": True, "notes": []}),
    })
    monkeypatch.setattr(backends, "make_backend", lambda kind=None: owner_backend)

    result = mcp_server.cc_verify(str(envp), str(fixture_repo), trust="strict")
    assert "error" not in result
    assert result["envelope_ok"] is True
    assert result["trust"] == "strict"
    assert result["pieces"][0]["verdict"] == "accept"


def test_cc_verify_never_applies_no_apply_param():
    """The MCP tool must not expose an apply/commit path at all."""
    import inspect
    assert "apply" not in inspect.signature(mcp_server.cc_verify).parameters


def test_cc_verify_bad_trust_returns_error(fixture_repo: Path, tmp_path: Path):
    result = mcp_server.cc_verify(str(tmp_path / "nope.zip"), str(fixture_repo), trust="bogus")
    assert "error" in result


def test_cc_verify_invalid_envelope_returns_error(fixture_repo: Path, tmp_path: Path, monkeypatch):
    from scpe import backends
    monkeypatch.setattr(backends, "make_backend", lambda kind=None: backends.MockBackend())
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"not a zip")
    result = mcp_server.cc_verify(str(junk), str(fixture_repo))
    assert "error" in result


# ---- cc_inspect ------------------------------------------------------------------

def test_cc_inspect_reads_envelope(fixture_repo: Path, tmp_path: Path):
    envp = _make_envelope(fixture_repo, tmp_path, "e_inspect.zip")
    result = mcp_server.cc_inspect(str(envp))
    assert "error" not in result
    assert result["signature_valid"] is True
    assert result["sender"] == "Alice Dev <1+alice@users.noreply.github.com>"
    assert len(result["pieces"]) == 1


def test_cc_inspect_bad_zip_returns_error_not_raise(tmp_path: Path):
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"not a zip")
    result = mcp_server.cc_inspect(str(junk))
    assert "error" in result


# ---- cc_changes ------------------------------------------------------------------

def test_cc_changes_owner_readable(fixture_repo: Path, tmp_path: Path):
    envp = _make_envelope(fixture_repo, tmp_path, "e_changes.zip")
    result = mcp_server.cc_changes(str(envp))
    assert "error" not in result
    assert "Changes in this contribution" in result["summary"]
    assert "demo/calc.py" in result["summary"]


def test_cc_changes_bad_zip_returns_error_not_raise(tmp_path: Path):
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"not a zip")
    result = mcp_server.cc_changes(str(junk))
    assert "error" in result


# ---- cc_verify_attest --------------------------------------------------------

def test_cc_verify_attest_validates(fixture_repo: Path, tmp_path: Path, monkeypatch):
    _canned_analyze_backend(monkeypatch)
    _patch_attest_identity(monkeypatch, tmp_path)
    attested = mcp_server.cc_attest(str(fixture_repo))
    result = mcp_server.cc_verify_attest(attested["out_path"])
    assert result["valid"] is True
    assert result["base_sha"] == attested["statement_summary"]["base_sha"]
    assert result["findings_count"] == 1


def test_cc_verify_attest_wrong_pinned_key_invalid(fixture_repo: Path, tmp_path: Path, monkeypatch):
    _canned_analyze_backend(monkeypatch)
    _patch_attest_identity(monkeypatch, tmp_path)
    attested = mcp_server.cc_attest(str(fixture_repo))
    result = mcp_server.cc_verify_attest(attested["out_path"], key="00" * 32)
    assert result["valid"] is False


def test_cc_verify_attest_bad_file_returns_error_not_raise(tmp_path: Path):
    junk = tmp_path / "junk.json"
    junk.write_bytes(b"not json at all")
    result = mcp_server.cc_verify_attest(str(junk))
    assert "error" in result


# ---- server wiring (only meaningful when `mcp` SDK is installed) ---------------

def test_build_server_registers_all_tools():
    pytest.importorskip("mcp")
    import asyncio
    server = mcp_server.build_server()
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert names == {"cc_pack", "cc_verify", "cc_attest", "cc_verify_attest", "cc_inspect",
                     "cc_changes"}


def test_build_server_raises_clear_error_without_mcp_sdk(monkeypatch):
    """Simulate `mcp` missing: build_server must raise ImportError with an actionable
    install hint (scpe[mcp]), never an opaque traceback."""
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "mcp" or name.startswith("mcp."):
            raise ImportError("simulated missing mcp")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ImportError, match=r"scpe\[mcp\]"):
        mcp_server.build_server()


def test_mcp_sdk_not_imported_at_module_level():
    """`mcp` must be imported lazily, inside build_server() — never at module import
    time — so importing scpe.mcp_server and calling any cc_* handler works
    with zero dependency on the optional SDK being installed."""
    assert "mcp" not in mcp_server.__dict__
