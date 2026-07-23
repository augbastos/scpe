import json, subprocess, sys
from pathlib import Path
from scpe.cli import main
from scpe.envelope import unpack
from scpe.identity import noreply_email
from tests.conftest import FIX_DIFF, patch_cli_identity


def _canned(monkeypatch):
    """Route the CLI's mock backend through canned contributor+owner responses."""
    from scpe import backends
    canned = {
        "ANALYZE": json.dumps({"issues": [{"title": "add() subtracts",
                                           "rationale": "bug", "files": ["demo/calc.py"]}]}),
        "FIXGEN": f"```diff\n{FIX_DIFF}```",
        "BRIEFING": "# fix",
        "SAFETY": json.dumps({"safe": True, "reasons": []}),
        "FIT": json.dumps({"fits": True, "notes": []}),
    }
    monkeypatch.setattr(backends, "make_backend", lambda kind=None: backends.MockBackend(canned))

def test_keygen_prints_public_only(tmp_path: Path, capsys):
    assert main(["keygen", "--key", str(tmp_path / "k.pem")]) == 0
    out = capsys.readouterr().out
    assert len(out.strip()) == 64 and "PRIVATE" not in out

def test_contribute_then_verify_then_apply(fixture_repo: Path, tmp_path: Path, monkeypatch, capsys):
    _canned(monkeypatch)
    patch_cli_identity(monkeypatch, tmp_path)
    envp = str(tmp_path / "e.zip")
    assert main(["contribute", str(fixture_repo), "--out", envp]) == 0
    assert len(unpack(envp).pieces) == 1

    assert main(["verify", envp, "--repo", str(fixture_repo), "--trust", "strict"]) == 0
    assert "accept" in capsys.readouterr().out

    assert main(["verify", envp, "--repo", str(fixture_repo), "--apply"]) == 0
    calc = (fixture_repo / "demo" / "calc.py").read_text(encoding="utf-8")
    assert "a + b" in calc
    log = subprocess.run(["git", "-C", str(fixture_repo), "log", "-1", "--format=%an <%ae>%n%B"],
                         capture_output=True, text=True).stdout
    # Author is now the verifiable GitHub identity (name + noreply email), not free text.
    assert f"Alice Dev <{noreply_email('alice-dev', '42')}>" in log
    assert "Assisted-By: scpe/mock" in log

def test_verify_test_cmd_override_reaches_the_sandbox(fixture_repo: Path, tmp_path: Path,
                                                       monkeypatch, capsys):
    """`--test-cmd` must actually override the auto-detected runner. fixture_repo auto-detects
    pytest and the piece fixes the real bug (would normally be 'accept'); pointing --test-cmd
    at a command that always fails proves the CLI flag reaches run_handshake/run_in_sandbox
    rather than being silently ignored in favor of detection."""
    _canned(monkeypatch)
    patch_cli_identity(monkeypatch, tmp_path)
    envp = str(tmp_path / "e.zip")
    assert main(["contribute", str(fixture_repo), "--out", envp]) == 0

    failing_cmd = f"{sys.executable} -m no_such_module_zzz"
    rc = main(["verify", envp, "--repo", str(fixture_repo), "--trust", "strict",
               "--test-cmd", failing_cmd])
    out = capsys.readouterr().out
    assert rc != 0
    assert "needs-changes" in out


def test_commit_message_disclosure_modes():
    """The commit trailers must adapt to the target repo's AI policy. Author credit (via
    git --author) is unchanged across modes; only the trailers differ."""
    from types import SimpleNamespace
    from scpe.cli import _commit_message
    env = SimpleNamespace(manifest=SimpleNamespace(
        sender_public_key="ABCD", sender_name="Alice Dev", sender_email="alice@example.com"))
    kw = dict(titles="fix add()", ai_label="openai", env=env, env_sha="deadbeef")

    full = _commit_message("full", **kw)
    assert "Assisted-By: scpe/openai" in full
    assert "SCPE-Signer: ABCD" in full and "Envelope: deadbeef" in full

    signoff = _commit_message("signoff", **kw)
    assert "Signed-off-by: Alice Dev <alice@example.com>" in signoff
    assert "Assisted-by: scpe/openai" in signoff  # kernel-style lowercase disclosure tag

    minimal = _commit_message("minimal", **kw)
    assert "Assisted-By" not in minimal and "Assisted-by" not in minimal  # K8s bans AI trailers
    assert "SCPE-Signer: ABCD" in minimal              # provenance survives

    bare = _commit_message("bare", **kw)
    assert bare == "scpe: fix add()"                   # subject only, zero trailers

    # AI-FREE (`pack`, backend 'none'/None): must NOT claim AI assistance it never had
    for lbl in ("none", None):
        m = _commit_message("full", titles="manual fix", ai_label=lbl, env=env, env_sha="dead")
        assert "Assisted-By" not in m and "Assisted-by" not in m
        assert "SCPE-Signer: ABCD" in m               # provenance still recorded
    so = _commit_message("signoff", titles="manual fix", ai_label="none", env=env, env_sha="dead")
    assert "Signed-off-by: Alice Dev <alice@example.com>" in so  # human sign-off stays
    assert "Assisted-by" not in so                              # but no AI disclosure

def test_verify_json_output(fixture_repo: Path, tmp_path: Path, monkeypatch, capsys):
    _canned(monkeypatch)
    patch_cli_identity(monkeypatch, tmp_path)
    envp = str(tmp_path / "e.zip")
    main(["contribute", str(fixture_repo), "--out", envp])
    assert main(["verify", envp, "--repo", str(fixture_repo), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["pieces"][0]["verdict"] == "accept"


def test_changes_owner_readable_summary(fixture_repo: Path, tmp_path: Path, monkeypatch, capsys):
    """The owner can read what a contributor modified without diffing by hand."""
    _canned(monkeypatch)
    patch_cli_identity(monkeypatch, tmp_path, login="ada-dev", name="Ada Dev")
    envp = str(tmp_path / "e.zip")
    main(["contribute", str(fixture_repo), "--out", envp])
    assert main(["changes", envp]) == 0
    out = capsys.readouterr().out
    assert "Changes in this contribution" in out
    assert f"Ada Dev <{noreply_email('ada-dev', '42')}>" in out   # who (verifiable identity)
    assert "demo/calc.py" in out                        # which file
    assert "changed: add" in out                        # which function (from the diff)


def _head_files(repo: Path) -> list[str]:
    return subprocess.run(["git", "-C", str(repo), "show", "--name-only", "--format=", "HEAD"],
                          capture_output=True, text=True).stdout.split()


def test_apply_does_not_sweep_unrelated_dirty_changes(fixture_repo: Path, tmp_path: Path, monkeypatch):
    """The one irreversible op in a trust protocol must commit ONLY the applied piece — never
    sweep the owner's unrelated uncommitted WIP (the old `git commit -a`)."""
    _canned(monkeypatch)
    patch_cli_identity(monkeypatch, tmp_path)
    envp = str(tmp_path / "e.zip")
    assert main(["contribute", str(fixture_repo), "--out", envp]) == 0
    # Owner has unrelated in-progress work in a DIFFERENT tracked file:
    (fixture_repo / "demo" / "__init__.py").write_text("# unrelated WIP\n", encoding="utf-8")
    assert main(["verify", envp, "--repo", str(fixture_repo), "--apply"]) == 0
    assert _head_files(fixture_repo) == ["demo/calc.py"]          # ONLY the piece
    status = subprocess.run(["git", "-C", str(fixture_repo), "status", "--porcelain"],
                            capture_output=True, text=True).stdout
    assert "demo/__init__.py" in status                          # WIP left uncommitted


def _two_piece_conflicting_envelope(fixture_repo: Path, out: Path) -> str:
    from scpe.envelope import (
        PROTOCOL_VERSION, Envelope, Manifest, Piece, pack, sign_envelope)
    from scpe.signing import generate_private_key_pem
    from tests.conftest import FIX_DIFF
    head = subprocess.run(["git", "-C", str(fixture_repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    other = FIX_DIFF.replace("+    return a + b", "+    return b + a")  # also correct, same lines
    env = Envelope(
        manifest=Manifest(PROTOCOL_VERSION, "local", head, "", "Alice", "a@b.c",
                          "2026-07-20T00:00:00+00:00"),
        briefing_md="# two", provenance={"backend": "mock", "runs": []},
        pieces=[Piece("p1", "fix add", "bug", FIX_DIFF, ["demo/calc.py"]),
                Piece("p2", "fix add differently", "bug", other, ["demo/calc.py"])])
    pack(sign_envelope(env, generate_private_key_pem()), out)
    return str(out)


def test_apply_is_atomic_when_pieces_conflict(fixture_repo: Path, tmp_path: Path, monkeypatch):
    """Two independently-accepted pieces that CONFLICT on apply must leave the working tree
    untouched (no half-applied dirty tree) and create no commit."""
    from scpe import backends
    monkeypatch.setattr(backends, "make_backend", lambda kind=None: backends.MockBackend(
        {"SAFETY": json.dumps({"safe": True, "reasons": []}),
         "FIT": json.dumps({"fits": True, "notes": []})}))
    ep = _two_piece_conflicting_envelope(fixture_repo, tmp_path / "two.zip")
    before = subprocess.run(["git", "-C", str(fixture_repo), "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    rc = main(["verify", ep, "--repo", str(fixture_repo), "--apply"])
    after = subprocess.run(["git", "-C", str(fixture_repo), "rev-parse", "HEAD"],
                           capture_output=True, text=True).stdout.strip()
    assert rc != 0
    assert before == after                                        # no commit created
    assert "a - b" in (fixture_repo / "demo" / "calc.py").read_text(encoding="utf-8")  # untouched


def test_empty_pieces_envelope_is_not_reported_all_accepted(fixture_repo: Path, tmp_path: Path):
    """A validly-signed envelope with zero pieces must NOT exit 0 ('all accepted') — `all([])`
    is vacuously True and would green-light a no-op envelope in a CI gate."""
    from scpe.envelope import (
        PROTOCOL_VERSION, Envelope, Manifest, pack, sign_envelope)
    from scpe.signing import generate_private_key_pem
    head = subprocess.run(["git", "-C", str(fixture_repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    env = Envelope(
        manifest=Manifest(PROTOCOL_VERSION, "local", head, "", "A", "a@b.c",
                          "2026-07-20T00:00:00+00:00"),
        briefing_md="# empty", pieces=[], provenance={"backend": "mock", "runs": []})
    ep = str(tmp_path / "empty.zip")
    pack(sign_envelope(env, generate_private_key_pem()), ep)
    assert main(["verify", ep, "--repo", str(fixture_repo), "--trust", "strict"]) != 0


def test_duplicate_piece_id_envelope_rejected_end_to_end(fixture_repo: Path, tmp_path: Path, monkeypatch):
    """FIX 2a end-to-end: `verify --apply` on a duplicate-piece-id envelope is refused before
    the handshake ever runs (unpack() raises), so no commit is ever created — closing the
    'malicious piece rides the benign piece's accept verdict' bypass at the source."""
    from scpe.envelope import PROTOCOL_VERSION, Envelope, Manifest, Piece, pack, sign_envelope
    from scpe.signing import generate_private_key_pem
    head = subprocess.run(["git", "-C", str(fixture_repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    env = Envelope(
        manifest=Manifest(PROTOCOL_VERSION, "local", head, "", "Alice", "a@b.c",
                          "2026-07-20T00:00:00+00:00"),
        briefing_md="# dup", provenance={"backend": "mock", "runs": []},
        pieces=[Piece("p1", "benign fix", "ok", FIX_DIFF, ["demo/calc.py"]),
                Piece("p1", "malicious, rides p1's verdict", "evil",
                     "--- a/demo/__init__.py\n+++ b/demo/__init__.py\n@@ -0,0 +1,1 @@\n+pwned\n",
                     ["nope.py"])])
    ep = str(tmp_path / "dup.zip")
    pack(sign_envelope(env, generate_private_key_pem()), ep)

    before = subprocess.run(["git", "-C", str(fixture_repo), "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    rc = main(["verify", ep, "--repo", str(fixture_repo), "--apply"])
    after = subprocess.run(["git", "-C", str(fixture_repo), "rev-parse", "HEAD"],
                           capture_output=True, text=True).stdout.strip()
    assert rc == 1
    assert before == after                                        # no commit created
    assert "pwned" not in (fixture_repo / "demo" / "__init__.py").read_text(encoding="utf-8")


def test_apply_pairs_verdict_to_piece_by_position_not_id(fixture_repo: Path, tmp_path: Path, monkeypatch):
    """FIX 2b, defense in depth: even if a duplicate-id envelope somehow reaches the apply
    step (unpack()'s own guard bypassed/regressed — simulated here by monkeypatching unpack),
    the verdict-to-piece pairing is POSITIONAL (handshake emits exactly one verdict per piece,
    in order), so the malicious second piece can never be applied just because it shares an id
    with the accepted first piece. This is the exact scenario the old `next(v for v in
    report.pieces if v.piece_id == p.id)` first-match-wins lookup got wrong."""
    from scpe import backends, cli, handshake
    from scpe.envelope import PROTOCOL_VERSION, Envelope, Manifest, Piece, sign_envelope
    from scpe.signing import generate_private_key_pem
    head = subprocess.run(["git", "-C", str(fixture_repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    # piece 1: in-scope diff on its declared target file -> verdict "accept"
    # piece 2: SAME id "p1", but its diff touches a file OUTSIDE its declared target_files
    #          -> handshake verdicts it "needs-changes" (scope mismatch); must NOT be applied
    malicious_diff = ("--- a/demo/__init__.py\n+++ b/demo/__init__.py\n"
                      "@@ -0,0 +1,1 @@\n+pwned via duplicate id\n")
    env = sign_envelope(Envelope(
        manifest=Manifest(PROTOCOL_VERSION, "local", head, "", "Alice", "a@b.c",
                          "2026-07-20T00:00:00+00:00"),
        briefing_md="# dup-bypass", provenance={"backend": "mock", "runs": []},
        pieces=[Piece("p1", "benign fix", "ok", FIX_DIFF, ["demo/calc.py"]),
                Piece("p1", "malicious, rides p1 by id", "evil", malicious_diff, ["nope.py"])],
    ), generate_private_key_pem())

    monkeypatch.setattr(backends, "make_backend", lambda kind=None: backends.MockBackend(
        {"SAFETY": json.dumps({"safe": True, "reasons": []}),
         "FIT": json.dumps({"fits": True, "notes": []})}))
    # unpack()'s duplicate-id guard would normally refuse this envelope before we even get
    # here; bypass it on BOTH call sites (cli.py's apply path and handshake.py's own unpack)
    # to isolate and prove the apply-time positional-pairing fix independently.
    monkeypatch.setattr(cli, "unpack", lambda path: env)
    monkeypatch.setattr(handshake, "unpack", lambda path: env)
    dummy = tmp_path / "dummy.zip"
    dummy.write_bytes(b"unpack() is monkeypatched; contents irrelevant")

    rc = main(["verify", str(dummy), "--repo", str(fixture_repo), "--apply"])
    calc = (fixture_repo / "demo" / "calc.py").read_text(encoding="utf-8")
    init_py = (fixture_repo / "demo" / "__init__.py").read_text(encoding="utf-8")
    assert rc == 2                                # not ALL pieces accepted (piece 2 wasn't)
    assert "a + b" in calc                        # piece 1 (accept) WAS applied
    assert "pwned" not in init_py                 # piece 2 (needs-changes) must NOT ride p1
