"""Gate — the reference PRODUCER is runnable as a real CLI (argparse `main`).

The roundtrip test (test_producer_roundtrip.py) proves the *functions* round-trip;
this test proves a contributor can actually *run* them from a shell. We drive
`reference/producer.py` as a subprocess — exactly `python reference/producer.py <cmd>`,
the same surface the `scpe-envelope` console script wires to (`reference.producer:main`)
— and assert the four subcommands behave:

  * pack   -> writes an envelope zip;
  * verify -> human output says "verified" (exit 0);
  * verify --json -> {"status": "verified", ...};
  * attest -> SCPE-ATTESTATION-v1 block, and verify --diff on it -> "verified".

Everything is offline: throwaway git repo, throwaway SSH key, a local `keys` file
standing in for github.com/<login>.keys. No gh CLI, no network. If the installed
`scpe-envelope` entry point is on PATH we exercise it too, otherwise that leg skips.
"""
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PRODUCER_PATH = ROOT / "reference" / "producer.py"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """Invoke the producer CLI as `python reference/producer.py <args>` (the exact
    surface `scpe-envelope` maps to). Never raises on non-zero — callers assert."""
    return subprocess.run([sys.executable, str(PRODUCER_PATH), *args],
                          capture_output=True, text=True, timeout=120)


@pytest.fixture
def signing_key(tmp_path: Path) -> Path:
    key = tmp_path / "scpe_cli_ed25519"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(key), "-N", "", "-q"],
                   check=True, capture_output=True)
    return key


@pytest.fixture
def keys_file(signing_key: Path, tmp_path: Path) -> Path:
    """Local stand-in for https://github.com/<login>.keys — the bare public key."""
    kf = tmp_path / "keys"
    kf.write_bytes(Path(str(signing_key) + ".pub").read_bytes())
    return kf


@pytest.fixture
def changed_repo(tmp_path: Path) -> tuple[Path, str, str]:
    """A repo with two commits (base, head); returns (repo, base_sha, head_sha)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "fix")
    head = _git(repo, "rev-parse", "HEAD")
    return repo, base, head


def _pack(repo: Path, base: str, head: str, key: Path, out: Path,
          *extra: str) -> subprocess.CompletedProcess:
    return _run_cli(
        "pack", "--repo", str(repo), "--base", base, "--head", head,
        "--out", str(out), "--login", "octocat-test", "--key", str(key),
        "--created-at", "2026-07-21T18:00:00Z", *extra)


def test_cli_pack_writes_an_envelope(changed_repo, signing_key, tmp_path):
    repo, base, head = changed_repo
    env = tmp_path / "envelope.zip"
    proc = _pack(repo, base, head, signing_key, env, "--ai-disclosure", "assisted",
                 "--notes", "cli round-trip")
    assert proc.returncode == 0, proc.stderr
    assert env.is_file() and env.read_bytes()[:2] == b"PK", "pack did not emit a zip"
    with zipfile.ZipFile(env) as zf:
        assert set(zf.namelist()) == {"manifest.json", "manifest.sig", "diff.patch"}


def test_cli_verify_human_reports_verified(changed_repo, signing_key, keys_file, tmp_path):
    repo, base, head = changed_repo
    env = tmp_path / "envelope.zip"
    assert _pack(repo, base, head, signing_key, env).returncode == 0

    vf = _run_cli("verify", str(env), "--keys", str(keys_file))
    assert vf.returncode == 0, vf.stderr
    assert "verified" in vf.stdout.lower(), vf.stdout


def test_cli_verify_json_status_verified(changed_repo, signing_key, keys_file, tmp_path):
    repo, base, head = changed_repo
    env = tmp_path / "envelope.zip"
    assert _pack(repo, base, head, signing_key, env).returncode == 0

    vf = _run_cli("verify", str(env), "--keys", str(keys_file), "--json")
    assert vf.returncode == 0, vf.stderr
    res = json.loads(vf.stdout)
    assert res["status"] == "verified", res


def test_cli_attest_then_verify_with_out_of_band_diff(
        changed_repo, signing_key, keys_file, tmp_path):
    repo, base, head = changed_repo
    env = tmp_path / "envelope.zip"
    assert _pack(repo, base, head, signing_key, env).returncode == 0

    # attest -> PR-body block (manifest + sig, no diff)
    body = tmp_path / "pr_body.md"
    at = _run_cli("attest", str(env), "--out", str(body))
    assert at.returncode == 0, at.stderr
    assert "SCPE-ATTESTATION-v1" in body.read_text(encoding="utf-8")

    # the diff travels out of band (the PR); pull it from the envelope
    diff_file = tmp_path / "diff.patch"
    with zipfile.ZipFile(env) as zf:
        diff_file.write_bytes(zf.read("diff.patch"))

    vf = _run_cli("verify", str(body), "--keys", str(keys_file),
                  "--diff", str(diff_file), "--json")
    assert vf.returncode == 0, vf.stderr
    assert json.loads(vf.stdout)["status"] == "verified", vf.stdout


def test_cli_verify_tampered_diff_fails(changed_repo, signing_key, keys_file, tmp_path):
    """A verify leg that must NOT say verified — proves the CLI surfaces the verifier's
    real verdict and its non-zero exit, not a rubber stamp."""
    import io

    repo, base, head = changed_repo
    env = tmp_path / "envelope.zip"
    assert _pack(repo, base, head, signing_key, env).returncode == 0

    with zipfile.ZipFile(env) as zf:
        manifest, sig = zf.read("manifest.json"), zf.read("manifest.sig")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest)
        zf.writestr("manifest.sig", sig)
        zf.writestr("diff.patch", b"--- a/calc.py\n+++ b/calc.py\n@@ -1 +1 @@\n-x\n+y\n")
    env.write_bytes(buf.getvalue())

    vf = _run_cli("verify", str(env), "--keys", str(keys_file), "--json")
    assert vf.returncode == 1, vf.stderr
    assert json.loads(vf.stdout)["status"] == "tampered", vf.stdout


def test_installed_console_script_if_present(changed_repo, signing_key, keys_file, tmp_path):
    """If `pip install -e .` put `scpe-envelope` on PATH, prove the entry point runs the
    same main(). Skips cleanly when the package isn't installed in this environment."""
    exe = shutil.which("scpe-envelope")
    if exe is None:
        pytest.skip("scpe-envelope console script not on PATH (package not installed)")
    repo, base, head = changed_repo
    env = tmp_path / "envelope.zip"
    pk = subprocess.run(
        [exe, "pack", "--repo", str(repo), "--base", base, "--head", head,
         "--out", str(env), "--login", "octocat-test", "--key", str(signing_key),
         "--created-at", "2026-07-21T18:00:00Z"],
        capture_output=True, text=True, timeout=120)
    assert pk.returncode == 0, pk.stderr
    vf = subprocess.run([exe, "verify", str(env), "--keys", str(keys_file), "--json"],
                        capture_output=True, text=True, timeout=120)
    assert vf.returncode == 0, vf.stderr
    assert json.loads(vf.stdout)["status"] == "verified", vf.stdout
