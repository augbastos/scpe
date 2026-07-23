"""Gate 1 — the reference PRODUCER round-trips through the reference VERIFIER.

In a throwaway git repo, with a throwaway SSH key and a local `keys` file standing in
for github.com/<login>.keys (exactly like the normative vectors), we:

  * pack a real change -> envelope.zip, then verify it -> status "verified";
  * attest that envelope -> an SCPE-ATTESTATION-v1 block, then verify the block WITH the
    diff supplied out-of-band (--diff, the PR-transport form) -> status "verified".

Everything is offline: no gh CLI, no GitHub fetch, no network. The producer signs the
exact manifest bytes it zips; the standalone verifier (run as a subprocess) is the sole
authority on "verified".
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PRODUCER_PATH = ROOT / "reference" / "producer.py"

# Load reference/producer.py by path — it lives outside the scpe package on purpose.
_spec = importlib.util.spec_from_file_location("scpe_producer_ref", PRODUCER_PATH)
producer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(producer)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args],
                          check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def signing_key(tmp_path: Path) -> Path:
    key = tmp_path / "scpe_test_ed25519"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(key), "-N", "", "-q"],
                   check=True, capture_output=True)
    return key


@pytest.fixture
def keys_file(signing_key: Path, tmp_path: Path) -> Path:
    """The local stand-in for https://github.com/<login>.keys — the bare public key."""
    kf = tmp_path / "keys"
    kf.write_bytes((Path(str(signing_key) + ".pub")).read_bytes())
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


def _verify(path: Path, keys: Path, diff: Path | None = None) -> dict:
    args = [sys.executable, str(ROOT / "reference" / "standalone" / "verify_envelope.py"),
            str(path), "--keys", str(keys), "--json"]
    if diff is not None:
        args += ["--diff", str(diff)]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
    assert proc.stdout.strip(), f"no verifier output; stderr: {proc.stderr[-500:]}"
    return json.loads(proc.stdout)


def test_pack_envelope_verifies(changed_repo, signing_key, keys_file, tmp_path):
    repo, base, head = changed_repo
    env = tmp_path / "envelope.zip"
    producer.pack(repo=repo, base=base, head=head, out=env,
                  login="octocat-test", key=str(signing_key),
                  ai_mode="assisted", ai_notes="round-trip test",
                  created_at="2026-07-21T18:00:00Z")
    res = _verify(env, keys_file)
    assert res["status"] == "verified", res


def test_attest_block_verifies_with_out_of_band_diff(
        changed_repo, signing_key, keys_file, tmp_path):
    repo, base, head = changed_repo
    env = tmp_path / "envelope.zip"
    producer.pack(repo=repo, base=base, head=head, out=env,
                  login="octocat-test", key=str(signing_key),
                  created_at="2026-07-21T18:00:00Z")

    # extract diff.patch (the PR-transport diff the attestation does NOT carry)
    import zipfile
    diff_file = tmp_path / "diff.patch"
    with zipfile.ZipFile(env) as zf:
        diff_file.write_bytes(zf.read("diff.patch"))

    body = tmp_path / "pr_body.md"
    producer.attest(envelope=env, out=body)
    # sanity: exactly one attestation block, base64 of a zip
    assert producer.ATTESTATION_RE.search(body.read_text(encoding="utf-8"))

    res = _verify(body, keys_file, diff=diff_file)
    assert res["status"] == "verified", res


def test_pack_agent_trace_surfaces_in_verifier(
        changed_repo, signing_key, keys_file, tmp_path):
    repo, base, head = changed_repo
    env = tmp_path / "envelope.zip"
    producer.pack(repo=repo, base=base, head=head, out=env,
                  login="octocat-test", key=str(signing_key),
                  created_at="2026-07-21T18:00:00Z",
                  attestations=[{"type": "agent-trace", "format": "generic/1",
                                 "data": {"agent": "test"}}])
    res = _verify(env, keys_file)
    assert res["status"] == "verified", res
    assert res["attestations"] == [
        {"type": "agent-trace", "status": "present-generic/1"}], res


def test_tampered_diff_is_caught(changed_repo, signing_key, keys_file, tmp_path):
    repo, base, head = changed_repo
    env = tmp_path / "envelope.zip"
    producer.pack(repo=repo, base=base, head=head, out=env,
                  login="octocat-test", key=str(signing_key),
                  created_at="2026-07-21T18:00:00Z")
    # rewrite the diff.patch member so it no longer matches change.diff_sha256
    import io
    import zipfile
    with zipfile.ZipFile(env) as zf:
        manifest = zf.read("manifest.json")
        sig = zf.read("manifest.sig")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest)
        zf.writestr("manifest.sig", sig)
        zf.writestr("diff.patch", b"--- a/calc.py\n+++ b/calc.py\n@@ -1 +1 @@\n-x\n+y\n")
    env.write_bytes(buf.getvalue())
    res = _verify(env, keys_file)
    assert res["status"] == "tampered", res
