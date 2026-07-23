"""Gate — SCPE profiles (SPEC §13) pack and verify on the ONE core, profile surfaced.

A profile is a thin domain convention: a LABEL plus a media_type default, layered on the
artifact-agnostic core. It adds NO verification logic — integrity is always checked by
`subject.type` (SPEC §6, §8 step 7) — and the verifier SURFACES the stamped label but
never lets it change the verdict (SPEC §13.2).

This proves that end to end, fully offline (throwaway ed25519 key + local `keys` file
standing in for github.com/<login>.keys, exactly like the normative vectors):

  * SCPE-C     -> a `code-change` subject (a diff)   -> verified, profile SCPE-C surfaced
  * SCPE-I     -> an `artifact` subject (a real PNG) -> verified, profile SCPE-I surfaced
  * SCPE-M     -> an `artifact` subject (safetensors)-> verified, profile SCPE-M surfaced
  * SCPE-DATA  -> an `artifact` subject (JSONL)      -> verified, profile SCPE-DATA
  * SCPE-D     -> an `artifact` subject (PDF)        -> verified, profile SCPE-D

plus the two invariants: an artifact packed with NO profile surfaces profile=None yet
still verifies, and an UNKNOWN profile label is surfaced verbatim without changing the
`verified` verdict (SPEC §13.2 clause 3).
"""
import base64
import importlib.util
import json
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PRODUCER_PATH = ROOT / "reference" / "producer.py"
VERIFIER = ROOT / "reference" / "standalone" / "verify_envelope.py"

# Load reference/producer.py by path — it lives outside the scpe package on purpose.
_spec = importlib.util.spec_from_file_location("scpe_producer_ref", PRODUCER_PATH)
producer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(producer)

LOGIN = "octocat-test"
CREATED_AT = "2026-07-22T00:00:00Z"

# A real 1x1 transparent PNG (67 bytes) — a genuine image, not a stub.
PNG_1x1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args],
                          check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def signing_key(tmp_path: Path) -> Path:
    key = tmp_path / "scpe_prof_ed25519"
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
    args = [sys.executable, str(VERIFIER), str(path), "--keys", str(keys), "--json"]
    if diff is not None:
        args += ["--diff", str(diff)]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
    assert proc.stdout.strip(), f"no verifier output; stderr: {proc.stderr[-500:]}"
    return json.loads(proc.stdout)


def _manifest(env: Path) -> dict:
    with zipfile.ZipFile(env) as zf:
        return json.loads(zf.read("manifest.json"))


def _write_artifact(profile: str, tmp_path: Path) -> Path:
    """A REAL tiny file per artifact-family profile."""
    if profile == "SCPE-I":
        p = tmp_path / "pixel.png"
        p.write_bytes(PNG_1x1)
    elif profile == "SCPE-M":
        p = tmp_path / "tiny.safetensors"
        header = b'{"__metadata__":{"demo":"scpe"}}'
        p.write_bytes(struct.pack("<Q", len(header)) + header)
    elif profile == "SCPE-DATA":
        p = tmp_path / "train.jsonl"
        p.write_text('{"prompt":"hi","completion":"hello"}\n'
                     '{"prompt":"bye","completion":"goodbye"}\n', encoding="utf-8")
    elif profile == "SCPE-D":
        p = tmp_path / "note.pdf"
        p.write_bytes(b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n")
    else:  # pragma: no cover
        raise AssertionError(profile)
    return p


# --------------------------------------------------------------------- SCPE-C (code)

def test_scpe_c_code_change_verifies_and_surfaces_profile(
        changed_repo, signing_key, keys_file, tmp_path):
    repo, base, head = changed_repo
    env = tmp_path / "scpe-c.zip"
    producer.pack(repo=repo, base=base, head=head, out=env,
                  login=LOGIN, key=str(signing_key), ai_mode="assisted",
                  ai_notes="SCPE-C code change", created_at=CREATED_AT, profile="SCPE-C")
    # The label is stamped inside the SIGNED manifest, on a code-change subject.
    m = _manifest(env)
    assert m["profile"] == "SCPE-C"
    assert m["subject"]["type"] == "code-change"
    res = _verify(env, keys_file)
    assert res["status"] == "verified", res
    assert res["profile"] == "SCPE-C", res


# ------------------------------------------------- SCPE-I / SCPE-M / SCPE-DATA / SCPE-D

# GATE 1 requires SCPE-C + SCPE-I + SCPE-M + SCPE-DATA; SCPE-D is included for good measure.
ARTIFACT_PROFILES = {
    "SCPE-I": "image/png",
    "SCPE-M": "application/octet-stream",
    "SCPE-DATA": "application/octet-stream",
    "SCPE-D": "application/pdf",
}


@pytest.mark.parametrize("profile,expected_media", list(ARTIFACT_PROFILES.items()))
def test_artifact_profile_verifies_and_surfaces_profile(
        profile, expected_media, signing_key, keys_file, tmp_path):
    artifact = _write_artifact(profile, tmp_path)
    env = tmp_path / f"{profile.lower()}.zip"
    # No media_type passed: the profile convention (SPEC §13.1) supplies the default.
    producer.pack_artifact(artifact=artifact, out=env, media_type=None,
                           login=LOGIN, key=str(signing_key), ai_mode="generated",
                           ai_notes=f"{profile} artifact", created_at=CREATED_AT,
                           profile=profile)
    m = _manifest(env)
    assert m["profile"] == profile
    assert m["subject"]["type"] == "artifact"
    # The profile's media_type convention was applied (informational, unverified).
    assert m["subject"]["media_type"] == expected_media
    res = _verify(env, keys_file)
    assert res["status"] == "verified", res
    assert res["profile"] == profile, res


# ---------------------------------------------------------------- §13.2 invariants

def test_explicit_media_type_overrides_profile_convention(
        signing_key, keys_file, tmp_path):
    """An explicit --media-type always wins over the profile's convention default."""
    artifact = _write_artifact("SCPE-I", tmp_path)
    env = tmp_path / "override.zip"
    producer.pack_artifact(artifact=artifact, out=env, media_type="image/webp",
                           login=LOGIN, key=str(signing_key), created_at=CREATED_AT,
                           profile="SCPE-I")
    m = _manifest(env)
    assert m["subject"]["media_type"] == "image/webp"
    assert m["profile"] == "SCPE-I"
    assert _verify(env, keys_file)["status"] == "verified"


def test_no_profile_still_verifies_and_surfaces_none(
        changed_repo, signing_key, keys_file, tmp_path):
    """The default path: unstamped manifest still verifies; profile surfaces as None."""
    repo, base, head = changed_repo
    env = tmp_path / "no-profile.zip"
    producer.pack(repo=repo, base=base, head=head, out=env,
                  login=LOGIN, key=str(signing_key), created_at=CREATED_AT)
    assert "profile" not in _manifest(env)
    res = _verify(env, keys_file)
    assert res["status"] == "verified", res
    assert res["profile"] is None, res


def test_unknown_profile_is_surfaced_not_dispatched(
        signing_key, keys_file, tmp_path):
    """SPEC §13.2 clause 3: an unrecognized profile is surfaced verbatim and does NOT
    change the verdict. We hand-build a manifest with a bogus label and re-sign it."""
    artifact = _write_artifact("SCPE-DATA", tmp_path)
    data = artifact.read_bytes()
    digest = producer.hashlib.sha256(data).hexdigest()
    m = producer.build_artifact_manifest(
        login=LOGIN, fingerprint=producer.key_fingerprint(signing_key),
        digest_sha256=digest, media_type="application/octet-stream",
        ai_mode="none", ai_notes=None, created_at=CREATED_AT,
        profile="SCPE-TOTALLY-MADE-UP")
    manifest_bytes = producer.serialize_manifest(m)
    sig = producer.sign_manifest(manifest_bytes, signing_key)
    env = tmp_path / "unknown-profile.zip"
    env.write_bytes(producer._zip_bytes([
        ("manifest.json", manifest_bytes),
        ("manifest.sig", sig),
        ("artifact.bin", data),
    ]))
    res = _verify(env, keys_file)
    assert res["status"] == "verified", res            # verdict unchanged
    assert res["profile"] == "SCPE-TOTALLY-MADE-UP", res  # surfaced verbatim
