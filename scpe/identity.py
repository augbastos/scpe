"""GitHub-bound contributor identity.

Credit on a contribution must be *provable*, not a free-typed name: git author email is
spoofable, so "this came from @X" means nothing unless X actually signed it. Here we sign
an envelope's canonical digest with the contributor's SSH key and verify it against
`https://github.com/<login>.keys` — GitHub's own public list of that account's keys. A
valid signature is cryptographic proof that GitHub-user `<login>` signed this exact
envelope; GitHub vouches the key, so the owner trusts the proof, not our word.

Mechanics use the system `ssh-keygen -Y sign|verify` (the same SSH-signature format git
uses for commit signing), namespace `scpe`. No third-party deps. Every failure is
fail-closed: a malformed/absent/tampered signature yields `None` (never a trusted default).

Real keys are passphrase-protected, so production signing goes through the ssh-agent (the
key is already unlocked) — `sign_digest` shells to ssh-keygen, which uses the agent when
the private key isn't directly readable. Never handle the passphrase ourselves.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

NAMESPACE = "scpe/0.1"
_GITHUB_KEYS_URL = "https://github.com/{login}.keys"
_SIGNING_KEYS_URL = "https://api.github.com/users/{login}/ssh_signing_keys"
_MAX_KEYS_BYTES = 1_000_000
_KEY_PREFIXES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-")


class IdentityError(RuntimeError):
    """A precondition failed (ssh-keygen missing, network unreachable) — distinct from a
    signature that simply does not verify, which is a returned `None`, not an exception."""


@dataclass(frozen=True)
class Identity:
    login: str
    pubkey: str  # the authorized_keys line ("<type> <base64>") that carries the identity


@dataclass(frozen=True)
class LocalIdentity:
    """The contributor's own resolved GitHub identity, ready to sign an envelope with."""
    login: str
    user_id: str
    name: str      # display name for the git author (falls back to login)
    pubkey: str    # bare "<type> <base64>", confirmed present on the GitHub account
    key_path: str  # private key (or agent-backed public key) to sign with


_DEFAULT_KEY_PATH = "~/.ssh/scpe_ed25519"


def _run(args: list[str], *, stdin: bytes | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, input=stdin, capture_output=True, timeout=30)
    except FileNotFoundError as exc:
        raise IdentityError("ssh-keygen not found — install the OpenSSH client") from exc
    except subprocess.TimeoutExpired as exc:
        raise IdentityError("ssh-keygen timed out") from exc


def principal_for(login: str) -> str:
    """The allowed-signers principal we bind a login to. Not security-relevant on its own
    (the key list is), just a stable label ssh-keygen matches against."""
    return f"{login}@github"


def noreply_email(login: str, user_id: int | str) -> str:
    """GitHub's no-reply author email. Attributes a commit to the account WITHOUT leaking
    a real address; always associated with the account, so `--apply` can author as it."""
    return f"{user_id}+{login}@users.noreply.github.com"


def parse_keys(text: str) -> list[str]:
    """Normalize a `github.com/<login>.keys` body (or an authorized_keys file) to a list of
    `<type> <base64>` lines, dropping comments, blanks, and any trailing key comment."""
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith(_KEY_PREFIXES):
            out.append(f"{parts[0]} {parts[1]}")
    return out


def parse_signing_api(text: str) -> list[str]:
    """Extract bare keys from the JSON of `GET /users/<login>/ssh_signing_keys` — each
    item's `key` field is an authorized_keys-style `<type> <base64>` line."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[str] = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and isinstance(item.get("key"), str):
                out += parse_keys(item["key"])
    return out


def _get(url: str, timeout: int) -> str:
    req = urllib.request.Request(
        url, headers={"User-Agent": "scpe", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec: fixed https host
            return resp.read(_MAX_KEYS_BYTES).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        raise IdentityError(f"cannot fetch {url}: {exc}") from exc


def fetch_github_keys(login: str, *, timeout: int = 15) -> list[str]:
    """Union of the public SSH keys GitHub exposes for `login`: authentication keys
    (`github.com/<login>.keys`) AND ssh **signing** keys (the public API). Either alone
    suffices; a signing-only key never grants push access, so it is the safer place to
    register a dedicated scpe key. Raises IdentityError only if BOTH sources are
    unreachable; an account that simply has no keys returns []."""
    safe = urllib.parse.quote(login, safe="")
    collected: list[str] = []
    errors: list[str] = []
    for url, parse in (
        (_GITHUB_KEYS_URL.format(login=safe), parse_keys),
        (_SIGNING_KEYS_URL.format(login=safe), parse_signing_api),
    ):
        try:
            collected += parse(_get(url, timeout))
        except IdentityError as exc:
            errors.append(str(exc))
    if not collected and errors:
        raise IdentityError("; ".join(errors))
    seen: set[str] = set()
    out: list[str] = []
    for k in collected:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def sign_digest(digest: bytes, *, key_path: str | Path) -> str:
    """Sign `digest` (namespace `scpe`) with the SSH key at `key_path` — a private
    key, or a public key whose private half is loaded in the ssh-agent. Returns the armored
    SSH signature. Raises IdentityError if signing fails (e.g. locked key with no agent)."""
    with tempfile.TemporaryDirectory() as td:
        blob = Path(td) / "blob"
        blob.write_bytes(digest)
        r = _run(["ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", NAMESPACE, str(blob)])
        if r.returncode != 0:
            raise IdentityError(
                f"ssh-keygen sign failed: {r.stderr.decode(errors='replace').strip()}")
        return (Path(str(blob) + ".sig")).read_text(encoding="utf-8")


def verify_digest(digest: bytes, ssh_sig: str, login: str, *,
                  keys: list[str] | None = None,
                  expected_pubkey: str | None = None) -> Identity | None:
    """Verify that `login` signed `digest`, against `keys` (or, if None, the account's live
    `.keys`). Fail-closed: returns an Identity only on a cryptographically good signature by
    a key GitHub lists for `login`; otherwise None. If `expected_pubkey` is given, it must
    be present in the key list AND be a key the signature verifies under — this pins the
    manifest's claimed key so a valid signature can't be re-attributed to a different key."""
    keys = keys if keys is not None else fetch_github_keys(login)
    # Normalize to bare "<type> <base64>" so an injected raw authorized_keys line (with a
    # trailing comment) compares and pins the same as a fetched-and-parsed key.
    keys = [" ".join(k.split()[:2]) for k in keys if k.split()]
    if not keys:
        return None
    if expected_pubkey is not None:
        want = " ".join(expected_pubkey.split()[:2])
        if want not in keys:
            return None
        keys = [want]  # pin verification to exactly the claimed key
    principal = principal_for(login)
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "blob.sig").write_text(ssh_sig, encoding="utf-8")
        allowed = tdp / "allowed_signers"
        allowed.write_text(
            "".join(f'{principal} namespaces="{NAMESPACE}" {k}\n' for k in keys),
            encoding="utf-8")
        r = _run(["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", principal,
                  "-n", NAMESPACE, "-s", str(tdp / "blob.sig")], stdin=digest)
        if r.returncode != 0:
            return None
    matched = keys[0] if len(keys) == 1 else (expected_pubkey or keys[0])
    return Identity(login=login, pubkey=" ".join(matched.split()[:2]))


def _gh_user() -> tuple[str, str, str]:
    """(login, id, display_name) from the authenticated gh CLI."""
    try:
        r = subprocess.run(["gh", "api", "user"], capture_output=True, timeout=30)
    except FileNotFoundError as exc:
        raise IdentityError(
            "gh CLI not found — install GitHub CLI and run `gh auth login`") from exc
    except subprocess.TimeoutExpired as exc:
        raise IdentityError("`gh api user` timed out") from exc
    if r.returncode != 0:
        raise IdentityError(
            "gh is not authenticated — run `gh auth login` "
            f"({r.stderr.decode(errors='replace').strip()[:200]})")
    try:
        data = json.loads(r.stdout.decode("utf-8", "replace"))
    except json.JSONDecodeError as exc:
        raise IdentityError(f"unexpected `gh api user` output: {exc}") from exc
    login, uid = data.get("login"), data.get("id")
    if not login or uid is None:
        raise IdentityError("`gh api user` returned no login/id")
    return str(login), str(uid), str(data.get("name") or login)


def _read_pubkey(key_path: Path) -> str:
    pub = Path(str(key_path) + ".pub")
    if not pub.exists():
        raise IdentityError(
            f"no signing key at {pub} — create one with "
            f'ssh-keygen -t ed25519 -f {key_path} -N "" and register it: '
            f"gh ssh-key add {pub} --type signing --title scpe")
    parts = pub.read_text(encoding="utf-8").strip().split()
    if len(parts) < 2:
        raise IdentityError(f"malformed public key at {pub}")
    return f"{parts[0]} {parts[1]}"


def resolve_local_identity(*, key_path: str | Path | None = None) -> LocalIdentity:
    """Resolve the contributor's *verifiable* GitHub identity for signing: login/id/name via
    the authenticated gh CLI, the signing key at key_path (default ~/.ssh/scpe_ed25519),
    and CONFIRM that key is one GitHub publishes for the account — else refuse with guidance,
    so a pack never claims an identity the owner would fail to verify."""
    login, uid, name = _gh_user()
    kp = Path(key_path).expanduser() if key_path else Path(_DEFAULT_KEY_PATH).expanduser()
    pubkey = _read_pubkey(kp)
    if pubkey not in fetch_github_keys(login):
        raise IdentityError(
            f"signing key {kp}.pub is not registered on github.com/{login} — add it: "
            f"gh ssh-key add {kp}.pub --type signing --title scpe")
    return LocalIdentity(login=login, user_id=uid, name=name, pubkey=pubkey, key_path=str(kp))
