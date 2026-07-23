"""Acquire the target repo (URL or local path) and digest it for prompts, scrubbed."""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from scpe.scrub import scrub

_SHA_RE = re.compile(r"[0-9a-fA-F]{7,64}")

_SOURCE_SUFFIXES = {".py", ".js", ".ts", ".md", ".toml", ".cfg", ".txt"}


class RepoError(RuntimeError):
    pass


@dataclass
class RepoSnapshot:
    path: Path
    head_sha: str


def _run(args: list[str], cwd: Path | None = None) -> str:
    proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RepoError(f"{' '.join(args[:3])}… failed: {proc.stderr.strip()[:400]}")
    return proc.stdout


def clone_at(source: str, dest: Path, sha: str | None = None) -> RepoSnapshot:
    dest = Path(dest)
    # `--` ends option parsing so a manifest-derived source beginning with '-' is treated
    # as a path, never as a git option (e.g. --upload-pack=<cmd>). The `-c protocol.*.allow`
    # pins pin the TRANSPORT: without them a manifest-derived `source` of `ext::sh -c ...`
    # (git's "run an arbitrary command as a transport" protocol) or a crafted `file://`
    # would let an untrusted repo_url execute a command or read an arbitrary local path
    # during clone. `ext` is disabled outright; `file` is restricted to paths the invoking
    # user already owns (blocks e.g. cloning another user's private local repo via a
    # symlink/UNC trick), matching git's own recommended hardening for untrusted URLs.
    _run(["git", "clone", "-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=user",
         "--quiet", "--", source, str(dest)])
    if sha:
        # A base_sha is always a git object id; reject anything else so it can't be an option.
        if not _SHA_RE.fullmatch(sha):
            raise RepoError(f"refusing to check out non-hex ref {sha!r}")
        _run(["git", "checkout", "--quiet", sha], cwd=dest)
    head = _run(["git", "rev-parse", "HEAD"], cwd=dest).strip()
    return RepoSnapshot(path=dest, head_sha=head)


def repo_digest(path: Path, *, max_files: int = 40, max_bytes_per_file: int = 4000) -> str:
    path = Path(path)
    tracked = _run(["git", "ls-files"], cwd=path).splitlines()
    parts = ["# File tree", *tracked, ""]
    shown = 0
    for rel in tracked:
        if shown >= max_files:
            parts.append(f"… ({len(tracked) - shown} more files omitted)")
            break
        f = path / rel
        if f.suffix.lower() not in _SOURCE_SUFFIXES or not f.is_file():
            continue
        try:
            if f.stat().st_size > 100_000:
                continue
            text = f.read_text(encoding="utf-8", errors="replace")[:max_bytes_per_file]
        except OSError:
            continue
        parts += [f"## {rel}", text, ""]
        shown += 1
    return scrub("\n".join(parts))
