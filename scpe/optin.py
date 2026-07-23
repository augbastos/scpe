"""`init` — stamp the machine-detectable opt-in badge on a repo's README.

The badge is how a repo advertises "SCPE contributions welcome" in a way a
crawler can detect (the HTML comment anchor) and a human can click (the shields-style
image link). This module only touches README.md — it never commits, pushes, or reaches
the network; wiring into git is the caller's decision."""
from __future__ import annotations

import subprocess
from pathlib import Path

# Idempotency anchor: an invisible-in-rendered-markdown HTML comment. We key "already
# opted in?" off THIS marker, not the image URL, so a repo can restyle/move the badge
# without `init` re-inserting a duplicate.
BADGE_MARK = "<!-- scpe-optin -->"

_DEFAULT_SITE = "https://scpe.dev"


def badge_markdown(repo_url: str, site: str = _DEFAULT_SITE) -> str:
    """The two-line badge block: the detection anchor followed by the clickable image link."""
    return (f"{BADGE_MARK}\n"
            f"[![Contribute with SCPE]({site}/badge.svg)]({site}/go?repo={repo_url})")


def _origin_url(repo_path: Path) -> str | None:
    """Best-effort `origin` remote URL. Returns None on any failure (no remote, not a git
    repo, git absent) — the caller falls back to a placeholder rather than erroring."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_path), "remote", "get-url", "origin"],
            capture_output=True, text=True)
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def init_repo(repo_path: Path, *, repo_url: str | None = None,
              site: str = _DEFAULT_SITE) -> bool:
    """Insert the opt-in badge into `repo_path/README.md`. Returns True iff the file changed.

    Idempotent: if the badge marker is already present the file is left byte-for-byte intact
    and False is returned. Creates the README if absent, otherwise inserts the badge after the
    first markdown heading (or prepends it when there is no heading)."""
    repo_path = Path(repo_path)
    if repo_url is None:
        repo_url = _origin_url(repo_path) or "your repo URL"
    badge = badge_markdown(repo_url, site)
    readme = repo_path / "README.md"

    if not readme.exists():
        readme.write_text(f"# {repo_path.name}\n\n{badge}\n", encoding="utf-8")
        return True

    content = readme.read_text(encoding="utf-8")
    if BADGE_MARK in content:
        return False  # already opted in — no-op, no duplicate badge

    lines = content.splitlines()
    insert_at = next((i + 1 for i, ln in enumerate(lines)
                      if ln.lstrip().startswith("#")), None)

    if insert_at is None:
        # No heading to anchor under → the badge leads the file.
        new_content = f"{badge}\n\n{content}"
    else:
        block = ["", *badge.split("\n")]
        # Keep a blank line before following prose so the link renders as its own block.
        if insert_at < len(lines) and lines[insert_at].strip():
            block.append("")
        new_lines = lines[:insert_at] + block + lines[insert_at:]
        new_content = "\n".join(new_lines)
        if content.endswith("\n"):
            new_content += "\n"

    readme.write_text(new_content, encoding="utf-8")
    return True
