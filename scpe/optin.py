"""`init` — stamp the machine-detectable opt-in badge on a repo's README.

The badge is how a repo advertises "SCPE contributions welcome" in a way a
crawler can detect (the HTML comment anchor) and a human can click (the shields-style
image link). This module only touches README.md — it never commits, pushes, or reaches
the network; wiring into git is the caller's decision."""
from __future__ import annotations

from pathlib import Path

# Idempotency anchor: an invisible-in-rendered-markdown HTML comment. We key "already
# opted in?" off THIS marker, not the image URL, so a repo can restyle/move the badge
# without `init` re-inserting a duplicate.
BADGE_MARK = "<!-- scpe-optin -->"

# The badge is served from the project's own GitHub Pages site and links to the repository.
# It used to point at `scpe.dev`, a domain that was never registered. `scpe init` therefore
# wrote a broken image into a stranger's README — and an unregistered domain baked into a
# supply-chain tool is a takeover waiting to happen: whoever registered it would inherit every
# badge already written. The link was worse than the image. It carried `/go?repo=<your repo>`,
# a callback announcing the adopting repository to a host, in a project whose front page
# promises there is no SCPE server. Both are gone. Detection was never the image's job anyway:
# that is BADGE_MARK, which is inert text and reaches nothing.
_DEFAULT_SITE = "https://augbastos.github.io/scpe"
_PROJECT_URL = "https://github.com/augbastos/scpe"


def badge_markdown(site: str = _DEFAULT_SITE) -> str:
    """The two-line badge block: the detection anchor followed by the clickable image link.

    Takes no repository URL. It used to, and that was the defect: the URL existed only to be
    interpolated into a callback. The badge links to the protocol, not to a service that would
    have to be told about you."""
    return (f"{BADGE_MARK}\n"
            f"[![Contribute with SCPE]({site}/badge.svg)]({_PROJECT_URL})")


def init_repo(repo_path: Path, *, site: str = _DEFAULT_SITE) -> bool:
    """Insert the opt-in badge into `repo_path/README.md`. Returns True iff the file changed.

    Idempotent: if the badge marker is already present the file is left byte-for-byte intact
    and False is returned. Creates the README if absent, otherwise inserts the badge after the
    first markdown heading (or prepends it when there is no heading).

    This used to look up the repository's `origin` remote so the URL could be interpolated into
    a `/go?repo=` callback. The callback is gone, so the lookup is gone with it — nothing here
    shells out, and the adopting repository's identity is never read, let alone sent."""
    repo_path = Path(repo_path)
    badge = badge_markdown(site)
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
