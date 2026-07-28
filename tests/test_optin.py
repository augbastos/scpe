from pathlib import Path

from scpe.optin import BADGE_MARK, badge_markdown, init_repo


def test_badge_markdown_shape():
    md = badge_markdown()
    assert md.startswith(BADGE_MARK + "\n")
    assert "https://augbastos.github.io/scpe/badge.svg" in md
    assert "https://github.com/augbastos/scpe" in md


def test_badge_names_no_unregistered_domain():
    """The regression this file failed to catch for three releases.

    `scpe init` shipped a badge pointing at `scpe.dev`, a domain nobody had registered. It
    wrote a broken image into the README of anyone who ran the project's own adoption command,
    and an unregistered domain welded into a supply-chain tool is a takeover waiting to happen:
    whoever registered it would have inherited every badge already written.

    The reason it survived is in this file's own history — the previous test asserted the dead
    URLs verbatim, so CI could not tell "correct" from "unchanged". Pinning a constant proves
    the constant did not move; it proves nothing about whether it was ever right. This asserts
    the property instead."""
    md = badge_markdown()
    assert "scpe.dev" not in md


def test_badge_sends_nothing_about_the_adopting_repo():
    """No callback, and no repository URL available to put in one.

    The badge link used to be `<site>/go?repo=<your repo url>` — a request announcing the
    adopting repository to a host, in a project whose front page promises there is no SCPE
    server and nothing to shut down. The parameter that fed it is gone from the signature, so
    the shape cannot return by someone re-adding a template variable."""
    md = badge_markdown()
    assert "/go?" not in md and "?repo=" not in md
    assert badge_markdown.__code__.co_argcount == 1  # `site` only


def test_site_is_overridable(tmp_path: Path):
    """No domain is welded in without an escape hatch. A mirror can serve its own copy."""
    assert "https://mirror.example/scpe/badge.svg" in badge_markdown(
        site="https://mirror.example/scpe")
    repo = tmp_path / "m"
    repo.mkdir()
    assert init_repo(repo, site="https://mirror.example/scpe") is True
    assert "https://mirror.example/scpe/badge.svg" in (repo / "README.md").read_text(
        encoding="utf-8")


def test_init_adds_badge_to_readme(fixture_repo: Path):
    readme = fixture_repo / "README.md"
    readme.write_text("# Fixture\n\nA demo repo.\n", encoding="utf-8")
    changed = init_repo(fixture_repo)
    assert changed is True
    text = readme.read_text(encoding="utf-8")
    assert BADGE_MARK in text
    assert "badge.svg" in text
    # Original content survives; badge sits under the first heading.
    assert "# Fixture" in text and "A demo repo." in text
    assert text.index("# Fixture") < text.index(BADGE_MARK) < text.index("A demo repo.")


def test_init_idempotent(fixture_repo: Path):
    readme = fixture_repo / "README.md"
    readme.write_text("# Fixture\n\nA demo repo.\n", encoding="utf-8")
    assert init_repo(fixture_repo) is True
    after_first = readme.read_text(encoding="utf-8")
    assert init_repo(fixture_repo) is False
    assert readme.read_text(encoding="utf-8") == after_first
    # Exactly one badge marker — never a stacked duplicate.
    assert after_first.count(BADGE_MARK) == 1


def test_init_creates_readme_if_absent(tmp_path: Path):
    repo = tmp_path / "fresh"
    repo.mkdir()
    readme = repo / "README.md"
    assert not readme.exists()
    changed = init_repo(repo)
    assert changed is True
    text = readme.read_text(encoding="utf-8")
    assert BADGE_MARK in text
    assert "# fresh" in text  # repo name becomes the heading


def test_init_prepends_when_no_heading(tmp_path: Path):
    repo = tmp_path / "noh"
    repo.mkdir()
    readme = repo / "README.md"
    readme.write_text("just some prose, no markdown heading\n", encoding="utf-8")
    assert init_repo(repo) is True
    text = readme.read_text(encoding="utf-8")
    # No heading → badge goes to the very top, prose preserved below it.
    assert text.index(BADGE_MARK) < text.index("just some prose")


def test_init_reads_no_git_state(fixture_repo: Path):
    """`init` used to shell out to `git remote get-url origin` purely to fill the callback.

    With the callback gone the lookup is gone: the module imports no subprocess at all, so a
    repo with no remote, no git, or a git that hangs behaves identically to one without."""
    import scpe.optin as optin
    assert not hasattr(optin, "subprocess")
    assert not hasattr(optin, "_origin_url")
    readme = fixture_repo / "README.md"
    readme.write_text("# Fixture\n", encoding="utf-8")
    assert init_repo(fixture_repo) is True
    assert BADGE_MARK in readme.read_text(encoding="utf-8")
