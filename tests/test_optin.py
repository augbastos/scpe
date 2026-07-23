from pathlib import Path

from scpe.optin import BADGE_MARK, badge_markdown, init_repo


def test_badge_markdown_shape():
    md = badge_markdown("https://github.com/x/y")
    assert md.startswith(BADGE_MARK + "\n")
    assert "https://scpe.dev/badge.svg" in md
    assert "https://scpe.dev/go?repo=https://github.com/x/y" in md


def test_init_adds_badge_to_readme(fixture_repo: Path):
    readme = fixture_repo / "README.md"
    readme.write_text("# Fixture\n\nA demo repo.\n", encoding="utf-8")
    changed = init_repo(fixture_repo, repo_url="https://github.com/x/y")
    assert changed is True
    text = readme.read_text(encoding="utf-8")
    assert BADGE_MARK in text
    assert "https://github.com/x/y" in text
    assert "badge.svg" in text
    # Original content survives; badge sits under the first heading.
    assert "# Fixture" in text and "A demo repo." in text
    assert text.index("# Fixture") < text.index(BADGE_MARK) < text.index("A demo repo.")


def test_init_idempotent(fixture_repo: Path):
    readme = fixture_repo / "README.md"
    readme.write_text("# Fixture\n\nA demo repo.\n", encoding="utf-8")
    assert init_repo(fixture_repo, repo_url="https://github.com/x/y") is True
    after_first = readme.read_text(encoding="utf-8")
    assert init_repo(fixture_repo, repo_url="https://github.com/x/y") is False
    assert readme.read_text(encoding="utf-8") == after_first
    # Exactly one badge marker — never a stacked duplicate.
    assert after_first.count(BADGE_MARK) == 1


def test_init_creates_readme_if_absent(tmp_path: Path):
    repo = tmp_path / "fresh"
    repo.mkdir()
    readme = repo / "README.md"
    assert not readme.exists()
    changed = init_repo(repo, repo_url="https://github.com/a/b")
    assert changed is True
    text = readme.read_text(encoding="utf-8")
    assert BADGE_MARK in text
    assert "https://github.com/a/b" in text
    assert "# fresh" in text  # repo name becomes the heading


def test_init_prepends_when_no_heading(tmp_path: Path):
    repo = tmp_path / "noh"
    repo.mkdir()
    readme = repo / "README.md"
    readme.write_text("just some prose, no markdown heading\n", encoding="utf-8")
    assert init_repo(repo, repo_url="https://github.com/a/b") is True
    text = readme.read_text(encoding="utf-8")
    # No heading → badge goes to the very top, prose preserved below it.
    assert text.index(BADGE_MARK) < text.index("just some prose")


def test_init_falls_back_when_no_origin(fixture_repo: Path):
    # fixture_repo has no 'origin' remote → best-effort lookup fails → placeholder url.
    readme = fixture_repo / "README.md"
    readme.write_text("# Fixture\n", encoding="utf-8")
    assert init_repo(fixture_repo) is True
    text = readme.read_text(encoding="utf-8")
    assert BADGE_MARK in text
    assert "your repo URL" in text
