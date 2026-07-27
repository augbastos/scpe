"""Every `${{ … }}` in action.yml must be a non-empty expression.

GitHub's template engine parses expressions everywhere inside a composite action —
including inside `#` comments in a `run:` block, which are comments to the shell but
plain text to the parser. An empty `${{ }}` there is not ignored: the runner rejects
the whole manifest with

    action.yml (Line: N, Col: M): An expression was expected
    Failed to load augbastos/scpe/action.yml

before a single step executes. The Action does not misbehave — it does not load.

This is a regression guard for exactly that, introduced by a comment that explained
how to avoid pasting expressions into shell text by spelling one out. Nothing caught
it: `yaml.safe_load` accepts the file, the CI suite never invokes the Action, and the
failure only appears on a runner resolving `uses:`. The cheapest place to notice is
here, on a string scan that needs no runner at all.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "action.yml"

# Any `${{` up to its closing `}}`, non-greedy so adjacent expressions stay separate.
_EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)


def _expressions() -> list[tuple[int, str]]:
    text = ACTION.read_text(encoding="utf-8")
    out = []
    for m in _EXPR.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        out.append((line, m.group(1)))
    return out


def test_action_yml_exists():
    assert ACTION.is_file(), "action.yml is the Action; without it there is nothing to publish"


def test_every_expression_has_a_body():
    empty = [(line, raw) for line, raw in _expressions() if not raw.strip()]
    assert not empty, (
        "empty GitHub expression(s) in action.yml at line(s) "
        f"{[line for line, _ in empty]} — the runner rejects the whole manifest with "
        "'An expression was expected' and the Action fails to load. Describe expressions "
        "in prose instead of writing an empty one, even in a comment."
    )


def test_expressions_are_balanced():
    text = ACTION.read_text(encoding="utf-8")
    assert text.count("${{") == text.count("}}"), (
        f"unbalanced expression delimiters: {text.count('${{')} opening vs "
        f"{text.count('}}')} closing")


@pytest.mark.parametrize("line,raw", _expressions())
def test_expression_looks_like_a_reference(line, raw):
    """Beyond non-empty: an expression here should name something. A bare operator or
    punctuation is the same class of typo and fails the same way on a runner."""
    body = raw.strip()
    assert re.search(r"[A-Za-z_]", body), (
        f"action.yml line {line}: expression {{{{{raw}}}}} contains no identifier")
