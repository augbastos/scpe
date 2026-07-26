"""The package must run from a checkout with nothing installed.

action.yml's level-2 branch now does what its level-1 branch has always done:

    PYTHONPATH="${{ github.action_path }}" python3 -m scpe.cli seal ...

No pipx, no pip, no package index — which means the bytes that decide a maintainer's gate
are the bytes of the tag the caller pinned, instead of whatever `pipx run --spec
scpe-protocol` happens to resolve at that moment inside an untrusted job. That property is
worth a test because it is invisible: a single `import cryptography` added for convenience
breaks it, and nothing else in the suite would notice until a runner did.
"""
from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "scpe"
SOURCES = sorted(PACKAGE.glob("*.py"))
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

# `reference` ships in the same distribution (pyproject packages.find includes reference*),
# and it is where the normative verifier and the reference producer live — importing it is
# the whole point of the adapter, not a dependency.
LOCAL_PACKAGES = {"scpe", "reference"}


def test_the_distribution_declares_no_runtime_dependencies():
    assert PYPROJECT["project"]["dependencies"] == [], (
        "a runtime dependency puts the package back behind an install step, and the Action "
        "can no longer run it straight out of github.action_path")


def test_the_mcp_extra_is_gone_and_ci_no_longer_asks_for_it():
    """The MCP server exposed the AGENT's tools (cc_pack/cc_verify/...). Dropping the extra
    without editing .github/workflows/ci.yml would fail BOTH Python jobs at dependency
    resolution — a confusing red that looks nothing like the change that caused it."""
    extras = PYPROJECT["project"].get("optional-dependencies", {})
    assert "mcp" not in extras
    assert "dev" in extras, "pytest/pyyaml are still needed to run this suite"
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "mcp]" not in ci and "[dev,mcp]" not in ci


def test_console_scripts_are_the_two_the_protocol_needs():
    scripts = PYPROJECT["project"]["scripts"]
    assert scripts["scpe"] == "scpe.cli:main"
    # The producer is the spec's own packing tool; it stays on PATH.
    assert scripts["scpe-envelope"] == "reference.producer:main"
    assert "scpe-mcp" not in scripts


@pytest.mark.parametrize("source", SOURCES, ids=lambda p: p.name)
def test_every_import_is_stdlib_or_local(source):
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:            # relative import: local by construction
                continue
            names = [node.module or ""]
        else:
            continue
        for name in names:
            root = name.split(".")[0]
            assert root in sys.stdlib_module_names or root in LOCAL_PACKAGES, (
                f"{source.name} imports third-party module {name!r}; the package has to "
                f"run from a bare checkout on a runner")


def test_the_package_is_small_enough_to_read():
    """The repositioning was from "an agent that happens to ship a protocol" to "the
    protocol, packaged". Size is the crudest possible proxy for that, and the only one
    that fails loudly when the drift starts again."""
    for source in SOURCES:
        lines = source.read_text(encoding="utf-8").splitlines()
        assert len(lines) < 500, f"{source.name} is {len(lines)} lines — split it"
