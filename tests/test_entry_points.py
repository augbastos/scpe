"""Every console script the distribution advertises must actually resolve.

`[project.scripts]` is a promise made to anyone who installs the package, and it is the one
promise this suite could not previously keep. tests/test_package_is_stdlib_only.py asserts
that the DECLARATION reads `scpe = "scpe.cli:main"` — a string comparison inside
pyproject.toml, which never imports anything. Everywhere else the suite drives
`python -m scpe.cli` (tests/conftest.py, action.yml), because that is what a runner does
from a checkout. So a typo in an entry-point target, a module that stopped being
importable, or a `main` that lost its zero-argument form would leave the whole suite green
and break on the first `scpe verify` a stranger runs after `pip install`.

This file closes that by RESOLVING each declaration: import the module named on the left of
the colon, look up the attribute on the right, and check it is callable the way a generated
console script calls it — `sys.exit(main())`, with no arguments.

Nothing is installed and no wheel is built; that stays out of scope here on purpose (see
the note under the packaging test below). What this file can do without an install, it
does: it proves the targets exist in this checkout, and that the packaging configuration
would carry them.
"""
from __future__ import annotations

import fnmatch
import importlib
import inspect
import tomllib
from pathlib import Path

import pytest

import scpe

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
SCRIPTS = PYPROJECT["project"]["scripts"]
PACKAGE_INCLUDES = PYPROJECT["tool"]["setuptools"]["packages"]["find"]["include"]

# Not an entry point, and that is exactly why it is listed. `scpe/cli.py` and
# `scpe/verify.py` import `reference.standalone.verify_envelope` at module scope, so the
# console script `scpe` cannot start unless `reference` ships alongside `scpe`. The suite
# runs against an editable install (ci.yml: `pip install -e ".[dev]"`), which resolves the
# import from the source tree no matter what the packaging configuration says — so if
# `reference*` ever fell out of the include list, every test here would stay green and the
# published wheel would ImportError on its first invocation.
TRANSITIVE_SHIPPED_MODULES = ("reference.standalone.verify_envelope",)


def _target(spec: str) -> tuple[str, str]:
    module, _, attr = spec.partition(":")
    assert module and attr, f"{spec!r} is not a valid console-script target"
    return module, attr


@pytest.mark.parametrize("name", sorted(SCRIPTS), ids=lambda n: n)
def test_the_declared_target_imports_and_is_callable(name):
    """The literal contract of a console script: import the module, get the attribute,
    call it with nothing. A generated wrapper does no more than that, so anything this
    check accepts, `pip install` will run."""
    module_name, attr = _target(SCRIPTS[name])
    module = importlib.import_module(module_name)

    assert hasattr(module, attr), (
        f"console script {name!r} points at {SCRIPTS[name]!r}, but {module_name} has no "
        f"{attr!r} — installing this package would produce a command that cannot start")
    fn = getattr(module, attr)
    assert callable(fn), f"{SCRIPTS[name]!r} is not callable"

    # Zero-argument form. `main(argv=None)` qualifies; `main(argv)` does not, and the
    # failure would only ever be seen by someone who installed the package.
    try:
        inspect.signature(fn).bind()
    except TypeError as exc:
        pytest.fail(f"{SCRIPTS[name]!r} cannot be called as `{attr}()`, which is the only "
                    f"way a console script calls it: {exc}")


@pytest.mark.parametrize("name", sorted(SCRIPTS), ids=lambda n: n)
def test_the_target_resolves_inside_this_checkout(name):
    """Guards against the suite testing someone else's copy. `scpe-protocol` exists on
    PyPI, and a stray non-editable install of an older release would satisfy the import
    above while every assertion in this repository quietly described code that is not in
    it. The module has to come from this working tree."""
    module_name, _attr = _target(SCRIPTS[name])
    module = importlib.import_module(module_name)
    origin = Path(module.__file__).resolve()
    assert origin.is_relative_to(ROOT), (
        f"{module_name} resolved to {origin}, outside {ROOT} — the tests are running "
        f"against an installed copy of scpe-protocol, not against this checkout. Reinstall "
        f"it editable (`pip install -e \".[dev]\"`) or drop it from the environment.")


@pytest.mark.parametrize(
    "module_name",
    sorted({_target(spec)[0] for spec in SCRIPTS.values()} | set(TRANSITIVE_SHIPPED_MODULES)),
    ids=lambda n: n)
def test_the_packaging_configuration_would_ship_the_module(module_name):
    """Static half of the packaging question: is the module's containing package matched by
    `[tool.setuptools.packages.find] include`?

    This is a configuration check, not a proof — it cannot detect a wheel that was built
    wrong for some other reason. The real assurance is installing the built artifacts into
    a clean environment and running each advertised command there, which belongs in CI
    (it needs a build step and network-free venv creation, neither of which a unit test
    should be doing). Until that job exists, this catches the specific mistake that is easy
    to make and impossible to see locally: narrowing the include list while an editable
    install keeps every import working from the source tree.
    """
    # setuptools matches these globs against the FULL dotted package name, so
    # `reference.standalone` is covered by `reference*` — check the same string it does,
    # not just the first segment.
    package = module_name.rsplit(".", 1)[0]
    assert any(fnmatch.fnmatch(package, pattern) for pattern in PACKAGE_INCLUDES), (
        f"{module_name} is shipped code, but its package {package!r} matches none of the "
        f"packaging include patterns {PACKAGE_INCLUDES} — it would be missing from the "
        f"wheel while an editable install keeps this suite green")


def test_the_version_the_cli_prints_is_the_version_the_distribution_declares():
    """`scpe --version` reads `scpe.__version__`; the index reads `[project] version`. Two
    sources for one number, and the one users quote in a bug report is the CLI's. They have
    to be the same string, or a release is shipped under a version nobody can reproduce."""
    assert scpe.__version__ == PYPROJECT["project"]["version"], (
        f"scpe/__init__.py says {scpe.__version__!r} and pyproject.toml says "
        f"{PYPROJECT['project']['version']!r}")
