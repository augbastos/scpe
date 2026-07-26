"""Static guard: the package must not grow a second verifier.

"Reuse, never duplicate" is easy to agree with and easy to erode one convenience function
at a time — a local sha256 of the diff here, a key fetch there, and six months later there
are two answers to "who signed this" and no way to tell which one a seal reported.

These are grep-shaped assertions on purpose. They cannot prove the package defers to
reference/standalone/verify_envelope.py (tests/test_verify_cli_parity.py does that by
comparing output); what they do is make the duplication expensive to start.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "scpe"
SOURCES = sorted(PACKAGE.glob("*.py"))

# Signature and integrity machinery — every one of these belongs to §8 and lives in the
# one file the vectors and the Go/Rust ports are measured against.
VERIFIER_INTERNALS = ("ssh-keygen", "-Y verify", "SSHSIG", "diff_sha256",
                      "allowed_signers", "PROVIDER_HOSTS")

# Modules that could reach the network. Key resolution (§8 step 4) is the verifier's, and
# its rules are strict — fixed provider registry, no redirects, host re-checked on the
# final URL, 1 MiB cap. A second fetcher here would be a weaker copy of that.
NETWORK_MODULES = {"urllib", "http", "socket", "ssl", "ftplib", "smtplib", "telnetlib",
                   "requests", "httpx", "aiohttp"}

# Seven of the eight §8 statuses. "verified" is left out because it is also an ordinary
# English word this package legitimately prints ("identity verified", a green badge); the
# comparison against it is covered separately below.
STATUS_LITERALS = ("unattested", "unsupported-version", "unsupported-provider",
                   "unsupported-subject", "identity-unverifiable", "signature-invalid",
                   "tampered")


def _quoted(needle: str) -> re.Pattern:
    return re.compile(rf"""['"]{re.escape(needle)}['"]""")


def test_the_package_has_sources_to_scan():
    # A scan over an empty set passes vacuously; make that impossible.
    assert len(SOURCES) >= 5, [p.name for p in SOURCES]


@pytest.mark.parametrize("source", SOURCES, ids=lambda p: p.name)
def test_no_module_reimplements_verifier_internals(source):
    text = source.read_text(encoding="utf-8")
    for needle in VERIFIER_INTERNALS:
        assert needle not in text, (
            f"{source.name} mentions {needle!r} — signature and integrity checking is "
            f"reference/standalone/verify_envelope.py's job, and having it in two places "
            f"means two possible verdicts for one set of bytes")


@pytest.mark.parametrize("source", SOURCES, ids=lambda p: p.name)
def test_no_module_can_reach_the_network(source):
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            continue
        for name in names:
            root = name.split(".")[0]
            assert root not in NETWORK_MODULES, (
                f"{source.name} imports {name!r}: this package renders and reports, it "
                f"never fetches — a key resolved here would be a second, weaker answer "
                f"to §8 step 4")


@pytest.mark.parametrize("source", [p for p in SOURCES if p.name != "results.py"],
                         ids=lambda p: p.name)
def test_only_results_py_names_a_status(source):
    """One module maps the verifier's word onto results.json. Everywhere else, a status is
    a value that arrived from somewhere — never a string this package chose."""
    text = source.read_text(encoding="utf-8")
    for status in STATUS_LITERALS:
        assert not _quoted(status).search(text), (
            f"{source.name} contains the literal {status!r}; §8 statuses belong to "
            f"scpe/results.py alone")


@pytest.mark.parametrize("source", [p for p in SOURCES if p.name != "results.py"],
                         ids=lambda p: p.name)
def test_only_results_py_decides_what_verified_means(source):
    """`verified` is the one status word that also reads as prose, so the guard is on the
    COMPARISON rather than the string: the rule "verified iff status == 'verified'" has
    exactly one home, and every consumer reads the boolean it produced."""
    text = source.read_text(encoding="utf-8")
    assert not re.search(r"""[=!]=\s*['"]verified['"]""", text), (
        f"{source.name} re-derives the verified boolean instead of reading it")


def test_the_reference_verifier_is_still_the_single_file_it_claims_to_be():
    """The other half of the same promise, restated where a package author will see it:
    the verifier must not start importing the package it is now reused BY.
    tests/test_spec_vectors.py holds the same line; this repeats it here because the
    temptation ("just import scpe.diffinfo") arrives while editing the package."""
    src = (ROOT / "reference" / "standalone" / "verify_envelope.py").read_text(
        encoding="utf-8")
    for banned in ("from scpe", "import scpe", "import requests", "import cryptography"):
        assert banned not in src
