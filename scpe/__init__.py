"""SCPE — the installable distribution of the protocol: verify, seal, disclose.

This package is a thin adapter, not a second implementation. Every verdict it reports
comes from reference/standalone/verify_envelope.py — the one-file, stdlib-only normative
verifier (SPEC §8) that the eighteen test vectors and the Go/Rust ports are measured
against. What lives here is everything the protocol deliberately leaves outside the
verifier: which bytes to verify, where the diff comes from, the machine-readable
results.json a CI job hands between its untrusted and trusted halves, the rendered seal,
and the repo opt-in badge.

Stdlib only, on purpose: with no third-party dependency the whole package runs straight
from a checkout (`PYTHONPATH=<action_path> python3 -m scpe.cli`), so a CI job verifies
with the exact bytes of the tag it pinned rather than whatever a package index serves
at that moment.
"""
__version__ = "0.2.3"
