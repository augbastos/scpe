"""SCPE scpe/0.1 reference implementation.

Two auditable, stdlib-only files:
    producer.py            the signing side (pack / attest / verify / submit)
    standalone/verify_envelope.py  the verifier (SPEC.md §8, verbatim)

Importing this package pulls in nothing heavy: `import reference.producer` only
loads the producer module (stdlib imports), and the standalone verifier stays
runnable as a plain file (`python reference/standalone/verify_envelope.py ...`).
"""
