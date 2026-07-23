"""The SCPE standalone reference verifier — one file, stdlib only.

`verify_envelope.py` keeps its own `if __name__ == "__main__"` guard, so it stays
runnable as a plain file exactly as the spec/test-vectors invoke it; this
`__init__` only makes it a discoverable subpackage so the build ships it.
"""
