from pathlib import Path
from scpe.signing import (
    generate_private_key_pem, public_key_hex, sign_bytes, verify_bytes, load_or_create_key,
)

def test_sign_and_verify_round_trip():
    pem = generate_private_key_pem()
    pub = public_key_hex(pem)
    assert len(pub) == 64
    sig = sign_bytes(pem, b"payload")
    assert verify_bytes(pub, b"payload", sig) is True

def test_verify_rejects_tamper_and_garbage():
    pem = generate_private_key_pem()
    pub = public_key_hex(pem)
    sig = sign_bytes(pem, b"payload")
    assert verify_bytes(pub, b"payload!", sig) is False
    assert verify_bytes(pub, b"payload", "00" * 64) is False
    assert verify_bytes("zz", b"payload", sig) is False  # invalid hex → False, not raise

def test_load_or_create_key_persists(tmp_path: Path):
    p = tmp_path / "keys" / "key.pem"
    pem1 = load_or_create_key(p)
    pem2 = load_or_create_key(p)
    assert pem1 == pem2 and p.exists()
