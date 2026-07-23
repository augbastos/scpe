"""Ed25519 signing for Envelope provenance. The signature proves only
'a real keyholder produced this, unaltered' — anti-forgery, never trust."""
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)


def generate_private_key_pem() -> bytes:
    key = Ed25519PrivateKey.generate()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _load(private_pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    return key


def public_key_hex(private_pem: bytes) -> str:
    return _load(private_pem).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    ).hex()


def sign_bytes(private_pem: bytes, data: bytes) -> str:
    return _load(private_pem).sign(data).hex()


def verify_bytes(public_hex: str, data: bytes, signature_hex: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        pub.verify(bytes.fromhex(signature_hex), data)
        return True
    except Exception:
        return False


def load_or_create_key(path: Path) -> bytes:
    path = Path(path)
    if path.exists():
        return path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = generate_private_key_pem()
    path.write_bytes(pem)
    return pem
