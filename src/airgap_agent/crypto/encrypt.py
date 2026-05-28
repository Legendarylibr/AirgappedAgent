from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ENC_PREFIX = "ENC1:"
NONCE_LEN = 12
KEY_LEN = 32


def parse_key_material(raw: str) -> bytes:
    """Accept 64-char hex or base64-encoded 32-byte key."""
    stripped = raw.strip()
    if len(stripped) == 64 and all(c in "0123456789abcdefABCDEF" for c in stripped):
        key = bytes.fromhex(stripped)
    else:
        key = base64.b64decode(stripped.encode("ascii"))
    if len(key) != KEY_LEN:
        raise ValueError(f"audit encryption key must be {KEY_LEN} bytes")
    return key


def encrypt_bytes(key: bytes, plaintext: bytes, *, aad: bytes | None = None) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def decrypt_bytes(key: bytes, blob: bytes, *, aad: bytes | None = None) -> bytes:
    if len(blob) < NONCE_LEN + 16:
        raise ValueError("ciphertext too short")
    nonce, ciphertext = blob[:NONCE_LEN], blob[NONCE_LEN:]
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext, aad)


def seal_line(key: bytes, plaintext_line: str) -> str:
    blob = encrypt_bytes(key, plaintext_line.encode("utf-8"))
    return ENC_PREFIX + base64.b64encode(blob).decode("ascii")


def open_line(key: bytes, sealed_line: str) -> str:
    if not sealed_line.startswith(ENC_PREFIX):
        raise ValueError("not an encrypted audit line")
    blob = base64.b64decode(sealed_line[len(ENC_PREFIX) :].encode("ascii"))
    return decrypt_bytes(key, blob).decode("utf-8")
