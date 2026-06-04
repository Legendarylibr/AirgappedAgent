from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def generate_keypair(out_dir: Path, key_id: str) -> tuple[Path, Path]:
    """Create an Ed25519 keypair for offline signing (staging) and verification (deploy)."""
    out_dir = out_dir.resolve()
    trust_dir = out_dir / "trust"
    signing_dir = out_dir / "signing"
    trust_dir.mkdir(parents=True, exist_ok=True)
    signing_dir.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_path = signing_dir / f"{key_id}.pem"
    public_path = trust_dir / f"{key_id}.pub.pem"
    meta_path = trust_dir / f"{key_id}.json"

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_bytes)
    private_path.chmod(0o600)
    public_path.write_bytes(public_bytes)
    meta_path.write_text(
        json.dumps(
            {"key_id": key_id, "algorithm": "ed25519", "purpose": "release-signing"}, indent=2
        )
        + "\n",
        encoding="utf-8",
    )
    return private_path, public_path


def load_private_key(path: Path) -> Ed25519PrivateKey:
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def load_public_key(path: Path) -> Ed25519PublicKey:
    data = path.read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"expected Ed25519 public key: {path}")
    return key


def resolve_public_key(trust_dir: Path, key_id: str) -> Ed25519PublicKey:
    path = trust_dir / f"{key_id}.pub.pem"
    if not path.exists():
        raise FileNotFoundError(f"public key not found for key_id={key_id}: {path}")
    return load_public_key(path)
