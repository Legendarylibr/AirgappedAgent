from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from airgap_agent.crypto.keys import load_private_key, load_public_key, resolve_public_key


@dataclass(frozen=True)
class SignatureEnvelope:
    version: int
    algorithm: str
    key_id: str
    target: str
    target_sha256: str
    signature_b64: str

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "target": self.target,
            "target_sha256": self.target_sha256,
            "signature": self.signature_b64,
        }

    @classmethod
    def from_dict(cls, data: dict) -> SignatureEnvelope:
        return cls(
            version=int(data["version"]),
            algorithm=str(data["algorithm"]),
            key_id=str(data["key_id"]),
            target=str(data["target"]),
            target_sha256=str(data["target_sha256"]),
            signature_b64=str(data["signature"]),
        )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def sign_bytes(private_key_path: Path, data: bytes) -> bytes:
    key = load_private_key(private_key_path)
    return key.sign(data)


def verify_bytes(public_key_path: Path, data: bytes, signature: bytes) -> bool:
    key = load_public_key(public_key_path)
    try:
        key.verify(signature, data)
        return True
    except Exception:
        return False


def sign_file(
    target: Path,
    private_key_path: Path,
    key_id: str,
    *,
    algorithm: str = "ed25519",
) -> SignatureEnvelope:
    target = target.resolve()
    digest = sha256_file(target)
    signature = sign_bytes(private_key_path, bytes.fromhex(digest))
    return SignatureEnvelope(
        version=1,
        algorithm=algorithm,
        key_id=key_id,
        target=target.name,
        target_sha256=digest,
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def write_envelope(envelope: SignatureEnvelope, path: Path) -> Path:
    path.write_text(json.dumps(envelope.to_dict(), indent=2) + "\n", encoding="utf-8")
    return path


def load_envelope(path: Path) -> SignatureEnvelope:
    return SignatureEnvelope.from_dict(json.loads(path.read_text(encoding="utf-8")))


def verify_envelope(
    envelope: SignatureEnvelope,
    target: Path,
    trust_dir: Path,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    target = target.resolve()

    if envelope.algorithm != "ed25519":
        errors.append(f"unsupported algorithm: {envelope.algorithm}")
        return False, errors

    if target.name != envelope.target:
        errors.append(f"target name mismatch: expected {envelope.target}, got {target.name}")

    actual = sha256_file(target)
    if actual != envelope.target_sha256:
        errors.append("target SHA-256 does not match envelope")

    try:
        public = resolve_public_key(trust_dir, envelope.key_id)
    except FileNotFoundError as exc:
        errors.append(str(exc))
        return False, errors

    signature = base64.b64decode(envelope.signature_b64.encode("ascii"))
    try:
        public.verify(signature, bytes.fromhex(envelope.target_sha256))
    except Exception:
        errors.append("Ed25519 signature verification failed")
        return False, errors

    return len(errors) == 0, errors
