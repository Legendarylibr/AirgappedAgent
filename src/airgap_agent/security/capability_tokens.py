from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))

def parse_hmac_key(raw: str) -> bytes:
    """
    Parse an HMAC key from hex or base64.

    - Prefer 32 bytes (256-bit) or longer.
    - Accept raw as:
      - 64+ hex chars (>= 32 bytes)
      - base64 string decoding to >= 32 bytes
    """
    s = raw.strip()
    if not s:
        raise ValueError("missing HMAC key material")

    is_hex = all(c in "0123456789abcdefABCDEF" for c in s)
    key: bytes
    if is_hex and len(s) % 2 == 0 and len(s) >= 64:
        key = bytes.fromhex(s)
    else:
        try:
            key = base64.b64decode(s.encode("ascii"), validate=True)
        except Exception as exc:
            raise ValueError("HMAC key must be hex (>=64 chars) or base64 (>=32 bytes)") from exc

    if len(key) < 32:
        raise ValueError("HMAC key must be at least 32 bytes")
    return key


@dataclass(frozen=True)
class CapabilityTokenClaims:
    iat: int
    exp: int
    caps: list[str]
    budgets: dict[str, int]
    nonce: str | None = None
    method: str | None = None
    path: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CapabilityTokenClaims":
        return cls(
            iat=int(d["iat"]),
            exp=int(d["exp"]),
            caps=list(d.get("caps", [])),
            budgets={str(k): int(v) for k, v in (d.get("budgets", {}) or {}).items()},
            nonce=d.get("nonce"),
            method=d.get("method"),
            path=d.get("path"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "iat": self.iat,
            "exp": self.exp,
            "caps": list(self.caps),
            "budgets": dict(self.budgets),
            "nonce": self.nonce,
            "method": self.method,
            "path": self.path,
        }


def mint_capability_token(
    key: bytes,
    *,
    caps: list[str],
    ttl_seconds: int,
    budgets: dict[str, int],
    nonce: str | None = None,
    method: str | None = None,
    path: str | None = None,
    now: int | None = None,
) -> str:
    now_ts = int(now if now is not None else time.time())
    claims = CapabilityTokenClaims(
        iat=now_ts,
        exp=now_ts + int(ttl_seconds),
        caps=sorted(set(caps)),
        budgets=budgets,
        nonce=nonce,
        method=method,
        path=path,
    )
    payload = json.dumps(claims.to_dict(), separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(key, payload, hashlib.sha256).digest()
    return f"{_b64url_encode(payload)}.{_b64url_encode(sig)}"


def verify_capability_token(key: bytes, token: str, *, now: int | None = None) -> CapabilityTokenClaims:
    try:
        payload_b64, sig_b64 = token.split(".", 1)
    except ValueError as exc:
        raise ValueError("invalid token format") from exc

    payload = _b64url_decode(payload_b64)
    sig = _b64url_decode(sig_b64)
    expected = hmac.new(key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("invalid token signature")

    data = json.loads(payload.decode("utf-8"))
    claims = CapabilityTokenClaims.from_dict(data)
    now_ts = int(now if now is not None else time.time())
    if claims.exp < now_ts:
        raise ValueError("token expired")
    if claims.iat > now_ts + 30:
        raise ValueError("token issued in the future")
    return claims

