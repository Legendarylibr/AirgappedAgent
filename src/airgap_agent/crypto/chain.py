from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS_HASH = "0" * 64
CHAIN_FIELDS = ("audit_seq", "audit_prev_hash", "audit_entry_hash")


def canonical_payload(record: dict[str, Any]) -> bytes:
    """Deterministic serialization for hash-chain verification (excludes chain fields)."""
    payload = {k: v for k, v in record.items() if k not in CHAIN_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def compute_entry_hash(prev_hash: str, record: dict[str, Any]) -> str:
    material = f"{prev_hash}\n".encode() + canonical_payload(record)
    return hashlib.sha256(material).hexdigest()


def attach_chain_fields(record: dict[str, Any], prev_hash: str, seq: int) -> dict[str, Any]:
    out = dict(record)
    out["audit_seq"] = seq
    out["audit_prev_hash"] = prev_hash
    out["audit_entry_hash"] = compute_entry_hash(prev_hash, out)
    return out


def verify_record_chain(record: dict[str, Any], expected_prev: str, expected_seq: int) -> bool:
    if record.get("audit_seq") != expected_seq:
        return False
    if record.get("audit_prev_hash") != expected_prev:
        return False
    expected_hash = compute_entry_hash(expected_prev, record)
    return record.get("audit_entry_hash") == expected_hash


def verify_audit_chain(lines: list[str]) -> tuple[bool, int, list[str]]:
    errors: list[str] = []
    prev = GENESIS_HASH
    verified = 0

    for i, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        if line.startswith("ENC1:"):
            errors.append(f"line {i}: encrypted audit line (supply decryption key to verify)")
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"line {i}: invalid JSON")
            continue
        if not isinstance(record, dict):
            errors.append(f"line {i}: expected JSON object")
            continue
        if not verify_record_chain(record, prev, verified + 1):
            errors.append(f"line {i}: hash chain broken at seq={verified + 1}")
            break
        prev = str(record["audit_entry_hash"])
        verified += 1

    ok = len(errors) == 0 and (verified > 0 or len([ln for ln in lines if ln.strip()]) == 0)
    return ok, verified, errors
