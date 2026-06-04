from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

from airgap_agent.config import AuditSettings
from airgap_agent.crypto.chain import GENESIS_HASH, attach_chain_fields, verify_record_chain
from airgap_agent.crypto.encrypt import open_line, parse_key_material, seal_line

logger = structlog.get_logger(__name__)


class AuditLogger:
    def __init__(self, settings: AuditSettings) -> None:
        self._settings = settings
        self._run_id = uuid.uuid4().hex
        self._prev_hash = GENESIS_HASH
        self._seq = 0
        self._encrypt_key: bytes | None = None
        if settings.enabled:
            settings.log_path.parent.mkdir(parents=True, exist_ok=True)
        if settings.encrypt_at_rest:
            raw = os.environ.get(settings.encryption_key_env, "")
            if not raw:
                raise ValueError(
                    f"audit.encrypt_at_rest requires {settings.encryption_key_env} to be set"
                )
            self._encrypt_key = parse_key_material(raw)
        self._restore_chain_state()

    def _decode_line(self, line: str) -> str | None:
        line = line.strip()
        if not line:
            return None
        if line.startswith("ENC1:"):
            if self._encrypt_key is None:
                return None
            return open_line(self._encrypt_key, line)
        return line

    def _restore_chain_state(self) -> None:
        path = self._settings.log_path
        if not path.exists() or not self._settings.hash_chain:
            return
        last_hash = GENESIS_HASH
        seq = 0
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            decoded = self._decode_line(raw_line)
            if decoded is None:
                continue
            try:
                record = json.loads(decoded)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict) or "audit_entry_hash" not in record:
                continue
            if not verify_record_chain(record, last_hash, seq + 1):
                logger.warning("audit.chain_break_on_restore", seq=seq + 1)
                break
            last_hash = str(record["audit_entry_hash"])
            seq = int(record["audit_seq"])
        self._prev_hash = last_hash
        self._seq = seq

    def emit(self, event: str, **fields: Any) -> None:
        record: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
            "pid": os.getpid(),
            "run_id": self._run_id,
            **fields,
        }
        if not self._settings.enabled:
            logger.info("audit.disabled", audit_event=event)
            return
        if not self._settings.include_prompts:
            record.pop("prompt", None)
            record.pop("messages", None)

        if self._settings.hash_chain:
            self._seq += 1
            record = attach_chain_fields(record, self._prev_hash, self._seq)
            self._prev_hash = str(record["audit_entry_hash"])

        line = json.dumps(record, default=str)
        self._append(line)
        logger.info(event, **{k: v for k, v in fields.items() if k not in ("prompt", "messages")})

    def _append(self, line: str) -> None:
        if self._encrypt_key is not None:
            line = seal_line(self._encrypt_key, line)
        path = self._settings.log_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
