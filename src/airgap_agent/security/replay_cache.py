from __future__ import annotations

import json
import time
from pathlib import Path


class ReplayNonceCache:
    """Tracks used capability-token nonces (in-memory with optional disk persistence)."""

    def __init__(self, path: Path | None, *, max_entries: int) -> None:
        self._path = path
        self._max_entries = max_entries
        self._nonces: dict[str, int] = {}
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._load()

    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        if isinstance(raw, dict):
            self._nonces = {str(k): int(v) for k, v in raw.items()}

    def _persist(self) -> None:
        if self._path is None:
            return
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._nonces), encoding="utf-8")
        tmp.replace(self._path)

    def _prune(self, now: int) -> None:
        for key, exp in list(self._nonces.items()):
            if exp <= now:
                self._nonces.pop(key, None)

    def _trim(self) -> None:
        if len(self._nonces) <= self._max_entries:
            return
        overflow = len(self._nonces) - self._max_entries
        for key in list(self._nonces.keys())[:overflow]:
            self._nonces.pop(key, None)

    def accept(self, nonce: str, exp: int) -> bool:
        """
        Record nonce if fresh. Returns True when accepted, False on replay or missing nonce.
        """
        if not nonce:
            return False
        now = int(time.time())
        self._prune(now)
        if nonce in self._nonces:
            return False
        self._nonces[str(nonce)] = int(exp)
        self._trim()
        self._persist()
        return True
