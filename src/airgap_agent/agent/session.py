from __future__ import annotations

import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from threading import Lock

from airgap_agent.agent.tool_gate import normalize_user_task, sanitize_untrusted_content
from airgap_agent.inference.base import ChatMessage


@dataclass
class SessionRecord:
    session_id: str
    messages: list[ChatMessage] = field(default_factory=list)
    updated_at: float = field(default_factory=time.time)


class SessionStore:
    """Bounded in-memory conversation store for loopback API multi-turn runs."""

    def __init__(
        self, *, max_sessions: int = 100, max_messages: int = 50, ttl_seconds: int = 3600
    ) -> None:
        self._max_sessions = max_sessions
        self._max_messages = max_messages
        self._ttl_seconds = ttl_seconds
        self._sessions: OrderedDict[str, SessionRecord] = OrderedDict()
        self._lock = Lock()

    def create(self) -> str:
        session_id = uuid.uuid4().hex
        with self._lock:
            self._sessions[session_id] = SessionRecord(session_id=session_id)
            self._evict()
        return session_id

    def get_history(self, session_id: str) -> list[ChatMessage] | None:
        with self._lock:
            self._purge_expired()
            rec = self._sessions.get(session_id)
            if rec is None:
                return None
            self._sessions.move_to_end(session_id)
            return list(rec.messages)

    @staticmethod
    def _sanitize_for_storage(messages: list[ChatMessage]) -> list[ChatMessage]:
        stored: list[ChatMessage] = []
        for msg in messages:
            if msg.role == "user":
                body = normalize_user_task(msg.content, max_chars=32_000)
            else:
                body = sanitize_untrusted_content(msg.content)
            stored.append(ChatMessage(role=msg.role, content=body))
        return stored

    def append(self, session_id: str, messages: list[ChatMessage]) -> bool:
        with self._lock:
            self._purge_expired()
            rec = self._sessions.get(session_id)
            if rec is None:
                return False
            rec.messages.extend(self._sanitize_for_storage(messages))
            if len(rec.messages) > self._max_messages:
                rec.messages = rec.messages[-self._max_messages :]
            rec.updated_at = time.time()
            self._sessions.move_to_end(session_id)
            return True

    def delete(self, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def stats(self) -> dict[str, int]:
        with self._lock:
            self._purge_expired()
            return {"active_sessions": len(self._sessions)}

    def _purge_expired(self) -> None:
        now = time.time()
        expired = [
            sid for sid, rec in self._sessions.items() if now - rec.updated_at > self._ttl_seconds
        ]
        for sid in expired:
            self._sessions.pop(sid, None)

    def _evict(self) -> None:
        self._purge_expired()
        while len(self._sessions) > self._max_sessions:
            self._sessions.popitem(last=False)
