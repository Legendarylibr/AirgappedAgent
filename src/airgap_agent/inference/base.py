from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ChatMessage:
    role: str
    content: str


@dataclass
class CompletionResult:
    content: str
    finish_reason: str = "stop"
    usage: dict[str, int] | None = None


class InferenceBackend(ABC):
    @abstractmethod
    def complete(self, messages: list[ChatMessage], **kwargs: Any) -> CompletionResult:
        raise NotImplementedError

    def health(self) -> dict[str, Any]:
        return {"status": "ok", "backend": self.__class__.__name__}
