from __future__ import annotations

import json
from typing import Any

from airgap_agent.inference.base import ChatMessage, CompletionResult, InferenceBackend


class MockBackend(InferenceBackend):
    """Deterministic offline backend for CI and dry-runs without GPU weights."""

    def complete(self, messages: list[ChatMessage], **kwargs: Any) -> CompletionResult:
        last_user = next((m.content for m in reversed(messages) if m.role == "user"), "")
        if "untrusted_tool_result" in last_user and "FORMAT: json" in last_user:
            return CompletionResult(
                content="Task completed using workspace data from the airgapped sandbox.",
                finish_reason="stop",
            )
        payload = {
            "tool": "list_directory",
            "arguments": {"path": "."},
        }
        return CompletionResult(
            content=f"TOOL_CALL\n{json.dumps(payload)}",
            finish_reason="stop",
        )
