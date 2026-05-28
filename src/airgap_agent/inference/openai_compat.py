from __future__ import annotations

import os
from typing import Any

import httpx

from airgap_agent.config import InferenceSettings
from airgap_agent.inference.base import ChatMessage, CompletionResult, InferenceBackend


class OpenAICompatBackend(InferenceBackend):
    """Talks only to a loopback OpenAI-compatible server (vLLM, llama.cpp server, etc.)."""

    def __init__(self, settings: InferenceSettings) -> None:
        self._settings = settings
        api_key = os.environ.get(settings.api_key_env, "local-only")
        self._client = httpx.Client(
            base_url=settings.base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=httpx.Timeout(120.0, connect=5.0),
            trust_env=False,  # ignore HTTP_PROXY in airgapped environments
        )

    def complete(self, messages: list[ChatMessage], **kwargs: Any) -> CompletionResult:
        payload = {
            "model": kwargs.get("model", "local"),
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": kwargs.get("temperature", self._settings.temperature),
            "max_tokens": kwargs.get("max_tokens", self._settings.max_tokens),
        }
        resp = self._client.post("/chat/completions", json=payload)
        resp.raise_for_status()
        data = resp.json()
        choice = data["choices"][0]
        usage = data.get("usage")
        return CompletionResult(
            content=choice["message"]["content"],
            finish_reason=choice.get("finish_reason", "stop"),
            usage=usage,
        )

    def health(self) -> dict[str, Any]:
        try:
            r = self._client.get("/models")
            ok = r.status_code == 200
        except httpx.HTTPError:
            ok = False
        return {
            "status": "ok" if ok else "degraded",
            "backend": "openai_compat",
            "base_url": self._settings.base_url,
        }
