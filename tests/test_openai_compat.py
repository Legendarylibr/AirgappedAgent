from __future__ import annotations

import json

import httpx
import pytest

from airgap_agent.config import InferenceSettings
from airgap_agent.inference.base import ChatMessage
from airgap_agent.inference.openai_compat import OpenAICompatBackend


def test_openai_compat_empty_choices_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": []})

    transport = httpx.MockTransport(handler)
    settings = InferenceSettings(base_url="http://127.0.0.1:8080/v1")
    backend = OpenAICompatBackend(settings)
    backend._client = httpx.Client(
        base_url=settings.base_url,
        transport=transport,
        timeout=httpx.Timeout(5.0),
    )
    with pytest.raises(RuntimeError, match="empty choices"):
        backend.complete([ChatMessage(role="user", content="hi")])


def test_openai_compat_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert payload["messages"][0]["content"] == "hi"
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "hello"}, "finish_reason": "stop"}],
                "usage": {"total_tokens": 3},
            },
        )

    transport = httpx.MockTransport(handler)
    settings = InferenceSettings(base_url="http://127.0.0.1:8080/v1")
    backend = OpenAICompatBackend(settings)
    backend._client = httpx.Client(
        base_url=settings.base_url,
        transport=transport,
        timeout=httpx.Timeout(5.0),
    )
    result = backend.complete([ChatMessage(role="user", content="hi")])
    assert result.content == "hello"
    assert result.finish_reason == "stop"
