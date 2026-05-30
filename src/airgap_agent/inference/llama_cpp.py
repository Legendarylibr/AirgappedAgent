from __future__ import annotations

from pathlib import Path
from threading import Lock
from typing import Any

from airgap_agent.config import InferenceSettings
from airgap_agent.inference.base import ChatMessage, CompletionResult, InferenceBackend
from airgap_agent.inference.chat_format import format_chat_prompt


class LlamaCppBackend(InferenceBackend):
    def __init__(self, settings: InferenceSettings) -> None:
        self._settings = settings
        try:
            from llama_cpp import Llama
        except ImportError as exc:
            raise RuntimeError(
                "llama-cpp-python is not installed. Install with: pip install 'airgap-agent[llama]'"
            ) from exc

        model_path = Path(settings.model_path)
        if not model_path.exists():
            raise FileNotFoundError(f"model not found: {model_path}")

        self._llm = Llama(
            model_path=str(model_path),
            n_ctx=settings.n_ctx,
            n_gpu_layers=settings.n_gpu_layers,
            verbose=False,
        )
        self._lock = Lock()

    def complete(self, messages: list[ChatMessage], **kwargs: Any) -> CompletionResult:
        temperature = kwargs.get("temperature", self._settings.temperature)
        max_tokens = kwargs.get("max_tokens", self._settings.max_tokens)
        prompt = format_chat_prompt(messages, self._settings.chat_template)
        stops = ["</s>", "USER:", "ASSISTANT:", "<|eot_id|>"]
        with self._lock:
            out = self._llm(
                prompt,
                max_tokens=max_tokens,
                temperature=temperature,
                stop=stops,
            )
        text = out["choices"][0]["text"].strip()
        return CompletionResult(content=text, finish_reason="stop")

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "backend": "llama_cpp",
            "model_path": str(self._settings.model_path),
            "n_ctx": self._settings.n_ctx,
            "chat_template": self._settings.chat_template,
        }
