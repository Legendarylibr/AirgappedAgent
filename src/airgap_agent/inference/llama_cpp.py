from __future__ import annotations

from pathlib import Path
from typing import Any

from airgap_agent.config import InferenceSettings
from airgap_agent.inference.base import ChatMessage, CompletionResult, InferenceBackend


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

    def complete(self, messages: list[ChatMessage], **kwargs: Any) -> CompletionResult:
        temperature = kwargs.get("temperature", self._settings.temperature)
        max_tokens = kwargs.get("max_tokens", self._settings.max_tokens)
        prompt = self._format_prompt(messages)
        out = self._llm(
            prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            stop=["</s>", "USER:", "ASSISTANT:"],
        )
        text = out["choices"][0]["text"].strip()
        return CompletionResult(content=text, finish_reason="stop")

    @staticmethod
    def _format_prompt(messages: list[ChatMessage]) -> str:
        parts: list[str] = []
        for m in messages:
            role = m.role.upper()
            parts.append(f"{role}:\n{m.content}\n")
        parts.append("ASSISTANT:\n")
        return "\n".join(parts)

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "backend": "llama_cpp",
            "model_path": str(self._settings.model_path),
            "n_ctx": self._settings.n_ctx,
        }
