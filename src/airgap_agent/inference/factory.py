from __future__ import annotations

from airgap_agent.config import AppConfig
from airgap_agent.inference.base import InferenceBackend
from airgap_agent.inference.llama_cpp import LlamaCppBackend
from airgap_agent.inference.mock import MockBackend
from airgap_agent.inference.openai_compat import OpenAICompatBackend


def create_backend(config: AppConfig) -> InferenceBackend:
    backend = config.inference.backend
    if backend == "mock":
        return MockBackend()
    if backend == "llama_cpp":
        return LlamaCppBackend(config.inference)
    if backend == "openai_compat":
        return OpenAICompatBackend(config.inference)
    raise ValueError(f"unknown inference backend: {backend}")
