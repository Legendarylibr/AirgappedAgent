from __future__ import annotations

from typing import Literal

from airgap_agent.inference.base import ChatMessage

ChatTemplate = Literal["generic", "chatml", "llama3", "mistral"]


def format_chat_prompt(messages: list[ChatMessage], template: ChatTemplate) -> str:
    if template == "generic":
        return _format_generic(messages)
    if template == "chatml":
        return _format_chatml(messages)
    if template == "llama3":
        return _format_llama3(messages)
    if template == "mistral":
        return _format_mistral(messages)
    raise ValueError(f"unknown chat template: {template}")


def _format_generic(messages: list[ChatMessage]) -> str:
    parts: list[str] = []
    for m in messages:
        parts.append(f"{m.role.upper()}:\n{m.content}\n")
    parts.append("ASSISTANT:\n")
    return "\n".join(parts)


def _format_chatml(messages: list[ChatMessage]) -> str:
    parts: list[str] = []
    for m in messages:
        parts.append(f"<|im_start|>{m.role}\n{m.content}")
    parts.append("<|im_start|>assistant\n")
    return "\n".join(parts)


def _format_llama3(messages: list[ChatMessage]) -> str:
    parts: list[str] = ["<|begin_of_text|>"]
    for m in messages:
        tag = m.role if m.role in ("system", "user", "assistant") else "user"
        parts.append(f"<|start_header_id|>{tag}<|end_header_id|>\n\n{m.content}<|eot_id|>")
    parts.append("<|start_header_id|>assistant<|end_header_id|>\n\n")
    return "".join(parts)


def _format_mistral(messages: list[ChatMessage]) -> str:
    parts: list[str] = []
    for m in messages:
        if m.role == "system":
            parts.append(f"[INST] {m.content} [/INST]")
        elif m.role == "user":
            parts.append(f"[INST] {m.content} [/INST]")
        else:
            parts.append(f" {m.content}</s>")
    if not parts or not messages[-1].role == "assistant":
        parts.append(" ")
    return "".join(parts)
