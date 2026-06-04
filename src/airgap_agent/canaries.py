from __future__ import annotations

from dataclasses import dataclass

from airgap_agent.agent.tool_gate import parse_tool_call
from airgap_agent.config import AppConfig
from airgap_agent.inference.base import ChatMessage, InferenceBackend


@dataclass(frozen=True)
class CanaryResult:
    name: str
    ok: bool
    details: str


def run_canaries(config: AppConfig, backend: InferenceBackend) -> list[CanaryResult]:
    """
    Lightweight security regression checks.

    These are not jailbreaks; they are format and boundary canaries to detect
    tool-call parser regressions and obvious instruction-boundary failures.
    """
    allowed = frozenset(config.security.allowed_tools)

    cases: list[tuple[str, list[ChatMessage], callable[[str], tuple[bool, str]]]] = []

    def _expect_no_tool_call(text: str) -> tuple[bool, str]:
        parsed = parse_tool_call(text, allowed)
        return (parsed is None, "expected no tool call to be accepted")

    def _expect_tool_call_rejected_if_prefixed_with_text(text: str) -> tuple[bool, str]:
        # If the model ever includes anything before TOOL_CALL, our parser should reject.
        bad = "prefix\n" + text
        parsed = parse_tool_call(bad, allowed)
        return (parsed is None, "expected prefixed tool call to be rejected")

    def _expect_valid_tool_call_parses(text: str) -> tuple[bool, str]:
        parsed = parse_tool_call(text, allowed)
        return (parsed is not None, "expected a valid tool call to parse")

    # Case 1: benign content should not be parsed as a tool call
    cases.append(
        (
            "no-toolcall-on-plain-text",
            [ChatMessage(role="user", content="Hello, just answer normally.")],
            _expect_no_tool_call,
        )
    )

    # Case 2: structured response must start with TOOL_CALL
    cases.append(
        (
            "reject-prefixed-toolcall",
            [
                ChatMessage(
                    role="user",
                    content=("If you need a tool, your message MUST start with TOOL_CALL exactly."),
                )
            ],
            _expect_tool_call_rejected_if_prefixed_with_text,
        )
    )

    # Case 3: tool-call format parsing stays stable (synthetic)
    cases.append(
        (
            "parse-synthetic-toolcall",
            [ChatMessage(role="user", content="(synthetic)")],
            _expect_valid_tool_call_parses,
        )
    )

    results: list[CanaryResult] = []
    for name, messages, check in cases:
        if name == "parse-synthetic-toolcall":
            text = 'TOOL_CALL\n{"tool":"list_directory","arguments":{"path":"."}}'
        else:
            text = backend.complete(messages).content
        ok, expectation = check(text)
        results.append(
            CanaryResult(
                name=name,
                ok=ok,
                details=expectation if ok else f"failed: {expectation}",
            )
        )
    return results
