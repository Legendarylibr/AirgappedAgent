from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from airgap_agent.agent.prompts import DEFAULT_SYSTEM_PROMPT
from airgap_agent.agent.tool_gate import (
    format_tool_observation,
    make_run_delimiters,
    normalize_user_task,
    parse_tool_call,
    sanitize_history_messages,
    sanitize_untrusted_content,
    wrap_user_task,
)
from airgap_agent.agent.tools import RunBudgets, ToolRegistry
from airgap_agent.config import AppConfig
from airgap_agent.inference.base import ChatMessage, InferenceBackend
from airgap_agent.security import AuditLogger, PolicyEngine


@dataclass
class AgentRunResult:
    answer: str
    iterations: int
    tool_calls: int
    run_id: str = ""
    structured: dict[str, Any] | None = None


class AgentHarness:
    def __init__(
        self,
        config: AppConfig,
        backend: InferenceBackend,
        policy: PolicyEngine,
        audit: AuditLogger,
        *,
        budgets: RunBudgets | None = None,
    ) -> None:
        self._config = config
        self._backend = backend
        self._policy = policy
        self._audit = audit
        self._budgets = budgets or RunBudgets()
        self._tools = ToolRegistry(config, policy, audit, self._budgets)
        self._system = self._load_system_prompt()
        self._allowed_tools = frozenset(config.security.allowed_tools)

    def _load_system_prompt(self) -> str:
        path = self._config.agent.system_prompt_path
        if path and Path(path).exists():
            content = Path(path).read_text(encoding="utf-8")
        else:
            content = DEFAULT_SYSTEM_PROMPT

        expected = self._config.agent.system_prompt_sha256
        if expected:
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            norm = expected.lower().removeprefix("sha256:").strip()
            if digest != norm:
                raise ValueError("system prompt SHA-256 mismatch with agent.system_prompt_sha256")
        return content

    def run(
        self,
        user_task: str,
        *,
        history: list[ChatMessage] | None = None,
        run_id: str | None = None,
    ) -> AgentRunResult:
        task = normalize_user_task(
            user_task,
            max_chars=self._config.agent.max_task_chars,
        )
        if len(user_task) > self._config.agent.max_task_chars:
            raise ValueError(f"task exceeds max length ({self._config.agent.max_task_chars})")

        rid = run_id or uuid.uuid4().hex
        delimiters = make_run_delimiters(rid)
        allowlist_block = (
            "Allowed tools (JSON schema):\n" + self._tools.schema_description()
        )
        output_hint = ""
        if self._config.agent.response_format == "json":
            output_hint = (
                "\n\nWhen you have the final answer, respond with a single JSON object only "
                '(no TOOL_CALL), e.g. {"summary": "...", "findings": []}.'
            )

        messages: list[ChatMessage] = [
            ChatMessage(role="system", content=self._system + output_hint),
        ]
        if history:
            messages.extend(
                sanitize_history_messages(
                    history,
                    max_chars=self._config.agent.max_tool_output_chars,
                )
            )
        messages.append(
            ChatMessage(
                role="user",
                content=wrap_user_task(task, delimiters, allowlist_block=allowlist_block),
            ),
        )
        self._audit.emit("agent.start", task_len=len(task), run_id=rid)

        tool_calls = 0
        invalid_tool_calls = 0
        json_retries = 0

        for i in range(self._config.agent.max_iterations):
            completion = self._backend.complete(messages)
            text = completion.content
            self._audit.emit(
                "agent.completion", iteration=i, finish_reason=completion.finish_reason, run_id=rid
            )

            parsed = parse_tool_call(text, self._allowed_tools)
            if not parsed:
                if text.strip().startswith("TOOL_CALL"):
                    invalid_tool_calls += 1
                    self._audit.emit("agent.invalid_tool_call", iteration=i, run_id=rid)
                    if invalid_tool_calls >= self._config.agent.max_invalid_tool_calls:
                        self._audit.emit(
                            "agent.circuit_breaker",
                            reason="too_many_invalid_tool_calls",
                            invalid_tool_calls=invalid_tool_calls,
                            run_id=rid,
                        )
                        return AgentRunResult(
                            answer=(
                                "Agent stopped: too many invalid tool calls. "
                                "Try a different model/prompt or lower temperature."
                            ),
                            iterations=i + 1,
                            tool_calls=tool_calls,
                            run_id=rid,
                        )
                    messages.append(
                        ChatMessage(
                            role="assistant",
                            content=sanitize_untrusted_content(text),
                        )
                    )
                    messages.append(
                        ChatMessage(
                            role="user",
                            content=(
                                "Tool call rejected: invalid format. "
                                "Respond with TOOL_CALL at the start of the message, "
                                "then a single JSON object on the following lines."
                            ),
                        )
                    )
                    continue

                answer = text.strip()
                structured = None
                if self._config.agent.response_format == "json":
                    structured, parse_ok = _try_parse_json_answer(answer)
                    if not parse_ok and json_retries < 1:
                        json_retries += 1
                        messages.append(
                            ChatMessage(
                                role="assistant",
                                content=sanitize_untrusted_content(text),
                            )
                        )
                        messages.append(
                            ChatMessage(
                                role="user",
                                content="Final answer must be valid JSON only. Retry.",
                            )
                        )
                        continue
                    if structured is not None:
                        answer = json.dumps(structured, indent=2)

                self._audit.emit("agent.done", iterations=i + 1, tool_calls=tool_calls, run_id=rid)
                return AgentRunResult(
                    answer=answer,
                    iterations=i + 1,
                    tool_calls=tool_calls,
                    run_id=rid,
                    structured=structured,
                )

            tool_name, arguments = parsed
            tool_calls += 1
            result = self._tools.invoke(tool_name, arguments)
            observation = format_tool_observation(
                tool_name,
                result.ok,
                result.output,
                result.error,
                delimiters=delimiters,
            )
            messages.append(
                ChatMessage(role="assistant", content=sanitize_untrusted_content(text))
            )
            messages.append(ChatMessage(role="user", content=observation))

        self._audit.emit("agent.max_iterations", tool_calls=tool_calls, run_id=rid)
        return AgentRunResult(
            answer="Agent stopped: max iterations reached without a final answer.",
            iterations=self._config.agent.max_iterations,
            tool_calls=tool_calls,
            run_id=rid,
        )


def _try_parse_json_answer(text: str) -> tuple[dict[str, Any] | None, bool]:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return None, False
    if not isinstance(data, dict):
        return None, False
    return data, True
