from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from airgap_agent.agent.prompts import DEFAULT_SYSTEM_PROMPT
from airgap_agent.agent.tool_gate import format_tool_observation, parse_tool_call
from airgap_agent.agent.tools import ToolRegistry
from airgap_agent.config import AppConfig
from airgap_agent.inference.base import ChatMessage, InferenceBackend
from airgap_agent.security import AuditLogger, PolicyEngine


@dataclass
class AgentRunResult:
    answer: str
    iterations: int
    tool_calls: int


class AgentHarness:
    def __init__(
        self,
        config: AppConfig,
        backend: InferenceBackend,
        policy: PolicyEngine,
        audit: AuditLogger,
    ) -> None:
        self._config = config
        self._backend = backend
        self._policy = policy
        self._audit = audit
        self._tools = ToolRegistry(config, policy, audit)
        self._system = self._load_system_prompt()
        self._allowed_tools = frozenset(config.security.allowed_tools)

    def _load_system_prompt(self) -> str:
        path = self._config.agent.system_prompt_path
        if path and Path(path).exists():
            return Path(path).read_text(encoding="utf-8")
        return DEFAULT_SYSTEM_PROMPT

    def run(self, user_task: str) -> AgentRunResult:
        if len(user_task) > self._config.agent.max_task_chars:
            raise ValueError(f"task exceeds max length ({self._config.agent.max_task_chars})")

        allowlist_block = (
            "Allowed tools (JSON schema):\n" + self._tools.schema_description()
        )
        messages = [
            ChatMessage(role="system", content=self._system),
            ChatMessage(
                role="user",
                content=f"{allowlist_block}\n\n<user_task>\n{user_task}\n</user_task>",
            ),
        ]
        self._audit.emit("agent.start", task_len=len(user_task))

        tool_calls = 0
        invalid_tool_calls = 0
        tools = ToolRegistry(self._config, self._policy, self._audit)
        for i in range(self._config.agent.max_iterations):
            completion = self._backend.complete(messages)
            text = completion.content
            self._audit.emit("agent.completion", iteration=i, finish_reason=completion.finish_reason)

            parsed = parse_tool_call(text, self._allowed_tools)
            if not parsed:
                if text.strip().startswith("TOOL_CALL"):
                    invalid_tool_calls += 1
                    self._audit.emit("agent.invalid_tool_call", iteration=i)
                    if invalid_tool_calls >= self._config.agent.max_invalid_tool_calls:
                        self._audit.emit(
                            "agent.circuit_breaker",
                            reason="too_many_invalid_tool_calls",
                            invalid_tool_calls=invalid_tool_calls,
                        )
                        return AgentRunResult(
                            answer=(
                                "Agent stopped: too many invalid tool calls. "
                                "Try a different model/prompt or lower temperature."
                            ),
                            iterations=i + 1,
                            tool_calls=tool_calls,
                        )
                    messages.append(ChatMessage(role="assistant", content=text))
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
                self._audit.emit("agent.done", iterations=i + 1, tool_calls=tool_calls)
                return AgentRunResult(answer=text.strip(), iterations=i + 1, tool_calls=tool_calls)

            tool_name, arguments = parsed
            tool_calls += 1
            result = tools.invoke(tool_name, arguments)
            observation = format_tool_observation(
                tool_name, result.ok, result.output, result.error
            )
            messages.append(ChatMessage(role="assistant", content=text))
            messages.append(ChatMessage(role="user", content=observation))

        self._audit.emit("agent.max_iterations", tool_calls=tool_calls)
        return AgentRunResult(
            answer="Agent stopped: max iterations reached without a final answer.",
            iterations=self._config.agent.max_iterations,
            tool_calls=tool_calls,
        )
