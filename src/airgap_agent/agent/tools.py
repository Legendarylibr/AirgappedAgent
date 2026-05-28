from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from airgap_agent.agent.schemas import validate_tool_arguments
from airgap_agent.agent.tool_gate import sanitize_untrusted_content
from airgap_agent.config import AppConfig
from airgap_agent.security.capabilities import Capability
from airgap_agent.security import (
    AuditLogger,
    PolicyEngine,
    SandboxError,
    read_file_bounded,
    resolve_workspace_path,
    run_python_sandboxed,
)

@dataclass
class RunBudgets:
    tool_calls: int = 0
    read_bytes: int = 0
    python_execs: int = 0


@dataclass
class ToolResult:
    ok: bool
    output: str
    error: str | None = None


class ToolRegistry:
    def __init__(
        self,
        config: AppConfig,
        policy: PolicyEngine,
        audit: AuditLogger,
        budgets: RunBudgets | None = None,
    ) -> None:
        self._config = config
        self._policy = policy
        self._audit = audit
        self._workspace = config.security.workspace_root
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._budgets = budgets or RunBudgets()
        self._handlers: dict[str, Callable[[dict[str, Any]], ToolResult]] = {
            "read_file": self._read_file,
            "list_directory": self._list_directory,
            "search_text": self._search_text,
            "run_python": self._run_python,
        }

    def invoke(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        self._budgets.tool_calls += 1
        if self._budgets.tool_calls > self._config.security.max_total_tool_calls_per_run:
            self._audit.emit(
                "tool.denied",
                tool=name,
                reason="budget: max_total_tool_calls_per_run",
            )
            return ToolResult(ok=False, output="", error="budget exceeded: tool calls")

        if name not in self._config.security.allowed_tools:
            self._audit.emit("tool.denied", tool=name, reason="not in allowlist")
            return ToolResult(ok=False, output="", error=f"tool not allowed: {name}")

        capability = self._capability_for_tool(name)
        if str(capability) not in self._config.security.allowed_capabilities:
            self._audit.emit("tool.denied", tool=name, reason="capability not allowed", capability=str(capability))
            return ToolResult(ok=False, output="", error="capability not allowed")

        try:
            arguments = validate_tool_arguments(name, arguments)
        except ValueError as exc:
            self._audit.emit("tool.denied", tool=name, reason=str(exc))
            return ToolResult(ok=False, output="", error=str(exc))

        decision = self._policy.evaluate(
            "tool.invoke",
            {"tool_name": name, "capability": str(capability), "workspace_root": str(self._workspace)},
        )
        if decision.effect != "allow":
            self._audit.emit(
                "tool.denied",
                tool=name,
                rule_id=decision.rule_id,
                reason=decision.reason,
            )
            return ToolResult(ok=False, output="", error=decision.reason)

        handler = self._handlers.get(name)
        if not handler:
            return ToolResult(ok=False, output="", error=f"unknown tool: {name}")

        self._audit.emit(
            "tool.invoke",
            tool=name,
            capability=str(capability),
            argument_keys=sorted(arguments.keys()),
        )
        try:
            result = handler(arguments)
        except (SandboxError, OSError, ValueError) as exc:
            self._audit.emit("tool.error", tool=name, error=str(exc))
            return ToolResult(ok=False, output="", error=str(exc))

        max_chars = self._config.agent.max_tool_output_chars
        if len(result.output) > max_chars:
            result = ToolResult(
                ok=result.ok,
                output=result.output[:max_chars] + "\n...[truncated]",
                error=result.error,
            )
        self._audit.emit("tool.result", tool=name, ok=result.ok, output_len=len(result.output))
        return result

    def _read_file(self, args: dict[str, Any]) -> ToolResult:
        path = args["path"]
        target = resolve_workspace_path(self._workspace, path)
        decision = self._policy.evaluate(
            "fs.read",
            {"path": str(target), "workspace_root": str(self._workspace)},
        )
        if decision.effect != "allow":
            return ToolResult(ok=False, output="", error=decision.reason)
        if not target.is_file():
            return ToolResult(ok=False, output="", error="not a file")
        max_one = self._config.security.max_read_bytes
        size = target.stat().st_size
        if self._budgets.read_bytes + min(size, max_one) > self._config.security.max_total_read_bytes_per_run:
            return ToolResult(ok=False, output="", error="budget exceeded: read bytes")
        content = read_file_bounded(target, max_one)
        self._budgets.read_bytes += len(content.encode("utf-8", errors="ignore"))
        return ToolResult(ok=True, output=content)

    def _list_directory(self, args: dict[str, Any]) -> ToolResult:
        path = args.get("path", ".")
        target = resolve_workspace_path(self._workspace, path)
        if not target.is_dir():
            return ToolResult(ok=False, output="", error="not a directory")
        limit = self._config.security.max_list_entries
        entries: list[str] = []
        for p in sorted(target.iterdir()):
            if p.is_symlink():
                continue
            entries.append(p.name + ("/" if p.is_dir() else ""))
            if len(entries) >= limit:
                entries.append("...[truncated]")
                break
        return ToolResult(ok=True, output=json.dumps(entries, indent=2))

    def _search_text(self, args: dict[str, Any]) -> ToolResult:
        query = args["query"].strip()
        path = args.get("path", ".")
        root = resolve_workspace_path(self._workspace, path)
        hits: list[dict[str, str]] = []
        max_file = self._config.security.max_read_bytes
        allowed_ext = set(self._config.security.search_allowed_extensions)
        files_scanned = 0
        for file in root.rglob("*"):
            if file.is_symlink() or not file.is_file():
                continue
            if allowed_ext and file.suffix not in allowed_ext:
                continue
            if file.stat().st_size > max_file:
                continue
            if self._budgets.read_bytes >= self._config.security.max_total_read_bytes_per_run:
                break
            files_scanned += 1
            if files_scanned > self._config.security.max_search_files:
                break
            try:
                text = read_file_bounded(file, max_file)
            except OSError:
                continue
            self._budgets.read_bytes += len(text.encode("utf-8", errors="ignore"))
            for i, line in enumerate(text.splitlines(), start=1):
                if query.lower() in line.lower():
                    rel = file.relative_to(self._workspace.resolve())
                    safe_line = sanitize_untrusted_content(line.strip(), max_chars=200)
                    hits.append({"file": str(rel), "line": str(i), "text": safe_line})
                    if len(hits) >= self._config.security.max_search_hits:
                        break
            if len(hits) >= self._config.security.max_search_hits:
                break
        return ToolResult(ok=True, output=json.dumps(hits, indent=2))

    def _run_python(self, args: dict[str, Any]) -> ToolResult:
        self._budgets.python_execs += 1
        if self._budgets.python_execs > self._config.security.max_total_python_execs_per_run:
            return ToolResult(ok=False, output="", error="budget exceeded: python execs")
        source = args["source"]
        out = run_python_sandboxed(source, self._config.security)
        return ToolResult(ok=True, output=out)

    def schema_description(self) -> str:
        return json.dumps(
            {
                "allowlist": self._config.security.allowed_tools,
                "capabilities": self._config.security.allowed_capabilities,
                "tools": {
                    "read_file": {"path": "string"},
                    "list_directory": {"path": "string"},
                    "search_text": {"path": "string", "query": "string"},
                    "run_python": {"source": "string"},
                },
            },
            indent=2,
        )

    @staticmethod
    def _capability_for_tool(tool_name: str) -> Capability:
        match tool_name:
            case "read_file":
                return Capability.FS_READ
            case "list_directory":
                return Capability.FS_LIST
            case "search_text":
                return Capability.FS_SEARCH
            case "run_python":
                return Capability.PY_EXEC
            case _:
                raise ValueError(f"unknown tool: {tool_name}")
