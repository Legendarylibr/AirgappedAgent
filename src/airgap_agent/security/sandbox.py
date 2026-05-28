from __future__ import annotations

import ast
import os
import subprocess
import sys
import textwrap
from shutil import which

from airgap_agent.config import PythonSandboxSettings, SecuritySettings
from airgap_agent.security.errors import SandboxError
from airgap_agent.security.paths import read_file_bounded, resolve_workspace_path

__all__ = [
    "SandboxError",
    "read_file_bounded",
    "resolve_workspace_path",
    "run_python_sandboxed",
    "validate_python_source",
]


_ALLOWED_CALL_NAMES = frozenset(
    {
        "abs",
        "all",
        "any",
        "bool",
        "dict",
        "enumerate",
        "filter",
        "float",
        "int",
        "len",
        "list",
        "map",
        "max",
        "min",
        "print",
        "range",
        "reversed",
        "set",
        "sorted",
        "str",
        "sum",
        "tuple",
        "zip",
    }
)

_ALLOWED_NODES: tuple[type[ast.AST], ...] = (
    ast.Module,
    ast.FunctionDef,
    ast.Return,
    ast.Expr,
    ast.Assign,
    ast.AugAssign,
    ast.AnnAssign,
    ast.For,
    ast.While,
    ast.If,
    ast.Break,
    ast.Continue,
    ast.Pass,
    ast.Raise,
    ast.Assert,
    ast.Call,
    ast.Name,
    ast.Load,
    ast.Store,
    ast.Constant,
    ast.BinOp,
    ast.UnaryOp,
    ast.Compare,
    ast.BoolOp,
    ast.IfExp,
    ast.List,
    ast.Tuple,
    ast.Dict,
    ast.Set,
    ast.Subscript,
    ast.Slice,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
    ast.comprehension,
    ast.Starred,
    ast.JoinedStr,
    ast.FormattedValue,
    ast.keyword,
    ast.arguments,
    ast.arg,
    ast.operator,
    ast.cmpop,
    ast.unaryop,
    ast.boolop,
)


class SafeAstVisitor(ast.NodeVisitor):
    def __init__(self, denied_imports: set[str]) -> None:
        self._denied = denied_imports
        self.violations: list[str] = []

    def generic_visit(self, node: ast.AST) -> None:
        if not isinstance(node, _ALLOWED_NODES):
            self.violations.append(f"disallowed syntax: {type(node).__name__}")
            return
        super().generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name.split(".")[0] in self._denied:
                self.violations.append(f"denied import: {alias.name}")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and node.module.split(".")[0] in self._denied:
            self.violations.append(f"denied import: {node.module}")

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            if node.func.id not in _ALLOWED_CALL_NAMES:
                self.violations.append(f"disallowed call: {node.func.id}")
        else:
            self.violations.append("only direct function calls are allowed")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.violations.append("attribute access is not allowed")


def validate_python_source(source: str, settings: PythonSandboxSettings) -> None:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise SandboxError(f"invalid python: {exc}") from exc
    visitor = SafeAstVisitor(set(settings.deny_imports))
    visitor.visit(tree)
    if visitor.violations:
        raise SandboxError(f"sandbox policy violation: {visitor.violations[0]}")


def run_python_sandboxed(source: str, security: SecuritySettings) -> str:
    validate_python_source(source, security.python_sandbox)
    wrapped = textwrap.dedent(
        f"""
        def __airgap_entry__():
        {textwrap.indent(source, "    ")}
        __airgap_result__ = __airgap_entry__()
        import json, sys
        sys.stdout.write(json.dumps({{"ok": True, "result": __airgap_result__}}, default=str))
        """
    )

    if security.python_sandbox.mode == "docker":
        return _run_python_docker(wrapped, security, security.python_sandbox)

    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-S", "-c", wrapped],
            capture_output=True,
            text=True,
            timeout=security.tool_timeout_seconds,
            cwd=str(security.workspace_root.resolve()),
            env={
                "LANG": "C.UTF-8",
                "PYTHONNOUSERSITE": "1",
            },
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(f"execution exceeded {security.tool_timeout_seconds}s") from exc

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "unknown error").strip()[:2000]
        raise SandboxError(f"sandbox execution failed: {err}")

    import json

    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise SandboxError("sandbox returned invalid output") from exc
    result = payload.get("result")
    return "" if result is None else str(result)


def _run_python_docker(wrapped: str, security: SecuritySettings, settings: PythonSandboxSettings) -> str:
    docker = which("docker")
    if not docker:
        raise SandboxError("docker sandbox requested but docker is not installed")

    ws = security.workspace_root.resolve()
    image = settings.docker_image
    cmd = [
        docker,
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "-v",
        f"{ws}:/ws:ro",
        "-w",
        "/ws",
        image,
        "python",
        "-I",
        "-S",
        "-c",
        wrapped,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=security.tool_timeout_seconds,
            env={
                "LANG": "C.UTF-8",
            },
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(f"docker sandbox exceeded {security.tool_timeout_seconds}s") from exc

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "unknown error").strip()[:2000]
        raise SandboxError(f"docker sandbox failed: {err}")

    import json

    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise SandboxError("docker sandbox returned invalid output") from exc
    result = payload.get("result")
    return "" if result is None else str(result)
