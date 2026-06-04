from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from airgap_agent.agent.tool_gate import parse_tool_call, sanitize_untrusted_content
from airgap_agent.config import AppConfig
from airgap_agent.inference.base import ChatMessage, InferenceBackend


@dataclass(frozen=True)
class EvalCaseResult:
    name: str
    ok: bool
    details: str
    file: str


def load_eval_cases(path: Path) -> list[dict[str, Any]]:
    if path.is_dir():
        cases: list[dict[str, Any]] = []
        for f in sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml")):
            doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            if isinstance(doc, list):
                for item in doc:
                    item.setdefault("_file", str(f))
                    cases.append(item)
            elif isinstance(doc, dict) and "cases" in doc:
                for item in doc["cases"]:
                    item.setdefault("_file", str(f))
                    cases.append(item)
        return cases
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict) and "cases" in doc:
        return doc["cases"]
    raise ValueError(f"unsupported eval file format: {path}")


def run_eval_cases(
    cases: list[dict[str, Any]],
    *,
    config: AppConfig,
    backend: InferenceBackend | None = None,
) -> list[EvalCaseResult]:
    allowed = frozenset(config.security.allowed_tools)
    results: list[EvalCaseResult] = []

    for case in cases:
        name = str(case.get("name", "unnamed"))
        source = str(case.get("_file", "inline"))
        kind = case.get("kind", "parse_tool_call")

        try:
            if kind == "parse_tool_call":
                text = case.get("input", "")
                expect = case.get("expect_parsed", True)
                parsed = parse_tool_call(text, allowed)
                ok = (parsed is not None) == bool(expect)
                details = "parsed" if parsed else "not parsed"
            elif kind == "backend_completion":
                if backend is None:
                    ok, details = False, "backend required for backend_completion cases"
                else:
                    messages = [
                        ChatMessage(role=m["role"], content=m["content"])
                        for m in case.get("messages", [])
                    ]
                    text = backend.complete(messages).content
                    check = case.get("check", "no_tool_call")
                    if check == "no_tool_call":
                        ok = parse_tool_call(text, allowed) is None
                        details = "no tool call" if ok else f"unexpected tool call: {text[:120]}"
                    elif check == "contains":
                        needle = case.get("contains", "")
                        ok = needle in text
                        details = f"contains {needle!r}" if ok else f"missing {needle!r}"
                    else:
                        ok, details = False, f"unknown check: {check}"
            elif kind == "sanitize_content":
                text = str(case.get("input", ""))
                out = sanitize_untrusted_content(text)
                ok = True
                for key in ("expect_contains", "expect_contains2"):
                    needle = case.get(key)
                    if needle and needle not in out:
                        ok = False
                details = "sanitized" if ok else f"output missing expected markers: {out[:120]}"
            elif kind == "json_schema":
                payload = case.get("input", {})
                schema = case.get("schema", {})
                ok = _validate_simple_schema(payload, schema)
                details = "schema ok" if ok else "schema mismatch"
            else:
                ok, details = False, f"unknown kind: {kind}"
        except Exception as exc:
            ok, details = False, str(exc)

        results.append(EvalCaseResult(name=name, ok=ok, details=details, file=source))

    return results


def _validate_simple_schema(value: Any, schema: dict[str, Any]) -> bool:
    if schema.get("type") == "object" and not isinstance(value, dict):
        return False
    required = schema.get("required", [])
    if isinstance(value, dict):
        for key in required:
            if key not in value:
                return False
        props = schema.get("properties", {})
        for key, sub in props.items():
            if key in value and not _validate_simple_schema(value[key], sub):
                return False
    return True
