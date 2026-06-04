from pathlib import Path

from airgap_agent.agent import AgentHarness
from airgap_agent.config import AppConfig, AuditSettings, TrustSettings
from airgap_agent.inference.base import ChatMessage, CompletionResult, InferenceBackend
from airgap_agent.security import AuditLogger, PolicyEngine


class AlwaysInvalidToolCallBackend(InferenceBackend):
    def complete(self, messages: list[ChatMessage], **kwargs):
        return CompletionResult(content="TOOL_CALL\n{not-json", finish_reason="stop")


def test_invalid_tool_call_circuit_breaker(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()

    cfg = AppConfig()
    cfg.inference.backend = "mock"
    cfg.security.workspace_root = ws
    cfg.airgap.require_bundle_manifest = False
    cfg.trust = TrustSettings(require_signed_policy=False, require_signed_manifest=False)
    cfg.audit = AuditSettings(enabled=False)
    cfg.agent.max_iterations = 10
    cfg.agent.max_invalid_tool_calls = 2

    harness = AgentHarness(
        cfg,
        AlwaysInvalidToolCallBackend(),
        PolicyEngine(Path("policies/default.yaml"), cfg.trust),
        AuditLogger(cfg.audit),
    )

    result = harness.run("do something")
    assert "too many invalid tool calls" in result.answer.lower()
