from pathlib import Path

from airgap_agent.agent import AgentHarness
from airgap_agent.config import AppConfig, AuditSettings
from airgap_agent.inference import create_backend
from airgap_agent.security import AuditLogger, PolicyEngine


def test_mock_agent_run(tmp_path: Path) -> None:
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "readme.txt").write_text("airgapped agent test")

    cfg = AppConfig()
    cfg.inference.backend = "mock"
    cfg.airgap.require_bundle_manifest = False
    cfg.security.workspace_root = ws
    cfg.audit = AuditSettings(enabled=False)
    cfg.policy_path = Path("policies/default.yaml")

    from airgap_agent.config import TrustSettings

    cfg.trust = TrustSettings(require_signed_policy=False)
    harness = AgentHarness(
        cfg,
        create_backend(cfg),
        PolicyEngine(Path("policies/default.yaml"), cfg.trust),
        AuditLogger(cfg.audit),
    )
    result = harness.run("List workspace and summarize readme.txt")
    assert result.iterations >= 1
    assert result.answer
