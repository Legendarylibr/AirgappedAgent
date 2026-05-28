from pathlib import Path
from unittest.mock import patch

from airgap_agent.agent.harness import AgentHarness
from airgap_agent.agent.tools import ToolRegistry
from airgap_agent.config import AppConfig, AuditSettings, TrustSettings
from airgap_agent.inference.mock import MockBackend
from airgap_agent.security import AuditLogger, PolicyEngine


def test_harness_instantiates_tool_registry_once_per_run(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()

    cfg = AppConfig()
    cfg.security.workspace_root = ws
    cfg.airgap.require_bundle_manifest = False
    cfg.trust = TrustSettings(require_signed_policy=False, require_signed_manifest=False)
    cfg.audit = AuditSettings(enabled=False)

    harness = AgentHarness(
        cfg,
        MockBackend(),
        PolicyEngine(Path("policies/default.yaml"), cfg.trust),
        AuditLogger(cfg.audit),
    )
    created: list[int] = []
    orig_init = ToolRegistry.__init__

    def track(self, *args, **kwargs) -> None:
        created.append(id(self))
        orig_init(self, *args, **kwargs)

    with patch.object(ToolRegistry, "__init__", track):
        harness.run("List workspace files")

    assert len(created) == 1
