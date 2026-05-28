from pathlib import Path

from airgap_agent.agent.tools import RunBudgets, ToolRegistry
from airgap_agent.config import AppConfig, AuditSettings, TrustSettings
from airgap_agent.security import AuditLogger, PolicyEngine


def test_budget_blocks_total_read_bytes(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "a.txt").write_text("x" * 2000)
    (ws / "b.txt").write_text("y" * 2000)

    cfg = AppConfig()
    cfg.security.workspace_root = ws
    cfg.airgap.require_bundle_manifest = False
    cfg.trust = TrustSettings(require_signed_policy=False, require_signed_manifest=False)
    cfg.audit = AuditSettings(enabled=False)
    cfg.security.max_read_bytes = 2000
    cfg.security.max_total_read_bytes_per_run = 2500

    budgets = RunBudgets()
    tools = ToolRegistry(
        cfg,
        PolicyEngine(Path("policies/default.yaml"), cfg.trust),
        AuditLogger(cfg.audit),
        budgets,
    )

    r1 = tools.invoke("read_file", {"path": "a.txt"})
    assert r1.ok
    r2 = tools.invoke("read_file", {"path": "b.txt"})
    assert not r2.ok
    assert "budget" in (r2.error or "").lower()


def test_budget_blocks_total_python_execs(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()

    cfg = AppConfig()
    cfg.security.workspace_root = ws
    cfg.airgap.require_bundle_manifest = False
    cfg.trust = TrustSettings(require_signed_policy=False, require_signed_manifest=False)
    cfg.audit = AuditSettings(enabled=False)
    cfg.security.max_total_python_execs_per_run = 1

    budgets = RunBudgets()
    tools = ToolRegistry(
        cfg,
        PolicyEngine(Path("policies/default.yaml"), cfg.trust),
        AuditLogger(cfg.audit),
        budgets,
    )

    r1 = tools.invoke("run_python", {"source": "return 1+1"})
    assert r1.ok
    r2 = tools.invoke("run_python", {"source": "return 2+2"})
    assert not r2.ok
    assert "budget" in (r2.error or "").lower()

