from pathlib import Path

from airgap_agent.agent.tools import ToolRegistry
from airgap_agent.config import AppConfig, AuditSettings, TrustSettings
from airgap_agent.security import AuditLogger, PolicyEngine


def test_write_file_workspace_only(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()

    cfg = AppConfig()
    cfg.security.workspace_root = ws
    cfg.security.allowed_tools = [
        "read_file",
        "list_directory",
        "search_text",
        "run_python",
        "write_file",
    ]
    cfg.security.allowed_capabilities = [
        "fs.read",
        "fs.list",
        "fs.search",
        "fs.write",
        "py.exec",
    ]
    cfg.airgap.require_bundle_manifest = False
    cfg.trust = TrustSettings(require_signed_policy=False, require_signed_manifest=False)
    cfg.audit = AuditSettings(enabled=False)

    tools = ToolRegistry(
        cfg,
        PolicyEngine(Path("policies/default.yaml"), cfg.trust),
        AuditLogger(cfg.audit),
    )
    r = tools.invoke("write_file", {"path": "out.txt", "content": "hello"})
    assert r.ok
    assert (ws / "out.txt").read_text(encoding="utf-8") == "hello"
