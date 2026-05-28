from pathlib import Path

import pytest

from airgap_agent.config import SecuritySettings
from airgap_agent.security.sandbox import SandboxError, resolve_workspace_path, run_python_sandboxed


def test_path_jail(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "ok.txt").write_text("hi")
    p = resolve_workspace_path(ws, "ok.txt")
    assert p.name == "ok.txt"
    with pytest.raises(SandboxError):
        resolve_workspace_path(ws, "../etc/passwd")


def test_symlink_rejected(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    target = tmp_path / "secret.txt"
    target.write_text("secret")
    (ws / "link").symlink_to(target)
    with pytest.raises(SandboxError, match="symlink"):
        resolve_workspace_path(ws, "link")


def test_deny_attribute_escape() -> None:
    sec = SecuritySettings(workspace_root=Path("/tmp/ws"))
    with pytest.raises(SandboxError, match="attribute"):
        run_python_sandboxed("x = ().__class__", sec)


def test_safe_python() -> None:
    ws = Path("/tmp/airgap-test-ws")
    ws.mkdir(exist_ok=True)
    sec = SecuritySettings(workspace_root=ws)
    out = run_python_sandboxed("return sum([1, 2, 3])", sec)
    assert out == "6"


def test_search_ext_allowlist_config_defaults() -> None:
    sec = SecuritySettings(workspace_root=Path("/tmp/airgap-test-ws"))
    assert ".py" in sec.search_allowed_extensions
