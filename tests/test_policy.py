from pathlib import Path

from airgap_agent.config import TrustSettings
from airgap_agent.security.policy import PolicyEngine

_TRUST = TrustSettings(require_signed_policy=False)


def test_allow_listed_tool() -> None:
    engine = PolicyEngine(Path("policies/default.yaml"), _TRUST)
    d = engine.evaluate("tool.invoke", {"tool_name": "read_file"})
    assert d.effect == "deny"


def test_allow_listed_capability() -> None:
    engine = PolicyEngine(Path("policies/default.yaml"), _TRUST)
    d = engine.evaluate("tool.invoke", {"capability": "fs.read"})
    assert d.effect == "allow"


def test_deny_shell_tool() -> None:
    engine = PolicyEngine(Path("policies/default.yaml"), _TRUST)
    d = engine.evaluate("tool.invoke", {"tool_name": "curl"})
    assert d.effect == "deny"
