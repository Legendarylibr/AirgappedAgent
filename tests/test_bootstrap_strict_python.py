from pathlib import Path

import pytest

from airgap_agent.config import AppConfig, TrustSettings
from airgap_agent.deployment.bootstrap import BootstrapError, ensure_runtime_ready


def _strict_cfg() -> AppConfig:
    cfg = AppConfig()
    cfg.airgap.mode = "strict"
    cfg.airgap.require_bundle_manifest = False
    cfg.policy_path = Path("policies/default.yaml")
    cfg.trust = TrustSettings(require_signed_policy=False, require_signed_manifest=False)
    cfg.security.python_sandbox.mode = "process"
    return cfg


def test_strict_requires_docker_for_run_python(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AIRGAP_ALLOW_PROCESS_PYTHON", raising=False)
    with pytest.raises(BootstrapError, match="docker"):
        ensure_runtime_ready(_strict_cfg(), dev=False)


def test_strict_allows_process_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AIRGAP_ALLOW_PROCESS_PYTHON", "1")
    ensure_runtime_ready(_strict_cfg(), dev=False)
