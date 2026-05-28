from pathlib import Path

import pytest

from airgap_agent.deployment.bootstrap import BootstrapError, ensure_dev_allowed


def test_dev_blocked_under_etc(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    etc = tmp_path / "etc" / "airgap-agent"
    etc.mkdir(parents=True)
    monkeypatch.chdir(etc)
    monkeypatch.delenv("AIRGAP_ALLOW_DEV", raising=False)
    with pytest.raises(BootstrapError):
        ensure_dev_allowed(True)


def test_dev_allowed_with_flag(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    etc = tmp_path / "etc" / "airgap-agent"
    etc.mkdir(parents=True)
    monkeypatch.chdir(etc)
    monkeypatch.setenv("AIRGAP_ALLOW_DEV", "1")
    ensure_dev_allowed(True)
