from __future__ import annotations

from unittest.mock import patch

import pytest

from airgap_agent.cli import _load
from airgap_agent.deployment.bootstrap import BootstrapError, validate_api_config, verify_api_token


def test_verify_api_token_constant_time_compare() -> None:
    cfg = _load(None, dev=False)
    cfg.api.require_token = True
    with patch.dict("os.environ", {"AIRGAP_API_TOKEN": "secret-token"}):
        assert verify_api_token(cfg, {"Authorization": "Bearer secret-token"})
        assert not verify_api_token(cfg, {"Authorization": "Bearer wrong-token"})
        assert not verify_api_token(cfg, {})


def test_validate_api_config_missing_hmac_key() -> None:
    cfg = _load(None, dev=False)
    cfg.api.require_token = False
    cfg.api.require_capability_token = True
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(BootstrapError, match="AIRGAP_API_HMAC_KEY"):
            validate_api_config(cfg)
