from __future__ import annotations

import hmac
import os
from pathlib import Path

from airgap_agent.config import AppConfig
from airgap_agent.deployment.bundle import verify_bundle
from airgap_agent.security.capability_tokens import parse_hmac_key, verify_capability_token
from airgap_agent.security.policy import PolicyEngine


class BootstrapError(Exception):
    pass


def _is_production_like_path(path: Path) -> bool:
    parts = path.resolve().parts
    return parts[-2:] == ("etc", "airgap-agent") or parts[-3:] == (
        "var",
        "lib",
        "airgap-agent",
    )


def ensure_dev_allowed(dev: bool) -> None:
    if not dev:
        return
    if os.environ.get("AIRGAP_ALLOW_DEV") == "1":
        return
    cwd = Path.cwd().resolve()
    prod_roots = (Path("/etc/airgap-agent"), Path("/var/lib/airgap-agent"))
    if any(str(cwd).startswith(str(root)) for root in prod_roots) or _is_production_like_path(cwd):
        raise BootstrapError(
            "refusing --dev under production paths; export AIRGAP_ALLOW_DEV=1 to override"
        )


def ensure_runtime_ready(config: AppConfig, *, dev: bool = False) -> PolicyEngine:
    ensure_dev_allowed(dev)
    policy_path = resolve_policy_path(config)

    if config.airgap.require_bundle_manifest and not dev:
        bundle = verify_bundle(config.bundle, config.trust)
        if not bundle.ok:
            raise BootstrapError("bundle verification failed: " + "; ".join(bundle.errors))

    if (
        not dev
        and config.airgap.mode == "strict"
        and "run_python" in config.security.allowed_tools
        and config.security.python_sandbox.mode != "docker"
        and os.environ.get("AIRGAP_ALLOW_PROCESS_PYTHON") != "1"
    ):
        raise BootstrapError(
            "strict mode requires security.python_sandbox.mode=docker for run_python; "
            "set AIRGAP_ALLOW_PROCESS_PYTHON=1 to override"
        )

    return PolicyEngine(policy_path, config.trust)


def resolve_policy_path(config: AppConfig) -> Path:
    policy_path = config.policy_path
    if not policy_path.is_absolute():
        policy_path = Path.cwd() / policy_path
    return policy_path


def validate_api_config(config: AppConfig) -> None:
    """Fail fast at serve startup when required API secrets are missing."""
    if config.api.require_token:
        if not os.environ.get(config.api.token_env, ""):
            raise BootstrapError(
                f"{config.api.token_env} must be set when api.require_token is true"
            )
    if config.api.require_capability_token:
        if not os.environ.get(config.api.capability_token_env, ""):
            raise BootstrapError(
                f"{config.api.capability_token_env} must be set when "
                "api.require_capability_token is true"
            )


def verify_api_token(config: AppConfig, headers: dict[str, str]) -> bool:
    if not config.api.require_token:
        return True
    expected = os.environ.get(config.api.token_env, "")
    if not expected:
        return False
    auth = headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else headers.get("X-Airgap-Token", "")
    if not token:
        hmac.compare_digest("", "")
        return False
    return hmac.compare_digest(token, expected)


def verify_capability_token_from_headers(config: AppConfig, headers: dict[str, str]) -> dict:
    """
    Verify the HMAC-signed capability token and return claims dict.
    This is intended for loopback HTTP API requests, not local CLI runs.
    """
    if not config.api.require_capability_token:
        return {"caps": list(config.security.allowed_capabilities), "budgets": {}}

    raw_key = os.environ.get(config.api.capability_token_env, "")
    if not raw_key:
        raise BootstrapError(
            f"{config.api.capability_token_env} must be set when "
            "api.require_capability_token is true"
        )
    header = config.api.capability_token_header
    token = headers.get(header, "")
    if not token:
        raise BootstrapError(f"missing capability token header: {header}")

    try:
        key = parse_hmac_key(raw_key)
        claims = verify_capability_token(key, token)
    except ValueError as exc:
        raise BootstrapError(f"invalid capability token: {exc}") from exc
    return claims.to_dict()
