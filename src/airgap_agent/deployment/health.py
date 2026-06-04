from __future__ import annotations

import os
from typing import Any

from airgap_agent.config import AppConfig
from airgap_agent.deployment.bootstrap import resolve_policy_path
from airgap_agent.deployment.bundle import verify_bundle
from airgap_agent.inference.base import InferenceBackend


def health_report(config: AppConfig, backend: InferenceBackend) -> dict[str, Any]:
    bundle = (
        verify_bundle(config.bundle, config.trust)
        if config.airgap.require_bundle_manifest
        else None
    )
    workspace = config.security.workspace_root
    workspace_ok = workspace.exists() and workspace.is_dir()
    audit_path = config.audit.log_path
    audit_parent = audit_path.parent
    audit_writable = (
        audit_parent.exists() and audit_parent.is_dir() and os.access(audit_parent, os.W_OK)
    )
    policy_path = resolve_policy_path(config)
    policy_exists = policy_path.exists()

    return {
        "status": "ok"
        if workspace_ok and (not config.audit.enabled or audit_writable)
        else "degraded",
        "airgap_mode": config.airgap.mode,
        "deny_egress": config.airgap.deny_egress,
        "inference": backend.health(),
        "trust": {
            "public_keys_dir": str(config.trust.public_keys_dir),
            "require_signed_manifest": config.trust.require_signed_manifest,
            "require_signed_policy": config.trust.require_signed_policy,
        },
        "audit": {
            "hash_chain": config.audit.hash_chain,
            "encrypt_at_rest": config.audit.encrypt_at_rest,
            "log_path": str(audit_path),
            "writable": audit_writable,
        },
        "policy": {"path": str(policy_path), "exists": policy_exists},
        "bundle": None
        if bundle is None
        else {
            "ok": bundle.ok,
            "checked": bundle.checked,
            "signature_ok": bundle.signature_ok,
            "errors": bundle.errors,
        },
        "workspace": {
            "path": str(workspace),
            "exists": workspace_ok,
        },
        "allowed_tools": config.security.allowed_tools,
        "allowed_capabilities": config.security.allowed_capabilities,
        "api": {
            "replay_protection": config.api.replay_protection,
            "sessions_enabled": config.api.sessions.enabled,
            "metrics_enabled": config.api.metrics.enabled,
        },
    }
