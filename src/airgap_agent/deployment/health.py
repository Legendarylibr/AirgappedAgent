from __future__ import annotations

from typing import Any

from airgap_agent.config import AppConfig
from airgap_agent.deployment.bundle import verify_bundle
from airgap_agent.inference.base import InferenceBackend


def health_report(config: AppConfig, backend: InferenceBackend) -> dict[str, Any]:
    bundle = verify_bundle(config.bundle, config.trust) if config.airgap.require_bundle_manifest else None
    return {
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
        },
        "bundle": None
        if bundle is None
        else {
            "ok": bundle.ok,
            "checked": bundle.checked,
            "signature_ok": bundle.signature_ok,
            "errors": bundle.errors,
        },
        "workspace": str(config.security.workspace_root),
        "allowed_tools": config.security.allowed_tools,
    }
