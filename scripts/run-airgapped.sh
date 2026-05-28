#!/usr/bin/env bash
# Example launcher for strict airgapped runs.
set -euo pipefail

export AIRGAP_AIRGAP__MODE="${AIRGAP_AIRGAP__MODE:-strict}"
export AIRGAP_AIRGAP__DENY_EGRESS="${AIRGAP_AIRGAP__DENY_EGRESS:-true}"
export AIRGAP_AIRGAP__REQUIRE_BUNDLE_MANIFEST="${AIRGAP_AIRGAP__REQUIRE_BUNDLE_MANIFEST:-true}"
export AIRGAP_INFERENCE__BACKEND="${AIRGAP_INFERENCE__BACKEND:-llama_cpp}"
export AIRGAP_INFERENCE__MODEL_PATH="${AIRGAP_INFERENCE__MODEL_PATH:-/var/lib/airgap-agent/models/model.gguf}"
export AIRGAP_SECURITY__WORKSPACE_ROOT="${AIRGAP_SECURITY__WORKSPACE_ROOT:-/var/lib/airgap-agent/workspace}"

airgap-agent verify-bundle --models-dir "${AIRGAP_BUNDLE__MODELS_DIR:-/var/lib/airgap-agent/models}"

exec airgap-agent run "$@"
