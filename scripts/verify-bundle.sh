#!/usr/bin/env bash
set -euo pipefail

MODELS_DIR="${1:-./models}"
MANIFEST="${2:-MANIFEST.sha256}"

airgap-agent verify-bundle --models-dir "$MODELS_DIR" --manifest "$MANIFEST"
