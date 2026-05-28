#!/usr/bin/env bash
# Sign model bundle on staging (private key never leaves signing host).
set -euo pipefail

MODELS_DIR="${1:?usage: sign-bundle.sh /path/to/models}"
PRIVATE_KEY="${2:?usage: sign-bundle.sh /path/to/models /path/to/signing/release.pem}"
KEY_ID="${3:-release}"

airgap-agent write-manifest "$MODELS_DIR"
airgap-agent sign-bundle "$MODELS_DIR" --private-key "$PRIVATE_KEY" --key-id "$KEY_ID"
echo "Copy models/, MANIFEST.sha256, MANIFEST.sig.json, and trust/*.pub.pem to airgapped host."
