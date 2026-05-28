#!/usr/bin/env bash
# Build a wheelhouse on a connected machine, transfer to airgapped host, then:
#   ./scripts/offline-install.sh /path/to/wheelhouse
set -euo pipefail

WHEELHOUSE="${1:?usage: offline-install.sh /path/to/wheelhouse}"

python3 -m venv .venv
.venv/bin/pip install --no-index --find-links="$WHEELHOUSE" -r requirements-dev.txt
.venv/bin/pip install --no-index --find-links="$WHEELHOUSE" -e .
echo "Installed from offline wheelhouse."
