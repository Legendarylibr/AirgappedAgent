#!/usr/bin/env bash
# Run on a connected staging machine to prepare offline install artifacts.
set -euo pipefail

OUT="${1:-./wheelhouse}"
mkdir -p "$OUT"
pip download -r requirements-dev.txt -d "$OUT"
pip wheel . -w "$OUT"
echo "Wheelhouse ready: $OUT"
