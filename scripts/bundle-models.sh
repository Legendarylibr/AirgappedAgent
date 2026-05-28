#!/usr/bin/env bash
set -euo pipefail

MODELS_DIR="${1:-./models}"
MANIFEST="${2:-MANIFEST.sha256}"

if [[ ! -d "$MODELS_DIR" ]]; then
  echo "models directory not found: $MODELS_DIR" >&2
  exit 1
fi

echo "Generating SHA-256 manifest in $MODELS_DIR"
(
  cd "$MODELS_DIR"
  find . -type f ! -name "$MANIFEST" -print0 \
    | sort -z \
    | while IFS= read -r -d '' f; do
        rel="${f#./}"
        sum=$(shasum -a 256 "$rel" | awk '{print $1}')
        printf '%s  %s\n' "$sum" "$rel"
      done
) > "$MODELS_DIR/$MANIFEST"

echo "Wrote $MODELS_DIR/$MANIFEST"
wc -l < "$MODELS_DIR/$MANIFEST" | xargs echo "files:"
