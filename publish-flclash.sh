#!/bin/bash
# Push the local FlClash config (from dotfile repo) into Workers KV so
# FlClash subscriptions at vv.bigkyle.com/sub?token=... serve the latest version.
#
# Usage: bash publish-flclash.sh

set -euo pipefail

YAML="${FLCLASH_YAML:-/Users/kyle/git/dotfile/mac/.config/flclash/flclash.yaml}"

if [[ ! -f "$YAML" ]]; then
  echo "error: YAML not found at $YAML" >&2
  exit 1
fi

cd "$(dirname "$0")"

echo "Publishing $YAML -> KV[CONFIG]/flclash ..."
npx wrangler kv key put --binding=CONFIG flclash --path="$YAML"

echo
echo "Done. FlClash will pick up the change on next poll (or pull-to-refresh)."
