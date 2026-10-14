#!/usr/bin/env bash
# One-command run path (no install needed). Examples:
#   ./run.sh pipeline
#   ./run.sh lint
#   ./run.sh scan
#   ./run.sh draft "powershell downloading from a pastebin url"
set -euo pipefail
cd "$(dirname "$0")"
exec python -m detection_as_code "$@"
