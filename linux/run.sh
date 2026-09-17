#!/usr/bin/env bash
# Build the loader if needed, then load and run a honey-compiled program.
# Paths are relative to where you run it from (the repo root in honey-linux):
#   linux/honey-linux ./linux/run.sh [--json] build/x.bin build/x.json
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -x "$DIR/loader" ] || make -s -C "$DIR" loader
exec "$DIR/loader" "$@"
