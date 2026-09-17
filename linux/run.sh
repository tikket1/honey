#!/usr/bin/env bash
# Build the loader if needed, then load and run a honey-compiled program.
#   linux/honey-linux ./linux/run.sh <program.bin> <program.json>
set -euo pipefail
cd "$(dirname "$0")"
[ -x ./loader ] || make -s loader
exec ./loader "$@"
