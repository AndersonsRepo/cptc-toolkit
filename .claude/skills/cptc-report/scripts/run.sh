#!/usr/bin/env bash
# Thin shell wrapper for build_report.py. Mostly for muscle memory.
set -euo pipefail
exec python3 "$(dirname "$0")/build_report.py" "$@"
