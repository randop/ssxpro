#!/usr/bin/env bash
# Run tests/ssx_e2e.py against every server compression mode.
#
# Usage:
#   tests/compression_e2e.sh              # off, fast, standard, high
#   tests/compression_e2e.sh fast high    # selected modes
#
# The wrapper starts and stops a fresh test ssxd for each mode through
# tests/bootstrap.sh. No other test ssxd may be running.

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODES=(off fast standard high)

if [ "$#" -gt 0 ]; then
    MODES=("$@")
fi

for mode in "${MODES[@]}"; do
    case "$mode" in
        off | fast | standard | high) ;;
        *)
            printf 'error: unknown compression mode: %s\n' "$mode" >&2
            printf 'expected one of: off, fast, standard, high\n' >&2
            exit 2
            ;;
    esac
done

if status="$("$ROOT/tests/bootstrap.sh" status 2>&1)"; then
    printf 'error: a test ssxd is already running; stop it first\n' >&2
    printf '%s\n' "$status" >&2
    exit 1
fi

for mode in "${MODES[@]}"; do
    printf '\n=== compression: %s ===\n' "$mode"
    SSXD_COMPRESSION="$mode" "$ROOT/tests/bootstrap.sh" -- \
        python3 "$ROOT/tests/ssx_e2e.py"
done

printf '\ncompression e2e: %s/%s modes passed\n' "${#MODES[@]}" "${#MODES[@]}"
