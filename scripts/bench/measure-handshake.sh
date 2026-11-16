#!/usr/bin/env bash
# Full handshakes per second per core.
#
# Spawns N parallel clients that each complete auth + OpenShell then exit.
# Reports median of several runs.
#
# Usage:
#   measure-handshake.sh [--profile lan] [--parallel 32] [--runs 5] [--out DIR]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

PROFILE="lan"
PARALLEL=32
RUNS=5
OUT=""
USE_NETNS=1
SERVER_IP="10.200.0.2"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --parallel) PARALLEL="$2"; shift 2 ;;
    --runs) RUNS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --no-netns) USE_NETNS=0; SERVER_IP="127.0.0.1"; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

need_binaries

if [[ -z "$OUT" ]]; then
  OUT="$BENCH_ROOT/$(run_id)-handshake-$PROFILE"
fi
mkdir -p "$OUT"
meta_json "$OUT/meta.json"
write_summary_header "$OUT" "Handshakes / s ($PROFILE, parallel=$PARALLEL, runs=$RUNS)"

cleanup() {
  if [[ $USE_NETNS -eq 1 ]]; then
    "$SCRIPT_DIR/netns-setup.sh" down 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ $USE_NETNS -eq 1 ]]; then
  need_root
  "$SCRIPT_DIR/netns-setup.sh" up --profile "$PROFILE"
fi

# Intended measurement:
# for run in 1..RUNS:
#   start $PARALLEL clients that each do: ssx -o BatchMode user@$SERVER_IP true
#   measure wall time, compute handshakes/s = PARALLEL / elapsed
# report median and /core (divide by nproc or by pinned workers)

append_result "$OUT" "handshakes_per_s" "null" "1/s (not measured)"
append_result "$OUT" "handshakes_per_s_per_core" "null" "1/s/core (not measured)"
append_result "$OUT" "parallel" "$PARALLEL" ""
append_result "$OUT" "runs" "$RUNS" ""

echo "Handshake harness skeleton ready at $OUT"
echo "See docs/performance.md for the measurement protocol."
