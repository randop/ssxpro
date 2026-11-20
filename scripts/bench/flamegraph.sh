#!/usr/bin/env bash
# Capture a flamegraph of the server or client under a given workload.
#
# Requires: perf, stackcollapse-perf.pl, and flamegraph.pl on PATH (or FLAMEGRAPH_PL).
#
# Usage:
#   flamegraph.sh --side server|client --duration 30 --workload latency|bulk|idle
#                 [--pid PID] [--out DIR]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

SIDE="server"
DURATION=30
WORKLOAD="latency"
PID=""
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --side) SIDE="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --workload) WORKLOAD="$2"; shift 2 ;;
    --pid) PID="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

need_cmd perf
FLAMEGRAPH_PL="${FLAMEGRAPH_PL:-$(command -v flamegraph.pl || true)}"
[[ -n "$FLAMEGRAPH_PL" ]] || die "flamegraph.pl not found (set FLAMEGRAPH_PL)"
need_cmd "$FLAMEGRAPH_PL"
STACKCOLLAPSE_PERF_PL="${STACKCOLLAPSE_PERF_PL:-$(command -v stackcollapse-perf.pl || true)}"
[[ -n "$STACKCOLLAPSE_PERF_PL" ]] || die "stackcollapse-perf.pl not found (set STACKCOLLAPSE_PERF_PL)"
need_cmd "$STACKCOLLAPSE_PERF_PL"

if [[ -z "$OUT" ]]; then
  OUT="$BENCH_ROOT/$(run_id)-flame-$SIDE-$WORKLOAD"
fi
mkdir -p "$OUT"
meta_json "$OUT/meta.json"

if [[ -z "$PID" ]]; then
  case "$SIDE" in
    server) PID=$(pgrep -x ssxd | head -1 || true) ;;
    client) PID=$(pgrep -x ssx  | head -1 || true) ;;
    *) die "side must be server or client" ;;
  esac
fi
[[ -n "$PID" ]] || die "no $SIDE process found; start it or pass --pid"

echo "Recording perf for pid $PID (${DURATION}s, workload=$WORKLOAD) ..."
perf record -o "$OUT/perf.data" -F 99 -p "$PID" -g -- sleep "$DURATION"
perf script -i "$OUT/perf.data" >"$OUT/perf.script"
"$STACKCOLLAPSE_PERF_PL" "$OUT/perf.script" >"$OUT/perf.folded"
"$FLAMEGRAPH_PL" "$OUT/perf.folded" >"$OUT/flame.svg"
echo "Flamegraph written to $OUT/flame.svg"
append_result "$OUT" "flamegraph" "$OUT/flame.svg" "" string
