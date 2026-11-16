#!/usr/bin/env bash
# Orchestrate the full M10 baseline suite.
#
# Usage:
#   run-all.sh [--profile lan|metro|wan|lossy] [--openssh] [--flame]
#              [--out DIR]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

PROFILE="lan"
DO_OPENSSH=0
DO_FLAME=0
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --openssh) DO_OPENSSH=1; shift ;;
    --flame) DO_FLAME=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help)
      cat <<EOF
Usage: $0 [options]

  --profile PROFILE   netem profile (lan|metro|wan|lossy), default lan
  --openssh           also run OpenSSH comparison
  --flame             print manual flamegraph capture instructions
  --out DIR           result directory (default: target/bench/<timestamp>)
EOF
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

need_binaries

if [[ -z "$OUT" ]]; then
  OUT="$BENCH_ROOT/$(run_id)-full-$PROFILE"
fi
mkdir -p "$OUT"
meta_json "$OUT/meta.json"
write_summary_header "$OUT" "Full baseline suite ($PROFILE)"

echo "=== M10 performance suite ==="
echo "Results: $OUT"
echo "Profile: $PROFILE"
echo

"$SCRIPT_DIR/measure-handshake.sh"  --profile "$PROFILE" --out "$OUT/handshake"
"$SCRIPT_DIR/measure-latency.sh"    --profile "$PROFILE" --out "$OUT/latency"
"$SCRIPT_DIR/measure-throughput.sh" --profile "$PROFILE" --out "$OUT/throughput"
"$SCRIPT_DIR/measure-idle.sh"       --out "$OUT/idle"

if [[ $DO_OPENSSH -eq 1 ]]; then
  "$SCRIPT_DIR/compare-openssh.sh" --profile "$PROFILE" --out "$OUT/openssh"
fi

if [[ $DO_FLAME -eq 1 ]]; then
  echo "Flamegraphs require a live ssxd/ssx under the chosen workload."
  echo "Start the processes, then re-run flamegraph.sh manually, or extend"
  echo "this orchestrator once the interactive drivers are wired."
fi

{
  echo
  echo "## Sub-results"
  echo
  for d in handshake latency throughput idle openssh; do
    if [[ -f "$OUT/$d/summary.md" ]]; then
      echo "### $d"
      tail -n +2 "$OUT/$d/summary.md"
      echo
    fi
  done
} >>"$OUT/summary.md"

echo
echo "Suite finished. Aggregate summary: $OUT/summary.md"
echo "Fill the tables in docs/performance.md after reviewing the numbers."
echo
echo "Acceptance criteria reminder:"
echo "  - Baseline and tuned results published in docs/performance.md"
echo "  - Every enabled-by-default feature has a measured win"
echo "  - Regression benchmark runs in CI nightly with a threshold alert"
