#!/usr/bin/env bash
# CPU and memory cost of 1k / 10k / 50k idle authenticated connections.
#
# Usage:
#   measure-idle.sh [--counts 1000,10000,50000] [--hold-seconds 30] [--out DIR]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

COUNTS="1000,10000,50000"
HOLD=30
OUT=""
USE_NETNS=0   # large connection counts usually run on the host, not netns

while [[ $# -gt 0 ]]; do
  case "$1" in
    --counts) COUNTS="$2"; shift 2 ;;
    --hold-seconds) HOLD="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --netns) USE_NETNS=1; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

need_binaries

if [[ -z "$OUT" ]]; then
  OUT="$BENCH_ROOT/$(run_id)-idle"
fi
mkdir -p "$OUT"
meta_json "$OUT/meta.json"
write_summary_header "$OUT" "Idle connection cost (hold ${HOLD}s)"

# Protocol:
#   1. Start ssxd with a high max_connections / max_sessions.
#   2. For each N in COUNTS:
#        - open N authenticated sessions that simply sleep
#        - sample RSS / CPU of the worker process(es) for HOLD seconds
#        - record median RSS and CPU%
#   3. Tear down.
#
# Requires careful file-descriptor and port limits (ulimit -n, sysctl).

IFS=',' read -ra COUNT_ARR <<<"$COUNTS"
for n in "${COUNT_ARR[@]}"; do
  append_result "$OUT" "rss_mib_at_${n}" "null" "MiB (not measured)"
  append_result "$OUT" "cpu_pct_at_${n}" "null" "% (not measured)"
done

echo "Idle-connection harness skeleton ready at $OUT"
echo "Large N requires raised ulimits and a multi-worker ssxd build."
echo "See docs/performance.md."
