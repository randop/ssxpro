#!/usr/bin/env bash
# Bulk throughput: cat /dev/zero | ssx ... 'cat > /dev/null' and the reverse.
#
# Usage:
#   measure-throughput.sh [--profile lan] [--seconds 30] [--out DIR]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

PROFILE="lan"
SECONDS_RUN=30
OUT=""
USE_NETNS=1
SERVER_IP="10.200.0.2"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --seconds) SECONDS_RUN="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --no-netns) USE_NETNS=0; SERVER_IP="127.0.0.1"; shift ;;
    --server-ip) SERVER_IP="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

need_binaries

if [[ -z "$OUT" ]]; then
  OUT="$BENCH_ROOT/$(run_id)-throughput-$PROFILE"
fi
mkdir -p "$OUT"
meta_json "$OUT/meta.json"
write_summary_header "$OUT" "Bulk throughput ($PROFILE, ${SECONDS_RUN}s)"

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

# The real measurement drives:
#   client:  timeout $SECONDS_RUN cat /dev/zero | ssx user@$SERVER_IP "cat >/dev/null"
#   and the reverse direction with a remote `cat /dev/zero`.
# Both need a live authenticated session; the e2e bootstrap already
# knows how to start one. This skeleton records the intended protocol.

append_result "$OUT" "tx_mib_per_s" "null" "MiB/s (not measured)"
append_result "$OUT" "rx_mib_per_s" "null" "MiB/s (not measured)"
append_result "$OUT" "duration_s" "$SECONDS_RUN" "s"

echo "Throughput harness skeleton ready at $OUT"
echo "Wire against a live session (tests/bootstrap.sh + ssx) to obtain numbers."
echo "See docs/performance.md for the exact command shapes."
