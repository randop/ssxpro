#!/usr/bin/env bash
# Run the same latency / throughput / handshake workloads against OpenSSH
# on the same hosts so the tables in docs/performance.md have a real baseline.
#
# Usage:
#   compare-openssh.sh [--profile lan] [--out DIR]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

PROFILE="lan"
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$OPENSSH_BIN" ]] || die "ssh binary not found (set OPENSSH_BIN)"

if [[ -z "$OUT" ]]; then
  OUT="$BENCH_ROOT/$(run_id)-openssh-$PROFILE"
fi
mkdir -p "$OUT"
meta_json "$OUT/meta.json"
write_summary_header "$OUT" "OpenSSH baseline ($PROFILE)"

# Expect a pre-started sshd listening on OPENSSH_PORT (or 22) with a
# key-based account that matches the identity used for ssx measurements.
# The same netem profile should be applied on the path.

append_result "$OUT" "openssh_keystroke_p50_us" "null" "µs (not measured)"
append_result "$OUT" "openssh_keystroke_p99_us" "null" "µs (not measured)"
append_result "$OUT" "openssh_tx_mib_per_s" "null" "MiB/s (not measured)"
append_result "$OUT" "openssh_handshakes_per_s" "null" "1/s (not measured)"

echo "OpenSSH comparison skeleton ready at $OUT"
echo "Start an sshd with matching identity material, then drive the same"
echo "workloads used by measure-latency.sh / measure-throughput.sh."
echo "See docs/performance.md."
