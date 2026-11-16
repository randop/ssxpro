#!/usr/bin/env bash
# Measure keystroke-echo latency (client → server PTY → echo → client).
#
# Strategy:
#   1. Start ssxd in the server netns (or on host if --no-netns).
#   2. From the client side, open an interactive session and send single
#      bytes, timing the round-trip until the same byte is observed on
#      the local PTY.
#   3. Report p50 / p99 / p99.9 in microseconds.
#
# Usage:
#   measure-latency.sh [--profile lan] [--iterations 2000] [--out DIR]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

PROFILE="lan"
ITERATIONS=2000
OUT=""
USE_NETNS=1
SERVER_IP="10.200.0.2"
CLIENT_NS="ssx-bench-cli"
SERVER_NS="ssx-bench-srv"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --no-netns) USE_NETNS=0; SERVER_IP="127.0.0.1"; shift ;;
    --server-ip) SERVER_IP="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

need_binaries
need_cmd python3

if [[ -z "$OUT" ]]; then
  OUT="$BENCH_ROOT/$(run_id)-latency-$PROFILE"
fi
mkdir -p "$OUT"
meta_json "$OUT/meta.json"
write_summary_header "$OUT" "Keystroke-echo latency ($PROFILE)"

cleanup() {
  if [[ $USE_NETNS -eq 1 ]]; then
    "$SCRIPT_DIR/netns-setup.sh" down 2>/dev/null || true
  fi
  if [[ -n "${SSXD_PID:-}" ]]; then
    kill "$SSXD_PID" 2>/dev/null || true
    wait "$SSXD_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ $USE_NETNS -eq 1 ]]; then
  need_root
  "$SCRIPT_DIR/netns-setup.sh" up --profile "$PROFILE"
fi

# Minimal server config for the measurement (features-off style baseline).
WORK="$OUT/work"
mkdir -p "$WORK"
HOST_KEY="$WORK/host_ed25519"
IDENTITY="$WORK/id_ed25519"
AUTH_KEYS="$WORK/authorized_keys"
KNOWN_HOSTS="$WORK/known_hosts"
SSXD_CFG="$WORK/ssxd.yaml"
CLIENT_CFG="$WORK/ssx.yaml"

# Generate a throw-away Ed25519 seed pair if the real binaries support keygen.
# Fall back to a fixed test vector only when the harness is dry-run.
if "$SSX_BIN" keygen --force --path "$IDENTITY" >/dev/null 2>&1; then
  true
else
  # 32-byte zero seed is rejected by production code; the e2e bootstrap
  # already knows how to produce valid material. For a pure harness
  # skeleton we document the requirement and exit cleanly when keys are
  # missing.
  die "ssx keygen failed; produce $IDENTITY and matching authorized_keys manually"
fi

# Host key: reuse the same generator if available, else expect pre-provisioned.
if [[ ! -f "$HOST_KEY" ]]; then
  # ssxd expects a raw 32-byte seed. The real bootstrap script creates it;
  # here we ask the operator to supply one when keygen is unavailable.
  if command -v openssl >/dev/null 2>&1; then
    openssl rand 32 >"$HOST_KEY"
    chmod 0600 "$HOST_KEY"
  else
    die "host key missing and openssl unavailable"
  fi
fi

# authorized_keys and known_hosts are expected to be filled by the same
# bootstrap path used by tests/; the harness records the paths so a
# future fully-automated version can wire them.

cat >"$SSXD_CFG" <<EOF
listen: "0.0.0.0:$BENCH_PORT"
host_key: "$HOST_KEY"
compression: off
workers: 1
io:
  ring_entries: 4096
  recv_buffers: 2048
  buffer_size: 2048
  hugepages: false
  gro: true
  gso: true
  zerocopy_send: false
  zerocopy_min_bytes: 16384
  sqpoll: false
  sqpoll_idle_ms: 2
  napi_busy_poll_us: 0
  txtime_pacing: false
  pin_cpus: true
  restrict_ring: true
quic:
  idle_timeout_secs: 60
  keep_alive_interval_secs: 15
  max_connections: 64
  max_datagram_size: 1200
  retry: true
auth:
  server_authorized_keys: "$AUTH_KEYS"
  authorized_keys: authorized_keys
  max_attempts: 1
  allow_root: true
session:
  login_grace_secs: 10
  max_sessions: 16
  shell_path: /bin/sh
log:
  level: warn
  json: false
EOF

echo "NOTE: measure-latency.sh expects a fully bootstrapped identity,"
echo "      authorized_keys and known_hosts (see tests/bootstrap.sh)."
echo "      Results directory prepared at: $OUT"
echo "      Config skeleton written; full automated run requires the"
echo "      same key material the e2e suite already generates."

# Placeholder result so the summary is valid even before the first real run.
append_result "$OUT" "keystroke_p50_us" "null" "µs (not measured)"
append_result "$OUT" "keystroke_p99_us" "null" "µs (not measured)"
append_result "$OUT" "keystroke_p99_9_us" "null" "µs (not measured)"
append_result "$OUT" "iterations" "$ITERATIONS" ""

echo
echo "Harness skeleton ready. Wire the interactive PTY driver (Python or"
echo "a small Rust helper) against the same protocol used by tests/ssx_e2e.py"
echo "to complete the measurement. See docs/performance.md."
