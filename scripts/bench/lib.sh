#!/usr/bin/env bash
# Common helpers for ssxpro performance harness.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BENCH_ROOT="${BENCH_ROOT:-$REPO_ROOT/target/bench}"
SSXD_BIN="${SSXD_BIN:-$REPO_ROOT/target/release/ssxd}"
SSX_BIN="${SSX_BIN:-$REPO_ROOT/target/release/ssx}"
OPENSSH_BIN="${OPENSSH_BIN:-$(command -v ssh || true)}"

# Default ports inside namespaces
BENCH_PORT="${BENCH_PORT:-2222}"
OPENSSH_PORT="${OPENSSH_PORT:-2223}"

die() { echo "bench: $*" >&2; exit 1; }

need_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    die "this measurement requires root (netns / tc / pinning)"
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

need_binaries() {
  [[ -x "$SSXD_BIN" ]] || die "ssxd not found or not executable: $SSXD_BIN (build with --release first)"
  [[ -x "$SSX_BIN" ]]  || die "ssx not found or not executable: $SSX_BIN"
}

run_id() {
  date -u +%Y%m%dT%H%M%SZ
}

meta_json() {
  local out="$1"
  cat >"$out" <<EOF
{
  "commit": "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)",
  "kernel": "$(uname -r)",
  "cpu": "$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | xargs || echo unknown)",
  "nproc": $(nproc),
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "ssxd": "$SSXD_BIN",
  "ssx": "$SSX_BIN"
}
EOF
}

write_summary_header() {
  local dir="$1"
  local title="$2"
  {
    echo "# $title"
    echo
    echo "- commit: \`$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)\`"
    echo "- kernel: \`$(uname -r)\`"
    echo "- cpu: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | xargs || echo unknown)"
    echo "- cores: $(nproc)"
    echo "- time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
  } >"$dir/summary.md"
}

append_result() {
  local dir="$1"
  local name="$2"
  local value="$3"
  local unit="${4:-}"
  echo "- **$name**: $value${unit:+ $unit}" >>"$dir/summary.md"
  echo "{\"metric\":\"$name\",\"value\":$value,\"unit\":\"$unit\"}" >>"$dir/results.jsonl"
}

# Simple percentile helper from a sorted numeric list on stdin.
percentile() {
  local p="$1"
  awk -v p="$p" '
    { a[NR] = $1 }
    END {
      if (NR == 0) { print "nan"; exit }
      idx = int((p/100.0) * (NR - 1)) + 1
      if (idx < 1) idx = 1
      if (idx > NR) idx = NR
      print a[idx]
    }'
}
