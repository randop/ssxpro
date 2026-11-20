#!/usr/bin/env bash
# Create (or tear down) a pair of network namespaces linked by a veth pair,
# optionally applying a tc netem profile on the server side.
#
# Usage:
#   netns-setup.sh up   [--profile lan|metro|wan|lossy]
#   netns-setup.sh down
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

CLIENT_NS="${CLIENT_NS:-ssx-bench-cli}"
SERVER_NS="${SERVER_NS:-ssx-bench-srv}"
VETH_C="${VETH_C:-veth-c}"
VETH_S="${VETH_S:-veth-s}"
CLIENT_IP="${CLIENT_IP:-10.200.0.1/24}"
SERVER_IP="${SERVER_IP:-10.200.0.2/24}"
PROFILE="lan"

usage() {
  cat <<EOF
Usage: $0 up [--profile PROFILE]
       $0 down

Profiles: lan (default), metro, wan, lossy
EOF
  exit 1
}

apply_netem() {
  local ns="$1"
  local profile="$2"
  # Clear any existing qdisc
  ip netns exec "$ns" tc qdisc del dev "$VETH_S" root 2>/dev/null || true

  case "$profile" in
    lan)
      ip netns exec "$ns" tc qdisc add dev "$VETH_S" root netem delay 0.3ms 0.1ms distribution normal
      ;;
    metro)
      ip netns exec "$ns" tc qdisc add dev "$VETH_S" root netem delay 5ms 1ms distribution normal loss 0.01%
      ;;
    wan)
      ip netns exec "$ns" tc qdisc add dev "$VETH_S" root netem delay 40ms 5ms distribution normal loss 0.1% reorder 0.1%
      ;;
    lossy)
      ip netns exec "$ns" tc qdisc add dev "$VETH_S" root netem delay 20ms 10ms distribution normal loss 1% reorder 1%
      ;;
    none)
      ;;
    *)
      die "unknown netem profile: $profile"
      ;;
  esac
}

cmd_up() {
  need_root
  need_cmd ip
  need_cmd tc

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --profile) PROFILE="$2"; shift 2 ;;
      *) usage ;;
    esac
  done

  # Tear down any leftover namespaces first
  cmd_down 2>/dev/null || true

  # Track only a pair successfully created by this invocation. Install rollback
  # before allocation so a failed move cannot strand an endpoint on the host.
  VETH_OWNED=0
  trap 'cmd_down' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  ip netns add "$CLIENT_NS"
  ip netns add "$SERVER_NS"

  ip link add "$VETH_C" type veth peer name "$VETH_S"
  VETH_OWNED=1
  ip link set "$VETH_C" netns "$CLIENT_NS"
  ip link set "$VETH_S" netns "$SERVER_NS"

  ip netns exec "$CLIENT_NS" ip addr add "$CLIENT_IP" dev "$VETH_C"
  ip netns exec "$SERVER_NS" ip addr add "$SERVER_IP" dev "$VETH_S"
  ip netns exec "$CLIENT_NS" ip link set "$VETH_C" up
  ip netns exec "$SERVER_NS" ip link set "$VETH_S" up
  ip netns exec "$CLIENT_NS" ip link set lo up
  ip netns exec "$SERVER_NS" ip link set lo up

  apply_netem "$SERVER_NS" "$PROFILE"

  trap - EXIT INT TERM
  echo "netns ready: client=$CLIENT_NS ($CLIENT_IP) server=$SERVER_NS ($SERVER_IP) profile=$PROFILE"
}

cmd_down() {
  need_root
  ip netns del "$CLIENT_NS" 2>/dev/null || true
  ip netns del "$SERVER_NS" 2>/dev/null || true
  # Namespace deletion removes moved endpoints. Delete any owned endpoints
  # left on the host after a failed move, but never a pre-existing host device.
  if [[ ${VETH_OWNED:-0} -eq 1 ]]; then
    ip link del "$VETH_C" 2>/dev/null || true
    ip link del "$VETH_S" 2>/dev/null || true
  fi
  echo "netns torn down"
}

case "${1:-}" in
  up)   shift; cmd_up "$@" ;;
  down) shift; cmd_down "$@" ;;
  *)    usage ;;
esac
