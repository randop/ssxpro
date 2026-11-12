#!/usr/bin/env bash
# tests/bootstrap.sh — bootstrap a local test ssxd for tests/ssx_e2e.py.
#
# The e2e driver deliberately does not start or stop servers; it only
# drives clients. This script is the missing half: it prepares every
# artifact the driver expects from its environment (host key, test
# identity, authorized_keys, known_hosts pin, ssxd.yaml), validates the
# configuration and kernel with `ssxd --check-config`, starts
# `ssxd --yes-I-know-permission-risks-go-ahead-please` in the background, and waits until
# the server reports ready.
#
# Usage:
#   tests/bootstrap.sh                     start ssxd and leave it running
#   tests/bootstrap.sh start               same as above
#   tests/bootstrap.sh -- CMD [ARG...]     start, run CMD (e.g.
#                                          python3 tests/ssx_e2e.py), then stop
#   tests/bootstrap.sh stop                stop a running test ssxd
#   tests/bootstrap.sh restart             stop, then start again
#   tests/bootstrap.sh status              report whether the test ssxd runs
#   tests/bootstrap.sh --help              show this text
#
# Environment (defaults mirror tests/ssx_e2e.py):
#   SSXD_BIN               ssxd binary; default: target/{debug,release}/ssxd
#   SSXD_VERBOSE           server verbosity flags; default: "-v"
#   SSXD_READY_TIMEOUT     seconds to wait for "worker ready"; default: 30
#   SSXD_EXTRA_ARGS        extra arguments appended to the ssxd command line
#   SSXD_COMPRESSION       PTY stream compression mode: off, fast,
#                          standard or high; default: off
#   SSX_E2E_HOST           bind/connect address; default: 127.0.0.1 (an IP
#                          literal, not a hostname: it goes into `listen:`)
#   SSX_E2E_PORT           UDP port; default: 2222
#   SSX_E2E_USER           login account; default: $USER, else "root"
#   SSX_E2E_WORK           artifact directory; default: target/e2e
#   SSX_E2E_IDENTITY       client identity seed; default: a generated
#                          32-byte seed kept in SSX_E2E_WORK
#   SSX_E2E_KNOWN_HOSTS    pinned-hosts file; default: a generated pin file
#                          in SSX_E2E_WORK
#
# Exit codes: 0 success; 1 runtime failure (server died, readiness
# timeout, already running); 2 usage or preflight failure. With `--`
# CMD, the exit status of CMD is propagated.
#
# Files written under SSX_E2E_WORK (directory 0700, files 0600):
#   ssxd.yaml              generated server configuration
#   host_ed25519           32-byte Ed25519 host key seed
#   identity_ed25519       32-byte Ed25519 client identity seed
#   authorized_keys        server-wide key list for the test identity
#   known_hosts.bootstrap  `HOST:PORT spki-sha256 ...` pin for the host key
#   ssxd.check.log         output of the `--check-config` preflight
#   ssxd.log               running server log
#   ssxd.pid               server pid while it runs
#   test.env               exports to `source` before tests/ssx_e2e.py

set -Eeuo pipefail
umask 077

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WORK="${SSX_E2E_WORK:-$REPO/target/e2e}"
HOST="${SSX_E2E_HOST:-127.0.0.1}"
PORT="${SSX_E2E_PORT:-2222}"
TEST_USER="${SSX_E2E_USER:-${USER:-root}}"
SSXD_READY_TIMEOUT="${SSXD_READY_TIMEOUT:-30}"
SSXD_VERBOSE="${SSXD_VERBOSE:-"-v"}"
SSXD_EXTRA_ARGS="${SSXD_EXTRA_ARGS:-}"
SSXD_COMPRESSION="${SSXD_COMPRESSION:-off}"

SSXD_PID_FILE="$WORK/ssxd.pid"
SSXD_LOG="$WORK/ssxd.log"
SSXD_CHECK_LOG="$WORK/ssxd.check.log"
SSXD_CONFIG="$WORK/ssxd.yaml"
SSXD_HOST_KEY="$WORK/host_ed25519"
SSXD_IDENTITY="$WORK/identity_ed25519"
SSXD_AUTHORIZED_KEYS="$WORK/authorized_keys"
SSXD_KNOWN_HOSTS="$WORK/known_hosts.bootstrap"
SSXD_ENV_FILE="$WORK/test.env"

MODE="start"
RUN_CMD=()
SSXD_PID=
START_COMPLETED=0
LAUNCHED_HERE=0
ALLOW_ROOT=false

# Operator presets, captured before this script exports its own defaults.
PRESET_IDENTITY="${SSX_E2E_IDENTITY:-}"
PRESET_KNOWN_HOSTS="${SSX_E2E_KNOWN_HOSTS:-}"
PRESET_SSX_BIN="${SSX_BIN:-}"

log()  { printf 'bootstrap: %s\n' "$*"; }
warn() { printf 'bootstrap: warning: %s\n' "$*" >&2; }
die()  { local code=$1; shift; printf 'bootstrap: error: %s\n' "$*" >&2; exit "$code"; }

usage() {
    awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' \
        "${BASH_SOURCE[0]}"
}

shquote() {
    local quoted=${1//\'/\'\\\'\'}
    printf "'%s'" "$quoted"
}

while [ $# -gt 0 ]; do
    case "$1" in
        start|stop|restart|status)
            MODE=$1; shift ;;
        --)
            shift
            [ $# -gt 0 ] || die 2 "'--' must be followed by a command to run"
            RUN_CMD=("$@")
            break ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            die 2 "unknown argument: $1 (try --help)" ;;
    esac
done

if [ "${#RUN_CMD[@]}" -gt 0 ] && [ "$MODE" != "start" ]; then
    die 2 "'--' can only be combined with start mode"
fi

# ---------------------------------------------------------------------------
# Ed25519 helpers.
#
# Key files are exactly 32 raw seed bytes (the ssxd host-key requirement).
# The fixed PKCS#8 prefix below is the RFC 8410 encoding wrapping an
# Ed25519 seed, so OpenSSL derives the SPKI public encoding without any
# extra key tooling. The SPKI DER is a fixed 12-byte header plus the
# 32-byte public key; the SHA-256 of that DER is the `spki-sha256`
# known_hosts pin the client enforces.
# ---------------------------------------------------------------------------

require_openssl() {
    command -v openssl >/dev/null 2>&1 || die 2 "openssl is required but not on PATH"
}

# seed file -> SPKI DER on stdout
derive_spki() {
    { printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'
      cat "$1"; } | openssl pkey -inform DER -pubout -outform DER 2>/dev/null
}

# seed file -> raw 32-byte public key on stdout
derive_public_key() {
    derive_spki "$1" | tail -c 32
}

# seed file -> base64 spki-sha256 pin value (no trailing newline)
derive_host_pin() {
    derive_spki "$1" | openssl dgst -sha256 -binary | openssl base64 -A
}

new_seed_file() {
    head -c 32 /dev/urandom > "$1"
    chmod 600 "$1"
}

# ---------------------------------------------------------------------------
# Preflight checks.
# ---------------------------------------------------------------------------

resolve_ssxd() {
    if [ -n "${SSXD_BIN:-}" ]; then
        [ -x "$SSXD_BIN" ] || die 2 "SSXD_BIN=$SSXD_BIN is not executable"
        return
    fi
    local candidate
    for candidate in "$REPO/target/debug/ssxd" "$REPO/target/release/ssxd"; do
        if [ -x "$candidate" ]; then
            SSXD_BIN=$candidate
            return
        fi
    done
    die 2 "ssxd binary not found; build it first (scripts/cargo-pinned.sh build --workspace --locked) or set SSXD_BIN"
}

check_test_user() {
    command -v getent >/dev/null 2>&1 \
        || die 2 "getent is required to resolve the test account"
    local entry pw_uid pw_home pw_shell
    entry="$(getent passwd "$TEST_USER" 2>/dev/null || true)"
    [ -n "$entry" ] \
        || die 2 "test user '$TEST_USER' not found in the account database (ssxd resolves logins through NSS)"
    # passwd fields: name:passwd:uid:gid:gecos:home:shell (gecos holds no ':')
    IFS=: read -r _ _ pw_uid _ _ pw_home pw_shell <<< "$entry"
    [ -n "$pw_home" ] && [[ "$pw_home" = /* ]] \
        || die 2 "account '$TEST_USER' has no absolute home directory; ssxd denies such logins"
    [ -n "$pw_shell" ] \
        || die 2 "account '$TEST_USER' has an empty login shell; run: chsh -s /bin/sh $TEST_USER"

    # ssxd spawns the account's passwd shell and validates it strictly
    # (session.rs:validate_login_shell): absolute, not /false or /nologin,
    # listed in /etc/shells, executable. A violation denies every login,
    # so fail here with an actionable message instead.
    if [[ "$pw_shell" == */nologin || "$pw_shell" == */false || "$pw_shell" != /* ]]; then
        die 2 "account '$TEST_USER' has shell '$pw_shell', which ssxd rejects as a non-login shell"
    fi
    [ -f /etc/shells ] \
        || die 2 "/etc/shells is missing; ssxd only spawns shells listed there (add '$pw_shell' to /etc/shells)"
    grep -Fxq "$pw_shell" /etc/shells \
        || die 2 "shell '$pw_shell' of user '$TEST_USER' is not listed in /etc/shells (append it, or run: chsh -s /bin/sh $TEST_USER)"
    [ -x "$pw_shell" ] || die 2 "shell '$pw_shell' is not executable"

    if [ "$pw_uid" -eq 0 ]; then
        ALLOW_ROOT=true
        log "test user '$TEST_USER' is root; setting auth.allow_root: true in $SSXD_CONFIG"
    fi
}

# Export the environment tests/ssx_e2e.py reads. Operator-provided
# overrides win; generated artifacts fill everything else.
export_test_env() {
    if [ -n "$PRESET_IDENTITY" ] && [ ! -f "$PRESET_IDENTITY" ]; then
        die 2 "SSX_E2E_IDENTITY=$PRESET_IDENTITY is set but missing"
    fi
    if [ -n "$PRESET_IDENTITY" ]; then
        export SSX_E2E_IDENTITY=$PRESET_IDENTITY
    else
        export SSX_E2E_IDENTITY=$SSXD_IDENTITY
    fi
    if [ -n "$PRESET_KNOWN_HOSTS" ]; then
        export SSX_E2E_KNOWN_HOSTS=$PRESET_KNOWN_HOSTS
        warn "SSX_E2E_KNOWN_HOSTS is preset; leaving it alone (it must already pin $HOST:$PORT)"
    else
        export SSX_E2E_KNOWN_HOSTS=$SSXD_KNOWN_HOSTS
    fi
    export SSX_E2E_HOST=$HOST SSX_E2E_PORT=$PORT SSX_E2E_USER=$TEST_USER SSX_E2E_WORK=$WORK
    export SSX_E2E_COMPRESSION=$SSXD_COMPRESSION

    if [ -n "$PRESET_SSX_BIN" ]; then
        [ -x "$PRESET_SSX_BIN" ] || warn "SSX_BIN=$PRESET_SSX_BIN is not executable; tests/ssx_e2e.py will fail"
    elif [ -x "$REPO/target/debug/ssx" ]; then
        export SSX_BIN=$REPO/target/debug/ssx
    elif [ -x "$REPO/target/release/ssx" ]; then
        export SSX_BIN=$REPO/target/release/ssx
        warn "client found only in the release profile; exporting SSX_BIN=$SSX_BIN"
    else
        warn "client binary not found (target/debug/ssx); tests/ssx_e2e.py needs it or SSX_BIN"
    fi
}

write_env_file() {
    {
        printf '# Generated by tests/bootstrap.sh; source with bash, then run tests/ssx_e2e.py.\n'
        printf 'export SSX_E2E_HOST=%s\n' "$(shquote "$HOST")"
        printf 'export SSX_E2E_PORT=%s\n' "$(shquote "$PORT")"
        printf 'export SSX_E2E_USER=%s\n' "$(shquote "$TEST_USER")"
        printf 'export SSX_E2E_WORK=%s\n' "$(shquote "$WORK")"
        printf 'export SSX_E2E_COMPRESSION=%s\n' "$(shquote "$SSXD_COMPRESSION")"
        printf 'export SSX_E2E_IDENTITY=%s\n' "$(shquote "${SSX_E2E_IDENTITY:-}")"
        printf 'export SSX_E2E_KNOWN_HOSTS=%s\n' "$(shquote "${SSX_E2E_KNOWN_HOSTS:-}")"
        if [ -n "${SSX_BIN:-}" ]; then
            printf 'export SSX_BIN=%s\n' "$(shquote "$SSX_BIN")"
        fi
    } > "$SSXD_ENV_FILE"
}

# ---------------------------------------------------------------------------
# Artifact generation.
# ---------------------------------------------------------------------------

write_config() {
    local listen="$HOST:$PORT"
    [[ "$HOST" == *:* ]] && listen="[$HOST]:$PORT"   # IPv6 literal
    case "$SSXD_COMPRESSION" in
        off | fast | standard | high) ;;
        *) die 2 "SSXD_COMPRESSION must be one of: off, fast, standard, high (got '$SSXD_COMPRESSION')" ;;
    esac
    cat > "$SSXD_CONFIG" <<YAML
# Generated by tests/bootstrap.sh — local e2e test configuration.
listen: "$listen"
host_key: "$SSXD_HOST_KEY"
compression: "$SSXD_COMPRESSION"
workers: 1
io:
  # Dev hosts and CI runners rarely reserve huge pages; the probe fails
  # closed, so ssxd would refuse to start with the default (true).
  hugepages: false
  # Avoid CPU-pinning constraints inside containers and shared runners.
  pin_cpus: false
auth:
  # The server-wide list is checked before the per-user file, so no
  # $HOME/.ssx permission choreography is needed for the test account.
  server_authorized_keys: "$SSXD_AUTHORIZED_KEYS"
  allow_root: $ALLOW_ROOT
session:
  shell_path: "/bin/sh"
log:
  level: "info"
YAML
    chmod 600 "$SSXD_CONFIG"
}

write_keys() {
    local pub_b64 pin identity_source

    # Host key: reuse across runs so restarts keep a stable pin.
    if [ ! -s "$SSXD_HOST_KEY" ]; then
        new_seed_file "$SSXD_HOST_KEY"
        log "generated host key $SSXD_HOST_KEY"
    fi

    # Client identity: reuse the generated one; honor an operator-provided one.
    if [ -n "$PRESET_IDENTITY" ]; then
        log "using preset identity $PRESET_IDENTITY"
    elif [ ! -s "$SSXD_IDENTITY" ]; then
        new_seed_file "$SSXD_IDENTITY"
        log "generated test identity $SSXD_IDENTITY"
    fi
    identity_source=${PRESET_IDENTITY:-$SSXD_IDENTITY}
    # ssx reads identities as exactly 32 raw seed bytes; anything else only
    # fails at connect time, so reject it here.
    [ "$(wc -c < "$identity_source")" -eq 32 ] \
        || die 2 "identity $identity_source must be exactly 32 raw Ed25519 seed bytes, got $(wc -c < "$identity_source")"

    pub_b64="$(derive_public_key "$identity_source" | openssl base64 -A)"
    [ "${#pub_b64}" -eq 44 ] \
        || die 1 "could not derive the Ed25519 public key from $identity_source (openssl failed)"
    printf 'ed25519 %s ssx-e2e-bootstrap\n' "$pub_b64" > "$SSXD_AUTHORIZED_KEYS"
    chmod 600 "$SSXD_AUTHORIZED_KEYS"

    # known_hosts pin: the client only auto-appends pins to ~/.ssx/known_hosts;
    # custom paths (as the e2e driver uses) must already contain the pin.
    pin="$(derive_host_pin "$SSXD_HOST_KEY")"
    [ -n "$pin" ] || die 1 "could not derive the host key pin from $SSXD_HOST_KEY (openssl failed)"
    printf '%s:%s spki-sha256 %s\n' "$HOST" "$PORT" "$pin" > "$SSXD_KNOWN_HOSTS"
    chmod 600 "$SSXD_KNOWN_HOSTS"
}

# ---------------------------------------------------------------------------
# Server lifecycle.
# ---------------------------------------------------------------------------

preflight_check_config() {
    local code=0
    # shellcheck disable=SC2086 # SSXD_VERBOSE is an intentional word list
    "$SSXD_BIN" --config "$SSXD_CONFIG" --yes-I-know-permission-risks-go-ahead-please \
        $SSXD_VERBOSE --check-config > "$SSXD_CHECK_LOG" 2>&1 || code=$?
    if [ "$code" -ne 0 ]; then
        cat "$SSXD_CHECK_LOG" >&2 || true
        case $code in
            4) warn "kernel feature probe failed; ssxd requires io_uring with COOP_TASKRUN/DEFER_TASKRUN/SINGLE_ISSUER plus UDP_GRO and UDP_SEGMENT — see docs/ci-kernels.md" ;;
            3) warn "configuration or key file rejected (exit 3)" ;;
            2) warn "ssxd rejected the command line (exit 2)" ;;
        esac
        die 1 "ssxd --check-config failed (exit $code); full output above, kept in $SSXD_CHECK_LOG"
    fi
    log "ssxd --check-config passed (probe details in $SSXD_CHECK_LOG)"
}

server_alive() {
    local stat
    kill -0 "$SSXD_PID" 2>/dev/null || return 1
    stat="$(ps -o stat= -p "$SSXD_PID" 2>/dev/null || true)"
    [ -n "$stat" ] && [ "${stat:0:1}" != "Z" ]
}

# Does pid $1 look like the ssxd server (or a script wrapping it)?
pid_is_ssxd() {
    local pid=$1
    if [ -r "/proc/$pid/cmdline" ]; then
        tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | grep -q ssxd
    else
        ps -o comm= -p "$pid" 2>/dev/null | grep -q ssxd
    fi
}

# Stop the server and, because ssxd forks helpers (TLS monitor, session
# shells), its whole process group when it leads one (it runs under
# setsid). Falls back to the pid alone plus its direct children.
stop_server() {
    local pid pgid waited=0
    [ -f "$SSXD_PID_FILE" ] || return 0
    pid="$(cat "$SSXD_PID_FILE" 2>/dev/null || true)"
    [ -n "$pid" ] || { rm -f "$SSXD_PID_FILE"; return 0; }
    if ! kill -0 "$pid" 2>/dev/null; then
        rm -f "$SSXD_PID_FILE"
        return 0
    fi
    pgid="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ' || true)"
    if [ -n "$pgid" ] && [ "$pgid" = "$pid" ]; then
        kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    else
        kill -TERM "$pid" 2>/dev/null || true
        pkill -TERM -P "$pid" 2>/dev/null || true
    fi
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 50 ]; do
        sleep 0.2
        waited=$((waited + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        warn "ssxd (pid $pid) ignored SIGTERM; sending SIGKILL"
        kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    fi
    rm -f "$SSXD_PID_FILE"
    log "stopped ssxd (pid $pid)"
}

start_server() {
    mkdir -p "$WORK"
    chmod 700 "$WORK"

    require_openssl
    resolve_ssxd
    check_test_user
    export_test_env
    write_config
    write_keys

    # Refuse to stack a second server on the same artifacts; recover from
    # stale pid files (dead process, zombie, or a recycled pid).
    if [ -f "$SSXD_PID_FILE" ]; then
        local old_pid old_stat
        old_pid="$(cat "$SSXD_PID_FILE" 2>/dev/null || true)"
        old_stat="$(ps -o stat= -p "$old_pid" 2>/dev/null || true)"
        if [ -n "$old_pid" ] && [ -n "$old_stat" ] && [ "${old_stat:0:1}" != "Z" ] \
            && pid_is_ssxd "$old_pid"; then
            die 1 "test ssxd already running (pid $old_pid); use 'tests/bootstrap.sh restart'"
        fi
        warn "removing stale pid file $SSXD_PID_FILE"
        rm -f "$SSXD_PID_FILE"
    fi

    preflight_check_config

    : > "$SSXD_LOG"
    # setsid detaches ssxd into its own session so it outlives this script
    # in plain start mode and the whole group can be signalled on stop.
    # shellcheck disable=SC2086 # SSXD_VERBOSE/SSXD_EXTRA_ARGS are word lists
    if command -v setsid >/dev/null 2>&1; then
        setsid "$SSXD_BIN" --config "$SSXD_CONFIG" --yes-I-know-permission-risks-go-ahead-please \
            $SSXD_VERBOSE $SSXD_EXTRA_ARGS >> "$SSXD_LOG" 2>&1 < /dev/null &
    else
        "$SSXD_BIN" --config "$SSXD_CONFIG" --yes-I-know-permission-risks-go-ahead-please \
            $SSXD_VERBOSE $SSXD_EXTRA_ARGS >> "$SSXD_LOG" 2>&1 < /dev/null &
    fi
    SSXD_PID=$!
    printf '%s\n' "$SSXD_PID" > "$SSXD_PID_FILE"
    LAUNCHED_HERE=1

    # Each worker logs "ssxd: worker N ready" once its endpoints are bound.
    local started=$SECONDS
    while :; do
        if grep -Eq '^ssxd: worker [0-9]+ ready$' "$SSXD_LOG" 2>/dev/null; then
            break
        fi
        if ! server_alive; then
            sed -n '1,80p' "$SSXD_LOG" >&2 || true
            rm -f "$SSXD_PID_FILE"
            die 1 "ssxd exited before becoming ready; log: $SSXD_LOG"
        fi
        if [ $((SECONDS - started)) -ge "$SSXD_READY_TIMEOUT" ]; then
            sed -n '1,80p' "$SSXD_LOG" >&2 || true
            stop_server
            die 1 "timed out after ${SSXD_READY_TIMEOUT}s waiting for 'ssxd: worker ready' in $SSXD_LOG"
        fi
        sleep 0.2
    done

    write_env_file
    START_COMPLETED=1
    log "ssxd ready: pid $SSXD_PID, listening on $HOST:$PORT (workers=1, compression=$SSXD_COMPRESSION)"
    log "server log: $SSXD_LOG"
    log "run e2e   : tests/bootstrap.sh -- python3 tests/ssx_e2e.py"
    log "or manual : source $SSXD_ENV_FILE && python3 tests/ssx_e2e.py"
    log "stop with : tests/bootstrap.sh stop"
}

# If this invocation launched a server and start did not complete (error,
# INT/TERM during startup), take it back down; otherwise leave everything
# as it was — a refused start must not kill an already-running server.
on_exit_during_start() {
    if [ "$START_COMPLETED" != 1 ] && [ "$LAUNCHED_HERE" = 1 ]; then
        stop_server
    fi
}

on_start_interrupt() {
    warn "interrupted; stopping the test server"
    if [ "$LAUNCHED_HERE" = 1 ]; then
        stop_server
    fi
    exit 130
}

do_status() {
    if [ -f "$SSXD_PID_FILE" ]; then
        local pid
        pid="$(cat "$SSXD_PID_FILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            log "ssxd running (pid $pid); log: $SSXD_LOG"
            return 0
        fi
        log "stale pid file for pid ${pid:-?}"
        return 1
    fi
    log "ssxd not running (no $SSXD_PID_FILE)"
    return 1
}

case "$MODE" in
    stop)
        stop_server ;;
    status)
        do_status ;;
    restart)
        stop_server
        trap on_exit_during_start EXIT
        trap on_start_interrupt INT TERM
        start_server
        START_COMPLETED=1
        trap - EXIT INT TERM ;;
    start)
        trap on_exit_during_start EXIT
        trap on_start_interrupt INT TERM
        start_server
        START_COMPLETED=1
        if [ "${#RUN_CMD[@]}" -gt 0 ]; then
            trap 'stop_server' EXIT
            set +e
            "${RUN_CMD[@]}"
            RUN_STATUS=$?
            set -e
            trap - EXIT
            stop_server
            exit "$RUN_STATUS"
        fi
        trap - EXIT INT TERM ;;
esac
