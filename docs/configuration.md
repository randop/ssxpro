<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:b502c95b7bbbe5b2dc479b00d336100bc6a2eba03502a7108acc0f79320a1304 -->

# Configuration

Both programs deserialize YAML into strict, typed structures. Unknown keys and wrong types are errors; all omitted keys receive the defaults shown below. Range and cross-field errors identify the YAML key and line. Parser errors include the YAML parser's line and column.

`ssxd` reads `/etc/ssx/ssxd.yaml` by default. `--config PATH` selects another file. `ssxd --check-config` validates YAML, requires the configuration and host-key files to be regular files owned by root with exact mode `0600`, opens them with `openat2(RESOLVE_NO_SYMLINKS)`, then reports kernel feature checks. The host key is exactly 32 raw Ed25519 seed bytes. `--yes-I-know-permission-risks-go-ahead-please` skips owner and mode checks for the configuration, host key, and both authorized_keys sources; use it only for unprivileged development.

```yaml
listen: "0.0.0.0:22"
host_key: /etc/ssx/host_ed25519
# PTY stream compression, enforced by the server:
#   off      - no compression
#   fast     - LZ4, optimized for low CPU utilization
#   standard - Snappy
#   high     - Zstd level 19
compression: off
workers: 1 # Example; omitted workers defaults to the number of available CPUs
io:
  ring_entries: 4096
  recv_buffers: 2048
  buffer_size: 2048
  hugepages: true
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
  idle_timeout_secs: 600
  keep_alive_interval_secs: 15
  max_connections: 4096
  max_datagram_size: 1200
  retry: true
proto:
  max_control_frame_bytes: 4096
  hello_grace_secs: 5
  auth_timeout_secs: 30
auth:
  server_authorized_keys: /etc/ssx/authorized_keys
  authorized_keys: authorized_keys
  max_attempts: 1
  allow_root: false
session:
  login_grace_secs: 10
  max_sessions: 1024
  max_rows: 500
  max_columns: 500
  shell_path: /bin/sh
log:
  level: info
  json: false
```

`ssx` reads `~/.ssx/config.yaml` by default, expanding the home directory from `$HOME`. If that file does not exist, built-in defaults are used; without a config file the target must include an explicit port (`USER@HOST:PORT`). It accepts `--config PATH` (which must exist) and `--check-config`.

```yaml
hosts:
  production:
    host: shell.example.net
    port: 22
    identity: /home/alice/.ssx/id_ed25519
identity: /home/alice/.ssx/id_ed25519
port: 22
connect_timeout_secs: 10
handshake_timeout_secs: 15
idle_timeout_secs: 600
server_alive_interval_secs: 15
server_alive_count_max: 6
known_hosts: /home/alice/.ssx/known_hosts
known_hosts_policy: ask
```

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:dd63097dae93d7fab181d23d2c94983e0f70671d580ab17d4764f8ec5df2755c -->

Client `known_hosts_policy` is `deny`, `ask` (default), or `approve`. `deny` rejects a host that is not already pinned; `ask` prints the server key fingerprint and prompts `Allow this host? (y/N)`, accepting only an explicit `y` or `yes`; `approve` saves an unknown host key without prompting. A changed host key is always a fatal error. Accepted keys are appended to the secure default `~/.ssx/known_hosts` (directory mode `0700`, file mode `0600`); a custom `known_hosts` path must already contain the pin. `--approve-host` automatically approves and saves an unknown host key for one connection, overriding the configured policy.

<!-- /coderabbit-ai-generated:v1 -->

The target is `USER@HOST[:PORT]` or a configured host alias. Bracket an IPv6 literal when supplying a port, for example `alice@[2001:db8::1]:2222`. A port in the target overrides an alias or config port; `--port` overrides both. Host aliases require a nonempty host. Alias fields inherit global port and identity when omitted.

## Idle timeouts and keepalives

QUIC closes an idle connection after the negotiated minimum of both peers' idle timeouts. `ssxd` uses `quic.idle_timeout_secs` (default 600 s) and the client uses `idle_timeout_secs` (default 600 s; `0` disables the idle timeout).

QUIC PING frames are the keepalive mechanism (there is no TCP keepalive in QUIC):

* `ssxd`: `quic.keep_alive_interval_secs` (default 15, `0` disables) sends a PING when a session has been quiet for a full interval, keeping NAT bindings and the connection alive.
* `ssx`: `server_alive_interval_secs` (default 15, `0` disables, SSH `ServerAliveInterval`) sends a PING when no packet has been received for a full interval. After `server_alive_count_max` (default 6, SSH `ServerAliveCountMax`) unanswered PINGs, the client disconnects with exit code 255 and `server did not answer N keepalives; disconnecting`.

## Compression

Compression is enforced by `ssxd` and applies only to the stream-4 PTY data. Control frames are never compressed. The client advertises which algorithms its build supports in `Hello`; the server selects its configured mode in `AuthChallenge`. If the client does not support the configured algorithm, the connection is rejected rather than silently downgraded.

| `compression` | Algorithm | Intended use |
|---|---|---|
| `off` (default) | none | lowest latency and zero added CPU |
| `fast` | LZ4 | low CPU utilization |
| `standard` | Snappy | balanced |
| `high` | Zstd level 19 | maximum ratio, highest CPU cost |

When enabled, each direction sends self-contained frames after the one-byte stream-4 open marker. A frame is `format:u8`, uncompressed length `u32be`, payload length `u32be`, then the payload. Stored blocks are used when compression would expand the data. Blocks are limited to 64 KiB uncompressed, so a peer cannot force unbounded allocations.

## `ssxd --check-config` exit codes

| Code | Meaning |
|---:|---|
| 0 | YAML, permissions, key-file checks, and requested kernel capabilities passed |
| 2 | Command-line usage error |
| 3 | Config parse/validation, file access, owner, mode, or file-type error |
| 4 | Required or explicitly configured kernel feature unavailable |

Configured opt-in features fail closed. The probe prints `PASS` or `FAIL` for required and requested features, and `SKIP` when an optional feature is disabled in config. It does not silently disable an unsupported requested option.

Public keys are checked in two places, in order:

1. `auth.server_authorized_keys`: an absolute path (default `/etc/ssx/authorized_keys`). A missing file is skipped; an existing file must be a regular file owned by the monitor's user (root in production) with exact mode `0600`. A key listed here authorizes that key for any local account, subject to `allow_root` and the account shell policy, so treat the file as root-only.
2. `~USER/.ssx/<auth.authorized_keys>` (default `authorized_keys`): the per-user file, read only when the server-wide list did not match. Home, `.ssx`, and key-file ownership and modes are checked before reading. The permission-risk override flag skips these checks for unprivileged development.

Each non-comment line in either file is `ed25519 BASE64_KEY [comment]`; any option or unknown token rejects the line.


<!-- /coderabbit-ai-generated:v1 -->