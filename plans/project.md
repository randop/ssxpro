# ssxpro — P-RAN-11

Status: In progress (2026-11-12) — M0–M3 complete; M5 functional end-to-end including server-enforced PTY compression; M4, M6, M7 partial; M8/M9 foundations only; M10 backlog; M11 docs partial.

## Overview

**ssxpro** is a minimal, remote-shell-only server and client that run over **QUIC** on **UDP/22**, written in **Rust**. It is a native protocol, not SSH-compatible. OpenSSH is used as a reference for semantics only (authorized_keys, strict modes, login and PTY setup order).

* Server binary: `ssxd`
* Client binary: `ssx`
* TLS and QUIC: `quiche` on BoringSSL (single encryption layer)
* I/O: **io_uring only**, with no epoll or other fallback. The kernel baseline is enforced at startup by a capability probe.
* Config: YAML, with `deny_unknown_fields` and fail-closed validation
* Scope: public-key auth, one PTY login shell per connection, resize, signals and exit status. No SFTP, exec, forwarding or password auth.

## Progress snapshot (2026-11-12)

**Working end to end.** `ssx` and `ssxd` complete a QUIC handshake (ALPN `ssxpro/1`) with Retry, pin the Ed25519 host SPKI, authenticate with a signed nonce, open a broker-created PTY login shell, carry interactive input/output over stream 4, and report the remote exit status. The workspace is at version `0.1.1`. Verified on the local dev host with `tests/ssx_e2e.py`:

* A. shell round-trip: login, command output, exit `0`
* B. remote exit status: `exit 7` → client exit `7`
* C. authentication rejection (unauthorized key): exit `255`
* D. host-key mismatch (wrong pinned SPKI): exit `255`, loud warning, auth never attempted
* E. idle keepalive: the session survives a quiet period longer than the idle timeout
* F. compression negotiation: the server-selected mode reaches the client, or `off` leaves stream 4 unframed
* G. bulk compression data: multi-frame server output and client input round-trip through every configured mode

**Server-enforced PTY compression (v0.1.1).** `ssxd.yaml` now has `compression: off|fast|standard|high`: `off` is raw stream-4 data, `fast` is LZ4, `standard` is Snappy, and `high` is Zstd level 19. The client advertises every supported algorithm in `Hello` feature bits; the server selects its configured mode in `AuthChallenge` and fails closed if the client does not advertise it. Compressed data uses bounded frames (`format`, uncompressed length, payload length) with stored-block fallback; control frames stay uncompressed. `tests/compression_e2e.sh` runs the full e2e suite against all four modes.

**Verified commands:** `cargo build --workspace --locked`, `cargo test --workspace --locked` (61 passed, 2 ignored), `cargo clippy --workspace --all-targets`, `cargo fmt --all -- --check`, `scripts/licenses.sh --check` — clean; `tests/compression_e2e.sh` — 7/7 scenarios in each of `off`, `fast`, `standard` and `high`.

**Bugs fixed during the M5 bring-up:**

* Client did not advertise Ed25519 in its BoringSSL verify signature algorithms → server handshake failed with `NO_COMMON_SIGNATURE_ALGORITHMS`.
* Client control phase queued Hello/AuthRequest but never flushed or received packets.
* Client gated the first stream-4 send on `stream_capacity(4)`, which errors until the stream exists → the stream was never opened.
* Server treated short-header (1-RTT) packets as Version Negotiation because quiche reports `version == 0` for them.
* Restricted rings denied `IORING_REGISTER_FILES_UPDATE` after enable; register-op restriction now allowlists it.
* Monitor seccomp allowlist lacked `statx`, so Rust `fs::metadata`/NSS group resolution failed with `EPERM` and rejected valid logins.

**Open gaps and deviations (must be resolved before release):**

* The ring runtime falls back to direct `sendmsg`/`recvmsg`/`read`/`write` when unprivileged io_uring submission is restricted (`SSXPRO_USE_IO_URING=1` opts back in). The io_uring-only rule is not yet enforced on every path.
* The local dev host runs Linux 6.8 (below the 6.12 baseline) without Landlock. The PTY pump warns and continues with seccomp only; a fail-closed baseline probe is still required.
* Unprivileged dev mode (`--yes-I-know-permission-risks-go-ahead-please`, broker already running as the target account) exists for local testing; production remains root plus strict permissions.
* The GitHub CI workflow was removed from the tree. `fmt`/`clippy`/`test`/`audit`/`deny` run locally through `scripts/cargo-pinned.sh`; the kernel matrix job is only documented in `docs/ci-kernels.md`.
* Compression added one byte to the `AuthChallenge` payload (now 33 bytes) while the protocol version remains `1`. Version `0.1.0` and `0.1.1` peers therefore do not interoperate; the mismatch fails closed, but a protocol-version decision is still required before release.

## Architecture

* `ssxd` monitor (root, own ring): owns the host key, verifies auth signatures, runs getpwnam/policy/authorized_keys, and does openpty/fork/exec. It passes PTY master fds to workers over `SCM_RIGHTS`.
* `ssxd` workers (unprivileged, one thread per core, one ring and one `SO_REUSEPORT` UDP socket each): run quiche, the sans-IO protocol state machine and the PTY pumps. A ring-restriction allowlist, seccomp and Landlock limit what a compromised worker can do.
* `ssx` client: a single ring that drives the TTY, UDP, signals and timers.

## Crates

`ssxpro-proto` (sans-IO), `ssxpro-compression` (bounded PTY block codecs), `ssxpro-crypto`, `ssxpro-io` (ring runtime), `ssxpro-server`, `ssxpro-client`.

## Milestones (one issue each)

M0 spec and scaffold — **Done**; M1 config — **Done**; M2 crypto and keys — **Done** (host-key `memfd_secret` deferred); M3 proto — **Done** (property/fuzz-CI items open); M4 ring runtime — **In progress**; M5 end-to-end — **In progress** (functional including compression, verification gaps); M6 monitor and PTY — **In progress**; M7 client UX — **In progress**; M8 multi-worker and steering — **In progress** (foundations only); M9 hardening — **In progress** (partial layers); M10 performance — **Backlog**; M11 packaging and docs — **Backlog** (docs partial).

**Assisted By:** Anthropic Claude Sonnet 5.5

---

# Issues

## RAN-188 — M0: Spec, workspace scaffold, CI, kernel baseline

Status: Done (CI workflow files removed from the tree; local checks green)
Priority: No priority

## Goal

Write the spec before the code, set up the workspace, and lock down the build and kernel baselines.

## Scope

* Write `SPEC.md`: wire format, both state machines (`Hello → Auth → Open → Running → Exit`), error codes, limits and the threat model.
* Cargo workspace with these crates: `ssxpro-proto` (sans-IO), `ssxpro-crypto`, `ssxpro-io`, `ssxpro-server` (bin `ssxd`), `ssxpro-client` (bin `ssx`).
* CI: `fmt`, `clippy -D warnings`, `cargo-audit`, `cargo-deny`, and a `cargo-fuzz` skeleton. Add a kernel matrix job (6.12 LTS plus the latest stable).
* Vendor and pin BoringSSL (a commit hash), and build quiche against it.
* Document the baseline: **Linux 6.12 LTS or newer**, with a feature-to-kernel-version table for every io_uring and Linux feature used.

## Spikes (answer in the spec)

1. Does quiche expose TLS key export (`SSL_export_keying_material`) so auth can bind to the TLS session? If not, use the nonce plus SPKI-hash fallback.
2. Verify each feature-to-kernel-version entry against kernel docs and source (this plan's table is from memory).
3. Can `READ_MULTISHOT` with buffer select run on a PTY master as expected?

## Progress

* `SPEC.md`, the seven-crate workspace (including `ssxpro-compression`), `ssxd`/`ssx` binaries, `deny.toml`, `rustfmt.toml`, config examples, `scripts/cargo-pinned.sh` and `scripts/check-kernel-version.sh` are in the tree.
* Spike answers are recorded in `SPEC.md`: no TLS exporter on quiche's public connection API (nonce + SPKI binding for v1), feature-to-version audit, and the PTY multishot read deferred to an M6 probe.
* BoringSSL/quiche pins and the update procedure are in `docs/dependencies.md` (quiche `0.30.0`, BoringSSL commit `44b3df6f03d85c901767250329c571db405122d5` via `boring-sys` `4.22.0`).
* Kernel matrix runners are documented in `docs/ci-kernels.md`; the workflow file that used them is no longer in the tree.
* Fuzz skeleton with five targets exists under `fuzz/` (config, key files, proto codec/state, monitor IPC).

## Acceptance criteria

- [ ] `SPEC.md` merged and reviewed — merged; independent security review still tracked by RAN-200
- [ ] `cargo build` and CI green on an empty workspace; both binaries named `ssxd` and `ssx` — workspace builds and both binaries are named correctly; tests/clippy green locally; GitHub workflow absent
- [x] Spike answers recorded in the spec
- [x] BoringSSL pin documented, with an update procedure

**Assisted By:** Anthropic Claude Sonnet 5.5

---

## RAN-189 — M1: YAML config for ssxd and ssx, --check-config with kernel probe

Status: Done
Priority: No priority

## Goal

Typed, validated YAML config for `ssxd` and `ssx`. Fail closed.

## Scope

`ssxd` (`/etc/ssx/ssxd.yaml`): `listen`, `host_key`, `compression`, `workers`, `io`, `quic`, `proto`, `auth`, `session`, `log`.

```yaml
io:
  ring_entries: 4096
  recv_buffers: 2048
  buffer_size: 2048          # sized for GRO segments
  hugepages: true            # ring memory + registered buffers
  gro: true
  gso: true
  zerocopy_send: false
  zerocopy_min_bytes: 16384
  sqpoll: false
  sqpoll_idle_ms: 2
  napi_busy_poll_us: 0
  txtime_pacing: false       # SO_TXTIME + fq
  pin_cpus: true
  restrict_ring: true
```

`ssx` (`~/.ssx/config.yaml`): host aliases, identity, port, timeouts, `known_hosts` policy.

* `deny_unknown_fields` everywhere, and defaults for every optional key.
* `ssxd --check-config` validates the file, checks that key and file permissions are 0600 and root-owned, and then **runs the kernel capability probe**, reporting pass or fail per feature.
* An opt-in feature that is requested but unsupported by the kernel is a **hard error**, never a silent downgrade.

## Progress

* Configuration paths: `ssxd` reads `/etc/ssx/ssxd.yaml` and `ssx` reads `~/.ssx/config.yaml`; per-user keys, `authorized_keys`, and `known_hosts` live under `~/.ssx` (renamed from `/etc/ssxpro` and `~/.ssxpro`).
* Both config types parse strictly with defaults; unknown keys, wrong types and range errors report the YAML key and source line (unit tests cover each case).
* The server `compression` enum (`off`, `fast`, `standard`, `high`) defaults to `off`; invalid values are rejected with line-accurate errors and all documented modes are covered by tests.
* `ssxd --check-config` runs the kernel probe and reports PASS/FAIL/SKIP per feature; exit codes are documented in `docs/configuration.md` and covered by tests (`masked_requested_feature_is_a_hard_failure`, CLI usage/config exit codes).
* Config, host-key, and authorized_keys reads use `openat2` with `RESOLVE_NO_SYMLINKS`; `--yes-I-know-permission-risks-go-ahead-please` exists for unprivileged dev runs only and skips owner/mode checks for all of them.
* `config/ssxd.example.yaml` and `config/ssx.example.yaml` are complete examples; `features:` gates the optional server features.
* Fuzz target `fuzz/fuzz_targets/config_yaml.rs` covers both parsers.

## Acceptance criteria

- [x] Unknown keys, bad types and out-of-range values are rejected with line-accurate errors
- [x] Permission checks use `openat2` with `RESOLVE_NO_SYMLINKS`
- [x] `--check-config` exit codes are documented and tested, including a masked-feature test
- [x] Fuzz target for the config parser

**Assisted By:** Anthropic Claude Sonnet 5.5

---

## RAN-190 — M2: Crypto wrappers, keygen, authorized_keys and known_hosts, strict modes

Status: Done (`memfd_secret` host-key storage deferred)
Priority: No priority

## Goal

A tiny crypto layer over BoringSSL, plus key and trust-file formats.

## Scope

* `ssxpro-crypto`: Ed25519 sign and verify, SHA-256, RNG (`getrandom`), constant-time compare. Nothing else. Known-answer tests for each primitive.
* `ssx keygen` writes `~/.ssx/id_ed25519` (0600) and `.pub`. `ssx fingerprint` prints an SPKI SHA-256 fingerprint.
* Server key sources, checked in order: `auth.server_authorized_keys` (absolute, default `/etc/ssx/authorized_keys`, root-owned 0600; a missing file is skipped), then `~USER/.ssx/<auth.authorized_keys>` (default `authorized_keys`). Each line is `ed25519 <base64-32-byte-key> comment`. **Any option or unknown token rejects the line.**
* Client `known_hosts` at `~/.ssx/known_hosts`: `host:port spki-sha256 <b64>`. A mismatch is a hard failure with a loud warning.
* Strict-modes checks via `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`: owner and mode of the home dir, `.ssx` and the file.
* Host key held by the monitor in `memfd_secret` memory where available (verify availability at startup; document it if this is opt-in on the target kernel).
* v1.1: passphrase-protected keys (scrypt plus AEAD).

## Progress

* Ed25519 sign/verify, SHA-256, OS RNG and constant-time compare are implemented over BoringSSL; `ed25519_rfc8032_vector_one` and `sha256_known_answer` are the KATs.
* `ssx keygen` / `ssx fingerprint` and the strict-mode user-file readers are implemented; SPKI fingerprints are used for both pinning and auth binding.
* `authorized_keys` and `known_hosts` parsers reject malformed, option-bearing and oversize lines; fuzz target `key_files.rs` exists.
* Login authorization checks the server-wide `auth.server_authorized_keys` file first and falls back to the per-user `~USER/.ssx/<auth.authorized_keys>`; the ordering, strict modes, and missing-file skip are unit-tested.
* Strict-mode handling opens home and `.ssx` with `openat2` and the strict resolve flags; the unit test covers wrong mode and symlink escape. Wrong-owner and group-writable cases are not yet exercised.
* `memfd_secret` is not used yet; the host seed is zeroized but lives in process memory.

## Acceptance criteria

- [x] KATs pass against published Ed25519 and SHA-256 vectors
- [x] Parsers reject malformed, option-bearing and oversize lines; fuzz targets exist
- [ ] Strict-modes tests cover symlink escape, wrong owner and group- or world-writable cases — symlink and wrong mode covered; wrong owner and group-writable cases still open

**Assisted By:** Anthropic Claude Sonnet 5.5

---

## RAN-191 — M3: ssxpro-proto: wire format, codec and state machines (sans-IO)

Status: Done (property tests and fuzz-with-sanitizers CI still open)
Priority: No priority

## Goal

The sans-IO wire protocol for both roles. No sockets, no allocation on the hot path, fully fuzzable.

## Scope

* ALPN `ssxpro/1`. Stream 0 is the control stream (high priority). Stream 4 is the PTY data stream; with compression `off` it is raw bytes, otherwise it carries bounded compressed frames selected by the server. QUIC flow control does the work in both cases.
* Control frames: varint type, length-prefixed, bounded fields, **max 4 KiB**.
  * `Hello{version, features}`
  * `AuthChallenge{server_nonce, compression}`
  * `AuthRequest{user, pubkey, client_nonce, sig}`
  * `AuthOk` / `AuthFail{reason_class}`
  * `OpenShell{term, rows, cols}`
  * `Resize{rows, cols}`
  * `Signal{HUP|INT|TERM|...}` (small allowlist)
  * `Exit{status | signal}`
  * `Close{code}`
* Strict state machines for client and server (`feed(bytes) -> events`, `poll_output`). Any unknown type, out-of-order message or oversize frame closes the connection with an error code.
* Auth signature input: `"ssxpro-auth-v1" || server_nonce || client_nonce || server_spki_hash || user || pubkey`. If the TLS exporter is available (see the M0 spike), bind to it instead.
* Session end: `Exit` on control, then FIN on the data stream after draining.

## Progress

* Codec, both state machines, auth binding, broker frames and monitor frames are implemented with no crate dependencies (no I/O, no async).
* Round-trip, fragmented-frame decode, noncanonical/oversize rejection and strict state-machine tests pass; `auth_binding_matches_spec_field_order` pins the signed byte order.
* Fuzz targets `proto_codec.rs` and `proto_state.rs` exist, plus `monitor_ipc.rs` for the IPC decoders.
* Stream 4 is opened with a single 0x00 marker byte (decided during M5 bring-up). The marker is transport-level, so the control-frame codec is unchanged; `SPEC.md` documents it in the wire format and both state machines.
* Compression negotiation uses `Hello` feature bits 0–2 (LZ4, Snappy, Zstd); `AuthChallenge` carries the server-selected algorithm and unknown feature bits or unsupported selections fail closed. `SPEC.md` documents the algorithm IDs and frame layout.

## Acceptance criteria

- [ ] Encode/decode round-trip and property tests — round-trip covered by unit tests; no property-test harness yet
- [ ] Fuzz targets for the codec and both state machines, run with sanitizers in CI — targets exist; CI execution missing
- [x] Negative tests: replayed, reordered, truncated and oversize frames
- [x] Compression feature-bit negotiation and bounded frame codec covered by tests
- [x] The crate has no I/O or async dependencies

**Assisted By:** Anthropic Claude Sonnet 5.5

---

## RAN-192 — M4: ssxpro-io: io_uring-only runtime (probe, rings, buffers, UDP GRO/GSO, timers)

Status: In progress
Priority: No priority

## Goal

`ssxpro-io`: a concrete io_uring runtime that uses the kernel's modern features, with **no epoll and no fallback path**.

## Scope

**Startup probe (fail fast).** `IORING_REGISTER_PROBE` plus feature flags. Any missing required opcode or flag prints the exact feature and exits non-zero.

**Ring setup (per worker thread):**

* `SINGLE_ISSUER | DEFER_TASKRUN | COOP_TASKRUN | NO_SQARRAY`, with `CLAMP`
* `REGISTERED_FD_ONLY` plus a registered ring fd
* `NO_MMAP`: ring memory in our own **huge pages** (NUMA-local)
* `REGISTER_IOWQ_MAX_WORKERS` set to bound the kernel's async worker pool
* `REGISTER_RESTRICTIONS` so only an allowlisted set of opcodes can be submitted (recvmsg, sendmsg, send_zc, sendmsg_zc, read, write, timeout, poll, cancel, msg_ring)

**Resources:**

* Direct descriptors: UDP, PTY master, IPC and signal fds all live in the registered file table, with no fd-table lookups on the hot path
* Registered fixed buffers backed by huge pages
* Ring-mapped provided-buffer rings with **incremental consumption** (`IOU_PBUF_RING_INC`), sized for GRO

**UDP receive:** multishot `RECVMSG` + provided buffers + `UDP_GRO`. The segment size comes from the cmsg.

**UDP send:** one `SENDMSG` per flow batch with `UDP_SEGMENT` (GSO). `SENDMSG_ZC` / `SEND_ZC` above a size threshold, with strict notification-CQE tracking so a buffer is never reused early. Optional `SO_TXTIME` pacing from quiche's send time.

**Timers:** one `TIMEOUT` per worker, retargeted with `TIMEOUT_UPDATE`.

**Wait strategy:** one `io_uring_enter` per tick using `IORING_ENTER_EXT_ARG_REG` with a **minimum-wait timeout** to batch CQEs under load while keeping latency low when idle. Use `IOSQE_CQE_SKIP_SUCCESS` on fire-and-forget ops, and linked SQEs where ordering is needed.

**Optional, opt-in:** NAPI busy-poll registration (`IORING_REGISTER_NAPI`), `SQPOLL` with idle timeout, `SO_BUSY_POLL` / `SO_PREFER_BUSY_POLL`.

**Robustness:** CQ overflow handling, `-ENOBUFS` when the buffer ring is exhausted, short reads and writes, and cancel-on-close of multishot ops.

## Progress

* Implemented: full startup probe with PASS/FAIL/SKIP per feature; ring setup with `CLAMP | COOP_TASKRUN | SINGLE_ISSUER | DEFER_TASKRUN | NO_SQARRAY`; `R_DISABLED` + `REGISTER_RESTRICTIONS` + `REGISTER_ENABLE_RINGS`; `REGISTER_IOWQ_MAX_WORKERS`; sparse fixed-file table with register/unregister; `IORING_OP_TIMEOUT` wait helper; `UdpEndpoint` with `UDP_GRO`, `UDP_SEGMENT` send helper and fixed-file registration.
* Fixed during M5: a restricted, enabled ring denies every `io_uring_register` opcode that is not allowlisted. `IORING_REGISTER_FILES_UPDATE` is now in the register-op allowlist, so lazy PTY/terminal descriptor registration works.
* The M0 wait-strategy conflict is recorded in `SPEC.md`: `IORING_ENTER_EXT_ARG_REG` is 6.13 while the baseline is 6.12; it is not implemented yet.
* Not yet implemented: multishot `RECVMSG` + provided-buffer rings in the live path (`IOU_PBUF_RING_INC` is probed only), registered ring fd / `REGISTERED_FD_ONLY`, `NO_MMAP` + huge-page ring memory, zero-copy send usage, `SO_TXTIME` pacing, NAPI/`SQPOLL` use in the runtime, and the `EXT_ARG_REG` wait strategy.
* Dev-host accommodation: `UdpEndpoint` defaults to direct `sendmsg`/`recvmsg` when unprivileged io_uring submission is restricted (`SSXPRO_USE_IO_URING=1` opts back in). This is not the target runtime and must be removed or restricted before release.

## Acceptance criteria

- [ ] Loopback UDP echo benchmark with GRO/GSO, with the numbers recorded
- [x] Probe test: masking a feature produces a clear error and a non-zero exit
- [ ] Restriction test: a forbidden opcode (e.g. `OPENAT`) is rejected by the ring — restrictions are registered; no forbidden-opcode submission test yet
- [ ] Test builds deny `epoll_*` via seccomp so any accidental fallback crashes loudly
- [ ] Zero-copy completion-ordering tests

**Assisted By:** Anthropic Claude Sonnet 5.5

---

## RAN-193 — M5: End-to-end on io_uring: handshake, SPKI pinning, auth, echo

Status: In progress (functional end-to-end path and compression matrix done; verification items open)
Priority: No priority

## Goal

The first working client and server on the ring runtime: handshake, pinning, auth and an echo over the data stream. One worker only.

## Scope

* quiche on BoringSSL inside the ring loops of `ssxd` and `ssx` (sans-IO quiche, fed by `ssxpro-io`).
* Self-signed cert generated from the Ed25519 host key. Identity is the **SPKI SHA-256 fingerprint**, so cert regeneration doesn't matter.
* Client sets `verify_peer(false)` and compares the SPKI fingerprint against `known_hosts` **before sending anything sensitive**. First connect prompts `(Y/n)`, or `--approve-host` saves the key without prompting.
* Auth per the M3 spec (exporter binding if available, else nonce plus SPKI hash). Signature verification is a stub call to the monitor interface in this milestone.
* 0-RTT disabled, Retry required, hello grace timer, max control frame size enforced.
* Echo over stream 4 to prove the data path.

## Progress

* The full path works locally and is covered by `tests/ssx_e2e.py` (PTY-driven): handshake with Retry, SPKI pin, challenge/response auth verified by the monitor, PTY login shell, stream-4 input/output, resize/signal plumbing, and remote exit status.
* `ssxd` serves multiple sessions via a forked monitor (signing + auth) and a forked session broker (PTY), and drains cleanly on SIGTERM.
* Idle sessions survive AFK: the client idle timeout was wrongly bound to `handshake_timeout_secs` (15 s). It is now `idle_timeout_secs` (default 600 s), and QUIC PING keepalives (`server_alive_interval_secs`/`server_alive_count_max` client-side, `quic.keep_alive_interval_secs` server-side) keep quiet sessions alive. Covered by `tests/ssx_e2e.py` scenario `E-idle-keepalive`.
* Server-enforced PTY compression works end to end: the server selects `off`, LZ4, Snappy or Zstd level 19 from its config, negotiates it through `Hello`/`AuthChallenge`, and both directions use bounded stream-4 frames when enabled. `tests/compression_e2e.sh` runs scenarios F (negotiation) and G (multi-frame bulk data) plus the original suite under all four modes; 7/7 pass per mode.
* Fixed to reach this state: Ed25519 client sigalgs, control-phase flush/receive, stream-4 open, short-header dispatch, register-op restrictions, monitor `statx` seccomp allowance.
* Beyond the milestone scope, sessions are real PTY login shells (M6 work), not just an echo.
* The data stream opens with a client 0x00 marker, so the initial prompt arrives without a keystroke; scenario A waits for the shell banner with no input.
* Remaining: idle-grace closure is implemented but untested; replay rejection is enforced by a one-time nonce but has no dedicated test; no `strace` verification that `epoll_*` is absent.

## Acceptance criteria

- [x] Client connects, pins, authenticates and echoes bytes both ways — verified as a full PTY round-trip by `tests/ssx_e2e.py` scenarios A/B
- [x] Server-selected compression modes are negotiated and exercised end to end — all four modes pass the compression matrix
- [ ] Wrong fingerprint, wrong key and replayed auth are all rejected — wrong fingerprint (D) and wrong key (C) verified; replay rejection enforced by one-time nonce, untested
- [ ] An idle connection that never opens its streams is closed after the grace timer — implemented, untested
- [ ] No `epoll_*` syscalls in an `strace` of either binary — no epoll in the code; not measured

**Assisted By:** Anthropic Claude Sonnet 5.5

---

## RAN-194 — M6: Monitor, IPC and PTY sessions (pidfd, cgroup v2, direct descriptors)

Status: In progress
Priority: No priority

## Goal

The privileged monitor, the IPC to workers, and the PTY shell session lifecycle, using Linux process primitives and the ring wherever they apply.

## Scope

**Monitor (root, its own ring, single-threaded, no network I/O):**

* IPC: `SOCK_SEQPACKET` socketpair per worker, `RECVMSG` with `SCM_RIGHTS` on the ring, compact binary protocol with fuzzed parser
* Verifies the auth signature itself, so a compromised worker can't forge a login
* Policy: `getpwnam`, allow users/groups, `permit_root`, valid shell from `/etc/shells` (not `nologin`/`false`), `authorized_keys` with strict modes via `openat2` and ring ops
* NSS calls (`getpwnam`, `initgroups`) run on a **dedicated thread with a deadline**, so a slow LDAP/sssd never stalls the ring
* Login grace and max-attempt enforcement

**Spawn:**

* `openpty` with `TIOCGPTPEER` for the slave
* `clone3` with `CLONE_PIDFD | CLONE_INTO_CGROUP`: each session in its own **cgroup v2** (limits for pids and memory, killed on teardown with `cgroup.kill`)
* Child setup order: `setsid`, `TIOCSCTTY`, `initgroups`, `setgid`, `setuid` (verify root can't be regained), `chdir($HOME)`, clear env, set `HOME USER LOGNAME SHELL PATH TERM`, exec with login-shell argv0
* `PR_SET_PDEATHSIG`, `PR_SET_CHILD_SUBREAPER` in the monitor
* PTY master fd goes to the worker via `SCM_RIGHTS` and is installed as a **direct descriptor** in the worker's ring

**Worker PTY pump:**

* `READ_MULTISHOT` with provided buffers on the PTY master, writes from fixed buffers
* Explicit backpressure: stop the PTY read when the QUIC stream is blocked, resume on writable
* `Resize` via `TIOCSWINSZ`, `Signal` via `pidfd_send_signal` to the process group

**Exit:** child exit observed with `IORING_OP_WAITID` on the pidfd (or `POLL_ADD` plus `waitid`). `Exit` is sent on the control stream, then the data stream gets FIN after drain. Disconnect sends SIGHUP to the foreground process group and `cgroup.kill` as backstop.

## Progress

* Implemented: a forked monitor that owns the host key, verifies Ed25519 signatures, resolves NSS on a dedicated thread with a 3 s deadline, checks policy and strict-mode `authorized_keys`, and mints one-time session tokens; a forked broker that owns `openpty`/`TIOCGPTPEER`, spawns the login shell (`setsid`, `TIOCSCTTY`, `setgroups`/`setresgid`/`setresuid`, `chdir`, cleared env, login argv0, `PR_SET_PDEATHSIG`), observes exit with `waitid(P_PIDFD)` and cleans up process groups; `SOCK_SEQPACKET` worker/broker IPC with bounded frames and `SCM_RIGHTS` for the PTY master; PTY master installed as a registered direct descriptor; `Resize` via `TIOCSWINSZ`; `Signal` via process-group kill; `Exit` then stream-4 FIN after drain.
* Verified end to end: interactive shell login and command round-trip, exit status 0 and 7, session teardown on client disconnect, no stuck sessions across repeated runs.
* Unprivileged dev mode: when the broker already runs as the target account (`--yes-I-know-permission-risks-go-ahead-please`), privilege-drop syscalls are skipped; any other unprivileged identity mismatch fails closed.
* Not yet implemented: `clone3` + `CLONE_INTO_CGROUP` and cgroup v2 limits/`cgroup.kill`, `PR_SET_CHILD_SUBREAPER`, `READ_MULTISHOT` (the pump uses single-shot `READ`), `pidfd_send_signal`, in-ring `WAITID`, and monitor ring ops (the monitor uses blocking reads on its sockets).

## Acceptance criteria

- [ ] Login, interactive shell, vim and tmux work; window resize propagates — login shell and command output verified; vim/tmux/resize untested
- [ ] Exit status and signal exit are reported correctly — exit status verified (0 and 7); signal mapping implemented but untested
- [ ] Killing a worker or dropping the client leaves no orphaned processes — drop path exercised, orphan check missing
- [ ] A fork bomb in a session is contained by the cgroup limits — cgroups not implemented
- [ ] Negative tests: disallowed user, root, bad key perms, nologin shell — auth rejection and strict-mode units exist; the rest untested

**Assisted By:** Anthropic Claude Sonnet 5.5

---

## RAN-195 — M7: ssx client UX: single-ring loop, raw-mode guard, escapes, known_hosts

Status: In progress
Priority: No priority

## Goal

The `ssx` client: one ring, low latency, a robust terminal experience.

## Scope

* CLI: `ssx [-i key] [-p port] [--approve-host] [-v] user@host[:port]`, plus subcommands `ssx keygen` and `ssx fingerprint`.
* **One ring** (`SINGLE_ISSUER | DEFER_TASKRUN`) driving everything:
  * TTY stdin `READ` (re-armed, small buffer, flushed immediately)
  * UDP multishot `RECVMSG`, `SENDMSG` (GSO when available)
  * `signalfd` `READ` for `SIGWINCH`/`SIGTERM`/`SIGHUP`
  * stdout `WRITE`
  * `TIMEOUT` for quiche timers
  * `IORING_OP_CONNECT` / `SOCKET` for address setup, with v4/v6 happy eyeballs and a handshake timeout
* Keystroke path: stdin CQE, quiche send, SQE, all within one tick with no intermediate queues. Low `max_ack_delay`.
* Terminal: raw mode via termios behind a guard that restores on **every** exit path (normal, panic hook, signalfd-handled signals). Initial size via `TIOCGWINSZ`, `Resize` on SIGWINCH, `TERM` passthrough. stdin must be a TTY in v1.
* Escapes (OpenSSH-style, only after a newline): `~.` disconnect, `~^Z` suspend, `~?` help.
* known_hosts prompt flow, a mismatch is a loud hard failure, clear message when UDP/22 looks blocked.
* Exit code is the remote shell's status. Transport or auth failure is 255. Idle timeout prints a message and exits 255.
* `~/.ssx/config.yaml` host aliases.

## Progress

* Implemented: the full CLI (target, `-i`, `-p`, `--approve-host`, `-v`, `--config`, `--check-config`, `keygen`, `fingerprint`), host aliases, `known_hosts` prompt/pin flow with a loud mismatch failure, raw mode with restore-on-drop and SIGTERM/SIGHUP handlers, resize via `SIGWINCH` + `TIOCGWINSZ` + `Resize`, OpenSSH-style escapes, and remote-exit-code propagation (verified: 0 and 7; failures exit 255).
* Not yet one ring: the client uses a main ring plus a stdin reader thread with its own ring, and falls back to direct syscalls where io_uring is restricted. There is no `signalfd` (handlers set atomic flags), no `IORING_OP_CONNECT`/`SOCKET` (std UDP socket + `quiche::connect`), and no single-tick keystroke path.
* Type-ahead typed before raw mode is flushed by `TCSAFLUSH`; fine for normal use, noted for the test harness.
* Not yet verified/measured: terminal restoration under kill/panic (pty-driven tests), the full escape matrix, resize/signal forwarding end to end, `strace` epoll check, and keystroke latency.

## Acceptance criteria

- [ ] Terminal is restored after kill -TERM, kill -HUP, panic and normal exit (pty-driven tests) — guard implemented; tests missing
- [ ] Escape sequence matrix passes — implemented with two unit tests; no full matrix
- [ ] Resize and signal forwarding work end to end
- [ ] p50/p99 keystroke latency measured and recorded (feeds M10)
- [ ] No `epoll_*` syscalls in an `strace` of `ssx`

**Assisted By:** Anthropic Claude Sonnet 5.5

---

## RAN-196 — M8: Multi-worker: SO_REUSEPORT, eBPF CID steering, MSG_RING, Retry, rate limits

Status: In progress (foundations only)
Priority: No priority

## Goal

Scale `ssxd` across cores with kernel-level steering, so each connection stays on one worker, one ring and one core, including across NAT rebinding and migration.

## Scope

* Workers are **threads of one unprivileged process** (the monitor is a separate root process). One ring, one `SO_REUSEPORT` UDP socket, one core per worker. Optional `SO_INCOMING_CPU` alignment.
* Server-chosen QUIC connection IDs encode the worker ID. An **eBPF** `sk_reuseport` **program** (via `aya`) steers packets by DCID, with the 4-tuple hash used only for initial packets (new connections).
* Cross-worker coordination with `IORING_OP_MSG_RING` between worker rings: graceful drain and shutdown, config reload notification, global connection-cap accounting. Workers do not share locks.
* CPU pinning and NUMA-local allocation of ring memory and buffers (hooks provided by M4).
* QUIC Retry (address validation) enabled by default, `max_connections` cap, per-source-IP rate limiting for handshakes and auth failures.
* Graceful shutdown: stop accepting, drain sessions, then exit. `sd_notify` readiness and stopping messages.

## Progress

* Already present (needed by M5): Retry with HMAC-bound tokens, per-source initial rate limiting, per-source auth-failure limiting, per-worker connection/session caps, `SO_REUSEPORT` bind path for multiple workers, CPU pinning, graceful drain with a deadline, and `sd_notify` READY/STOPPING.
* An eBPF `sk_reuseport` CID selector exists with a kernel-verification probe, but it is skipped for single-worker configs and has no steering test.
* Not implemented: worker-ID steering verification, `IORING_OP_MSG_RING` cross-worker coordination, NUMA-local memory hooks, NAT-rebinding test, and the flood/load acceptance tests.

## Acceptance criteria

- [ ] N workers show even load under many concurrent clients
- [ ] A client that changes source address (NAT rebinding, `tc` or netns test) keeps its connection on the same worker
- [ ] Handshake flood with Retry on does not exhaust memory or starve existing sessions
- [ ] Shutdown drains cleanly with no dropped sessions on `SIGTERM`
- [ ] BPF program is verified by the kernel and covered by a test that checks steering by DCID

**Assisted By:** Anthropic Claude Sonnet 5.5

---

## RAN-197 — M9: Hardening: ring restrictions, seccomp, Landlock, privilege separation

Status: In progress (partial layers already in the runtime)
Priority: No priority

## Goal

Shrink what a compromised pre-auth worker can do, using layered Linux mechanisms.

## Scope

**Layers on the worker (unprivileged, no root in the data path):**

1. **Dedicated unprivileged user**, empty chroot or mount namespace, no capabilities (except `CAP_NET_BIND_SERVICE` only if the bind happens in the worker; preferably the monitor binds UDP/22 and passes sockets).
2. **io_uring ring restrictions** (see M4): allowlisted opcodes only. This is the key control, because **seccomp does not filter operations submitted through the ring**.
3. **seccomp allowlist** on worker threads: `io_uring_enter`/`register`, memory and futex basics, `exit`. Applied after setup.
4. **Landlock** ruleset: no filesystem access after init, and network restrictions where the ABI supports it.
5. `PR_SET_NO_NEW_PRIVS`, and `PR_SET_DUMPABLE=0`.
6. **cgroup v2** and memcg limits per worker and per session; since io_uring memory is memcg-accounted on modern kernels, set sensible limits.

**Monitor:** minimal surface, no network I/O, `memfd_secret` for key material (where available), strict IPC parser (fuzzed), small seccomp allowlist for its own work.

**Service:** systemd unit with `NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet`, `RestrictAddressFamilies`, `SystemCallFilter`, `MemoryDenyWriteExecute` and friends. Document that **Docker's default seccomp profile blocks io_uring**, so running in a container needs an explicit profile.

**Tests:** forbidden-opcode and forbidden-syscall tests, escape attempts (file open, socket creation, ptrace) from a simulated compromised worker, IPC fuzzing, oversize and malformed frames at every layer.

## Progress

* Already implemented: io_uring restrictions on the server worker ring (with the register-op allowlist fix), `PR_SET_NO_NEW_PRIVS` + `PR_SET_DUMPABLE=0` on workers, a seccomp allowlist on the PTY pump thread, a monitor seccomp allowlist (including the NSS/`statx` needs), and a Landlock deny-all attempt for the PTY pump.
* Dev-host behavior: when Landlock is unavailable (`EOPNOTSUPP`/`ENOSYS`, e.g. Linux 6.8 without `CONFIG_SECURITY_LANDLOCK`), the pump prints a loud warning and continues with seccomp only. The 6.12 baseline expects Landlock; a fail-closed startup probe is still required.
* The monitor seccomp allowlist is portable across glibc and musl: musl's stdio/NSS path uses `open`, `readv`/`writev`, `stat`/`lstat`, and its nscd probe needs `socket()` to fail with `EAFNOSUPPORT` (not `EPERM`) so it falls back to the local files.
* Not implemented: dedicated unprivileged user/mount namespace for workers (they are threads of the server process today), cgroup/memcg limits, `memfd_secret` for key material, the systemd unit, and the escape/forbidden-syscall test harness.

## Acceptance criteria

- [ ] A worker test harness proves it cannot open files, create sockets, or submit non-allowlisted ring ops
- [ ] Monitor rejects a forged signature and a forged policy verdict coming from a worker
- [ ] systemd-analyze security score recorded, with a justification for any remaining exposure
- [ ] Documented threat model updated in `SPEC.md`

**Assisted By:** Anthropic Claude Sonnet 5.5

---

## RAN-198 — M10: Performance: baselines, benchmarks, tuning

Status: Backlog
Priority: No priority

## Goal

Measure, then tune. "Blazing fast" must be a number, not a feeling.

## Scope

**Baselines first** (record before setting targets): OpenSSH over TCP on the same hosts, and an `ssxd` build with every opt-in feature off.

**Metrics:**

* full handshakes per second per core
* p50/p99/p99.9 keystroke-echo latency added by the server and by the client
* bulk throughput per core (`cat /dev/zero | ssx`)
* CPU and memory per connection at 1k, 10k and 50k idle connections
* syscalls per second and per packet (`bpftrace`), context switches, cache misses (`perf`)

**Tuning levers (each A/B tested, kept only if it wins):**

* `SEND_ZC` / `SENDMSG_ZC` and the size threshold
* GSO and GRO segment sizes
* `SQPOLL` with idle timeout (CPU cost vs latency), and the minimum-wait timeout for CQE batching
* NAPI busy poll and `SO_PREFER_BUSY_POLL`
* huge-page ring and buffer memory
* `SO_TXTIME` pacing with the `fq` qdisc
* CPU pinning, IRQ affinity, NUMA placement
* congestion control (BBR2 vs CUBIC), QUIC flow-control windows, `max_ack_delay`
* send/receive socket buffer sizes
* evaluate `IORING_RECVSEND_BUNDLE` only if a stream-socket path exists (UDP/PTY paths may not benefit)

**Deliverables:** a repeatable benchmark harness (netns plus `tc netem` for loss/latency profiles), flamegraphs, a tuning guide, and numeric targets agreed after the baselines.

## Acceptance criteria

- [ ] Baseline and tuned results published in `docs/performance.md`
- [ ] Every enabled-by-default feature has a measured win; losing ones stay opt-in or are dropped
- [ ] Regression benchmark runs in CI nightly with a threshold alert

**Assisted By:** Anthropic Claude Sonnet 5.5

---

## RAN-199 — M11: Packaging, systemd unit, man pages and docs

Status: Backlog (some docs already exist)
Priority: No priority

## Goal

Ship it: reproducible builds, service integration and documentation for `ssxd` and `ssx`.

## Scope

* Release builds for `ssxd` and `ssx` (static where practical; decide musl vs glibc based on BoringSSL and quiche build results). Reproducible build notes and checksums.
* `ssxd.service` systemd unit (see M9 hardening options) with `Type=notify` and `sd_notify`, `LimitNOFILE`, and a documented sample `ssxd.yaml` and `~/.ssx/config.yaml`.
* Man pages: `ssx(1)`, `ssxd(8)`, `ssxd.yaml(5)`.
* README and docs:
  * quickstart (keygen, authorized_keys, first connect and pinning)
  * **kernel requirements** (Linux 6.12 LTS or newer, `kernel.io_uring_disabled` must permit use, container seccomp notes)
  * explicit statement of non-goals (no SSH compatibility, no SFTP, no forwarding, no password auth)
  * UDP/22 firewall guidance and how to change the port
  * operations guide: logs, metrics, reload, graceful shutdown
* Release checklist: security review sign-off, fuzz corpus run, benchmark report attached.

## Progress

* Already present: `config/ssxd.example.yaml`, `config/ssx.example.yaml`, `docs/configuration.md`, `docs/dependencies.md`, `docs/ci-kernels.md`, `tests/ssx_e2e.py` (the local end-to-end driver, which can serve as the basis for the quickstart walkthrough), and `tests/compression_e2e.sh` (the four-mode compression matrix). Compression configuration and wire framing are documented in `docs/configuration.md` and `SPEC.md`.
* Static release builds for `x86_64-unknown-linux-musl` work: `cargo build --release --target x86_64-unknown-linux-musl` produces fully static (non-PIE) `ssxd`/`ssx` via `.cargo/config.toml` and `scripts/musl-toolchain.cmake`; requires an `x86_64-linux-musl-gcc` cross toolchain on `PATH`. The glibc host build is unchanged. The static binaries previously passed the 5-scenario e2e suite; rerunning the new 7-scenario suite and compression matrix against the static build is still pending.
* Not started: reproducible-build notes and checksums, systemd unit, man pages, README, operations guide and the release checklist. `sd_notify` support itself is already implemented in `ssxd`.

## Acceptance criteria

- [ ] Clean-machine install and first login following only the README
- [ ] `ssxd --check-config` documented and referenced in the quickstart
- [ ] Release artifacts are built in CI with checksums

**Assisted By:** Anthropic Claude Sonnet 5.5

---

## RAN-200 — Gate: Independent security review before any public exposure

Status: Backlog
Priority: No priority

## Goal

The custom auth protocol and the privilege-separation design are the highest-risk parts of this project. No public exposure until an independent person has reviewed them.

## Scope

* Review of the `SPEC.md` auth protocol: signature input, session binding (TLS exporter or nonce plus SPKI fallback), replay and reflection resistance, downgrade resistance and error-class leakage.
* Review of the monitor and worker split: IPC protocol, what a compromised worker can ask the monitor to do, and the child setup path (`setsid` ... `setuid` ... `exec`).
* Review of the io_uring restriction set and the seccomp, Landlock and cgroup layers.
* Review of the pre-auth surface: Retry, grace timers, rate limits and parser bounds.
* Triage findings, fix, and re-test. Record the outcome in `docs/security-review.md`.

## Progress

* Not started. The gate stays open until the M5 verification gaps and the M4/M6/M9 hardening items above are closed.

## Acceptance criteria

- [ ] Reviewer identified, scope agreed and findings written up
- [ ] All high and critical findings fixed and re-verified before any release
- [ ] Fuzz corpora from M2, M3, M6 and M9 are run for a sustained period with no open crashes
- [ ] Gate is linked as a blocker for the M11 release checklist

**Assisted By:** Anthropic Claude Sonnet 5.5
