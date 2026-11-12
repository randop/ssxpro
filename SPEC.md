# ssxpro protocol and security specification

Status: M0 baseline (2026-11-04)  
Protocol version: 1  
ALPN: `ssxpro/1`  
Transport: QUIC over UDP, normally port 22. This is a new protocol and is not SSH.

## Goals and non-goals

ssxpro provides public-key authenticated interactive login to one PTY-backed login shell. It does not provide password authentication, arbitrary command execution, SFTP, forwarding, or SSH wire compatibility. The protocol separates authentication and session control from an unframed terminal byte stream.

## Wire format

QUIC provides confidentiality, integrity, peer transport authentication, stream ordering, and flow control. TLS 1.3 is carried inside QUIC by quiche/BoringSSL; there is no second encryption layer.

The client negotiates ALPN `ssxpro/1`. Stream 0 is the bidirectional control stream. Stream 4 is a bidirectional byte stream for PTY data. The client opens stream 4 immediately after `OpenShell` with a single 0x00 open marker; the server discards exactly that first byte. All remaining stream-4 bytes carry PTY data, either raw or in compression frames when the server selected a compression mode. QUIC flow control supplies backpressure. A stream 4 whose first byte is not 0x00, or a FIN before the marker, is a protocol error. All other stream IDs are forbidden in v1. The control stream is opened first and has priority over PTY data.

Control frames are `type` followed by `length` followed by `payload`. `type` is a QUIC varint; `length` is an unsigned big-endian 16-bit byte count. The payload is at most 4096 bytes. Integers in payloads are unsigned big-endian unless stated otherwise. Strings are UTF-8, nonempty where required, and contain no NUL. Decoders reject trailing bytes, invalid UTF-8, noncanonical/overflowing integer encodings, unknown message types, and lengths above the bound. A frame is not acted on until its full declared payload has arrived.

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:f27873c5831c54ba43fcfdd32b555f28208c18f69950dc9c0ba5902665da1380 -->

| Type | Direction | Payload |
|---|---|---|
| 0x00 `Hello` | client→server | version u16 (=1), feature bits u32 (unknown bits rejected); bits 0–2 advertise LZ4, Snappy and Zstd stream compression support |
| 0x01 `AuthChallenge` | server→client | 32-byte unpredictable server nonce, selected compression u8 (0=off, 1=LZ4, 2=Snappy, 3=Zstd) |
| 0x02 `AuthRequest` | client→server | username (u16 length + UTF-8), Ed25519 public key (32), client nonce (32), signature (64) |
| 0x03 `AuthOk` | server→client | empty |
| 0x04 `AuthFail` | server→client | reason class u8; classes are `denied`=1 and `temporarily_unavailable`=2 |
| 0x05 `OpenShell` | client→server | terminal name (u16 length + UTF-8, max 64), rows u16, columns u16 |
| 0x06 `Resize` | client→server | rows u16, columns u16 |
| 0x07 `Signal` | client→server | signal u8: HUP=1, INT=2, QUIT=3, TERM=4, KILL=5, TSTP=6, CONT=7, WINCH=8 |
| 0x08 `Exit` | server→client | kind u8 (status=0 or signal=1), value u8 |
| 0x09 `Close` | either | application code u16 |

Dimensions must be in 1..=4096. Terminal names are limited to 64 bytes. Username is limited to 256 bytes. Control message-specific exact payload lengths are mandatory. `Exit` status is 0..=255; signal values are native Linux signal numbers in 1..=64 (including signals outside the `Signal` control allowlist), as reported by `waitid`. These differ from control-message codes. Close codes are 0 normal, 1 protocol error, 2 authentication failed, 3 resource limit, 4 internal error. The peer receives only the coarse `AuthFail` class; details are logged locally by the monitor.

The server configuration is authoritative for stream compression. `off` leaves stream 4 as raw bytes. `fast` selects LZ4, `standard` selects Snappy, and `high` selects Zstd level 19. The client advertises every algorithm it supports in `Hello`; the server selects the configured algorithm in `AuthChallenge` and rejects a client that does not advertise it. There is no silent downgrade. When compression is enabled, both directions send frames after the 0x00 open marker: `format:u8` (0 stored, 1 compressed), uncompressed length `u32be`, payload length `u32be`, then the payload. Stored blocks are used when compression would expand a block. Uncompressed blocks are limited to 64 KiB and compressed payloads to 128 KiB, so decoding is bounded. A FIN must fall on a frame boundary.

## Client state machine

<!-- /coderabbit-ai-generated:v1 -->

`Hello → Auth → Open → Running → Exit`:

1. `Hello`: after QUIC handshake and ALPN validation, client sends exactly one `Hello`.
2. `Auth`: client accepts one `AuthChallenge`, selects an identity, and sends one `AuthRequest`. It accepts one `AuthOk` or `AuthFail`. No shell/data stream is opened before `AuthOk`.
3. `Open`: client sends one `OpenShell` and opens stream 4 with a single 0x00 open marker. It may send `Resize` or allowlisted `Signal` only after `OpenShell`.
4. `Running`: client forwards terminal bytes on stream 4 and accepts `Resize`-independent output bytes and one `Exit` on control.
5. `Exit`: client drains stream 4 to FIN, restores terminal state, then closes. A transport close at any earlier state is failure.

## Server state machine

`Hello → Auth → Open → Running → Exit`:

1. `Hello`: server accepts one supported `Hello` on stream 0 before a short hello deadline; it sends `AuthChallenge`.
2. `Auth`: server accepts one `AuthRequest`, verifies signature, principal policy and authorized key through the monitor, and sends exactly one `AuthOk` or `AuthFail`.
3. `Open`: after `AuthOk`, server accepts exactly one valid `OpenShell`, consumes the stream-4 open marker, creates one PTY/login shell, and starts sending PTY output on stream 4.
4. `Running`: server pumps PTY bytes with QUIC backpressure and applies only allowlisted resize/signal controls.
5. `Exit`: server sends `Exit`, drains output, then FINs stream 4. Either side may send `Close` to terminate. Disconnect triggers SIGHUP and session cleanup.

Any message out of order, duplicate singleton message, forbidden stream, malformed frame, or unsupported feature/version terminates the connection with `Close(1)` when possible, then transport close. Connections are never resumed or accepted with 0-RTT in v1.

## Authentication and session binding

The signature is Ed25519 over the exact concatenation:

```
"ssxpro-auth-v1" || server_nonce[32] || client_nonce[32] || server_spki_sha256[32] || username_utf8 || client_ed25519_public_key[32]
```

The username is length-delimited in the wire message; for the signature input it is its UTF-8 bytes. Both nonces are generated independently with the OS CSPRNG. A fresh server nonce is required for every authentication attempt. The monitor checks the signature and authorized key. The known-hosts identity is SHA-256 of the DER SubjectPublicKeyInfo, not the certificate bytes.

**M0 spike result:** quiche's public `Connection` API does not expose TLS exporter material. BoringSSL has `SSL_export_keying_material`, but using it on QUIC's TLS object requires an API path through quiche; the upstream BoringSSL issue notes that ordinary SSL exporter calls on QUIC SSL objects historically failed. v1 therefore uses the nonce + SPKI construction above. Before changing this, M5 must prove exporter availability on both endpoints and bind the exporter label/context into the signed message. It must not silently switch binding modes.

## Limits and timeouts

| Resource | v1 limit |
|---|---:|
| Control payload | 4096 bytes |
| Username | 256 UTF-8 bytes |
| Terminal name | 64 UTF-8 bytes |
| Concurrent bidi streams | 2 (IDs 0 and 4 only) |
| Auth attempts | 1 per connection |
| Hello deadline | 5 seconds |
| Authentication deadline | 30 seconds |
| Open-shell deadline | 10 seconds |
| Idle connection | 10 minutes by default, configurable (`quic.idle_timeout_secs`, client `idle_timeout_secs`); QUIC PING keepalives (`quic.keep_alive_interval_secs`, client `server_alive_interval_secs`/`server_alive_count_max`) |
| QUIC datagram payload | bounded by negotiated path MTU; no application fragmentation |

The server also enforces global and per-source connection/auth limits in M8. A resource exhaustion condition fails closed and does not fall back to a less restrictive transport or kernel path.

## Threat model

Assets are host private keys, user private keys, user account/session integrity, terminal contents, and server availability. The network attacker may observe, drop, replay, reorder, inject, and delay packets or attempt address spoofing; QUIC/TLS protects established connections. An unauthenticated peer may send arbitrary bounded protocol input. A compromised worker is assumed to control its process and all data it handles; it must not be able to read the host key, choose the authenticated principal, spawn arbitrary host processes, or access the filesystem/network beyond its assigned sockets and ring operations. The root monitor, kernel, BoringSSL/quiche, user database, and host are trusted. Root compromise, kernel compromise, malicious authorized users, and traffic analysis are out of scope.

The monitor owns host keys, validates signatures/policy and creates PTYs. Workers are unprivileged and receive only PTY master descriptors. Ring restrictions, seccomp, Landlock, cgroups and privilege separation are defense in depth, not claims that a compromised kernel or unsafe native dependency is contained. Error classes and frame sizes are bounded to limit information leakage and parser abuse. Deployment requires patched Linux, private host-key storage and independent security review before public exposure.

## Kernel baseline and feature matrix

Linux **6.12 LTS or newer** is required. Startup probes exact opcodes, setup flags, registrations, and socket options; a required feature failing the probe is fatal. Optional performance features are enabled only when configured and successfully probed. Kernel versions below are first upstream mainline availability; distribution backports do not change the startup probe requirement.

| Feature used/planned | First mainline | Required/optional | Notes |
|---|---:|---|---|
| io_uring interface | 5.1 | Required | `io_uring_setup/enter/register`; availability may be disabled by sysctl/seccomp |
| `IORING_SETUP_CLAMP` | 5.5 | Required | setup flag |
| `IORING_SETUP_COOP_TASKRUN` | 5.19 | Required | cooperative task work |
| `IORING_SETUP_SINGLE_ISSUER` | 6.0 | Required | one submitting task per ring |
| `IORING_SETUP_DEFER_TASKRUN` | 6.1 | Required | requires single issuer |
| `IORING_SETUP_NO_SQARRAY` | 6.6 | Required | no SQ indirection array |
| registered provided-buffer ring | 5.19 | Required | `IORING_REGISTER_PBUF_RING` |
| incremental provided buffers (`IOU_PBUF_RING_INC`) | 6.12 | Required | incremental consumption and `IORING_CQE_F_BUF_MORE` |
| multishot `RECVMSG` + buffer select | 6.0 | Required | runtime probe with UDP socket; GRO cmsg still validated |
| `READ_MULTISHOT` | 6.7 | Required for PTY plan | runtime behavior on PTY is an M0/M6 spike; see below |
| `IORING_REGISTER_RESTRICTIONS` | 5.10 | Required | ring must be created disabled, then explicitly enabled after restrictions are registered |
| registered ring fd (`IORING_REGISTER_RING_FDS`) | 5.18 | Required | registration API; setup `REGISTERED_FD_ONLY` additionally requires 6.5 |
| registered fixed buffers/files | 5.1 / 5.1 | Required | registration and fixed-file SQE support |
| `IORING_OP_SEND_ZC` | 6.0 | Optional | notification CQE must be tracked before buffer reuse |
| `IORING_OP_SENDMSG_ZC` | 6.0 | Optional | same completion lifetime rules |
| `IORING_OP_MSG_RING` | 5.18 | Required in M8 | cross-ring control |
| `IORING_OP_WAITID` | 6.7 | Required in M6 | pidfd exit observation; poll+waitid alternative remains io_uring-only |
| `IORING_REGISTER_NAPI` | 6.9 | Optional | opt-in busy polling |
| `IORING_ENTER_EXT_ARG_REG` | 6.13 | Required in M4 | registered wait argument, introduced with registered memory regions |
| `IORING_OP_TIMEOUT` / update | 5.4 / 5.5 | Required | worker timer |
| UDP GRO (`UDP_GRO`) | 5.0 | Required | Linux UDP socket ancillary data |
| UDP GSO (`UDP_SEGMENT`) | 4.18 | Required | socket option/control message; probe at socket setup |
| `SO_TXTIME` | 4.20 | Optional | requires `sch_fq` for pacing |
| `memfd_secret` | 5.14 | Optional | monitor key-memory hardening; verified at startup if configured |
| `openat2` resolve flags | 5.6 | Required in M1/M2 | `RESOLVE_BENEATH`, `NO_SYMLINKS`, `NO_MAGICLINKS` |
| `clone3` | 5.3 | Required in M6 | process creation syscall |
| `clone3` `CLONE_PIDFD` | 5.3 | Required in M6 | child process management |
| `CLONE_INTO_CGROUP` | 5.7 | Required in M6 | cgroup v2 session placement |
| pidfd signal/wait | 5.1 / 5.4 | Required in M6 | `pidfd_send_signal` / `waitid(P_PIDFD)` |
| Landlock | 5.13 | Required in M9 | ABI version queried; rule support varies |
| `IORING_SETUP_NO_MMAP` | 6.5 | Required in M4 | user-provided ring memory; verify associated registration details |
| `IORING_SETUP_REGISTERED_FD_ONLY` | 6.5 | Required in M4 | used with `NO_MMAP`; `IORING_ENTER_REGISTERED_RING` avoids fd-table lookup |
| `IORING_OP_SOCKET` | 5.19 | Required | socket creation through ring; startup probe |
| `IORING_REGISTER_IOWQ_MAX_WORKERS` | 5.15 | Required in M4 | bounds async worker pool |
| `IOSQE_CQE_SKIP_SUCCESS` | 5.17 | Required | fire-and-forget SQEs; CQE behavior still checked |
| `SO_REUSEPORT` | 3.9 | Required in M8 | one UDP socket per worker |
| `SO_BUSY_POLL` / `SO_PREFER_BUSY_POLL` | 3.11 / 5.11 | Optional | socket busy polling |
| `TIOCGPTPEER` | 4.13 | Required in M6 | obtain PTY slave descriptor |
| `TIOCSWINSZ` / `TIOCSCTTY` | 1.x | Required in M6 | PTY resize and controlling terminal setup |
| cgroup v2 `cgroup.kill` | 5.14 | Required in M6 | session teardown backstop; requires cgroup v2 mount |
| `PR_SET_PDEATHSIG` / `PR_SET_CHILD_SUBREAPER` | 2.1 / 3.4 | Required in M6 | monitor/child lifecycle |
| `signalfd` | 2.6.22 | Required in M7 | signal delivery through the ring |
| seccomp filter | 3.5 | Required in M9 | worker syscall allowlist |

The versions above are minimum upstream versions; the project's baseline is 6.12. The ring setup and operation combination still needs an integration probe because individual feature availability does not guarantee all requested flags are compatible on a given kernel/configuration.

**Baseline conflict found during M1:** `IORING_ENTER_EXT_ARG_REG` was introduced in Linux 6.13, while the project baseline and M0 kernel matrix include 6.12. Before M4, either raise the minimum kernel to 6.13 or revise the wait strategy to use `IORING_ENTER_EXT_ARG` (available since 5.11). Do not mark the current 6.12 baseline as supporting the registered wait argument.

### M0 spikes

* **TLS exporter:** no exporter on quiche's public connection API was found. Use nonce + SPKI binding for v1. BoringSSL's `SSL_export_keying_material` alone does not prove that quiche's QUIC TLS session can call it.
* **Feature-to-version audit:** versions are recorded against Linux UAPI, liburing man pages and kernel source. Runtime support remains subject to the capability probe because distro configuration and backports vary.
* **PTY multishot read:** Linux has `IORING_OP_READ_MULTISHOT` since 6.7, but opcode availability alone does not prove PTY master support. The PTY behavior is not confirmed by the M0 source evidence. M6 must probe on an actual PTY master; if unsupported, rearm single-shot `IORING_OP_READ` (still io_uring-only), or revise the M4 requirement before implementation.

Kernel evidence references: [Linux io_uring UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/io_uring.h), [liburing `io_uring_setup(2)`](https://kernel.googlesource.com/pub/scm/linux/kernel/git/axboe/liburing/+/refs/heads/master/man/io_uring_setup.2), [liburing provided-buffer ring documentation](https://kernel.googlesource.com/pub/scm/linux/kernel/git/axboe/liburing/+/refs/heads/master/man/io_uring_register_buf_ring.3), [liburing `io_uring_enter(2)`](https://kernel.googlesource.com/pub/scm/linux/kernel/git/axboe/liburing/+/refs/heads/master/man/io_uring_enter.2).

## BoringSSL pin and updates

quiche is pinned to the published `0.30.0` release. Its BoringSSL ABI pin is upstream commit `44b3df6f03d85c901767250329c571db405122d5`, supplied by the matching `boring-sys` 4.22.0 build. This is a source pin, not a promise of an independently maintained fork. `boring-sys` builds that pinned source and applies its compatibility patches.

To update, select a quiche release, inspect its resolved `boring-sys` BoringSSL revision and any patches, update the exact quiche dependency and `BORINGSSL_COMMIT` together, regenerate the lockfile, then run build, audit, and TLS/exporter compatibility checks. Never float either dependency on a branch or tag in a release build. Review BoringSSL's upstream security advisories before accepting the update.
