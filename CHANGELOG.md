# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-11-12

### Security
- Enforce TLS 1.3 only on both QUIC endpoints and disable TLS tickets/session resumption for protocol v1.
- Add optional CA-verified server certificate chains with strict DNS/IP Subject Alternative Name validation, while retaining mandatory SPKI known-hosts pinning.
- Default unknown-host handling to deny; remove silent `approve` enrollment and require an independently verified full fingerprint for interactive enrollment.
- Add bounded server certificate-chain parsing and verify the leaf SPKI matches the monitor-protected host key; reject expired and not-yet-valid certificates at startup.
- Add `ssxd --print-host-pin` and a CSR helper (`scripts/ssxpro-csr.py`) for certificates using the existing monitor-held Ed25519 host identity.

### Added
- `ssxd --print-host-pin`: prints the server SPKI SHA-256 as base64 for out-of-band known_hosts provisioning.
- `ssx --trust-new-host`: guarded interactive enrollment (the legacy `--approve-host` spelling remains an alias and no longer silently approves).
- `scripts/ssxpro-csr.py`: creates a CSR from the protected host seed without exporting private key material.
- `docs/tls-security.md`: provisioning, rotation, and recovery procedures for pin-only and CA modes.
- TLS security e2e coverage (`tests/ssx_e2e.py`): untrusted CA rejected during the handshake (MITM simulation), missing CA bundle refused, and verbose logging of CA loading, chain verification, SAN matching, negotiated ALPN, and SPKI pin result.
- `tests/bootstrap.sh` generates a test CA, a server chain signed by it (using the host key), an unrelated CA for negative tests, and a TLS-enabled client config.

### Changed
- Server certificate chain is configured as `tls.certificate_chain` (optional; the built-in self-signed host certificate remains the default).
- Client CA trust is configured as `tls.ca_bundle` (optional; without it, strict pre-provisioned SPKI pinning remains the trust anchor).
- `known_hosts_policy` defaults to `deny`; the `approve` value is rejected.
- Removed SHA-1/MD5-incompatible algorithm restrictions: the client advertises Ed25519 plus SHA-2 ECDSA/RSA for certificate verification so CA-issued chains work with common private PKIs.
- Updated the protocol specification, configuration reference, and example configs with the TLS settings.

## [0.1.1] - 2026-11-12

### Added
- Server-enforced PTY stream compression, configured with `compression: off|fast|standard|high` (default `off`)
  - `off`: raw stream-4 bytes
  - `fast`: LZ4, optimized for low CPU utilization
  - `standard`: Snappy
  - `high`: Zstd level 19
- Compression negotiation through `Hello` feature bits and the server's `AuthChallenge` selection. Bits 0–2 advertise LZ4, Snappy, and Zstd; unknown bits are rejected. A client that does not advertise the configured algorithm is rejected.
- Bounded stream-4 compression frames (`format:u8`, uncompressed length `u32be`, payload length `u32be`) with stored-block fallback when compression would expand data
  - Uncompressed blocks are limited to 64 KiB and compressed payloads to 128 KiB
  - A FIN must fall on a frame boundary
  - Zstd decoding rejects a window larger than one block
  - The server keeps decoded PTY input within 256 KiB and holds a complete frame until that queue has room
- `ssxpro-compression` workspace crate with LZ4, Snappy, and Zstd codecs
- End-to-end coverage for compression negotiation and bulk transfer in every mode (`tests/compression_e2e.sh`)
- GitLab CI release builds for native `x86_64-unknown-linux-gnu`, fully static `x86_64-unknown-linux-musl`, and cross-compiled `aarch64-unknown-linux-gnu`
- Cargo and CMake toolchain settings for those musl and aarch64 targets
- Redistributed third-party `LICENSE`, `NOTICE`, and `AUTHORS` texts under `licenses/`, checked by `scripts/licenses.sh`

### Changed
- Control frames are incompatible with 0.1.0. Protocol version remains 1 and ALPN remains `ssxpro/1`. Every control frame except `Close` ends with a reserved `u32` extension word: senders set it to zero and receivers reject a nonzero value. `Hello` is 10 bytes and carries the compression feature bits. `AuthChallenge` is 37 bytes: the 32-byte server nonce, the selected compression algorithm, and the extension word. The Ed25519 authentication proof is unchanged.
- Updated the protocol specification, configuration reference, and example `ssxd.yaml` with the compression settings

## [0.1.0] - 2026-11-07

### Added
- Initial remote-shell-only server (`ssxd`) and client (`ssx`)
- QUIC transport (quiche / BoringSSL) with ALPN `ssxpro/1`
- io_uring-centric I/O path with strict Linux 6.12+ feature probes
- Ed25519 public-key authentication using nonce + server SPKI binding
- Single interactive PTY session per connection
  - Control stream: Hello, AuthChallenge/Request/Ok/Fail, OpenShell, Resize, Signal, Exit, Close
  - Unframed bidirectional PTY data stream
- Workspace crates: `ssxpro-server`, `ssxpro-client`, `ssxpro-proto`, `ssxpro-config`, `ssxpro-crypto`, `ssxpro-io`
- YAML configuration with server and client examples
- Protocol and security specification (`SPEC.md`)
- Fuzz targets for config, key files, monitor IPC, and protocol codec/state
- Test bootstrap script and basic end-to-end scaffolding
- Documentation for configuration, dependencies, and CI kernel requirements

### Fixed
- Authentication and PTY stalls
- QUIC timer handling
- I/O robustness and configuration validation
- Preserve io_uring completions and isolate broker failures
- Correct session, retry, and exit-signal handling
- Require explicit host trust approval
- Reject non-regular files without blocking (openat2 + non-blocking paths)

### Changed
- Client `known_hosts_policy` default set to `ask`
- Improved client CLI target handling and identity/config path robustness
