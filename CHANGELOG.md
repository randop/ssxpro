# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-11-12

### Added
- Server-enforced PTY stream compression, configured with `compression: off|fast|standard|high`
  - `off`: no compression
  - `fast`: LZ4, optimized for low CPU utilization
  - `standard`: Snappy
  - `high`: Zstd level 19
- Compression negotiation through `Hello` feature bits and the server's `AuthChallenge` selection; unsupported clients fail closed instead of downgrading
- Bounded stream-4 compression frames with stored-block fallback when compression would expand data
- `ssxpro-compression` workspace crate with LZ4, Snappy and Zstd codecs

### Changed
- Updated protocol specification, configuration reference, and example `ssxd.yaml` with compression settings
- `AuthChallenge` now carries the selected stream-compression algorithm
- `Hello` now carries a reserved `u32` extension word; version 1 senders set it to zero and receivers reject nonzero values

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
