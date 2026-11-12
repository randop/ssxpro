# ssxpro: TLS 1.3 and MITM Protection Implementation Plan

**Target repository:** [randop/ssxpro](https://github.com/randop/ssxpro)  
**Document type:** Architecture-specific security implementation plan  
**Date:** November 12, 2026

## 1. Executive Summary

The objective is to make **TLS 1.3 mandatory for every ssxpro network connection and prevent unauthorized interception, impersonation, certificate substitution, and downgrade attacks.**

The repository is a Linux remote-shell application built around QUIC, Rust, `io_uring`, and the quiche/BoringSSL stack. Its protocol specification establishes an important security foundation:

- QUIC provides transport confidentiality, integrity, and peer authentication through TLS 1.3.
- The application negotiates the `ssxpro/1` ALPN identifier.
- Client authentication uses Ed25519 public-key signatures.
- Authentication signatures incorporate the server's SHA-256 SubjectPublicKeyInfo (SPKI) fingerprint.
- Connections are not resumed and do not accept 0-RTT in protocol version 1.

Consequently, the recommended approach is **not to add another encryption layer on top of QUIC**, but to strengthen TLS 1.3 configuration, server identity verification, certificate lifecycle management, client trust decisions, and downgrade resistance.

An important distinction: TLS 1.3 encryption alone does not prevent MITM attacks. The client must also authenticate the intended server and reject invalid, substituted, expired, or untrusted certificates.

## 2. Repository Assessment

### 2.1 Existing Security Architecture

The repository's `SPEC.md` describes the following transport and authentication model:

```text
+------------------------------+
|         ssxpro client        |
| User identity                |
| Ed25519 private key          |
| Known-hosts database         |
+------------------------------+
               |
               | QUIC / UDP
               | TLS 1.3 mandatory
               | ALPN: ssxpro/1
               v
+------------------------------+
|       quiche / BoringSSL     |
| TLS handshake                |
| Certificate verification    |
| Encryption and integrity    |
+------------------------------+
               |
               v
+------------------------------+
|         ssxpro server        |
| Certificate identity         |
| Ed25519 authentication       |
| Protocol state machine       |
+------------------------------+
               |
               v
+------------------------------+
| Privileged monitor / worker  |
| Authorized keys              |
| PTY creation                  |
| Login shell                   |
| Session isolation             |
+------------------------------+
```

The following existing protections are particularly relevant:

| Existing mechanism | Security contribution |
|---|---|
| QUIC with TLS 1.3 | Encrypted and authenticated transport |
| `ssxpro/1` ALPN | Protocol identification |
| Ed25519 authentication | Client identity verification |
| Server SPKI fingerprint in authentication signature | Binds user authentication to the server's public-key identity |
| Fresh client/server nonces | Prevents reuse of old authentication proofs |
| No 0-RTT | Prevents early-data replay exposure |
| No legacy protocol compatibility | Reduces downgrade opportunities |

Source: repository `SPEC.md`, particularly its transport, authentication, and state-machine sections.

### 2.2 Rust Workspace Components

The workspace defines six relevant crates:

| Crate | Recommended security responsibilities |
|---|---|
| `ssxpro-proto` | Enforce protocol and ALPN-related invariants |
| `ssxpro-crypto` | Certificate identity hashing, fingerprints, and authentication binding |
| `ssxpro-io` | QUIC transport integration and connection handling |
| `ssxpro-config` | TLS policy, certificate paths, and trust configuration |
| `ssxpro-server` | Server TLS configuration and mandatory client/server protocol checks |
| `ssxpro-client` | Certificate validation, server identity verification, and trust-on-first-use/pinning policy |

The workspace explicitly pins `boring = 4.22.0`, while the security specification identifies quiche 0.30.0 and its associated BoringSSL source revision. These are important compatibility boundaries: TLS changes should not casually introduce an independent TLS implementation or a mismatched BoringSSL build.

**Assessment limitation:** The repository's protocol and workspace specifications are available for inspection, but the implementation of every Rust source file has not been independently verified in this plan. The following is therefore a proposed implementation and audit plan, not a claim that every listed protection is already implemented or that vulnerabilities have been confirmed.

## 3. Security Gaps and Implementation Priorities

The source-code inspection identifies the following areas to address.

### 3.1 Client Certificate Verification — Critical

File: `crates/ssxpro-client/src/transport.rs`

The client explicitly calls:

```rust
tls.verify_peer(false);
```

This disables fatal certificate-verification errors. The application subsequently performs its own SPKI pin check, so this is not equivalent to having no server authentication; however, normal X.509 chain validation is absent.

### 3.2 First-Connection Trust — Critical

The known-hosts policy defaults to `KnownHostsPolicy::Ask`. The `--approve-host` option can automatically accept a previously unknown fingerprint. An attacker intercepting the initial connection could exploit careless acceptance.

### 3.3 TLS Certificate Properties — High

File: `crates/ssxpro-server/src/tls.rs`

The server constructs a self-signed certificate with the common name `ssxpro`, a fixed serial number, and a 365-day validity period. The certificate-generation routine does not add Subject Alternative Name, Extended Key Usage, or other standard certificate extensions.

### 3.4 Missing Peer Certificate Handling — High

The client checks for a certificate when processing the authentication challenge, but its initial pin-check block marks the pin as checked even when `peer_cert()` returns `None`. This should fail immediately.

### 3.5 TLS Version and ALPN Enforcement — Existing Foundation

QUIC already uses TLS 1.3, and both endpoints configure the `ssxpro/1` ALPN identifier. Preserve this architecture and introduce regression tests.

Relevant implementation references:

- [Client transport](https://github.com/randop/ssxpro/blob/master/crates/ssxpro-client/src/transport.rs)
- [Server TLS implementation](https://github.com/randop/ssxpro/blob/master/crates/ssxpro-server/src/tls.rs)
- [Configuration crate](https://github.com/randop/ssxpro/blob/master/crates/ssxpro-config/src/lib.rs)

## 4. Recommended Target Security Architecture

I recommend a combination of **TLS 1.3 certificate verification, private certificate authority (CA) trust, hostname verification, and the existing SPKI pinning mechanism**.

These controls provide independent checks:

1. TLS 1.3 authenticates the server's possession of its certificate private key and protects the handshake.
2. CA verification establishes that the certificate was issued by a trusted authority.
3. Hostname verification establishes that the certificate belongs to the hostname the client intended to reach.
4. SPKI pinning detects unexpected server key changes, even when certificate validation succeeds.
5. Existing Ed25519 user authentication establishes the identity authorized to open a shell.

The private CA should be maintained separately from the production server. Its signing private key should remain offline. The server should possess only its issued certificate and the corresponding private key protected by the existing privileged monitor.

A strict, pre-provisioned SPKI-only deployment can remain available where operating a CA is impractical, but it must not rely on blind first-use acceptance.

## 5. Detailed Implementation Phases

### Phase 1 — Establish Mandatory Transport Security

**Priority: P0**

Files:

- `crates/ssxpro-client/src/transport.rs`
- `crates/ssxpro-server/src/tls.rs`
- `crates/ssxpro-server/src/transport.rs`
- `crates/ssxpro-proto`

Implementation:

1. Retain QUIC as the sole network transport.
2. Keep the exact ALPN identifier `ssxpro/1`.
3. Ensure that all client and server connection configurations use the QUIC TLS integration provided by the pinned quiche/BoringSSL dependencies.
4. Do not add a TCP or TLS 1.2 fallback.
5. Ensure that application messages are not processed until TLS establishment and server identity verification have completed.
6. Explicitly verify the negotiated ALPN before allowing the protocol state machine to advance.
7. Keep unsupported protocol versions and ALPN identifiers fatal.

QUIC v1 uses TLS 1.3 as its cryptographic handshake. Consequently, implementing this requirement does not mean introducing a second TLS connection or an additional encryption layer.

**Acceptance criteria:**

- TLS 1.3 is used on every successful QUIC connection.
- TLS 1.2 connections are impossible.
- An incorrect ALPN causes handshake failure.
- No application authentication message can be sent before server authentication.

### Phase 2 — Implement Certificate Authority and Server Certificates

**Priority: P0**

Primary file: `crates/ssxpro-server/src/tls.rs`

Replace the dynamically generated self-signed certificate as the preferred deployment certificate with a CA-issued server certificate.

Recommended certificate hierarchy:

```text
Offline ssxpro Root CA
  - Private signing key kept offline
              |
              v
ssxpro Server Certificate
  - Ed25519 public key
  - DNS/IP Subject Alternative Name
  - serverAuth Extended Key Usage
              |
              v
ssxpro QUIC Server
  - Uses its corresponding private key through the monitor
```

Required certificate properties:

| Property | Requirement |
|---|---|
| Public key | Ed25519 |
| Subject Alternative Name | Configured DNS names and/or IP addresses |
| Extended Key Usage | `serverAuth` |
| Key Usage | `digitalSignature` |
| Basic Constraints | `CA:FALSE` |
| Serial number | Unique, cryptographically unpredictable |
| Validity | Preferably 30–90 days |
| Signature algorithm | Supported Ed25519-based certificate chain |
| Certificate chain | Leaf plus required intermediate certificates |

The server certificate's SPKI must match the public key associated with the server's protected signing identity.

Implementation tasks:

- Add certificate-chain loading and validation.
- Add certificate hostname configuration.
- Validate the certificate's public key against the monitor's existing host identity.
- Ensure the certificate chain is loaded into BoringSSL.
- Preserve the existing `IpcSigner` mechanism so that private key operations remain in the privileged monitor.
- Keep the CA private key outside the server runtime.
- Fail startup when the certificate is expired, malformed, incompatible with the host identity, or missing its required chain.

Do not expose a private key to the unprivileged workers merely to support certificate loading.

### Phase 3 — Enforce Client-Side Certificate Verification

**Priority: P0 — Most important code change**

Primary file: `crates/ssxpro-client/src/transport.rs`

The current client contains:

```rust
tls.verify_peer(false);
```

This must be replaced with mandatory certificate verification in the CA-based deployment mode.

The proposed configuration sequence is:

```rust
let mut tls =
    quiche::Config::with_boring_ssl_ctx_builder(
        quiche::PROTOCOL_VERSION,
        ssl,
    )?;

// Load the trusted ssxpro CA.
tls.load_verify_locations_from_file(ca_bundle)?;

// Make certificate verification mandatory.
tls.verify_peer(true);

// Keep the protocol restricted to ssxpro.
tls.set_application_protos(&[ssxpro_proto::ALPN])?;
```

This is an implementation pattern; the final integration must preserve the repository's existing BoringSSL signature-algorithm configuration and monitor-compatible Ed25519 certificates.

**Important:** Loading a CA certificate and enabling certificate verification are separate operations in quiche. Loading the CA alone does not turn certificate-verification failures into fatal errors.

Implementation requirements:

1. Verify the server certificate chain against the configured trusted CA.
2. Reject certificates issued by unknown authorities.
3. Reject expired and not-yet-valid certificates.
4. Validate the DNS name or IP address against the certificate's Subject Alternative Name.
5. Reject certificates with invalid signatures.
6. Reject missing server certificates.
7. Reject certificates that do not match the configured server identity.
8. Do not provide a normal runtime option to disable verification.

The existing call:

```rust
quiche::connect(Some(hostname), &scid, local, peer, &mut tls)?;
```

should retain the intended hostname rather than substituting the resolved network IP for DNS connections.

That distinction matters: DNS resolution determines where packets are sent, while certificate verification determines which server identity the client is willing to trust.

The behavior must be covered by tests for both DNS names and IP address connections.

### Phase 4 — Strengthen SPKI Fingerprint Validation

**Priority: P0**

Primary files:

- `crates/ssxpro-client/src/transport.rs`
- `crates/ssxpro-crypto/src/lib.rs`

Keep the existing known-hosts SPKI fingerprint mechanism.

It is an important security feature and should complement CA verification rather than be removed.

The intended validation sequence becomes:

1. Complete the TLS 1.3 QUIC handshake.
2. Require that the server provides a certificate.
3. Verify the certificate chain against the trusted CA.
4. Verify the server hostname or IP identity.
5. Calculate SHA-256 over the DER-encoded SubjectPublicKeyInfo.
6. Compare the fingerprint with the expected known-hosts identity.
7. Only after successful validation, send `Hello`.
8. Proceed with the existing Ed25519 authentication challenge.

The client should fail immediately when:

- The certificate is missing.
- The certificate is not trusted.
- The certificate hostname does not match.
- The fingerprint differs from the expected pin.
- The server attempts to use a different identity.

The existing implementation already checks the host key before sending the application `Hello`. Preserve this ordering and make it mandatory on every new connection.

**First-connection policy**

The current default is `KnownHostsPolicy::Ask`, and the client also supports `--approve-host`.

For strict deployment:

- Use pre-provisioned trust anchors and expected fingerprints.
- Change the unattended default to reject untrusted identities.
- Remove automatic acceptance of unknown host keys, or restrict it to an explicit enrollment operation that verifies an expected fingerprint obtained through a trusted independent channel.
- Never replace an existing pin automatically.
- Keep host identity mismatches fatal.

In CA-verified deployments, first-use pin enrollment may take place after successful CA-chain and hostname verification. In pin-only deployments, the fingerprint must be obtained out of band before the first connection.

### Phase 5 — Add TLS Security Configuration

**Priority: P1**

Primary file: `crates/ssxpro-config/src/lib.rs`

Introduce a dedicated TLS configuration structure rather than mixing TLS settings with general QUIC settings.

Suggested server configuration:

```yaml
tls:
  certificate_chain: /etc/ssx/server-fullchain.pem
  # The corresponding signing identity remains
  # protected by the privileged monitor.

quic:
  # Existing QUIC settings remain unchanged.
```

Suggested client configuration:

```yaml
tls:
  ca_bundle: /etc/ssx/ssxpro-ca.pem
  require_peer_verification: true
  require_spki_pin: true
```

The `require_peer_verification` value should be enforced by application policy, not treated as a user-selectable security bypass. A missing CA bundle in strict CA mode must prevent the connection.

Add configuration validation for:

- Unreadable certificate and CA files.
- Invalid PEM encoding.
- Missing certificate chains.
- Unsupported certificate algorithms.
- Invalid paths.
- Incompatible certificate and signing-key pairs.
- Missing or invalid trust settings.

Use the existing configuration parser's `deny_unknown_fields` behavior to avoid silently accepting misspelled security settings.

### Phase 6 — Preserve Session-Binding and Replay Protection

**Priority: P1**

Primary files:

- `crates/ssxpro-client/src/transport.rs`
- `crates/ssxpro-server/src/tls.rs`
- `crates/ssxpro-crypto/src/lib.rs`

Retain the existing authentication construction:

```text
ssxpro-auth-v1
|| server_nonce
|| client_nonce
|| server_spki_sha256
|| username
|| client_ed25519_public_key
```

This binds client authentication to the server's TLS identity.

Additional requirements:

- Generate fresh nonces using the operating system CSPRNG.
- Never reuse authentication challenges.
- Verify the SPKI binding in the privileged monitor.
- Keep replayed authentication requests invalid.
- Continue rejecting protocol messages received in the wrong state.
- Keep 0-RTT disabled.
- Do not introduce session resumption in protocol version 1.

The specification already explicitly prohibits 0-RTT and resumed connections in v1. These restrictions should become regression-tested requirements.

If session tickets are emitted by the TLS stack, verify that clients cannot use them to resume connections. Disable ticket issuance where supported by the pinned API.

### Phase 7 — Certificate and Key Lifecycle Management

**Priority: P1**

Introduce documented procedures for:

| Event | Required action |
|---|---|
| Initial installation | Provision CA trust and server certificate |
| Certificate renewal | Issue a new certificate and reload safely |
| Certificate expiration | Reject the expired certificate |
| Host key rotation | Pre-authorize the replacement SPKI |
| CA rotation | Distribute the new root before removing the old root |
| Private key compromise | Revoke trust and replace the affected identity |
| Server recovery | Restore the verified certificate and protected identity |

Use overlapping trusted CA certificates during planned CA rotation.

When changing a server SPKI pin, permit the replacement only through an authenticated administrative operation. Never accept a new fingerprint merely because the old certificate stopped working.

Retain the existing monitor-based private key protection, and ensure that certificates and CA public certificates are not accidentally treated as private key material.

### Phase 8 — Logging and Monitoring

**Priority: P1**

Add structured security events for:

- Successful TLS handshakes.
- Certificate validation failures.
- Untrusted certificate authorities.
- Hostname mismatches.
- SPKI fingerprint mismatches.
- Unknown host identities.
- ALPN negotiation failures.
- TLS handshake failures.
- Certificate renewals and key rotations.
- Unexpected authentication failures.

Each event should include:

- Timestamp.
- Remote address.
- Expected hostname.
- Negotiated ALPN.
- TLS handshake result.
- Server fingerprint where available.
- Failure classification.

Never log private keys, Ed25519 authentication seeds, session secrets, terminal contents, or TLS key-log material in production.

## 6. Security Testing and Validation Plan

**Priority: P0 — Required before production release**

Add integration tests that establish actual QUIC connections between the client and a local test server using controlled certificates.

### 6.1 TLS 1.3 Verification Matrix

| Test | Expected result |
|---|---|
| Valid TLS 1.3 certificate | Pass |
| Valid trusted CA and matching hostname | Pass |
| Untrusted CA | Reject |
| Expired certificate | Reject |
| Not-yet-valid certificate | Reject |
| Wrong DNS hostname | Reject |
| Incorrect IP SAN | Reject |
| Invalid certificate signature | Reject |
| Missing server certificate | Reject |
| Unexpected SPKI fingerprint | Reject |
| Incorrect ALPN | Reject |
| TLS 1.2-only endpoint | Reject |
| TLS 1.3 with 0-RTT attempted | Reject early data |

### 6.2 MITM Attack Simulation

Build a test environment with three components:

```text
+------------------------------+
|     Legitimate ssxpro client |
+------------------------------+
               |
               v
+------------------------------+
|        MITM test proxy       |
| Intercepts traffic           |
| Presents attacker-controlled |
| certificate                  |
+------------------------------+
               |
               v
+------------------------------+
|     Legitimate ssxpro server |
+------------------------------+
```

Perform these attack scenarios:

1. Replace the legitimate server certificate with an attacker-controlled certificate.
2. Present a certificate signed by an untrusted CA.
3. Present a valid certificate for a different hostname.
4. Present a certificate containing a different SPKI fingerprint.
5. Attempt to modify, inject, or replay QUIC packets.
6. Attempt to redirect DNS to an attacker-controlled IP address.
7. Attempt to establish a connection using an unsupported ALPN.
8. Attempt to downgrade the client into a non-QUIC or legacy transport.
9. Attempt first-connection interception during host enrollment.

**Expected outcome:** The client must refuse to establish an authenticated ssxpro session whenever the server identity does not satisfy the configured trust requirements. No `AuthRequest`, `AuthOk`, `OpenShell`, or PTY session may result from an unauthenticated connection.

### 6.3 Automated Security Checks

Add the following to CI:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo audit
```

Additionally:

- Run certificate-validation integration tests.
- Run malformed certificate and malformed handshake tests.
- Run QUIC protocol compatibility tests.
- Run known-hosts pinning and key-rotation tests.
- Fuzz certificate parsing and identity-validation boundaries.
- Test supported Linux kernel configurations.

The quiche and BoringSSL pins must remain synchronized. The repository documents its quiche 0.30.0 and BoringSSL source pinning strategy. Dependency updates must include security-advisory review and complete transport regression testing.

## 7. Suggested Implementation Breakdown

| Work item | Main files | Priority |
|---|---|---|
| TLS trust policy and certificate configuration | `ssxpro-config` | P0 |
| CA-issued certificate support | Server `tls.rs` | P0 |
| Mandatory client peer verification | Client `transport.rs` | P0 |
| Mandatory server certificate presence | Client `transport.rs` | P0 |
| Strict SPKI pinning and enrollment | Client `transport.rs`, `ssxpro-crypto` | P0 |
| TLS and ALPN integration tests | `tests/` | P0 |
| 0-RTT and resumption regression tests | Client/server transport | P1 |
| Certificate renewal and rotation | Server TLS/configuration | P1 |
| Structured TLS security events | Client/server | P1 |
| CI security enforcement | Repository CI configuration | P1 |
| Independent penetration testing | Security validation | P1 |

## 8. Definition of Done

The implementation should not be considered production-ready until every requirement below is satisfied.

- [ ] QUIC connections exclusively use TLS 1.3.
- [ ] The `ssxpro/1` ALPN identifier is mandatory.
- [ ] The client enforces certificate-chain validation in CA mode.
- [ ] Hostname and IP identity validation are mandatory.
- [ ] The expected server SPKI is verified before application authentication.
- [ ] An unknown or substituted identity cannot be automatically trusted.
- [ ] Certificate and pin mismatches terminate the connection.
- [ ] Missing server certificates terminate the connection.
- [ ] TLS 0-RTT is disabled.
- [ ] Session resumption is not accepted in protocol version 1.
- [ ] The privileged monitor continues to protect server signing keys.
- [ ] Certificate renewal and key rotation are documented and tested.
- [ ] MITM simulation tests pass.
- [ ] No insecure transport fallback exists.
- [ ] Security regression tests run in CI.
- [ ] Independent security review is completed before public production deployment.

## 9. Recommended Deployment Sequence

### Stage 1 — Development

Implement the CA-based trust architecture, update client verification, improve certificate generation, and introduce automated integration tests.

### Stage 2 — Staging

Generate a dedicated test CA, install it on clients, issue server certificates, and verify all supported DNS/IP connection scenarios.

### Stage 3 — Security Validation

Run MITM simulations, certificate substitution tests, protocol downgrade tests, and key-rotation tests.

### Stage 4 — Production Migration

Provision the production CA and certificates through an authenticated administrative channel. Distribute new trust anchors before enabling mandatory verification. Pre-provision server fingerprints where strict pinning is required.

### Stage 5 — Enforcement

Make the new trust policy mandatory. Reject clients with missing CA configuration or incorrect server fingerprints. Remove obsolete trust-on-first-use bypasses and document the supported certificate rotation procedure.

## 10. Technical References

The implementation should be aligned with these authoritative specifications and library references:

| Reference | Purpose |
|---|---|
| [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001.html) | TLS 1.3 and QUIC integration |
| [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html) | Handshake, certificate authentication, and cryptographic requirements |
| [RFC 9525 — Service Identity in TLS](https://www.rfc-editor.org/rfc/rfc9525.html) | Certificate hostname and service identity verification |
| [quiche 0.30.0 documentation](https://docs.rs/quiche/0.30.0/quiche/) | Rust QUIC transport and TLS configuration |
| [quiche Config API](https://docs.quic.tech/quiche/struct.Config.html) | Certificate loading, trusted CA configuration, and peer verification |
| [BoringSSL documentation](https://boringssl.googlesource.com/boringssl/) | TLS implementation and certificate handling |
| [ssxpro SPEC.md](https://github.com/randop/ssxpro/blob/master/SPEC.md) | Existing application security and authentication specification |

## Final Recommendation

**Retain QUIC + TLS 1.3 + Ed25519, introduce CA-verified server certificates, enable mandatory BoringSSL peer verification on clients, and preserve SPKI pinning as an additional identity-continuity mechanism.**

Three changes should be treated as release-blocking:

1. Replace the client's disabled certificate-verification policy with mandatory verification against a configured trust anchor.
2. Eliminate blind first-connection trust and automatic unknown-host approval in strict deployments.
3. Require successful certificate, hostname, and SPKI validation before sending any application authentication data.

This approach strengthens the existing ssxpro architecture rather than redesigning its transport protocol or adding redundant encryption.

## Repository-Specific Verification Notes

The findings above are based on the inspected [client TLS setup and pin-check sequence](https://github.com/randop/ssxpro/blob/master/crates/ssxpro-client/src/transport.rs), [server certificate generation](https://github.com/randop/ssxpro/blob/master/crates/ssxpro-server/src/tls.rs), and [known-hosts policy](https://github.com/randop/ssxpro/blob/master/crates/ssxpro-config/src/lib.rs).

The quiche documentation indicates that peer verification must be explicitly enabled for certificate-validation enforcement. The implementation examples above are starting points, not guaranteed drop-in code: verify the exact API signatures against the repository's pinned quiche/BoringSSL versions and preserve the existing BoringSSL context and monitor integration.
