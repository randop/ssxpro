# TLS 1.3, server identity, and MITM protection

ssxpro uses QUIC v1 with TLS 1.3 and ALPN `ssxpro/1`. It does not add a second
TLS or application-encryption layer. The security boundary is the combination
of TLS 1.3, server identity verification, the SPKI pin in `known_hosts`, and
the existing Ed25519 client-authentication proof bound to that SPKI.

## Security properties implemented

- Both QUIC endpoints constrain the BoringSSL context to TLS 1.3 only.
- The server and client disable TLS session tickets and the session cache;
  protocol v1 does not enable 0-RTT or session resumption.
- The client requires a server certificate and checks its SPKI against the
  `known_hosts` entry before sending `Hello` or application authentication.
- Unknown host keys are rejected by default. Interactive enrollment requires
  typing the complete SPKI SHA-256 base64 value after independently comparing
  it with the value printed on the server.
- Optional CA mode verifies the certificate chain and checks DNS/IP identity
  against Subject Alternative Name (SAN), in addition to the SPKI pin.
- A configured server certificate must use the public key derived from the
  host seed held by the privileged monitor. The server worker never receives
  the host private key.

## Mode A: pre-provisioned SPKI pin (self-signed default)

This mode is compatible with the generated self-signed server certificate.
It is secure against an active MITM only when the expected pin is installed
through an authenticated, independent channel before the client connects.
The client does not perform X.509 CA-chain or hostname validation in this mode;
the SPKI pin is its trust anchor.

On the server, run the pin command with permission to read the protected host
key and with the same config used by the service:

```sh
sudo ssxd --config /etc/ssx/ssxd.yaml --print-host-pin
```

The output is standard padded base64 of SHA-256 over the DER SubjectPublicKeyInfo.
On the client, install that exact value in `~/.ssx/known_hosts`:

```sh
install -d -m 0700 ~/.ssx
umask 077
printf '%s spki-sha256 %s\n' 'shell.example.net:22' 'PASTE_SERVER_PIN_HERE' \
  >> ~/.ssx/known_hosts
chmod 0600 ~/.ssx/known_hosts
```

The configured host key uses the connection hostname and port, not a resolved
IP address. If a host alias is used, pin the actual hostname selected by that
alias. A pin mismatch always terminates the connection.

`known_hosts_policy` defaults to `deny`. To enroll interactively, use
`ssx --trust-new-host USER@HOST:PORT` and type the complete base64 fingerprint
only after comparing it out of band. The legacy `--approve-host` CLI spelling
is retained as an alias for this same interactive check; it no longer silently
approves. `known_hosts_policy: approve` is invalid. `ask` can be configured,
but `deny` plus pre-provisioned pins is recommended for unattended use.

## Mode B: private CA plus SPKI pin (recommended for managed deployments)

Use a private CA to validate certificate chains and SAN identities while still
pinning the leaf SPKI. Keep the CA signing key offline or in a dedicated
issuing system. Never copy the CA private key to the ssxpro server.

### 1. Create a CSR matching the server host key

The TLS leaf certificate must use the same Ed25519 public key as the configured
`host_key`, because the corresponding private key remains in ssxd's privileged
monitor and performs the TLS handshake signature. The helper reads the raw
32-byte seed but never writes or exports a private key:

```sh
sudo scripts/ssxpro-csr.py \
  --host-key /etc/ssx/host_ed25519 \
  --dns shell.example.net \
  --ip 192.0.2.10 \
  --output /root/ssxpro-server.csr
```

The helper requires Python 3 and the `cryptography` package. It opens the host
key without following symlinks and requires a regular file owned by the
invoking effective user with exact mode `0600`. Include every DNS name and IP
address clients will use. SAN is authoritative; the CN is informational only.

### 2. Have the CA issue the server certificate

Issue a short-lived end-entity certificate from your private CA. It must:

- Preserve the CSR's Ed25519 public key.
- Include the requested DNS and/or IP SAN entries.
- Include Extended Key Usage `serverAuth`.
- Include Key Usage `digitalSignature` and Basic Constraints `CA:FALSE`.
- Have a unique serial number and a bounded validity period (for example,
  30–90 days).
- Use a modern SHA-2 signature from the issuing CA (ECDSA or RSA-PSS/RSA-SHA2).

The client advertises Ed25519 plus SHA-2 ECDSA and RSA signature algorithms so
the server's Ed25519 TLS key can coexist with common CA signing keys. Do not
issue SHA-1 or MD5-signed certificates.

Concatenate the leaf certificate first, followed by required intermediate
certificates. Do not append the root CA unless your PKI specifically requires
it to be sent (normally it should not be sent by the server):

```sh
cat server-leaf.pem issuing-intermediate.pem > /etc/ssx/server-fullchain.pem
chown root:root /etc/ssx/server-fullchain.pem
chmod 0644 /etc/ssx/server-fullchain.pem
```

The configured chain is limited to 256 KiB and eight certificates. ssxd checks
that the leaf SPKI exactly matches the host key before starting. The PEM file
must be a regular root-owned file, exact mode `0644`, and its path must be
absolute and opened without following symlinks.

### 3. Configure the server

```yaml
host_key: /etc/ssx/host_ed25519
tls:
  certificate_chain: /etc/ssx/server-fullchain.pem
```

The host seed remains root-owned mode `0600`. Only the public certificate is
loaded into the worker TLS context; the TLS signing operation continues through
the existing monitor IPC signer.

### 4. Configure the client

Install the private CA's public certificate in the client's trust store and
configure it:

```yaml
tls:
  ca_bundle: ~/.ssx/ssxpro-ca.pem
known_hosts: ~/.ssx/known_hosts
known_hosts_policy: deny
```

The CA bundle is a PEM trust bundle. The client validates the chain, validates
SAN against the hostname (or IP literal) used for the connection, then performs
the SPKI pin comparison. No application `Hello` or authentication data is sent
until all of those checks succeed.

### 5. Verify configuration

On the server:

```sh
sudo ssxd --config /etc/ssx/ssxd.yaml --check-config
sudo ssxd --config /etc/ssx/ssxd.yaml --print-host-pin
```

Provision the printed pin on each client as described in Mode A. Run the
client's `--check-config`, then establish a test connection from a trusted
network before production rollout.

## Enrollment, rotation, and recovery

- **First install:** distribute the CA root and host SPKI pin through a trusted
  channel before enabling connections.
- **Leaf renewal with the same host key:** issue a renewed leaf certificate
  using the same CSR/key identity. The SPKI pin remains unchanged.
- **Host-key rotation:** distribute and install the new SPKI pin before the
  server begins presenting the new key. Never auto-accept a changed pin.
- **CA rotation:** distribute the new root trust anchor before switching the
  issued chain; remove the old root only after all clients have migrated.
- **Compromise:** remove the affected pin/CA trust, replace the server key or
  issuing CA as appropriate, and investigate all clients that trusted it.
- **Unknown certificate or pin:** treat it as a failed connection, not a
  recoverable prompt to accept without independent verification.

## Test expectations

The release test suite should verify successful CA+SAN+pin connections and
rejection of: untrusted CA, expired/not-yet-valid certificate, invalid chain
signature, missing certificate, missing SAN, wrong DNS SAN, wrong IP SAN,
SPKI mismatch, wrong ALPN, TLS versions other than 1.3, and first-use MITM
attempts. Confirm that `Hello`, `AuthRequest`, and `OpenShell` are not sent for
any failed identity check. Keep tests for the existing nonce/SPKI-bound Ed25519
authentication and protocol state machine.

The default self-signed pin mode intentionally skips CA chain and hostname
validation for compatibility. It still requires an exact pre-provisioned SPKI
pin before application data. Operators who require both PKI validation and
hostname verification must configure `tls.ca_bundle` on clients and
`tls.certificate_chain` on servers.
