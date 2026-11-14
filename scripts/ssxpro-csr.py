#!/usr/bin/env python3
"""Create an Ed25519 TLS server CSR from ssxd's monitor-protected host seed.

The script reads the same 32-byte seed configured as `host_key`; it never writes
or exports a private key. Run it as the account that owns the protected host
key (root in a production installation).
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import stat
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def read_seed(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("host key must be a regular file")
        if metadata.st_uid != os.geteuid():
            raise ValueError("host key must be owned by the effective user")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("host key must have exact mode 0600")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            seed = stream.read(33)
        if len(seed) != 32:
            raise ValueError("host key must contain exactly 32 raw Ed25519 seed bytes")
        return seed
    finally:
        os.close(fd)


def parse_san(value: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        if not value or len(value) > 253 or value.startswith(".") or value.endswith("."):
            raise argparse.ArgumentTypeError(f"invalid DNS name: {value!r}")
        try:
            value.encode("ascii")
        except UnicodeEncodeError as error:
            raise argparse.ArgumentTypeError("use ASCII DNS names (IDNA A-labels)") from error
        labels = value.split(".")
        if any(
            not label
            or len(label) > 63
            or not label[0].isascii()
            or not label[-1].isascii()
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or any(
                not (character.isascii() and (character.isalnum() or character == "-"))
                for character in label
            )
            for label in labels
        ):
            raise argparse.ArgumentTypeError(f"invalid DNS name: {value!r}")
        return x509.DNSName(value)


def write_new(path: Path, contents: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-key", type=Path, default=Path("/etc/ssx/host_ed25519"))
    parser.add_argument("--dns", action="append", default=[], help="DNS SAN (repeatable)")
    parser.add_argument("--ip", action="append", default=[], help="IP SAN (repeatable)")
    parser.add_argument("--output", type=Path, required=True, help="new CSR output path")
    parser.add_argument("--common-name", help="optional subject CN; SAN remains authoritative")
    args = parser.parse_args()

    if not args.dns and not args.ip:
        parser.error("at least one --dns or --ip Subject Alternative Name is required")

    try:
        names = [parse_san(value) for value in args.dns]
        names.extend(x509.IPAddress(ipaddress.ip_address(value)) for value in args.ip)
        seed = read_seed(args.host_key)
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        common_name = args.common_name or (args.dns[0] if args.dns else args.ip[0])
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        )
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        csr = builder.sign(private_key, algorithm=None)
        pem = csr.public_bytes(serialization.Encoding.PEM)
        write_new(args.output, pem)
        print(f"Wrote CSR: {args.output}")
        print("The CSR public key matches the configured ssxd host key; no private key was exported.")
        return 0
    except (OSError, ValueError, argparse.ArgumentTypeError) as error:
        print(f"ssxpro-csr: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
