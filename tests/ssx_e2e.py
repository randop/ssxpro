#!/usr/bin/env python3
"""End-to-end local test driver for a running ssxd and the ssx client.

The script drives the client over a real PTY and verifies:

  A. login, shell output round-trip, clean exit (client exit code 0)
  B. remote exit status propagation (``exit 7`` -> client exit 7)
  C. authentication rejection with an unauthorized identity
  D. host key mismatch against a pinned known_hosts is a hard failure
  E. idle sessions survive a quiet period thanks to keepalives
  F. the server-selected compression mode reaches the client
  G. bulk data crosses the stream-4 compressor in both directions
  H. an untrusted CA is rejected during the TLS handshake (MITM simulation)
  I. a missing CA bundle refuses the connection (no silent downgrade)
  J. verbose logging shows CA load, mandatory peer verification, ALPN and
     the SPKI pin result

Set ``SSX_E2E_COMPRESSION`` to the server's configured mode (``off``,
``fast``, ``standard`` or ``high``) so scenario F can verify the negotiated
algorithm. ``tests/bootstrap.sh`` exports it from ``SSXD_COMPRESSION``.

TLS scenarios use the CA, server certificate chain, client config, and
unrelated "untrusted" CA that ``tests/bootstrap.sh`` writes under
``SSX_E2E_WORK``. Scenario H is skipped when ``SSX_E2E_UNTRUSTED_CA`` is
not present.

Prerequisites
-------------
* A built client at ``target/debug/ssx`` (or set ``SSX_BIN``).
* A locally running ``ssxd`` (e.g. ``tests/bootstrap.sh start``) bound to
  ``SSX_E2E_HOST:SSX_E2E_PORT`` (default 127.0.0.1:2222) and configured
  with ``tls.certificate_chain`` whose leaf key matches the host key.
* The user's key at ``SSX_E2E_IDENTITY`` (default ``~/.ssx/id_ed25519``)
  is listed in the server-side ``authorized_keys``.
* The server's key pin exists at ``SSX_E2E_KNOWN_HOSTS``
  (default ``~/.ssx/known_hosts``); provision it out of band using
  ``ssxd --print-host-pin`` before running this test.
* The trusted CA certificate exists at ``SSX_E2E_CA_BUNDLE`` and the
  client config at ``SSX_E2E_CLIENT_CONFIG`` sets ``tls.ca_bundle``.
  ``tests/bootstrap.sh`` writes all of these.
* The remote account's shell has ``seq`` and ``sha256sum`` for the bulk
  compression scenario.

The test does not start or stop servers; it only drives clients. All artifacts
are written under ``target/e2e`` unless ``SSX_E2E_WORK`` is set.

Usage::

    python3 tests/ssx_e2e.py
    python3 tests/ssx_e2e.py --self-test

``--self-test`` runs the driver's own failure-detection checks and needs no
server or client.
"""

import base64
import errno
import hashlib
import os
import pty
import re
import select
import signal
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parent.parent
WORK = Path(os.environ.get("SSX_E2E_WORK", REPO / "target" / "e2e"))
SSX = Path(os.environ.get("SSX_BIN", REPO / "target" / "debug" / "ssx"))
HOST = os.environ.get("SSX_E2E_HOST", "127.0.0.1")
PORT = int(os.environ.get("SSX_E2E_PORT", "2222"))
USER = os.environ.get("SSX_E2E_USER", os.environ.get("USER", "root"))
COMPRESSION = os.environ.get("SSX_E2E_COMPRESSION", "off")
COMPRESSION_NAMES = {
    "off": "Off",
    "fast": "Fast",
    "standard": "Standard",
    "high": "High",
}
IDENTITY_SOURCE = Path(
    os.environ.get("SSX_E2E_IDENTITY", Path.home() / ".ssx" / "id_ed25519")
)
KNOWN_HOSTS_SOURCE = Path(
    os.environ.get("SSX_E2E_KNOWN_HOSTS", Path.home() / ".ssx" / "known_hosts")
)
# TLS config and artifacts produced by tests/bootstrap.sh
CLIENT_CONFIG_SOURCE = Path(
    os.environ.get("SSX_E2E_CLIENT_CONFIG", WORK / "client_config.yaml")
)
CA_BUNDLE_SOURCE = Path(os.environ.get("SSX_E2E_CA_BUNDLE", WORK / "ca.pem"))
UNTRUSTED_CA_SOURCE = Path(
    os.environ.get("SSX_E2E_UNTRUSTED_CA", WORK / "ca_untrusted.pem")
)

CONFIG = WORK / "config.yaml"
CONFIG_IDLE = WORK / "config.idle.yaml"
CONFIG_UNTRUSTED_CA = WORK / "config.untrusted-ca.yaml"
CONFIG_MISSING_CA = WORK / "config.missing-ca.yaml"
KNOWN_HOSTS = WORK / "known_hosts"
WRONG_KNOWN_HOSTS = WORK / "known_hosts.wrong"
UNAUTHORIZED_KEY = WORK / "unauthorized_ed25519"
IDENTITY = WORK / "id_ed25519"

# Bulk-data scenario: enough server output to span multiple 64 KiB frames
# and enough client input to span multiple compressed frames in the other
# direction. Input is sent as canonical lines so it works with any login
# shell, including fish; each line stays below the 4096-byte MAX_CANON limit.
BULK_LINES = 20_000
BULK_INPUT_LINES = 64
BULK_INPUT_LINE = (b"ssxpro-compression " * 200)[:2047] + b"\n"
BULK_INPUT = BULK_INPUT_LINE * BULK_INPUT_LINES
BULK_INPUT_DIGEST = hashlib.sha256(BULK_INPUT).hexdigest()

CONFIG_TEMPLATE = """hosts: {{}}
identity: "{identity}"
port: {port}
connect_timeout_secs: 10
handshake_timeout_secs: 15
known_hosts: "{known_hosts}"
known_hosts_policy: "deny"
tls:
  ca_bundle: "{ca_bundle}"
"""


def write_config(known_hosts, path=CONFIG, extra="", ca_bundle=None):
    bundle = ca_bundle if ca_bundle is not None else str(CA_BUNDLE_SOURCE)
    path.write_text(
        CONFIG_TEMPLATE.format(
            identity=IDENTITY, port=PORT, known_hosts=known_hosts, ca_bundle=bundle
        )
        + extra
    )
    os.chmod(path, 0o600)


def host_pin():
    """Return the pinned known_hosts line for HOST:PORT, or exit with advice."""
    target = f"{HOST}:{PORT}"
    try:
        lines = KNOWN_HOSTS_SOURCE.read_text().splitlines()
    except FileNotFoundError:
        lines = []
    for line in lines:
        if line.split()[:1] == [target]:
            return line + "\n"
    print(
        f"missing pin for {target} in {KNOWN_HOSTS_SOURCE}; provision it out of band "
        "using `ssxd --print-host-pin` before running this test",
        file=sys.stderr,
    )
    sys.exit(2)


class PtySession:
    def __init__(self, argv):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.environ["TERM"] = "xterm-256color"
            os.execv(SSX, [str(SSX)] + argv)
        self.output = b""
        self.answer_queries = True

    def _read_chunk(self):
        try:
            chunk = os.read(self.fd, 65536)
        except OSError as exc:
            if exc.errno == errno.EIO:  # child closed the PTY
                return False
            raise
        if not chunk:
            return False
        self.output += chunk
        if self.answer_queries:
            # Answer basic terminal queries so fish does not stall for 10 seconds.
            if b"\x1b[c" in chunk:
                os.write(self.fd, b"\x1b[?62;c")
            if b"\x1b[6n" in chunk:
                os.write(self.fd, b"\x1b[1;1R")
        return True

    def _pump_once(self, timeout):
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return False
        return self._read_chunk()

    def wait_for(self, needle, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if isinstance(needle, str):
                if needle.encode() in self.output:
                    return True
            elif re.search(needle, self.output):
                return True
            self._pump_once(0.25)
        return False

    def send(self, data, timeout=30):
        # Bulk input can exceed both the local and remote PTY buffers. Keep
        # draining client output while writing so neither side can deadlock.
        was_blocking = os.get_blocking(self.fd)
        os.set_blocking(self.fd, False)
        try:
            deadline = time.monotonic() + timeout
            view = memoryview(data)
            while view:
                if time.monotonic() >= deadline:
                    raise TimeoutError("timed out sending data to PTY")
                readable, writable, _ = select.select([self.fd], [self.fd], [], 0.25)
                if readable:
                    self._read_chunk()
                if not writable:
                    continue
                try:
                    written = os.write(self.fd, view[:4096])
                except BlockingIOError:
                    continue
                if written == 0:
                    raise OSError("short write to PTY")
                view = view[written:]
        finally:
            os.set_blocking(self.fd, was_blocking)

    def wait_exit(self, timeout=30):
        deadline = time.time() + timeout
        status = None
        while time.time() < deadline:
            pid, st = os.waitpid(self.pid, os.WNOHANG)
            if pid == self.pid:
                status = st
                break
            self._pump_once(0.25)
        if status is None:
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
            return None
        while self._pump_once(0.05):  # drain what is left
            pass
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status)
        if os.WIFSIGNALED(status):
            return 128 + os.WTERMSIG(status)
        return -1


def run_scenario(name, argv, steps, expect_status, expect_output=(), forbid_output=(), validate_output=None):
    """Run one client session.

    Steps are one of:
      * ``"text"``          - wait until the output contains text
      * ``("text", data)``  - wait, then send data
      * ``(None, data)``    - send data without waiting
      * a number           - sleep that many seconds
      * a callable         - call it with the session (for mode toggles)
    """
    session = PtySession(argv)
    ok = True
    try:
        for step in steps:
            if callable(step):
                step(session)
                continue
            if isinstance(step, (int, float)):
                time.sleep(step)
                continue
            if step[0] is None:
                session.send(step[1])
                continue
            needle, payload = step
            if not session.wait_for(needle, timeout=30):
                print(f"[{name}] FAIL: timed out waiting for {needle!r}")
                print(session.output[-2000:].decode(errors="replace"))
                ok = False
                break
            if payload:
                session.send(payload)
    except TimeoutError as exc:
        print(f"[{name}] FAIL: {exc}")
        ok = False
    status = session.wait_exit(timeout=30)
    if status != expect_status:
        print(f"[{name}] FAIL: exit status {status}, expected {expect_status}")
        ok = False
    for needle in expect_output:
        if needle.encode() not in session.output:
            print(f"[{name}] FAIL: output missing {needle!r}")
            ok = False
    for needle in forbid_output:
        if needle.encode() in session.output:
            print(f"[{name}] FAIL: output unexpectedly contains {needle!r}")
            ok = False
    if validate_output is not None and not validate_output(session.output):
        print(f"[{name}] FAIL: bulk output differs from expected sequence")
        ok = False
    if not ok:
        print(f"[{name}] output tail:")
        print(session.output[-3000:].decode(errors="replace"))
    else:
        print(f"[{name}] PASS (exit {status})")
    return ok


def validate_bulk_output(output):
    normalized = output.replace(b"\r\n", b"\n")
    match = re.search(rb"SEQ_BEGIN\n(.*?)SEQ_DONE\n", normalized, re.DOTALL)
    expected = b"".join(f"{i}\n".encode() for i in range(1, BULK_LINES + 1))
    return match is not None and match.group(1) == expected


class BulkChecks(unittest.TestCase):
    """Focused checks for the PTY test driver's failure detection."""

    def test_exact_sequence_required(self):
        lines = [f"{i}\r\n".encode() for i in range(1, BULK_LINES + 1)]

        def wrap(values):
            return (
                b"prompt\r\n\x1b]3008;start=test\x1b\\SEQ_BEGIN\r\n"
                + b"".join(values)
                + b"SEQ_DONE\r\n"
            )

        self.assertTrue(validate_bulk_output(wrap(lines)))
        self.assertFalse(validate_bulk_output(wrap(lines[:-1])))
        changed = list(lines)
        changed[100] = b"changed\r\n"
        self.assertFalse(validate_bulk_output(wrap(changed)))
        changed[100], changed[101] = lines[101], lines[100]
        self.assertFalse(validate_bulk_output(wrap(changed)))

    def test_send_deadline_restores_fd(self):
        session = PtySession.__new__(PtySession)
        session.fd = 42
        with patch.object(os, "get_blocking", return_value=True), \
             patch.object(os, "set_blocking") as mode, \
             patch.object(time, "monotonic", side_effect=[0, 0, 31]), \
             patch.object(select, "select", return_value=([], [], [])):
            with self.assertRaises(TimeoutError):
                session.send(b"bulk")
            self.assertEqual(mode.call_args_list[-1].args, (42, True))

    def test_send_timeout_uses_child_cleanup(self):
        session = Mock(output=b"")
        session.send.side_effect = TimeoutError("stalled")
        session.wait_exit.return_value = 0
        with patch.object(sys.modules[__name__], "PtySession", return_value=session):
            self.assertFalse(run_scenario("timeout", [], [(None, b"bulk")], 0))
        session.wait_exit.assert_called_once_with(timeout=30)


def main():
    if not SSX.exists():
        print(f"client binary not found: {SSX} (build it or set SSX_BIN)", file=sys.stderr)
        return 2
    if not KNOWN_HOSTS_SOURCE.exists():
        print(f"known_hosts not found: {KNOWN_HOSTS_SOURCE}", file=sys.stderr)
        return 2
    if not CLIENT_CONFIG_SOURCE.exists():
        print(f"client config not found: {CLIENT_CONFIG_SOURCE} (run tests/bootstrap.sh first)", file=sys.stderr)
        return 2
    if not CA_BUNDLE_SOURCE.exists():
        print(f"CA bundle not found: {CA_BUNDLE_SOURCE} (run tests/bootstrap.sh first)", file=sys.stderr)
        return 2
    if COMPRESSION not in COMPRESSION_NAMES:
        print(
            "SSX_E2E_COMPRESSION must be one of: "
            + ", ".join(COMPRESSION_NAMES)
            + f" (got {COMPRESSION!r})",
            file=sys.stderr,
        )
        return 2

    WORK.mkdir(parents=True, exist_ok=True)
    os.chmod(WORK, 0o700)
    # The scenario configs are written below by write_config(); the
    # bootstrap-generated client config is only checked for presence above
    # so the CA bundle, pin file, and TLS policy are guaranteed coherent.
    IDENTITY.write_bytes(IDENTITY_SOURCE.read_bytes())
    os.chmod(IDENTITY, 0o600)
    UNAUTHORIZED_KEY.write_bytes(os.urandom(32))
    os.chmod(UNAUTHORIZED_KEY, 0o600)
    KNOWN_HOSTS.write_text(host_pin())
    os.chmod(KNOWN_HOSTS, 0o600)
    # Wrong pin: valid syntax, wrong 32-byte hash.
    WRONG_KNOWN_HOSTS.write_text(
        f"{HOST}:{PORT} spki-sha256 {base64.b64encode(bytes(32)).decode()}\n"
    )
    os.chmod(WRONG_KNOWN_HOSTS, 0o600)

    base = [
        f"{USER}@{HOST}",
        "--port",
        str(PORT),
        "--config",
        str(CONFIG),
        "--identity",
        str(IDENTITY),
        "-v",
    ]
    results = []

    write_config(KNOWN_HOSTS)
    results.append(
        run_scenario(
            "A-shell-roundtrip",
            base,
            [
                # The client opens stream 4 itself; the prompt must appear
                # without the user typing anything.
                ("terminal raw mode enabled", b"printf 'SSX_%s\\n' READY\r"),
                ("SSX_READY", b"uname -s\r"),
                ("Linux", b"printf 'MARK_%s\\n' 42\r"),
                ("MARK_42", b"exit\r"),
            ],
            expect_status=0,
            expect_output=("Linux", "MARK_42", "kind=Status, value=0"),
        )
    )

    results.append(
        run_scenario(
            "B-remote-exit-status",
            base,
            [("terminal raw mode enabled", b"printf 'SSX_%s\\n' READY\r"), ("SSX_READY", b"exit 7\r")],
            expect_status=7,
            expect_output=("kind=Status, value=7",),
        )
    )

    compression_name = COMPRESSION_NAMES[COMPRESSION]
    compression_expected = [f"compression={compression_name}"]
    compression_forbidden = []
    if COMPRESSION == "off":
        compression_forbidden.append("stream compression enabled (")
    else:
        compression_expected.append(f"stream compression enabled ({compression_name})")
    results.append(
        run_scenario(
            "F-compression-negotiation",
            base,
            [("terminal raw mode enabled", b"exit\r")],
            expect_status=0,
            expect_output=compression_expected,
            forbid_output=compression_forbidden,
        )
    )

    bulk_command = (
        b"printf 'SEQ_%s\\n' BEGIN; seq 1 "
        + str(BULK_LINES).encode()
        + b"; printf 'SEQ_%s\\n' DONE\r"
        b"printf 'BULK_%s\\n' READY; sha256sum; printf 'BULK_%s\\n' DONE\r"
    )
    results.append(
        run_scenario(
            "G-compression-bulk-data",
            base,
            [
                ("terminal raw mode enabled", b"printf 'SSX_%s\\n' READY\r"),
                ("SSX_READY", None),
                lambda session: setattr(session, "answer_queries", False),
                (None, bulk_command),
                ("SEQ_DONE", None),
                ("BULK_READY", BULK_INPUT + b"\x04"),
                (BULK_INPUT_DIGEST, None),
                lambda session: setattr(session, "answer_queries", True),
                ("BULK_DONE", b"exit\r"),
            ],
            expect_status=0,
            expect_output=("SEQ_DONE", "BULK_DONE", BULK_INPUT_DIGEST, "kind=Status, value=0"),
            validate_output=validate_bulk_output,
        )
    )

    # Short idle timeout with frequent client keepalives: the session must
    # survive a quiet period longer than idle_timeout_secs.
    write_config(
        KNOWN_HOSTS,
        path=CONFIG_IDLE,
        extra=(
            "idle_timeout_secs: 12\n"
            "server_alive_interval_secs: 3\n"
            "server_alive_count_max: 3\n"
        ),
    )
    idle_base = list(base)
    idle_base[idle_base.index(str(CONFIG))] = str(CONFIG_IDLE)
    results.append(
        run_scenario(
            "E-idle-keepalive",
            idle_base,
            [
                # After shell readiness, the session must survive a quiet period longer
                # than the client idle timeout thanks to keepalive pings.
                ("terminal raw mode enabled", b"printf 'SSX_%s\\n' READY\r"),
                ("SSX_READY", None),
                15,
                (None, b"printf 'IDLE_%s\\n' ok\r"),
                ("IDLE_ok", b"exit\r"),
            ],
            expect_status=0,
            expect_output=("IDLE_ok", "kind=Status, value=0"),
        )
    )

    results.append(
        run_scenario(
            "C-auth-rejected",
            [
                f"{USER}@{HOST}",
                "--port",
                str(PORT),
                "--config",
                str(CONFIG),
                "--identity",
                str(UNAUTHORIZED_KEY),
            ],
            [],
            expect_status=255,
            expect_output=("ssx:",),
        )
    )

    write_config(WRONG_KNOWN_HOSTS)
    results.append(
        run_scenario(
            "D-host-key-mismatch",
            base,
            [],
            expect_status=255,
            expect_output=("WARNING: REMOTE HOST KEY HAS CHANGED",),
            forbid_output=("authentication succeeded",),
        )
    )

    # H: an unrelated CA must be rejected during the TLS handshake, before
    # any application message (Hello/AuthRequest) is sent.
    if UNTRUSTED_CA_SOURCE.exists():
        write_config(
            KNOWN_HOSTS, path=CONFIG_UNTRUSTED_CA, ca_bundle=str(UNTRUSTED_CA_SOURCE)
        )
        untrusted_base = list(base)
        untrusted_base[untrusted_base.index(str(CONFIG))] = str(CONFIG_UNTRUSTED_CA)
        results.append(
            run_scenario(
                "H-tls-untrusted-ca",
                untrusted_base,
                [],
                expect_status=255,
                expect_output=("ssx:",),
                forbid_output=(
                    "authentication succeeded",
                    "host key verified",
                    "sent client hello",
                ),
            )
        )
    else:
        print(f"[H-tls-untrusted-ca] SKIP: {UNTRUSTED_CA_SOURCE} not present")
        results.append(True)

    # I: a missing CA bundle must refuse the connection instead of silently
    # falling back to unverified TLS.
    write_config(
        KNOWN_HOSTS,
        path=CONFIG_MISSING_CA,
        ca_bundle=str(WORK / "does-not-exist-ca.pem"),
    )
    missing_base = list(base)
    missing_base[missing_base.index(str(CONFIG))] = str(CONFIG_MISSING_CA)
    results.append(
        run_scenario(
            "I-tls-missing-ca-bundle",
            missing_base,
            [],
            expect_status=255,
            expect_output=("ssx:",),
            forbid_output=("authentication succeeded", "host key verified"),
        )
    )

    # J: verbose TLS policy logging must show CA loading, mandatory chain
    # verification, SAN matching, the negotiated ALPN, and the SPKI pin result.
    write_config(KNOWN_HOSTS)
    debug_base = list(base)
    debug_base[debug_base.index("-v")] = "-vv"
    results.append(
        run_scenario(
            "J-tls-verification-debug",
            debug_base,
            [("terminal raw mode enabled", b"exit\r")],
            expect_status=0,
            expect_output=(
                "TLS certificate-chain verification enabled",
                "loading CA bundle",
                'negotiated ALPN: "ssxpro/1"',
                "certificate SAN matched",
                "SPKI pin matched for",
                "host certificate and SPKI identity verified for",
            ),
            forbid_output=("peer verification disabled",),
        )
    )

    print()
    if all(results):
        print(f"e2e: {len(results)}/{len(results)} scenarios passed")
        return 0
    print(f"e2e: {sum(results)}/{len(results)} scenarios passed")
    return 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.argv.remove("--self-test")
        unittest.main()
    else:
        sys.exit(main())
