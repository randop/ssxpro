"""Focused checks for the PTY test driver's failure detection."""
import unittest
from unittest.mock import patch, Mock
import ssx_e2e as e2e


class BulkChecks(unittest.TestCase):
    def test_exact_sequence_required(self):
        lines = [f"{i}\r\n".encode() for i in range(1, e2e.BULK_LINES + 1)]
        def wrap(values):
            return b"prompt\r\n\x1b]3008;start=test\x1b\\SEQ_BEGIN\r\n" + b"".join(values) + b"SEQ_DONE\r\n"
        self.assertTrue(e2e.validate_bulk_output(wrap(lines)))
        self.assertFalse(e2e.validate_bulk_output(wrap(lines[:-1])))
        changed = list(lines)
        changed[100] = b"changed\r\n"
        self.assertFalse(e2e.validate_bulk_output(wrap(changed)))
        changed[100], changed[101] = lines[101], lines[100]
        self.assertFalse(e2e.validate_bulk_output(wrap(changed)))

    def test_send_deadline_restores_fd(self):
        session = e2e.PtySession.__new__(e2e.PtySession)
        session.fd = 42
        with patch.object(e2e.os, "get_blocking", return_value=True), \
             patch.object(e2e.os, "set_blocking") as mode, \
             patch.object(e2e.time, "monotonic", side_effect=[0, 0, 31]), \
             patch.object(e2e.select, "select", return_value=([], [], [])):
            with self.assertRaises(TimeoutError):
                session.send(b"bulk")
            self.assertEqual(mode.call_args_list[-1].args, (42, True))

    def test_send_timeout_uses_child_cleanup(self):
        session = Mock(output=b"")
        session.send.side_effect = TimeoutError("stalled")
        session.wait_exit.return_value = 0
        with patch.object(e2e, "PtySession", return_value=session):
            self.assertFalse(e2e.run_scenario("timeout", [], [(None, b"bulk")], 0))
        session.wait_exit.assert_called_once_with(timeout=30)


if __name__ == "__main__":
    unittest.main()
