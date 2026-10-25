"""Offline tests for host_verify.py using fake QEMU-owned sockets.

Each test runs real unix-socket servers in threads that play the part of QEMU's
-qmp and -serial endpoints. They prove the verifier's accept/reject logic and
bounds; they do not prove real QEMU/Packer behavior or guest compatibility.
"""
import argparse
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

import host_verify

NONCE = "a1" * 32
INPUTS = "b2" * 32
GREETING = b'{"QMP":{"version":{"qemu":{"major":8}},"capabilities":[]}}\n'
SHUTDOWN_OK = (b'{"event":"SHUTDOWN","data":{"guest":true,"reason":"guest-shutdown"},'
               b'"timestamp":{"seconds":1,"microseconds":2}}\n')


def receipt(nonce=NONCE, inputs=INPUTS, status="ok"):
    return ("LABAPP-RECEIPT v1 nonce=%s inputs=%s status=%s\n" % (nonce, inputs, status)).encode()


class Fake:
    """Owns fake QEMU endpoints in a private temp dir; joins every thread."""

    def __init__(self, test):
        self.dir = tempfile.mkdtemp(prefix="hv-test-")
        test.addCleanup(self.close)
        self.qmp, self.serial = (os.path.join(self.dir, n) for n in ("q.sock", "s.sock"))
        self.result = os.path.join(self.dir, "verified.json")
        self.threads = []

    def serve(self, path, script, delay=0.0):
        def run():
            time.sleep(delay)
            srv = socket.socket(socket.AF_UNIX)
            srv.bind(path)
            srv.listen(1)
            srv.settimeout(10)
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                script(conn)
            except OSError:
                pass
            finally:
                conn.close()
                srv.close()
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.threads.append(thread)

    def qmp_script(self, events, handshake=True):
        def script(conn):
            conn.sendall(GREETING)
            if handshake:
                conn.recv(4096)
                conn.sendall(b'{"return":{}}\n')
            for delay, data in events:
                time.sleep(delay)
                conn.sendall(data)
        self.serve(self.qmp, script)

    def serial_script(self, chunks, delay=0.0):
        def script(conn):
            for pause, data in chunks:
                time.sleep(pause)
                conn.sendall(data)
        self.serve(self.serial, script, delay)

    def args(self, timeout=5.0):
        return argparse.Namespace(qmp=self.qmp, serial=self.serial, result=self.result,
                                  timeout=timeout, nonce=NONCE, inputs=INPUTS)

    def close(self):
        for thread in self.threads:
            thread.join(11)
        for name in os.listdir(self.dir):
            os.unlink(os.path.join(self.dir, name))
        os.rmdir(self.dir)


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.fake = Fake(self)
        patcher = mock.patch.object(host_verify, "DRAIN_GRACE", 0.6)
        patcher.start()
        self.addCleanup(patcher.stop)

    def reason(self, timeout=5.0):
        with self.assertRaises(host_verify.Failure) as caught:
            host_verify.verify(self.fake.args(timeout))
        self.assertFalse(os.path.exists(self.fake.result), "no result on failure")
        return str(caught.exception)

    def test_receipt_and_guest_shutdown_succeed_and_bind_result(self):
        self.fake.qmp_script([(0.3, SHUTDOWN_OK)])
        self.fake.serial_script([(0.1, b"[    0.1] kernel noise\r\n"), (0.0, b"\n" + receipt())])
        host_verify.verify(self.fake.args())
        with open(self.fake.result) as handle:
            self.assertEqual(json.load(handle), {"nonce": NONCE, "inputs": INPUTS,
                                                 "receipt": "ok", "shutdown": "guest-shutdown"})

    def test_sockets_created_late_and_receipt_split_across_reads(self):
        self.fake.serve(self.fake.qmp, lambda c: (
            c.sendall(GREETING), c.recv(4096), c.sendall(b'{"return":{}}\n'),
            time.sleep(0.5), c.sendall(SHUTDOWN_OK)), delay=0.4)
        half = receipt()
        self.fake.serial_script([(0.0, half[:30]), (0.2, half[30:])], delay=0.4)
        host_verify.verify(self.fake.args())

    def test_shutdown_before_receipt_is_accepted_if_receipt_drains(self):
        self.fake.qmp_script([(0.1, SHUTDOWN_OK)])
        self.fake.serial_script([(0.3, receipt())])
        host_verify.verify(self.fake.args())

    def test_guest_shutdown_without_receipt_fails(self):
        self.fake.qmp_script([(0.1, SHUTDOWN_OK)])
        self.fake.serial_script([(0.0, b"kernel noise only\n"), (2.0, b"")])
        self.assertEqual(self.reason(), "shutdown-without-receipt")

    def test_receipt_but_abrupt_qemu_exit_is_not_success(self):
        self.fake.qmp_script([])  # closes without SHUTDOWN: process death/EOF
        self.fake.serial_script([(0.0, receipt()), (1.0, b"")])
        self.assertEqual(self.reason(), "qmp-eof-before-shutdown")

    def test_serial_eof_without_any_evidence_fails(self):
        self.fake.qmp_script([(2.0, b"")])
        self.fake.serial_script([])
        self.assertEqual(self.reason(), "serial-eof-before-receipt")

    def test_stale_or_wrong_receipts_fail(self):
        for bad in (receipt(nonce="c3" * 32), receipt(inputs="d4" * 32)):
            with self.subTest(bad=bad[:40]):
                fake = Fake(self)
                fake.qmp_script([(1.0, SHUTDOWN_OK)])
                fake.serial_script([(0.0, bad), (1.5, b"")])
                with self.assertRaises(host_verify.Failure) as caught:
                    host_verify.verify(fake.args())
                self.assertEqual(str(caught.exception), "stale-or-wrong-receipt")

    def test_guest_reported_failure_and_malformed_and_duplicate_receipts_fail(self):
        cases = {"guest-reported-failure": [receipt(status="fail")],
                 "malformed-receipt": [b"LABAPP-RECEIPT v1 nonce=zz\n"],
                 "duplicate-receipt": [receipt(), receipt()]}
        for expected, chunks in cases.items():
            with self.subTest(expected=expected):
                fake = Fake(self)
                fake.qmp_script([(1.5, SHUTDOWN_OK)])
                fake.serial_script([(0.0, c) for c in chunks] + [(1.5, b"")])
                with self.assertRaises(host_verify.Failure) as caught:
                    host_verify.verify(fake.args())
                self.assertEqual(str(caught.exception), expected)

    def test_echoed_receipt_text_inside_other_output_is_ignored(self):
        self.fake.qmp_script([(0.4, SHUTDOWN_OK)])
        self.fake.serial_script([(0.0, b"+ printf LABAPP-RECEIPT v1 nonce=x\n"), (0.0, receipt())])
        host_verify.verify(self.fake.args())

    def test_non_guest_shutdown_events_fail(self):
        for data in (b'{"event":"SHUTDOWN","data":{"guest":false,"reason":"host-qmp-quit"}}\n',
                     b'{"event":"SHUTDOWN","data":{"guest":true,"reason":"guest-panic"}}\n',
                     b'{"event":"SHUTDOWN"}\n',
                     b'{"event":"GUEST_PANICKED","data":{}}\n'):
            with self.subTest(data=data):
                fake = Fake(self)
                fake.qmp_script([(0.1, data), (1.0, b"")])
                fake.serial_script([(0.0, receipt()), (1.5, b"")])
                with self.assertRaises(host_verify.Failure):
                    host_verify.verify(fake.args())

    def test_silence_times_out_within_bound(self):
        self.fake.qmp_script([(3.0, b"")])
        self.fake.serial_script([(3.0, b"")])
        started = time.monotonic()
        self.assertEqual(self.reason(timeout=1.0), "timeout")
        self.assertLess(time.monotonic() - started, 2.5)

    def test_missing_sockets_time_out(self):
        self.assertEqual(self.reason(timeout=1.0), "connect-timeout")

    def test_non_socket_endpoint_is_rejected(self):
        open(self.fake.qmp, "w").close()
        self.assertEqual(self.reason(), "endpoint-not-owned-socket")

    def test_qmp_protocol_violations_fail(self):
        for script, expected in (
                (lambda c: c.sendall(b"not json\n"), "qmp-malformed"),
                (lambda c: c.sendall(b'{"event":"X"}\n'), "qmp-no-greeting"),
                (lambda c: (c.sendall(GREETING), c.recv(4096),
                            c.sendall(b'{"error":{"class":"x"}}\n')), "qmp-negotiation"),
                (lambda c: c.sendall(b"[1]\n"), "qmp-malformed"),
                (lambda c: c.sendall(b"x" * (host_verify.QMP_LINE_MAX + 10)), "line-limit")):
            with self.subTest(expected=expected):
                fake = Fake(self)
                fake.serve(fake.qmp, script)
                fake.serial_script([(1.5, b"")])
                with self.assertRaises(host_verify.Failure) as caught:
                    host_verify.verify(fake.args())
                self.assertEqual(str(caught.exception), expected)

    def test_serial_total_output_is_bounded(self):
        self.fake.qmp_script([(3.0, b"")])
        flood = b"k" * 1000 + b"\n"
        self.fake.serial_script([(0.0, flood * 600) for _ in range(8)])
        with mock.patch.object(host_verify, "SERIAL_TOTAL_MAX", 1 << 20):
            self.assertEqual(self.reason(), "output-limit")

    def test_overlong_serial_line_is_skipped_not_fatal(self):
        self.fake.qmp_script([(0.5, SHUTDOWN_OK)])
        junk = b"j" * (host_verify.SERIAL_LINE_MAX * 3) + b"\n"
        self.fake.serial_script([(0.0, junk), (0.0, receipt())])
        host_verify.verify(self.fake.args())

    def test_result_file_is_never_overwritten(self):
        with open(self.fake.result, "w") as handle:
            handle.write("stale")
        with self.assertRaises(FileExistsError):
            host_verify.write_result(self.fake.result, NONCE, INPUTS)

    def test_argument_validation(self):
        good = ["--qmp", "/q", "--serial", "/s", "--result", "/r", "--timeout", "5",
                "--nonce", NONCE, "--inputs", INPUTS]
        host_verify.parse(good)
        for bad in (["--nonce", "XYZ"], ["--timeout", "0"], ["--timeout", "99999"],
                    ["--qmp", "relative"]):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                host_verify.parse(good + bad)


if __name__ == "__main__":
    unittest.main()
