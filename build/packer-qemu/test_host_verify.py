"""Offline tests for host_verify.py using fake QEMU-owned sockets.

Each test runs real unix-socket servers in threads that play the part of QEMU's
-qmp and -serial endpoints. They prove the verifier's accept/reject logic and
bounds; they do not prove real QEMU/Packer behavior or guest compatibility.
"""
import argparse
import json
import os
import selectors
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

import host_verify

NONCE = "a1" * 32
INPUTS = "b2" * 32
GREETING = (b'{"QMP":{"version":{"qemu":{"major":8,"minor":2,"micro":2},"package":"x"},'
            b'"capabilities":["oob"]}}\n')
TS = {"seconds": 1, "microseconds": 2}
SHUTDOWN_OK = (b'{"event":"SHUTDOWN","data":{"guest":true,"reason":"guest-shutdown"},'
               b'"timestamp":{"seconds":1,"microseconds":2}}\n')
RETURNS = {"qmp_capabilities": {},
           "query-status": {"status": "prelaunch", "running": False, "singlestep": False},
           "query-kvm": {"enabled": True, "present": True},
           "cont": {}}
ORDER = list(RETURNS)


def ok(ident, ret):
    return json.dumps({"return": ret, "id": ident}).encode() + b"\n"


def event(name, data=None):
    msg = {"event": name, "timestamp": TS}
    if data is not None:
        msg["data"] = data
    return json.dumps(msg).encode() + b"\n"


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
        self.commands = []
        self.serial_event = threading.Event()
        self.serial_attached_at_cont = None

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

    def qmp_script(self, events, greeting=GREETING, reply=None, frag=0, between=False,
                   delay=0.0):
        """Fake QEMU QMP. `reply` maps a command name to bytes or fn(ident)->bytes.

        Records commands in self.commands and whether the serial reader had been
        attached when `cont` arrived (self.serial_attached_at_cont).
        """
        reply = reply or {}

        def put(conn, data):
            if not frag:
                conn.sendall(data)
                return
            for i in range(0, len(data), frag):
                conn.sendall(data[i:i + frag])
                time.sleep(0.002)

        def script(conn):
            put(conn, greeting)
            buf = b""
            for _ in ORDER:
                while b"\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                line, buf = buf.split(b"\n", 1)
                cmd = json.loads(line)
                name, ident = cmd["execute"], cmd["id"]
                self.commands.append(name)
                if name == "cont":
                    self.serial_attached_at_cont = self.serial_event.is_set()
                if between:
                    put(conn, event("STOP"))
                out = reply.get(name)
                if callable(out):
                    out = out(ident)
                put(conn, ok(ident, RETURNS[name]) if out is None else out)
            for pause, data in events:
                time.sleep(pause)
                put(conn, data)
        self.serve(self.qmp, script, delay)

    def serial_script(self, chunks, delay=0.0):
        def script(conn):
            self.serial_event.set()
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

    def reason(self, timeout=5.0, fake=None):
        fake = fake or self.fake
        with self.assertRaises(host_verify.Failure) as caught:
            host_verify.verify(fake.args(timeout))
        self.assertFalse(os.path.exists(fake.result), "no result on failure")
        return str(caught.exception)

    def expect(self, expected, fake_setup, serial=((1.5, b""),)):
        """Run one fresh fake with the given QMP setup and assert the reason."""
        fake = Fake(self)
        fake_setup(fake)
        fake.serial_script(list(serial))
        self.assertEqual(self.reason(fake=fake), expected)

    # --- success paths and ordering -------------------------------------

    def test_receipt_and_guest_shutdown_succeed_and_bind_result(self):
        self.fake.qmp_script([(0.3, SHUTDOWN_OK)])
        self.fake.serial_script([(0.1, b"[    0.1] kernel noise\r\n"), (0.0, b"\n" + receipt())])
        host_verify.verify(self.fake.args())
        with open(self.fake.result) as handle:
            self.assertEqual(json.load(handle), {"nonce": NONCE, "inputs": INPUTS,
                                                 "receipt": "ok", "shutdown": "guest-shutdown"})

    def test_startup_order_and_reader_attached_before_cont(self):
        self.fake.qmp_script([(0.1, SHUTDOWN_OK)])
        self.fake.serial_script([(0.2, receipt())])
        host_verify.verify(self.fake.args())
        self.assertEqual(self.fake.commands, ORDER)
        self.assertTrue(self.fake.serial_attached_at_cont)

    def test_fragmented_responses_and_interleaved_events(self):
        self.fake.qmp_script([(0.1, event("RESUME")), (0.1, SHUTDOWN_OK)], frag=5, between=True)
        self.fake.serial_script([(0.0, receipt()[:20]), (0.3, receipt()[20:])])
        host_verify.verify(self.fake.args())
        self.assertEqual(self.fake.commands, ORDER)

    def test_two_messages_in_one_read_are_both_handled(self):
        # An event and the kvm reply arrive in one read; both must be handled
        # in order and `cont` still follows the valid reply.
        def packed(ident):
            return event("STOP") + ok(ident, RETURNS["query-kvm"])
        self.fake.qmp_script([(0.1, SHUTDOWN_OK)], reply={"query-kvm": packed})
        self.fake.serial_script([(0.2, receipt())])
        host_verify.verify(self.fake.args())
        self.assertEqual(self.fake.commands, ORDER)

    def test_sockets_created_late_and_receipt_split_across_reads(self):
        self.fake.qmp_script([(0.5, SHUTDOWN_OK)], delay=0.4)
        half = receipt()
        self.fake.serial_script([(0.0, half[:30]), (0.2, half[30:])], delay=0.4)
        host_verify.verify(self.fake.args())

    def test_shutdown_before_receipt_is_accepted_if_receipt_drains(self):
        self.fake.qmp_script([(0.1, SHUTDOWN_OK)])
        self.fake.serial_script([(0.3, receipt())])
        host_verify.verify(self.fake.args())

    def test_receipt_alone_keeps_observing_until_shutdown(self):
        self.fake.qmp_script([(0.8, SHUTDOWN_OK)])
        self.fake.serial_script([(0.0, receipt())])
        started = time.monotonic()
        host_verify.verify(self.fake.args())
        self.assertGreaterEqual(time.monotonic() - started, 0.7)

    def test_receipt_without_any_shutdown_times_out(self):
        self.fake.qmp_script([(3.0, b"")])
        self.fake.serial_script([(0.0, receipt()), (3.0, b"")])
        self.assertEqual(self.reason(timeout=1.0), "timeout")

    # --- receipt/shutdown evidence failures -----------------------------

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
                self.assertEqual(self.reason(fake=fake), "stale-or-wrong-receipt")

    def test_guest_reported_failure_and_malformed_and_duplicate_receipts_fail(self):
        cases = {"guest-reported-failure": [receipt(status="fail")],
                 "malformed-receipt": [b"LABAPP-RECEIPT v1 nonce=zz\n"],
                 "duplicate-receipt": [receipt(), receipt()]}
        for expected, chunks in cases.items():
            with self.subTest(expected=expected):
                fake = Fake(self)
                fake.qmp_script([(1.5, SHUTDOWN_OK)])
                fake.serial_script([(0.0, c) for c in chunks] + [(1.5, b"")])
                self.assertEqual(self.reason(fake=fake), expected)

    def test_echoed_receipt_text_inside_other_output_is_ignored(self):
        self.fake.qmp_script([(0.4, SHUTDOWN_OK)])
        self.fake.serial_script([(0.0, b"+ printf LABAPP-RECEIPT v1 nonce=x\n"), (0.0, receipt())])
        host_verify.verify(self.fake.args())

    def test_non_guest_or_malformed_shutdown_events_fail(self):
        cases = (
            (shutdown_event(False, "host-qmp-quit"), "non-guest-shutdown"),
            (shutdown_event(True, "guest-panic"), "non-guest-shutdown"),
            (shutdown_event("true", "guest-shutdown"), "non-guest-shutdown"),
            (shutdown_event(1, "guest-shutdown"), "non-guest-shutdown"),
            (event("SHUTDOWN", {"guest": True}), "non-guest-shutdown"),
            (event("SHUTDOWN", {"guest": True, "reason": "guest-shutdown", "x": 1}),
             "non-guest-shutdown"),
            (event("SHUTDOWN"), "non-guest-shutdown"),
            (b'{"event":"SHUTDOWN","data":{"guest":true,"reason":"guest-shutdown"}}\n',
             "qmp-bad-message"),  # no timestamp
            (event("GUEST_PANICKED", {}), "guest-panicked"),
            # Independent reproduction: duplicate guest key, false then true.
            (b'{"event":"SHUTDOWN","data":{"guest":false,"guest":true,'
             b'"reason":"guest-shutdown"},"timestamp":{"seconds":1,"microseconds":2}}\n',
             "qmp-malformed"),
            (SHUTDOWN_OK + SHUTDOWN_OK, "duplicate-shutdown"))
        for data, expected in cases:
            with self.subTest(data=data):
                self.expect(expected, lambda f, d=data: f.qmp_script([(0.1, d), (1.0, b"")]),
                            serial=[(0.0, receipt()), (1.5, b"")])

    # --- startup / protocol negative tests ------------------------------

    def test_greeting_violations_fail(self):
        good_ver = b'{"version":{"qemu":{"major":8,"minor":2,"micro":2}},"capabilities":[]}'
        cases = (
            (b'{"QMP":null}\n', "qmp-no-greeting"),  # independent reproduction
            (b'{"QMP":{}}\n', "qmp-bad-greeting"),
            (b'{"QMP":[]}\n', "qmp-no-greeting"),
            (b'{"QMP":' + good_ver + b',"extra":1}\n', "qmp-no-greeting"),
            (b'{"QMP":{"version":{"qemu":{"major":8,"minor":2,"micro":2}}}}\n',
             "qmp-bad-greeting"),  # no capabilities
            (b'{"QMP":{"version":{"qemu":{"major":true,"minor":2,"micro":2}},'
             b'"capabilities":[]}}\n', "qmp-bad-greeting"),
            (b'{"QMP":{"version":{"qemu":{"major":"8","minor":2,"micro":2}},'
             b'"capabilities":[]}}\n', "qmp-bad-greeting"),
            (b'{"QMP":{"version":{"qemu":{"major":3,"minor":1,"micro":0}},'
             b'"capabilities":[]}}\n', "qmp-version"),
            (event("STOP"), "qmp-no-greeting"),
            (b'{"return":{},"id":"hv-1"}\n', "qmp-no-greeting"))
        for greeting, expected in cases:
            with self.subTest(greeting=greeting):
                self.expect(expected, lambda f, g=greeting: f.qmp_script([], greeting=g))

    def test_json_level_violations_fail(self):
        lines = (b"not json\n", b"[1]\n", b'"str"\n', b"null\n", b"\xff\xfe{}\n",
                 b'{"return":NaN,"id":"hv-1"}\n', b'{"return":Infinity,"id":"hv-1"}\n',
                 b'{"return":-Infinity,"id":"hv-1"}\n', b'{"return":1e999,"id":"hv-1"}\n',
                 b'{"return":{},"id":"hv-1","id":"hv-1"}\n',
                 b'{"return":{"a":1,"a":2},"id":"hv-1"}\n',
                 b'{"return":{},"id":"hv-1"\n')
        for line in lines:
            with self.subTest(line=line):
                self.expect("qmp-malformed", lambda f, l=line: f.qmp_script(
                    [], reply={"qmp_capabilities": l}))

    def test_response_schema_violations_fail(self):
        def plain(ident):
            return ok(ident, {})
        cases = (
            # independent reproduction: both return and error
            (lambda i: json.dumps({"return": {}, "error": {"class": "x"}, "id": i}).encode()
             + b"\n", "qmp-bad-message"),
            (lambda i: b'{"return":{}}\n', "qmp-bad-message"),  # missing id
            (lambda i: json.dumps({"return": {}, "id": i, "x": 1}).encode() + b"\n",
             "qmp-bad-message"),
            (lambda i: b'{"return":{},"id":"hv-9"}\n', "qmp-id-mismatch"),
            (lambda i: b'{"return":{},"id":null}\n', "qmp-id-mismatch"),
            (lambda i: b'{"return":{},"id":1}\n', "qmp-id-mismatch"),
            (lambda i: json.dumps({"error": {"class": "GenericError", "desc": "x"},
                                   "id": i}).encode() + b"\n", "qmp-negotiation"),
            (lambda i: b'{"error":{"class":"x"}}\n', "qmp-bad-message"),
            (lambda i: ok(i, {"a": 1}), "qmp-negotiation"),
            (lambda i: ok(i, None), "qmp-negotiation"),
            # duplicate response: the answered id again while the next is pending
            (lambda i: plain(i) + plain(i), "qmp-unexpected-response"))
        for make, expected in cases:
            with self.subTest(expected=expected, sample=make("hv-1")):
                self.expect(expected, lambda f, m=make: f.qmp_script(
                    [], reply={"qmp_capabilities": m}))

    def test_prelaunch_and_kvm_gates_fail(self):
        cases = (
            ("query-status", {"status": "running", "running": True}, "qmp-not-prelaunch"),
            ("query-status", {"status": "prelaunch", "running": True}, "qmp-not-prelaunch"),
            ("query-status", {"status": "paused", "running": False}, "qmp-not-prelaunch"),
            ("query-status", {"status": "prelaunch"}, "qmp-not-prelaunch"),
            ("query-status", {"status": "prelaunch", "running": 0}, "qmp-not-prelaunch"),
            ("query-status", {"status": "prelaunch", "running": False, "extra": 1},
             "qmp-not-prelaunch"),
            ("query-kvm", {"enabled": False, "present": True}, "qmp-kvm-unavailable"),
            ("query-kvm", {"enabled": True, "present": False}, "qmp-kvm-unavailable"),
            ("query-kvm", {"enabled": 1, "present": True}, "qmp-kvm-unavailable"),
            ("query-kvm", {"present": True}, "qmp-kvm-unavailable"),
            ("cont", {"x": 1}, "qmp-cont"))
        for name, ret, expected in cases:
            with self.subTest(name=name, ret=ret):
                self.expect(expected, lambda f, n=name, r=ret: f.qmp_script(
                    [], reply={n: lambda i, r=r: ok(i, r)}))

    def test_cont_is_not_sent_after_a_failed_gate(self):
        fake = self.fake
        fake.qmp_script([], reply={"query-kvm": lambda i: ok(i, {"enabled": False,
                                                                 "present": True})})
        fake.serial_script([(1.0, b"")])
        self.assertEqual(self.reason(), "qmp-kvm-unavailable")
        for thread in fake.threads:
            thread.join(11)
        self.assertEqual(fake.commands, ORDER[:3])  # never reached `cont`

    def test_shutdown_before_cont_ack_is_buffered_until_matching_ack(self):
        self.fake.qmp_script([], reply={"cont": lambda i: SHUTDOWN_OK + ok(i, {})})
        self.fake.serial_script([(0.0, receipt())])
        host_verify.verify(self.fake.args())

    def test_shutdown_before_cont_is_sent_fails(self):
        self.expect("early-shutdown", lambda f: f.qmp_script(
            [], reply={"query-kvm": lambda i: SHUTDOWN_OK + ok(i, RETURNS["query-kvm"])}))

    def test_shutdown_without_successful_cont_ack_fails(self):
        for suffix in (b"", ok("wrong-id", {}),
                       b'{"error":{"class":"GenericError"},"id":"hv-4"}\n'):
            with self.subTest(suffix=suffix):
                fake = Fake(self)
                fake.qmp_script([], reply={"cont": lambda i, tail=suffix: SHUTDOWN_OK + tail})
                fake.serial_script([(0.0, receipt())])
                self.reason(fake=fake)

    def test_reset_and_crashloaded_reject_even_before_later_shutdown(self):
        for name, reason in (("RESET", "guest-reset"), ("GUEST_CRASHLOADED", "guest-panicked")):
            with self.subTest(name=name):
                self.expect(reason, lambda f, n=name: f.qmp_script(
                    [(0.1, event(n, {}) + SHUTDOWN_OK)]), serial=[(0.0, receipt())])

    def test_evidence_observed_after_deadline_cannot_succeed(self):
        expired = [False]
        original = host_verify.Qmp._event
        def capture(proto, msg):
            original(proto, msg)
            if proto.shutdown_ok:
                expired[0] = True
        self.fake.qmp_script([(0.2, SHUTDOWN_OK)])
        self.fake.serial_script([(0.0, receipt())])
        with mock.patch.object(host_verify.Qmp, "_event", capture):
            with self.assertRaisesRegex(host_verify.Failure, "timeout"):
                host_verify.verify(self.fake.args(), clock=lambda: 106.0 if expired[0] else 100.0)
        self.assertFalse(os.path.exists(self.fake.result))

    def test_expiry_after_observation_prevents_result_publication(self):
        now = [100.0]
        def observed(*_args):
            now[0] = 106.0
        with mock.patch.object(host_verify, "connect", return_value=mock.Mock()), \
                mock.patch.object(host_verify, "observe", side_effect=observed), \
                mock.patch.object(host_verify, "write_result") as write:
            with self.assertRaisesRegex(host_verify.Failure, "timeout"):
                host_verify.verify(self.fake.args(), clock=lambda: now[0])
        write.assert_not_called()

    def test_panic_during_startup_fails(self):
        self.expect("guest-panicked", lambda f: f.qmp_script(
            [], reply={"query-kvm": lambda i: event("GUEST_PANICKED", {}) + ok(i, {})}))

    def test_unexpected_response_after_startup_fails(self):
        self.expect("qmp-unexpected-response", lambda f: f.qmp_script(
            [(0.0, ok("hv-4", {})), (0.5, SHUTDOWN_OK)]), serial=[(0.0, receipt()), (1.5, b"")])

    def test_malformed_event_envelopes_fail(self):
        for data in (b'{"event":1,"timestamp":{"seconds":1,"microseconds":2}}\n',
                     b'{"event":"X"}\n',
                     b'{"event":"X","timestamp":[]}\n',
                     b'{"event":"X","timestamp":{},"data":[]}\n',
                     b'{"event":"X","timestamp":{},"junk":1}\n'):
            with self.subTest(data=data):
                self.expect("qmp-bad-message", lambda f, d=data: f.qmp_script([(0.0, d)]),
                            serial=[(0.0, receipt()), (1.5, b"")])

    def test_qmp_line_limit_fails(self):
        self.expect("line-limit", lambda f: f.qmp_script(
            [], greeting=b"x" * (host_verify.QMP_LINE_MAX + 10)))

    # --- transport behaviour --------------------------------------------

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
        self.fake.serial_script([(1.0, b"")])
        self.assertEqual(self.reason(), "endpoint-not-owned-socket")

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


def shutdown_event(guest, reason):
    return event("SHUTDOWN", {"guest": guest, "reason": reason})


class CommandTrackingTests(unittest.TestCase):
    def test_response_for_queued_or_partial_command_is_unsolicited(self):
        for count in (0, 1):
            with self.subTest(bytes_sent=count):
                proto = host_verify.Qmp()
                proto.handle(host_verify.parse_json(GREETING))
                proto.sent(count)
                with self.assertRaisesRegex(host_verify.Failure, "qmp-unexpected-response"):
                    proto.handle({"return": {}, "id": "hv-1"})

    def test_queued_next_command_is_not_inflight_after_previous_reply(self):
        proto = host_verify.Qmp()
        proto.handle(host_verify.parse_json(GREETING))
        proto.sent(len(proto.out))
        proto.handle({"return": {}, "id": "hv-1"})
        self.assertTrue(proto.out)
        with self.assertRaisesRegex(host_verify.Failure, "qmp-unexpected-response"):
            proto.handle({"return": RETURNS["query-status"], "id": "hv-2"})


class Trickle:
    """Socket wrapper whose nonblocking send accepts one byte, then would block."""

    def __init__(self, sock):
        self.sock, self.flip, self.sent = sock, False, bytearray()

    def fileno(self):
        return self.sock.fileno()

    def recv(self, size):
        return self.sock.recv(size)

    def send(self, data):
        self.flip = not self.flip
        if self.flip:
            raise BlockingIOError()
        self.sent += data[:1]
        return self.sock.send(data[:1])

    def close(self):
        self.sock.close()


class PartialWriteTests(unittest.TestCase):
    def test_partial_and_blocked_writes_are_resumed(self):
        qmp_host, qmp_peer = socket.socketpair()
        ser_host, ser_peer = socket.socketpair()
        self.addCleanup(lambda: [s.close() for s in (qmp_host, qmp_peer, ser_host, ser_peer)])
        for sock in (qmp_host, ser_host):
            sock.setblocking(False)
        wrapped = Trickle(qmp_host)
        commands = []

        def peer():
            qmp_peer.sendall(GREETING)
            buf = b""
            while len(commands) < len(ORDER):
                buf += qmp_peer.recv(4096)
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    cmd = json.loads(line)
                    commands.append(cmd["execute"])
                    qmp_peer.sendall(ok(cmd["id"], RETURNS[cmd["execute"]]))
            qmp_peer.sendall(SHUTDOWN_OK)
            ser_peer.sendall(receipt())
        thread = threading.Thread(target=peer, daemon=True)
        thread.start()
        host_verify.observe(wrapped, ser_host, NONCE, INPUTS, time.monotonic() + 10)
        thread.join(5)
        self.assertEqual(commands, ORDER)
        self.assertIn(b'"cont"', bytes(wrapped.sent))



def evidence(nonce=NONCE, inputs=INPUTS):
    return (f"LABAPP-EVIDENCE v1 nonce={nonce} inputs={inputs} "
            "cloud-init=done errors=0 recoverable=0\n").encode()


class SentinelEvidenceTests(unittest.TestCase):
    def run_case(self, serial, expected=None, required=True):
        fake = Fake(self)
        fake.qmp_script([(0.05, SHUTDOWN_OK)])
        fake.serial_script([(0.02, serial)])
        args = fake.args(timeout=1)
        args.require_sentinel_evidence = required
        if expected:
            with self.assertRaisesRegex(host_verify.Failure, expected):
                host_verify.verify(args)
            self.assertFalse(os.path.exists(fake.result))
        else:
            host_verify.verify(args)
            with open(fake.result) as handle:
                return json.load(handle)

    def test_required_valid_summary_is_retained_with_existing_binding(self):
        result = self.run_case(evidence() + receipt())
        self.assertEqual(result, {"nonce": NONCE, "inputs": INPUTS, "receipt": "ok",
                                  "shutdown": "guest-shutdown", "cloud_init": host_verify.CLOUD_INIT})

    def test_optional_absent_evidence_keeps_four_keys(self):
        self.assertNotIn("cloud_init", self.run_case(receipt(), required=False))
        self.assertNotIn("cloud_init", self.run_case(b"LABAPP-EVIDENCE arbitrary boot text\n" + receipt(),
                                                    required=False))

    def test_missing_duplicate_stale_malformed_and_non_done_fail(self):
        cases = [(b"", "missing-sentinel-evidence"),
                 (evidence() * 2, "duplicate-sentinel-evidence"),
                 (evidence(nonce="0" * 64), "stale-or-wrong-sentinel-evidence"),
                 (evidence(inputs="0" * 64), "stale-or-wrong-sentinel-evidence"),
                 (evidence().replace(b"done", b"running"), "malformed-sentinel-evidence"),
                 (evidence().replace(b"errors=0", b"errors=1"), "malformed-sentinel-evidence"),
                 (evidence().replace(b"v1 ", b"v1 extra=secret "), "malformed-sentinel-evidence")]
        for line, reason in cases:
            with self.subTest(reason=reason, line=line):
                self.run_case(line + receipt(), reason)

    def test_oversize_evidence_is_not_dropped_like_boot_noise(self):
        self.run_case(evidence().rstrip() + b"x" * host_verify.SERIAL_LINE_MAX + b"\n" + receipt(),
                      "line-limit")
        # Including a valid prefix before excess bytes must not accept a truncation.
        with mock.patch.object(host_verify, "SERIAL_TOTAL_MAX", 16):
            self.run_case(evidence() + receipt(), "output-limit")

    def test_missing_evidence_still_obeys_original_deadline(self):
        fake = Fake(self)
        fake.qmp_script([(0.05, SHUTDOWN_OK)])
        fake.serial_script([(0.02, receipt()), (0.3, b"")])
        args = fake.args(timeout=0.15)
        args.require_sentinel_evidence = True
        with self.assertRaisesRegex(host_verify.Failure, "timeout"):
            host_verify.verify(args)
        self.assertFalse(os.path.exists(fake.result))


if __name__ == "__main__":
    unittest.main()
