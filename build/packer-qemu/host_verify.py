"""Bounded host-side completion observer for the stock Packer/QEMU experiment.

Invoke: python3 -I /absolute/path/host_verify.py --qmp SOCK --serial SOCK
--result FILE --timeout SECONDS --nonce HEX64 --inputs HEX64 [--require-sentinel-evidence]
Python 3.10+ stdlib, Linux only, no environment overrides, no cwd dependence,
no shell, no sudo. Runs as the build user (the same user that runs Packer).

QEMU is launched paused (-S). This sole observer first attaches the serial
receipt reader, then negotiates validated QMP (greeting and version, command
ids, strict response schemas), confirms query-status prelaunch with
running=false and query-kvm present=true enabled=true, and only then sends
`cont`. Duplicate JSON keys, non-finite numbers, invalid UTF-8 or types,
wrong/missing/duplicate ids and return/error conflicts all fail.

Success requires BOTH, from the one QEMU instance this run owns:
  1. a guest receipt line on the private serial socket carrying this run's
     nonce and input digest with status=ok, and
  2. a QMP SHUTDOWN event with data.guest == true and reason "guest-shutdown".
With --require-sentinel-evidence, also require one fixed, run-bound pre-seal
cloud-init summary (done, zero errors/recoverable errors), retained as cloud_init
in the result. Ordinary observations ignore these evidence lines and keep the four-key result.
The receipt alone is never enough: observation continues until a normal guest
shutdown. QEMU process exit, EOF or a vanished socket is never accepted alone.

This process must be the ONLY client of both sockets. They are opened by QEMU
(-qmp ...,server=on,wait=off and -serial unix:...,server=on,wait=off) through
qemuargs, with the builder's own qmp_enable left false: the builder's monitor
is a separate single-client socket whose events go unread (see README).
Neither channel authenticates the guest; the nonce rejects stale receipts only.
"""
import argparse
import json
import math
import os
import re
import selectors
import socket
import stat
import sys
import time

QMP_LINE_MAX = 65536
QMP_TOTAL_MAX = 1 << 20
SERIAL_LINE_MAX = 4096
SERIAL_TOTAL_MAX = 4 << 20
DRAIN_GRACE = 5.0
MIN_QEMU_MAJOR = 4  # SHUTDOWN.reason needs QEMU 4.0+
CONNECT_POLL = 0.05
RECEIPT_PREFIX = b"LABAPP-RECEIPT"
RECEIPT_RE = re.compile(
    rb"^LABAPP-RECEIPT v1 nonce=([0-9a-f]{64}) inputs=([0-9a-f]{64}) status=(ok|fail)$")
EVIDENCE_PREFIX = b"LABAPP-EVIDENCE"
EVIDENCE_RE = re.compile(
    rb"^LABAPP-EVIDENCE v1 nonce=([0-9a-f]{64}) inputs=([0-9a-f]{64}) "
    rb"cloud-init=done errors=0 recoverable=0$")
CLOUD_INIT = {"status": "done", "errors": 0, "recoverable_errors": 0}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Failure(Exception):
    """Fixed, side-channel-free reason code; peer bytes are never echoed."""


def connect(path, deadline, clock):
    """Connect to a socket QEMU creates; tolerates startup races until deadline."""
    while True:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            info = None
        if info is not None:
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
                raise Failure("endpoint-not-owned-socket")
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(path)
                sock.setblocking(False)
                return sock
            except (ConnectionRefusedError, FileNotFoundError):
                sock.close()  # created but not yet listening
            except OSError:
                sock.close()
                raise Failure("connect-error")
        if clock() >= deadline:
            raise Failure("connect-timeout")
        time.sleep(CONNECT_POLL)


class Lines:
    """Newline framing with per-line and total byte bounds."""

    def __init__(self, line_max, total_max, overflow_fatal, protected_prefix=None):
        self.line_max, self.total_max = line_max, total_max
        self.protected_prefix = protected_prefix
        self.fatal, self.buf, self.skipping, self.total = overflow_fatal, b"", False, 0

    def feed(self, data):
        self.total += len(data)
        if self.total > self.total_max:
            raise Failure("output-limit")
        out = []
        for piece in data.splitlines(keepends=True):
            done = piece.endswith(b"\n")
            if self.skipping:
                self.skipping = not done
                continue
            self.buf += piece
            if len(self.buf.rstrip(b"\r\n")) > self.line_max:
                if self.fatal or (self.protected_prefix and self.buf.startswith(self.protected_prefix)):
                    raise Failure("line-limit")
                self.buf, self.skipping = b"", not done  # drop the overlong line
            elif done:
                out.append(self.buf.rstrip(b"\r\n"))
                self.buf = b""
        return out


def _no_dupes(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _no_constant(_name):
    raise ValueError("nonfinite constant")


def _finite_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("nonfinite number")
    return value


def parse_json(line):
    """Strict UTF-8 JSON object: no duplicate keys, NaN/Infinity or non-objects."""
    try:
        msg = json.loads(line.decode("utf-8"), object_pairs_hook=_no_dupes,
                         parse_constant=_no_constant, parse_float=_finite_float)
    except (ValueError, RecursionError):  # UnicodeDecodeError is a ValueError
        raise Failure("qmp-malformed") from None
    if not isinstance(msg, dict):
        raise Failure("qmp-malformed")
    return msg


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def check_greeting(msg):
    """Exactly {"QMP": {"version": {"qemu": {major,minor,micro}}, "capabilities": [..]}}."""
    body = msg.get("QMP")
    if set(msg) != {"QMP"} or not isinstance(body, dict):
        raise Failure("qmp-no-greeting")
    version = body.get("version")
    qemu = version.get("qemu") if isinstance(version, dict) else None
    if (not isinstance(qemu, dict) or not isinstance(body.get("capabilities"), list)
            or not all(_is_int(qemu.get(k)) for k in ("major", "minor", "micro"))):
        raise Failure("qmp-bad-greeting")
    if qemu["major"] < MIN_QEMU_MAJOR:
        raise Failure("qmp-version")


def _empty(ret):
    return isinstance(ret, dict) and not ret


def _prelaunch(ret):
    return (isinstance(ret, dict) and {"status", "running"} <= set(ret)
            and set(ret) <= {"status", "running", "singlestep"}
            and ret["status"] == "prelaunch" and ret["running"] is False)


def _kvm(ret):
    return (isinstance(ret, dict) and set(ret) == {"enabled", "present"}
            and ret["present"] is True and ret["enabled"] is True)


# (command, id, return-value check, failure reason). The guest only starts at
# `cont`, after the serial receipt reader is attached and KVM is confirmed.
STARTUP = (("qmp_capabilities", "hv-1", _empty, "qmp-negotiation"),
           ("query-status", "hv-2", _prelaunch, "qmp-not-prelaunch"),
           ("query-kvm", "hv-3", _kvm, "qmp-kvm-unavailable"),
           ("cont", "hv-4", _empty, "qmp-cont"))


class Qmp:
    """QMP state machine: greeting -> startup commands (one in flight) -> running."""

    def __init__(self):
        self.state, self.step, self.out = "greeting", 0, bytearray()
        self.shutdown_ok = False
        self.inflight = None
        self.cont_sent = False

    def _send_next(self):
        command, ident = STARTUP[self.step][:2]
        self.out += json.dumps({"execute": command, "id": ident}).encode() + b"\n"

    def sent(self, count):
        """Record bytes actually accepted by the socket, separately from queuing."""
        if count < 0 or count > len(self.out):
            raise Failure("qmp-send")
        if count == 0:
            return
        del self.out[:count]
        if not self.out:
            self.inflight = STARTUP[self.step][1]
            if STARTUP[self.step][0] == "cont":
                self.cont_sent = True

    def handle(self, msg):
        if self.state == "greeting":
            check_greeting(msg)
            self.state = "startup"
            self._send_next()
        elif "event" in msg:
            self._event(msg)
        elif set(msg) in ({"return", "id"}, {"error", "id"}):
            self._response(msg)
        else:
            raise Failure("qmp-bad-message")

    def _response(self, msg):
        if self.state != "startup" or self.inflight is None:
            raise Failure("qmp-unexpected-response")
        _, ident, check, reason = STARTUP[self.step]
        if msg["id"] != ident:  # also rejects replays of an already-answered id
            raise Failure("qmp-id-mismatch")
        if "error" in msg or not check(msg["return"]):
            raise Failure(reason)
        self.inflight = None
        self.step += 1
        if self.step == len(STARTUP):
            self.state = "running"
        else:
            self._send_next()

    def _event(self, msg):
        data = msg.get("data")
        if (set(msg) - {"event", "data", "timestamp"} or not isinstance(msg["event"], str)
                or not isinstance(msg.get("timestamp"), dict)
                or ("data" in msg and not isinstance(data, dict))):
            raise Failure("qmp-bad-message")
        if msg["event"] in ("GUEST_PANICKED", "GUEST_CRASHLOADED"):
            raise Failure("guest-panicked")
        if msg["event"] == "RESET":
            raise Failure("guest-reset")
        if msg["event"] != "SHUTDOWN":
            return  # interleaved events (RESUME, STOP, ...) are not evidence
        if not self.cont_sent:
            raise Failure("early-shutdown")
        if self.shutdown_ok:
            raise Failure("duplicate-shutdown")
        if (set(data or {}) != {"guest", "reason"} or data["guest"] is not True
                or data["reason"] != "guest-shutdown"):
            raise Failure("non-guest-shutdown")
        self.shutdown_ok = True


def observe(qmp, serial, nonce, inputs, deadline, clock=time.monotonic,
            require_sentinel_evidence=False):
    """Drive both connected nonblocking sockets to a verdict; raise Failure.

    The serial socket is attached and registered before `cont` is ever sent, so
    the guest cannot run before the receipt reader exists.
    """
    want = (nonce.encode(), inputs.encode())
    qlines = Lines(QMP_LINE_MAX, QMP_TOTAL_MAX, True)
    slines = Lines(SERIAL_LINE_MAX, SERIAL_TOTAL_MAX, False,
                   EVIDENCE_PREFIX if require_sentinel_evidence else None)
    proto, receipt_ok = Qmp(), False
    evidence_ok = False
    qmp_open = serial_open = True
    drain_until = None
    watching_write = False
    sel = selectors.DefaultSelector()
    sel.register(qmp, selectors.EVENT_READ, "qmp")
    sel.register(serial, selectors.EVENT_READ, "serial")
    try:
        while True:
            now = clock()
            if now >= deadline:
                raise Failure("timeout")
            if receipt_ok and proto.shutdown_ok and proto.state == "running":
                if not require_sentinel_evidence or evidence_ok:
                    return dict(CLOUD_INIT) if evidence_ok else None
            if drain_until is not None and (now >= drain_until or not serial_open):
                raise Failure("missing-sentinel-evidence" if receipt_ok else "shutdown-without-receipt")
            if not qmp_open and (not proto.shutdown_ok or proto.state != "running"):
                raise Failure("qmp-eof-before-shutdown")
            if not serial_open and not receipt_ok and not proto.shutdown_ok:
                raise Failure("serial-eof-before-receipt")
            if qmp_open and bool(proto.out) != watching_write:
                watching_write = bool(proto.out)
                sel.modify(qmp, selectors.EVENT_READ
                           | (selectors.EVENT_WRITE if watching_write else 0), "qmp")
            limit = deadline if drain_until is None else min(deadline, drain_until)
            for key, mask in sel.select(max(0.0, min(0.2, limit - now))):
                if key.data == "qmp" and mask & selectors.EVENT_WRITE and proto.out:
                    try:  # nonblocking: a partial write keeps the remainder queued
                        sent = qmp.send(bytes(proto.out))
                    except BlockingIOError:
                        sent = 0
                    except OSError:
                        raise Failure("qmp-send") from None
                    proto.sent(sent)
                if not mask & selectors.EVENT_READ:
                    continue
                try:
                    data = key.fileobj.recv(65536)
                except BlockingIOError:
                    continue
                except OSError:
                    data = b""
                if key.data == "serial":
                    if not data:
                        sel.unregister(serial)
                        serial_open = False
                        continue
                    for line in slines.feed(data):
                        if require_sentinel_evidence and line.startswith(EVIDENCE_PREFIX):
                            found = EVIDENCE_RE.fullmatch(line)
                            if not found:
                                raise Failure("malformed-sentinel-evidence")
                            if evidence_ok:
                                raise Failure("duplicate-sentinel-evidence")
                            if found.groups() != want:
                                raise Failure("stale-or-wrong-sentinel-evidence")
                            evidence_ok = True
                            continue
                        if not line.startswith(RECEIPT_PREFIX):
                            continue
                        found = RECEIPT_RE.match(line)
                        if not found:
                            raise Failure("malformed-receipt")
                        if receipt_ok:
                            raise Failure("duplicate-receipt")
                        if found.group(3) == b"fail":
                            raise Failure("guest-reported-failure")
                        if (found.group(1), found.group(2)) != want:
                            raise Failure("stale-or-wrong-receipt")
                        receipt_ok = True
                    continue
                if not data:
                    sel.unregister(qmp)
                    qmp_open = False
                    continue
                for line in qlines.feed(data):
                    proto.handle(parse_json(line))
                    if proto.shutdown_ok and drain_until is None:
                        drain_until = clock() + DRAIN_GRACE
    finally:
        sel.close()


def write_result(path, nonce, inputs, cloud_init=None):
    result = {"nonce": nonce, "inputs": inputs, "shutdown": "guest-shutdown", "receipt": "ok"}
    if cloud_init is not None:
        result["cloud_init"] = cloud_init
    body = json.dumps(result, sort_keys=True).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(body)
        handle.flush()
        os.fsync(handle.fileno())


def verify(args, clock=time.monotonic):
    deadline = clock() + args.timeout
    qmp = serial = None
    try:
        serial = connect(args.serial, deadline, clock)  # receipt reader first
        qmp = connect(args.qmp, deadline, clock)
        cloud_init = observe(qmp, serial, args.nonce, args.inputs, deadline, clock,
                             getattr(args, "require_sentinel_evidence", False))
        if clock() >= deadline:
            raise Failure("timeout")
        write_result(args.result, args.nonce, args.inputs, cloud_init)
    finally:
        for sock in (qmp, serial):
            if sock is not None:
                sock.close()


def parse(argv):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--qmp", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--timeout", required=True, type=float)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--require-sentinel-evidence", action="store_true")
    args = parser.parse_args(argv)
    if not HEX64.match(args.nonce) or not HEX64.match(args.inputs):
        parser.error("nonce and inputs must be 64 lowercase hex digits")
    if not 1 <= args.timeout <= 3600:
        parser.error("timeout must be 1..3600 seconds")
    for name in ("qmp", "serial", "result"):
        if not os.path.isabs(getattr(args, name)):
            parser.error(name + " path must be absolute")
    return args


def main(argv=None):
    args = parse(sys.argv[1:] if argv is None else argv)
    try:
        verify(args)
    except Failure as exc:
        print("host-verify: failed reason=%s" % exc)
        return 1
    except OSError:
        print("host-verify: failed reason=os-error")
        return 1
    print("host-verify: verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
