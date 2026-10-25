"""Bounded host-side completion observer for the stock Packer/QEMU experiment.

Invoke: python3 -I /absolute/path/host_verify.py --qmp SOCK --serial SOCK
--result FILE --timeout SECONDS --nonce HEX64 --inputs HEX64
Python 3.10+ stdlib, Linux only, no environment overrides, no cwd dependence,
no shell, no sudo. Runs as the build user (the same user that runs Packer).

Success requires BOTH, from the one QEMU instance this run owns:
  1. a guest receipt line on the private serial socket carrying this run's
     nonce and input digest with status=ok, and
  2. a QMP SHUTDOWN event with data.guest == true and reason "guest-shutdown".
QEMU process exit, EOF or a vanished socket is never accepted on its own.

This process must be the ONLY client of both sockets. They are opened by QEMU
(-qmp ...,server=on,wait=off and -serial unix:...,server=on,wait=off) through
qemuargs, with the builder's own qmp_enable left false: the builder's monitor
is a separate single-client socket whose events go unread (see README).
Neither channel authenticates the guest; the nonce rejects stale receipts only.
"""
import argparse
import json
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
CONNECT_POLL = 0.05
RECEIPT_PREFIX = b"LABAPP-RECEIPT"
RECEIPT_RE = re.compile(
    rb"^LABAPP-RECEIPT v1 nonce=([0-9a-f]{64}) inputs=([0-9a-f]{64}) status=(ok|fail)$")
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

    def __init__(self, line_max, total_max, overflow_fatal):
        self.line_max, self.total_max = line_max, total_max
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
                if self.fatal:
                    raise Failure("line-limit")
                self.buf, self.skipping = b"", not done  # drop the overlong line
            elif done:
                out.append(self.buf.rstrip(b"\r\n"))
                self.buf = b""
        return out


def observe(qmp, serial, nonce, inputs, deadline, clock=time.monotonic):
    """Drive both connected nonblocking sockets to a verdict; raise Failure."""
    want = (nonce.encode(), inputs.encode())
    qlines = Lines(QMP_LINE_MAX, QMP_TOTAL_MAX, True)
    slines = Lines(SERIAL_LINE_MAX, SERIAL_TOTAL_MAX, False)
    state, receipt_ok, shutdown_ok = "greeting", False, False
    qmp_open = serial_open = True
    drain_until = None
    sel = selectors.DefaultSelector()
    sel.register(qmp, selectors.EVENT_READ, "qmp")
    sel.register(serial, selectors.EVENT_READ, "serial")
    try:
        while True:
            if receipt_ok and shutdown_ok:
                return
            now = clock()
            if now >= deadline:
                raise Failure("timeout")
            if drain_until is not None and (now >= drain_until or not serial_open):
                raise Failure("shutdown-without-receipt")
            if not qmp_open and not shutdown_ok:
                raise Failure("qmp-eof-before-shutdown")
            if not serial_open and not receipt_ok and not shutdown_ok:
                raise Failure("serial-eof-before-receipt")
            limit = deadline if drain_until is None else min(deadline, drain_until)
            for key, _ in sel.select(max(0.0, min(0.2, limit - now))):
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
                    try:
                        msg = json.loads(line)
                    except ValueError:
                        raise Failure("qmp-malformed") from None
                    if not isinstance(msg, dict):
                        raise Failure("qmp-malformed")
                    if state == "greeting":
                        if "QMP" not in msg:
                            raise Failure("qmp-no-greeting")
                        try:
                            qmp.send(b'{"execute":"qmp_capabilities"}\n')
                        except OSError:
                            raise Failure("qmp-send") from None
                        state = "negotiating"
                    elif state == "negotiating":
                        if "event" in msg:
                            continue
                        if "return" not in msg:
                            raise Failure("qmp-negotiation")
                        state = "events"
                    elif msg.get("event") == "SHUTDOWN":
                        data_ = msg.get("data")
                        if (isinstance(data_, dict) and data_.get("guest") is True
                                and data_.get("reason") == "guest-shutdown"):
                            shutdown_ok = True
                            drain_until = clock() + DRAIN_GRACE
                        else:
                            raise Failure("non-guest-shutdown")
                    elif msg.get("event") == "GUEST_PANICKED":
                        raise Failure("guest-panicked")
    finally:
        sel.close()


def write_result(path, nonce, inputs):
    body = json.dumps({"nonce": nonce, "inputs": inputs, "shutdown": "guest-shutdown",
                       "receipt": "ok"}, sort_keys=True).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(body)
        handle.flush()
        os.fsync(handle.fileno())


def verify(args, clock=time.monotonic):
    deadline = clock() + args.timeout
    qmp = serial = None
    try:
        qmp = connect(args.qmp, deadline, clock)
        serial = connect(args.serial, deadline, clock)
        observe(qmp, serial, args.nonce, args.inputs, deadline, clock)
        write_result(args.result, args.nonce, args.inputs)
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
