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
With --expiry-witness FILE (fixed expiry proof, mutually exclusive with success mode) the
observer never succeeds: after `cont` is acknowledged it requires query-status running,
`stop`, then query-status paused, writes ONE bounded armed witness bound to this run's
nonce and inputs, and keeps both sockets until the container's own timer ends the proof.
Any guest receipt, SHUTDOWN event or socket EOF afterwards is a failure.
With --require-sentinel-evidence, also require one fixed, run-bound pre-seal
cloud-init summary (done, zero errors/recoverable errors), retained as cloud_init
in the result. Ordinary observations ignore these evidence lines and keep the four-key result.
In the same mode one optional, strict `LABAPP-QEMU v2 ...` (TAP unrun) or `v3 ...` (finite TAP witness) line (fixed literals plus bounded
integers/flags, run-bound by nonce and inputs, at most one) is retained as the closed
`qemu_witness` object; anything malformed, duplicate or stale fails. The observer does not
require it: the runner requires it for `qemu-fixture` and rejects it for every other mode.
In the same mode, one run-bound `LABAPP-DIAG v1 ... step=N exit=N reason=token` line sent before
a failing receipt adds only those three fixed-shape fields to the failure reason. The observer
never prints other guest bytes.
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
DIAG_PREFIX = b"LABAPP-DIAG"
DIAG_RE = re.compile(
    rb"^LABAPP-DIAG v1 nonce=([0-9a-f]{64}) inputs=([0-9a-f]{64}) "
    rb"step=([0-9]{1,2}) exit=([0-9]{1,3}) reason=([a-z][a-z0-9-]{0,31})$")
# Fixed `qemu-fixture` guest summary (guest/assert-qemu.py). Every field is a literal or a bounded
# integer/flag; the guest emits it only after its own installer/witness checks passed, and the
# runner independently revalidates the resulting object. Nothing else from the guest is kept.
QEMU_PREFIX = b"LABAPP-QEMU"
# v2 keeps its meaning (TAP creation unrun). v3 is the explicit successor schema that adds ONE finite
# ephemeral TAP witness: absent before, present while the guest owned the descriptor, absent after.
_QEMU_BODY = (
    rb"nonce=([0-9a-f]{64}) inputs=([0-9a-f]{64}) "
    rb"accel=kvm exit=33 uid=0 equal=1 backing=1 removed=1 "
    rb"i1=1:([0-9]{1,3}) i2=0:([0-9]{1,3}) w=([0-9]{1,3}) net=([01])([01])([01]) "
    rb"sudo=([0-9][A-Za-z0-9.+:~\-]{0,63}):([0-9a-f]{64}) "
    rb"ssh=([0-9][A-Za-z0-9.+:~\-]{0,63}):([0-9a-f]{64}) "
    rb"less=([0-9][A-Za-z0-9.+:~\-]{0,63}):([0-9a-f]{64}) "
    rb"caller=1000 sudo_uid=0 arch=amd64 tun_open=1 tun_api=1 tap_flag=1 tap_create=")
QEMU_RE = re.compile(rb"^LABAPP-QEMU v2 " + _QEMU_BODY + rb"unrun$")
QEMU_TAP_RE = re.compile(
    rb"^LABAPP-QEMU v3 " + _QEMU_BODY
    + rb"passed tap_before=absent tap_owned=present tap_after=absent tap_s=(10|[0-9])$")
CLOUD_INIT = {"status": "done", "errors": 0, "recoverable_errors": 0}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ARMED_KIND = "labapp-expiry-armed v1"


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


def _status(ret, status, running):
    return (isinstance(ret, dict) and {"status", "running"} <= set(ret)
            and set(ret) <= {"status", "running", "singlestep"}
            and ret["status"] == status and ret["running"] is running)


def _running(ret):
    return _status(ret, "running", True)


def _paused(ret):
    return _status(ret, "paused", False)


# Expiry proof only, after `cont` is acknowledged: running, stop, paused.
EXPIRY_STEPS = (("query-status", "hv-5", _running, "qmp-not-running"),
                ("stop", "hv-6", _empty, "qmp-stop"),
                ("query-status", "hv-7", _paused, "qmp-not-paused"))


class Qmp:
    """QMP state machine: greeting -> startup commands (one in flight) -> running."""

    def __init__(self, expiry=False):
        self.expiry = expiry
        self.steps = STARTUP + EXPIRY_STEPS if expiry else STARTUP
        self.state, self.step, self.out = "greeting", 0, bytearray()
        self.shutdown_ok = False
        self.inflight = None
        self.cont_sent = False

    def _send_next(self):
        command, ident = self.steps[self.step][:2]
        self.out += json.dumps({"execute": command, "id": ident}).encode() + b"\n"

    def sent(self, count):
        """Record bytes actually accepted by the socket, separately from queuing."""
        if count < 0 or count > len(self.out):
            raise Failure("qmp-send")
        if count == 0:
            return
        del self.out[:count]
        if not self.out:
            self.inflight = self.steps[self.step][1]
            if self.steps[self.step][0] == "cont":
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
        _, ident, check, reason = self.steps[self.step]
        if msg["id"] != ident:  # also rejects replays of an already-answered id
            raise Failure("qmp-id-mismatch")
        if "error" in msg or not check(msg["return"]):
            raise Failure(reason)
        self.inflight = None
        self.step += 1
        if self.step == len(self.steps):
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
        if self.expiry:
            raise Failure("shutdown-during-expiry-proof")
        if not self.cont_sent:
            raise Failure("early-shutdown")
        if self.shutdown_ok:
            raise Failure("duplicate-shutdown")
        if (set(data or {}) != {"guest", "reason"} or data["guest"] is not True
                or data["reason"] != "guest-shutdown"):
            raise Failure("non-guest-shutdown")
        self.shutdown_ok = True


def qemu_summary(groups):
    """The closed object kept for a matched v2 line; no native command text or paths."""
    one, two, wit, route, ca, dns = groups[2:8]
    native = {package: {"version": groups[index].decode("ascii"), "architecture": "amd64",
                        "sha256": groups[index + 1].decode("ascii")}
              for package, index in (("sudo", 8), ("openssh-client", 10), ("less", 12))}
    host = {"native": native, "caller_uid": 1000, "sudo_uid": 0,
            "tun_open": True, "tun_api": True, "tap_flag": True, "tap_create": "unrun"}
    if len(groups) == 15:       # v3: closed TAP observations; only the bounded whole seconds vary
        host["tap_create"] = "passed"
        host["tap"] = {"before": "absent", "owned": "present", "after": "absent",
                       "seconds": int(groups[14])}
    return {"accelerator": "kvm", "exit": 33, "uid": 0, "nonce_equal": True,
            "backing_unchanged": True, "workspace_removed": True,
            "install1": {"changed": True, "seconds": int(one)},
            "install2": {"changed": False, "seconds": int(two)},
            "witness_seconds": int(wit),
            "network": {"default_route": route == b"1", "ca_bundle": ca == b"1",
                        "resolver": dns == b"1"},
            "host_contract": host}


def qemu_match(line):
    """The strict v2 (TAP unrun) or v3 (finite TAP witness passed) match, else None."""
    return QEMU_RE.fullmatch(line) or QEMU_TAP_RE.fullmatch(line)


def observe(qmp, serial, nonce, inputs, deadline, clock=time.monotonic,
            require_sentinel_evidence=False, on_armed=None, captured=None):
    """Drive both connected nonblocking sockets to a verdict; raise Failure.

    The serial socket is attached and registered before `cont` is ever sent, so
    the guest cannot run before the receipt reader exists. With sentinel evidence required,
    at most ONE strict run-bound LABAPP-QEMU line is also accepted and, when a `captured`
    dict is supplied, kept as captured["qemu_witness"]. Its presence is not required here;
    the runner requires it for `qemu-fixture` and rejects it everywhere else.
    """
    want = (nonce.encode(), inputs.encode())
    qlines = Lines(QMP_LINE_MAX, QMP_TOTAL_MAX, True)
    slines = Lines(SERIAL_LINE_MAX, SERIAL_TOTAL_MAX, False,
                   (EVIDENCE_PREFIX, DIAG_PREFIX, QEMU_PREFIX) if require_sentinel_evidence else None)
    qemu_seen = False
    expiry = on_armed is not None
    proto, receipt_ok, armed = Qmp(expiry), False, False
    evidence_ok = False
    diag = None
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
                        if require_sentinel_evidence and line.startswith(QEMU_PREFIX):
                            found = qemu_match(line)
                            if not found:
                                raise Failure("malformed-qemu-witness")
                            if qemu_seen:
                                raise Failure("duplicate-qemu-witness")
                            if found.groups()[:2] != want:
                                raise Failure("stale-or-wrong-qemu-witness")
                            qemu_seen = True
                            if captured is not None:
                                captured["qemu_witness"] = qemu_summary(found.groups())
                            continue
                        if require_sentinel_evidence and line.startswith(DIAG_PREFIX):
                            found = DIAG_RE.fullmatch(line)
                            if not found:
                                raise Failure("malformed-guest-diagnostic")
                            if found.groups()[:2] != want:
                                raise Failure("stale-or-wrong-guest-diagnostic")
                            if diag is None:        # the first failing step is the useful one
                                diag = " step=%d exit=%d reason=%s" % (
                                    int(found.group(3)), int(found.group(4)), found.group(5).decode("ascii"))
                            continue
                        if not line.startswith(RECEIPT_PREFIX):
                            continue
                        if expiry:
                            raise Failure("guest-receipt-during-expiry-proof")
                        found = RECEIPT_RE.match(line)
                        if not found:
                            raise Failure("malformed-receipt")
                        if receipt_ok:
                            raise Failure("duplicate-receipt")
                        if found.group(3) == b"fail":
                            raise Failure("guest-reported-failure" + (diag or ""))
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
                    if expiry and proto.state == "running" and not armed:
                        armed = True    # right after the last actual response, before any later line
                        on_armed()      # then wait for the container's outer timer
                    if proto.shutdown_ok and drain_until is None:
                        drain_until = clock() + DRAIN_GRACE
    finally:
        sel.close()


def write_result(path, nonce, inputs, cloud_init=None, qemu_witness=None):
    result = {"nonce": nonce, "inputs": inputs, "shutdown": "guest-shutdown", "receipt": "ok"}
    if cloud_init is not None:
        result["cloud_init"] = cloud_init
    if qemu_witness is not None:
        result["qemu_witness"] = qemu_witness
    body = json.dumps(result, sort_keys=True).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(body)
        handle.flush()
        os.fsync(handle.fileno())


def write_armed(path, nonce, inputs, armed_at, boot_id):
    """One strict witness; armed_at is CLOCK_BOOTTIME seconds (ceiling) when paused was observed."""
    body = json.dumps({"kind": ARMED_KIND, "armed": "paused", "armed_at": math.ceil(armed_at), "boot_id": boot_id,
                       "nonce": nonce, "inputs": inputs}, sort_keys=True).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(body)
        handle.flush()
        os.fsync(handle.fileno())


def arm_expiry(path, nonce, inputs):
    """Arm only with at least 60 actual seconds left on PID1's original timer."""
    fd = os.open("/out/witness", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise Failure("invalid-timer-witness")
        raw = handle.read(257)
    found = re.fullmatch(rb"start (\d{1,12}) (\d{1,4})\n", raw)
    if not found:
        raise Failure("invalid-timer-witness")
    n, timer = map(int, found.groups())
    now = time.clock_gettime(time.CLOCK_BOOTTIME)
    if not n <= now or n + timer - math.ceil(now) < 60:
        raise Failure("insufficient-expiry-dwell")
    with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as handle:
        boot_id = handle.read(38).strip()
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id):
        raise Failure("invalid-boot-id")
    write_armed(path, nonce, inputs, now, boot_id)


def verify(args, clock=time.monotonic):
    deadline = clock() + args.timeout
    qmp = serial = None
    witness = getattr(args, "expiry_witness", None)
    try:
        serial = connect(args.serial, deadline, clock)  # receipt reader first
        qmp = connect(args.qmp, deadline, clock)
        on_armed = None
        if witness:
            def on_armed():
                arm_expiry(witness, args.nonce, args.inputs)
        captured = {}
        cloud_init = observe(qmp, serial, args.nonce, args.inputs, deadline, clock,
                             getattr(args, "require_sentinel_evidence", False), on_armed, captured)
        if clock() >= deadline:
            raise Failure("timeout")
        write_result(args.result, args.nonce, args.inputs, cloud_init, captured.get("qemu_witness"))
    finally:
        if witness:
            # A later observer failure must revoke arming even if Packer cleanup hangs.
            # Default SIGTERM at the outer PID1 deadline does not run this finally.
            try:
                fd = os.open(witness + ".failed", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(b"observer-ended\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                if os.path.lexists(witness):
                    os.unlink(witness)
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
    parser.add_argument("--expiry-witness")
    args = parser.parse_args(argv)
    if args.expiry_witness is not None:
        if args.require_sentinel_evidence:
            parser.error("--expiry-witness excludes --require-sentinel-evidence")
        if not os.path.isabs(args.expiry_witness):
            parser.error("expiry witness path must be absolute")
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
