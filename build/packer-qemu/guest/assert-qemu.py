"""Fixed networked QEMU fixture adapter (see ../README.md "Fixed `qemu-fixture` task").

Staged on the CD by stage_tools.py and run by guest-build.sh's plan as
`root /usr/bin/python3 -I -B @IN@/assert-qemu.py <phase>` under `env -i`, cwd `/`, stdin /dev/null,
next to the UNCHANGED build/provision modules install-qemu.py, qemu_offline.py, hhfab_release.py and
qemu_witness.py (staged byte-for-byte, with shared hhfab_release.py public 0444 for the existing nonroot probe). Python 3.10+ stdlib only. It adds no installer
option, repair, retry, NIC or network configuration: it only RUNS the existing modules and OBSERVES.

Phases: baseline (root, identities, bounded network facts), `install 1` / `install 2` (the unchanged
`python3 -B install-qemu.py`, no arguments, ordinary network mode: run 1 must change the guest, run 2 must be
a package/artifact no-change rerun (APT still authenticates and executes), and native dpkg/artifact state must match the pins and stay identical), witness (the
unchanged `qemu_witness.py`: real `-accel kvm -cpu host`, nonce, exit 33, unchanged backing, removed scratch;
then ONE strict run-bound `LABAPP-QEMU v3` line on the serial console). The same four phases also observe
native sudo/ssh/less packages and trusted executable identities before/after installation. Witness additionally
checks only ubuntu's fixed noninteractive sudo root identity command and root's nonmutating TUNGETFEATURES
query, then ONE finite FD-owned nonpersistent TAP operation (`tap_witness`): refuse a preexisting fixed
interface name, TUNSETIFF `IFF_TAP|IFF_NO_PI` (never TUNSETPERSIST) on the trusted /dev/net/tun descriptor,
verify the exact interface/type while the descriptor is open, close it and require the interface absent. The
guest root's namespace is the guest's own, not the host's. Bridge, IP, route and official VLAB helper
operations remain unrun; no official VLAB binary/helper is invoked. The retained line is `LABAPP-QEMU v3`
(`v2` and its `tap_create=unrun` meaning are unchanged and no longer emitted by this adapter).

A failing phase writes ONE fixed reason token to /run/labapp-reason (read and validated by guest-build.sh,
which adds the plan step and exit code to its bounded diagnostic line) and exits 1. Tokens never contain
peer or tool text: installer failures are `inst<N>-<kind>[-s<seconds>]` with a fixed kind, so the observer
reports the failing installer run and its bounded wall time (the evidence #281 needs). No raw APT, dpkg,
installer or witness output is ever echoed. KVM/witness caller remains root; the additional sudo identity
check starts as ubuntu UID1000. Neither proves student readiness. These new checks are UNRUN in a guest.
"""
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import pwd
import re
import shutil
import signal
import socket
import stat
import struct
import sys
import time

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV = {"PATH": SAFE_PATH, "HOME": "/root", "LC_ALL": "C.UTF-8", "DEBIAN_FRONTEND": "noninteractive"}
REASON_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
MODULES = ("install-qemu.py", "qemu_offline.py", "hhfab_release.py", "qemu_witness.py")
INSTALL_SECONDS = 240      # above install-qemu.py's own 235 s alarm; its limits are unchanged
WITNESS_SECONDS = 45       # above qemu_witness.py's own 40 s alarm
INSTALL_OUTPUT_CAP = 1 << 20  # installer report; same bound as its internal command helper
WITNESS_OUTPUT_CAP = 4096    # small fixed witness report, never exported
NATIVE_OUTPUT_CAP = 1 << 18  # unchanged bounded native query/audit
SECONDS_CAP = 999
STATUS_CAP = 65536
INSTALL_KEYS = {"snapshot", "pins", "resolved_installed", "downloaded_archives", "changed", "seconds"}
WITNESS_KEYS = {"accelerator", "exit", "nonce_equal", "fixture_sha256", "backing_unchanged",
                "owned_workspace_removed", "artifacts", "pins", "uid", "gid", "groups", "device", "seconds"}
# The unchanged witness prints exactly `qemu witness: <message>`; only these fixed messages are mapped.
WITNESS_REFUSALS = {"KVM character device absent; no fallback": "witness-nokvm",
                    "execution nonce/exit mismatch": "witness-mismatch",
                    "QEMU/firmware artifact identity mismatch": "witness-artifact",
                    "QEMU package identity mismatch": "witness-pins",
                    "backing fixture changed": "witness-backing",
                    "command timeout": "witness-timeout",
                    "overall deadline exceeded": "witness-deadline"}
PACKAGE_ARTIFACTS = ("/usr/bin/qemu-system-x86_64", "/usr/bin/qemu-img", "/usr/bin/socat1",
                     "/usr/share/seabios/bios-256k.bin")
REMAINING = (("sudo", "sudo", 0o4755), ("openssh-client", "ssh", 0o755), ("less", "less", 0o755))
VERSION_RE = re.compile(r"[0-9][A-Za-z0-9.+:~\-]{0,63}\Z")
HOST_OUTPUT_CAP = 4096
TUNGETFEATURES = 0x800454cf  # Linux amd64 _IOR('T', 207, unsigned int); query only
TUNSETIFF = 0x400454ca       # Linux amd64 _IOW('T', 202, int); TUNSETPERSIST is never issued
IFF_TUN, IFF_TAP, IFF_NO_PI, IFF_PERSIST, IFF_TUN_EXCL = 0x0001, 0x0002, 0x1000, 0x0800, 0x8000
ARPHRD_ETHER = 1
TAP_NAME = "labapp-tap0"     # fixed, safe, <= 15 bytes; a preexisting interface of this name is refused
TAP_SECONDS = 10             # whole finite operation; inside the existing 1800 s work + 900 s cleanup windows


class Check(Exception):
    """A failed assertion; its text is a fixed reason token, never peer output."""


class Config:
    def __init__(self, here, state="/run/labapp-qemufixture", reason="/run/labapp-reason", tty="/dev/ttyS0",
                 route="/proc/net/route", resolver="/etc/resolv.conf", ca="/etc/ssl/certs/ca-certificates.crt",
                 euid=os.geteuid, run=None, clock=time.monotonic, owner=0, artifacts=PACKAGE_ARTIFACTS,
                 inventory=None, tun=None, lookup=pwd.getpwnam, tap_ops=None, tap_clock=time.monotonic):
        self.here, self.state, self.reason, self.tty = here, state, reason, tty
        self.route, self.resolver, self.ca = route, resolver, ca
        self.euid, self.clock = euid, clock
        self.owner = owner              # production root; synthetic metadata tests use their caller
        self.artifacts = artifacts
        self.run = run or self.bounded      # tests substitute a fake with the same contract
        self.inventory = inventory or (lambda: remaining_inventory(self))
        self.tun = tun or tun_query
        self.lookup = lookup
        self.tap_ops = tap_ops or TapOps()
        self.tap_clock = tap_clock

    def path(self, name):
        return os.path.join(self.here, name)

    def bounded(self, argv, seconds):
        """(exit code, combined output) through the unchanged sibling helper's streaming cap and
        process-group deadline/cleanup. -I excludes cwd/script imports, so load the exact sibling."""
        spec = importlib.util.spec_from_file_location("qemu_fixture_release", self.path("hhfab_release.py"))
        release = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(release)
        try:
            limit = (INSTALL_OUTPUT_CAP if argv[-1] == self.path("install-qemu.py") else
                     WITNESS_OUTPUT_CAP if argv[-1] == self.path("qemu_witness.py") else NATIVE_OUTPUT_CAP)
            return release.bounded(["/usr/bin/env", "-C", "/", *argv], seconds, limit=limit, env=ENV)
        except release.Refusal as exc:
            raise Timeout("output" if str(exc) == "command output overflow" else "timeout") from None


class Timeout(Exception):
    """The bounded helper's deadline or output cap; kind is `timeout` or `output`."""

    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


def need(condition, reason):
    if not condition:
        raise Check(reason)


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    def invalid(_):
        raise ValueError("nonfinite JSON")
    return json.loads(raw.decode("ascii"), object_pairs_hook=pairs, parse_constant=invalid)


def whole_seconds(started, now):
    return min(SECONDS_CAP, max(0, math.ceil(now - started)))


def state_path(cfg, name):
    return os.path.join(cfg.state, name)


def read_state(cfg, name):
    path = state_path(cfg, name)
    try:
        info = os.lstat(path)
    except OSError:
        raise Check("state-missing") from None
    need(stat.S_ISREG(info.st_mode) and info.st_size <= 1 << 20, "state-missing")
    with open(path, "rb") as handle:
        return json.loads(handle.read(1 << 20).decode("ascii"))


def write_state(cfg, name, value):
    fd = os.open(state_path(cfg, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(json.dumps(value, sort_keys=True).encode("ascii"))
        handle.flush()
        os.fsync(handle.fileno())


def read_small(path):
    """A small regular file, bounded read; None when absent or not regular."""
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            return None
        with open(path, "rb") as handle:
            return handle.read(STATUS_CAP)
    except OSError:
        return None


def network_facts(cfg):
    """Bounded booleans only: a default IPv4 route, a nonempty CA bundle and a nameserver line. They are
    reported, never repaired, so an actual failure shows what the generated NoCloud network lacked."""
    table = read_small(cfg.route) or b""
    route = any(len(row.split()) >= 8 and row.split()[1] == b"00000000" and row.split()[7] == b"00000000"
                for row in table.splitlines()[1:])
    bundle = read_small(cfg.ca)
    resolver_path = cfg.resolver
    if os.path.islink(resolver_path):
        # Ubuntu systemd-resolved's two documented local resolver files only.
        target = os.path.normpath(os.path.join(os.path.dirname(resolver_path), os.readlink(resolver_path)))
        resolver_path = target if target in ("/run/systemd/resolve/stub-resolv.conf",
                                             "/run/systemd/resolve/resolv.conf") else ""
    resolver = any(row.split()[:1] == [b"nameserver"] and len(row.split()) >= 2
                   for row in (read_small(resolver_path) or b"").splitlines())
    return {"default_route": route, "ca_bundle": bool(bundle), "resolver": resolver}


def trusted_parents(path, reason):
    """Only real root-owned directories; fixed canonical paths have no symlink ancestors."""
    part = os.path.dirname(path)
    while True:
        info = os.lstat(part)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
             and info.st_mode & 0o111 == 0o111, reason)
        if part == "/":
            break
        part = os.path.dirname(part)


def file_identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def remaining_inventory(cfg):
    """Native installed-state observations, not new pins or package integrity certification.

    Canonical package files are regular and root-owned. Sudo legitimately has its setuid bit;
    hardlinks are permitted. Only the documented merged-usr /bin alias can resolve to these files.
    No binary is executed for inventory, and native text never leaves the guest.
    """
    try:
        code, raw = cfg.run(["/usr/bin/dpkg-query", "-W",
                             "-f=${Package}\t${Architecture}\t${Version}\t${db:Status-Status}\\n",
                             "sudo", "openssh-client", "less"], 20)
        need(code == 0 and len(raw) <= HOST_OUTPUT_CAP, "host-query")
        packages = {}
        for row in raw.decode("ascii").splitlines():
            fields = row.split("\t")
            need(len(fields) == 4, "host-query")
            package, arch, version, status = fields
            need(package in {p for p, _, _ in REMAINING} and package not in packages
                 and arch == "amd64" and status == "installed" and VERSION_RE.fullmatch(version), "host-query")
            packages[package] = {"version": version, "architecture": arch}
        need(set(packages) == {p for p, _, _ in REMAINING}, "host-query")
        for package, name, mode in REMAINING:
            path = "/usr/bin/" + name
            resolved = shutil.which(name, path=SAFE_PATH)
            if resolved == "/bin/" + name:
                alias = os.lstat("/bin")
                need(stat.S_ISLNK(alias.st_mode) and alias.st_uid == 0
                     and os.readlink("/bin") in ("usr/bin", "/usr/bin"), "host-path")
            else:
                need(resolved == path, "host-path")
            trusted_parents(path, "host-path")
            before = os.lstat(path)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_gid == 0
                 and stat.S_IMODE(before.st_mode) == mode and before.st_nlink >= 1
                 and not os.statvfs(path).f_flag & os.ST_NOEXEC, "host-path")
            code, raw = cfg.run(["/usr/bin/dpkg-query", "-S", path], 20)
            need(code == 0 and len(raw) <= HOST_OUTPUT_CAP and raw in (
                (package + ": " + path + "\n").encode("ascii"),
                (package + ":amd64: " + path + "\n").encode("ascii")), "host-owner")
            digest = sha256(path)
            need(file_identity(before) == file_identity(os.lstat(path)), "host-drift")
            packages[package].update(sha256=digest, identity=file_identity(before))
        return packages
    except Timeout as exc:
        raise Check("host-" + exc.kind) from None
    except (OSError, UnicodeError):
        raise Check("host-query") from None


def sudo_identity(cfg):
    """One necessary noninteractive sudo identity command, not arbitrary sudo policy proof.

    runuser establishes the actual ubuntu caller with its normal groups. -n refuses prompts;
    -k with a command ignores cached authentication and does not update that cache.
    The shared bounded helper fixes cwd=/, closed stdin, clean environment and process cleanup.
    """
    try:
        owner = cfg.lookup("ubuntu")
        need(owner.pw_uid == 1000 and owner.pw_gid > 0, "sudo-owner")
        code, raw = cfg.run(["/usr/sbin/runuser", "-u", "ubuntu", "--", "/usr/bin/env", "-i",
                             "PATH=" + SAFE_PATH, "HOME=/home/ubuntu", "LC_ALL=C.UTF-8",
                             "/usr/bin/sudo", "-n", "-k", "--", "/usr/bin/id", "-u"], 10)
        need(code == 0 and raw == b"0\n", "sudo-identity")
    except Timeout as exc:
        raise Check("sudo-" + exc.kind) from None
    except (OSError, KeyError):
        raise Check("sudo-owner") from None


def tun_query():
    """Open/query/close only. GETFEATURES reports valid flags even without an interface.

    This does not test CAP_NET_ADMIN, TAP creation, bridges, LSM authorization or official helpers.
    No interface is attached and no persistent device or network configuration is created.
    """
    try:
        path = "/dev/net/tun"
        trusted_parents(path, "tun-path")
        before = os.lstat(path)
        need(stat.S_ISCHR(before.st_mode) and before.st_uid == 0
             and (os.major(before.st_rdev), os.minor(before.st_rdev)) == (10, 200), "tun-device")
        fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            need((before.st_dev, before.st_ino, before.st_rdev, before.st_mode, before.st_uid, before.st_gid)
                 == (opened.st_dev, opened.st_ino, opened.st_rdev, opened.st_mode, opened.st_uid, opened.st_gid),
                 "tun-identity")
            flags = bytearray(4)
            need(fcntl.ioctl(fd, TUNGETFEATURES, flags, True) == 0, "tun-api")
            need(int.from_bytes(flags, "little") & 0x0002 != 0, "tun-features")
        finally:
            os.close(fd)
    except OSError:
        raise Check("tun-api") from None


class TapOps:
    """The kernel-facing primitives of the finite TAP witness; offline tests substitute these five methods
    (mocks cannot prove kernel authorization). Nothing here deletes, persists or configures an interface."""

    def exists(self, name):
        # CPython if_nametoindex discards errno. A successful inventory distinguishes
        # absence from query failure without interpreting exception text.
        rows = socket.if_nameindex()
        need(isinstance(rows, list) and all(isinstance(row, tuple) and len(row) == 2
             and type(row[0]) is int and row[0] > 0 and isinstance(row[1], str)
             for row in rows), "tap-query")
        return any(found == name for _, found in rows)

    def open(self):
        """The same trusted real /dev/net/tun character device 10:200 and descriptor identity as tun_query."""
        try:
            path = "/dev/net/tun"
            trusted_parents(path, "tap-open")
            before = os.lstat(path)
            need(stat.S_ISCHR(before.st_mode) and before.st_uid == 0
                 and (os.major(before.st_rdev), os.minor(before.st_rdev)) == (10, 200), "tap-open")
            fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise Check("tap-open") from None
        try:
            opened = os.fstat(fd)
            need((before.st_dev, before.st_ino, before.st_rdev, before.st_mode, before.st_uid, before.st_gid)
                 == (opened.st_dev, opened.st_ino, opened.st_rdev, opened.st_mode, opened.st_uid, opened.st_gid),
                 "tap-open")
        except BaseException as exc:
            os.close(fd)
            if isinstance(exc, OSError):
                raise Check("tap-open") from None
            raise
        return fd

    def create(self, fd, name):
        """TUNSETIFF IFF_TAP|IFF_NO_PI only; the descriptor owns the interface (no TUNSETPERSIST)."""
        request = bytearray(struct.pack("16sH22x", name.encode("ascii"), IFF_TAP | IFF_NO_PI | IFF_TUN_EXCL))
        try:
            need(fcntl.ioctl(fd, TUNSETIFF, request, True) == 0, "tap-create")
        except OSError:
            raise Check("tap-create") from None
        need(bytes(request[:16]).split(b"\0", 1)[0] == name.encode("ascii"), "tap-create")

    def inspect(self, name):
        """(ARPHRD type, tun_flags) of the named interface from its fixed sysfs attributes."""
        base = "/sys/class/net/" + name
        kind, flags = read_small(base + "/type"), read_small(base + "/tun_flags")
        need(kind is not None and flags is not None, "tap-inspect")
        try:
            return int(kind.strip(), 10), int(flags.strip(), 16)
        except ValueError:
            raise Check("tap-inspect") from None

    def close(self, fd):
        os.close(fd)


@contextlib.contextmanager
def tap_deadline():
    """Interrupt this standalone main-thread guest operation; never replace an existing timer.

    SIGTERM/SIGINT become cancellation failures so the owned descriptor's finally runs.
    The timer stays armed through close/absence checks; default process termination
    remains the outer guest/controller boundary if an uninterruptible kernel call stalls.
    """
    need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "tap-deadline")
    previous = {}
    def stop(signum, _frame):
        raise Check("tap-deadline" if signum == signal.SIGALRM else "tap-cancelled")
    try:
        for signum in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, stop)
        signal.setitimer(signal.ITIMER_REAL, TAP_SECONDS)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def tap_witness(cfg):
    with tap_deadline():
        return tap_observe(cfg)


def tap_observe(cfg):
    """ONE finite ephemeral TAP operation; returns {"seconds": n} only after observing the interface
    absent before, present with the exact type while the descriptor is open, and absent after close.

    A preexisting interface of the fixed name is refused before any mutation and is never deleted or
    repaired. The descriptor is always closed (also on cancellation) and no persistence is requested, so
    closing is the only cleanup. Any failure, a close error, or an interface still present afterwards
    raises a fixed token. A main-thread alarm interrupts the operation; monotonic checks additionally
    refuse late results. No bridge, address, route or helper is touched.
    """
    ops = cfg.tap_ops
    started = cfg.tap_clock()
    try:
        present = ops.exists(TAP_NAME)
    except OSError:
        raise Check("tap-query") from None
    need(not present, "tap-collision")
    need(cfg.tap_clock() - started <= TAP_SECONDS, "tap-deadline")
    fd = failure = None
    closed = True
    try:
        fd = ops.open()
        ops.create(fd, TAP_NAME)
        try:
            owned = ops.exists(TAP_NAME)
            kind, flags = ops.inspect(TAP_NAME) if owned else (None, None)
        except OSError:
            raise Check("tap-inspect") from None
        need(owned, "tap-missing")
        need(kind == ARPHRD_ETHER and flags == IFF_TAP | IFF_NO_PI,
             "tap-type")
        need(cfg.tap_clock() - started <= TAP_SECONDS, "tap-deadline")
    except BaseException as exc:
        failure = exc
    finally:
        if fd is not None:
            try:
                ops.close(fd)
            except BaseException as exc:
                closed = False
                if failure is None:
                    failure = exc
    leaked = None
    if fd is not None:
        try:
            leaked = ops.exists(TAP_NAME)
        except OSError:
            leaked = None
        if leaked:
            raise Check("tap-after-present")
    if not closed:
        raise Check("tap-close")
    if failure is not None:
        raise failure
    need(leaked is False, "tap-query")
    spent = cfg.tap_clock() - started
    need(spent <= TAP_SECONDS, "tap-deadline")
    return {"seconds": whole_seconds(started, started + spent)}


def baseline(cfg):
    need(cfg.euid() == 0, "not-root")
    for name in MODULES:
        info = os.lstat(cfg.path(name))
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == cfg.owner
             and stat.S_IMODE(info.st_mode) == (0o444 if name == "hhfab_release.py" else 0o400), "staging-input")
    os.makedirs(cfg.state, mode=0o700)
    write_state(cfg, "baseline.json", {"network": network_facts(cfg), "remaining": cfg.inventory()})


def native_state(cfg, names):
    """Native facts, independent of the installer's own report: the pinned packages (`names` only, so
    unrelated background package activity cannot fail the run) with their installed versions, a clean dpkg
    audit, and each artifact's identity so the rerun can be shown not to have rewritten it."""
    code, out = cfg.run(["/usr/bin/dpkg-query", "-W",
                         "-f=${binary:Package}\t${Version}\t${db:Status-Status}\\n"], 20)
    need(code == 0, "native-query")
    rows = [row.split("\t") for row in out.decode("ascii", "replace").splitlines()]
    packages = {row[0]: row[1] for row in rows if len(row) == 3 and row[2] == "installed" and row[0] in names}
    code, out = cfg.run(["/usr/bin/dpkg", "--audit"], 20)
    need(code == 0 and not out.strip(), "native-audit")
    artifacts = {}
    for path in cfg.artifacts:
        info = os.lstat(path)
        need(stat.S_ISREG(info.st_mode), "native-artifact")
        artifacts[path] = [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, sha256(path)]
        if os.path.basename(path) == "socat1":
            link = os.path.join(os.path.dirname(path), "socat")
            meta = os.lstat(link)
            need(stat.S_ISLNK(meta.st_mode) and os.readlink(link) == "socat1", "native-artifact")
            artifacts[link] = [meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns,
                               meta.st_ctime_ns, os.readlink(link)]
    return {"packages": packages, "artifacts": artifacts}


EXPECTED_SNAPSHOT = "20261024T000000Z"
EXPECTED_PINS = {"qemu-system-x86": "1:8.2.2+ds-0ubuntu1.18", "qemu-utils": "1:8.2.2+ds-0ubuntu1.18",
                 "socat": "1.8.0.0-4ubuntu0.1", "seabios": "1.16.3-2"}


EXPECTED_ARTIFACTS = {
    "/usr/bin/qemu-system-x86_64": "8a35ccba41582fc6c38b9df85fc9e35fa1d42f414d2d7d8090ee9b2f5e7c0854",
    "/usr/share/seabios/bios-256k.bin": "1a9ea4f17bcfb27bda5728e2c21d9fa074cf7947b9b4910bb28213a735c96735"}


def finite_seconds(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= SECONDS_CAP


def install_report(text, number):
    """Validate the unchanged installer's one-line JSON report; return it."""
    try:
        need(len(text) <= INSTALL_OUTPUT_CAP, "inst%d-output" % number)
        report = strict_json(text)
    except (UnicodeError, ValueError, RecursionError):
        raise Check("inst%d-output" % number) from None
    pins = report.get("pins") if isinstance(report, dict) else None
    ok = (isinstance(report, dict) and set(report) == INSTALL_KEYS and isinstance(pins, dict) and pins
          and all(isinstance(k, str) and isinstance(v, str) for k, v in pins.items())
          and isinstance(report["resolved_installed"], dict)
          and all(report["resolved_installed"].get(k) == v for k, v in pins.items())
          and isinstance(report["downloaded_archives"], list)
          and type(report["changed"]) is bool and report["snapshot"] == EXPECTED_SNAPSHOT
          and pins == EXPECTED_PINS and finite_seconds(report["seconds"])
          and all(isinstance(row, dict) and set(row) == {"name", "bytes", "sha256"}
                  and isinstance(row["name"], str) and type(row["bytes"]) is int and row["bytes"] >= 0
                  and isinstance(row["sha256"], str) and HEX64_RE.fullmatch(row["sha256"])
                  for row in report["downloaded_archives"]))
    need(ok, "inst%d-output" % number)
    return report


def install(cfg, number):
    need(number in (1, 2), "internal")
    first = number == 1
    prior = read_state(cfg, "baseline.json" if first else "install1.json")
    started = cfg.clock()
    try:
        code, out = cfg.run(["/usr/bin/python3", "-B", cfg.path("install-qemu.py")], INSTALL_SECONDS)
    except Timeout as exc:
        raise Check("inst%d-%s" % (number, exc.kind)) from None
    spent = whole_seconds(started, cfg.clock())
    if code != 0:
        raise Check("inst%d-%s-s%03d" % (number, "refused" if code == 1 else "exit", spent))
    report = install_report(out, number)
    need(report["changed"] is first, "inst1-unchanged" if first else "inst2-changed")
    native = native_state(cfg, set(report["pins"]))
    need(native["packages"] == report["pins"], "native-pins")
    remaining = cfg.inventory()
    need(remaining == prior["remaining"], "host-drift")
    if not first:
        need(report["pins"] == prior["pins"], "rerun-pins")
        need(native == prior["native"], "rerun-state")
    write_state(cfg, "install%d.json" % number,
                {"pins": report["pins"], "native": native, "seconds": spent, "changed": report["changed"],
                 "network": prior["network"], "remaining": remaining})


def sha256(path):
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_size <= 1 << 28, "native-artifact")
        total = 0
        for block in iter(lambda: handle.read(1 << 20), b""):
            total += len(block)
            need(total <= info.st_size, "native-artifact")
            digest.update(block)
        after = os.fstat(handle.fileno())
        need(total == info.st_size and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "native-artifact")
    return digest.hexdigest()


def witness_report(text, pins):
    try:
        need(len(text) <= WITNESS_OUTPUT_CAP, "witness-output")
        report = strict_json(text)
    except (UnicodeError, ValueError, RecursionError):
        raise Check("witness-output") from None
    device = report.get("device") if isinstance(report, dict) else None
    ok = (isinstance(report, dict) and set(report) == WITNESS_KEYS
          and report["accelerator"] == "KVM" and type(report["exit"]) is int and report["exit"] == 33
          and report["nonce_equal"] is True and report["backing_unchanged"] is True
          and report["owned_workspace_removed"] is True
          and type(report["uid"]) is int and report["uid"] == 0
          and isinstance(report["fixture_sha256"], str) and HEX64_RE.fullmatch(report["fixture_sha256"])
          and type(report["gid"]) is int and report["gid"] >= 0
          and isinstance(report["groups"], list) and all(type(g) is int and g >= 0 for g in report["groups"])
          and isinstance(report["artifacts"], dict) and report["artifacts"] == EXPECTED_ARTIFACTS
          and finite_seconds(report["seconds"])
          and report["pins"] == pins and isinstance(device, dict) and device.get("character") is True)
    need(ok, "witness-invalid")
    return report


def emit_line(cfg, line):
    """Write the whole fixed line with os.write (partial writes, EINTR); no buffered stream."""
    try:
        fd = os.open(cfg.tty, os.O_WRONLY | os.O_NOCTTY)
    except OSError:
        raise Check("emit-failed") from None
    try:
        view = memoryview(line)
        while view:
            try:
                count = os.write(fd, view)
            except InterruptedError:
                continue
            except OSError:
                raise Check("emit-failed") from None
            need(count > 0, "emit-failed")
            view = view[count:]
    finally:
        os.close(fd)


def witness(cfg):
    need(cfg.euid() == 0, "not-root")
    base, one, two = (read_state(cfg, name) for name in ("baseline.json", "install1.json", "install2.json"))
    need(one["changed"] is True and two["changed"] is False and one["pins"] == two["pins"], "rerun-state")
    started = cfg.clock()
    try:
        code, out = cfg.run(["/usr/bin/python3", "-B", cfg.path("qemu_witness.py")], WITNESS_SECONDS)
    except Timeout as exc:
        raise Check("witness-" + exc.kind) from None
    spent = whole_seconds(started, cfg.clock())
    if code != 0:
        prefix = b"qemu witness: "
        text = out.rstrip(b"\n")
        need(code == 1 and text.startswith(prefix), "witness-failed")
        raise Check(WITNESS_REFUSALS.get(text[len(prefix):].decode("ascii", "replace"), "witness-failed"))
    witness_report(out, one["pins"])
    need(cfg.inventory() == two["remaining"] == one["remaining"] == base["remaining"], "host-drift")
    sudo_identity(cfg)
    cfg.tun()
    tap = tap_witness(cfg)
    nonce = read_small(cfg.path("nonce"))
    manifest = read_small(cfg.path("MANIFEST"))
    need(nonce is not None and manifest is not None, "identity")
    nonce = nonce.decode("ascii", "replace").strip()
    inputs = hashlib.sha256(manifest).hexdigest()
    need(HEX64_RE.fullmatch(nonce) is not None, "identity")
    flags = "".join("1" if base["network"][key] else "0" for key in ("default_route", "ca_bundle", "resolver"))
    inventory = " ".join("%s=%s:%s" % (name, base["remaining"][package]["version"],
                                        base["remaining"][package]["sha256"])
                         for package, name, _ in REMAINING)
    line = ("\nLABAPP-QEMU v3 nonce=%s inputs=%s accel=kvm exit=33 uid=0 equal=1 backing=1 removed=1 "
            "i1=1:%d i2=0:%d w=%d net=%s %s caller=1000 sudo_uid=0 arch=amd64 "
            "tun_open=1 tun_api=1 tap_flag=1 tap_create=passed tap_before=absent tap_owned=present "
            "tap_after=absent tap_s=%d\n" %
            (nonce, inputs, one["seconds"], two["seconds"], spent, flags, inventory, tap["seconds"]))
    emit_line(cfg, line.encode("ascii"))


def report(cfg, token):
    """One fixed token, never overwriting an earlier reason. Best effort."""
    if not REASON_RE.fullmatch(token):
        token = "internal"
    try:
        fd = os.open(cfg.reason, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(token.encode("ascii"))
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        pass


def run(argv, cfg=None):
    if argv == ["baseline"]:
        action = baseline
    elif argv in (["install", "1"], ["install", "2"]):
        action = lambda c: install(c, int(argv[1]))
    elif argv == ["witness"]:
        action = witness
    else:
        return 2
    cfg = cfg or Config(os.path.dirname(os.path.abspath(__file__)))
    try:
        action(cfg)
    except Check as exc:
        report(cfg, str(exc))
        return 1
    except Exception:       # peer-controlled text must not reach the diagnostic
        report(cfg, "internal")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
