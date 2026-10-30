"""Install the explicitly pinned helm 3.19.4 linux/amd64 archive; Python 3.12 on Ubuntu 24.04.

Invoke python3 /absolute/path/install-helm.py --version 3.19.4 --platform linux/amd64
[--install-dir /absolute/dir] [--archive /absolute/file]. No environment overrides, prompts,
TTY, sudo or cwd dependence; all paths must be absolute. Default dir /usr/local/bin must
already exist and be caller-owned (root for the default); an explicit caller-owned
alternate supports nonroot tests. Network mode needs curl in /usr/bin or /bin; --archive
accepts a local single-link regular archive fully verified before parsing. Keep sibling hhfab_release.py (Refusal, digest) alongside this file.
Never executes helm. Absent target: install; exact pinned 0755 target: unchanged;
exact pinned bytes with another mode: atomic repair; any other existing bytes: refused
(no force or upgrade mode). Callers must exclude concurrent mutations of the destination
directory and its ancestors; only the final directory's ownership/mode is checked.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import subprocess
import time
import zlib
import signal
import stat
import sys
import tempfile

from hhfab_release import Refusal, digest

VERSION = "3.19.4"
PLATFORM = "linux/amd64"
PINS = {VERSION: {
    "url": "https://get.helm.sh/helm-v3.19.4-linux-amd64.tar.gz",
    "archive_size": 18014603,
    "archive_sha256": "759c656fbd9c11e6a47784ecbeac6ad1eb16a9e76d202e51163ab78504848862",
    "size": 60182712,
    "sha256": "ea22096683b9b61005584501e36168a1eadc5b6883a89df299f5a55e4e2dd283",
}}
MEMBERS = ((b"linux-amd64/", b"5", 0),
           (b"linux-amd64/LICENSE", b"0", 11373),
           (b"linux-amd64/README.md", b"0", 3699),
           (b"linux-amd64/helm", b"0", 60182712))
EXPANDED_LIMIT = 70 * 1024 * 1024
# Finite assumptions, not measured fit: curl transfer, child (transfer plus grace), whole run.
TRANSFER, CHILD, TOTAL = 120, 125, 180
RESULT_LIMIT = 4096
CURL_DIRS = ("/usr/bin", "/bin")
CHILD_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Refusal("expected single-link regular file")
    return info


def directory(path):
    if not path.is_absolute():
        raise Refusal("install directory must be absolute")
    for component in [*reversed(path.parents), path]:
        if not stat.S_ISDIR(component.lstat().st_mode):
            raise Refusal("install directory components must be real directories")
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise Refusal("install directory must be caller-owned and not group/world writable")


def exact(path, pin):
    info = regular(path)
    return info.st_size == pin["size"] and digest(path) == pin["sha256"]


def curl():
    for directory_name in CURL_DIRS:
        candidate = Path(directory_name) / "curl"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    raise Refusal("curl dependency unavailable")


def download(pin, target):
    code, _ = bounded([curl(), "--disable", "--fail", "--location", "--silent", "--show-error",
                       "--proto", "=https", "--proto-redir", "=https", "--retry", "0",
                       "--max-time", str(TRANSFER), "--speed-limit", "1024", "--speed-time", "20",
                       "--max-filesize", str(pin["archive_size"]), "--output", str(target), pin["url"]],
                      CHILD, env=dict(CHILD_ENV))
    if code:
        raise Refusal("official helm download failed")


def bounded(args, seconds, limit=1024 * 1024, env=None):
    """Helm-local copy of bounded child I/O, with fixed root cwd."""
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=env, cwd="/", start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + seconds
    try:
        with selectors.DefaultSelector() as select:
            select.register(proc.stdout, selectors.EVENT_READ)
            while select.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Refusal("command timeout")
                for key, _ in select.select(min(remaining, 0.1)):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        select.unregister(key.fileobj)
                    elif len(output) + len(block) > limit:
                        raise Refusal("command output overflow")
                    else:
                        output.extend(block)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Refusal("command timeout")
        return proc.wait(timeout=remaining), bytes(output)
    except subprocess.TimeoutExpired:
        raise Refusal("command timeout") from None
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=2)
        proc.stdout.close()


class GzipStream:
    """Bounded single gzip member reader; never retains expanded archive."""
    def __init__(self, source):
        self.source = source
        self.decoder = zlib.decompressobj(31)
        self.pending = b""
        self.total = 0

    def read(self, count):
        output = bytearray()
        while len(output) < count:
            if self.decoder.eof:
                if self.decoder.unused_data or self.pending or self.source.read(1):
                    raise Refusal("trailing or concatenated gzip data")
                break
            data = self.pending or self.source.read(65536)
            if not data:
                raise Refusal("truncated gzip stream")
            try:
                block = self.decoder.decompress(data, count - len(output))
            except zlib.error:
                raise Refusal("invalid gzip stream") from None
            self.pending = self.decoder.unconsumed_tail
            output.extend(block)
            self.total += len(block)
            if self.total > EXPANDED_LIMIT:
                raise Refusal("expanded archive exceeds bound")
        return bytes(output)


def octal(field):
    value = field.rstrip(b"\0 ").lstrip(b" ")
    if not value or any(c not in b"01234567" for c in value):
        raise Refusal("invalid tar numeric field")
    return int(value, 8)


def tar_string(field):
    value, _, suffix = field.partition(b"\0")
    if any(suffix):
        raise Refusal("invalid tar string padding")
    return value


def parse_helm(source, target, pin):
    reader = GzipStream(source)
    hashed = hashlib.sha256()
    with target.open("xb") as dst:
        for index, (name, kind, size) in enumerate(MEMBERS):
            header = reader.read(512)
            if len(header) != 512:
                raise Refusal("missing tar header")
            checksum = sum(header[:148]) + 8 * 32 + sum(header[156:])
            if octal(header[148:156]) != checksum:
                raise Refusal("invalid tar checksum")
            if (tar_string(header[:100]) != name or header[156:157] != kind
                    or octal(header[124:136]) != size
                    or octal(header[100:108]) != (0o755 if index in (0, 3) else 0o644)
                    or any(header[157:257]) or any(header[345:500])
                    or header[257:265] != b"ustar  \0"):
                raise Refusal("unexpected physical tar member")
            remaining = size
            while remaining:
                block = reader.read(min(65536, remaining))
                if not block:
                    raise Refusal("truncated tar member")
                remaining -= len(block)
                if name == b"linux-amd64/helm":
                    dst.write(block)
                    hashed.update(block)
            padding = reader.read((-size) % 512)
            if len(padding) != (-size) % 512 or any(padding):
                raise Refusal("invalid tar member padding")
        tail = 0
        while True:
            block = reader.read(65536)
            if not block:
                break
            tail += len(block)
            if any(block):
                raise Refusal("unexpected tar entry or nonzero tail")
        if tail < 1024 or tail % 512:
            raise Refusal("invalid tar end markers")
        dst.flush()
        if target.stat().st_size != pin["size"] or hashed.hexdigest() != pin["sha256"]:
            raise Refusal("member checksum/size mismatch")


def extract_helm(archive, target, pin):
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size != pin["archive_size"]):
            raise Refusal("archive checksum/size mismatch")
        hashed = hashlib.sha256()
        remaining = pin["archive_size"]
        while remaining:
            block = source.read(min(65536, remaining))
            if not block:
                raise Refusal("archive checksum/size mismatch")
            hashed.update(block)
            remaining -= len(block)
        if source.read(1):
            raise Refusal("archive checksum/size mismatch")
        if hashed.hexdigest() != pin["archive_sha256"] or identity(os.fstat(source.fileno())) != identity(info):
            raise Refusal("archive checksum/size mismatch")
        source.seek(0)
        parse_helm(source, target, pin)
        if identity(os.fstat(source.fileno())) != identity(info):
            raise Refusal("archive changed during parsing")


def cleanup_stage(stage, original):
    """Only known regular children of the exact owned directory; retain unknowns."""
    now = stage.lstat()
    if (now.st_dev, now.st_ino, now.st_uid, now.st_mode) != (
            original.st_dev, original.st_ino, original.st_uid, original.st_mode):
        raise Refusal("owned stage identity changed")
    for child in stage.iterdir():
        if child.name not in ("helm", "archive.tar.gz"):
            raise Refusal("unknown stage child preserved")
        regular(child)
    for child in stage.iterdir():
        child.unlink()
    stage.rmdir()
    if os.path.lexists(stage):
        raise Refusal("owned stage remains")


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)


def install(version, platform_name, destination, archive=None):
    if (version not in PINS or platform_name != PLATFORM or platform.system() != "Linux"
            or platform.machine() not in ("x86_64", "amd64")):
        raise Refusal("unsupported version or platform")
    pin = PINS[version]
    if destination == Path("/usr/local/bin") and os.geteuid() != 0:
        raise Refusal("default install directory requires root")
    if len(json.dumps(str(destination / "helm"))) > 1024:
        raise Refusal("target path exceeds result budget")
    directory(destination)
    target = destination / "helm"
    existing = None
    status = "installed"
    if os.path.lexists(target):
        existing = regular(target)
        if existing.st_uid != os.geteuid():
            raise Refusal("existing target must be caller-owned")
        if not exact(target, pin):
            raise Refusal("existing helm differs from the pin; no upgrade or force mode")
        if stat.S_IMODE(existing.st_mode) == 0o755:
            return result(version, pin, target, "unchanged")
        status = "mode-repaired"
    if archive is not None:
        if not archive.is_absolute():
            raise Refusal("archive path must be absolute")
        regular(archive)
    else:
        curl()
    stage = Path(tempfile.mkdtemp(prefix=".helm-stage-", dir=destination))
    stage_info = stage.lstat()
    try:
        staged = stage / "helm"
        if archive is None:
            archive = stage / "archive.tar.gz"
            download(pin, archive)
        extract_helm(archive, staged, pin)
        descriptor = os.open(staged, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fchmod(descriptor, 0o755)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if existing is None:
            try:
                os.link(staged, target)  # no-clobber publication of an absent target
            except FileExistsError:
                raise Refusal("destination changed during installation") from None
            staged.unlink()
        else:
            if identity(regular(target)) != identity(existing):
                raise Refusal("destination changed during installation")
            os.replace(staged, target)
        with contextlib.suppress(OSError):
            descriptor = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        # Preserve a primary failure, but never report success after failed cleanup.
        primary = sys.exc_info()[0] is not None
        try:
            cleanup_stage(stage, stage_info)
        except (OSError, Refusal):
            if not primary:
                raise Refusal("owned stage cleanup failed after publication") from None
    return result(version, pin, target, status)


def result(version, pin, target, status):
    info = regular(target)
    observed = digest(target)
    after = regular(target)
    if (identity(info) != identity(after) or info.st_uid != os.geteuid()
            or info.st_size != pin["size"] or observed != pin["sha256"]
            or stat.S_IMODE(info.st_mode) != 0o755):
        raise Refusal("installed target changed or fails verification")
    here = Path(__file__).resolve()
    helper = Path(sys.modules["hhfab_release"].__file__).resolve()
    outcome = {
        "tool": "helm", "version": version, "platform": PLATFORM, "source_url": pin["url"],
        "pinned_size": pin["size"], "pinned_sha256": pin["sha256"],
        "archive_size": pin["archive_size"], "archive_sha256": pin["archive_sha256"],
        "module_sha256": hashlib.sha256(here.read_bytes()).hexdigest(),
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "target": str(target), "target_sha256": observed,
        "target_size": info.st_size, "target_uid": info.st_uid,
        "target_dev": info.st_dev, "target_inode": info.st_ino,
        "target_mode": format(stat.S_IMODE(info.st_mode), "04o"), "status": status,
        "verified": "size and sha256 of installed bytes against the repo pin only",
        "not_verified": "GPG signature, upstream-build provenance, redirect chain, runtime, baseline-path/owner/mode equivalence",
        "executed": False,
        "atomicity": "single rename or no-clobber link; no rollback after publication",
    }
    if len(json.dumps(outcome, sort_keys=True).encode("utf-8")) + 1 > RESULT_LIMIT:
        raise Refusal("result exceeds output budget after publication")
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--version", required=True, choices=tuple(PINS))
    parser.add_argument("--platform", required=True, choices=(PLATFORM,))
    parser.add_argument("--install-dir", type=Path, default=Path("/usr/local/bin"))
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()

    def expired(_signum, _frame):
        raise Refusal("installation deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(TOTAL)
    try:
        print(json.dumps(install(args.version, args.platform, args.install_dir, args.archive),
                         sort_keys=True))
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except KeyboardInterrupt:
        print("helm install: interrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as error:
        print("helm install: " + (str(error) if isinstance(error, Refusal) else "operational failure"),
              file=sys.stderr)
        sys.exit(1)
