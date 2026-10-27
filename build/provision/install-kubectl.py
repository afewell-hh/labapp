"""Install the explicitly pinned kubectl 1.35.0 linux/amd64 binary; Python 3.12 on Ubuntu 24.04.

Invoke python3 /absolute/path/install-kubectl.py --version 1.35.0 --platform linux/amd64
[--install-dir /absolute/dir] [--binary /absolute/file]. No environment overrides, prompts,
TTY, sudo or cwd dependence; all paths must be absolute. Default dir /usr/local/bin must
already exist and be caller-owned (root for the default); an explicit caller-owned
alternate supports nonroot tests. Network mode needs curl in /usr/bin or /bin; --binary
accepts a local single-link regular file that is fully size/hash verified before any
mutation. Keep sibling hhfab_release.py (Refusal, bounded, digest) alongside this file.
Never executes kubectl. Absent target: install; exact pinned 0755 target: unchanged;
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
import shutil
import signal
import stat
import sys
import tempfile

from hhfab_release import Refusal, bounded, digest

VERSION = "1.35.0"
PLATFORM = "linux/amd64"
PINS = {VERSION: {
    "url": "https://dl.k8s.io/release/v1.35.0/bin/linux/amd64/kubectl",
    "size": 58597560,
    "sha256": "a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989",
}}
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
                       "--max-filesize", str(pin["size"]), "--output", str(target), pin["url"]],
                      CHILD, env=dict(CHILD_ENV))
    if code:
        raise Refusal("official kubectl download failed")


def copy_binary(source, target, pin):
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as src, target.open("xb") as dst:
        info = os.fstat(src.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != pin["size"]:
            raise Refusal("binary input must be a single-link regular file of the pinned size")
        remaining = pin["size"]
        while remaining:
            block = src.read(min(1024 * 1024, remaining))
            if not block:
                raise Refusal("truncated binary input")
            dst.write(block)
            remaining -= len(block)
        if src.read(1):
            raise Refusal("binary input grew during copy")


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)


def install(version, platform_name, destination, binary=None):
    if (version not in PINS or platform_name != PLATFORM or platform.system() != "Linux"
            or platform.machine() not in ("x86_64", "amd64")):
        raise Refusal("unsupported version or platform")
    pin = PINS[version]
    if destination == Path("/usr/local/bin") and os.geteuid() != 0:
        raise Refusal("default install directory requires root")
    if len(json.dumps(str(destination / "kubectl"))) > 1024:
        raise Refusal("target path exceeds result budget")
    directory(destination)
    target = destination / "kubectl"
    existing = None
    status = "installed"
    if os.path.lexists(target):
        existing = regular(target)
        if existing.st_uid != os.geteuid():
            raise Refusal("existing target must be caller-owned")
        if not exact(target, pin):
            raise Refusal("existing kubectl differs from the pin; no upgrade or force mode")
        if stat.S_IMODE(existing.st_mode) == 0o755:
            return result(version, pin, target, "unchanged")
        status = "mode-repaired"
    if binary is not None:
        if not binary.is_absolute():
            raise Refusal("binary path must be absolute")
        if not exact(binary, pin):
            raise Refusal("binary input size/checksum mismatch")
    else:
        curl()  # refuses before staging when the dependency is absent
    stage = Path(tempfile.mkdtemp(prefix=".kubectl-stage-", dir=destination))
    try:
        staged = stage / "kubectl"
        if binary is None:
            download(pin, staged)
        else:
            copy_binary(binary, staged, pin)
        if not exact(staged, pin):
            raise Refusal("kubectl size/checksum mismatch")
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
            shutil.rmtree(stage)
        except OSError:
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
        "tool": "kubectl", "version": version, "platform": PLATFORM, "source_url": pin["url"],
        "pinned_size": pin["size"], "pinned_sha256": pin["sha256"],
        "module_sha256": hashlib.sha256(here.read_bytes()).hexdigest(),
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "target": str(target), "target_sha256": observed,
        "target_mode": format(stat.S_IMODE(info.st_mode), "04o"), "status": status,
        "verified": "size and sha256 of installed bytes against the repo pin only",
        "not_verified": "signature, certificate, redirect chain, runtime, baseline-path equivalence",
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
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()

    def expired(_signum, _frame):
        raise Refusal("installation deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(TOTAL)
    try:
        print(json.dumps(install(args.version, args.platform, args.install_dir, args.binary),
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
        print("kubectl install: interrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as error:
        print("kubectl install: " + (str(error) if isinstance(error, Refusal) else "operational failure"),
              file=sys.stderr)
        sys.exit(1)
