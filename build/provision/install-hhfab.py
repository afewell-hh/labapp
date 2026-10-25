"""Install an explicitly pinned hhfab binary; Python 3.10+ stdlib on Linux amd64.

Invoke python3 /absolute/path/install-hhfab.py --version VERSION [--install-dir DIR]
[--archive FILE]. No environment overrides, prompts, sudo or cwd dependence.
Default DIR /usr/local/bin must already exist, be trusted and writable by caller
(root for the default). Requires curl on PATH for network mode only; --archive
accepts a local regular non-symlink release archive, still fully verified.
Keep sibling hhfab_release.py alongside this file. Never executes hhfab.
Callers must exclude concurrent mutations of destination directory and ancestors.
"""
import argparse
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
import sys
import tempfile

from hhfab_release import PINS, Refusal, digest, download, extract


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Refusal("expected single-link regular file")
    return info


def directory(path):
    if not path.is_absolute():
        raise Refusal("install directory must be absolute")
    # Reject symlinks in every component, including parent components.
    for component in [*reversed(path.parents), path]:
        if not stat.S_ISDIR(component.lstat().st_mode):
            raise Refusal("install directory components must be real directories")
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise Refusal("install directory must be caller-owned and not group/world writable")


def install(version, destination, archive=None):
    if version not in PINS or platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise Refusal("unsupported version or platform")
    if archive is None and shutil.which("curl") is None:
        raise Refusal("curl dependency unavailable")
    directory(destination)
    target = destination / "hhfab"
    pin = PINS[version]
    existing = None
    if os.path.lexists(target):
        existing = regular(target)
        if existing.st_size == pin[2] and digest(target) == pin[3]:
            # Replace even for mode repair: chmod could modify a concurrent inode.
            if stat.S_IMODE(existing.st_mode) == 0o755:
                return "unchanged"
    if archive is not None:
        regular(archive)
    with tempfile.TemporaryDirectory(prefix=".hhfab-stage-", dir=destination) as temporary:
        stage = Path(temporary)
        if archive is None:
            archive = stage / "release.tar.gz"
            download(version, archive)
        binary = stage / "hhfab"
        extract(archive, binary, pin)
        with binary.open("rb") as stream:
            os.fsync(stream.fileno())
        # No destination change before complete archive/member verification.
        if existing is None:
            if os.path.lexists(target):
                raise Refusal("destination changed during installation")
        else:
            now = regular(target)
            if (now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns, now.st_ctime_ns) != (
                    existing.st_dev, existing.st_ino, existing.st_size, existing.st_mtime_ns, existing.st_ctime_ns):
                raise Refusal("destination changed during installation")
        os.replace(binary, target)
    return "installed"


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--version", required=True, choices=tuple(PINS))
    parser.add_argument("--install-dir", type=Path, default=Path("/usr/local/bin"))
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    def expired(_signum, _frame):
        raise Refusal("installation deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(180)
    try:
        print("hhfab install: " + install(args.version, args.install_dir, args.archive))
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except KeyboardInterrupt:
        print("hhfab install: interrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as error:
        print("hhfab install: " + (str(error) if isinstance(error, Refusal) else "operational failure"), file=sys.stderr)
        sys.exit(1)
