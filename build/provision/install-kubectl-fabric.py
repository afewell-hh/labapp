"""Install the native kubectl-fabric plugin from the pinned Fabric v0.96.2 hhfctl linux/amd64 archive.

Invoke python3 /absolute/path/install-kubectl-fabric.py --version 0.96.2 --platform linux/amd64
[--install-dir /absolute/dir] [--archive /absolute/hhfctl-linux-amd64-v0.96.2.tar.gz]
on Ubuntu 24.04 with Python 3.12 stdlib (3.10+ for host tests), linux/amd64 only. No environment
overrides, prompts, TTY, sudo, kubeconfig or cwd dependence; all paths must be absolute. Default dir
/usr/local/bin must already exist and be caller-owned (root for the default; no automatic sudo); an
explicit caller-owned alternate supports nonroot use. Network mode needs curl in /usr/bin or /bin;
--archive accepts a local single-link regular file. Keep sibling hhfab_release.py (Refusal, bounded,
digest) alongside this file.
The repo pins only the archive (size and SHA256). The member's size and hash are UNOBSERVED, so the
expected installed bytes are derived from the verified archive via bounded streaming extraction of
the sole member hhfctl-linux-amd64/hhfctl (member size capped at MEMBER_LIMIT, a finite assumption).
Because no independent member pin exists, every run, including a rerun that finds matching bytes,
needs the verified archive again (download or --archive). Absent target: install 0755 without
clobber; derived-equal 0755 target: unchanged; derived-equal bytes with another mode: atomic repair;
any other existing bytes: refused and preserved (no force or upgrade). Callers must exclude
concurrent mutations of the destination directory and its ancestors; only the final directory's
ownership/mode is checked. Never executes the installed or archived bytes.
"""
import argparse
import contextlib
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
import sys
import tarfile
import tempfile
import zlib

from hhfab_release import Refusal, bounded, digest

VERSION = "0.96.2"
PLATFORM = "linux/amd64"
NAME = "kubectl-fabric"
MEMBER = "hhfctl-linux-amd64/hhfctl"
PINS = {VERSION: {
    "url": "https://github.com/githedgehog/fabric/releases/download/v0.96.2/hhfctl-linux-amd64-v0.96.2.tar.gz",
    "size": 13620070,
    "sha256": "379b7ae4210f766fab733024bbb3313333135bfbde04ecf1bdf1d38e735aabca",
}}
# Finite assumptions, not measured fit: curl transfer, child (transfer plus grace), whole run.
TRANSFER, CHILD, TOTAL = 120, 125, 180
# Finite assumption: ceiling on the uncompressed member, which has no repo pin.
MEMBER_LIMIT = 256 * 1024 * 1024
RESULT_LIMIT = 4096
CURL_DIRS = ("/usr/bin", "/bin")
CHILD_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
BLOCK = 1024 * 1024


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


def exact_archive(path, pin):
    info = regular(path)
    return info.st_size == pin["size"] and digest(path) == pin["sha256"]


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)


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
        raise Refusal("official archive download failed")


def copy_archive(source, target, pin):
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as src, target.open("xb") as dst:
        info = os.fstat(src.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != pin["size"]:
            raise Refusal("archive input must be a single-link regular file of the pinned size")
        remaining = pin["size"]
        while remaining:
            block = src.read(min(BLOCK, remaining))
            if not block:
                raise Refusal("truncated archive input")
            dst.write(block)
            remaining -= len(block)
        if src.read(1):
            raise Refusal("archive input grew during copy")


def extract_member(archive, target, pin):
    """Never tar.extract: verified archive, sole regular fixed member, bounded streamed copy.

    Returns (size, sha256) derived from the written member bytes."""
    if not exact_archive(archive, pin):
        raise Refusal("archive size/checksum mismatch")
    try:
        with tarfile.open(archive, "r:gz") as tar:
            member = tar.next()
            if (member is None or member.name != MEMBER or not member.isreg()
                    or member.islnk() or member.issym()):
                raise Refusal("unexpected release archive member")
            if member.size <= 0 or member.size > MEMBER_LIMIT:
                raise Refusal("archive member size outside the bounded limit")
            if tar.next() is not None:
                raise Refusal("unexpected release archive member")
            total = hashlib.sha256()
            with tar.extractfile(member) as src, target.open("xb") as dst:
                remaining = member.size
                while remaining:
                    block = src.read(min(BLOCK, remaining))
                    if not block:
                        raise Refusal("truncated archive member")
                    dst.write(block)
                    total.update(block)
                    remaining -= len(block)
            trailer = tar.fileobj.read(tarfile.RECORDSIZE + 1)
            if len(trailer) > tarfile.RECORDSIZE or trailer.strip(b"\0"):
                raise Refusal("unexpected release archive trailer")
    except (tarfile.TarError, gzip.BadGzipFile, EOFError, zlib.error):
        raise Refusal("unreadable release archive") from None
    return member.size, total.hexdigest()


def install(version, platform_name, destination, archive=None):
    if (version not in PINS or platform_name != PLATFORM or platform.system() != "Linux"
            or platform.machine() not in ("x86_64", "amd64")):
        raise Refusal("unsupported version or platform")
    pin = PINS[version]
    if destination == Path("/usr/local/bin") and os.geteuid() != 0:
        raise Refusal("default install directory requires root")
    if len(json.dumps(str(destination / NAME))) > 1024:
        raise Refusal("target path exceeds result budget")
    directory(destination)
    target = destination / NAME
    existing = None
    if os.path.lexists(target):
        existing = regular(target)
        if existing.st_uid != os.geteuid():
            raise Refusal("existing target must be caller-owned")
    if archive is not None:
        if not archive.is_absolute():
            raise Refusal("archive path must be absolute")
        if not exact_archive(archive, pin):
            raise Refusal("archive input size/checksum mismatch")
    else:
        curl()  # refuses before staging when the dependency is absent
    status = "installed"
    stage = Path(tempfile.mkdtemp(prefix=".kubectl-fabric-stage-", dir=destination))
    try:
        staged_archive = stage / "archive.tar.gz"
        staged = stage / NAME
        if archive is None:
            download(pin, staged_archive)
        else:
            copy_archive(archive, staged_archive, pin)
        size, sha = extract_member(staged_archive, staged, pin)
        staged_archive.unlink()
        derived = {"size": size, "sha256": sha}
        if regular(staged).st_size != size or digest(staged) != sha:
            raise Refusal("staged member changed after extraction")
        publish = True
        if existing is not None:
            if existing.st_size != size or digest(target) != sha:
                raise Refusal("existing kubectl-fabric differs from the archive member; no upgrade or force mode")
            if stat.S_IMODE(existing.st_mode) == 0o755:
                publish = False
                status = "unchanged"
            else:
                status = "mode-repaired"
        if publish:
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
    return result(version, pin, derived, target, status)


def result(version, pin, derived, target, status):
    info = regular(target)
    observed = digest(target)
    after = regular(target)
    if (identity(info) != identity(after) or info.st_uid != os.geteuid()
            or info.st_size != derived["size"] or observed != derived["sha256"]
            or stat.S_IMODE(info.st_mode) != 0o755):
        raise Refusal("installed target changed or fails verification")
    here = Path(__file__).resolve()
    helper = Path(sys.modules["hhfab_release"].__file__).resolve()
    outcome = {
        "tool": NAME, "version": version, "platform": PLATFORM, "archive_url": pin["url"],
        "archive_size": pin["size"], "archive_sha256": pin["sha256"], "member": MEMBER,
        "member_size": derived["size"], "member_sha256": derived["sha256"],
        "module_sha256": hashlib.sha256(here.read_bytes()).hexdigest(),
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "target": str(target), "target_sha256": observed,
        "target_mode": format(stat.S_IMODE(info.st_mode), "04o"), "status": status,
        "verified": "archive size/sha256 against the repo pin; member size/sha256 derived from it",
        "not_verified": "signature, certificate, redirect chain, runtime compatibility, plugin discovery, student access",
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
        print("kubectl-fabric install: interrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as error:
        print("kubectl-fabric install: " + (str(error) if isinstance(error, Refusal) else "operational failure"),
              file=sys.stderr)
        sys.exit(1)
