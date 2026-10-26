"""Pinned public hhfab release integrity and bounded child I/O (stdlib only)."""
import hashlib
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tarfile
import time

PINS = {
    "0.43.1": (93055151, "b1387342191a329772c2595504ec6ff129eb45980727c1c86d9901ef4d9f37a4", 170709176,
               "b5c7e0265339b9b95fa1073967bfb6c6fede6086755c85eca24cb80637b04e37"),
    "0.50.4": (59692810, "a8e6d1b8d0f752d7586c29201add3ff174d330c87fa25a3bdadec43f6c1376b6", 104890530,
               "b7a5c7744e3b617d7e76d9ccc9015588a8c32da62623c8ecc114cae24e1a5fcd"),
}
class Refusal(Exception):
    """Fixed, safe diagnostic only; never include CLI output or generated data."""


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def bounded(args, seconds, limit=1024 * 1024, env=None, on_start=None):
    """Combined pipes capped in memory; kill/reap process group on every failure."""
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=env, start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + seconds
    try:
        # Keep observation inside the cleanup boundary: a failing observer must
        # never strand the child just launched above. Existing callers unchanged.
        if on_start is not None:
            on_start(proc.pid)
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
        # Also covers interruption/KeyboardInterrupt and descendants retaining pipes.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=2)
        proc.stdout.close()


def extract(archive, target, pin):
    """Never tar.extract: exact bounded sole regular member, no links/extra entries."""
    archive_size, archive_sha, size, member_sha = pin
    if archive.stat().st_size != archive_size or digest(archive) != archive_sha:
        raise Refusal("archive checksum/size mismatch")
    with tarfile.open(archive, "r:gz") as tar:
        member = tar.next()
        if (member is None or member.name != "hhfab-linux-amd64/hhfab"
                or not member.isfile() or member.size != size or tar.next() is not None):
            raise Refusal("unexpected release archive member")
        with tar.extractfile(member) as src, target.open("xb") as dst:
            remaining = size
            while remaining:
                block = src.read(min(1024 * 1024, remaining))
                if not block:
                    raise Refusal("truncated archive member")
                dst.write(block)
                remaining -= len(block)
        if digest(target) != member_sha:
            raise Refusal("member checksum mismatch")
    target.chmod(0o755)



def download(version, target):
    pin = PINS[version]
    url = ("https://github.com/githedgehog/fabricator/releases/download/v" + version
           + "/hhfab-linux-amd64-v" + version + ".tar.gz")
    code, _ = bounded(["curl", "--fail", "--location", "--silent", "--show-error",
                       "--proto", "=https", "--proto-redir", "=https", "--max-time", "120",
                       "--speed-limit", "1024", "--speed-time", "20", "--max-filesize", str(pin[0]),
                       "--output", str(target), url], 125)
    if code:
        raise Refusal("official release download failed")
