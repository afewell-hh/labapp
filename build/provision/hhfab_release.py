"""Pinned public hhfab release integrity and bounded child I/O (stdlib only)."""
import hashlib
import os
from pathlib import Path
import re
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
    """Fixed, safe diagnostic only; never include CLI output or generated data.

    `observation` is None unless an opt-in observer attached closed numeric data."""
    observation = None


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


READ_BLOCK = 65536
LINE_CLASSES = ("get", "hit", "ign", "err", "w", "e", "dpkg", "other")
_PREFIX = 24  # only this many leading bytes of a record are ever retained
_CLASS_BY_PREFIX = (
    (b"Get:", "get"), (b"Hit:", "hit"), (b"Ign:", "ign"), (b"Err:", "err"),
    (b"W:", "w"), (b"E:", "e"), (b"(Reading database", "dpkg"), (b"Preparing ", "dpkg"),
    (b"Selecting previously", "dpkg"), (b"Unpacking ", "dpkg"), (b"Setting up ", "dpkg"),
    (b"Processing triggers", "dpkg"),
)
_TERMINATOR = re.compile(rb"[\r\n]")
_NON_ASCII = re.compile(rb"[\x00\x80-\xff]")
_LONG_RECORD = 4096


class _Observer:
    """Closed counters over combined output. Only a fixed-size record prefix is
    held transiently for classification and then discarded; work is linear in
    observed bytes and memory is O(1) beyond the one read block."""

    def __init__(self):
        self.blocks = 0
        self.observed = 0
        self.lines = dict.fromkeys(LINE_CLASSES, 0)
        self.long_records = 0
        self.non_ascii = False
        self._prefix = b""
        self._length = 0

    def _finish(self):
        if self._length:
            name = "other"
            for prefix, label in _CLASS_BY_PREFIX:
                if self._prefix.startswith(prefix):
                    name = label
                    break
            self.lines[name] += 1
            if self._length > _LONG_RECORD:
                self.long_records += 1
        self._prefix = b""
        self._length = 0

    def feed(self, block):
        self.blocks += 1
        self.observed += len(block)
        if _NON_ASCII.search(block):
            self.non_ascii = True
        # CR and LF both end records, so progress rewrites cannot hide classes.
        for index, part in enumerate(_TERMINATOR.split(block)):
            if index:
                self._finish()
            if part:
                if len(self._prefix) < _PREFIX:
                    self._prefix += part[:_PREFIX - len(self._prefix)]
                self._length += len(part)

    def snapshot(self, limit, retained, seconds, started):
        return {
            "cap": limit, "block": READ_BLOCK, "deadline_seconds": int(seconds),
            "elapsed_ms": min(int((time.monotonic() - started) * 1000), 10 ** 9),
            "outcome": "overflow", "blocks": self.blocks,
            "observed_bytes": self.observed, "retained_bytes": retained,
            "lines": dict(self.lines), "long_records": self.long_records,
            "unterminated_tail": self._length > 0, "non_ascii": self.non_ascii,
        }


def _reap(proc):
    """Run every cleanup step; return the first failure (or None), never raise."""
    failure = None
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except BaseException as exc:
        failure = exc
    try:
        proc.wait(timeout=2)
    except BaseException as exc:
        if failure is None:
            failure = exc
    try:
        proc.stdout.close()
    except BaseException as exc:
        if failure is None:
            failure = exc
    return failure


def bounded(args, seconds, limit=1024 * 1024, env=None, on_start=None, observe=False):
    """Combined pipes capped in memory; kill/reap process group on every failure.

    observe=True (internal, fixed schema) attaches closed counters to the
    overflow Refusal. They cover only output read through the cutoff."""
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=env, start_new_session=True)
    failed = False
    try:
        # Every post-spawn initialization is inside the cleanup boundary.
        output = bytearray()
        started = time.monotonic()
        deadline = started + seconds
        observer = None
        if observe:
            try:
                observer = _Observer()
            except Exception:
                # Ordinary diagnostic failures only drop optional observations.
                # Interruptions still propagate through child cleanup below.
                pass
        if on_start is not None:
            on_start(proc.pid)
        with selectors.DefaultSelector() as select:
            select.register(proc.stdout, selectors.EVENT_READ)
            while select.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Refusal("command timeout")
                for key, _ in select.select(min(remaining, 0.1)):
                    block = os.read(key.fileobj.fileno(), READ_BLOCK)
                    if not block:
                        select.unregister(key.fileobj)
                        continue
                    if observer is not None:
                        # Diagnostics are best effort and never alter control flow.
                        try:
                            observer.feed(block)
                        except Exception:
                            observer = None
                    if len(output) + len(block) > limit:
                        refusal = Refusal("command output overflow")
                        if observer is not None:
                            try:
                                refusal.observation = observer.snapshot(
                                    limit, len(output), seconds, started)
                            except Exception:
                                pass
                        raise refusal
                    output.extend(block)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Refusal("command timeout")
        return proc.wait(timeout=remaining), bytes(output)
    except subprocess.TimeoutExpired:
        failed = True
        raise Refusal("command timeout") from None
    except BaseException:
        failed = True
        raise
    finally:
        # Also covers interruption/KeyboardInterrupt and descendants retaining pipes.
        # Leader reap does not prove the whole session/descendants are gone.
        cleanup_failure = _reap(proc)
        if cleanup_failure is not None and not failed:
            # Uncertain cleanup after an apparent success still fails; with a
            # primary failure in flight that primary is preserved.
            raise cleanup_failure


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
