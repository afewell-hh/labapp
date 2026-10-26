"""Sentinel-only pre-seal cloud-init summary; Python stdlib, root, stdin JSON.

Read at most 64 KiB + one rejection byte. Never print input bytes/errors. The
run identities come from the same checked CD staging as guest-build.sh.

Exit status is the renderer classification read by assert-sentinel.sh: 0 accepted,
1 input rejected, 3-7 fixed output-write failures (see emit). Nonzero is never accepted.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import sys

STATUS_CAP = 65536


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate status field")
        result[key] = value
    return result


def summary(raw):
    if len(raw) > STATUS_CAP:
        raise ValueError("status size")
    body = json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    if not isinstance(body, dict) or body.get("status") != "done":
        raise ValueError("status not done")
    counts = {"errors": 0, "recoverable_errors": 0}

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in counts:
                    # cloud-init 24.x uses a list for errors and a mapping of
                    # severity to lists for recoverable_errors. Unknown types
                    # fail, including false/0/null masquerading as no errors.
                    if isinstance(item, list):
                        counts[key] += len(item)
                    elif isinstance(item, dict) and key == "recoverable_errors":
                        if not all(isinstance(v, list) for v in item.values()):
                            raise ValueError("error shape")
                        counts[key] += sum(map(len, item.values()))
                    else:
                        raise ValueError("error shape")
                if key in ("exit_code", "returncode", "status_code"):
                    if item is not None and (type(item) is not int or item != 0):
                        raise ValueError("exit status")
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(body)
    if any(counts.values()):
        raise ValueError("cloud-init errors")
    return {"status": "done", **counts}


def record(raw, nonce, inputs):
    if not all(re.fullmatch("[0-9a-f]{64}", value) for value in (nonce, inputs)):
        raise ValueError("identity")
    summary(raw)
    return (f"\nLABAPP-EVIDENCE v1 nonce={nonce} inputs={inputs} "
            "cloud-init=done errors=0 recoverable=0\n")


REJECTED = 1       # stdin/identity/summary rejection (never a write failure)
WRITE_EPIPE = 3    # reader of the output closed
WRITE_ENOSPC = 4   # e.g. /dev/full
WRITE_EIO = 5
WRITE_OTHER = 6    # any other errno, including a closed/invalid descriptor
WRITE_STALLED = 7  # write made no progress


def emit(data, fd=1):
    """Write all of data to fd with os.write; return 0 or a fixed status. No buffered
    stream is involved, so interpreter finalization cannot flush (and fail) again."""
    view = memoryview(data)
    while view:
        try:
            count = os.write(fd, view)
        except InterruptedError:
            continue
        except OSError as exc:
            return {errno.EPIPE: WRITE_EPIPE, errno.ENOSPC: WRITE_ENOSPC,
                    errno.EIO: WRITE_EIO}.get(exc.errno, WRITE_OTHER)
        if count <= 0:
            return WRITE_STALLED
        view = view[count:]
    return 0


def main():
    try:
        root = Path(__file__).parent
        raw = sys.stdin.buffer.read(STATUS_CAP + 1)
        line = record(raw, (root / "nonce").read_text(encoding="ascii").strip(),
                      hashlib.sha256((root / "MANIFEST").read_bytes()).hexdigest())
    except (ValueError, OSError, RecursionError):
        return REJECTED
    return emit(line.encode("ascii"))


if __name__ == "__main__":
    sys.exit(main())
