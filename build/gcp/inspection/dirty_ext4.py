"""Lead-only, no-input real pending-journal refusal proof on an owned file.

Preparation writes only a new 32MiB regular file via mkfs/debugfs journal APIs.
The file is then attached READ_ONLY and NEVER mounted, repaired or replayed.
Run in a private mount namespace on the authorized clean inspector. No cloud,
credentials, source paths or source disk discovery. Not whole-wrapper proof:
production layout validation still refuses loop devices.
"""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

from .mounted_collect import Refused, command, device_number, validate_clean, validate_namespace
from .synthetic_ext4 import COLUMNS, LOSETUP, SIZE, digest, verify_loop


def validate_dirty_evidence(header, journal):
    """Require a real pending committed fixture transaction, then guard refusal."""
    features = re.findall(r"^Filesystem features:\s*(.*)$", header, re.MULTILINE)
    starts = re.findall(r"^Journal start:\s*([0-9]+)\s*$", header, re.MULTILINE)
    records = re.findall(r"^Found expected sequence ([0-9]+), type ([0-9]+) "
                         r"\((descriptor|commit) block\) at block ([0-9]+)$",
                         journal, re.MULTILINE)
    if (len(features) != 1 or "needs_recovery" not in features[0].split()
            or starts != ["1"]
            or "Journal starts at block 1, transaction 1\n" not in journal
            or records != [("1", "1", "descriptor", "1"), ("1", "2", "commit", "3")]
            or "No magic number at block 4: end of journal." not in journal):
        raise Refused("dirty_fixture_evidence_missing")
    try:
        validate_clean(header)
    except Refused as error:
        if str(error) != "unclean_filesystem":
            raise
    else:
        raise Refused("dirty_fixture_not_refused")


def validate_loop_layout(raw, loop, number):
    entries = json.loads(raw).get("blockdevices")
    if (not isinstance(entries, list) or len(entries) != 1
            or not isinstance(entries[0], dict)
            or entries[0].get("name") != loop or entries[0].get("maj:min") != number
            or entries[0].get("type") != "loop" or entries[0].get("fstype") != "ext4"
            or entries[0].get("ro") not in (True, 1)
            or entries[0].get("mountpoints") != [None] or entries[0].get("children")):
        raise Refused("dirty_fixture_layout_mismatch")


def loop_layout(loop):
    return command(["/usr/bin/lsblk", "--json", "--paths", "--output",
                    "NAME,MAJ:MIN,TYPE,FSTYPE,RO,MOUNTPOINTS", "--", loop])


def run():
    if os.geteuid() != 0:
        raise Refused("root_required")
    for tool in (LOSETUP, "/usr/sbin/mkfs.ext4", "/usr/sbin/debugfs",
                 "/usr/sbin/dumpe2fs", "/usr/sbin/blockdev", "/usr/bin/lsblk",
                 "/usr/bin/findmnt", "/usr/bin/udevadm"):
        if not os.access(tool, os.X_OK):
            raise Refused("dirty_fixture_tool_missing")
    work = Path(tempfile.mkdtemp(prefix="labapp-dirty-", dir="/run"))
    backing = work / "owned.ext4"
    script = work / "journal.commands"
    attached = False
    loop = None
    cleanup_ok = True
    try:
        validate_namespace(command, work)
        fd = os.open(backing, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.truncate(SIZE)
        info = backing.lstat()
        identity = info.st_dev, info.st_ino
        command(["/usr/sbin/mkfs.ext4", "-q", "-F", "-b", "4096", str(backing)])
        # Upstream e2fsprogs test recipe: one real committed journal transaction.
        # Block 7000 is within this fixed 8192-block fixture; no replay occurs.
        with script.open("x", encoding="ascii") as stream:
            stream.write("journal_open\njournal_write -b 7000 /dev/zero\njournal_close\n")
        command(["/usr/sbin/debugfs", "-w", "-f", str(script), str(backing)])
        before = digest(backing)
        attached = True  # uncertain allocation must reconcile this exact file
        loop = command([LOSETUP, "--find", "--show", "--read-only",
                        "--sizelimit", str(SIZE), str(backing)]).strip()
        loop, number = verify_loop(command([LOSETUP, "--json", "--list", "--output",
                                           COLUMNS, "--associated", str(backing)]),
                                   backing, identity, loop)
        device_number(loop, number)
        if (command(["/usr/sbin/blockdev", "--getro", loop]).strip() != "1"
                or command(["/usr/sbin/blockdev", "--getsize64", loop]).strip() != str(SIZE)):
            raise Refused("dirty_fixture_not_readonly")
        validate_loop_layout(loop_layout(loop), loop, number)
        validate_dirty_evidence(command(["/usr/sbin/dumpe2fs", "-h", loop]),
                                command(["/usr/sbin/debugfs", "-R", "logdump", loop]))
    finally:
        if attached:
            try:
                actual, number = verify_loop(command([LOSETUP, "--json", "--list", "--output",
                                                      COLUMNS, "--associated", str(backing)]),
                                             backing, identity, loop)
                device_number(actual, number)
                validate_loop_layout(loop_layout(actual), actual, number)
                command([LOSETUP, "--detach", actual])
                command(["/usr/bin/udevadm", "settle", "--timeout=10"])
                remaining = json.loads(command([LOSETUP, "--json", "--list", "--output",
                                                 COLUMNS, "--associated", str(backing)]))["loopdevices"]
                if remaining or digest(backing) != before:
                    raise Refused("dirty_fixture_cleanup_or_readonly_failed")
            except BaseException:
                cleanup_ok = False
        if cleanup_ok:
            for path in (script, backing):
                path.unlink(missing_ok=True)
            work.rmdir()
        else:
            raise Refused("dirty_fixture_cleanup_required") from None
    return {"actual_pending_journal": "passed", "production_cleanliness_refusal": "passed",
            "fixture_mount_attempts": 0, "unchanged_hash": "passed", "owned_cleanup": "passed"}


def main():
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        print(json.dumps(run(), sort_keys=True))
    except (Refused, OSError, ValueError, KeyError, KeyboardInterrupt, subprocess.SubprocessError):
        raise SystemExit("Dirty-journal proof refused; owned cleanup may be required.") from None


if __name__ == "__main__":
    main()
