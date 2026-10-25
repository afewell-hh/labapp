"""Lead-only synthetic kernel proof; no arguments, source disk, cloud or credentials.

Run as root in a fresh private mount namespace on the authorized clean inspector.
Creates only its own tiny /run backing file and loop. Production layout validation
must refuse TYPE=loop; this is not a positive whole-wrapper/source-layout proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile

from .collector import write_private
from .mounted_collect import (MOUNT_OPTIONS, Refused, command, device_number,
                              validate_clean, validate_layout, validate_mount,
                              validate_namespace)

SIZE = 32 * 1024 * 1024
LOSETUP = "/usr/sbin/losetup"
COLUMNS = "NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,MAJ:MIN,OFFSET,SIZELIMIT,RO"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_loop(raw, backing, identity, loop=None):
    """Require the exact newly owned regular file, inode, range and RO mapping."""
    info = backing.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_size != SIZE or
            (info.st_dev, info.st_ino) != identity):
        raise Refused("synthetic_backing_changed")
    try:
        entries = json.loads(raw)["loopdevices"]
        if len(entries) != 1:
            raise ValueError
        item = entries[0]
        name = item["name"]
        if (not re.fullmatch(r"/dev/loop[0-9]+", name) or
                (loop is not None and loop != name) or
                item["back-file"] != str(backing) or
                int(item["back-ino"]) != info.st_ino or
                item["back-maj:min"] != f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}" or
                int(item["offset"]) != 0 or int(item["sizelimit"]) != SIZE or
                item["ro"] not in (True, 1) or
                not re.fullmatch(r"[0-9]+:[0-9]+", item["maj:min"])):
            raise ValueError
        return name, item["maj:min"]
    except (KeyError, TypeError, ValueError):
        raise Refused("synthetic_loop_mismatch") from None


def populate_fixture(fixture, profile):
    """Compile-time public fixtures; return exact owned entries for cleanup."""
    if profile not in ('default', 'host-baseline-v1'):
        raise Refused('unsupported_profile')
    files = {'/etc/os-release': b'ID=labapp_synthetic\n'}
    if profile == 'host-baseline-v1':
        from .host_baseline import MANIFEST
        files.update({path: b'' for _, path, _ in MANIFEST})
        files['/home/ubuntu/hhfab/include/synthetic.yaml'] = (
            b'apiVersion: wiring.githedgehog.com/v1beta1\nkind: SwitchGroup\n'
            b'metadata: {name: synthetic}\nspec: {}\n')
    directories = set()
    for path, body in files.items():
        target = fixture / path.lstrip('/')
        parent = target.parent
        while parent != fixture:
            directories.add(parent)
            parent = parent.parent
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(body)
    return [fixture / path.lstrip('/') for path in files], sorted(
        directories, key=lambda path: len(path.parts), reverse=True)


def run(profile='default'):
    if os.geteuid() != 0:
        raise Refused("root_required")
    for tool in (LOSETUP, "/usr/sbin/mkfs.ext4", "/usr/sbin/blockdev",
                 "/usr/bin/lsblk", "/usr/bin/findmnt", "/usr/sbin/dumpe2fs",
                 "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/udevadm"):
        if not os.access(tool, os.X_OK):
            raise Refused("synthetic_tool_missing")
    work = Path(tempfile.mkdtemp(prefix="labapp-synthetic-", dir="/run"))
    fixture = work / "fixture"
    backing = work / "owned.ext4"
    target = work / "mounted"
    output = work / "inventory.json"
    attached = attempted = False
    loop = None
    cleanup_ok = True
    fixture_files, fixture_dirs = [], []
    try:
        validate_namespace(command, work)
        fixture.mkdir(mode=0o700)
        fixture_files, fixture_dirs = populate_fixture(fixture, profile)
        with backing.open("xb") as stream:
            stream.truncate(SIZE)
        info = backing.lstat()
        identity = info.st_dev, info.st_ino
        command(["/usr/sbin/mkfs.ext4", "-q", "-F", "-d", str(fixture), str(backing)])
        before = digest(backing)
        # Set before submit: an uncertain allocation is reconciled by exact owned file.
        attached = True
        loop = command([LOSETUP, "--find", "--show", "--read-only",
                        "--sizelimit", str(SIZE), str(backing)]).strip()
        loop, number = verify_loop(command([LOSETUP, "--json", "--list",
                                            "--output", COLUMNS, "--associated", str(backing)]),
                                   backing, identity, loop)
        device_number(loop, number)
        if command(["/usr/sbin/blockdev", "--getsize64", loop]).strip() != str(SIZE):
            raise Refused("synthetic_size_mismatch")
        if command(["/usr/sbin/blockdev", "--getro", loop]).strip() != "1":
            raise Refused("synthetic_not_readonly")
        layout = command(["/usr/bin/lsblk", "--json", "--paths", "--output",
                          "NAME,MAJ:MIN,TYPE,FSTYPE,RO,MOUNTPOINTS", "--", loop])
        root = json.loads(layout)["blockdevices"]
        if len(root) != 1 or root[0].get("type") != "loop":
            raise Refused("synthetic_not_loop")
        try:
            validate_layout(layout, loop, "/dev/synthetic", number, "0:0", "0:1")
        except Refused as error:
            if str(error) != "unsupported_disk_layout":
                raise
        else:
            raise Refused("production_layout_did_not_refuse_loop")
        validate_clean(command(["/usr/sbin/dumpe2fs", "-h", loop]))
        # Exercise dirty-evidence refusal without modifying or repairing any filesystem.
        try:
            validate_clean("Filesystem state: clean\nFilesystem features: needs_recovery\n")
        except Refused:
            pass
        else:
            raise Refused("dirty_evidence_not_refused")
        target.mkdir(mode=0o700)
        attempted = True
        command(["/usr/bin/mount", "--internal-only", "-t", "ext4", "-o",
                 MOUNT_OPTIONS, "--", loop, str(target)])
        validate_mount(command(["/usr/bin/findmnt", "--json", "--mountpoint", str(target),
                                "--output", "TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN,PROPAGATION"]),
                       target, loop, number)
        if profile == 'default':
            summary = write_private(target, output)
            records = json.loads(output.read_text(encoding="ascii"))["records"]
            captured = [item for item in records if item["path"] == "/etc/os-release"]
            if len(captured) != 1 or captured[0].get("private_content") != 'ID=labapp_synthetic\n':
                raise Refused("synthetic_collector_mismatch")
        else:
            from .host_baseline import write_private as host_write_private
            summary = host_write_private(target, output)
            report = json.loads(output.read_text(encoding="ascii"))
            if (report['profile'] != profile or not report['collection_complete'] or
                    len(report['fixed_records']) != 16 or report['include']['selected_count'] != 1):
                raise Refused("synthetic_collector_mismatch")
        if stat.S_IMODE(output.lstat().st_mode) != 0o600:
            raise Refused("synthetic_collector_mismatch")
    finally:
        if attempted:
            try:
                command(["/usr/bin/umount", "--internal-only", "--", str(target)])
                # No exact-target mount can remain, regardless of filesystem type.
                check = subprocess.run(["/usr/bin/findmnt", "--mountpoint", str(target),
                                        "--noheadings"], capture_output=True, timeout=15,
                                       env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
                if check.returncode != 1 or check.stdout:
                    raise Refused("synthetic_mount_remains")
            except BaseException:
                cleanup_ok = False
        if attached and cleanup_ok:
            try:
                actual, _ = verify_loop(command([LOSETUP, "--json", "--list", "--output",
                                                 COLUMNS, "--associated", str(backing)]),
                                        backing, identity, loop)
                command([LOSETUP, "--detach", actual])
                command(["/usr/bin/udevadm", "settle", "--timeout=10"])
                remaining = json.loads(command([LOSETUP, "--json", "--list", "--output",
                                                 COLUMNS, "--associated", str(backing)]))["loopdevices"]
                if remaining or digest(backing) != before:
                    raise Refused("synthetic_cleanup_or_readonly_failed")
            except BaseException:
                cleanup_ok = False
        if cleanup_ok:
            # Explicit owned entries only. Never recurse through a guest mount.
            for path in [output, backing] + fixture_files:
                path.unlink(missing_ok=True)
            for path in [target] + fixture_dirs + [fixture]:
                if path.exists():
                    path.rmdir()
            work.rmdir()
        else:
            raise Refused("synthetic_cleanup_required") from None
    return {"synthetic_kernel_mount": "passed", "collector": summary,
            "production_loop_refusal": "passed", "owned_cleanup": "passed",
            "dirty_evidence_refusal": "passed", "actual_dirty_journal": "not_tested"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("default", "host-baseline-v1"), default="default")
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        print(json.dumps(run(args.profile), sort_keys=True))
    except (Refused, OSError, ValueError, KeyError, KeyboardInterrupt, subprocess.SubprocessError):
        raise SystemExit("Synthetic kernel proof refused; owned cleanup may be required.") from None


if __name__ == "__main__":
    main()
