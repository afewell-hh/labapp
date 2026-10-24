"""Fixed ext4 mount/collect/unmount for a lead-verified source-copy partition.

Run on a clean trusted Linux inspector, as root in a fresh private mount
namespace. This module does not create cloud resources, transfer data, repair
filesystems, activate volumes, or execute guest code. Device major/minor inputs
must be bound to the exact cloud lease/disk incarnation by the lead beforehand.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess

from .collector import Gap, write_private


class Refused(Exception):
    """Fixed status only, never include subprocess diagnostics/guest values."""


TOOLS = {"lsblk": "/usr/bin/lsblk", "findmnt": "/usr/bin/findmnt",
         "dumpe2fs": "/usr/sbin/dumpe2fs", "mount": "/usr/bin/mount",
         "umount": "/usr/bin/umount"}
MOUNT_OPTIONS = "ro,noload,nodev,nosuid,noexec"


def command(argv):
    """Trusted inspector commands only; stdout/stderr are never relayed."""
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=15, check=False,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        if result.returncode or len(result.stdout) > 65536 or len(result.stderr) > 65536:
            raise Refused("command_failed")
        return result.stdout.decode("utf-8")
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        raise Refused("command_failed") from None


def one_filesystem(raw):
    try:
        value = json.loads(raw)["filesystems"]
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise ValueError
        return value[0]
    except (ValueError, KeyError, TypeError):
        raise Refused("invalid_mount_evidence") from None


def device_number(path, expected):
    """Only direct, nonsymlink /dev block nodes; never open a device here."""
    if not re.fullmatch(r"/dev/[A-Za-z0-9]+", str(path)) or not re.fullmatch(r"[0-9]+:[0-9]+", expected):
        raise Refused("invalid_device")
    if not stat.S_ISDIR(os.lstat("/dev").st_mode):
        raise Refused("invalid_device")
    info = os.lstat(path)
    if not stat.S_ISBLK(info.st_mode) or f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}" != expected:
        raise Refused("device_identity_mismatch")


def private_directory(path):
    """Host path is explicit, absolute, nonsymlink, owned and mode0700."""
    path = Path(path)
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise Refused("invalid_private_directory")
    current = Path("/")
    for part in path.parts[1:]:
        current /= part
        if not stat.S_ISDIR(os.lstat(current).st_mode):
            raise Refused("invalid_private_directory")
    info = path.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refused("invalid_private_directory")
    return path


def validate_namespace(run):
    if os.readlink("/proc/self/ns/mnt") == os.readlink("/proc/1/ns/mnt"):
        raise Refused("private_namespace_required")
    root = one_filesystem(run([TOOLS["findmnt"], "--json", "--target", "/",
                               "--output", "MAJ:MIN,PROPAGATION"]))
    if root.get("propagation") != "private" or not re.fullmatch(r"[0-9]+:[0-9]+", str(root.get("maj:min"))):
        raise Refused("private_namespace_required")
    return root["maj:min"]


def validate_layout(raw, disk, partition, disk_number, partition_number, boot_number):
    try:
        roots = json.loads(raw)["blockdevices"]
        if len(roots) != 1:
            raise ValueError
        parent = roots[0]
        if (parent["name"] != disk or parent["maj:min"] != disk_number or
                parent["type"] != "disk" or parent.get("fstype") is not None or
                parent["ro"] not in (True, 1) or any(parent.get("mountpoints") or [])):
            raise ValueError
        children = parent["children"]
        if not 1 <= len(children) <= 4 or disk_number == boot_number:
            raise ValueError
        ext4 = []
        for child in children:
            if (child["type"] != "part" or child.get("children") or
                    child["ro"] not in (True, 1) or any(child.get("mountpoints") or []) or
                    child["maj:min"] == boot_number or
                    child.get("fstype") not in (None, "vfat", "ext4")):
                raise ValueError
            if child.get("fstype") == "ext4":
                ext4.append(child)
        if len(ext4) != 1 or ext4[0]["name"] != partition or ext4[0]["maj:min"] != partition_number:
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise Refused("unsupported_disk_layout") from None


def validate_clean(raw):
    fields = {}
    for line in raw.splitlines():
        key, sep, value = line.partition(":")
        if sep and key in ("Filesystem state", "Filesystem features"):
            if key in fields:
                raise Refused("unclean_filesystem")
            fields[key] = value.strip()
    if (fields.get("Filesystem state") != "clean" or
            "Filesystem features" not in fields or
            "needs_recovery" in fields["Filesystem features"].split()):
        raise Refused("unclean_filesystem")


def validate_mount(raw, mountpoint, partition, number):
    mounted = one_filesystem(raw)
    options = set(str(mounted.get("options", "")).split(","))
    if (mounted.get("target") != str(mountpoint) or mounted.get("source") != partition or
            mounted.get("maj:min") != number or mounted.get("fstype") != "ext4" or
            mounted.get("propagation") != "private" or
            not {"ro", "nodev", "nosuid", "noexec"} <= options or
            not {"noload", "norecovery"} & options or "rw" in options):
        raise Refused("mount_contract_failed")


def collect_mounted(disk, partition, disk_number, partition_number, private_dir,
                    run=command, collector=write_private):
    """Caller is root; run/collector injection is for offline tests only.

    An unmount failure refuses success and preserves the private mountpoint for
    lead cleanup. Never recursively delete a guest mount or inspect its files
    during cleanup. The explicit private directory must initially be empty.
    """
    private_dir = private_directory(private_dir)
    if disk == partition or disk_number == partition_number:
        raise Refused("invalid_device")
    if any(private_dir.iterdir()):
        raise Refused("private_directory_not_empty")
    boot_number = validate_namespace(run)
    device_number(disk, disk_number)
    device_number(partition, partition_number)
    validate_layout(run([TOOLS["lsblk"], "--json", "--paths", "--output",
                         "NAME,MAJ:MIN,TYPE,FSTYPE,RO,MOUNTPOINTS", "--", disk]),
                    disk, partition, disk_number, partition_number, boot_number)
    validate_clean(run([TOOLS["dumpe2fs"], "-h", partition]))
    mountpoint = private_dir / "guest-root"
    output = private_dir / "inventory.json"
    mountpoint.mkdir(mode=0o700)
    attempted, success = False, False
    try:
        attempted = True
        run([TOOLS["mount"], "--internal-only", "-t", "ext4", "-o", MOUNT_OPTIONS,
             "--", partition, str(mountpoint)])
        validate_mount(run([TOOLS["findmnt"], "--json", "--mountpoint", str(mountpoint),
                            "--output", "TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN,PROPAGATION"]),
                       mountpoint, partition, partition_number)
        summary = collector(mountpoint, output)
        success = True
    finally:
        try:
            if attempted:
                run([TOOLS["umount"], "--internal-only", "--", str(mountpoint)])
        except BaseException:
            # The source may remain mounted: never walk/rmtree this directory.
            raise Refused("unmount_failed") from None
        finally:
            if not success and output.exists():
                output.unlink()
        mountpoint.rmdir()
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disk", required=True)
    parser.add_argument("--partition", required=True)
    parser.add_argument("--disk-number", required=True)
    parser.add_argument("--partition-number", required=True)
    parser.add_argument("--private-dir", required=True)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if os.geteuid() != 0:
            raise Refused("root_required")
        summary = collect_mounted(args.disk, args.partition, args.disk_number,
                                  args.partition_number, args.private_dir)
    except (Refused, Gap, OSError, ValueError, KeyboardInterrupt):
        parser.exit(1, "Mount collection refused; private cleanup may be required.\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
