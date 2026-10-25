#!/usr/bin/env python3
"""Fixed KVM-only real-mode execution witness, Python3.12 stdlib, any UID/cwd.

No options/environment overrides. Needs sibling hhfab_release.py, pinned distro
QEMU/SeaBIOS and actual /dev/kvm access. Does not alter devices/groups/modules.
No network, Linux guest, student login, VLAB or capacity proof is implied.
"""
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import sys
import tempfile
import time

from hhfab_release import Refusal, bounded, digest

ARTIFACTS = {
    "/usr/bin/qemu-system-x86_64": "8a35ccba41582fc6c38b9df85fc9e35fa1d42f414d2d7d8090ee9b2f5e7c0854",
    "/usr/share/seabios/bios-256k.bin": "1a9ea4f17bcfb27bda5728e2c21d9fa074cf7947b9b4910bb28213a735c96735"}


def fixture(nonce):
    if len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
        raise Refusal("invalid nonce")
    expected = ("LABAPP-L2:" + nonce + "\n").encode("ascii")
    # 16-bit BIOS entry: CLI; XOR AX,AX; MOV DS,AX. For each output byte,
    # MOV AL,imm8; OUT imm8,AL (port E9). MOV AX,10h; OUT F4h,AX exits33.
    # HLT/JMP guard is unreachable on a correctly functioning debug-exit device.
    code = b"\xfa\x31\xc0\x8e\xd8" + b"".join(b"\xb0" + bytes([c]) + b"\xe6\xe9" for c in expected)
    code += b"\xb8\x10\x00\xe7\xf4\xf4\xeb\xfd"
    sector = code.ljust(510, b"\x00") + b"\x55\xaa"
    return sector.ljust(1024 * 1024, b"\x00"), expected


def verdict(code, output, expected):
    if code != 33 or output != expected:
        raise Refusal("execution nonce/exit mismatch")


def probe(*, test_tcg=False):
    started = time.monotonic()
    for path, sha in ARTIFACTS.items():
        if Path(path).is_symlink() or digest(path) != sha:
            raise Refusal("QEMU/firmware artifact identity mismatch")
    # Pins are independently checked, not inferred solely from a version banner.
    import runpy
    module = runpy.run_path(str(Path(__file__).with_name("install-qemu.py")))
    actual = module["installed"]()
    if any(actual.get(name) != version for name, version in module["PINS"].items()):
        raise Refusal("QEMU package identity mismatch")
    device = None
    if Path("/dev/kvm").exists():
        info = Path("/dev/kvm").stat()
        device = {"character": stat.S_ISCHR(info.st_mode), "uid": info.st_uid, "gid": info.st_gid, "mode": oct(stat.S_IMODE(info.st_mode)),
                  "major": os.major(info.st_rdev), "minor": os.minor(info.st_rdev)}
    if not test_tcg and (device is None or not device["character"]):
        raise Refusal("KVM character device absent; no fallback")
    data, expected = fixture(secrets.token_hex(16))
    with tempfile.TemporaryDirectory(prefix="labapp-qemu-witness-", dir="/tmp") as temporary:
        disk = Path(temporary) / "boot.raw"
        disk.write_bytes(data)
        disk.chmod(0o600)
        before = digest(disk)
        command = ["/usr/bin/qemu-system-x86_64", "-machine", "pc-i440fx-8.2",
                   "-accel", "tcg,thread=single" if test_tcg else "kvm", "-cpu", "qemu64" if test_tcg else "host",
                   "-smp", "1", "-m", "32M", "-nodefaults", "-no-user-config", "-display", "none",
                   "-monitor", "none", "-serial", "none", "-parallel", "none", "-nic", "none", "-no-reboot",
                   "-boot", "order=c,strict=on", "-bios", "/usr/share/seabios/bios-256k.bin",
                   "-drive", f"file={disk},format=raw,if=ide,snapshot=on",
                   "-chardev", "stdio,id=witness,signal=off", "-device", "isa-debugcon,iobase=0xe9,chardev=witness",
                   "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
        code, output = bounded(command, 15, limit=4096,
                               env={"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": temporary, "TMPDIR": temporary})
        verdict(code, output, expected)
        if digest(disk) != before:
            raise Refusal("backing fixture changed")
    return {"accelerator": "TCG-test-only" if test_tcg else "KVM", "exit": code, "nonce_equal": True,
            "fixture_sha256": before, "backing_unchanged": True, "owned_workspace_removed": not Path(temporary).exists(),
            "artifacts": ARTIFACTS, "pins": module["PINS"], "uid": os.getuid(), "gid": os.getgid(),
            "groups": os.getgroups(), "device": device, "seconds": round(time.monotonic() - started, 3)}


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    def expired(_signum, _frame):
        raise Refusal("overall deadline exceeded")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(40)
    try:
        if len(sys.argv) != 1:
            raise Refusal("no options accepted")
        print(json.dumps(probe(), sort_keys=True))
    except KeyboardInterrupt:
        print("qemu witness: interrupted", file=sys.stderr)
        sys.exit(130)
    except (Refusal, OSError) as exc:
        print("qemu witness: " + str(exc), file=sys.stderr)
        sys.exit(1)
