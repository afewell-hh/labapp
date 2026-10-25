#!/usr/bin/env python3
"""Root-only Ubuntu24.04 amd64 Python3.12 module; no options/env overrides.

Needs apt/dpkg, Ubuntu archive keyring, HTTPS CA certificates and sibling
hhfab_release.py. Any cwd; no shell/login environment. Run on disposable guests:
APT cannot roll back partial failure. Preserves distro sources/preferences.
"""
import json
import hashlib
import os
from pathlib import Path
import sys
import signal
import tempfile
import time

from hhfab_release import Refusal, bounded, digest

SNAPSHOT = "20261024T000000Z"
PINS = {"qemu-system-x86": "1:8.2.2+ds-0ubuntu1.18",
        "qemu-utils": "1:8.2.2+ds-0ubuntu1.18", "socat": "1.8.0.0-4ubuntu0.1",
        "seabios": "1.16.3-2"}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
       "DEBIAN_FRONTEND": "noninteractive", "HOME": "/root"}


def call(args, seconds=10):
    code, out = bounded(args, seconds, env=ENV)
    if code:
        raise Refusal("command failed: " + Path(args[0]).name)
    return out


def installed():
    rows = call(["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\\n"]).decode().splitlines()
    return {row.split("\t")[0]: row.split("\t")[1] for row in rows
            if row.split("\t")[2] == "installed"}


def verify_tools():
    # dpkg --verify also reports documentation deliberately excluded by minimal
    # Ubuntu images. Verify the mandatory payloads against installed package
    # md5sums instead; origin authenticity is APT's signed SHA256 index chain.
    for package, relative in [('qemu-system-x86', 'usr/bin/qemu-system-x86_64'),
                              ('qemu-utils', 'usr/bin/qemu-img'), ('socat', 'usr/bin/socat1'),
                              ('seabios', 'usr/share/seabios/bios-256k.bin')]:
        metadata = call(['/usr/bin/dpkg-query', '--control-show', package, 'md5sums']).decode()
        expected = dict(line.split(None, 1)[::-1] for line in metadata.splitlines())
        artifact = Path('/') / relative
        if artifact.is_symlink() or not artifact.is_file() or relative not in expected:
            raise Refusal('installed pinned artifact missing: ' + package)
        if hashlib.md5(artifact.read_bytes()).hexdigest() != expected[relative]:
            raise Refusal('installed pinned artifact drift: ' + package)

    socat = Path('/usr/bin/socat')
    if not socat.is_symlink() or os.readlink(socat) != 'socat1':
        raise Refusal('socat package symlink drift')


def preflight():
    if os.geteuid() != 0:
        raise Refusal("root required")
    release = Path("/etc/os-release").read_text().splitlines()
    if 'ID=ubuntu' not in release or 'VERSION_ID="24.04"' not in release:
        raise Refusal("Ubuntu 24.04 required")
    if call(["/usr/bin/dpkg", "--print-architecture"]).strip() != b"amd64":
        raise Refusal("amd64 required")
    if call(["/usr/bin/dpkg", "--audit"]).strip():
        raise Refusal("broken dpkg state")
    if call(["/usr/bin/apt-mark", "showhold"]).strip():
        raise Refusal("held packages require explicit resolution")
    for path in ("/usr/share/keyrings/ubuntu-archive-keyring.gpg", "/etc/ssl/certs/ca-certificates.crt"):
        if not Path(path).is_file():
            raise Refusal("archive keyring/CA dependency missing")
    before = installed()
    for name, version in PINS.items():
        actual = before.get(name)
        if actual is not None and actual != version:
            raise Refusal("installed pinned package drift: " + name)
    if all(before.get(name) == version for name, version in PINS.items()):
        verify_tools()
    return before


def install():
    started = time.monotonic()
    before = preflight()
    # Lists/cache/sources/preferences isolated. The real dpkg database stays real;
    # APT acquires its normal dpkg locks. No ambient APT_CONFIG or proxy variables.
    with tempfile.TemporaryDirectory(prefix="labapp-qemu-", dir="/var/tmp") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        for name in ("lists/partial", "archives/partial", "parts", "preferences"):
            (root / name).mkdir(parents=True)
        sources = root / "sources.list"
        sources.write_text("".join(
            "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
            f"https://snapshot.ubuntu.com/ubuntu/{SNAPSHOT}/ {suite} main universe\n"
            for suite in ("noble", "noble-updates", "noble-security")))
        options = ["-o", f"Dir::Etc::sourcelist={sources}", "-o", f"Dir::Etc::sourceparts={root / 'parts'}",
                   "-o", f"Dir::Etc::preferences={root / 'preferences' / 'none'}",
                   "-o", f"Dir::Etc::preferencesparts={root / 'preferences'}",
                   "-o", f"Dir::State::lists={root / 'lists'}", "-o", f"Dir::Cache::archives={root / 'archives'}",
                   "-o", "Acquire::Retries=0", "-o", "Acquire::https::Timeout=15",
                   "-o", "DPkg::Lock::Timeout=10", "-o", "APT::Get::AllowUnauthenticated=false",
                   "-o", "Acquire::AllowInsecureRepositories=false", "-o", "Acquire::AllowWeakRepositories=false",
                   "-o", "Acquire::AllowDowngradeToInsecureRepositories=false",
                   "-o", "Acquire::Check-Valid-Until=true",
                   "-o", "APT::Get::allow-Downgrades=false", "-o", "APT::Get::allow-Change-Held-Packages=false"]
        apt = ["/usr/bin/apt-get", *options]
        def run(args):
            remaining = 210 - (time.monotonic() - started)
            if remaining <= 0:
                raise Refusal("installation deadline exceeded")
            return call(args, min(180, remaining))
        run([*apt, "-o", "APT::Update::Error-Mode=any", "update"])
        # dpkg audit can be clean despite configured-but-unsatisfied dependency
        # relations. Refuse that base before install can implicitly repair it.
        run([*apt, "check"])
        selected = [name + "=" + version for name, version in PINS.items()]
        # --no-remove and no downgrade/hold override remain active for simulation
        # and actual transaction. Standard signed Release/index/deb verification.
        run([*apt, "--simulate", "--no-remove", "--no-install-recommends", "install", *selected])
        run([*apt, "--yes", "--no-remove", "--no-install-recommends", "install", *selected])
        run([*apt, "check"])
        archives = [{"name": p.name, "bytes": p.stat().st_size, "sha256": digest(p)}
                    for p in sorted((root / "archives").glob("*.deb"))]
        after = installed()
        if any(after.get(name) != version for name, version in PINS.items()):
            raise Refusal("installed version mismatch")
        if call(["/usr/bin/dpkg", "--audit"]).strip():
            raise Refusal("post-install dpkg audit failed")
        verify_tools()
        for path in ("/usr/bin/qemu-system-x86_64", "/usr/bin/qemu-img", "/usr/bin/socat",
                     "/usr/share/seabios/bios-256k.bin"):
            if not Path(path).is_file():
                raise Refusal("installed artifact missing")
        print(json.dumps({"snapshot": SNAPSHOT, "pins": PINS, "resolved_installed": after,
                          "downloaded_archives": archives, "changed": before != after,
                          "seconds": round(time.monotonic() - started, 3)}, sort_keys=True))


def main():
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    def expired(_signum, _frame):
        raise Refusal("overall deadline exceeded")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(235)
    try:
        if len(sys.argv) != 1:
            raise Refusal("no options accepted")
        install()
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("qemu install: interrupted", file=sys.stderr)
        sys.exit(130)
    except (Refusal, OSError) as exc:
        print("qemu install: " + str(exc), file=sys.stderr)
        sys.exit(1)
