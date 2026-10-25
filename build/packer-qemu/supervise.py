"""Offline input preparation and read-only runner diagnostics.

VM/build execution is deliberately disabled: a process session is not a reliable
containment boundary. No callable in this module launches or signals processes.
The staging helper is for disposable offline inputs only, not a bounded build.
Python 3.10+ stdlib. See README.md for the unmet execution gate.
"""
import argparse
import hashlib
import os
import platform
import re
import shutil
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILES = {"sentinel": (15 * 60, 5 * 60), "fixture": (30 * 60, 15 * 60)}
BUILTIN_NAMES = ("user-data", "guest-build.sh")
GENERATED_NAMES = ("plan.txt", "meta-data", "nonce", "MANIFEST")
NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")
EXIT = {"usage": 2, "disabled": 6}
EXECUTION_GATE = (
    "execution disabled: supported process containment and an absolute "
    "admission/preparation/work/cleanup budget are not implemented or validated"
)


def sha256_file(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def stage_inputs(cd, stage, plan, nonce):
    """Copy staged bytes into cd/, write MANIFEST (sorted sha256 list); return its digest.

    MANIFEST covers every staged file except itself and the nonce file, so the
    input digest identifies exact module/service/user-data bytes only. This is a
    trusted disposable offline helper: lstat/copy can race and parent directories
    or plan may be symlinks; file reads are unbounded. It is not a secure stager.
    """
    names = set(GENERATED_NAMES + BUILTIN_NAMES)
    # Validate the entire caller-supplied namespace before copying anything.
    for source in stage:
        name = os.path.basename(source)
        info = os.lstat(source)
        if not NAME_RE.match(name) or name in names or not stat.S_ISREG(info.st_mode):
            raise ValueError("staged input must be a unique non-reserved regular file")
        names.add(name)
    sources = list(stage) + [os.path.join(HERE, "guest", n) for n in BUILTIN_NAMES]
    os.mkdir(cd, 0o700)
    for source in sources:
        shutil.copyfile(source, os.path.join(cd, os.path.basename(source)))
    with open(os.path.join(cd, "plan.txt"), "wb") as handle:
        if plan:
            with open(plan, "rb") as src:
                handle.write(src.read())
    with open(os.path.join(cd, "meta-data"), "w") as handle:
        handle.write("instance-id: labapp-build\n")
    with open(os.path.join(cd, "nonce"), "w") as handle:
        handle.write(nonce + "\n")
    lines = ["%s  %s\n" % (sha256_file(os.path.join(cd, n)), n)
             for n in sorted(os.listdir(cd)) if n not in ("nonce", "MANIFEST")]
    manifest = "".join(lines).encode()
    with open(os.path.join(cd, "MANIFEST"), "wb") as handle:
        handle.write(manifest)
    return hashlib.sha256(manifest).hexdigest()


def preflight(cpuinfo="/proc/cpuinfo", sys_module="/sys/module", dev_kvm="/dev/kvm"):
    """Return read-only hardware/tool diagnostic failures, not execution admission.

    Device permissions are inspected without opening KVM; passing does not prove
    acceleration. Nested exposure is a separate later VLAB requirement. Execution
    stays disabled regardless of this diagnostic. TCG is not a substitute.
    """
    bad = []
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        bad.append("not Linux x86_64")
    if not os.access(dev_kvm, os.R_OK | os.W_OK):
        bad.append("%s missing or not readable/writable by this user" % dev_kvm)
    try:
        with open(cpuinfo) as handle:
            flags = next((ln for ln in handle if ln.startswith("flags")), "").split()
    except OSError:
        flags = []
    vendor = "kvm_intel" if "vmx" in flags else "kvm_amd" if "svm" in flags else None
    if vendor is None:
        bad.append("CPU does not expose vmx/svm (no nested virtualization)")
    else:
        try:
            with open("%s/%s/parameters/nested" % (sys_module, vendor)) as handle:
                if handle.read().strip() not in ("1", "Y", "y"):
                    bad.append("%s nested parameter is not enabled" % vendor)
        except OSError:
            bad.append("%s nested parameter unreadable (module not loaded?)" % vendor)
    for tool in ("qemu-system-x86_64", "qemu-img"):
        if shutil.which(tool) is None:
            bad.append("%s not on PATH" % tool)
    # Exactly the tools packer-plugin-sdk v0.6.11 step_create_cdrom.go searches on Linux
    # (it also tries hdiutil and oscdimg); genisoimage alone is never found by the plugin.
    if not any(shutil.which(t) for t in ("xorriso", "mkisofs")):
        bad.append("no CD builder the pinned plugin searches (xorriso or mkisofs) on PATH")
    return bad


def run(cfg, work_seconds, cleanup_seconds, **_unused):
    """Reject every build request before reading inputs or creating ownership.

    Kept as an explicit fail-closed entrypoint for callers. Neither supplied
    profiles, existing receipt files, successful hardware diagnostics nor fake
    backends can enable execution. No child or workspace is created here.
    """
    return "disabled", None


def parse(argv):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--profile", choices=sorted(PROFILES))
    parser.add_argument("--packer")
    parser.add_argument("--base-image")
    parser.add_argument("--base-sha256")
    parser.add_argument("--stage", action="append", default=[])
    parser.add_argument("--plan")
    parser.add_argument("--work-root", default=tempfile.gettempdir())
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args(argv)
    if args.preflight_only:
        return args
    for name in ("profile", "packer", "base_image", "base_sha256"):
        if not getattr(args, name):
            parser.error("--%s is required" % name.replace("_", "-"))
    paths = [args.packer, args.base_image, args.work_root, *args.stage]
    if args.plan:
        paths.append(args.plan)
    if not all(PATH_RE.match(p) for p in paths):
        parser.error("paths must be absolute and use only [A-Za-z0-9_./-]")
    if not re.match(r"^[0-9a-f]{64}$", args.base_sha256):
        parser.error("--base-sha256 must be 64 lowercase hex digits")
    return args


def main(argv=None):
    args = parse(sys.argv[1:] if argv is None else argv)
    if not args.preflight_only:
        print("supervise: " + EXECUTION_GATE)
        return EXIT["disabled"]
    failures = preflight()
    print("supervise: " + EXECUTION_GATE)
    if failures:
        print("supervise: hardware diagnostics failed: " + "; ".join(failures))
        return EXIT["usage"]
    print("supervise: hardware diagnostics passed; execution remains disabled")
    return 0


if __name__ == "__main__":
    sys.exit(main())
