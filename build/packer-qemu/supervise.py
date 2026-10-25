"""Host supervisor for one bounded stock Packer/QEMU experiment run.

Invoke: python3 -I /absolute/path/supervise.py --profile sentinel|fixture
--packer ABS --base-image ABS --base-sha256 HEX [--stage ABS]... [--plan ABS]
[--work-root ABS] | --preflight-only.
Python 3.10+ stdlib, Linux x86_64 only, no shell, no sudo, no network.

It is deliberately independent of Packer's shell-local timeout (untraced in
the pinned source): it owns one absolute work-plus-cleanup deadline, starts
Packer as the leader of a NEW SESSION, and on deadline, SIGTERM/SIGINT or
failure signals only that session, then verifies no process of that session
remains (/proc scan) and that its private work directory is gone (failure) or
holds only the output (success). Descendants that call setsid() escape the
scan; the Packer/QEMU path is not known to do so (UNRUN).

Success needs ALL of: Packer exit 0, a fresh verifier result file bound to this
run's nonce and input digest (written only by host_verify.py after receipt AND
guest-shutdown evidence), and a verified-empty session. Absolute deadlines,
no renewal. Allocations are experiment values, not measured performance.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILES = {"sentinel": (15 * 60, 5 * 60), "fixture": (30 * 60, 15 * 60)}
TERM_GRACE = 20.0
POLL = 0.1
NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")
EXIT = {"ok": 0, "failed": 1, "usage": 2, "timeout": 3, "cancelled": 4, "cleanup": 5}

_cancel = []


def _on_signal(signum, _frame):
    _cancel.append(signum)


def session_members(sid, proc="/proc"):
    """PIDs of live (non-zombie) processes in session sid."""
    found = []
    for entry in os.listdir(proc):
        if not entry.isdigit():
            continue
        try:
            with open("%s/%s/stat" % (proc, entry), "rb") as handle:
                rest = handle.read().rsplit(b")", 1)[1].split()
        except (OSError, IndexError):
            continue
        if rest[0] != b"Z" and int(rest[3]) == sid:
            found.append(int(entry))
    return found


def signal_session(sid, signum, proc="/proc"):
    """Signal only members of the session we created, never by name or pattern."""
    for pid in session_members(sid, proc):
        try:
            os.kill(pid, signum)
        except ProcessLookupError:
            pass


def drain_session(sid, term_grace, cleanup_deadline, proc="/proc"):
    """TERM, then KILL, until the session is empty; True only if verified empty."""
    signal_session(sid, signal.SIGTERM, proc)
    kill_at = min(time.monotonic() + term_grace, cleanup_deadline)
    killed = False
    while time.monotonic() < cleanup_deadline:
        if not session_members(sid, proc):
            return True
        if not killed and time.monotonic() >= kill_at:
            signal_session(sid, signal.SIGKILL, proc)
            killed = True
        time.sleep(POLL)
    return not session_members(sid, proc)


def sha256_file(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def stage_inputs(cd, stage, plan, nonce):
    """Copy staged bytes into cd/, write MANIFEST (sorted sha256 list); return its digest.

    MANIFEST covers every staged file except itself and the nonce file, so the
    input digest identifies exact module/service/user-data bytes only.
    """
    os.mkdir(cd, 0o700)
    names = set()
    sources = list(stage) + [os.path.join(HERE, "guest", n)
                             for n in ("user-data", "guest-build.sh")]
    for source in sources:
        name = os.path.basename(source)
        info = os.lstat(source)
        if not NAME_RE.match(name) or name in names or not stat.S_ISREG(info.st_mode):
            raise ValueError("staged input must be a uniquely named regular file")
        names.add(name)
        shutil.copyfile(source, os.path.join(cd, name))
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
    """Return failure strings; empty means the runner can boot an accelerated builder.

    Builder boot needs usable KVM. The later nested VLAB proof additionally needs
    nested CPU exposure. TCG is never a substitute for either.
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
    if not any(shutil.which(t) for t in ("xorriso", "mkisofs", "genisoimage")):
        bad.append("no CD builder (xorriso, mkisofs or genisoimage) on PATH")
    return bad


def read_marker(path, nonce, inputs):
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            return False
        with open(path, "rb") as handle:
            data = json.loads(handle.read())
    except (OSError, ValueError):
        return False
    return data == {"nonce": nonce, "inputs": inputs, "shutdown": "guest-shutdown",
                    "receipt": "ok"}


def run(cfg, work_seconds, cleanup_seconds, term_grace=TERM_GRACE, proc="/proc"):
    """Run one build under an absolute deadline; returns (result_name, work_dir|None)."""
    start = time.monotonic()
    work_deadline, cleanup_deadline = start + work_seconds, start + work_seconds + cleanup_seconds
    nonce = secrets.token_hex(32)
    work = tempfile.mkdtemp(prefix="labapp-pq-", dir=cfg["work_root"])
    result, child = "failed", None
    try:
        os.chmod(work, 0o700)
        if not PATH_RE.match(work):
            raise ValueError("work directory path outside the safe character set")
        inputs = stage_inputs(os.path.join(work, "cd"), cfg["stage"], cfg["plan"], nonce)
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": os.environ.get("HOME", "/"),
               "PACKER_NO_COLOR": "1", "PACKER_CHECKPOINT_DISABLE": "1",
               "PKR_VAR_work_dir": work, "PKR_VAR_nonce": nonce, "PKR_VAR_inputs": inputs,
               "PKR_VAR_base_image": cfg["base_image"], "PKR_VAR_base_sha256": cfg["base_sha256"],
               "PKR_VAR_verifier": os.path.join(HERE, "host_verify.py"),
               "PKR_VAR_verify_seconds": str(max(1, int(work_seconds - 60)))}
        if os.environ.get("PACKER_PLUGIN_PATH"):
            env["PACKER_PLUGIN_PATH"] = os.environ["PACKER_PLUGIN_PATH"]
        child = subprocess.Popen(
            [cfg["packer"], "build", "-color=false", "-on-error=cleanup",
             os.path.join(HERE, "labapp.pkr.hcl")],
            env=env, cwd=work, stdin=subprocess.DEVNULL, start_new_session=True)
        reason = None
        while reason is None:
            if child.poll() is not None:
                reason = "exit"
            elif _cancel:
                reason = "cancelled"
            elif time.monotonic() >= work_deadline:
                reason = "timeout"
            else:
                time.sleep(POLL)
        empty = drain_session(child.pid, term_grace, cleanup_deadline, proc)
        child.wait(timeout=max(1.0, cleanup_deadline - time.monotonic()))
        if not empty:
            result = "cleanup"
        elif reason in ("timeout", "cancelled"):
            result = reason
        elif child.returncode == 0 and read_marker(os.path.join(work, "verified.json"),
                                                   nonce, inputs):
            result = "ok"
    except (OSError, ValueError, subprocess.SubprocessError):
        result = "cleanup" if child is not None and session_members(child.pid, proc) else "failed"
    finally:
        if child is not None and child.poll() is None:
            child.kill()
    if result == "ok":
        for sock in ("events.sock", "serial.sock"):
            if os.path.lexists(os.path.join(work, sock)):
                result = "cleanup"
        return result, work
    shutil.rmtree(work, ignore_errors=True)
    if os.path.lexists(work):
        result = "cleanup"
    return result, None


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
    failures = preflight()
    if failures:
        print("supervise: preflight failed: " + "; ".join(failures))
        return EXIT["usage"]
    if args.preflight_only:
        print("supervise: preflight ok (TCG is never a substitute)")
        return 0
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, _on_signal)
    work_s, cleanup_s = PROFILES[args.profile]
    cfg = {"packer": args.packer, "base_image": args.base_image, "base_sha256": args.base_sha256,
           "stage": args.stage, "plan": args.plan, "work_root": args.work_root}
    result, work = run(cfg, work_s, cleanup_s)
    print("supervise: result=%s%s" % (result, " output=%s/out" % work if work else ""))
    return EXIT[result]


if __name__ == "__main__":
    sys.exit(main())
