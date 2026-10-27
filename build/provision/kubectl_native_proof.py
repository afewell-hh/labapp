"""Native proof: run the unchanged install-kubectl.py CLI twice into one private destination.

Manual-workflow harness for a fresh GitHub-hosted Ubuntu 24.04 runner (Python 3.12 stdlib,
curl); never runs kubectl and never touches /usr/local/bin. Invoke
python3 -B /absolute/kubectl_native_proof.py --root /absolute/private --commit SHA --tree SHA
[--runner-image TEXT] with a cleared environment. --root must be a caller-owned 0700 directory
containing empty caller-owned 0700 `home` and `tmp` directories; the harness creates, verifies
and removes `root/install` (the only destination) and prints one JSON report. Keep the sibling
install-kubectl.py and hhfab_release.py alongside this file. Work is bounded by WORK seconds and
a separate CLEANUP; a failed run is never retried or repaired. Only owned, expected artifacts are
removed; any unknown child is left in place and reported.
"""
import argparse
import contextlib
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import stat
import sys
import time

from hhfab_release import Refusal, bounded, digest

VERSION = "1.35.0"
PLATFORM = "linux/amd64"
PIN = {
    "url": "https://dl.k8s.io/release/v1.35.0/bin/linux/amd64/kubectl",
    "size": 58597560,
    "sha256": "a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989",
}
# Initial finite limits, not measured fit: whole work phase, separate cleanup phase, and one
# installer invocation (its own 180s alarm plus grace). The installer's limits are unchanged.
WORK, CLEANUP, RUN_CAP = 600, 60, 185
PYTHON = "/usr/bin/python3"
CURL = "/usr/bin/curl"
OS_RELEASE = Path("/etc/os-release")
INSTALLER = Path(__file__).resolve().with_name("install-kubectl.py")
ALLOWED_ENV = {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "PYTHONDONTWRITEBYTECODE"}
CHILD_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
SAFE_MESSAGE = re.compile(rb"kubectl install: [A-Za-z0-9 ;,./()_-]{1,120}")


class CleanupExpired(BaseException):
    """Not an Exception, so no cleanup step can swallow the separate cleanup deadline."""


def describe(error):
    if isinstance(error, Refusal):
        return str(error)
    if isinstance(error, CleanupExpired):
        return "cleanup deadline exceeded"
    if isinstance(error, KeyboardInterrupt):
        return "interrupted"
    return "operational failure (" + type(error).__name__ + ")"


def private(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise Refusal("private directory must be a caller-owned 0700 real directory")


def check_environment(environ):
    extra = sorted(set(environ) - ALLOWED_ENV)
    if extra:
        raise Refusal("ambient environment not cleared: " + ", ".join(extra))


def observe_host():
    release = {}
    for line in OS_RELEASE.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        release[key] = value.strip().strip('"')
    if (platform.system() != "Linux" or platform.machine() != "x86_64"
            or (release.get("ID"), release.get("VERSION_ID")) != ("ubuntu", "24.04")
            or sys.version_info[:2] != (3, 12)):
        raise Refusal("host is not Ubuntu 24.04 x86_64 with Python 3.12")
    code, output = bounded([CURL, "--version"], 10, limit=8192, env=dict(CHILD_ENV))
    if code:
        raise Refusal("curl version unavailable")
    lines = output.decode("ascii", "replace").splitlines() or [""]
    return {"os": release["ID"] + " " + release["VERSION_ID"], "machine": platform.machine(),
            "python": sys.version.split()[0], "uid": os.geteuid(), "curl": lines[0][:200]}


def command(installer, destination):
    return [PYTHON, "-B", str(installer), "--version", VERSION, "--platform", PLATFORM,
            "--install-dir", str(destination)]


def session_members(sid):
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            text = Path("/proc/" + entry + "/stat").read_text()
        except OSError:
            continue
        fields = text.rsplit(")", 1)[-1].split()  # state, ppid, pgrp, session, ...
        if len(fields) > 3 and fields[0] != "Z" and fields[3] == str(sid):
            found.append(int(entry))
    return found


def reap_session(sid):
    """No live process may remain in the installer's own session; kill strays, then refuse."""
    members = session_members(sid)
    if not members:
        return
    for pid in members:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
    limit = time.monotonic() + 3
    while session_members(sid) and time.monotonic() < limit:
        time.sleep(0.05)
    if session_members(sid):
        raise Refusal("owned process could not be reaped")
    raise Refusal("unexpected process outlived the installer")


def observe(target):
    info = target.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o755 or info.st_size != PIN["size"]):
        raise Refusal("installed target metadata mismatch")
    sha = digest(target)
    after = target.lstat()
    seen = {"dev": info.st_dev, "ino": info.st_ino, "size": info.st_size, "mode": "0755",
            "uid": info.st_uid, "nlink": info.st_nlink, "mtime_ns": info.st_mtime_ns,
            "ctime_ns": info.st_ctime_ns, "sha256": sha}
    if (after.st_ino, after.st_mtime_ns, after.st_ctime_ns) != (info.st_ino, info.st_mtime_ns,
                                                                  info.st_ctime_ns):
        raise Refusal("installed target changed while observed")
    if sha != PIN["sha256"]:
        raise Refusal("installed target checksum mismatch")
    return seen


def verify_outcome(code, output, status, sources, target):
    if code:
        text = output.rstrip(b"\n")
        raise Refusal("installer failed: " + (text.decode("ascii") if SAFE_MESSAGE.fullmatch(text)
                                              else "unrecognized output"))
    if len(output) > 4096 or output.count(b"\n") != 1 or not output.endswith(b"\n"):
        raise Refusal("unexpected installer output shape")
    try:
        outcome = json.loads(output)
    except ValueError:
        raise Refusal("installer output is not JSON") from None
    if not isinstance(outcome, dict):
        raise Refusal("installer output is not an object")
    expected = {
        "tool": "kubectl", "version": VERSION, "platform": PLATFORM, "source_url": PIN["url"],
        "pinned_size": PIN["size"], "pinned_sha256": PIN["sha256"],
        "module_sha256": sources["installer_sha256"], "helper_sha256": sources["helper_sha256"],
        "target": str(target), "target_sha256": PIN["sha256"], "target_mode": "0755",
        "status": status, "executed": False,
    }
    for key, value in expected.items():
        if outcome.get(key) != value or type(outcome.get(key)) is not type(value):
            raise Refusal("installer result mismatch: " + key)
    return outcome


def work(root, installer, report, state, environ):
    check_environment(environ)
    if not root.is_absolute() or not installer.is_absolute():
        raise Refusal("paths must be absolute")
    home, tmp = root / "home", root / "tmp"
    for path in (root, home, tmp):
        private(path)
    for path in (home, tmp):
        if any(path.iterdir()):
            raise Refusal("private home and tmp must start empty")
    report["host"] = observe_host()
    helper = installer.with_name("hhfab_release.py")
    sources = {"proof_sha256": digest(Path(__file__).resolve()),
               "installer_sha256": digest(installer), "helper_sha256": digest(helper)}
    report["source"] = sources
    destination = root / "install"
    os.mkdir(destination, 0o700)
    info = destination.lstat()
    state["dir"], state["dir_id"] = destination, (info.st_dev, info.st_ino)
    private(destination)
    target = destination / "kubectl"
    if os.path.lexists(target) or any(destination.iterdir()):
        raise Refusal("target must be absent before the first invocation")
    report["target_absent_before_first"] = True
    print(json.dumps({"preflight": report}, sort_keys=True), flush=True)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(tmp), "LC_ALL": "C",
           "PYTHONDONTWRITEBYTECODE": "1"}
    first = None
    for label, status in (("first", "installed"), ("rerun", "unchanged")):
        remaining = state["deadline"] - time.monotonic()
        if remaining <= 0:
            raise Refusal("work deadline exceeded")
        begun = time.monotonic()
        code, output = bounded(command(installer, destination), min(RUN_CAP, remaining),
                               limit=8192, env=dict(env), on_start=state["pids"].append)
        elapsed = time.monotonic() - begun
        reap_session(state["pids"][-1])
        outcome = verify_outcome(code, output, status, sources, target)
        if (digest(installer), digest(helper)) != (sources["installer_sha256"],
                                                   sources["helper_sha256"]):
            raise Refusal("installer sources changed during the proof")
        seen = observe(target)
        if first is None:
            first = seen
            state["target_id"] = (seen["dev"], seen["ino"])
        elif seen != first:
            raise Refusal("rerun changed the target identity or metadata")
        if sorted(entry.name for entry in destination.iterdir()) != ["kubectl"]:
            raise Refusal("install directory contains unexpected entries")
        if not math.isfinite(elapsed):
            raise Refusal("non-finite timing")
        report[label] = {"outcome": outcome, "target": seen, "seconds": round(elapsed, 3)}


def remove_stage(child, info, removed):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        return False
    stage = Path(child.path)
    with os.scandir(stage) as entries:
        inner = list(entries)
    for entry in inner:
        item = entry.stat(follow_symlinks=False)
        if (entry.name != "kubectl" or not stat.S_ISREG(item.st_mode)
                or item.st_uid != os.geteuid() or item.st_nlink != 1):
            return False
    for entry in inner:
        os.unlink(entry.path)
    os.rmdir(stage)
    removed.append(child.name + "/")
    return True


def remove_destination(destination, state, removed):
    info = destination.lstat()
    if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != state["dir_id"]:
        raise Refusal("install directory is not the owned inode")
    with os.scandir(destination) as entries:
        children = sorted(entries, key=lambda entry: entry.name)
    unknown = 0
    for child in children:
        item = child.stat(follow_symlinks=False)
        if (child.name == "kubectl" and stat.S_ISREG(item.st_mode) and item.st_nlink == 1
                and item.st_uid == os.geteuid()
                and state["target_id"] in (None, (item.st_dev, item.st_ino))):
            os.unlink(child.path)
            removed.append("kubectl")
        elif not (child.name.startswith(".kubectl-stage-") and remove_stage(child, item, removed)):
            unknown += 1
    if unknown:
        raise Refusal(str(unknown) + " unknown child entries retained in the install directory")
    os.rmdir(destination)


def clean(root, state, info):
    problems = []
    for pid in state["pids"]:
        try:
            reap_session(pid)
        except Refusal as error:
            problems.append(str(error))
    info["processes_absent"] = not any(session_members(pid) for pid in state["pids"])
    destination = state["dir"]
    if destination is not None:
        try:
            remove_destination(destination, state, info["removed"])
        except (Refusal, OSError) as error:
            problems.append(describe(error))
        info["install_dir_absent"] = not os.path.lexists(destination)
        if not info["install_dir_absent"]:
            problems.append("install directory still present")
    else:
        info["install_dir_absent"] = not os.path.lexists(root / "install")
    for name in ("home", "tmp"):
        try:
            if any((root / name).iterdir()):
                problems.append("unknown child entries in private " + name)
        except OSError as error:
            problems.append(describe(error))
    if problems:
        raise Refusal("; ".join(problems))


def _work_expired(_signum, _frame):
    raise Refusal("work deadline exceeded")


def _cleanup_expired(_signum, _frame):
    raise CleanupExpired


def _interrupted(_signum, _frame):
    raise KeyboardInterrupt


def prove(root, installer, commit, tree, runner_image="", environ=None):
    """Run the proof; always attempts owned cleanup and returns the report (never raises)."""
    root, installer = Path(root), Path(installer)
    report = {"proof": "kubectl-native-install-rerun", "status": "failed", "commit": commit,
              "tree": tree, "runner_image_claimed": runner_image,
              "limits": {"work": WORK, "cleanup": CLEANUP, "run_cap": RUN_CAP}}
    state = {"dir": None, "dir_id": None, "target_id": None, "pids": [], "deadline": None}
    saved = {number: signal.getsignal(number)
             for number in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM)}
    primary = cleanup_error = None
    begun = time.monotonic()
    try:
        signal.signal(signal.SIGALRM, _work_expired)
        signal.signal(signal.SIGINT, _interrupted)
        signal.signal(signal.SIGTERM, _interrupted)
        state["deadline"] = time.monotonic() + WORK
        signal.alarm(WORK)
        work(root, installer, report, state, os.environ if environ is None else environ)
    except BaseException as error:  # noqa: BLE001 - primary failure is preserved and reported
        primary = error
    finally:
        signal.alarm(0)
    try:
        # Hard cancellation (SIGKILL) skips this and leaves cleanup unverified.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGALRM, _cleanup_expired)
        signal.alarm(CLEANUP)
        info = report["cleanup"] = {"removed": []}
        clean(root, state, info)
    except BaseException as error:  # noqa: BLE001
        cleanup_error = describe(error)
    finally:
        signal.alarm(0)
        for number, handler in saved.items():
            signal.signal(number, handler)
    if primary is not None:
        report["error"] = describe(primary)
    if cleanup_error is not None:
        report["cleanup_error"] = cleanup_error
    report["elapsed_seconds"] = round(time.monotonic() - begun, 3)
    if primary is None and cleanup_error is None:
        report["status"] = "passed"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)

    def pattern(expression):
        def check(value):
            if not re.fullmatch(expression, value):
                raise argparse.ArgumentTypeError("invalid value")
            return value
        return check
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--commit", required=True, type=pattern(r"[0-9a-f]{40}"))
    parser.add_argument("--tree", required=True, type=pattern(r"[0-9a-f]{40}"))
    parser.add_argument("--runner-image", default="", type=pattern(r"[A-Za-z0-9._ -]{0,64}"))
    args = parser.parse_args(argv)
    report = prove(args.root, INSTALLER, args.commit, args.tree, args.runner_image)
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
