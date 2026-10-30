"""Native proof: run the unchanged install-helm.py CLI twice into one private destination.

Manual-workflow harness for a fresh GitHub-hosted Ubuntu 24.04 runner (Python 3.12 stdlib,
curl); never runs downloaded Helm. Invoke
python3 -B /absolute/helm_native_proof.py --root /absolute/private --commit SHA --tree SHA
[--runner-image TEXT] with a cleared environment. --root must be a caller-owned 0700 directory
containing empty caller-owned 0700 `home` and `tmp` directories; the harness creates, verifies
and removes `root/install` (the only destination), printing preflight and final JSON lines. Keep the sibling
install-helm.py and hhfab_release.py alongside this file. Work is bounded by WORK seconds and
a separate CLEANUP; a failed run is never retried or repaired. Only owned, expected artifacts are
removed; any unknown child is left in place and reported.
"""
import argparse
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import selectors
import subprocess
import stat
import sys
import time

from hhfab_release import Refusal, digest

VERSION = "3.19.4"
PLATFORM = "linux/amd64"
PIN = {
    "url": "https://get.helm.sh/helm-v3.19.4-linux-amd64.tar.gz",
    "archive_size": 18014603,
    "archive_sha256": "759c656fbd9c11e6a47784ecbeac6ad1eb16a9e76d202e51163ab78504848862",
    "size": 60182712,
    "sha256": "ea22096683b9b61005584501e36168a1eadc5b6883a89df299f5a55e4e2dd283",
}
# Initial finite limits, not measured fit: whole work phase, separate cleanup phase, and one
# installer invocation (its own 180s alarm plus grace). The installer's limits are unchanged.
WORK, CLEANUP, RUN_CAP = 600, 60, 185
TERM_GRACE = 5
PYTHON = "/usr/bin/python3"
OS_RELEASE = Path("/etc/os-release")
INSTALLER = Path(__file__).resolve().with_name("install-helm.py")
ALLOWED_ENV = {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "PYTHONDONTWRITEBYTECODE"}
CHILD_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
SAFE_MESSAGE = re.compile(rb"helm install: [A-Za-z0-9 ;,./()_-]{1,120}")


class Failure(Refusal):
    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


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
    executable = Path(sys.executable).resolve()
    return {"os": release["ID"] + " " + release["VERSION_ID"], "machine": platform.machine(),
            "python": sys.version, "python_path": str(executable),
            "python_sha256": digest(executable), "uid": os.geteuid(),
            "platform": platform.platform()}


def command(installer, destination):
    return [PYTHON, "-B", str(installer), "--version", VERSION, "--platform", PLATFORM,
            "--install-dir", str(destination)]


def run_installer(args, seconds, env, state):
    """Supervise this one CLI; graceful cancellation lets its own helper reap curl."""
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=env, cwd="/", start_new_session=True)
    state["children"].append(proc)
    deadline = time.monotonic() + seconds
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selected:
            selected.register(proc.stdout, selectors.EVENT_READ)
            while selected.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Failure("command timeout", 124)
                for key, _ in selected.select(min(remaining, 0.1)):
                    block = os.read(key.fileobj.fileno(), 8192)
                    if not block:
                        selected.unregister(key.fileobj)
                    elif len(output) + len(block) > 8192:
                        raise Refusal("command output overflow")
                    else:
                        output.extend(block)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Failure("command timeout", 124)
        try:
            return proc.wait(timeout=remaining), bytes(output)
        except subprocess.TimeoutExpired:
            raise Failure("command timeout", 124) from None
    except BaseException:
        # Preserve the original error. Grace is finite and charged to work/cleanup;
        # suppress repeated interruption while the unchanged installer reaps its child.
        saved = {n: signal.getsignal(n) for n in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM)}
        signal.alarm(0)
        for number in saved:
            signal.signal(number, signal.SIG_IGN)
        try:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=max(0.001, min(TERM_GRACE, state["envelope"] - time.monotonic())))
                except subprocess.TimeoutExpired:
                    state["forced"] = True
                    proc.kill()
                    proc.wait(timeout=max(0.001, min(2, state["envelope"] - time.monotonic())))
        except (OSError, subprocess.TimeoutExpired):
            state["forced"] = True
        finally:
            for number, handler in saved.items():
                signal.signal(number, handler)
            # Do not renew the absolute work deadline after a per-call failure.
            remaining = state["deadline"] - time.monotonic()
            signal.alarm(max(1, math.ceil(remaining)))
        raise
    finally:
        proc.stdout.close()


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
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size",
              "st_mtime_ns", "st_ctime_ns")
    if any(getattr(after, key) != getattr(info, key) for key in fields):
        raise Refusal("installed target changed while observed")
    if sha != PIN["sha256"]:
        raise Refusal("installed target checksum mismatch")
    return seen


def verify_outcome(code, output, status, sources, target, seen):
    if code:
        text = output.rstrip(b"\n")
        raise Failure("installer failed: " + (text.decode("ascii") if SAFE_MESSAGE.fullmatch(text)
                                              else "unrecognized output"), code if code > 0 else 128 - code)
    if len(output) > 4096 or output.count(b"\n") != 1 or not output.endswith(b"\n"):
        raise Refusal("unexpected installer output shape")
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result
        outcome = json.loads(output, object_pairs_hook=unique,
                             parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite")))
    except ValueError:
        raise Refusal("installer output is not JSON") from None
    if not isinstance(outcome, dict):
        raise Refusal("installer output is not an object")
    expected = {
        "tool": "helm", "version": VERSION, "platform": PLATFORM, "source_url": PIN["url"],
        "pinned_size": PIN["size"], "pinned_sha256": PIN["sha256"],
        "module_sha256": sources["installer_sha256"], "helper_sha256": sources["helper_sha256"],
        "target": str(target), "target_sha256": PIN["sha256"], "target_mode": "0755",
        "status": status, "executed": False,
        "archive_size": PIN["archive_size"], "archive_sha256": PIN["archive_sha256"],
        "target_size": seen["size"], "target_uid": seen["uid"],
        "target_dev": seen["dev"], "target_inode": seen["ino"],
    }
    for key, value in expected.items():
        if outcome.get(key) != value or type(outcome.get(key)) is not type(value):
            raise Refusal("installer result mismatch: " + key)
    extra = {"verified", "not_verified", "atomicity"}
    if set(outcome) != set(expected) | extra:
        raise Refusal("installer result keys mismatch")
    for key in extra:
        if type(outcome[key]) is not str:
            raise Refusal("installer result mismatch: " + key)
    return outcome


def directory_identity(path):
    private(path)
    info = path.lstat()
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode)


def check_directories(state):
    for path, identity in state["directories"].items():
        if directory_identity(path) != identity:
            raise Refusal("private directory identity changed")


def work(root, installer, report, state, environ):
    check_environment(environ)
    if not root.is_absolute() or not installer.is_absolute():
        raise Refusal("paths must be absolute")
    home, tmp = root / "home", root / "tmp"
    for path in (root, home, tmp):
        state["directories"][path] = directory_identity(path)
    if sorted(p.name for p in root.iterdir()) != ["home", "tmp"]:
        raise Refusal("private root contains unexpected entries")
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
    state["dir"], state["dir_id"] = destination, directory_identity(destination)
    state["directories"][destination] = state["dir_id"]
    private(destination)
    target = destination / "helm"
    if os.path.lexists(target) or any(destination.iterdir()):
        raise Refusal("target must be absent before the first invocation")
    report["private_modes"] = {name: oct(stat.S_IMODE(path.lstat().st_mode))
                               for name, path in (("root", root), ("home", home),
                                                  ("tmp", tmp), ("install", destination))}
    report["target_absent_before_first"] = True
    print(json.dumps({"preflight": report}, sort_keys=True), flush=True)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(tmp), "LC_ALL": "C",
           "PYTHONDONTWRITEBYTECODE": "1"}
    first = None
    for label, status in (("first", "installed"), ("rerun", "unchanged")):
        remaining = state["deadline"] - time.monotonic()
        if remaining <= 0:
            raise Failure("work deadline exceeded", 124)
        check_directories(state)
        begun = time.monotonic()
        code, output = run_installer(command(installer, destination), min(RUN_CAP, remaining),
                                     dict(env), state)
        elapsed = time.monotonic() - begun
        if code < 0:
            state["forced"] = True
        if code:
            verify_outcome(code, output, status, sources, target, None)
        check_directories(state)
        seen = None
        if code == 0:
            seen = observe(target)
            if state["target_id"] is None:
                state["target_id"] = (seen["dev"], seen["ino"])
        outcome = verify_outcome(code, output, status, sources, target, seen)
        if (digest(Path(__file__).resolve()), digest(installer), digest(helper)) != (
                sources["proof_sha256"], sources["installer_sha256"], sources["helper_sha256"]):
            raise Refusal("installer sources changed during the proof")
        if first is None:
            first = seen
            state["target_id"] = (seen["dev"], seen["ino"])
        elif seen != first:
            raise Refusal("rerun changed the target identity or metadata")
        if sorted(entry.name for entry in destination.iterdir()) != ["helm"]:
            raise Refusal("install directory contains unexpected entries")
        if not math.isfinite(elapsed):
            raise Refusal("non-finite timing")
        report[label] = {"outcome": outcome, "target": seen, "seconds": round(elapsed, 3)}


def remove_destination(destination, state, removed):
    if directory_identity(destination) != state["dir_id"]:
        raise Refusal("install directory is not the owned inode")
    with os.scandir(destination) as entries:
        children = sorted(entries, key=lambda entry: entry.name)
    unknown = 0
    for child in children:
        item = child.stat(follow_symlinks=False)
        if (child.name == "helm" and stat.S_ISREG(item.st_mode) and item.st_nlink == 1
                and item.st_uid == os.geteuid()
                and state["target_id"] == (item.st_dev, item.st_ino)):
            os.unlink(child.path)
            removed.append("helm")
        else:
            unknown += 1
    if unknown:
        raise Refusal(str(unknown) + " unknown child entries retained in the install directory")
    os.rmdir(destination)


def clean(root, state, info):
    problems = []
    # Wait/poll only Popen handles created here. The accepted installer owns its
    # separate-session curl killpg/wait; this is not a descendant census.
    for proc in state["children"]:
        if proc.poll() is None:
            state["forced"] = True
            try:
                proc.kill()
                proc.wait(timeout=max(0.001, min(2, state["envelope"] - time.monotonic())))
            except (OSError, subprocess.TimeoutExpired):
                problems.append("direct installer termination failed")
    info["direct_children_reaped"] = all(proc.poll() is not None for proc in state["children"])
    info["nested_cleanup"] = "unverified" if state["forced"] else "relies on installer graceful cleanup"
    if not info["direct_children_reaped"]:
        problems.append("direct installer child remains")
    if state["forced"]:
        problems.append("forced installer termination: nested process cleanup unverified")
    try:
        check_directories(state)
    except (Refusal, OSError) as error:
        raise Refusal("private directory identity changed; owned paths retained") from error
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
    info["home_tmp_state"] = "retained for identity-bound host cleanup"
    for name in ("home", "tmp"):
        try:
            if any((root / name).iterdir()):
                problems.append("unknown child entries in private " + name)
        except OSError as error:
            problems.append(describe(error))
    if sorted(p.name for p in root.iterdir()) != ["home", "tmp"]:
        problems.append("private root contains unexpected entries")
    if problems:
        raise Refusal("; ".join(problems))


def _work_expired(_signum, _frame):
    raise Failure("work deadline exceeded", 124)


def _cleanup_expired(_signum, _frame):
    raise CleanupExpired


def _interrupted(signum, _frame):
    raise Failure("interrupted by " + signal.Signals(signum).name, 128 + signum)


def prove(root, installer, commit, tree, runner_image="", environ=None):
    """Run the proof; always attempts owned cleanup and returns the report (never raises)."""
    root, installer = Path(root), Path(installer)
    report = {"proof": "helm-native-install-rerun", "status": "failed", "commit": commit,
              "tree": tree, "runner_image_claimed": runner_image,
              "limits": {"work": WORK, "cleanup": CLEANUP, "run_cap": RUN_CAP},
              "pins": dict(PIN)}
    state = {"dir": None, "dir_id": None, "target_id": None, "children": [], "directories": {}, "deadline": None, "forced": False,
             "envelope": time.monotonic() + WORK + CLEANUP}
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
        # Cancellation grace consumes the fixed overall work+cleanup envelope.
        remaining = begun + WORK + CLEANUP - time.monotonic()
        if remaining <= 0:
            raise CleanupExpired
        signal.alarm(max(1, math.ceil(min(CLEANUP, remaining))))
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
    report["exit_code"] = getattr(primary, "code", 1) if primary is not None else (1 if cleanup_error else 0)
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
    def absolute(value):
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts:
            raise argparse.ArgumentTypeError("root must be absolute without parent components")
        return path
    parser.add_argument("--root", required=True, type=absolute)
    parser.add_argument("--commit", required=True, type=pattern(r"[0-9a-f]{40}"))
    parser.add_argument("--tree", required=True, type=pattern(r"[0-9a-f]{40}"))
    parser.add_argument("--runner-image", default="", type=pattern(r"[A-Za-z0-9._ -]{0,64}"))
    args = parser.parse_args(argv)
    report = prove(args.root, INSTALLER, args.commit, args.tree, args.runner_image)
    print(json.dumps(report, sort_keys=True), flush=True)
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
