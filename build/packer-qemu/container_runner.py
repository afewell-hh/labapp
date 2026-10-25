"""Fixed non-VM containment probe in one owned Docker container.

Not a general runner: one mode (`probe`) runs a fixed command in a pre-acquired,
digest-pinned image so the lead can later validate the containment premise
before any VM mode is scoped. No Packer/QEMU path exists here. Docker is reached
only through `Backend`; tests substitute a fake. The CLI refuses to contact
Docker unless `--execute` is given (otherwise it prints the validated plan).
Python 3.10+ stdlib. See README.md "Bounded container probe" for unmet gates.
"""
import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid

# probe: 30 s work + 20 s cleanup, measured from one admission time, no renewal.
# The proposed sentinel (15+5 min) and fixture (30+15 min) profiles are VM-mode
# allocations and are intentionally not accepted here.
PROFILES = {"probe": (30, 20)}
CALL_CAP = 10          # per Docker CLI call, further capped by remaining budget
STOP_GRACE = 3         # docker stop --time
KILL_AFTER = 5         # GNU timeout --kill-after inside the container
START_RESERVE = 10     # budget left for the start call before the timer is armed
MIN_TIMER = 5
POLL = 1.0
EXPECTED_EXIT = (124, 137)   # timer fired (TERM honoured) / escalated to KILL
EXIT = {"accepted": 0, "failed": 1, "usage": 2, "hold": 7}
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}@sha256:[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")      # no comma: --mount is comma-split
STATE_RE = re.compile(r"^(created|running|paused|restarting|removing|exited|dead) (\d{1,3}) (true|false)$")
# Fixed child tree: a setsid descendant plus a TERM-ignoring shell loop, so the
# internal timer must escalate and PID 1 exit must reap the namespace.
PROBE_SCRIPT = "/usr/bin/setsid /bin/sleep 3600 & trap '' TERM; while :; do /bin/sleep 1; done"


class DockerError(Exception):
    """Definite nonzero client exit."""


class DockerTimeout(Exception):
    """Client killed by our bound or interrupted: daemon outcome unknown."""


class Expired(Exception):
    """Absolute budget exhausted; no call was made."""


class Backend:
    """Real client: fixed absolute docker binary, minimal environment, bounded."""

    def __init__(self, docker="/usr/bin/docker"):
        self.docker = docker

    def call(self, args, seconds):
        try:
            done = subprocess.run([self.docker, *args], stdin=subprocess.DEVNULL,
                                  capture_output=True, timeout=seconds,
                                  env={"PATH": "/usr/bin:/bin"})
        except subprocess.TimeoutExpired as exc:
            raise DockerTimeout() from exc
        except OSError as exc:
            raise DockerError() from exc
        if done.returncode != 0:
            raise DockerError()
        return done.stdout[:65536].decode("utf-8", "replace").strip()


class Budget:
    def __init__(self, work, cleanup, clock, admitted_at):
        self.clock = clock
        self.work_deadline = admitted_at + work
        self.deadline = admitted_at + work + cleanup

    def work_left(self):
        return self.work_deadline - self.clock()

    def seconds(self, cap, deadline=None):
        left = (self.deadline if deadline is None else deadline) - self.clock()
        if left <= 0:
            raise Expired()
        return min(cap, left)


def create_args(name, label, image_id, user, workspace, timer):
    """Exact, fixed creation argv: no shell, no init, no restart, no pull."""
    return ["create", "--pull=never", f"--name={name}", f"--label={label}",
            "--restart=no", "--network=none", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--read-only", f"--user={user}",
            "--memory=256m", "--memory-swap=256m", "--cpus=1", "--pids-limit=64",
            "--log-driver=none", f"--mount=type=bind,src={workspace},dst=/out",
            "--entrypoint=/usr/bin/timeout", image_id,
            f"--kill-after={KILL_AFTER}s", f"{timer}s", "/bin/sh", "-c", PROBE_SCRIPT]


def owned_query(name, label):
    return ["container", "ls", "-aq", "--no-trunc", "--filter", f"name=^/{name}$",
            "--filter", f"label={label}"]


def id_query(ident):
    return ["container", "ls", "-aq", "--no-trunc", "--filter", f"id={ident}"]


def make_workspace(root, ident, uid):
    """Fresh 0700 directory under a validated, unshared, symlink-free root."""
    if not PATH_RE.match(root) or os.path.realpath(root) != root:
        raise ValueError("workspace root must be a safe absolute path without symlinks")
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
        raise ValueError("workspace root must be an owned directory not writable by others")
    path = os.path.join(root, f"labapp-probe-{ident}")
    os.mkdir(path, 0o700)
    return path


def run_probe(image, root, backend, *, clock=time.monotonic, sleep=time.sleep,
              admitted_at=None, new_uuid=lambda: str(uuid.uuid4()),
              uid=None, gid=None, work=None, cleanup=None):
    """Return a result dict; outcome is accepted, failed or hold. Never raises on
    daemon trouble. `hold` keeps the ownership record and workspace for the lead."""
    admitted_at = clock() if admitted_at is None else admitted_at
    uid, gid = (os.getuid() if uid is None else uid), (os.getgid() if gid is None else gid)
    w, c = PROFILES["probe"]
    budget = Budget(w if work is None else work, c if cleanup is None else cleanup, clock, admitted_at)
    if not IMAGE_RE.match(image):
        raise ValueError("image must be a pre-acquired name@sha256:<64 hex> reference")
    if uid == 0:
        raise ValueError("refusing to run as root")
    ident = new_uuid()
    # Ownership is reserved in memory before any object can exist.
    own = {"name": f"labapp-probe-{ident}", "label": f"labapp.probe.run={ident}",
           "id": None, "ambiguous": None, "attempted": False, "workspace": None}
    result = {"outcome": "failed", "reason": None, "name": own["name"], "label": own["label"]}
    try:
        _run(image, root, backend, budget, own, result, sleep, uid, gid)
    except BaseException as exc:   # cancellation/interrupt included: always clean up
        result["outcome"], result["reason"] = "failed", result["reason"] or _reason(exc)
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            result["reason"] = "cancelled"
    clean = _cleanup(backend, budget, own)
    result["container_id"] = own["id"]
    result["cleanup"] = "verified" if clean else "uncertain"
    if own["ambiguous"]:
        result["outcome"], result["reason"] = "hold", own["ambiguous"]
    elif not clean:
        result["outcome"], result["reason"] = "hold", "cleanup_uncertain"
    if result["outcome"] == "accepted":
        # Output is untrusted data: this probe produces none, so any entry rejects.
        if os.listdir(own["workspace"]):
            result["outcome"], result["reason"] = "failed", "unexpected_output"
    if own["workspace"] and clean and not own["ambiguous"]:
        shutil.rmtree(own["workspace"])
        result["workspace"] = "removed"
    elif own["workspace"]:
        result["workspace"] = "retained"
        result["workspace_path"] = own["workspace"]
    return result


def _reason(exc):
    return {Expired: "budget_exhausted", DockerError: "daemon_error",
            DockerTimeout: "daemon_timeout", ValueError: "invalid_input"}.get(type(exc), "error")


def _run(image, root, backend, budget, own, result, sleep, uid, gid):
    # Preparation consumes the same budget as everything else.
    own["workspace"] = make_workspace(root, own["name"][len("labapp-probe-"):], uid)
    backend.call(["version", "--format", "{{.Server.Version}}"], budget.seconds(CALL_CAP, budget.work_deadline))
    image_id = backend.call(["image", "inspect", "--format", "{{.Id}}", image],
                            budget.seconds(CALL_CAP, budget.work_deadline))
    if not IMAGE_ID_RE.match(image_id):
        raise DockerError()
    # Internal timer gets what is left now, minus start and kill-after reserves.
    timer = int(budget.work_left() - START_RESERVE - KILL_AFTER)
    if timer < MIN_TIMER:
        raise Expired()
    own["attempted"] = True
    own["ambiguous"] = "ambiguous_create"
    out = backend.call(create_args(own["name"], own["label"], image_id, f"{uid}:{gid}",
                                   own["workspace"], timer), budget.seconds(CALL_CAP, budget.work_deadline))
    if not CONTAINER_ID_RE.match(out):
        raise DockerError()      # response unusable: stays ambiguous
    own["id"], own["ambiguous"] = out, None
    own["ambiguous"] = "ambiguous_start"
    backend.call(["start", own["id"]], budget.seconds(CALL_CAP, budget.work_deadline))
    own["ambiguous"] = None
    while True:
        if budget.work_left() <= 0:
            result["reason"] = "host_expiry"     # internal timer should have won
            return
        state = backend.call(["inspect", "--type=container", "--format",
                              "{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}", own["id"]],
                             budget.seconds(CALL_CAP, budget.work_deadline))
        match = STATE_RE.match(state)
        if not match:
            raise DockerError()
        status, code, oom = match.group(1), int(match.group(2)), match.group(3) == "true"
        if status in ("exited", "dead"):
            break
        sleep(min(POLL, max(budget.work_left(), 0)))
    if oom or code not in EXPECTED_EXIT:
        result["reason"] = "unexpected_exit"
        return
    result["outcome"], result["reason"] = "accepted", None
    result["exit_code"] = code


def _cleanup(backend, budget, own):
    """Stop/remove by retained full ID or reserved name+label, then prove both gone."""
    if not own["attempted"]:
        return True       # nothing could have been created
    try:
        found = set(backend.call(owned_query(own["name"], own["label"]), budget.seconds(CALL_CAP)).split())
        if own["id"]:
            if found - {own["id"]}:
                return False      # stale/foreign identity under our reservation: HOLD
            found.add(own["id"])
        if len(found) > 1 or any(not CONTAINER_ID_RE.match(i) for i in found):
            return False
        for ident in found:
            own["id"] = ident
            for args in (["stop", f"--time={STOP_GRACE}", ident], ["rm", "-f", ident]):
                try:
                    backend.call(args, budget.seconds(CALL_CAP))
                except (DockerError, DockerTimeout):
                    pass      # decided by verification queries, not by this response
        if backend.call(owned_query(own["name"], own["label"]), budget.seconds(CALL_CAP)):
            return False
        return not own["id"] or not backend.call(id_query(own["id"]), budget.seconds(CALL_CAP))
    except (DockerError, DockerTimeout, Expired):
        return False


def parse(argv):
    p = argparse.ArgumentParser(prog="container_runner.py", description=__doc__.splitlines()[0])
    p.add_argument("--image", required=True, help="pre-acquired name@sha256:<digest>; never pulled")
    p.add_argument("--workspace-root", required=True, help="existing owned absolute directory")
    p.add_argument("--docker", default="/usr/bin/docker")
    p.add_argument("--execute", action="store_true", help="contact Docker (default: print plan only)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse(sys.argv[1:] if argv is None else argv)
    if not IMAGE_RE.match(args.image) or not PATH_RE.match(args.docker):
        print("invalid image or docker path", file=sys.stderr)
        return EXIT["usage"]
    if not args.execute:
        plan = create_args("labapp-probe-<uuid>", "labapp.probe.run=<uuid>", "<image id>",
                           "<uid>:<gid>", args.workspace_root + "/labapp-probe-<uuid>", "<timer>")
        print(json.dumps({"mode": "probe", "executed": False, "create": plan}))
        return 0
    try:
        result = run_probe(args.image, args.workspace_root, Backend(args.docker))
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT["usage"]
    print(json.dumps(result))
    return EXIT[result["outcome"]]


if __name__ == "__main__":
    sys.exit(main())
