"""Fixed non-VM containment probe in one owned Docker container.

Not a general runner: one mode (`probe`) runs a fixed command in the one trusted,
pre-acquired Ubuntu digest pinned in this repo, so the lead can later validate the
containment premise before any VM mode is scoped. No Packer/QEMU path exists here.
Docker is reached only through `Backend`; tests substitute a fake. The CLI refuses
to contact Docker unless `--execute` is given (otherwise it prints the plan).
Python 3.10+ stdlib. See README.md "Bounded container probe" for unmet gates.

Clock basis: one wall-clock epoch (`time.time` on the host, `date +%s` inside the
container, which shares the host clock). Deadlines are floored to whole seconds
and the container subtracts one more second, so rounding only shortens the timer.
"""
import argparse
import json
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

# The only image this probe accepts: the Ubuntu digest already pinned across
# build/provision (qemu_offline.py BASE, CI K3D_TEST_IMAGE). Never pulled.
PINNED_IMAGE = "ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac"
# probe: 30 s work + 20 s cleanup, measured from one admission time, no renewal.
# The proposed sentinel (15+5 min) and fixture (30+15 min) profiles are VM-mode
# allocations and are intentionally not accepted here.
PROFILES = {"probe": (30, 20)}
CALL_CAP = 10          # per Docker CLI call, further capped by remaining budget
STOP_GRACE = 3         # docker stop --time
KILL_AFTER = 5         # GNU timeout --kill-after inside the container
START_RESERVE = 10     # minimum work left before create is attempted
MIN_TIMER = 5          # in-container timer below this: the probe does not run
OUT_CAP = 65536        # bytes accepted from one Docker client call
POLL = 1.0
EXPECTED_EXIT = (124, 137)   # timer fired (TERM honoured) / escalated to KILL
EXIT = {"accepted": 0, "failed": 1, "usage": 2, "hold": 7}
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")      # no comma: --mount is comma-split
HOST_RE = re.compile(r"^unix:///[A-Za-z0-9_./-]+$")
STATE_RE = re.compile(r"^(created|running|paused|restarting|removing|exited|dead) (\d{1,3}) (true|false)$")
WITNESS_RE = re.compile(r"^start (\d{9,12}) (\d{1,4})\nprobe (\d{1,9})\nterm_ignored\n$")
# Runs as the container's PID 1 (sh), recomputes the timer at ACTUAL startup from
# the original admission deadline ($1), then execs timeout, which stays PID 1.
# Under MIN_TIMER (late start) it exits 125 without running the probe.
ENTRY = ("n=$(/bin/date +%s) || exit 125; t=$(($1-n-1-" + str(KILL_AFTER) + ")); "
         "[ \"$t\" -ge " + str(MIN_TIMER) + " ] || exit 125; "
         "echo \"start $n $t\" > /out/witness || exit 125; "
         "exec /usr/bin/timeout --kill-after=" + str(KILL_AFTER) + "s \"${t}s\" /bin/sh -c \"$2\"")
# Fixed child tree: a setsid descendant (its pid is witnessed) plus a TERM-ignoring
# shell loop, so the internal timer must escalate and PID 1 exit must reap the
# namespace.
PROBE_SCRIPT = ("/usr/bin/setsid /bin/sleep 3600 & echo \"probe $!\" >> /out/witness; trap '' TERM; "
                "echo term_ignored >> /out/witness; while :; do /bin/sleep 1; done")


class DockerError(Exception):
    """Definite nonzero client exit, overflow or invalid output."""


class DockerTimeout(Exception):
    """Client killed by our bound or interrupted: daemon outcome unknown."""


class Expired(Exception):
    """Absolute budget exhausted; no call was made."""


class Cancelled(BaseException):
    """SIGTERM/SIGINT while working; cleanup still runs."""


class Backend:
    """Real client: fixed absolute binary, explicit local endpoint and empty config
    dir (no caller context or credential helpers), minimal environment, and a
    bounded byte collector with a deadline."""

    def __init__(self, docker="/usr/bin/docker", host="unix:///var/run/docker.sock", config="/nonexistent-empty"):
        self.docker, self.host, self.config = docker, host, config

    def call(self, args, seconds):
        argv = [self.docker, "--host", self.host, "--config", self.config, *args]
        end = time.monotonic() + seconds
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, start_new_session=True,
                                    env={"PATH": "/usr/bin:/bin"})
        except OSError as exc:
            raise DockerError() from exc
        chunks, size, fd = [], 0, proc.stdout.fileno()
        try:
            while True:
                left = end - time.monotonic()
                if left <= 0:
                    raise DockerTimeout()
                if not select.select([fd], [], [], left)[0]:
                    continue
                data = os.read(fd, 8192)
                if not data:
                    break
                size += len(data)
                if size > OUT_CAP:
                    raise DockerError()          # overflow: reject, do not truncate
                chunks.append(data)
            proc.wait(timeout=max(end - time.monotonic(), 0.01))
        except subprocess.TimeoutExpired as exc:
            raise DockerTimeout() from exc
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
                proc.wait()
            proc.stdout.close()
        if proc.returncode != 0:
            raise DockerError()
        try:
            return b"".join(chunks).decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise DockerError() from exc


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


class Ledger:
    """Host-only durable record for one request, outside the container-writable
    workspace. Every mutation intent is fsynced before the daemon is contacted.
    A record not in state `released` blocks new requests (never retried as fresh)."""

    def __init__(self, directory, ident, fields):
        self.path = os.path.join(directory, f"labapp-probe-{ident}.json")
        self.directory, self.data, self.failed = directory, dict(fields), False
        self.write("reserved")

    def write(self, state, **more):
        self.data.update(more, state=state)
        tmp = self.path + ".tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write(json.dumps(self.data, sort_keys=True))
                handle.flush()
                os.fsync(handle.fileno())
            os.rename(tmp, self.path)
            dfd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            self.failed = True
            raise


def check_private_dir(path, uid, what):
    if not PATH_RE.match(path) or os.path.realpath(path) != path:
        raise ValueError(f"{what} must be a safe absolute path without symlinks")
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
        raise ValueError(f"{what} must be an owned directory not writable by others")
    return info


def unresolved_records(directory):
    """Names of ledger records that are not released (corrupt counts as unresolved)."""
    out = []
    for entry in sorted(os.listdir(directory)):
        if entry.startswith("labapp-probe-") and entry.endswith(".json"):
            try:
                with open(os.path.join(directory, entry)) as handle:
                    released = json.load(handle).get("state") == "released"
            except (OSError, ValueError, AttributeError):
                released = False
            if not released:
                out.append(entry)
    return out


def create_args(name, label, image_id, user, workspace, deadline):
    """Exact, fixed creation argv: no init, no restart, no pull, healthcheck off."""
    return ["create", "--pull=never", f"--name={name}", f"--label={label}",
            "--restart=no", "--network=none", "--cap-drop=ALL", "--no-healthcheck",
            "--security-opt=no-new-privileges", "--read-only", f"--user={user}",
            "--memory=256m", "--memory-swap=256m", "--cpus=1", "--pids-limit=64",
            "--log-driver=none", f"--mount=type=bind,src={workspace},dst=/out",
            "--entrypoint=/bin/sh", image_id, "-c", ENTRY, "sh", str(deadline), PROBE_SCRIPT]


def owned_query(name, label):
    return ["container", "ls", "-aq", "--no-trunc", "--filter", f"name=^/{name}$",
            "--filter", f"label={label}"]


def id_query(ident):
    return ["container", "ls", "-aq", "--no-trunc", "--filter", f"id={ident}"]


def identity_args(ident):
    return ["inspect", "--type=container", "--format",
            '{{.Id}} {{.Name}} {{index .Config.Labels "labapp.probe.run"}}', ident]


IMAGE_FORMAT = ('{"id":{{json .Id}},"repo":{{json .RepoDigests}},"vol":{{json .Config.Volumes}},'
                '"onbuild":{{json .Config.OnBuild}}}')


def check_image(raw, image):
    """Return the image ID after rejecting inherited behavior this probe cannot bound."""
    try:
        info = json.loads(raw)
        ok = (IMAGE_ID_RE.match(info["id"]) and image in info["repo"]
              and not info["vol"] and not info["onbuild"])
    except (ValueError, KeyError, TypeError):
        ok = False
    if not ok:
        raise DockerError()      # wrong digest, anonymous volumes or ONBUILD: refuse
    return info["id"]


def make_workspace(root, ident, uid):
    """Fresh 0700 directory under a validated, unshared, symlink-free root."""
    check_private_dir(root, uid, "workspace root")
    path = os.path.join(root, f"labapp-probe-{ident}")
    os.mkdir(path, 0o700)
    return path


def read_witness(path, deadline, started_after):
    """Parse the fixed probe's startup witness; return the timer seconds or None.
    Untrusted data: exactly one small regular file with an exact format."""
    if os.listdir(path) != ["witness"]:
        return None
    full = os.path.join(path, "witness")
    if not stat.S_ISREG(os.lstat(full).st_mode):
        return None
    fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        raw = handle.read(257)
    match = WITNESS_RE.match(raw.decode("ascii", "replace"))
    if not match:
        return None
    n, t = int(match.group(1)), int(match.group(2))
    if t != deadline - n - 1 - KILL_AFTER or t < MIN_TIMER or n < started_after - 1:
        return None
    return t


def run_probe(image, root, ledger_dir, backend, *, clock=time.time, sleep=time.sleep,
              admitted_at=None, new_uuid=lambda: str(uuid.uuid4()),
              uid=None, gid=None, work=None, cleanup=None, handle_signals=False):
    """Return a result dict; outcome is accepted, failed or hold. Never raises on
    daemon trouble. `hold` keeps the ledger record and workspace for the lead."""
    admitted_at = clock() if admitted_at is None else admitted_at
    uid, gid = (os.getuid() if uid is None else uid), (os.getgid() if gid is None else gid)
    w, c = PROFILES["probe"]
    budget = Budget(w if work is None else work, c if cleanup is None else cleanup, clock, admitted_at)
    if image != PINNED_IMAGE:
        raise ValueError("image must be the pinned Ubuntu digest of this repo")
    if uid == 0:
        raise ValueError("refusing to run as root")
    check_private_dir(ledger_dir, uid, "ledger dir")
    if os.path.commonpath([root, ledger_dir]) in (root, ledger_dir):
        raise ValueError("ledger dir and workspace root must be separate trees")
    if unresolved_records(ledger_dir):
        return {"outcome": "hold", "reason": "unresolved_prior_request", "cleanup": "not_attempted",
                "records": unresolved_records(ledger_dir)}
    ident = new_uuid()
    own = {"name": f"labapp-probe-{ident}", "label": f"labapp.probe.run={ident}", "ident": ident,
           "id": None, "ambiguous": None, "attempted": False, "workspace": None, "ledger": None,
           "cancelled": False, "cleaning": False, "uncertain": False, "started_at": None,
           "witness": None, "deadline": int(budget.work_deadline)}
    result = {"outcome": "failed", "reason": None, "name": own["name"], "label": own["label"]}
    if handle_signals:
        def on_signal(signum, frame):
            own["cancelled"] = True
            if not own["cleaning"]:
                raise Cancelled()
        previous = [signal.signal(s, on_signal) for s in (signal.SIGTERM, signal.SIGINT)]
    try:
        try:
            # Durable reservation first; failure here means no mutation was possible.
            own["ledger"] = Ledger(ledger_dir, ident, {
                "name": own["name"], "label": own["label"], "image": image, "id": None,
                "workspace": None, "admitted_at": admitted_at, "work_deadline": budget.work_deadline,
                "deadline": budget.deadline, "pid": os.getpid()})
            _run(image, root, backend, budget, own, result, sleep, uid, gid, clock)
        except BaseException as exc:   # cancellation/interrupt included: always clean up
            result["outcome"], result["reason"] = "failed", result["reason"] or _reason(exc)
            if isinstance(exc, (Cancelled, KeyboardInterrupt, SystemExit)):
                result["reason"] = "cancelled"
        own["cleaning"] = True
        try:
            _finish(backend, budget, own, result, clock)
        except BaseException as exc:   # finalization must never erase the ledger or accept
            result["outcome"], result["reason"] = "hold", "finalization_error"
            result["error"] = type(exc).__name__
    finally:
        if handle_signals:
            for s, old in zip((signal.SIGTERM, signal.SIGINT), previous):
                signal.signal(s, old)
    return result


def _reason(exc):
    return {Expired: "budget_exhausted", DockerError: "daemon_error", OSError: "ledger_or_fs_error",
            DockerTimeout: "daemon_timeout", ValueError: "invalid_input"}.get(type(exc), "error")


def _checkpoint(own, budget, clock):
    """After any slow call: cancellation and work deadline are re-checked."""
    if own["cancelled"]:
        raise Cancelled()
    if clock() >= budget.work_deadline:
        raise Expired()


def _run(image, root, backend, budget, own, result, sleep, uid, gid, clock):
    ledger = own["ledger"]
    # Preparation consumes the same budget as everything else.
    own["workspace"] = make_workspace(root, own["ident"], uid)
    ledger.write("workspace_made", workspace=own["workspace"])
    backend.call(["version", "--format", "{{.Server.Version}}"], budget.seconds(CALL_CAP, budget.work_deadline))
    _checkpoint(own, budget, clock)
    image_id = check_image(backend.call(["image", "inspect", "--format", IMAGE_FORMAT, image],
                                        budget.seconds(CALL_CAP, budget.work_deadline)), image)
    _checkpoint(own, budget, clock)
    if budget.work_left() < START_RESERVE + KILL_AFTER + MIN_TIMER:
        raise Expired()
    argv = create_args(own["name"], own["label"], image_id, f"{uid}:{gid}", own["workspace"], own["deadline"])
    own["attempted"] = True
    own["ambiguous"] = "ambiguous_create"
    ledger.write("create_intent", image_id=image_id)       # durable BEFORE the daemon mutation
    out = backend.call(argv, budget.seconds(CALL_CAP, budget.work_deadline))
    if not CONTAINER_ID_RE.match(out):
        raise DockerError()      # response unusable: stays ambiguous
    own["id"], own["ambiguous"] = out, None
    own["ambiguous"] = "ambiguous_start"
    ledger.write("created", id=own["id"])
    _checkpoint(own, budget, clock)
    ledger.write("start_intent")
    own["started_at"] = clock()
    backend.call(["start", own["id"]], budget.seconds(CALL_CAP, budget.work_deadline))
    own["ambiguous"] = None
    ledger.write("started")
    while True:
        if own["cancelled"]:
            raise Cancelled()
        # The in-container timer ends about a second before the work deadline, so
        # one last look is allowed after it (bounded by the total deadline).
        state = backend.call(["inspect", "--type=container", "--format",
                              "{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}", own["id"]],
                             budget.seconds(CALL_CAP))
        match = STATE_RE.match(state)
        if not match:
            raise DockerError()
        status, code, oom = match.group(1), int(match.group(2)), match.group(3) == "true"
        if status in ("exited", "dead"):
            break
        if budget.work_left() <= 0:
            result["reason"] = "host_expiry"     # internal timer should have won
            return
        sleep(min(POLL, max(budget.work_left(), 0)))
    own["exit_seen_at"] = clock()
    if oom or code not in EXPECTED_EXIT:
        result["reason"] = "unexpected_exit"
        return
    # Startup/descendant evidence, not an exit code alone. The probe must also
    # have run for about its timer; an immediate 137 is not evidence.
    timer = read_witness(own["workspace"], own["deadline"], int(own["started_at"]))
    if timer is None:
        result["reason"] = "no_probe_witness"
        return
    if own["exit_seen_at"] - own["started_at"] < timer - 1:
        result["reason"] = "exited_before_timer"
        return
    own["witness"] = timer
    result["outcome"], result["reason"] = "accepted", None
    result["exit_code"] = code


def _finish(backend, budget, own, result, clock):
    ledger = own["ledger"]
    if ledger is None:        # reservation never became durable: no mutation was attempted
        result["cleanup"], result["container_id"] = "not_needed", None
        if own["workspace"]:
            result["workspace"], result["workspace_path"] = "retained", own["workspace"]
        return
    clean = _cleanup(backend, budget, own)
    result["container_id"] = own["id"]
    result["cleanup"] = "verified" if clean else "uncertain"
    if own["ambiguous"]:
        result["outcome"], result["reason"] = "hold", own["ambiguous"]
    elif not clean:
        result["outcome"], result["reason"] = "hold", "cleanup_uncertain"
    if result["outcome"] == "accepted":
        if own["cancelled"]:
            result["outcome"], result["reason"] = "failed", "cancelled"
        elif clock() >= budget.deadline:
            result["outcome"], result["reason"] = "failed", "deadline_exceeded"
    release = bool(own["workspace"]) and clean and not own["ambiguous"] and not ledger.failed
    if not release and result["outcome"] != "hold" and own["attempted"]:
        result["outcome"], result["reason"] = "hold", "ledger_or_cleanup_unresolved"
    if not own["attempted"] and not ledger.failed:
        release = True    # no daemon mutation was ever attempted
    try:
        ledger.write("released" if release else "hold", outcome=result["outcome"], reason=result["reason"])
    except OSError:
        release = False
        result["outcome"], result["reason"] = "hold", "ledger_write_failed"
    if own["workspace"] and release:
        try:
            shutil.rmtree(own["workspace"])
            result["workspace"] = "removed"
        except Exception:
            result["workspace"] = "retained"
            result["workspace_path"] = own["workspace"]
    elif own["workspace"]:
        result["workspace"] = "retained"
        result["workspace_path"] = own["workspace"]
    result["ledger"] = ledger.path


def _cleanup(backend, budget, own):
    """Validate exact identity, then stop/remove by full ID, then prove absence.
    Any uncertain mutation (lost/failed stop or rm, vanished container) is HOLD."""
    if not own["attempted"]:
        return True       # nothing could have been created
    ledger = own["ledger"]
    try:
        ledger.write("cleanup_intent")
        found = set(backend.call(owned_query(own["name"], own["label"]), budget.seconds(CALL_CAP)).split())
        if own["id"]:
            if found - {own["id"]}:
                return False      # stale/foreign identity under our reservation: HOLD
            if not found:
                return False      # our container vanished without our rm: unexplained
        if len(found) > 1 or any(not CONTAINER_ID_RE.match(i) for i in found):
            return False
        for ident in found:
            own["id"] = ident
            expect = f"{ident} /{own['name']} {own['ident']}"
            if backend.call(identity_args(ident), budget.seconds(CALL_CAP)) != expect:
                return False      # exact full ID + name + label must match before mutating
            ledger.write("stop_rm_intent", id=ident)
            for args in (["stop", f"--time={STOP_GRACE}", ident], ["rm", "-f", ident]):
                try:
                    if backend.call(args, budget.seconds(CALL_CAP)) not in ("", ident):
                        own["uncertain"] = True   # response names something else
                except (DockerError, DockerTimeout):
                    own["uncertain"] = True       # absence later does not clear this
        if own["uncertain"]:
            return False
        if backend.call(owned_query(own["name"], own["label"]), budget.seconds(CALL_CAP)):
            return False
        return not own["id"] or not backend.call(id_query(own["id"]), budget.seconds(CALL_CAP))
    except (DockerError, DockerTimeout, Expired, OSError):
        return False


def parse(argv):
    p = argparse.ArgumentParser(prog="container_runner.py", description=__doc__.splitlines()[0])
    p.add_argument("--workspace-root", required=True, help="existing owned absolute directory")
    p.add_argument("--ledger-dir", required=True, help="host-only owned 0700 directory, not under the workspace root")
    p.add_argument("--docker", default="/usr/bin/docker")
    p.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    p.add_argument("--execute", action="store_true", help="contact Docker (default: print plan only)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse(sys.argv[1:] if argv is None else argv)
    if not PATH_RE.match(args.docker) or not HOST_RE.match(args.docker_host) \
            or not PATH_RE.match(args.workspace_root) or not PATH_RE.match(args.ledger_dir):
        print("invalid docker, host or path argument", file=sys.stderr)
        return EXIT["usage"]
    if not args.execute:
        plan = create_args("labapp-probe-<uuid>", "labapp.probe.run=<uuid>", "<image id>",
                           "<uid>:<gid>", args.workspace_root + "/labapp-probe-<uuid>", "<deadline epoch>")
        print(json.dumps({"mode": "probe", "executed": False, "image": PINNED_IMAGE, "create": plan}))
        return 0
    try:
        config = os.path.join(args.ledger_dir, "docker-config")     # empty: no helpers/credentials
        check_private_dir(args.ledger_dir, os.getuid(), "ledger dir")
        os.makedirs(config, mode=0o700, exist_ok=True)
        result = run_probe(PINNED_IMAGE, args.workspace_root, args.ledger_dir,
                           Backend(args.docker, args.docker_host, config), handle_signals=True)
    except (ValueError, OSError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT["usage"]
    print(json.dumps(result))
    return EXIT[result["outcome"]]


if __name__ == "__main__":
    sys.exit(main())
