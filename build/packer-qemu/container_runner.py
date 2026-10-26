"""Fixed bounded tasks in one owned Docker container.

Fixed probe, HCL and non-VM runtime checks require separately scoped lead execution.
The sentinel and sentinel-expiry VM modes remain gated on separately accepted execution identities.
Only `qemu-fixture` and `control-build` get ordinary outbound Docker bridge networking; every other mode stays `--network=none`.
Docker is reached only through `Backend`; tests substitute a fake. The CLI refuses
to contact Docker unless `--execute` is given (otherwise it prints the plan).
Python 3.10+ stdlib. See README.md "Bounded container probe" for unmet gates.

Clock basis: Linux CLOCK_BOOTTIME on the host and /proc/uptime at startup,
including suspend. The fixed Bash wrapper checks the boot ID and zero time
namespace offsets, floors uptime, reserves rounding and escalation, then execs
GNU timeout as the same PID 1.
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import select
import shutil
import shlex
import signal
import stat
import subprocess
import sys
import time
import uuid

import stage_tools

# The probe/HCL image: the Ubuntu digest already pinned across
# build/provision (qemu_offline.py BASE, CI K3D_TEST_IMAGE). Never pulled.
PINNED_IMAGE = "ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac"
# probe: 30 s work + 20 s cleanup, measured from one admission time, no renewal.
# The sentinel (15+5 min) and hhfab fixture (30+15 min) profiles are VM-mode allocations
# (proposed, unmeasured); source activation never authorizes execution.
# fixture: 30 min work INCLUDING staging from admission + 15 min cleanup, no renewal.
# hcl-check: 120 s work INCLUDING all staging from admission + 30 s cleanup, no renewal.
# runtime-check: 90 s work + 30 s cleanup, no staging or renewal.
# sentinel: 15 min work INCLUDING staging from admission + 5 min cleanup, no renewal.
# sentinel-expiry: 300 s work INCLUDING staging + 120 s cleanup, no renewal. A failure-only
# proof: a paused KVM guest must outlive >=60 s until THIS container's own timer ends it.
PROFILES = {"probe": (30, 20), "hcl-check": (120, 30), "sentinel": (900, 300), "runtime-check": (90, 30),
            "sentinel-expiry": (300, 120), "fixture": (1800, 900), "qemu-fixture": (1800, 900),
            "control-build": (1800, 900)}
# control-build: the same 30 min work INCLUDING staging + 15 min cleanup, no renewal. It covers staging and the
# unchanged official hhfab init/validate/build sequence (cold, no-op, fresh-workspace warm) with no /dev/kvm. Unmeasured.
# qemu-fixture: the same 30 min work INCLUDING staging + 15 min cleanup as fixture, no renewal. It covers
# staging, two network installer runs and the KVM witness (unmeasured; an actual failure may identify #281).
MODES = tuple(PROFILES)
VM_MODES = ("sentinel", "sentinel-expiry", "fixture", "qemu-fixture")      # the only modes that receive /dev/kvm
STAGED_MODES = ("hcl-check", "sentinel", "sentinel-expiry", "fixture", "qemu-fixture")
# Observer-recorded success modes (the sentinel build step and receipt); only qemu-fixture adds a witness.
SUCCESS_MODES = ("sentinel", "fixture", "qemu-fixture")
# The ONLY modes whose outer container is not `--network=none`: ordinary outbound reachability for the fixed
# public package plan through Docker's default bridge. It is not hostname-allowlisted egress.
NETWORKED_MODES = ("qemu-fixture", "control-build")
SOURCE_KEYS = {"core", "plugin", "base"}
CONTROL_SOURCE_KEYS = {"archive"}      # control-build stages only the pinned hhfab archive; the wiring is fixed in-repo
FIXTURE_SOURCE_KEYS = SOURCE_KEYS | {"archive"}       # fixture adds the pinned hhfab archive
# Proposed explicit bounds, not measured requirements. The sentinel guest is 4 vCPU /
# 8 GiB (labapp.pkr.hcl); the container adds headroom for QEMU, Packer and the observer.
LIMITS = {"runtime-check": ("--memory=256m", "--memory-swap=256m", "--cpus=1", "--pids-limit=64"),
          "probe": ("--memory=256m", "--memory-swap=256m", "--cpus=1", "--pids-limit=64"),
          "hcl-check": ("--memory=1g", "--memory-swap=1g", "--cpus=1", "--pids-limit=128"),
          "sentinel": ("--memory=10g", "--memory-swap=10g", "--cpus=5", "--pids-limit=512")}
LIMITS["sentinel-expiry"] = LIMITS["fixture"] = LIMITS["qemu-fixture"] = LIMITS["control-build"] = LIMITS["sentinel"]
# Preparation artifact accepted in #266 comment 6406373578. Bound to original source
# 6b920067 / Dockerfile SHA256 63988869315f1df724e01647c6a334901f28edd689f1039c35080812e7e9e1ef;
# comment changes to that recipe do not mean this artifact was rebuilt. Tool execution
# requires separate lead authorization for each fixed task.
PREPARED_RUNTIME = {'image_id': 'sha256:64584cc2aac727f22d8cdbf5c7d8cd77c457089ec069f6c5fae08b1f3199b284',
 'diffids': ['sha256:32ab39660fd51c6dc3aae486b42d42bbe8fe4c1db78eaf57bb9c21198de48a16',
             'sha256:172d9fc216fc879d123ffe1f5300064d15678f43aab3947e295981a546981d9d',
             'sha256:24bfc479ac939d1a9ddad8b376ab4bb1d04e9f29dca3c73e7ed324bdd6dfb819',
             'sha256:faae59f53ff65efdcce8a5776891be45764c44942c0eaea1a31c08e69374bd82']}
# Fixed successful-sentinel identity; source activation does not authorize execution.
# Each actual trial requires separate lead scope and reconciled shared-ledger admission.
# No CLI, environment or caller option can supply or override either identity.
SENTINEL_RUNTIME = PREPARED_RUNTIME
# Failure-only identity for the fixed sentinel-expiry proof, separately lead-scoped in #266.
# This concrete identity does not authorize execution; each live trial needs lead scope.
EXPIRY_RUNTIME = PREPARED_RUNTIME
# The observer must outlive the container timer (<= 300 s), so its own and the shell-local
# secondary timeouts are fixed at 300 seconds from their later start and can never fire first.
EXPIRY_VERIFY_SECONDS = 300
EXPIRY_MIN_REMAINING = 150     # work left after staging for startup, paused dwell and exit
EXPIRY_MIN_DWELL = 60          # armed witness must precede the container timer by this much
ARMED_KEYS = {"kind", "armed", "armed_at", "nonce", "inputs", "boot_id"}
ARMED_KIND = "labapp-expiry-armed v1"
START_WITNESS_RE = re.compile(r"^start (\d{1,12}) (\d{1,4})\n$")
# Proposed, unmeasured reservation inside the ORIGINAL work window for Docker calls, Packer
# start, ISO creation, disk conversion, rehash and result reads. The pinned plugin's
# 5 min shutdown_timeout is NOT subtracted: with communicator=none the observer returns
# only after guest shutdown, and a later shutdown wait returns at once.
SENTINEL_RESERVE = 120
SENTINEL_MIN_VERIFY = 300
KVM_DEVICE = "/dev/kvm"
RESULT_CAP = 4096
SENTINEL_KEYS = {"nonce", "inputs", "shutdown", "receipt", "cloud_init"}
QEMU_KEYS = SENTINEL_KEYS | {"qemu_witness"}
QEMU_WITNESS_KEYS = {"accelerator", "exit", "uid", "nonce_equal", "backing_unchanged", "workspace_removed",
                     "install1", "install2", "witness_seconds", "network", "host_contract"}
QEMU_NETWORK_KEYS = {"default_route", "ca_bundle", "resolver"}
HOST_KEYS = {"native", "caller_uid", "sudo_uid", "tun_open", "tun_api", "tap_flag", "tap_create"}
# v3 successor schema: tap_create=passed plus exactly this closed observation (v2 stays `unrun`, no `tap`).
HOST_TAP_KEYS = HOST_KEYS | {"tap"}
TAP_SECONDS_CAP = 10
HOST_PACKAGES = {"sudo", "openssh-client", "less"}
HOST_VERSION_RE = re.compile(r"[0-9][A-Za-z0-9.+:~\-]{0,63}\Z")
QEMU_SECONDS_CAP = 999
# What a passing qemu-fixture does and does not establish; retained in evidence verbatim.
QEMU_CLAIMS = {"caller_uid": 0, "student_readiness": False, "full_vlab": False, "reboot": False,
               "other_platforms": False, "egress": "ordinary-docker-bridge-not-allowlisted"}
STEP_CAP = 2 * 1024 * 1024    # matches `ulimit -f 2048` in HCL_SCRIPT
EXCERPT = 2048
STEPS_EXPECTED = "version 0\nsyntax 0\nfull 0\n"
VERSION_RE = re.compile(r"^Packer v1\.16\.2\n?$")
CALL_CAP = 10          # per Docker CLI call, further capped by remaining budget
STOP_GRACE = 3         # docker stop --timeout
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
WITNESS_RE = re.compile(r"^start (\d{1,12}) (\d{1,4})\nprobe ([1-9]\d{0,8})\nterm_ignored\n$")
ENTRY = ('read -r boot < /proc/sys/kernel/random/boot_id || exit 125; '
         '[ "$boot" = "$2" ] || exit 125; '
         'count=0; while read -r kind sec ns extra; do '
         '[[ "$kind" = monotonic || "$kind" = boottime ]] || exit 125; '
         '[[ "$sec" = 0 && "$ns" = 0 && -z "$extra" ]] || exit 125; '
         '((count+=1)); done < /proc/self/timens_offsets; '
         '[[ "$count" = 2 ]] || exit 125; '
         'read -r up idle < /proc/uptime || exit 125; '
         r'[[ "$up" =~ ^[0-9]{1,12}\.[0-9]{2}$ ]] || exit 125; '
         'n=${up%.*}; t=$(($1-10#$n-1-5)); '
         '[ "$t" -ge 5 ] || exit 125; '
         'echo "start $n $t" > /out/witness || exit 125; '
         'exec /usr/bin/timeout --kill-after=5s "${t}s" /bin/bash -c "$3"')
# The detached child installs its own handler after setsid, then witnesses its
# own PID. The parent waits for that line before appending the final marker.
PROBE_SCRIPT = ("trap '' TERM; /usr/bin/setsid /bin/bash -c "
                "'trap \"\" TERM; echo \"probe $$\" >> /out/witness; "
                "while :; do /bin/sleep 1; done' & "
                'while :; do { read -r first; read -r child; } < /out/witness; '
                r'[[ "$child" = probe\ * ]] && break; /bin/sleep 0.01; done; '
                'echo term_ignored >> /out/witness; while :; do /bin/sleep 1; done')
# Fixed hcl-check script: three recorded steps, no init/build/install/download/
# datasource command, empty environment, outputs capped per file by ulimit.
HCL_ENV = ("/usr/bin/env -i HOME=/out/home TMPDIR=/out/tmp PATH=/usr/bin:/bin LC_ALL=C "
           "CHECKPOINT_DISABLE=1 PACKER_NO_COLOR=1 PACKER_PLUGIN_PATH=/in/plugins "
           "PACKER_CACHE_DIR=/out/cache")
HCL_SCRIPT = ("ulimit -f 2048 || exit 125; umask 077; "
              'step() { n=$1; shift; "$@" > "/out/$n.out" 2> "/out/$n.err" < /dev/null; '
              'echo "$n $?" >> /out/steps; }; '
              f"step version {HCL_ENV} /in/tools/packer version; "
              f"step syntax {HCL_ENV} /in/tools/packer validate -syntax-only /in/labapp.pkr.hcl; "
              f"step full {HCL_ENV} /in/tools/packer validate "
              "-var-file=/in/validate.pkrvars.hcl /in/labapp.pkr.hcl; exit 0")
# Fixed sentinel script: one recorded `packer build`, same empty-environment boundary. The
# file-size limit (8 GiB, proposed) must allow the qcow2 output, so logs are bounded by
# the reader (STEP_CAP), not by ulimit. No init/install/download; PLUGIN_PATH is read-only.
SENTINEL_SCRIPT = ("ulimit -f 8388608 || exit 125; umask 077; "
                   f'{HCL_ENV} /in/tools/packer build -color=false -var-file=/in/sentinel.pkrvars.hcl '
                   '/in/labapp.pkr.hcl > /out/build.out 2> /out/build.err < /dev/null; '
                   'echo "build $?" >> /out/steps; exit 0')
SENTINEL_STEPS = "build 0\n"
# host_verify.py prints `host-verify: failed reason=<token>[ step=N exit=N reason=<token>]` once;
# Packer prefixes the line, so search for just the fixed-shape text.
OBSERVER_FAILURE_RE = re.compile(
    r"host-verify: failed reason=([a-z][a-z0-9-]{0,40}(?: step=\d{1,2} exit=\d{1,3} reason=[a-z][a-z0-9-]{0,31})?)\r?$",
    re.MULTILINE)
ARTIFACT = ("work", "out", "labapp.qcow2")


# Fixed inert input represents SDK StepCreateCD filenames, including a nested long name.
RUNTIME_PATH = "nested-directory/representative-provision-module-with-long-name.txt"
RUNTIME_BYTES = b"labapp non-VM ISO tool check v1\n"
RUNTIME_ISO_CAP = 8 * 1024 * 1024
RUNTIME_VERSIONS = {"qemu": "QEMU emulator version 8.2.2", "qemu_img": "qemu-img version 8.2.2",
                    "python": "Python 3.12.3", "xorriso": "xorriso 1.5.6"}
RUNTIME_FIRMWARE = ("/usr/share/seabios/bios-256k.bin", "/usr/share/seabios/vgabios-stdvga.bin",
                    "/usr/lib/ipxe/qemu/efi-virtio.rom")
# The SDK v0.6.11 xorriso argv is copied exactly (label/source/dest fixed here).
# This program never boots QEMU or opens any device. Every child inherits env -i,
# a 90-second outer timer, no capabilities/network, and an 8 MiB per-file limit.
RUNTIME_PROGRAM = r'''
import hashlib, json, os, pathlib, subprocess, sys
os.umask(0o077)
os.chdir('/out')
env = {'PATH': '/usr/bin:/bin', 'HOME': '/out', 'TMPDIR': '/out', 'LC_ALL': 'C'}
def run(name, argv):
    with open(name + '.log', 'xb') as log:
        subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                       env=env, check=True)
    raw = pathlib.Path(name + '.log').read_bytes()
    if len(raw) > 16384:
        raise ValueError('tool output exceeds cap')
    return raw.decode('ascii')
versions = {}
for name, argv, expected in (
    ('qemu', ['/usr/bin/qemu-system-x86_64', '--version'], 'QEMU emulator version 8.2.2'),
    ('qemu_img', ['/usr/bin/qemu-img', '--version'], 'qemu-img version 8.2.2'),
    ('python', ['/usr/bin/python3', '--version'], 'Python 3.12.3'),
    ('xorriso', ['/usr/bin/xorriso', '-version'], 'xorriso 1.5.6')):
    text = run(name, argv)
    if not any(line == expected or line.startswith(expected + ' (') or
               line.startswith(expected + ' :') for line in text.splitlines()):
        raise ValueError('wrong tool version')
    versions[name] = expected
firmware = ['/usr/share/seabios/bios-256k.bin', '/usr/share/seabios/vgabios-stdvga.bin',
            '/usr/lib/ipxe/qemu/efi-virtio.rom']
for path in firmware:
    if not pathlib.Path(path).is_file() or not os.access(path, os.R_OK) or os.stat(path).st_size == 0:
        raise ValueError('firmware missing')
name = 'nested-directory/representative-provision-module-with-long-name.txt'
fixed = b'labapp non-VM ISO tool check v1\n'
source = pathlib.Path('source') / name
source.parent.mkdir(parents=True)
source.write_bytes(fixed)
run('create', ['/usr/bin/xorriso', '-as', 'genisoimage', '-rock', '-joliet', '-volid',
               'cidata', '-output', '/out/check.iso', '/out/source'])
iso = pathlib.Path('check.iso').read_bytes()
if not 32768 < len(iso) <= 8388608 or iso[32768:32775] != b'\x01CD001\x01' or iso[32808:32840] != b'cidata'.ljust(32):
    raise ValueError('invalid ISO volume')
run('extract', ['/usr/bin/xorriso', '-abort_on', 'FAILURE', '-osirrox', 'on', '-indev',
                '/out/check.iso', '-extract', '/' + name, '/out/readback'])
if pathlib.Path('readback').read_bytes() != fixed or source.read_bytes() != fixed:
    raise ValueError('ISO readback mismatch')
report = {'schema': 1, 'versions': versions, 'firmware': firmware,
          'input_sha256': hashlib.sha256(fixed).hexdigest(),
          'iso_sha256': hashlib.sha256(iso).hexdigest(), 'iso_bytes': len(iso),
          'readback_sha256': hashlib.sha256(fixed).hexdigest(), 'volume': 'cidata'}
with open('runtime.json', 'x') as out:
    json.dump(report, out, sort_keys=True)
'''
RUNTIME_SCRIPT = ("ulimit -f 8192 || exit 125; umask 077; "
                  "/usr/bin/env -i HOME=/out TMPDIR=/out PATH=/usr/bin:/bin LC_ALL=C "
                  "/usr/bin/python3 -I -B -c " + shlex.quote(RUNTIME_PROGRAM) +
                  " > /out/runtime.log 2>&1 < /dev/null")


# --- control-build: the unchanged official `hhfab build --build-controls=true --build-gateways=false --build-mode=iso`.
# Facts read from fabricator v0.50.4 source (nothing executed): init writes fab.yaml/.registry.yaml/include/result into
# --workdir; `--import-host-upstream` (hidden unless HHFAB_PREVIEW) reads only DOCKER_CONFIG/config.json and, for an
# empty store, yields an anonymous upstream stanza; `build` has no --force/--clean option; recipe.buildInstall skips when
# `<type>--<name>--install.inhash` matches AND `<type>--<name>--install-usb.iso` exists, otherwise removes and rebuilds.
CONTROL_STEPS = ("init1", "validate1", "assert1", "cold", "noop", "init2", "validate2", "assert2", "warm")
CONTROL_ENV = ("/usr/bin/env -i HOME=/out/home TMPDIR=/out/tmp PATH=/usr/bin:/bin LC_ALL=C "
               "DOCKER_CONFIG=/in/docker HHFAB_PREVIEW=true")
CONTROL_INIT = ("init --fabric-mode spine-leaf --dev --gateway=false --import-host-upstream "
                "--registry-repo ghcr.io --registry-prefix githedgehog --wiring /in/wiringd.yaml")
CONTROL_VALIDATE = "validate --hydrate-mode if-not-present"
CONTROL_BUILD = "build --hydrate-mode if-not-present --build-controls=true --build-gateways=false --build-mode=iso"
# The generated upstream stanza is checked from bounded text before any build; only the exit status is kept.
ASSERT_PROGRAM = r'''
import sys
raw = open(sys.argv[1], 'rb').read(1048577)
if len(raw) > 1048576:
    sys.exit(3)
# Check only the exact generated spec.config.registry subtree. Other generated
# user passwords and join tokens are unrelated and must never be exported.
lines = raw.decode('utf-8').splitlines()
path = []
registry = []
for line in lines:
    text = line.strip()
    if text == '---':
        break
    if not text or text.startswith('#'):
        continue
    indent = len(line) - len(line.lstrip(' '))
    while path and path[-1][0] >= indent:
        path.pop()
    if ':' not in text:
        if [entry[1] for entry in path][:3] == ['spec', 'config', 'registry']:
            sys.exit(4)
        continue
    key, value = text.split(':', 1)
    keys = [entry[1] for entry in path] + [key]
    if keys[:3] == ['spec', 'config', 'registry']:
        registry.append((keys[3:], value.strip()))
    path.append((indent, key))
want = [([], ''), (['mode'], 'upstream'), (['upstream'], ''),
        (['upstream', 'repo'], 'ghcr.io'), (['upstream', 'prefix'], 'githedgehog'),
        (['upstream', 'noTLSVerify'], 'false'), (['upstream', 'username'], ''),
        (['upstream', 'password'], '')]
# Official init emits empty scalars; accept their explicit quoted/null forms too.
empty = ('', '\"\"', "''", 'null')
normalized = [(keys, '' if keys in (['upstream', 'username'], ['upstream', 'password'])
               and value in empty else value) for keys, value in registry]
ok = normalized == want
sys.exit(0 if ok else 4)
'''
# Exact v0.50.4 recipe creates 9 GiB + 500 MiB + 2*(33*512) + 1 MiB =
# 10,189,046,784 logical bytes before ISO finalization. 12 GiB leaves ~2.51 GiB
# per-file headroom. Lead-approved experiment thresholds, not measured fit.
CONTROL_RECIPE_DISK_BYTES = 9 * (1 << 30) + 501 * (1 << 20) + 2 * 33 * 512
CONTROL_FILE_KIB = 12 * 1024 * 1024  # per-file ulimit, NOT a directory quota
CONTROL_OWNED_CAP = 32 << 30   # sampled allocated-bytes ceiling for /out (proposed, unmeasured); NOT a quota
CONTROL_MIN_FREE = 40 << 30    # host free-space precondition before the workspace exists (proposed, unmeasured)
CONTROL_SAMPLE = 5             # seconds between host samples of the owned tree
CONTROL_ENTRY_CAP = 200000
CONTROL_MS_CAP = 1800000
CONTROL_ISO_RE = re.compile(r"^[a-z]+--[A-Za-z0-9._-]+--install-usb\.iso$")
CONTROL_STEP_RE = re.compile(r"^([a-z0-9]+) (\d{1,3}) (\d{1,8})$")
CONTROL_SIZE_RE = re.compile(r"^(cache_cold|w1_cold|cache_warm|w2_warm) (\d{1,12}) (\d{1,12})$")
CONTROL_STAT_RE = re.compile(r"^(cold|noop) (\d{1,13}) (\d{1,12}) (\d{1,12})$")
# What a passing control-build does and does not establish; retained in evidence verbatim.
CONTROL_CLAIMS = {"measures": "inner official control-installer build only", "release_pin": False,
                  "outer_labapp_image": False, "full_vlab": False, "student_readiness": False,
                  "disk_quota": False, "peak": "sampled-lower-bound", "signatures_verified": False,
                  "egress": "ordinary-docker-bridge-not-allowlisted"}


def _control_step(name, command, workdir):
    return f"step {name} {CONTROL_ENV} /in/hhfab {command} --workdir {workdir} --cache-dir /out/cache"


CONTROL_SCRIPT = (
    f"ulimit -f {CONTROL_FILE_KIB} || exit 125; umask 077; "
    'now() { t=${EPOCHREALTIME/./}; echo $((t/1000)); }; '
    'step() { n=$1; shift; s=$(now); "$@" > "/out/$n.out" 2> "/out/$n.err" < /dev/null; c=$?; e=$(now); '
    'echo "$n $c $((e-s))" >> /out/steps; return $c; }; '
    'size() { a=$(/usr/bin/du -sk --apparent-size "$2") || return 1; b=$(/usr/bin/du -sk "$2") || return 1; '
    'echo "$1 ${a%%[[:space:]]*} ${b%%[[:space:]]*}" >> /out/sizes; }; '
    'isostat() { /usr/bin/stat -c "$1 %s %i %Y" /out/$2/result/*--install-usb.iso >> /out/isostat; }; '
    "asserted() { step $1 /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 -I -B -c "
    f"{shlex.quote(ASSERT_PROGRAM)} /out/$2/fab.yaml; }}; "
    f"{_control_step('init1', CONTROL_INIT, '/out/w1')} && "
    f"{_control_step('validate1', CONTROL_VALIDATE, '/out/w1')} && asserted assert1 w1 && "
    f"{_control_step('cold', CONTROL_BUILD, '/out/w1')} && size cache_cold /out/cache && size w1_cold /out/w1 && "
    "isostat cold w1 && "
    f"{_control_step('noop', CONTROL_BUILD, '/out/w1')} && isostat noop w1 && "
    f"{_control_step('init2', CONTROL_INIT, '/out/w2')} && "
    f"{_control_step('validate2', CONTROL_VALIDATE, '/out/w2')} && asserted assert2 w2 && "
    f"{_control_step('warm', CONTROL_BUILD, '/out/w2')} && size cache_warm /out/cache && size w2_warm /out/w2; exit 0")


class OutputBound(Exception):
    """Sampled owned-tree allocation or entry count crossed its bound (not a filesystem quota)."""


class DiskHeadroom(Exception):
    """Host free space is below the control-build precondition; no workspace was created."""


def free_bytes(path):
    info = os.statvfs(path)
    return info.f_bavail * info.f_frsize


def measure_tree(path, limit=CONTROL_ENTRY_CAP):
    """lstat-only walk (never follows symlinks): (logical bytes, allocated bytes, entries). Hard links are
    counted per name, so this is an upper bound; entries that vanish mid-walk are skipped."""
    logical = allocated = entries = 0
    stack = [path]
    while stack:
        try:
            with os.scandir(stack.pop()) as items:
                for item in items:
                    entries += 1
                    if entries > limit:
                        raise OutputBound("entry limit")
                    try:
                        info = item.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    logical += info.st_size
                    allocated += info.st_blocks * 512
                    if stat.S_ISDIR(info.st_mode):
                        stack.append(item.path)
        except FileNotFoundError:
            continue
    return logical, allocated, entries


def boot_clock():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def read_proc(path, limit=256):
    with open(path, "rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("oversized proc clock data")
    return raw.decode("ascii").strip()


def host_boot_id():
    boot = read_proc("/proc/sys/kernel/random/boot_id")
    if not re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot):
        raise ValueError("invalid boot ID")
    lines = read_proc("/proc/self/timens_offsets").splitlines()
    if sorted(line.split() for line in lines) != [["boottime", "0", "0"], ["monotonic", "0", "0"]]:
        raise ValueError("time namespace offsets unsupported")
    return boot



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
        if not HOST_RE.fullmatch(host):
            raise ValueError("local Unix Docker endpoint required")
        self.docker, self.host, self.config = docker, host, config

    def call(self, args, seconds):
        argv = [self.docker, "--host", self.host, "--config", self.config, *args]
        end = boot_clock() + seconds
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, start_new_session=True,
                                    env={"PATH": "/usr/bin:/bin"})
        except OSError as exc:
            raise DockerError() from exc
        chunks, size, fd = [], 0, proc.stdout.fileno()
        try:
            while True:
                left = end - boot_clock()
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
            # Observe exit without reaping: the retained leader pins its PID /
            # process-group ID until cleanup, preventing a reused group signal.
            while os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                left = end - boot_clock()
                if left <= 0:
                    raise DockerTimeout()
                time.sleep(min(0.01, left))
        finally:
            # Signal the owned group BEFORE reaping its leader, including when
            # that leader has exited but descendants still hold stdout open.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
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


def released_record(record):
    """Only our complete terminal records permit reuse; malformed state holds."""
    try:
        mode = record.get("mode", "probe")  # historical probe records predate the mode field
        if mode not in MODES:
            return False
        expected_image = (require_runtime(mode)["image_id"] if mode in VM_MODES else
                          PREPARED_RUNTIME["image_id"] if mode in ("runtime-check", "control-build") else PINNED_IMAGE)
        return (record["state"] == "released" and record["image"] == expected_image
                and re.fullmatch(r"labapp-probe-[a-zA-Z0-9-]+", record["name"])
                and record["label"] == "labapp.probe.run=" + record["name"][13:]
                and (record["id"] is None or CONTAINER_ID_RE.fullmatch(record["id"]))
                and (record["workspace"] is None or PATH_RE.fullmatch(record["workspace"]))
                and 0 <= record["admitted_at"] < record["work_deadline"] < record["deadline"]
                and isinstance(record["pid"], int) and record["pid"] > 0
                and record["outcome"] in ("accepted", "failed") and "reason" in record)
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def unresolved_records(directory):
    """Names of ledger records that are not released (corrupt counts as unresolved)."""
    out = []
    with os.scandir(directory) as entries:
        for count, entry in enumerate(entries):
            if count >= 128:
                return ["ledger_entry_limit"]
            if entry.name == "admission.lock" or entry.name == "docker-config":
                if entry.is_symlink():
                    return ["symlinked_ledger_entry"]
                continue
            if not re.fullmatch(r"labapp-probe-[a-zA-Z0-9-]+\.json", entry.name):
                return ["unexpected_ledger_entry"]
            try:
                fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as handle:
                    info = os.fstat(handle.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
                        return ["invalid_ledger_record"]
                    raw = handle.read(4097)
                record = json.loads(raw)
                if len(raw) > 4096 or not isinstance(record, dict) or not released_record(record):
                    out.append(entry.name)
            except (OSError, ValueError):
                out.append(entry.name)
    return out


def mounts(mode, workspace):
    """Fixed mounts. probe/runtime-check: only the writable workspace. hcl-check:
    staged inputs (including the base snapshot) and CD files read-only, and only
    the fresh `out` tree writable."""
    if mode in ("probe", "runtime-check"):
        return [f"--mount=type=bind,src={workspace},dst=/out"]
    if mode == "control-build":      # no CD tree: inputs read-only, only `out` writable
        return [f"--mount=type=bind,src={workspace}/in,dst=/in,readonly",
                f"--mount=type=bind,src={workspace}/out,dst=/out"]
    return [f"--mount=type=bind,src={workspace}/in,dst=/in,readonly",
            f"--mount=type=bind,src={workspace}/out,dst=/out",
            f"--mount=type=bind,src={workspace}/cd,dst=/out/work/cd,readonly"]


def create_args(name, label, image_id, user, workspace, deadline, boot_id="<boot-id>",
                mode="probe", kvm_gid="<kvm-gid>"):
    """Exact, fixed creation argv: no init, no restart, no pull, healthcheck off.
    sentinel adds exactly /dev/kvm and its numeric group; nothing else widens."""
    kvm = [f"--device={KVM_DEVICE}", f"--group-add={kvm_gid}"] if mode in VM_MODES else []
    script = {"probe": PROBE_SCRIPT, "hcl-check": HCL_SCRIPT, "sentinel": SENTINEL_SCRIPT,
              "sentinel-expiry": SENTINEL_SCRIPT, "fixture": SENTINEL_SCRIPT, "qemu-fixture": SENTINEL_SCRIPT,
              "runtime-check": RUNTIME_SCRIPT, "control-build": CONTROL_SCRIPT}[mode]
    network = "--network=bridge" if mode in NETWORKED_MODES else "--network=none"
    return ["create", "--pull=never", f"--name={name}", f"--label={label}",
            "--restart=no", network, "--cap-drop=ALL", "--no-healthcheck",
            "--security-opt=no-new-privileges", "--read-only", f"--user={user}",
            *LIMITS[mode], *kvm, "--log-driver=none", *mounts(mode, workspace),
            "--entrypoint=/bin/bash", image_id, "-c", ENTRY, "bash", str(deadline), boot_id, script]


class HardwareMissing(Exception):
    """/dev/kvm is absent or unusable by the nonroot runner; never replaced by TCG."""


def require_runtime(mode="sentinel"):
    """Fail closed unless the lead-accepted concrete runtime identity for this VM mode is set."""
    runtime = EXPIRY_RUNTIME if mode == "sentinel-expiry" else SENTINEL_RUNTIME
    ok = (isinstance(runtime, dict) and set(runtime) == {"image_id", "diffids"}
          and isinstance(runtime["image_id"], str) and IMAGE_ID_RE.fullmatch(runtime["image_id"])
          and isinstance(runtime["diffids"], list) and runtime["diffids"]
          and all(isinstance(d, str) and IMAGE_ID_RE.fullmatch(d) for d in runtime["diffids"]))
    if not ok:
        raise ValueError("sentinel runtime identity is not accepted: no VM runtime is available")
    return runtime


def kvm_preflight(path=KVM_DEVICE):
    """Metadata only (no open, no ioctl): a character device that its nonzero group may
    read and write. Returns that numeric GID for `--group-add`."""
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise HardwareMissing("kvm device absent") from exc
    if not stat.S_ISCHR(info.st_mode) or info.st_gid == 0 or info.st_mode & 0o060 != 0o060:
        raise HardwareMissing("kvm device not group read/write for a nonroot group")
    return info.st_gid


def owned_query(name, label):
    return ["container", "ls", "-aq", "--no-trunc", "--filter", f"name=^/{name}$",
            "--filter", f"label={label}"]


def id_query(ident):
    return ["container", "ls", "-aq", "--no-trunc", "--filter", f"id={ident}"]


def identity_args(ident):
    return ["inspect", "--type=container", "--format",
            '{{.Id}} {{.Name}} {{index .Config.Labels "labapp.probe.run"}}', ident]


IMAGE_FORMAT = '{{json .}}'


def check_image(raw, image):
    """Inspect whole bounded JSON: optional Config keys may be absent."""
    try:
        info = json.loads(raw)
        config = info["Config"]
        ok = (IMAGE_ID_RE.fullmatch(info["Id"]) and isinstance(info["RepoDigests"], list)
              and image in info["RepoDigests"]
              and not config.get("Volumes") and not config.get("OnBuild"))
    except (ValueError, KeyError, TypeError, AttributeError):
        ok = False
    if not ok:
        raise DockerError()
    return info["Id"]


def check_runtime(raw, runtime):
    """The prepared runtime must be exactly the accepted image ID and RootFS layers."""
    try:
        info = json.loads(raw)
        config = info["Config"]
        ok = (info["Id"] == runtime["image_id"] and info["RootFS"]["Layers"] == runtime["diffids"]
              and not config.get("Volumes") and not config.get("OnBuild"))
    except (ValueError, KeyError, TypeError, AttributeError):
        ok = False
    if not ok:
        raise DockerError()
    return info["Id"]


def make_workspace(root, ident, uid):
    """Fresh 0700 directory under a validated, unshared, symlink-free root."""
    check_private_dir(root, uid, "workspace root")
    path = os.path.join(root, f"labapp-probe-{ident}")
    os.mkdir(path, 0o700)
    return path


def read_witness(path, deadline, started_after):
    """Parse the fixed probe's startup witness; return the timer seconds or None.
    Untrusted data: exactly one small regular file with an exact format."""
    with os.scandir(path) as entries:
        first = next(entries, None)
        if first is None or first.name != "witness" or next(entries, None) is not None:
            return None
    full = os.path.join(path, "witness")
    if not stat.S_ISREG(os.lstat(full).st_mode):
        return None
    fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return None
        raw = handle.read(257)
    match = WITNESS_RE.fullmatch(raw.decode("ascii", "replace"))
    if not match:
        return None
    n, t = int(match.group(1)), int(match.group(2))
    if t != deadline - n - 1 - KILL_AFTER or t < MIN_TIMER or n < started_after - 1:
        return None
    return t


def run_probe(image, root, ledger_dir, backend, **kwargs):
    # Nonblocking admission: one host ledger authority must be used for this
    # endpoint. Hold this lock through scan, reservation, cleanup and publication.
    if kwargs.get("mode") in VM_MODES:
        require_runtime(kwargs["mode"])      # before the lock, ledger, workspace, staging or any Docker call
    check_private_dir(ledger_dir, kwargs.get("uid") or os.getuid(), "ledger dir")
    kwargs.setdefault("admitted_at", kwargs.get("clock", boot_clock)())
    try:
        fd = os.open(os.path.join(ledger_dir, "admission.lock"),
                     os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(fd, "r+") as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise OSError("invalid lock")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return _run_probe_locked(image, root, ledger_dir, backend, **kwargs)
    except OSError:
        return {"outcome": "hold", "reason": "admission_lock_unavailable", "cleanup": "not_attempted"}


def _run_probe_locked(image, root, ledger_dir, backend, *, clock=boot_clock, sleep=time.sleep,
              admitted_at=None, new_uuid=lambda: str(uuid.uuid4()),
              uid=None, gid=None, work=None, cleanup=None, handle_signals=False,
              mode="probe", sources=None):
    """Return a result dict; outcome is accepted, failed or hold. Never raises on
    daemon trouble. `hold` keeps the ledger record and workspace for the lead."""
    admitted_at = clock() if admitted_at is None else admitted_at
    uid, gid = (os.getuid() if uid is None else uid), (os.getgid() if gid is None else gid)
    if mode not in MODES:
        raise ValueError("unknown mode")
    keys = (FIXTURE_SOURCE_KEYS if mode in ("fixture", "qemu-fixture") else
            CONTROL_SOURCE_KEYS if mode == "control-build" else SOURCE_KEYS)
    if (mode in STAGED_MODES or mode == "control-build") and not (isinstance(sources, dict) and set(sources) == keys):
        raise ValueError(f"{mode} needs exactly the {', '.join(sorted(keys))} input files")
    if mode in VM_MODES:
        require_runtime(mode)
    w, c = PROFILES[mode]
    budget = Budget(w if work is None else work, c if cleanup is None else cleanup, clock, admitted_at)
    expected_image = (PREPARED_RUNTIME["image_id"] if mode in ("runtime-check", "control-build") else
                      require_runtime(mode)["image_id"] if mode in VM_MODES else PINNED_IMAGE)
    if image != expected_image:
        raise ValueError("image must be the fixed identity for this task")
    if mode == "runtime-check" and sources is not None:
        raise ValueError("runtime-check accepts no staged inputs")
    if uid == 0:
        raise ValueError("refusing to run as root")
    check_private_dir(ledger_dir, uid, "ledger dir")
    if os.path.commonpath([root, ledger_dir]) in (root, ledger_dir):
        raise ValueError("ledger dir and workspace root must be separate trees")
    prior = unresolved_records(ledger_dir)
    if prior:
        return {"outcome": "hold", "reason": "unresolved_prior_request", "cleanup": "not_attempted",
                "records": prior}
    ident = new_uuid()
    own = {"name": f"labapp-probe-{ident}", "label": f"labapp.probe.run={ident}", "ident": ident,
           "id": None, "ambiguous": None, "attempted": False, "workspace": None, "ledger": None,
           "cancelled": False, "cleaning": False, "uncertain": False, "started_at": None,
           "witness": None, "boot_id": host_boot_id(), "deadline": int(budget.work_deadline),
           "mode": mode, "sources": sources, "staged": None, "image_id": None}
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
                "deadline": budget.deadline, "pid": os.getpid(), "mode": mode})
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
            if own["ledger"] is not None:
                try:
                    own["ledger"].write("hold", outcome="hold", reason="finalization_error")
                except BaseException:
                    pass
    finally:
        if handle_signals:
            for s, old in zip((signal.SIGTERM, signal.SIGINT), previous):
                signal.signal(s, old)
    return result


def _reason(exc):
    return {OutputBound: "output_bound_exceeded", DiskHeadroom: "insufficient_disk_headroom",
            Expired: "budget_exhausted", DockerError: "daemon_error", OSError: "ledger_or_fs_error",
            DockerTimeout: "daemon_timeout", ValueError: "invalid_input",
            stage_tools.StageError: "staging_rejected", HardwareMissing: "kvm_unavailable"}.get(type(exc), "error")


def _checkpoint(own, budget, clock):
    """After any slow call: cancellation and work deadline are re-checked."""
    if own["cancelled"]:
        raise Cancelled()
    if clock() >= budget.work_deadline:
        raise Expired()


def _run(image, root, backend, budget, own, result, sleep, uid, gid, clock):
    ledger = own["ledger"]
    kvm_gid = None
    if own["mode"] in VM_MODES:
        kvm_gid = kvm_preflight()      # metadata only; no TCG fallback exists
    if own["mode"] == "control-build" and free_bytes(root) < CONTROL_MIN_FREE:
        raise DiskHeadroom()       # before any workspace or Docker mutation
    # Preparation consumes the same budget as everything else.
    own["workspace"] = make_workspace(root, own["ident"], uid)
    ledger.write("workspace_made", workspace=own["workspace"])
    if own["mode"] == "control-build":
        own["staged"] = stage_tools.stage_control(own["workspace"], own["sources"],
                                                  lambda: _checkpoint(own, budget, clock))
        _checkpoint(own, budget, clock)
    if own["mode"] in STAGED_MODES:
        # Staging starts after admission and spends the same absolute budget.
        extra = {}
        if own["mode"] in SUCCESS_MODES:
            def verify_budget():
                left = int(budget.work_left()) - SENTINEL_RESERVE
                if left < SENTINEL_MIN_VERIFY:
                    raise Expired()
                return left
            extra = {"task": own["mode"], "verify_seconds": verify_budget}
        elif own["mode"] == "sentinel-expiry":
            def expiry_budget():
                if budget.work_left() < EXPIRY_MIN_REMAINING:
                    raise Expired()      # staging consumed too much of the original 300 s
                return EXPIRY_VERIFY_SECONDS
            extra = {"task": "sentinel-expiry", "verify_seconds": expiry_budget}
        own["staged"] = stage_tools.stage(own["workspace"], own["sources"], os.urandom(32).hex(),
                                          lambda: _checkpoint(own, budget, clock), pins=stage_tools.PINS,
                                          **extra)
        _checkpoint(own, budget, clock)
    backend.call(["version", "--format", "{{.Server.Version}}"], budget.seconds(CALL_CAP, budget.work_deadline))
    _checkpoint(own, budget, clock)
    if own["mode"] in VM_MODES + ("runtime-check", "control-build"):
        runtime = (PREPARED_RUNTIME if own["mode"] in ("runtime-check", "control-build")
                   else require_runtime(own["mode"]))
        image_id = check_runtime(backend.call(["image", "inspect", "--format", IMAGE_FORMAT,
                                               runtime["image_id"]],
                                              budget.seconds(CALL_CAP, budget.work_deadline)), runtime)
    else:
        image_id = check_image(backend.call(["image", "inspect", "--format", IMAGE_FORMAT, image],
                                            budget.seconds(CALL_CAP, budget.work_deadline)), image)
    _checkpoint(own, budget, clock)
    if budget.work_left() < START_RESERVE + KILL_AFTER + MIN_TIMER:
        raise Expired()
    own["image_id"] = image_id
    argv = create_args(own["name"], own["label"], image_id, f"{uid}:{gid}", own["workspace"], own["deadline"],
                       own["boot_id"], own["mode"], kvm_gid)
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
        if own["mode"] == "control-build":
            _sample_control(own, clock)
        if budget.work_left() <= 0:
            if own["mode"] == "sentinel-expiry":
                own["exit_seen_at"] = clock()
                _accept_expiry(own, result, budget, clock, oom, code, live=True)
            result["reason"] = "host_expiry"     # internal timer should have won
            return
        sleep(min(POLL, max(budget.work_left(), 0)))
    own["exit_seen_at"] = clock()
    if own["mode"] == "runtime-check":
        _accept_runtime(own, result, budget, clock, oom, code)
        return
    if own["mode"] == "control-build":
        _accept_control(own, result, budget, clock, oom, code)
        return
    if own["mode"] == "hcl-check":
        _accept_hcl(own, result, budget, clock, oom, code)
        return
    if own["mode"] in SUCCESS_MODES:
        _accept_sentinel(own, result, budget, clock, oom, code)
        return
    if own["mode"] == "sentinel-expiry":
        _accept_expiry(own, result, budget, clock, oom, code)
        return
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


def read_step(out_dir, name, cap=STEP_CAP):
    """One fixed result file from the container-writable tree: untrusted, so it must be
    a regular file within the cap. Returns bytes or None when absent/invalid."""
    try:
        return stage_tools.read_file(os.path.join(out_dir, name), cap)
    except (OSError, stage_tools.StageError):
        return None


def _accept_runtime(own, result, budget, clock, oom, code):
    """Accept only bounded fixed tool/ISO evidence; final acceptance also needs exact
    container and workspace cleanup in _finish. No provisioner inputs are staged."""
    workspace = own["workspace"]
    evidence = {"image_id": own["image_id"], "runtime_diffids": PREPARED_RUNTIME["diffids"],
                "exit_code": code, "oom_killed": oom, "logs": {},
                "elapsed": round(own["exit_seen_at"] - own["started_at"], 2)}
    result["evidence"] = evidence
    # Diagnostics survive verified workspace cleanup even when the program stops
    # before writing its success report. Reject invalid files, never truncate them.
    invalid = []
    for name in ("qemu", "qemu_img", "python", "xorriso", "create", "extract", "runtime"):
        raw_log = read_step(workspace, name + ".log", 16384)
        if raw_log is None:
            invalid.append(name + ".log")
        else:
            evidence["logs"][name] = {"bytes": len(raw_log), "sha256": hashlib.sha256(raw_log).hexdigest(),
                                      "excerpt": raw_log[:EXCERPT].decode("ascii", "replace")}
    if invalid:
        evidence["invalid_files"] = sorted(invalid)
    if oom or code != 0:
        result["reason"] = "unexpected_exit"
        return
    if invalid:
        result["reason"] = "invalid_runtime_evidence"
        return
    try:
        raw = read_step(workspace, "runtime.json", RESULT_CAP)
        report = json.loads(raw.decode("ascii"), object_pairs_hook=_strict_pairs,
                            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        keys = {"schema", "versions", "firmware", "input_sha256", "iso_sha256", "iso_bytes",
                "readback_sha256", "volume"}
        fixed_sha = hashlib.sha256(RUNTIME_BYTES).hexdigest()
        if (not isinstance(report, dict) or set(report) != keys or type(report["schema"]) is not int
                or report["schema"] != 1 or report["versions"] != RUNTIME_VERSIONS
                or report["firmware"] != list(RUNTIME_FIRMWARE) or report["volume"] != "cidata"
                or report["input_sha256"] != fixed_sha or report["readback_sha256"] != fixed_sha
                or type(report["iso_bytes"]) is not int or not 32768 < report["iso_bytes"] <= RUNTIME_ISO_CAP):
            raise ValueError("invalid runtime report")
        iso = read_step(workspace, "check.iso", RUNTIME_ISO_CAP)
        if (iso is None or len(iso) != report["iso_bytes"]
                or hashlib.sha256(iso).hexdigest() != report["iso_sha256"]
                or iso[32768:32775] != b'\x01CD001\x01' or iso[32808:32840] != b'cidata'.ljust(32)
                or read_step(workspace, "readback", len(RUNTIME_BYTES)) != RUNTIME_BYTES
                or read_step(os.path.join(workspace, "source"), RUNTIME_PATH, len(RUNTIME_BYTES)) != RUNTIME_BYTES):
            raise ValueError("ISO evidence mismatch")
        _checkpoint(own, budget, clock)
    except (ValueError, TypeError, AttributeError, RecursionError):
        result["reason"] = "invalid_runtime_evidence"
        return
    evidence["report"] = report
    result["outcome"], result["reason"], result["exit_code"] = "accepted", None, code


def _sample_control(own, clock):
    """Periodic lstat walk of the owned `out` tree. This is SAMPLING: growth between samples can overshoot the
    bound, and the recorded peak is a lower bound. No filesystem quota exists or is claimed."""
    now = clock()
    if now - own.get("sampled_at", -CONTROL_SAMPLE) < CONTROL_SAMPLE:
        return
    own["sampled_at"] = now
    logical, allocated, _ = measure_tree(os.path.join(own["workspace"], "out"))
    peak = own.setdefault("peak", {"logical": 0, "allocated": 0, "samples": 0})
    peak["samples"] += 1
    peak["logical"], peak["allocated"] = max(peak["logical"], logical), max(peak["allocated"], allocated)
    if allocated > CONTROL_OWNED_CAP:
        raise OutputBound("owned allocation over bound")


def _control_lines(raw, pattern):
    """Closed parse of a small container-written file: every line must match, else None."""
    if raw is None:
        return None
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return None
    rows = [pattern.fullmatch(line) for line in lines]
    return None if not rows or any(row is None for row in rows) else [row.groups() for row in rows]


def _control_iso(out, name):
    """The single `<type>--<name>--install-usb.iso` in out/<name>/result, or None."""
    try:
        with os.scandir(os.path.join(out, name, "result")) as items:
            found = [item for item in items if CONTROL_ISO_RE.fullmatch(item.name)]
    except OSError:
        return None
    return found[0].path if len(found) == 1 and found[0].name == "control--control-1--install-usb.iso" else None


def _accept_control(own, result, budget, clock, oom, code):
    """Success needs exit 0, all nine recorded steps exiting 0 in order (init/validate/upstream assertion/cold
    build/no-op build/fresh init/validate/assertion/warm build), one bounded ISO in each workspace, a no-op
    labelled from metadata without claiming an internal hash skip, unchanged staged bytes and
    (checked in _finish) verified removal of the container and the whole owned workspace."""
    out = os.path.join(own["workspace"], "out")
    staged = own["staged"]
    evidence = {"image_id": own["image_id"], "runtime_diffids": PREPARED_RUNTIME["diffids"], "task": "control-build",
                "staged_inputs_verification": "not_run", "cache_audit": {"status": "not_run"},
                "inputs": staged, "exit_code": code, "oom_killed": oom, "claims": dict(CONTROL_CLAIMS),
                "network": "docker-bridge-outbound", "commands": {
                    "init": "hhfab " + CONTROL_INIT, "validate": "hhfab " + CONTROL_VALIDATE,
                    "build": "hhfab " + CONTROL_BUILD},
                "limits": {"file_kib": CONTROL_FILE_KIB, "owned_allocated_sample_cap": CONTROL_OWNED_CAP,
                           "min_free": CONTROL_MIN_FREE, "quota": False},
                "elapsed": round(own["exit_seen_at"] - own["started_at"], 2)}
    result["evidence"] = evidence
    raw = {n: read_step(out, n, RESULT_CAP) for n in ("steps", "sizes", "isostat")}
    steps = _control_lines(raw["steps"], CONTROL_STEP_RE)
    if steps is not None and (len(steps) > len(CONTROL_STEPS) or any(s[0] not in CONTROL_STEPS for s in steps)):
        steps = None
    if steps is not None:
        evidence["steps"] = [[n, int(c), int(ms)] for n, c, ms in steps]
    for step in CONTROL_STEPS:
        for suffix in ("out", "err"):
            data = read_step(out, f"{step}.{suffix}")
            if data is not None:
                evidence.setdefault("logs", {})[f"{step}.{suffix}"] = {
                    "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    failed = next((s for s in (steps or []) if s[1] != "0"), None)
    if failed is not None:
        evidence["failed_step"] = {"name": failed[0], "exit": int(failed[1])}
    try:
        logical, allocated, entries = measure_tree(out)
    except (OSError, OutputBound):
        result["reason"] = "output_bound_exceeded"
        return
    peak = own.setdefault("peak", {"logical": 0, "allocated": 0, "samples": 0})
    evidence["owned_bytes"] = {
        "at_exit": {"logical": logical, "allocated": allocated, "entries": entries},
        "peak_sampled": {"logical": max(peak["logical"], logical), "allocated": max(peak["allocated"], allocated),
                         "samples": peak["samples"]}}
    if allocated > CONTROL_OWNED_CAP:
        result["reason"] = "output_bound_exceeded"
        return
    if oom or code != 0:
        result["reason"] = "unexpected_exit"
        return
    if steps is None or [s[0] for s in steps] != list(CONTROL_STEPS) or any(
            s[1] != "0" or int(s[2]) > CONTROL_MS_CAP for s in steps):
        result["reason"] = "build_failed"
        return
    if len(evidence.get("logs", {})) != 2 * len(CONTROL_STEPS):
        result["reason"] = "invalid_step_evidence"
        return
    sizes, stats = _control_lines(raw["sizes"], CONTROL_SIZE_RE), _control_lines(raw["isostat"], CONTROL_STAT_RE)
    if (sizes is None or [s[0] for s in sizes] != ["cache_cold", "w1_cold", "cache_warm", "w2_warm"]
            or stats is None or [s[0] for s in stats] != ["cold", "noop"]):
        result["reason"] = "invalid_step_evidence"
        return
    kib = {label: {"apparent_kib": int(a), "allocated_kib": int(b)} for label, a, b in sizes}
    cold, noop = tuple(stats[0][1:]), tuple(stats[1][1:])
    seconds = {n: int(ms) / 1000 for n, _, ms in steps}
    evidence["timing_seconds"] = seconds
    evidence["cache_kib"] = {"after_cold": kib["cache_cold"], "after_warm": kib["cache_warm"]}
    evidence["workspace_kib"] = {"w1_after_cold": kib["w1_cold"], "w2_after_warm": kib["w2_warm"]}
    # Matching metadata alone cannot prove unchanged bytes or an internal hash skip.
    # `warm` is the fresh-workdir build sharing the cache; transfer is unobserved.
    evidence["noop"] = "unchanged_metadata_noop_candidate" if cold == noop else "rebuilt_in_place"
    evidence["warm_cache_growth_apparent_kib"] = (kib["cache_warm"]["apparent_kib"]
                                                  - kib["cache_cold"]["apparent_kib"])
    check = lambda: _checkpoint(own, budget, clock)
    evidence["staged_inputs_verification"] = "incomplete"
    try:
        intact = stage_tools.verify_control(own["workspace"], staged, check)
    except (OSError, stage_tools.StageError):
        intact = False
    evidence["staged_inputs_verification"] = "passed" if intact else "failed"
    if not intact:
        result["reason"] = "staged_inputs_changed"
        return
    isos = {}
    for name in ("w1", "w2"):
        path = _control_iso(out, name)
        try:
            if path is None:
                raise stage_tools.StageError("no single ISO")
            sha, _ = stage_tools.hash_file(path, limit=CONTROL_FILE_KIB * 1024, check=check)
            isos[name] = {"sha256": sha, "bytes": os.lstat(path).st_size, "name": os.path.basename(path)}
        except (OSError, stage_tools.StageError):
            result["reason"] = "iso_missing_or_invalid"
            return
    if isos["w1"]["bytes"] != int(noop[0]) or isos["w1"]["bytes"] <= 0 or isos["w2"]["bytes"] <= 0:
        result["reason"] = "iso_missing_or_invalid"
        return
    evidence["iso"] = isos
    evidence["iso_equal"] = isos["w1"]["sha256"] == isos["w2"]["sha256"]
    evidence["cache_audit"] = {"status": "incomplete"}
    try:
        evidence["cache_identity"] = stage_tools.verify_control_cache(os.path.join(out, "cache"), check)
    except stage_tools.CacheAuditRefusal as exc:
        evidence["cache_audit"] = exc.receipt
        result["reason"] = "cache_identity_mismatch"
        return
    except (OSError, stage_tools.StageError):
        evidence["cache_audit"] = {"status": "refused", "stage": "unknown", "reason": "unclassified"}
        result["reason"] = "cache_identity_mismatch"
        return
    evidence["cache_audit"] = {"status": "passed"}
    result["outcome"], result["reason"], result["exit_code"] = "accepted", None, code


def _accept_hcl(own, result, budget, clock, oom, code):
    """Success needs exit 0, all three steps 0, the pinned core version, unchanged
    staged bytes and (checked later in _finish) verified cleanup. Anything else is
    FAILED: a nonzero validation is never tool success."""
    out = os.path.join(own["workspace"], "out")
    staged = own["staged"]
    evidence = {"image_id": own["image_id"], "inputs": staged["inputs"],
                "vars_sha256": staged["vars_sha256"], "hcl_sha256": staged["hcl_sha256"],
                "base_sha256": staged["base_sha256"],
                "core_archive_sha256": staged["core_archive_sha256"],
                "core_member_sha256": staged["core_member_sha256"],
                "plugin_archive_sha256": staged["plugin_archive_sha256"],
                "plugin_member_sha256": staged["plugin_member_sha256"],
                "exit_code": code,
                "commands": ["packer version", "packer validate -syntax-only labapp.pkr.hcl",
                             "packer validate -var-file=validate.pkrvars.hcl labapp.pkr.hcl"],
                "elapsed": round(own["exit_seen_at"] - own["started_at"], 2)}
    result["evidence"] = evidence
    raw = {n: read_step(out, n) for n in ("steps", "version.out", "version.err", "syntax.out",
                                          "syntax.err", "full.out", "full.err")}
    for name, data in raw.items():
        if data is not None:
            evidence[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                              "excerpt": data[:EXCERPT].decode("ascii", "replace")}
    invalid = sorted(name for name, data in raw.items() if data is None)
    if invalid:
        evidence["invalid_files"] = invalid
        result["reason"] = "invalid_step_evidence"
        return
    if oom or code != 0:
        result["reason"] = "unexpected_exit"
        return
    steps = raw["steps"]
    if steps.decode("ascii", "replace") != STEPS_EXPECTED:
        result["reason"] = "tool_check_failed"
        return
    version = raw["version.out"]
    if not VERSION_RE.fullmatch(version.decode("ascii", "replace")):
        result["reason"] = "wrong_core_version"
        return
    try:
        intact = stage_tools.verify_staged(own["workspace"], staged,
                                           lambda: _checkpoint(own, budget, clock))
    except (OSError, stage_tools.StageError):
        intact = False
    if not intact:
        result["reason"] = "staged_inputs_changed"
        return
    result["outcome"], result["reason"] = "accepted", None
    result["exit_code"] = code


def _strict_pairs(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def _exact(value, expected):
    """Same type and value (so True is not 1 and 33.0 is not 33)."""
    return type(value) is type(expected) and value == expected


def _seconds(value):
    return type(value) is int and 0 <= value <= QEMU_SECONDS_CAP


def host_contract_valid(value):
    """Fixed native observations and the narrow sudo/TUN claims, independently revalidated."""
    if not isinstance(value, dict) or set(value) not in (HOST_KEYS, HOST_TAP_KEYS):
        return False
    if "tap" in value:      # v3 only; tap_create=passed is invalid without it and `unrun` with it
        tap = value["tap"]
        if not (_exact(value["tap_create"], "passed") and isinstance(tap, dict)
                and set(tap) == {"before", "owned", "after", "seconds"}
                and _exact(tap["before"], "absent") and _exact(tap["owned"], "present")
                and _exact(tap["after"], "absent") and type(tap["seconds"]) is int
                and 0 <= tap["seconds"] <= TAP_SECONDS_CAP):
            return False
    elif not _exact(value["tap_create"], "unrun"):
        return False
    native = value["native"]
    return (isinstance(native, dict) and set(native) == HOST_PACKAGES
            and all(isinstance(row, dict) and set(row) == {"version", "architecture", "sha256"}
                    and isinstance(row["version"], str) and HOST_VERSION_RE.fullmatch(row["version"])
                    and _exact(row["architecture"], "amd64") and isinstance(row["sha256"], str)
                    and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                    for row in native.values())
            and _exact(value["caller_uid"], 1000) and _exact(value["sudo_uid"], 0)
            and all(_exact(value[k], True) for k in ("tun_open", "tun_api", "tap_flag")))


def qemu_witness_valid(value):
    """The observer's closed qemu_witness object, revalidated as untrusted container output: exact
    keys and types, KVM, exit 33, root caller, nonce equality, unchanged backing, removed workspace,
    install 1 changed / install 2 unchanged, bounded integer seconds and boolean network flags."""
    try:
        install1, install2, network = value["install1"], value["install2"], value["network"]
        return (isinstance(value, dict) and set(value) == QEMU_WITNESS_KEYS
                and _exact(value["accelerator"], "kvm") and _exact(value["exit"], 33)
                and _exact(value["uid"], 0) and _exact(value["nonce_equal"], True)
                and _exact(value["backing_unchanged"], True) and _exact(value["workspace_removed"], True)
                and isinstance(install1, dict) and set(install1) == {"changed", "seconds"}
                and _exact(install1["changed"], True) and _seconds(install1["seconds"])
                and isinstance(install2, dict) and set(install2) == {"changed", "seconds"}
                and _exact(install2["changed"], False) and _seconds(install2["seconds"])
                and _seconds(value["witness_seconds"])
                and isinstance(network, dict) and set(network) == QEMU_NETWORK_KEYS
                and all(type(flag) is bool for flag in network.values())
                and host_contract_valid(value["host_contract"]))
    except (KeyError, TypeError):
        return False


def receipt_matches(raw, staged, qemu=False):
    """verified.json is untrusted container output: exactly the sentinel observer's five keys (six with
    the strict qemu_witness for qemu-fixture, and then required), bound to THIS run's nonce and to
    SHA256(cd/MANIFEST) (not the overall input identity)."""
    try:
        body = json.loads(raw.decode("ascii"), object_pairs_hook=_strict_pairs)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return False
    if qemu and not (isinstance(body, dict) and set(body) == QEMU_KEYS
                     and qemu_witness_valid(body["qemu_witness"])
                     and body["qemu_witness"]["host_contract"]["tap_create"] == "passed"):
        return False
    return (isinstance(body, dict) and set(body) == (QEMU_KEYS if qemu else SENTINEL_KEYS)
            and body["nonce"] == staged["nonce"] and body["inputs"] == staged["guest_receipt"]
            and body["shutdown"] == "guest-shutdown" and body["receipt"] == "ok"
            and body["cloud_init"] == {"status": "done", "errors": 0, "recoverable_errors": 0}
            and all(type(body["cloud_init"][k]) is int for k in ("errors", "recoverable_errors")))


def _accept_sentinel(own, result, budget, clock, oom, code):
    """Success needs the exit-0 build step, a fresh matching observer result (the observer
    itself requires prelaunch, enabled KVM, controlled `cont` and guest-initiated shutdown),
    a bounded artifact, unchanged staged bytes and (checked in _finish) verified cleanup.
    Packer exit 0 or verified.json alone is never enough. The disposable artifact is hashed
    and deleted here."""
    out = os.path.join(own["workspace"], "out")
    staged = own["staged"]
    evidence = {"image_id": own["image_id"], "runtime_diffids": SENTINEL_RUNTIME["diffids"],
                "inputs": staged["inputs"], "guest_receipt": staged["guest_receipt"],
                "nonce_sha256": hashlib.sha256(staged["nonce"].encode()).hexdigest(),
                "verify_seconds": staged["verify_seconds"], "vars_sha256": staged["vars_sha256"],
                "hcl_sha256": staged["hcl_sha256"], "base_sha256": staged["base_sha256"],
                "core_member_sha256": staged["core_member_sha256"],
                "plugin_member_sha256": staged["plugin_member_sha256"], "exit_code": code,
                "command": "packer build -var-file=sentinel.pkrvars.hcl labapp.pkr.hcl",
                "elapsed": round(own["exit_seen_at"] - own["started_at"], 2)}
    if own["mode"] in ("fixture", "qemu-fixture"):
        evidence["task"] = "fixture"
        evidence["hhfab_archive_sha256"] = staged["hhfab_archive_sha256"]
    qemu = own["mode"] == "qemu-fixture"
    if qemu:
        evidence["task"] = "qemu-fixture"
        evidence["network"] = "docker-bridge-outbound"
        evidence["claims"] = dict(QEMU_CLAIMS)
    result["evidence"] = evidence
    raw = {n: read_step(out, n) for n in ("steps", "build.out", "build.err")}
    raw["verified.json"] = read_step(os.path.join(out, "work"), "verified.json", RESULT_CAP)
    for name, data in raw.items():
        if data is not None:
            evidence[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            if name != "verified.json":
                evidence[name]["excerpt"] = data[:EXCERPT].decode("ascii", "replace")
    # The observer's bounded failure line can sit beyond the excerpt; keep only its fixed fields.
    found = OBSERVER_FAILURE_RE.findall((raw["build.out"] or b"").decode("ascii", "replace"))
    if found:
        evidence["observer_failure"] = found[-1]
    invalid = sorted(name for name, data in raw.items() if data is None)
    if invalid:
        evidence["invalid_files"] = invalid
        result["reason"] = "invalid_step_evidence"
        return
    if oom or code != 0:
        result["reason"] = "unexpected_exit"
        return
    if raw["steps"].decode("ascii", "replace") != SENTINEL_STEPS:
        result["reason"] = "build_failed"
        return
    if not receipt_matches(raw["verified.json"], staged, qemu):
        # For qemu-fixture this includes a missing, extra, forged or out-of-contract qemu_witness.
        result["reason"] = "stale_or_malformed_receipt"
        return
    # Retain only the validated closed summary, never arbitrary peer result text.
    body = json.loads(raw["verified.json"])
    evidence["cloud_init"] = body["cloud_init"]
    if qemu:
        evidence["qemu_witness"] = body["qemu_witness"]
    artifact = os.path.join(out, *ARTIFACT)
    try:
        sha, _ = stage_tools.hash_file(artifact, limit=stage_tools.ARTIFACT_LIMIT,
                                       check=lambda: _checkpoint(own, budget, clock))
        size = os.lstat(artifact).st_size
        evidence["artifact"] = {"sha256": sha, "bytes": size}
        os.unlink(artifact)
        if os.path.lexists(artifact):
            raise OSError("artifact still exists")
        evidence["artifact"]["deleted"] = True
    except (OSError, stage_tools.StageError):
        result["reason"] = "artifact_invalid_or_not_deleted"
        return
    try:
        intact = stage_tools.verify_staged(own["workspace"], staged,
                                           lambda: _checkpoint(own, budget, clock))
    except (OSError, stage_tools.StageError):
        intact = False
    if not intact:
        result["reason"] = "staged_inputs_changed"
        return
    result["outcome"], result["reason"] = "accepted", None
    result["exit_code"] = code


def _armed_valid(raw, staged, n, t, boot_id):
    """The observer's armed witness is untrusted container output: exactly the six fixed keys,
    this run's nonce and guest-receipt identity, and a paused-state time that leaves at least
    EXPIRY_MIN_DWELL seconds before the container timer (start n, t seconds) fires."""
    try:
        body = json.loads(raw.decode("ascii"), object_pairs_hook=_strict_pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return False
    return (isinstance(body, dict) and set(body) == ARMED_KEYS and body["kind"] == ARMED_KIND
            and body["armed"] == "paused" and body["nonce"] == staged["nonce"]
            and body["inputs"] == staged["guest_receipt"] and body["boot_id"] == boot_id
            and type(body["armed_at"]) is int and n <= body["armed_at"]
            and (n + t) - body["armed_at"] >= EXPIRY_MIN_DWELL)


def marker_absent(directory, name):
    """True only for confirmed ENOENT beneath anchored, nonsymlink parents."""
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in directory.split("/")[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return True
        return False
    except OSError:
        return False
    finally:
        os.close(parent)


def _accept_expiry(own, result, budget, clock, oom, code, live=False):
    """Accept a FAILURE-ONLY proof: the guest was paused by the sole observer (running, stop,
    paused all answered) and the container's own PID 1 timer ended Packer/QEMU at least
    EXPIRY_MIN_DWELL seconds later. It is never a successful guest or build: a completed build
    step, a success marker, an early or OOM exit, or a missing/malformed witness all fail.
    Bounded diagnostics and hashes are retained BEFORE any decision; cleanup is in _finish."""
    out = os.path.join(own["workspace"], "out")
    staged = own["staged"]
    evidence = {"image_id": own["image_id"], "runtime_diffids": EXPIRY_RUNTIME["diffids"],
                "proof": "expected_expiry", "build_success": False,
                "inputs": staged["inputs"], "guest_receipt": staged["guest_receipt"],
                "nonce_sha256": hashlib.sha256(staged["nonce"].encode()).hexdigest(),
                "verify_seconds": staged["verify_seconds"], "vars_sha256": staged["vars_sha256"],
                "hcl_sha256": staged["hcl_sha256"], "base_sha256": staged["base_sha256"],
                "core_member_sha256": staged["core_member_sha256"],
                "plugin_member_sha256": staged["plugin_member_sha256"], "exit_code": code,
                "oom_killed": oom, "command": "packer build -var-file=sentinel.pkrvars.hcl labapp.pkr.hcl",
                "elapsed": round(own["exit_seen_at"] - own["started_at"], 2)}
    result["evidence"] = evidence
    work = os.path.join(out, "work")
    raw = {"build.out": read_step(out, "build.out"), "build.err": read_step(out, "build.err"),
           "witness": read_step(out, "witness", 256), "steps": read_step(out, "steps"),
           "armed.json": read_step(work, "armed.json", RESULT_CAP),
           "verified.json": read_step(work, "verified.json", RESULT_CAP),
           "armed.failed": read_step(work, "armed.json.failed", RESULT_CAP)}
    for name, data in raw.items():
        if data is not None:
            evidence[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            if name in ("build.out", "build.err", "steps"):
                evidence[name]["excerpt"] = data[:EXCERPT].decode("ascii", "replace")
    if live:
        return                 # evidence only; no acceptance or mutation of live output
    if not marker_absent(work, "armed.json.failed"):
        result["reason"] = "observer_failed"
        return
    artifact = os.path.join(work, "out", "labapp.qcow2")
    try:
        handle, info = stage_tools.open_regular(artifact, stage_tools.ARTIFACT_LIMIT)
        handle.close()
        evidence["artifact"] = {"bytes": info.st_size, "disposal": "owned_workspace_cleanup"}
    except (OSError, stage_tools.StageError):
        pass                    # optional partial output; never follow aliases or unlink it here
    missing = sorted(n for n in ("build.out", "build.err", "witness") if raw[n] is None)
    if missing:
        evidence["invalid_files"] = missing
        result["reason"] = "invalid_step_evidence"
        return
    if oom or code not in EXPECTED_EXIT:
        result["reason"] = "unexpected_exit"
        return
    if not marker_absent(work, "verified.json"):
        result["reason"] = "unexpected_success_marker"
        return
    if not marker_absent(out, "steps"):
        result["reason"] = "build_completed_before_expiry"
        return
    match = START_WITNESS_RE.fullmatch(raw["witness"].decode("ascii", "replace"))
    n, t = (int(match.group(1)), int(match.group(2))) if match else (0, 0)
    if not match or t != own["deadline"] - n - 1 - KILL_AFTER or t < MIN_TIMER or n < int(own["started_at"]) - 1:
        result["reason"] = "no_timer_witness"
        return
    if own["exit_seen_at"] < n + t:
        result["reason"] = "exited_before_timer"
        return
    if raw["armed.json"] is None:
        result["reason"] = "missing_armed_witness"
        return
    if not _armed_valid(raw["armed.json"], staged, n, t, own["boot_id"]):
        result["reason"] = "invalid_or_short_armed_witness"
        return
    def evidence_checkpoint():
        # Work already ended; immutable reads use the original cleanup allocation,
        # retaining 60 seconds for exact container/workspace cleanup. No renewal.
        if own["cancelled"]:
            raise Cancelled()
        if clock() >= budget.deadline - 60:
            raise Expired()
    try:
        intact = stage_tools.verify_staged(own["workspace"], staged, evidence_checkpoint)
    except (OSError, stage_tools.StageError):
        intact = False
    if not intact:
        result["reason"] = "staged_inputs_changed"
        return
    result["outcome"], result["reason"] = "accepted", None
    result["exit_code"], result["proof"] = code, "expected_expiry"


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
    # Workspace absence is part of cleanup, before durable capacity release.
    if own["workspace"] and release:
        try:
            shutil.rmtree(own["workspace"])
            if os.path.lexists(own["workspace"]):
                raise OSError("workspace still exists")
            result["workspace"] = "removed"
        except Exception:
            release = False
            result["outcome"], result["reason"] = "hold", "workspace_cleanup_failed"
    if own["workspace"] and result.get("workspace") != "removed":
        result["workspace"] = "retained"
        result["workspace_path"] = own["workspace"]
    if own["cancelled"] or clock() >= budget.deadline:
        if result["outcome"] == "accepted":
            result["outcome"], result["reason"] = "failed", "cancelled" if own["cancelled"] else "deadline_exceeded"
    try:
        published_acceptance = result["outcome"] == "accepted"
        ledger.write("released" if release else "hold", outcome=result["outcome"], reason=result["reason"])
        # Publication itself can be slow/interrupted. Revoke acceptance and
        # durable release if its bound was crossed during that write.
        if published_acceptance and (own["cancelled"] or clock() >= budget.deadline):
            result["outcome"], result["reason"] = "hold", "publication_interrupted"
            ledger.write("hold", outcome="hold", reason=result["reason"])
    except OSError:
        result["outcome"], result["reason"] = "hold", "ledger_write_failed"
        ledger.write("hold", outcome="hold", reason=result["reason"])
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
            for args in (["stop", f"--timeout={STOP_GRACE}", ident], ["rm", "-f", ident]):
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
    p.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    p.add_argument("--execute", action="store_true", help="contact Docker (default: print plan only)")
    p.add_argument("--mode", choices=MODES, default="probe", help="fixed task (default: probe)")
    for key in ("core", "plugin", "base"):
        p.add_argument(f"--{key}-file", help=f"hcl-check: pinned {key} input file (absolute path)")
    p.add_argument("--archive-file", help="fixture/qemu-fixture: caller-supplied pinned hhfab release archive (absolute path)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse(sys.argv[1:] if argv is None else argv)
    if not HOST_RE.fullmatch(args.docker_host) \
            or not PATH_RE.match(args.workspace_root) or not PATH_RE.match(args.ledger_dir):
        print("invalid docker, host or path argument", file=sys.stderr)
        return EXIT["usage"]
    files = {key: getattr(args, f"{key}_file") for key in ("core", "plugin", "base")}
    control = args.mode == "control-build"
    if control and any(files.values()):
        print("control-build takes only --archive-file", file=sys.stderr)
        return EXIT["usage"]
    if control:
        files = {}
    if args.mode in ("fixture", "qemu-fixture", "control-build"):
        files["archive"] = args.archive_file
    elif args.archive_file is not None:
        print("--archive-file is only for --mode fixture, qemu-fixture or control-build", file=sys.stderr)
        return EXIT["usage"]
    if args.mode not in STAGED_MODES and not control and any(files.values()):
        print("input files are only for --mode hcl-check, sentinel, sentinel-expiry, fixture or qemu-fixture",
              file=sys.stderr)
        return EXIT["usage"]
    if (args.mode in STAGED_MODES or control) and not all(f and PATH_RE.match(f) for f in files.values()):
        print(f"{args.mode} requires "
              + ("safe absolute --archive-file" if control else "safe absolute --core-file, --plugin-file and --base-file"
                 + (" and --archive-file" if args.mode in ("fixture", "qemu-fixture") else "")), file=sys.stderr)
        return EXIT["usage"]
    if args.mode in VM_MODES and args.execute:
        try:
            require_runtime(args.mode)     # before Docker config, staging or any daemon contact
        except ValueError as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return EXIT["usage"]
    image = (PREPARED_RUNTIME["image_id"] if args.mode in ("runtime-check", "control-build") else
             ((EXPIRY_RUNTIME if args.mode == "sentinel-expiry" else SENTINEL_RUNTIME)
              or PREPARED_RUNTIME)["image_id"] if args.mode in VM_MODES else PINNED_IMAGE)
    if not args.execute:
        plan = create_args("labapp-probe-<uuid>", "labapp.probe.run=<uuid>", "<image id>",
                           "<uid>:<gid>", args.workspace_root + "/labapp-probe-<uuid>", "<deadline boottime>",
                           mode=args.mode)
        print(json.dumps({"mode": args.mode, "executed": False, "image": image, "create": plan,
                          "network": "bridge" if args.mode in NETWORKED_MODES else "none",
                          "runtime_accepted": (EXPIRY_RUNTIME if args.mode == "sentinel-expiry"
                                               else SENTINEL_RUNTIME) is not None if args.mode in VM_MODES else None}))
        return 0
    try:
        config = os.path.join(args.ledger_dir, "docker-config")     # empty: no helpers/credentials
        check_private_dir(args.ledger_dir, os.getuid(), "ledger dir")
        os.makedirs(config, mode=0o700, exist_ok=True)
        check_private_dir(config, os.getuid(), "docker config")
        with os.scandir(config) as entries:
            if next(entries, None) is not None:
                raise ValueError("Docker config must be empty")
        result = run_probe(image, args.workspace_root, args.ledger_dir,
                           Backend(host=args.docker_host, config=config), handle_signals=True,
                           mode=args.mode, sources=files if args.mode in STAGED_MODES or control else None)
    except (ValueError, OSError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT["usage"]
    print(json.dumps(result))
    return EXIT[result["outcome"]]


if __name__ == "__main__":
    sys.exit(main())
