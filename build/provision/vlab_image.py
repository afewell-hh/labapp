#!/usr/bin/python3
"""Guest-side PRIVATE candidate image preparation and clone-boot VLAB start (issue #526).

Ubuntu 24.04 / Python 3.12, stdlib only, root only. Three fixed actions:

  prepare      explicit opt-in; validates the finished full-core trial, then removes ONLY the
               fixed table of trial-owned files and installs the clone-start unit.
  verify       read-only report of the sealed postconditions.
  clone-start  run by labapp-vlab-clone.service on a NEW boot; delegates to the unchanged
               ``vlab_core.py start-resume`` (fresh operation, deadline and boot binding).

It never stops or captures a VM, never calls a cloud API, never runs ``init``, never touches
/home/ubuntu/hhfab or its cache (the preserved lab state) and never deletes a file it cannot
prove the trial created. Importing this module performs no IO. Messages are fixed literals:
no path, credential, argv or process output is ever printed or recorded.
"""
from __future__ import annotations

import argparse
import calendar
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

TRIAL = Path('/var/lib/labapp-vlab-trial')
TRIAL_UNIT = 'labapp-vlab-trial.service'
UNITS = Path('/etc/systemd/system')
RUNTIME_DROPIN = Path('/run/systemd/system') / (TRIAL_UNIT + '.d')
LIB = Path('/usr/local/lib/labapp')
SEAL = Path('/var/lib/labapp-vlab-image')
RECEIPT = 'seal.json'
CLONE_START = 'clone-start.json'
CLONE_UNIT = 'labapp-vlab-clone.service'
RESUME_UNIT, FRESH_UNIT = 'hhfab-vlab-resume.service', 'labapp-vlab-fresh.service'
CGROUP = Path('/sys/fs/cgroup/system.slice')
HOME, ROOT_HOME = Path('/home'), Path('/root')
PYTHON, SYSTEMCTL = '/usr/bin/python3', '/usr/bin/systemctl'
ENV = {'PATH': '/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root',
       'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
OWNER = 0  # root; tests patch this to the fixture owner
FORBIDDEN_EXE = ('/usr/bin/qemu-system-x86_64', '/usr/local/bin/hhfab')
DOCKER_CONFIG = Path('/run/labapp-vlab-docker')
# Same fallback registry stores the trial refused (vlab_trial.auth_fallbacks_absent), plus root's.
CREDENTIAL_FALLBACKS = tuple(Path(p) for p in (
    '/home/ubuntu/.docker/config.json', '/home/ubuntu/.dockercfg',
    '/home/ubuntu/.config/containers/auth.json', '/root/.docker/config.json'))
SUCCESS = {'origin': 'worker', 'phase': 'persistence', 'operation': 'complete',
           'category': 'none', 'child_status': None}  # == vlab_trial.SUCCESS (a test compares)
MAX_FILE = 65536
CORE_WAIT = 1000  # > vlab_core.START_SECONDS['resume'] (900) plus its own bounded cleanup

# ---- Fixed sealing manifest: the ONLY names this command may remove from the trial root ----
# Derived from vlab_trial.py: SOURCES/PAYLOADS/FILES, the guardian/worker/core receipts, the
# transient-auth bookkeeping (credentials themselves live only on /run tmpfs) and *.next / .new
# atomic-write temporaries. Anything else in the root is foreign: refuse, never delete.
_SOURCE_NAMES = (
    'vlab_trial.py', 'labapp-vlab-trial.service', 'vlab_core.py', 'owned_process.py',
    'ensure-bridge-ipv4.py', 'journald@labapp-vlab.conf', 'labapp-vlab-fresh.service',
    'hhfab-vlab-resume.service', 'install-qemu.py', 'qemu_offline.py', 'qemu_acquire.py',
    'prepare-qemu-offline.sh', 'install-docker.py', 'install-hhfab.py', 'hhfab_release.py',
    'install-kubectl.py', 'wiringd.yaml', 'hhfab.tar.gz', 'kubectl', 'fab.yaml')
_STATE_NAMES = (
    'phase.json', 'heartbeat.json', 'measurements.json', 'nonce-receipt.json', 'worker-status.json',
    'result.json', 'installer-failure.json')
_RECEIPT_NAMES = (
    'started.json', 'success.json', 'account-intent.json', 'account-receipt.json',
    'daemon-intent.json', 'docker-receipt.json', 'aux-intent.json', 'aux-receipt.json',
    'packages.json', 'core-contract.json', 'prestart-observation.json', 'offline-images.json',
    'VPC.json', 'VPCAttachment.json', 'install-qemu.py.receipt', 'install-docker.py.receipt',
    'install-hhfab.py.receipt', 'install-kubectl.py.receipt')
_AUTH_NAMES = (
    'auth.lock', 'auth-intent.json', 'auth-bound.json', 'auth-ready.json', 'auth-removed.json',
    'auth-closed.json', 'auth-file.json', 'auth-unlinked.json', 'auth-directory-removed.json',
    'auth-guardian.json')
# Removed last, so a rerun after an interruption can still validate the terminal result.
TERMINAL = ('success.json', 'worker-status.json', 'result.json', 'started.json',
            'manifest.json', 'contract.json')
OWNED_NAMES = frozenset((*_SOURCE_NAMES, *_STATE_NAMES, *_RECEIPT_NAMES, *_AUTH_NAMES, *TERMINAL,
                         *(n + s for n in ('phase', 'heartbeat', 'measurements', 'nonce-receipt',
                                           'worker-status', 'result') for s in ('.json.next',)),
                         'installer-failure.json.new'))
PYCACHE = '__pycache__'
PYC = re.compile(r'[a-z_]{1,40}\.cpython-3[0-9]{1,2}\.pyc')
DROPIN_BODY = re.compile(rb'\[Service\]\nRuntimeMaxSec=[0-9]{1,5}\n')

# Access material is reported, never removed: its ownership was never established because the
# pre-login hook is inventory-only (build/gcp/prelogin/hook.py SUPPORTED_MANIFESTS is empty).
KEY_NAMES = ('authorized_keys', 'authorized_keys2', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519')
OSLOGIN_CACHES = (Path('/etc/oslogin_passwd.cache'), Path('/etc/oslogin_group.cache'))
UNMET_ACCESS = 'access-material-provenance'

RECEIPT_FIELDS = {'schema', 'state', 'nonce', 'lease', 'source_sha', 'tool_sha256', 'build_boot',
                  'sealed_at', 'core_operation', 'core_invocation', 'trial_unit_sha256',
                  'evidence', 'removed', 'access', 'unmet', 'owned_sealed'}
HEX32, HEX40, HEX64 = '[0-9a-f]{32}', '[0-9a-f]{40}', '[0-9a-f]{64}'
UUID = '[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}'


class Refused(Exception):
    """Fixed nonsecret refusal."""


def require(ok, message='image preparation refused'):
    if not ok:
        raise Refused(message)


def pairs(items):
    out = {}
    for key, value in items:
        require(key not in out, 'duplicate JSON field')
        out[key] = value
    return out


def parse(raw):
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: require(False, 'JSON constant refused'))
    except (ValueError, RecursionError):
        raise Refused('JSON refused') from None


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def kernel_boot():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def no_links(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'unsafe path')
    for part in (*reversed(path.parents), path):
        require(not part.is_symlink(), 'symlink refused')
    return path


def owned_regular(info):
    return stat.S_ISREG(info.st_mode) and info.st_uid == OWNER and info.st_nlink == 1


def private_file(path, limit=MAX_FILE, mode=0o600):
    """Bounded read of an owned, single-link, exact-mode regular file; never follows links."""
    path = no_links(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(owned_regular(info) and stat.S_IMODE(info.st_mode) == mode and info.st_size <= limit,
                'file type/owner/mode refused')
        raw = b''
        while len(raw) <= limit:
            chunk = os.read(fd, limit + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
        require(len(raw) == info.st_size, 'file changed')
        return raw
    finally:
        os.close(fd)


def atomic(path, value):
    temporary = Path(str(path) + '.next')
    fd = os.open(no_links(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(encoded(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def run(argv, seconds):
    """Fixed argv, fixed environment, no stdin, output capped and discarded by callers."""
    try:
        done = subprocess.run(argv, env=ENV, stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=seconds, check=False)
    except subprocess.TimeoutExpired:
        raise Refused('child timeout') from None
    return done.returncode, done.stdout[:65536]


def unit_fields(name, *properties):
    code, out = run([SYSTEMCTL, 'show', name, *[f'--property={p}' for p in properties]], 15)
    require(code == 0, 'service query refused')
    fields = pairs([line.split('=', 1) for line in out.decode().splitlines() if '=' in line])
    require(set(fields) == set(properties), 'service query refused')
    return fields


def load_core():
    """Load the installed, already hash-pinned core module. No bytecode is written."""
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(LIB))
    spec = importlib.util.spec_from_file_location('labapp_image_core', LIB / 'vlab_core.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------- build-result binding ------
def bound_arguments(args):
    require(args.private_candidate is True, 'explicit private-candidate opt-in required')
    require(re.fullmatch(HEX40, args.source_sha) and re.fullmatch(HEX32, args.nonce)
            and re.fullmatch(UUID, args.lease) and re.fullmatch(UUID, args.build_boot)
            and re.fullmatch(HEX64, args.tool_sha256), 'binding arguments refused')


def trial_records(args):
    """Validate the finished full-core terminal result against the exact operator binding."""
    contract = parse(private_file(TRIAL / 'contract.json'))
    fields = {'schema', 'nonce', 'lease', 'epoch', 'run_id', 'attempt', 'body_sha256', 'vm_id',
              'boot_id', 'image_id', 'admitted_at', 'deadline', 'boot_uuid', 'source_sha'}
    require(type(contract) is dict and set(contract) == fields and contract['schema'] == 1
            and contract['nonce'] == args.nonce and contract['lease'] == args.lease
            and contract['source_sha'] == args.source_sha and contract['boot_uuid'] == args.build_boot,
            'contract binding refused')
    require(kernel_boot() == args.build_boot, 'not the build boot')
    try:
        deadline = calendar.timegm(time.strptime(contract['deadline'], '%Y-%m-%dT%H:%M:%SZ'))
    except (TypeError, ValueError):
        raise Refused('contract deadline refused') from None
    require(time.time() < deadline, 'original build deadline passed')  # no renewal, no new authority
    table = parse(private_file(TRIAL / 'manifest.json'))
    require(type(table) is dict and table.get('source_sha') == args.source_sha, 'manifest binding refused')
    started = parse(private_file(TRIAL / 'started.json'))
    require(type(started) is dict and started.get('boot') == args.build_boot
            and started.get('lease') == args.lease and started.get('nonce') == args.nonce,
            'guardian binding refused')
    result_raw = private_file(TRIAL / 'result.json')
    require(parse(result_raw) == {'schema': 2, 'code': 0, 'contained': True, 'nonce': args.nonce,
                                  'diagnostic': SUCCESS}, 'terminal result is not a contained success')
    status_raw = private_file(TRIAL / 'worker-status.json')
    status = parse(status_raw)
    require(type(status) is dict and set(status) == {'schema', 'nonce', 'seq', 'state', 'phase',
            'operation', 'code', 'diagnostic'} and status['schema'] == 1 and status['nonce'] == args.nonce
            and status['state'] == 'succeeded' and status['code'] == 0
            and (status['phase'], status['operation']) == ('persistence', 'complete')
            and status['diagnostic'] == SUCCESS, 'worker status is not a success')
    success_raw = private_file(TRIAL / 'success.json')
    success = parse(success_raw)
    require(type(success) is dict and set(success) == {'schema', 'nonce', 'cluster'}
            and success['schema'] == 1 and success['nonce'] == args.nonce
            and type(success['cluster']) is dict, 'success record refused')
    return {'result_sha256': sha(result_raw), 'worker_status_sha256': sha(status_raw),
            'success_sha256': sha(success_raw)}


# --------------------------------------------------------------------- offline proofs -------
def live_vlab_processes():
    """True if any QEMU or hhfab image is running; uncertainty is a refusal."""
    for entry in os.scandir('/proc'):
        if not entry.name.isdigit():
            continue
        try:
            target = os.readlink(f'/proc/{entry.name}/exe')
        except (FileNotFoundError, ProcessLookupError):
            continue  # exited, zombie or kernel thread
        except OSError:
            raise Refused('process table uncertain') from None
        if target.removesuffix(' (deleted)') in FORBIDDEN_EXE:
            return True
    return False


def cgroup_empty(unit):
    events = CGROUP / unit / 'cgroup.events'
    if not os.path.lexists(events):
        return True
    rows = dict(line.split() for line in events.read_text().splitlines() if line.strip())
    return rows.get('populated') == '0'


def units_offline():
    require(not live_vlab_processes(), 'live QEMU/hhfab process present')
    for unit in (FRESH_UNIT, RESUME_UNIT, TRIAL_UNIT):
        fields = unit_fields(unit, 'ActiveState', 'MainPID')
        require(fields['ActiveState'] in (('inactive',) if unit == TRIAL_UNIT else ('inactive', 'failed'))
                and fields['MainPID'] == '0' and cgroup_empty(unit), 'service not offline')


def core_offline(core, nonce):
    """The exact preserved-state conditions the core's own resume gate demands, read-only."""
    deadline = time.monotonic() + 900
    with core.locked():
        value = core.state()
    require(value['nonce'] == nonce and value['phase'] == 'resumable' and value['mode'] == 'resume'
            and value.get('stop_verified') == {'operation': value.get('operation'),
                                               'invocation': value.get('invocation')}
            and 'critical' in value and 'cluster' in value, 'core state is not a verified offline stop')
    core.verify_contract(value, deadline)
    require(core.critical_snapshot(deadline) == value['critical'], 'preserved VLAB state changed')
    return value


def credentials_absent():
    require(not os.path.lexists(DOCKER_CONFIG), 'transient registry credential present')
    for path in CREDENTIAL_FALLBACKS:
        require(not os.path.lexists(path), 'fallback registry credential store present')


def access_inventory():
    """Metadata-only counts. Nothing here is deleted or claimed as ours."""
    keys = homes = 0
    try:
        entries = [e for e in os.scandir(HOME) if e.is_dir(follow_symlinks=False)]
    except FileNotFoundError:
        entries = []
    for entry in entries:
        homes += entry.name != 'ubuntu'
    roots = [ROOT_HOME, *(Path(e.path) for e in entries)]
    for base in roots:
        for name in KEY_NAMES:
            keys += os.path.lexists(base / '.ssh' / name)
        keys += os.path.lexists(base / '.google_authenticator')
    caches = sum(1 for p in OSLOGIN_CACHES if os.path.lexists(p) and p.lstat().st_size > 0)
    status = 'absent' if not (keys or homes or caches) else 'unproven'
    return {'status': status, 'key_files': keys, 'other_home_dirs': homes, 'oslogin_caches': caches}


# ------------------------------------------------------------------- owned trial state ------
def trial_inventory():
    """Names present in the trial root; any foreign shape refuses before anything is removed."""
    no_links(TRIAL)
    info = TRIAL.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == OWNER and stat.S_IMODE(info.st_mode) == 0o700,
            'trial root refused')
    files, cache = [], []
    with os.scandir(TRIAL) as entries:
        for entry in entries:
            require(len(files) < 128, 'trial root too large')
            info = entry.stat(follow_symlinks=False)
            if entry.name == PYCACHE:
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == OWNER
                        and not info.st_mode & 0o022, 'foreign trial entry')
                with os.scandir(entry.path) as inner:
                    for item in inner:
                        require(len(cache) < 64 and PYC.fullmatch(item.name)
                                and owned_regular(item.stat(follow_symlinks=False)), 'foreign trial entry')
                        cache.append(item.name)
            else:
                require(entry.name in OWNED_NAMES and owned_regular(info), 'foreign trial entry')
                files.append(entry.name)
    return sorted(files), sorted(cache)


def remove_trial(files, cache):
    """Unlink only the inventoried names through a pinned directory descriptor."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(TRIAL, flags)
    try:
        for name in [n for n in files if n not in TERMINAL]:
            require(owned_regular(os.stat(name, dir_fd=fd, follow_symlinks=False)), 'foreign trial entry')
            os.unlink(name, dir_fd=fd)
        if cache:
            cfd = os.open(PYCACHE, flags, dir_fd=fd)
            try:
                for name in cache:
                    require(owned_regular(os.stat(name, dir_fd=cfd, follow_symlinks=False)),
                            'foreign trial entry')
                    os.unlink(name, dir_fd=cfd)
            finally:
                os.close(cfd)
            os.rmdir(PYCACHE, dir_fd=fd)
        for name in [n for n in TERMINAL if n in files]:
            require(owned_regular(os.stat(name, dir_fd=fd, follow_symlinks=False)), 'foreign trial entry')
            os.unlink(name, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(TRIAL)  # fails if anything foreign appeared meanwhile; nothing else is touched


def remove_trial_unit(expected_sha):
    path = UNITS / TRIAL_UNIT
    if not os.path.lexists(path):
        return
    info = no_links(path).lstat()
    require(owned_regular(info) and stat.S_IMODE(info.st_mode) == 0o644
            and sha(path.read_bytes()) == expected_sha, 'trial unit is not the installed copy')
    path.unlink()
    bound = dropin_file()
    if bound is not None:
        bound.unlink()
        RUNTIME_DROPIN.rmdir()


def dropin_file():
    """The bootstrap's exact volatile RuntimeMaxSec drop-in, or None; anything else refuses."""
    if not os.path.lexists(RUNTIME_DROPIN):
        return None
    no_links(RUNTIME_DROPIN)
    require(sorted(p.name for p in RUNTIME_DROPIN.iterdir()) == ['10-bound.conf'], 'foreign runtime drop-in')
    bound = RUNTIME_DROPIN / '10-bound.conf'
    require(owned_regular(bound.lstat()) and DROPIN_BODY.fullmatch(bound.read_bytes()),
            'foreign runtime drop-in')
    return bound


def install_conflict(target, raw):
    """True when identical bytes are already installed; a different file refuses (no overwrite)."""
    no_links(target)
    if os.path.lexists(target):
        require(owned_regular(target.lstat()) and target.read_bytes() == raw, 'installation conflict')
        return True
    return False


def install_exact(target, raw, mode):
    """Create exactly these bytes or accept identical existing bytes; never overwrite."""
    if install_conflict(target, raw):
        return
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    os.fchmod(fd, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def owned_absent():
    """Checkable postconditions for the trial-owned portion."""
    require(not os.path.lexists(TRIAL) and not os.path.lexists(UNITS / TRIAL_UNIT)
            and not os.path.lexists(RUNTIME_DROPIN), 'trial state remains')
    credentials_absent()
    require(unit_fields(TRIAL_UNIT, 'LoadState')['LoadState'] == 'not-found', 'trial unit still loaded')
    code, out = run([SYSTEMCTL, 'is-enabled', RESUME_UNIT], 15)
    require(out.strip() == b'disabled', 'resume unit must not be boot-enabled')
    code, out = run([SYSTEMCTL, 'is-enabled', CLONE_UNIT], 15)
    require(code == 0 and out.strip() == b'enabled', 'clone unit not enabled')
    fields = unit_fields(CLONE_UNIT, 'FragmentPath', 'NeedDaemonReload', 'DropInPaths')
    require(fields == {'FragmentPath': str(UNITS / CLONE_UNIT), 'NeedDaemonReload': 'no', 'DropInPaths': ''},
            'clone unit not loaded as installed')


# -------------------------------------------------------------------------- receipt ---------
def load_receipt():
    raw = private_file(SEAL / RECEIPT, 16384)
    value = parse(raw)
    require(type(value) is dict and set(value) == RECEIPT_FIELDS and value['schema'] == 1
            and value['state'] in ('sealing', 'sealed') and type(value['owned_sealed']) is bool
            and re.fullmatch(HEX32, value['nonce']) and re.fullmatch(UUID, value['lease'])
            and re.fullmatch(HEX40, value['source_sha']) and re.fullmatch(HEX64, value['tool_sha256'])
            and re.fullmatch(HEX64, value['trial_unit_sha256']) and re.fullmatch(UUID, value['build_boot'])
            and re.fullmatch(HEX32, value['core_operation']) and re.fullmatch(HEX32, value['core_invocation'])
            and value['owned_sealed'] == (value['state'] == 'sealed'), 'seal receipt refused')
    return value


def seal_directory():
    no_links(SEAL.parent)
    if not os.path.lexists(SEAL):
        SEAL.mkdir(mode=0o700)
    info = no_links(SEAL).lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == OWNER and stat.S_IMODE(info.st_mode) == 0o700,
            'seal directory refused')


# --------------------------------------------------------------------------- prepare -------
def prepare(args):
    require(os.geteuid() == OWNER, 'root required')
    bound_arguments(args)
    own = Path(__file__).resolve()
    tool = own.read_bytes()
    require(sha(tool) == args.tool_sha256, 'tool hash differs from the operator binding')
    unit_raw = (own.parent / CLONE_UNIT).read_bytes()
    existing = None
    if os.path.lexists(SEAL / RECEIPT):
        existing = load_receipt()
        require(existing['state'] == 'sealing' and (existing['nonce'], existing['lease'],
                existing['source_sha'], existing['tool_sha256'], existing['build_boot']) ==
                (args.nonce, args.lease, args.source_sha, args.tool_sha256, args.build_boot),
                'already sealed or receipt binding differs')
    core = load_core()
    require(core.boot() == args.build_boot, 'not the build boot')
    resumed = existing is not None and not os.path.lexists(TRIAL)
    if resumed:
        evidence, files, cache = existing['evidence'], [], []
        trial_sha = existing['trial_unit_sha256']
    else:
        evidence = trial_records(args)
        files, cache = trial_inventory()
        trial_sha = sha(private_file(TRIAL / TRIAL_UNIT))  # the root copy bootstrap installed
        installed = UNITS / TRIAL_UNIT
        require((not existing or existing['trial_unit_sha256'] == trial_sha)
                and (not os.path.lexists(installed) or sha(installed.read_bytes()) == trial_sha),
                'trial unit differs from its root copy')
    units_offline()
    credentials_absent()
    state = core_offline(core, args.nonce)
    require(unit_fields(RESUME_UNIT, 'LoadState')['LoadState'] == 'loaded')
    code, out = run([SYSTEMCTL, 'is-enabled', RESUME_UNIT], 15)
    require(out.strip() in (b'enabled', b'disabled'), 'resume enablement uncertain')
    if existing:
        require((existing['core_operation'], existing['core_invocation']) ==
                (state['operation'], state['invocation']), 'core state differs from the seal intent')
    install_conflict(LIB / 'vlab_image.py', tool)  # every refusal happens before any mutation
    install_conflict(UNITS / CLONE_UNIT, unit_raw)
    dropin_file()
    # ---- all checks passed; mutation order keeps evidence first and terminal records last ----
    access = access_inventory()
    seal_directory()
    receipt = {'schema': 1, 'state': 'sealing', 'nonce': args.nonce, 'lease': args.lease,
               'source_sha': args.source_sha, 'tool_sha256': args.tool_sha256,
               'build_boot': args.build_boot, 'sealed_at': int(time.time()),
               'core_operation': state['operation'], 'core_invocation': state['invocation'],
               'trial_unit_sha256': trial_sha, 'evidence': evidence, 'removed': sorted(files + cache),
               'access': access, 'unmet': [], 'owned_sealed': False}
    if existing:
        receipt['sealed_at'], receipt['removed'] = existing['sealed_at'], existing['removed']
    atomic(SEAL / RECEIPT, receipt)
    LIB.mkdir(mode=0o755, exist_ok=True)
    install_exact(LIB / 'vlab_image.py', tool, 0o644)
    install_exact(UNITS / CLONE_UNIT, unit_raw, 0o644)
    if not resumed:
        remove_trial(files, cache)
    remove_trial_unit(trial_sha)
    for argv in ([SYSTEMCTL, 'daemon-reload'], [SYSTEMCTL, 'disable', RESUME_UNIT],
                 [SYSTEMCTL, 'enable', CLONE_UNIT]):
        require(run(argv, 30)[0] == 0, 'service enablement refused')
    owned_absent()
    receipt.update(state='sealed', owned_sealed=True, access=access_inventory())
    receipt['unmet'] = [UNMET_ACCESS] if receipt['access']['status'] != 'absent' else []
    atomic(SEAL / RECEIPT, receipt)
    report(receipt)
    return 0 if not receipt['unmet'] else 3


def report(receipt):
    print(json.dumps({'owned_sealed': receipt['owned_sealed'], 'access': receipt['access'],
                      'unmet': receipt['unmet'], 'removed_count': len(receipt['removed'])}, sort_keys=True))


def verify(_args):
    require(os.geteuid() == OWNER, 'root required')
    receipt = load_receipt()
    require(receipt['state'] == 'sealed', 'not sealed')
    owned_absent()
    receipt['access'] = access_inventory()
    receipt['unmet'] = [UNMET_ACCESS] if receipt['access']['status'] != 'absent' else []
    report(receipt)
    return 0 if not receipt['unmet'] else 3


# ----------------------------------------------------------------------- clone start -------
def clone_start(_args):
    """New-boot start. Receives no lease, nonce, deadline or boot from the build; it only
    checks that the CURRENT boot differs and lets the core mint its own fresh operation."""
    require(os.geteuid() == OWNER, 'root required')
    receipt = load_receipt()
    require(receipt['state'] == 'sealed' and receipt['owned_sealed'] is True, 'image is not sealed')
    boot = kernel_boot()
    require(boot != receipt['build_boot'], 'not a new boot')
    core = load_core()
    require(core.boot() == boot, 'boot identity differs')
    owned_absent()
    units_offline()
    value = core_offline(core, receipt['nonce'])
    require(value['boot'] != boot and (value['operation'], value['invocation']) ==
            (receipt['core_operation'], receipt['core_invocation']), 'preserved core state is not the sealed one')
    try:
        code, _ = run([PYTHON, str(LIB / 'vlab_core.py'), 'start-resume'], CORE_WAIT)
    except Refused:
        run([PYTHON, str(LIB / 'vlab_core.py'), 'stop'], 70)  # bounded, ownership-checked by the core
        raise
    require(code == 0, 'core resume refused')
    with core.locked():
        after = core.state()
    require(after['nonce'] == receipt['nonce'] and after['phase'] == 'ready' and after['mode'] == 'resume'
            and after['boot'] == boot and after['operation'] != receipt['core_operation']
            and after.get('invocation') not in (None, receipt['core_invocation']),
            'resume did not reach readiness on this boot')
    atomic(SEAL / CLONE_START, {'schema': 1, 'boot': boot, 'operation': after['operation'],
                                'invocation': after['invocation']})
    print('vlab-image: ready on a new boot')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('action', choices=('prepare', 'verify', 'clone-start'))
    parser.add_argument('--private-candidate', action='store_true')
    parser.add_argument('--source-sha')
    parser.add_argument('--nonce')
    parser.add_argument('--lease')
    parser.add_argument('--build-boot')
    parser.add_argument('--tool-sha256')
    args = parser.parse_args(argv)
    bindings = (args.source_sha, args.nonce, args.lease, args.build_boot, args.tool_sha256)
    require((args.action == 'prepare') == args.private_candidate
            and (args.action == 'prepare') == all(v is not None for v in bindings)
            and (args.action == 'prepare' or all(v is None for v in bindings)), 'invalid arguments')
    os.umask(0o077)
    return {'prepare': prepare, 'verify': verify, 'clone-start': clone_start}[args.action](args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Refused as error:
        print('vlab-image: refused: ' + str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('vlab-image: operational failure', file=sys.stderr)
        sys.exit(1)
