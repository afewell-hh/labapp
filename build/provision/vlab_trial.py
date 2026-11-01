#!/usr/bin/env python3
"""Fixed disposable canonical trial, Ubuntu 24.04 amd64 Python 3.12.

Root bootstrap/guardian/worker; never an installer or arbitrary command loader.
No environment/cwd configuration. Execute only on the dedicated, authenticated
guest after separately accepted source and live scope. All mutable state stays
root-private. The unmodified component installers and corrected VLAB core are
required siblings. Importing this module performs no IO or privileged action.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import fcntl
import grp
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import stat
import subprocess
import sys
import time

ROOT = Path('/var/lib/labapp-vlab-trial')
UNIT = 'labapp-vlab-trial.service'
UNIT_PATH = Path('/etc/systemd/system') / UNIT
UNIT_BASES = tuple(Path(p) for p in ('/etc/systemd/system', '/run/systemd/system',
                                    '/usr/local/lib/systemd/system', '/usr/lib/systemd/system'))
RUNTIME_DROPIN = Path('/run/systemd/system') / (UNIT + '.d')
PYTHON = '/usr/bin/python3'
SYSTEMCTL = '/usr/bin/systemctl'
ENV = {'PATH': '/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root',
       'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'DEBIAN_FRONTEND': 'noninteractive'}
GIB = 1024**3
# Absolute cutoffs from durable admission. No duration input or renewal.
PHASES = {'access': 15, 'stage': 35, 'fresh': 70, 'strict': 80,
          'resume': 95, 'persistence': 105}
SOURCES = {
    name: 'build/provision/' + name for name in (
        'vlab_trial.py', 'labapp-vlab-trial.service', 'vlab_core.py', 'owned_process.py',
        'ensure-bridge-ipv4.py', 'journald@labapp-vlab.conf',
        'labapp-vlab-fresh.service', 'hhfab-vlab-resume.service',
        'install-qemu.py', 'qemu_offline.py', 'qemu_acquire.py',
        'prepare-qemu-offline.sh', 'install-docker.py', 'install-hhfab.py',
        'hhfab_release.py', 'install-kubectl.py')}
SOURCES['wiringd.yaml'] = 'wiringd.yaml'
PAYLOADS = {
    'hhfab.tar.gz': (93055151, 'b1387342191a329772c2595504ec6ff129eb45980727c1c86d9901ef4d9f37a4'),
    'kubectl': (58597560, 'a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989')}
FILES = {*SOURCES, *PAYLOADS, 'fab.yaml', 'contract.json'}
MAX_TOTAL = 160 * 1024**2  # transfer table, separate from 160GiB guest cache cap
MAX_SOURCE = 256 * 1024
AUX = ('sudo', 'socat', 'openssh-client', 'less', 'iproute2', 'systemd',
       'kmod', 'procps', 'python3-minimal', 'python3-yaml', 'ca-certificates',
       'curl', 'ubuntu-keyring', 'gpgv')
AUX_SNAPSHOT = '20261024T000000Z'
APT_TMP = Path('/var/tmp')


class Failure(Exception):
    """Fixed nonsecret refusal. category/child_status feed the closed diagnostic."""
    def __init__(self, message='fixed trial refused', code=1, category='policy', child_status=None):
        super().__init__(message)
        # A process exit status is 1..255; anything else cannot round-trip.
        self.code = code if type(code) is int and 0 < code < 256 else 1
        self.category = category
        self.child_status = child_status


def require(condition, message='fixed trial refused', category='policy'):
    if not condition:
        raise Failure(message, 1, category)


# Closed, reviewed diagnostic vocabulary (issue #364). Operations are source
# literals set BEFORE the work; no argv, path, user or resource value is ever a label.
PHASE_NAMES = ('startup', 'stage', 'fresh', 'strict', 'resume', 'persistence')
OPERATIONS = {
    'startup': ('worker-binding',),
    'stage': ('auth-check', 'account-policy', 'daemon-absent-check', 'aux-inventory', 'aux-audit', 'aux-holds',
              'aux-setup', 'aux-update', 'aux-check', 'aux-simulate', 'aux-simulate-exact',
              'aux-download', 'aux-files', 'aux-install', 'aux-postcheck', 'aux-cleanup',
              'install-qemu', 'install-docker', 'install-hhfab', 'install-kubectl', 'sudo-check',
              'daemon-start', 'docker-account', 'docker-socket', 'docker-fresh-groups',
              'docker-daemons', 'docker-access', 'kvm-device', 'tun-device', 'parser-check',
              'core-load', 'fab-validate', 'package-receipt', 'core-contract', 'resource-check',
              'core-prepare', 'prestart-audit'),
    'fresh': ('core-start-fresh', 'auth-remove'),
    'strict': ('strict-inspect', 'strict-ssh', 'api-ready', 'nonce-create'),
    'resume': ('core-stop', 'offline-audit', 'core-activate-resume', 'core-start-resume'),
    'persistence': ('strict-inspect', 'strict-ssh', 'api-ready', 'nonce-verify', 'nonce-remove',
                    'core-final-stop', 'complete')}
GUARDIAN_OPERATIONS = ('guardian-init', 'worker-spawn', 'worker-supervision')
ORIGINS = ('worker', 'guardian', 'unknown')
CATEGORIES = ('none', 'policy', 'capability', 'child-exit', 'child-signal', 'child-timeout',
              'output-overflow', 'phase-cutoff', 'heartbeat-loss', 'oom-event', 'resource-floor',
              'boot-change', 'status-invalid', 'core-refusal', 'interrupted', 'exception')
ORIGIN_CATEGORIES = {
    'worker': ('policy', 'capability', 'child-exit', 'child-signal', 'child-timeout', 'output-overflow',
               'phase-cutoff', 'resource-floor', 'status-invalid', 'core-refusal', 'interrupted', 'exception'),
    'guardian': ('policy', 'child-signal', 'phase-cutoff', 'heartbeat-loss', 'oom-event', 'resource-floor',
                 'boot-change', 'status-invalid', 'interrupted', 'exception'),
    'unknown': ('status-invalid',)}
DIAGNOSTIC_FIELDS = {'origin', 'phase', 'operation', 'category', 'child_status'}
RESULT_FIELDS = {'schema', 'code', 'contained', 'nonce', 'diagnostic'}
STATUS_FIELDS = {'schema', 'nonce', 'seq', 'state', 'phase', 'operation', 'code', 'diagnostic'}
SUCCESS = {'origin': 'worker', 'phase': 'persistence', 'operation': 'complete',
           'category': 'none', 'child_status': None}
MAX_RESULT = 4096


def child_status_ok(category, status):
    if status is None:
        return category != 'child-signal'
    if type(status) is not int:
        return False
    if category == 'child-signal':
        return -64 <= status <= -1
    if category == 'child-exit':
        return 1 <= status <= 255
    return category == 'status-invalid' and -64 <= status <= 255


def operation_ok(origin, phase, operation):
    if phase not in PHASE_NAMES or type(operation) is not str:
        return False
    if origin == 'worker':
        return operation in OPERATIONS[phase]
    if origin == 'guardian':
        return operation == 'worker-supervision' or (phase == 'startup' and operation in GUARDIAN_OPERATIONS)
    return operation == 'worker-supervision' or operation in OPERATIONS[phase]


def outcome_code_ok(code, detail):
    """Observed inner child evidence must agree with the normalized primary code.

    Null is unobserved; status-invalid carries context, not child provenance.
    """
    status = detail['child_status']
    if status is not None and detail['category'] == 'child-exit':
        return code == status
    if status is not None and detail['category'] == 'child-signal':
        return code == 128 - status
    return True


def diagnostic(value):
    """Strict closed validator; returns a fresh copy built only from vetted values."""
    require(type(value) is dict and set(value) == DIAGNOSTIC_FIELDS, 'diagnostic refused')
    origin, phase, operation = value['origin'], value['phase'], value['operation']
    category, status = value['category'], value['child_status']
    require(type(origin) is str and origin in ORIGINS and type(phase) is str
            and operation_ok(origin, phase, operation) and type(category) is str, 'diagnostic refused')
    if category == 'none':
        require(value == SUCCESS, 'diagnostic refused')
    else:
        require(category in ORIGIN_CATEGORIES[origin] and child_status_ok(category, status), 'diagnostic refused')
    return {'origin': origin, 'phase': phase, 'operation': operation, 'category': category,
            'child_status': status}


def result_record(value, nonce):
    """Schema 2 final guardian result. Success needs category none AND code 0."""
    require(type(value) is dict and set(value) == RESULT_FIELDS, 'result refused')
    code, contained = value['code'], value['contained']
    require(type(value['schema']) is int and value['schema'] == 2 and type(code) is int and 0 <= code <= 255
            and type(contained) is bool and type(value['nonce']) is str and value['nonce'] == nonce, 'result refused')
    detail = diagnostic(value['diagnostic'])
    require((code == 0) == (detail['category'] == 'none') and outcome_code_ok(code, detail), 'result refused')
    return {'schema': 2, 'code': code, 'contained': contained, 'nonce': nonce, 'diagnostic': detail}


def worker_status(value, nonce):
    """Worker-owned root-private checkpoint/terminal record."""
    require(type(value) is dict and set(value) == STATUS_FIELDS, 'status refused')
    state, phase, operation, seq = value['state'], value['phase'], value['operation'], value['seq']
    require(type(value['schema']) is int and value['schema'] == 1 and type(value['nonce']) is str
            and value['nonce'] == nonce and type(seq) is int and 0 <= seq <= 1000
            and type(state) is str and state in ('running', 'succeeded', 'failed')
            and type(phase) is str and operation_ok('worker', phase, operation), 'status refused')
    code = value['code']
    if state == 'running':
        require(code is None and value['diagnostic'] is None, 'status refused')
        detail = None
    else:
        detail = diagnostic(value['diagnostic'])
        require(detail['origin'] == 'worker' and detail['phase'] == phase
                and detail['operation'] == operation and type(code) is int, 'status refused')
        if state == 'succeeded':
            require(code == 0 and detail == SUCCESS, 'status refused')
        else:
            require(1 <= code <= 255 and detail['category'] != 'none'
                    and outcome_code_ok(code, detail), 'status refused')
    return {'schema': 1, 'nonce': nonce, 'seq': seq, 'state': state, 'phase': phase,
            'operation': operation, 'code': code, 'diagnostic': detail}


def failure_fields(error, origin):
    """Code/category/status from any exception, defensively reduced to the closed set.

    The message text, args and traceback are never read.
    """
    if isinstance(error, Failure):
        code, category, status = error.code, error.category, error.child_status
    elif isinstance(error, KeyboardInterrupt):
        code, category, status = 130, 'interrupted', None
    else:
        code, category, status = 1, 'exception', None
    if not (type(category) is str and category in ORIGIN_CATEGORIES[origin] and child_status_ok(category, status)):
        category, status = 'exception', None
    return code, category, status


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def candidate_fab(public_key, password_hash, token):
    """Pure fixed v0.43.1 nondevelopment candidate renderer, no secret creation.

    Host supplies fresh credentials; contained tests supply public fixture values.
    Core.prepare/official init+validate remain semantic authorities.
    """
    require(re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+', public_key)
            and re.fullmatch(r'\$5\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{43}', password_hash)
            and re.fullmatch('[a-f0-9]{64}', token))
    user = {'password': password_hash, 'authorizedKeys': [public_key]}
    config = {'registry': {'mode': 'airgap'}, 'control': {
        'joinToken': token, 'defaultUser': user, 'managementSubnet': '172.30.0.0/21',
        'controlVIP': '172.30.0.1/32', 'kubeClusterSubnet': '172.28.0.0/16', 'kubeServiceSubnet': '172.29.0.0/16',
        'kubeClusterDNS': '172.29.0.10', 'dummySubnet': '172.30.90.0/24'},
        'fabric': {'mode': 'spine-leaf', 'defaultSwitchUsers': {'admin': dict(user, role='admin'), 'op': dict(user, role='operator')},
        'managementDHCPStart': '172.30.4.0', 'managementDHCPEnd': '172.30.7.254', 'spineASN': 65100,
        'leafASNStart': 65101, 'leafASNEnd': 65533, 'protocolSubnet': '172.30.8.0/22', 'vtepSubnet': '172.30.12.0/22',
        'fabricSubnet': '172.30.128.0/17', 'mclagSessionSubnet': '172.30.95.0/31', 'vpcWorkaroundSubnet': '172.30.96.0/19'},
        'observability': {'defaults': ''}}
    docs = [{'apiVersion': 'fabricator.githedgehog.com/v1beta1', 'kind': 'Fabricator',
             'metadata': {'name': 'default', 'namespace': 'fab'}, 'spec': {'config': config}},
            {'apiVersion': 'fabricator.githedgehog.com/v1beta1', 'kind': 'ControlNode',
             'metadata': {'name': 'control-1', 'namespace': 'fab'}, 'spec': {'bootstrap': {'disk': '/dev/sda'},
              # Leave both management/dummy allocation to official if-not-present
              # hydration, like the v0.43.1 template; a lone IP is partial state.
              'external': {'interface': 'enp2s0', 'ip': 'dhcp'}, 'management': {'interface': 'enp2s1'}}}]
    return b'\n---\n'.join(encoded(d) for d in docs) + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, 'duplicate JSON field')
        value[key] = item
    return value


def data(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Failure()))


def stamp(value):
    moment = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    require(moment.strftime('%Y-%m-%dT%H:%M:%SZ') == value)
    return moment.timestamp()


def no_links(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts)
    for part in (*reversed(path.parents), path):
        try:
            require(not stat.S_ISLNK(part.lstat().st_mode), 'path link refused')
        except FileNotFoundError:
            pass
    return path


def kernel_boot():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def own_cgroup():
    return Path('/proc/self/cgroup').read_text().strip()


def guardian_processes():
    with (Path('/sys/fs/cgroup/system.slice') / UNIT / 'cgroup.procs').open('rb') as stream:
        raw = stream.read(65537)
    require(len(raw) <= 65536 and all(re.fullmatch(rb'[1-9][0-9]{0,9}', p) for p in raw.split()))
    return set(raw.split())


def regular(path, limit, uid=None, mode=None):
    path = no_links(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_size <= limit and (uid is None or info.st_uid == uid)
                and (mode is None or stat.S_IMODE(info.st_mode) == mode),
                'file type/owner/size refused')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        require(len(raw) == info.st_size and (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'file changed')
        return raw
    finally:
        os.close(fd)


def exclusive(path, raw, mode=0o600):
    fd = os.open(no_links(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    os.fchmod(fd, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def atomic(path, value):
    temporary = Path(str(path) + '.next')
    exclusive(temporary, encoded(value))
    os.replace(temporary, path)


def contract(value):
    fields = {'schema', 'nonce', 'lease', 'epoch', 'run_id', 'attempt', 'body_sha256',
              'vm_id', 'boot_id', 'image_id', 'admitted_at', 'deadline', 'boot_uuid', 'source_sha'}
    require(type(value) is dict and set(value) == fields and value['schema'] == 1)
    require(re.fullmatch('[a-f0-9]{32}', value['nonce']) and
            re.fullmatch('[a-f0-9]{40}', value['source_sha']) and
            re.fullmatch('[a-f0-9]{64}', value['body_sha256']))
    for key in ('lease', 'boot_uuid'):
        require(re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', value[key]))
    for key in ('vm_id', 'boot_id'):
        require(re.fullmatch('[1-9][0-9]{0,19}', value[key]))
    for key in ('epoch', 'run_id', 'attempt'):
        require(type(value[key]) is int and value[key] > 0)
    require(value['image_id'] == '4575951068918267275' and
            stamp(value['deadline']) - stamp(value['admitted_at']) == 7200)
    return value


def phase_end(value, phase):
    require(phase in PHASES)
    return stamp(value['admitted_at']) + PHASES[phase] * 60


class Clock:
    """Wall AND monotonic bounds, anchored once; backwards wall jumps cannot renew."""
    def __init__(self, value, wall=time.time, mono=time.monotonic):
        self.value, self.wall, self.mono = value, wall, mono
        self.started_wall, self.started_mono = wall(), mono()
        require(stamp(value['admitted_at']) <= self.started_wall < phase_end(value, 'persistence'))

    def remaining(self, phase):
        end = min(phase_end(self.value, phase), phase_end(self.value, 'persistence'))
        left = min(end - self.wall(), end - self.started_wall - (self.mono() - self.started_mono))
        if left <= 0:
            raise Failure('absolute phase cutoff', 124, 'phase-cutoff')
        return left

    def cleanup_remaining(self):
        end = stamp(self.value['deadline'])
        left = min(end - self.wall(), end - self.started_wall - (self.mono() - self.started_mono))
        if left <= 0:
            raise Failure('immutable cleanup cutoff', 124, 'phase-cutoff')
        return left


def manifest(value):
    require(type(value) is dict and set(value) == {'schema', 'source_sha', 'files'}
            and value['schema'] == 1 and re.fullmatch('[a-f0-9]{40}', value['source_sha']))
    require(type(value['files']) is dict and set(value['files']) == FILES)
    total = 0
    for name, item in value['files'].items():
        require(type(item) is dict and set(item) == {'bytes', 'sha256'}
                and type(item['bytes']) is int and item['bytes'] > 0
                and re.fullmatch('[a-f0-9]{64}', item['sha256']))
        require(item['bytes'] <= (PAYLOADS[name][0] if name in PAYLOADS else MAX_SOURCE))
        if name in PAYLOADS:
            require((item['bytes'], item['sha256']) == PAYLOADS[name], 'tool bytes refused')
        total += item['bytes']
    require(total <= MAX_TOTAL)
    return value


def load_sibling(name):
    require(name in ('qemu_offline', 'vlab_core'))
    path = ROOT / (name + '.py')
    spec = importlib.util.spec_from_file_location('labapp_trial_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def call_bounded(args, seconds, env=ENV):
    """Existing bounded helper; ONLY its two fixed Refusal messages are classified.

    Any other exception propagates unchanged and is reported as ``exception``
    without its text.
    """
    from hhfab_release import bounded, Refusal
    try:
        return bounded(args, seconds, limit=1024**2, env=env)
    except Refusal as error:
        message = str(error)
        if message == 'command timeout':
            raise Failure('bounded child failed', 124, 'child-timeout') from None
        if message == 'command output overflow':
            raise Failure('bounded child failed', 1, 'output-overflow') from None
        raise Failure('bounded child failed', 1, 'exception') from None


def child_failure(code, message):
    """Nonzero child status -> Failure. Negative is the raw subprocess signal."""
    if code > 0:
        return Failure(message, code, 'child-exit', code)
    return Failure(message, 128 - code, 'child-signal', code)


def run(argv, clock, phase, cap=30, user=False):
    # Existing bounded implementation caps output and kills/reaps exact process
    # groups. The guardian additionally contains independent systemd services.
    args = [str(a) for a in argv]
    if user:
        args = ['/usr/sbin/runuser', '-u', 'ubuntu', '--', *args]
    code, out = call_bounded(args, min(cap, clock.remaining(phase)))
    if code:
        raise child_failure(code, 'fixed child failed')
    return out


# ---- Transient GHCR registry authentication (#378) -------------------------------
# One narrowly authorized secret path: the owner sends ONE registry-only JSON record
# over the original bootstrap stdin; bootstrap builds the minimal Docker config in
# a fixed volatile directory readable only by the actual ``ubuntu`` hhfab user and
# the worker removes it right after fresh acquisition. Nothing derived from the
# secret value, digest or config bytes enters argv, manifest, receipts, the
# root tree, diagnostics or any image. Root-private records below hold identities,
# cutoffs and config file size only.
AUTH_REGISTRY = 'ghcr.io'
AUTH_MOUNT = Path('/run')
AUTH_DIR = AUTH_MOUNT / 'labapp-vlab-docker'
AUTH_NAME = 'config.json'
AUTH_HOME = Path('/home/ubuntu')
AUTH_INPUT_LIMIT = 1024
AUTH_GATE_SECONDS = 10
AUTH_LOCK = 'auth.lock'
AUTH_CLOSED = 'auth-closed.json'
AUTH_FILE = 'auth-file.json'
AUTH_UNLINKED = 'auth-unlinked.json'
AUTH_DIR_REMOVED = 'auth-directory-removed.json'
AUTH_OWNER = 0  # root throughout construction and the credential lifetime
AUTH_ROOT_GID = 0
AUTH_GUARDIAN = 'auth-guardian.json'
AUTH_INTENT, AUTH_BOUND, AUTH_READY, AUTH_REMOVED = (
    'auth-intent.json', 'auth-bound.json', 'auth-ready.json', 'auth-removed.json')
AUTH_USER = r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}'
AUTH_TOKEN = r'[A-Za-z0-9_.-]{20,255}'
MOUNTINFO = Path('/proc/self/mountinfo')
SWAPS = Path('/proc/swaps')
AUTH_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def auth_credentials(raw):
    """Closed registry-only record. No registry choice, helper, URL, token type or extra field.

    Refusal text is fixed; neither input bytes nor parser messages are propagated.
    """
    try:
        require(type(raw) is bytes and 0 < len(raw) <= AUTH_INPUT_LIMIT)
        value = data(raw)
        require(type(value) is dict and set(value) == {'schema', 'registry', 'username', 'token'}
                and type(value['schema']) is int and value['schema'] == 1
                and type(value['registry']) is str and value['registry'] == AUTH_REGISTRY
                and type(value['username']) is str and re.fullmatch(AUTH_USER, value['username'])
                and type(value['token']) is str and re.fullmatch(AUTH_TOKEN, value['token']))
    except Exception:
        raise Failure('GHCR credential input refused') from None
    return {key: value[key] for key in ('schema', 'registry', 'username', 'token')}


def auth_read_input(fd=0, seconds=10.0, *, until=None):
    """Bounded read of the one stdin record; EOF is required (no unbounded wait)."""
    end = time.monotonic() + seconds if until is None else until
    raw = b''
    try:
        while len(raw) <= AUTH_INPUT_LIMIT:
            left = end - time.monotonic()
            if left <= 0 or not select.select([fd], [], [], left)[0]:
                raise Failure('GHCR credential input refused')
            chunk = os.read(fd, AUTH_INPUT_LIMIT + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
    except Failure:
        raise
    except Exception:
        raise Failure('GHCR credential input refused') from None
    return auth_credentials(raw)


def auth_config(credentials):
    """Equivalent minimal Docker config: one ghcr.io basic-auth entry, nothing else."""
    pair = (credentials['username'] + ':' + credentials['token']).encode()
    return encoded({'auths': {AUTH_REGISTRY: {'auth': base64.b64encode(pair).decode()}}})


def harden_secret_process():
    """Conventional process protection; exec/pipe collectors have separate semantics."""
    try:
        import ctypes
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        require(resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
                and ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) == 0)
    except Exception:
        raise Failure('secret process hardening refused') from None


def auth_account():
    user = pwd.getpwnam('ubuntu')
    group = grp.getgrgid(user.pw_gid)
    require(user.pw_uid >= 1000 and user.pw_gid != 0 and user.pw_dir == '/home/ubuntu'
            and user.pw_shell == '/bin/bash' and group.gr_name == 'ubuntu'
            and set(group.gr_mem) <= {'ubuntu'}
            and all(other.pw_uid == user.pw_uid or other.pw_gid != user.pw_gid
                    for other in pwd.getpwall()), 'unexpected account policy')
    return user


def auth_volatile():
    """Directory's mount is the standard /run tmpfs and no swap can hold its pages.

    tmpfs is memory that CAN be swapped: require no active swap area, or an explicit
    ``noswap`` tmpfs mount option. A path under /run alone is never trusted.
    """
    require(AUTH_DIR.parent == AUTH_MOUNT, 'credential location refused')
    with MOUNTINFO.open('rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, 'mount table refused')
    best, target = None, str(AUTH_DIR)
    for line in raw.decode().splitlines():
        left, separator, right = line.partition(' - ')
        a, b = left.split(), right.split()
        require(separator and len(a) >= 6 and len(b) >= 3, 'mount table refused')
        point = a[4]
        if target == point or target.startswith(point.rstrip('/') + '/'):
            if best is None or len(point) >= len(best[0]):  # a later entry at the same point overmounts
                best = (point, a[5].split(','), b[0], b[2].split(','))
    require(best is not None and best[0] == str(AUTH_MOUNT) and best[2] == 'tmpfs',
            'credential volume is not the standard tmpfs')
    rows = SWAPS.read_text().splitlines()[1:]
    require(not any(row.strip() for row in rows) or 'noswap' in best[1] + best[3], 'swap may hold credentials')


def auth_fallbacks_absent(uid):
    """Refuse (never adopt or delete) other stores Docker/ORAS/containers-image would consult."""
    for path in (AUTH_HOME / '.docker' / AUTH_NAME, AUTH_HOME / '.dockercfg',
                 AUTH_HOME / '.config' / 'containers' / 'auth.json',
                 AUTH_MOUNT / 'containers' / str(uid) / 'auth.json',
                 AUTH_MOUNT / 'user' / str(uid) / 'containers' / 'auth.json'):
        require(not os.path.lexists(path), 'fallback registry credential store refused')


def auth_armed():
    return os.path.lexists(ROOT / AUTH_INTENT)


def auth_intent():
    item = data(regular(ROOT / AUTH_INTENT, 4096, 0))
    require(type(item) is dict and set(item) == {'schema', 'nonce', 'uid', 'gid', 'until', 'cleanup_until'} and item['schema'] == 1
            and type(item['nonce']) is str and re.fullmatch('[a-f0-9]{32}', item['nonce'])
            and all(type(item[k]) is int and item[k] > 0 for k in ('uid', 'gid'))
            and all(type(item[k]) in (int, float) and 0 < item[k] < float('inf')
                    for k in ('until', 'cleanup_until')), 'credential intent refused')
    return item


@contextmanager
def auth_locked(until):
    """One never-replaced root-private lock; no stdin or child wait under it."""
    fd = os.open(ROOT / AUTH_LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(auth_lock_ok(info), 'credential lock refused')
        while True:
            require(time.monotonic() < until, 'credential lock expired')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(min(.05, max(0, until - time.monotonic())))
        current = os.stat(ROOT / AUTH_LOCK, follow_symlinks=False)
        require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), 'credential lock changed')
        yield
    finally:
        os.close(fd)


def auth_lock_ok(info):
    return (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600)


def auth_open(intent):
    require(not os.path.lexists(ROOT / AUTH_CLOSED) and not os.path.lexists(ROOT / AUTH_REMOVED)
            and time.monotonic() < intent['until'], 'credential publication closed')


def auth_publish_check(value, intent):
    """Fresh original binding after ingress, while serialized against cleanup."""
    auth_open(intent)
    current = contract(data(regular(ROOT / 'contract.json', MAX_SOURCE, 0)))
    require(current == value and kernel_boot() == value['boot_uuid'], 'credential binding refused')
    # ``until`` was clipped using the ORIGINAL bootstrap Clock's remaining
    # stage time. Check that monotonic bound plus the current wall cutoff;
    # constructing a new Clock here would re-anchor its monotonic protection.
    require(time.time() < phase_end(value, 'stage'), 'absolute phase cutoff', 'phase-cutoff')
    table = manifest(data(regular(ROOT / 'manifest.json', MAX_SOURCE, 0)))
    require(table['source_sha'] == value['source_sha'], 'credential source refused')
    for name, item in table['files'].items():
        auth_open(intent)
        require(sha(regular(ROOT / name, item['bytes'], 0)) == item['sha256'], 'credential source refused')
    started = data(regular(ROOT / 'started.json', 4096, 0))
    original = data(regular(ROOT / AUTH_GUARDIAN, 4096, 0))
    require(started == original and started['boot'] == value['boot_uuid'] and started['lease'] == value['lease']
            and started['nonce'] == value['nonce'] and type(started['guardian_pid']) is int
            and str(started['guardian_pid']).encode() in guardian_processes()
            and not os.path.lexists(ROOT / 'result.json'), 'original guardian unavailable')
    beat = data(regular(ROOT / 'heartbeat.json', 4096, 0))
    require(beat['sequence'] == 0 and 0 <= time.monotonic() - beat['received'] < 30,
            'heartbeat lost', 'heartbeat-loss')
    auth_open(intent)


def auth_bound(intent, info, private=False):
    """The directory is the exact one this run created: recorded identity, owner, mode, volume."""
    bound = data(regular(ROOT / AUTH_BOUND, 4096, 0))
    require(type(bound) is dict and set(bound) == {'schema', 'dev', 'ino', 'uid', 'gid'}
            and (info.st_dev, info.st_ino) == (bound['dev'], bound['ino'])
            and (bound['uid'], bound['gid']) == (intent['uid'], intent['gid'])
            and info.st_uid == AUTH_OWNER and stat.S_ISDIR(info.st_mode)
            and ((info.st_gid == intent['gid'] and stat.S_IMODE(info.st_mode) == 0o750)
                 or private and info.st_gid in (AUTH_ROOT_GID, intent['gid']) and stat.S_IMODE(info.st_mode) == 0o700)
            and info.st_dev == os.stat(AUTH_MOUNT).st_dev, 'credential directory identity refused')


def auth_config_ok(info, intent, private=False):
    return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == AUTH_OWNER
            and ((info.st_gid == intent['gid'] and stat.S_IMODE(info.st_mode) == 0o640)
                 or private and info.st_gid in (AUTH_ROOT_GID, intent['gid']) and stat.S_IMODE(info.st_mode) == 0o600))


def auth_file_binding(descriptor, fd, intent, private=False):
    """Pin both names to the open descriptors, including metadata, before secret IO."""
    directory, file_info = os.fstat(descriptor), os.fstat(fd)
    auth_bound(intent, directory, private=private)
    current = os.stat(AUTH_DIR, follow_symlinks=False)
    named = os.stat(AUTH_NAME, dir_fd=descriptor, follow_symlinks=False)
    receipt = data(regular(ROOT / AUTH_FILE, 4096, 0))
    require((current.st_dev, current.st_ino) == (directory.st_dev, directory.st_ino)
            and (named.st_dev, named.st_ino) == (file_info.st_dev, file_info.st_ino)
            == (receipt['dev'], receipt['ino'])
            and auth_config_ok(file_info, intent, private=private)
            and auth_config_ok(named, intent, private=private), 'credential file identity refused')
    return file_info


def auth_install(value, credentials):
    intent = auth_intent()
    with auth_locked(intent['until']):
        auth_publish_check(value, intent)
        auth_install_locked(value, credentials, intent)


def auth_install_locked(value, credentials, intent):
    """Create the exact volatile config. Only reachable after the guardian is armed."""
    user = auth_account()
    require(intent['nonce'] == value['nonce'] and (user.pw_uid, user.pw_gid) == (intent['uid'], intent['gid']),
            'credential binding refused')
    auth_volatile()
    auth_fallbacks_absent(user.pw_uid)
    require(not os.path.lexists(AUTH_DIR) and not os.path.lexists(ROOT / AUTH_BOUND)
            and not os.path.lexists(ROOT / AUTH_READY), 'preexisting credential path refused')
    auth_publish_check(value, intent)
    os.mkdir(AUTH_DIR, 0o700)
    descriptor = os.open(AUTH_DIR, AUTH_DIR_FLAGS)
    try:
        info = os.fstat(descriptor)
        # Identity is recorded BEFORE any secret exists, so cleanup can prove ownership.
        exclusive(ROOT / AUTH_BOUND, encoded({'schema': 1, 'dev': info.st_dev, 'ino': info.st_ino,
                                              'uid': user.pw_uid, 'gid': user.pw_gid}))
        info = os.fstat(descriptor)
        auth_bound(intent, info, private=True)
        fd = os.open(AUTH_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=descriptor)
        try:
            file_info = os.fstat(fd)
            exclusive(ROOT / AUTH_FILE, encoded({'schema': 1, 'dev': file_info.st_dev,
                                                 'ino': file_info.st_ino}))
            auth_publish_check(value, intent)
            raw = auth_config(credentials)
            view = memoryview(raw)
            while view:
                auth_open(intent)
                auth_file_binding(descriptor, fd, intent, private=True)
                written = os.write(fd, view)
                require(written > 0, 'credential write refused')
                view = view[written:]
            os.fsync(fd)
            auth_publish_check(value, intent)
            auth_file_binding(descriptor, fd, intent, private=True)
            os.fchown(fd, AUTH_OWNER, user.pw_gid)
            os.fchmod(fd, 0o640)
            os.fchown(descriptor, AUTH_OWNER, user.pw_gid)
            os.fchmod(descriptor, 0o750)
            auth_publish_check(value, intent)
            file_info = auth_file_binding(descriptor, fd, intent)
            exclusive(ROOT / AUTH_READY, encoded({'schema': 1, 'nonce': value['nonce'],
                                                  'file_ino': file_info.st_ino, 'size': len(raw)}))
        finally:
            os.close(fd)
    finally:
        os.close(descriptor)
    auth_verify(value)


def auth_verify(value):
    """Present, minimal, exactly owned and still volatile. Never reads the secret bytes."""
    intent = auth_intent()
    user = auth_account()
    require(intent['nonce'] == value['nonce'] and (user.pw_uid, user.pw_gid) == (intent['uid'], intent['gid'])
            and not os.path.lexists(ROOT / AUTH_REMOVED)
            and not os.path.lexists(ROOT / AUTH_CLOSED), 'credential binding refused')
    ready = data(regular(ROOT / AUTH_READY, 4096, 0))
    require(type(ready) is dict and set(ready) == {'schema', 'nonce', 'file_ino', 'size'}
            and ready['schema'] == 1 and ready['nonce'] == value['nonce']
            and type(ready['file_ino']) is int and type(ready['size']) is int, 'credential readiness refused')
    auth_volatile()
    auth_fallbacks_absent(user.pw_uid)
    descriptor = os.open(AUTH_DIR, AUTH_DIR_FLAGS)
    try:
        auth_bound(intent, os.fstat(descriptor))
        require(os.listdir(descriptor) == [AUTH_NAME], 'credential directory contents refused')
        info = os.stat(AUTH_NAME, dir_fd=descriptor, follow_symlinks=False)
        receipt = data(regular(ROOT / AUTH_FILE, 4096, 0))
        require(auth_config_ok(info, intent) and info.st_ino == ready['file_ino']
                and (info.st_dev, info.st_ino) == (receipt['dev'], receipt['ino'])
                and info.st_size == ready['size'], 'credential file identity refused')
    finally:
        os.close(descriptor)


def auth_gate(value, clock):
    """Guardian-side: nothing is provisioned until the armed credential is ready (bounded)."""
    if not auth_armed():
        return
    require(auth_intent()['nonce'] == value['nonce'], 'credential binding refused')
    intent = auth_intent()
    until = min(intent['until'], time.monotonic() + clock.remaining('stage'))
    while not os.path.lexists(ROOT / AUTH_READY):
        if time.monotonic() >= until:
            raise Failure('credential ready gate expired', 124, 'phase-cutoff')
        time.sleep(.05)
    require(time.monotonic() < until, 'credential ready gate expired')
    auth_verify(value)


def auth_remove():
    """Idempotent removal of exactly the owned directory and config file.

    Absence of known objects needs positive exact removal receipts. Anything not provably ours (no binding, replaced directory,
    link, extra entry, other owner/mode/link count) is NOT deleted and raises a fixed
    uncertainty failure. Never follows links; deletes only through the bound descriptor.
    """
    if not auth_armed():
        return
    try:
        intent = auth_intent()
        # Close BEFORE waiting: even a stopped publisher holding the lock cannot
        # resume publication after cleanup reports absence or times out.
        try:
            exclusive(ROOT / AUTH_CLOSED, encoded({'schema': 1, 'nonce': intent['nonce']}))
        except FileExistsError:
            closed = data(regular(ROOT / AUTH_CLOSED, 4096, 0))
            require(closed == {'schema': 1, 'nonce': intent['nonce']})
        with auth_locked(min(intent['cleanup_until'], time.monotonic() + 2)):
            auth_remove_locked(intent)
    except Exception:
        failure = Failure('credential cleanup uncertain')
        failure.cleanup_uncertain = True
        raise failure from None


def auth_remove_locked(intent):
    try:
        descriptor = os.open(AUTH_DIR, AUTH_DIR_FLAGS)
    except FileNotFoundError:
        require(not os.path.lexists(AUTH_DIR))
        if os.path.lexists(ROOT / AUTH_FILE):
            auth_removal_receipt(AUTH_UNLINKED, AUTH_FILE, intent)
        if os.path.lexists(ROOT / AUTH_BOUND):
            auth_removal_receipt(AUTH_DIR_REMOVED, AUTH_BOUND, intent)
        return
    try:
        info = os.fstat(descriptor)
        auth_bound(intent, info, private=True)
        if AUTH_NAME not in os.listdir(descriptor) and os.path.lexists(ROOT / AUTH_FILE):
            auth_removal_receipt(AUTH_UNLINKED, AUTH_FILE, intent)
        foreign = False
        for name in os.listdir(descriptor):
            if name != AUTH_NAME:
                foreign = True
                continue
            receipt = data(regular(ROOT / AUTH_FILE, 4096, 0))
            require(type(receipt) is dict and set(receipt) == {'schema', 'dev', 'ino'}
                    and receipt['schema'] == 1)
            entry = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            owned = auth_config_ok(entry, intent, private=True)
            if owned and (entry.st_dev, entry.st_ino) == (receipt['dev'], receipt['ino']):
                current = os.stat(AUTH_DIR, follow_symlinks=False)
                fresh = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino)
                        and (fresh.st_dev, fresh.st_ino, fresh.st_ctime_ns) ==
                        (entry.st_dev, entry.st_ino, entry.st_ctime_ns))
                os.unlink(name, dir_fd=descriptor)
                exclusive(ROOT / AUTH_UNLINKED, encoded({'schema': 1, 'nonce': intent['nonce'],
                                                        'dev': entry.st_dev, 'ino': entry.st_ino}))
            else:
                foreign = True
        require(not foreign and not os.listdir(descriptor))
        current = os.stat(AUTH_DIR, follow_symlinks=False)
        require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino))
        os.rmdir(AUTH_DIR)
        exclusive(ROOT / AUTH_DIR_REMOVED, encoded({'schema': 1, 'nonce': intent['nonce'],
                                                   'dev': info.st_dev, 'ino': info.st_ino}))
    finally:
        os.close(descriptor)
    require(not os.path.lexists(AUTH_DIR))


def auth_removal_receipt(name, binding, intent):
    """Missing known objects are uncertain without our positive exact removal."""
    known = data(regular(ROOT / binding, 4096, 0))
    removed = data(regular(ROOT / name, 4096, 0))
    require(removed == {'schema': 1, 'nonce': intent['nonce'], 'dev': known['dev'], 'ino': known['ino']},
            'credential removal unconfirmed')


def auth_absent():
    require(not os.path.lexists(AUTH_DIR), 'credential still present')
    if auth_armed():
        intent = auth_intent()
        require(os.path.lexists(ROOT / AUTH_CLOSED), 'credential publication still open')
        if os.path.lexists(ROOT / AUTH_FILE):
            auth_removal_receipt(AUTH_UNLINKED, AUTH_FILE, intent)
        if os.path.lexists(ROOT / AUTH_BOUND):
            auth_removal_receipt(AUTH_DIR_REMOVED, AUTH_BOUND, intent)
        auth_fallbacks_absent(auth_account().pw_uid)


def bootstrap(incoming, expected_manifest, options=()):
    options = tuple(options)
    require(options in ((), ('ghcr-auth',)), 'unsupported bootstrap option')
    authenticated = bool(options)
    require(os.geteuid() == 0 and re.fullmatch('[a-f0-9]{64}', expected_manifest))
    incoming = no_links(incoming)
    require(re.fullmatch('/tmp/labapp-vlab-[a-f0-9]{32}', str(incoming)))
    info = incoming.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid != 0)
    uid = info.st_uid
    raw = regular(incoming / 'manifest.json', MAX_SOURCE, uid)
    require(sha(raw) == expected_manifest)
    table = manifest(data(raw))
    found = set()
    with os.scandir(incoming) as entries:
        for entry in entries:
            require(len(found) < len(FILES) + 1)
            found.add(entry.name)
    require(found == FILES | {'manifest.json'})
    # Validate all bytes first, then exclusive root copies; never extract or
    # execute owner-writable incoming sources. Root consumes the trusted hash
    # passed by the authenticated owner command, not an incoming self-assertion.
    for name, item in table['files'].items():
        require(sha(regular(incoming / name, item['bytes'], uid)) == item['sha256'])
    value = contract(data(regular(incoming / 'contract.json', MAX_SOURCE, uid)))
    require(incoming.name == 'labapp-vlab-' + value['nonce'] and table['source_sha'] == value['source_sha'])
    require(kernel_boot() == value['boot_uuid'])
    clock = Clock(value)
    clock.remaining('stage')
    require(not ROOT.exists() and not UNIT_PATH.exists(), 'one-shot root reservation collision')
    require(all(not (base / name).exists() and not (base / name).is_symlink()
                for base in UNIT_BASES for name in (UNIT, UNIT + '.d')), 'guardian unit override refused')
    no_links(ROOT.parent)
    require(not os.path.lexists(AUTH_DIR), 'preexisting credential path refused')
    account = None
    if authenticated:
        # Refuse before ANY state exists: wrong volume/swap, preexisting target or fallback
        # store. The secret has not been read yet; stdin is accepted only after the
        # guardian below is armed.
        harden_secret_process()
        account = auth_account()
        auth_volatile()
        auth_fallbacks_absent(account.pw_uid)
        require(not os.path.lexists(AUTH_DIR), 'preexisting credential path refused')
    ROOT.mkdir(mode=0o700)
    for name, item in table['files'].items():
        raw = regular(incoming / name, item['bytes'], uid)
        require(len(raw) == item['bytes'] and sha(raw) == item['sha256'])
        exclusive(ROOT / name, raw)
    exclusive(ROOT / 'manifest.json', encoded(table))
    exclusive(ROOT / 'phase.json', encoded({'phase': 'stage'}))
    if authenticated:
        # Arms guardian gate and every cleanup path BEFORE a credential can exist.
        exclusive(ROOT / AUTH_LOCK, b'')
        now = time.monotonic()
        exclusive(ROOT / AUTH_INTENT, encoded({'schema': 1, 'nonce': value['nonce'],
                  'uid': account.pw_uid, 'gid': account.pw_gid,
                  'until': now + min(AUTH_GATE_SECONDS, clock.remaining('stage'), 30),
                  'cleanup_until': now + clock.cleanup_remaining()}))
    exclusive(UNIT_PATH, regular(ROOT / UNIT, MAX_SOURCE, 0), 0o644)
    no_links(RUNTIME_DROPIN.parent)
    RUNTIME_DROPIN.mkdir(mode=0o755)
    # One exclusive nonextendable runtime bound, composed with admission. The
    # fixed thirty-second startup allowance makes manager delay consume work
    # rather than append to it. No update/renewal path exists.
    runtime = max(1, int(clock.remaining('persistence')) - 30)
    exclusive(RUNTIME_DROPIN / '10-bound.conf', f'[Service]\nRuntimeMaxSec={runtime}\n'.encode(), 0o644)
    sys.path.insert(0, str(ROOT))
    # Minimal bootstrap only: no packages, Docker or core work until guardian's
    # running process has accepted this one-shot contract.
    try:
        run([SYSTEMCTL, 'daemon-reload'], clock, 'stage', 10)
        exclusive(ROOT / 'heartbeat.json', encoded({'sequence': 0, 'received': time.monotonic()}))
        run([SYSTEMCTL, 'start', UNIT], clock, 'stage', 15)
        until = time.monotonic() + min(10, clock.remaining('stage'))
        while not (ROOT / 'started.json').exists():
            require(time.monotonic() < until, 'guardian readiness unconfirmed')
            require(not (ROOT / 'result.json').exists(), 'guardian startup failed')
            time.sleep(.1)
        started = data(regular(ROOT / 'started.json', 4096, 0))
        require(started['boot'] == value['boot_uuid'] and started['lease'] == value['lease']
                and started['nonce'] == value['nonce'], 'guardian binding differs')
        observed = run([SYSTEMCTL, 'show', UNIT, '-p', 'MainPID', '-p', 'ActiveState'], clock, 'stage', 5)
        fields = dict(line.split('=', 1) for line in observed.decode().splitlines())
        require(fields == {'MainPID': str(started['guardian_pid']), 'ActiveState': 'active'},
                'original guardian process not active')
        if authenticated:
            # The guardian is running, bound and blocked at its ready gate, and its
            # ExecStopPost cleanup is armed: only now is the secret accepted/usable.
            exclusive(ROOT / AUTH_GUARDIAN, encoded(started))
            auth_install(value, auth_read_input(until=auth_intent()['until']))
    except BaseException:
        # The fixed unit's ExecStopPost owns containment even if startup reply
        # was lost. Do not delete the reservation or retry a bootstrap.
        try:
            run([SYSTEMCTL, 'stop', UNIT], clock, 'stage', 30)
        except BaseException:
            pass
        if authenticated:
            try:
                auth_remove()  # idempotent; the primary failure below stays primary
            except BaseException:
                pass
        raise


# Root-private first-failure bundle (#368). The fixed core writer lives in vlab_core;
# this strict reader is shared by guest export and the owner host. Raw sections are
# untrusted text: only structure, sizes, enums and bindings are validated here.
FAILURE_LIMIT = 32 * 1024
FAILURE_SECTIONS = {'primary': 2048, 'command_context': 2048, 'manager': 2048, 'journal': 8192}
FAILURE_CONTEXT = 'last failed command output observed before manager-wrapper overwrite/core cleanup'
FAILURE_STATUS = ('ok', 'truncated', 'unavailable', 'invalid')
FAILURE_STAGES = ('reserve', 'manager', 'unit', 'final')
HEX32 = '[0-9a-f]{32}'
UUID = '[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}'


def first_failure_bundle(raw):
    """Strictly validate and return the bundle; raises Failure on anything else."""
    require(type(raw) is bytes and 0 < len(raw) <= FAILURE_LIMIT, 'failure bundle size refused')
    try:
        value = data(raw)
    except (ValueError, RecursionError):
        raise Failure('failure bundle JSON refused') from None
    fields = {'schema', 'source', 'nonce', 'mode', 'operation', 'invocation', 'boot', 'stage',
              'query_cleanup', 'state', 'primary', 'command_context', 'manager', 'journal'}
    require(type(value) is dict and set(value) == fields and value['schema'] == 1
            and type(value['schema']) is int and value['source'] == 'vlab_core'
            and value['mode'] in ('fresh', 'resume') and value['stage'] in FAILURE_STAGES
            and value['query_cleanup'] in ('confirmed', 'uncertain'))
    require(type(value['nonce']) is str and re.fullmatch(HEX32, value['nonce']))
    for key in ('operation', 'invocation'):
        require(value[key] is None or type(value[key]) is str and re.fullmatch(HEX32, value[key]))
    require(value['boot'] is None or type(value['boot']) is str and re.fullmatch(UUID, value['boot']))
    require((value['operation'] is None) == (value['stage'] == 'reserve')
            and (value['invocation'] is None or value['operation'] is not None))
    state = value['state']
    require(type(state) is dict and set(state) == {'status', 'phase', 'containment', 'service_result'}
            and state['status'] in ('ok', 'unavailable', 'invalid')
            and all(state[k] is None or type(state[k]) is str and re.fullmatch('[a-z0-9-]{1,32}', state[k])
                    for k in ('phase', 'containment', 'service_result')))
    for name, cap in FAILURE_SECTIONS.items():
        section = value[name]
        extra = {'message', 'code'} if name == 'primary' else {'label'} if name == 'command_context' else set()
        require(type(section) is dict and set(section) == {'status', 'output'} | extra
                and section['status'] in FAILURE_STATUS and type(section['output']) is str)
        try:
            raw_output = base64.b64decode(section['output'], validate=True)
        except (ValueError, TypeError):
            raise Failure('failure section encoding refused') from None
        require(len(raw_output) <= cap and (section['status'] in ('ok', 'truncated') or not raw_output)
                and (section['status'] != 'ok' or raw_output))
        if name == 'primary':
            require(section['message'] is None or type(section['message']) is str
                    and re.fullmatch('[ -~]{1,128}', section['message']))
            require(section['code'] is None or type(section['code']) is int and 0 <= section['code'] < 256)
        if name == 'command_context':
            require(section['label'] == FAILURE_CONTEXT)
    # Output can exist only for an exact bound identity.
    require(value['manager']['status'] == 'unavailable' or value['invocation'] is not None)
    require(value['command_context']['status'] == 'unavailable' or value['operation'] is not None)
    require(value['journal']['status'] in ('unavailable',) or value['invocation'] is not None)
    return value


def export_failure(nonce):
    """Fixed one-shot read for the owner: no path argument, ``absent`` or exact bytes.

    Output is ``<envelope JSON>\\n<bundle bytes>``. The envelope is read from the
    contract, the LIVE core state and the live boot id, independent of the bundle
    header, so a stale/foreign/replaced bundle cannot vouch for itself.
    """
    value = contract(data(regular(ROOT / 'contract.json', MAX_SOURCE, 0)))
    require(type(nonce) is str and nonce == value['nonce'])
    boot = kernel_boot()
    require(boot == value['boot_uuid'])
    core = load_sibling('vlab_core')
    root = core.ROOT.lstat()
    require(stat.S_ISDIR(root.st_mode) and root.st_uid == os.geteuid()
            and stat.S_IMODE(root.st_mode) == 0o700)  # main() already requires euid 0
    try:
        raw = regular(core.ROOT / core.FIRST_FAILURE, FAILURE_LIMIT, os.geteuid(), 0o600)
    except FileNotFoundError:
        return b'absent'
    bundle = first_failure_bundle(raw)
    current = core.state()
    require(current['nonce'] == nonce == bundle['nonce'] and bundle['mode'] == 'fresh'
            and bundle['boot'] == boot)
    operation, invocation = current.get('operation'), current.get('invocation')
    for item in (operation, invocation):
        require(item is None or type(item) is str and re.fullmatch(HEX32, item))
    require(operation == bundle['operation'] and invocation == bundle['invocation'])
    if operation is None:
        require(current.get('phase') == 'prepared'
                and all(key not in current for key in ('mode', 'operation', 'invocation')))
    else:
        require(current.get('mode') == 'fresh')
    envelope = {'schema': 1, 'source_sha': value['source_sha'], 'nonce': nonce, 'mode': 'fresh',
                'operation': operation, 'invocation': invocation, 'boot': boot}
    return encoded(envelope) + b'\n' + raw


def heartbeat(nonce, sequence):
    value = contract(data(regular(ROOT / 'contract.json', MAX_SOURCE, 0)))
    require(nonce == value['nonce'] and type(sequence) is int and sequence > 0)
    Clock(value).remaining('persistence')
    require(kernel_boot() == value['boot_uuid'])
    old = data(regular(ROOT / 'heartbeat.json', 4096, 0))
    require(sequence == old['sequence'] + 1)
    atomic(ROOT / 'heartbeat.json', {'sequence': sequence, 'received': time.monotonic()})


def memory_available():
    lines = Path('/proc/meminfo').read_text().splitlines()
    row = next(line for line in lines if line.startswith('MemAvailable:'))
    return int(row.split()[1]) * 1024


def resources(poststage=False):
    fs = os.statvfs(ROOT)
    free = fs.f_bavail * fs.f_frsize
    mem = memory_available()
    require(fs.f_favail > 4096 and free >= (250 if poststage else 64) * GIB
            and mem >= (96 if poststage else 16) * GIB, 'resource stop', 'resource-floor')
    return {'free_bytes': free, 'available_memory': mem}


def oom_count():
    # Kernel-wide event counter detects nested/daemon events outside guardian's
    # cgroup too. An unrelated OOM on this dedicated VM also fails the trial.
    rows = dict(line.split() for line in Path('/proc/vmstat').read_text().splitlines())
    return int(rows['oom_kill'])


def containment():
    """Fixed public core stop + exact daemon ownership, no private stop workaround."""
    from hhfab_release import bounded
    ok = True
    if Path('/var/lib/labapp-vlab-core').exists():
        try:
            code, _ = bounded([PYTHON, str(ROOT / 'vlab_core.py'), 'stop'], 70, env=ENV)
            ok = code == 0
        except BaseException:
            ok = False
    if (ROOT / 'daemon-intent.json').exists():
        try:
            code, _ = bounded([SYSTEMCTL, 'stop', 'docker.socket', 'docker.service', 'containerd.service'], 30, env=ENV)
            ok = ok and code == 0
            for name in ('docker.socket', 'docker.service', 'containerd.service'):
                code, out = bounded([SYSTEMCTL, 'show', name, '-p', 'ActiveState', '-p', 'SubState'], 10, env=ENV)
                ok = ok and code == 0 and b'ActiveState=inactive\n' in out and b'SubState=dead\n' in out
        except BaseException:
            ok = False
    # Readers (core/Docker) were stopped above. Always attempted, even after a stop
    # failure: removal is protective. Uncertainty withholds containment, never VM disposal.
    try:
        auth_remove()
    except BaseException:
        ok = False
    require(ok, 'exact service containment uncertain')


def read_status(nonce):
    """Valid worker status or None (missing/corrupt/oversize/wrong nonce); never raises."""
    try:
        return worker_status(data(regular(ROOT / 'worker-status.json', MAX_RESULT, 0)), nonce)
    except Exception:
        return None


def judge_worker(observed, current, last, phase):
    """Final (code, diagnostic) from the ACTUAL worker termination plus status evidence.

    observed: raw subprocess returncode (negative = signal). current: the valid
    status read after the exit, or None. last: last valid status seen at all
    (context only, never proof). The status can supply a diagnostic, never an
    exit code, never ``contained`` and never a success the exit does not match.
    """
    def supervised(category, status):
        return {'origin': 'guardian', 'phase': phase, 'operation': 'worker-supervision',
                'category': category, 'child_status': status}
    if observed < 0:
        # Direct worker signal: normalized like the helper (128+N); no inner operation.
        if observed >= -64:
            return 128 - observed, supervised('child-signal', observed)
        return 1, supervised('status-invalid', None)
    if observed == 0:
        if current is not None and current['state'] == 'succeeded':
            return 0, dict(SUCCESS)
        return 1, supervised('status-invalid', 0)
    if current is not None and current['state'] == 'failed' and current['code'] == observed:
        return observed, dict(current['diagnostic'])
    if last is not None:
        context = {'origin': 'unknown', 'phase': last['phase'], 'operation': last['operation']}
    else:
        context = {'origin': 'unknown', 'phase': phase, 'operation': 'worker-supervision'}
    return observed, dict(context, category='status-invalid', child_status=observed if observed <= 255 else None)


def final_record(nonce, code, contained, detail, phase):
    """Validated schema-2 record; an invalid pairing degrades to a closed fallback."""
    try:
        return result_record({'schema': 2, 'code': code, 'contained': contained,
                              'nonce': nonce, 'diagnostic': detail}, nonce)
    except Exception:
        fallback = {'origin': 'guardian', 'phase': phase if phase in PHASE_NAMES else 'startup',
                    'operation': 'worker-supervision', 'category': 'exception', 'child_status': None}
        return result_record({'schema': 2, 'code': code if type(code) is int and 0 < code < 256 else 1,
                              'contained': contained, 'nonce': nonce, 'diagnostic': fallback}, nonce)


def guardian():
    value = contract(data(regular(ROOT / 'contract.json', MAX_SOURCE, 0)))
    clock = Clock(value)
    require(kernel_boot() == value['boot_uuid'])
    # EXCL start reservation prevents restart/reset/renewal, including after reboot.
    # It is also the SOLE-WRITER proof for result.json: a collision raises here,
    # before the finally below, so an incumbent's result is never replaced. Contract,
    # Clock, boot and reservation failures therefore publish no guest result.
    exclusive(ROOT / 'started.json', encoded({'boot': value['boot_uuid'], 'lease': value['lease'],
              'nonce': value['nonce'], 'guardian_pid': os.getpid(), 'remaining': clock.remaining('stage')}))
    child = None
    result = 1
    contained = False
    children_absent = True
    phase_seen, operation, last = 'startup', 'guardian-init', None
    detail = {'origin': 'guardian', 'phase': 'startup', 'operation': 'guardian-init',
              'category': 'exception', 'child_status': None}
    try:
        original_oom = oom_count()
        # Initial heartbeat grace is bounded by the same thirty-second loss
        # window; no provisioning starts before the guardian checks it.
        beat = data(regular(ROOT / 'heartbeat.json', 4096, 0))
        require(0 <= time.monotonic() - beat['received'] <= 30, 'heartbeat lost', 'heartbeat-loss')
        # Armed credential gate: no worker/provisioning until bootstrap published the
        # verified credential, within a bounded wait. Expiry fails closed into cleanup.
        auth_gate(value, clock)
        if auth_armed():
            require(kernel_boot() == value['boot_uuid'], 'boot changed', 'boot-change')
            clock.remaining('stage')
            beat = data(regular(ROOT / 'heartbeat.json', 4096, 0))
            require(0 <= time.monotonic() - beat['received'] <= 30, 'heartbeat lost', 'heartbeat-loss')
        operation = 'worker-spawn'
        child = subprocess.Popen([PYTHON, str(ROOT / 'vlab_trial.py'), 'worker'],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, env=ENV, start_new_session=True)
        operation = 'worker-supervision'
        minimum = None
        while True:
            phase = data(regular(ROOT / 'phase.json', 4096, 0))['phase']
            if phase in PHASE_NAMES:
                phase_seen = phase
            clock.remaining(phase)
            require(kernel_boot() == value['boot_uuid'], 'boot changed', 'boot-change')
            beat = data(regular(ROOT / 'heartbeat.json', 4096, 0))
            require(0 <= time.monotonic() - beat['received'] <= 30, 'heartbeat lost', 'heartbeat-loss')
            require(oom_count() == original_oom, 'OOM event', 'oom-event')
            sample = resources()
            minimum = sample if minimum is None else {k: min(v, minimum[k]) for k, v in sample.items()}
            atomic(ROOT / 'measurements.json', minimum)
            observed = child.poll()
            if observed is not None:
                current = read_status(value['nonce'])
                result, detail = judge_worker(observed, current, current or last, phase_seen)
                break
            last = read_status(value['nonce']) or last
            time.sleep(min(5, clock.remaining(phase)))
    except Failure as error:
        # What the guardian itself observed; origin is always guardian here.
        result, category, status = failure_fields(error, 'guardian')
        detail = {'origin': 'guardian', 'phase': phase_seen, 'operation': operation,
                  'category': category, 'child_status': status}
    except KeyboardInterrupt:
        result = 130
        detail = {'origin': 'guardian', 'phase': phase_seen, 'operation': operation,
                  'category': 'interrupted', 'child_status': None}
    except Exception:
        result = 1
        detail = {'origin': 'guardian', 'phase': phase_seen, 'operation': operation,
                  'category': 'exception', 'child_status': None}
    finally:
        if child is not None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except BaseException:
                children_absent = False
            try:
                child.wait(timeout=10)
            except BaseException:
                children_absent = False
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=3)
                except BaseException:
                    pass
        try:
            containment()
            # Cgroup pseudo-files report zero stat size. Read this one fixed
            # kernel file with a separate byte bound, never regular-file logic.
            contained = children_absent and guardian_processes() <= {str(os.getpid()).encode()}
        except BaseException:
            pass
        try:
            # Serialization/validation trouble can only degrade the diagnostic or
            # clear `contained`; the primary code is captured above, before containment.
            record = final_record(value['nonce'], result, contained, detail, phase_seen)
            result = record['code']
            atomic(ROOT / 'result.json', record)
        except BaseException:
            # The host cannot claim success without this exact receipt.
            contained = False
    # Secondary cleanup never overwrites the primary result. An uncontained
    # success is still operational failure and cannot become clean acceptance.
    return result if result else (0 if contained else 1)


_WORKER = None


class WorkerStatus:
    """Sole writer of root-private worker-status.json.

    Ownership is the exclusive create (claim). A collision or earlier binding
    failure writes nothing, so an incumbent's checkpoint is never replaced. Each
    checkpoint is committed BEFORE its operation; a write failure stops that
    operation. The status never carries ``contained`` or any receipt.
    """
    def __init__(self, nonce):
        self.nonce, self.seq = nonce, 0
        self.phase, self.operation = 'startup', 'worker-binding'

    def record(self, state, seq, phase, operation, code=None, detail=None):
        return worker_status({'schema': 1, 'nonce': self.nonce, 'seq': seq, 'state': state,
                              'phase': phase, 'operation': operation, 'code': code,
                              'diagnostic': detail}, self.nonce)

    def claim(self):
        exclusive(ROOT / 'worker-status.json', encoded(self.record('running', 0, self.phase, self.operation)))

    def mark(self, phase, operation):
        # Validate the pair first so an unreviewed label can never be committed.
        record = self.record('running', self.seq + 1, phase, operation)
        self.seq, self.phase, self.operation = record['seq'], phase, operation
        try:
            atomic(ROOT / 'worker-status.json', record)
        except Exception:
            raise Failure('worker checkpoint unavailable', 1, 'status-invalid') from None

    def finish(self, error):
        if error is None:
            record = self.record('succeeded', self.seq + 1, self.phase, self.operation, 0, dict(SUCCESS))
        else:
            code, category, status = failure_fields(error, 'worker')
            detail = {'origin': 'worker', 'phase': self.phase, 'operation': self.operation,
                      'category': category, 'child_status': status}
            record = self.record('failed', self.seq + 1, self.phase, self.operation, code, detail)
        atomic(ROOT / 'worker-status.json', record)


def mark(phase, operation):
    """Commit the next fixed checkpoint; a no-op outside a claimed worker run."""
    if _WORKER is not None:
        _WORKER.mark(phase, operation)


def installed(clock):
    raw = run(['/usr/bin/dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n'], clock, 'stage')
    result = {}
    for line in raw.decode().splitlines():
        row = line.split('\t')
        if len(row) == 3 and row[2] == 'installed':
            require(row[0] not in result)
            result[row[0]] = row[1]
    return result


def auxiliary_plan(raw, before):
    plan = {}
    for line in raw.decode().splitlines():
        require(not line.startswith(('Remv ', 'Purg ')), 'auxiliary removal refused')
        if line.startswith('Inst '):
            match = re.fullmatch(r'Inst ([a-z0-9][a-z0-9+.-]*)(?: \[[^\]]+\])? \(([^ ]+) .+\)', line)
            require(match is not None, 'auxiliary simulation refused')
            name, version = match[1], match[2]
            require(name not in plan and name not in before and len(plan) < 64,
                    'auxiliary upgrades/duplicate/closure refused')
            plan[name] = version
    return plan


def provision_aux(clock):
    """Reuse authenticated fixed Ubuntu APT setup, preserving satisfactory stock.

    Selected auxiliary full versions are candidate facts, never recovered pins.
    No source edits, global upgrade, removals, downgrades or repair are allowed.
    """
    mark('stage', 'aux-inventory')
    import qemu_offline
    before = installed(clock)
    mark('stage', 'aux-audit')
    require(not run(['/usr/bin/dpkg', '--audit'], clock, 'stage').strip())
    mark('stage', 'aux-holds')
    require(not run(['/usr/bin/apt-mark', 'showhold'], clock, 'stage').strip())
    mark('stage', 'aux-setup')
    # APT's _apt traversal needs a deliberately public empty working directory;
    # private FAB/receipts stay outside it. No credentials enter this directory.
    public_apt = APT_TMP / ('labapp-vlab-aux-' + str(os.getpid()))
    public_apt.mkdir(mode=0o755)
    apt, config = qemu_offline.setup(public_apt, AUX_SNAPSHOT)
    # The guardian's private umask must not make native _apt fall back to root.
    # Only this new public, credential-free APT tree is traversable; ROOT/FAB
    # remain0700/0600. Existing unchanged installers run with explicit022 below.
    for name in ('lists', 'lists/partial', 'archives', 'archives/partial', 'parts', 'preferences'):
        (public_apt / name).chmod(0o755)
    for name in ('fixed.conf', 'sources.list'):
        (public_apt / name).chmod(0o644)
    apt_env = dict(ENV, APT_CONFIG=config)
    def apt_run(args):
        code, out = call_bounded(args, min(180, clock.remaining('stage')), apt_env)
        if code:
            raise child_failure(code, 'authenticated auxiliary APT refused')
        return out
    try:
        mark('stage', 'aux-update')
        apt_run([*apt, '-o', 'APT::Update::Error-Mode=any', 'update'])
        mark('stage', 'aux-check')
        apt_run([*apt, 'check'])
        mark('stage', 'aux-simulate')
        missing = [name for name in AUX if name not in before]
        simulate = [*apt, '--simulate', '--no-remove', '--no-install-recommends', 'install', *missing]
        plan = auxiliary_plan(apt_run(simulate), before) if missing else {}
        require(set(missing) <= set(plan), 'auxiliary closure missing requirements')
        # Pin EVERY selected dependency before mutation. Re-simulate this exact
        # closure, so solver drift or an unexpected additional dependency fails.
        selected = [name + '=' + version for name, version in sorted(plan.items())]
        mark('stage', 'aux-simulate-exact')
        if selected:
            require(auxiliary_plan(apt_run([*apt, '--simulate', '--no-remove', '--no-install-recommends',
                                             'install', *selected]), before) == plan)
            mark('stage', 'aux-download')
            apt_run([*apt, '--download-only', '--yes', '--no-remove', '--no-install-recommends', 'install', *selected])
        mark('stage', 'aux-files')
        files = qemu_offline.inventory(public_apt)
        receipt = {'schema': 1, 'snapshot': AUX_SNAPSHOT, 'before': before, 'closure': plan,
                   'sources_sha256': sha(regular(public_apt / 'sources.list', 16384)), 'files': files}
        exclusive(ROOT / 'aux-intent.json', encoded(receipt))
        mark('stage', 'aux-install')
        if selected:
            apt_run([*apt, '--no-download', '--yes', '--no-remove', '--no-install-recommends', 'install', *selected])
        mark('stage', 'aux-postcheck')
        apt_run([*apt, 'check'])
        require(not run(['/usr/bin/dpkg', '--audit'], clock, 'stage').strip())
        after = installed(clock)
        require(all(after.get(n) == v for n, v in before.items())
                and {n: v for n, v in after.items() if n not in before} == plan,
                'auxiliary transaction drift')
        require(all(n in after for n in AUX))
        exclusive(ROOT / 'aux-receipt.json', encoded(dict(receipt, after=after, audit='clean')))
    finally:
        # Only fixed APT-created names, checked by the existing bounded protocol;
        # never recursive discovery of arbitrary host paths.
        import shutil
        primary = sys.exc_info()[1]
        try:
            if primary is None:
                # Never relabel the operation of a failure already in flight.
                mark('stage', 'aux-cleanup')
            shutil.rmtree(public_apt)
        except BaseException:
            if primary is not None:
                primary.cleanup_uncertain = True
            else:
                raise Failure('auxiliary APT cleanup unverified') from None


def package_receipt(clock, core):
    selected = installed(clock)
    packages = {n: selected[n] for n in set(core.PACKAGE_PINS) | set(core.AUX.values())}
    commands = {}
    for name in set(core.AUX) | set(core.TOOL_PINS):
        path = Path(name).resolve(strict=True)
        info = path.stat()
        require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == (0o4755 if name == '/usr/bin/sudo' else 0o755))
        raw = regular(path, 180 * 1024**2, 0)
        commands[name] = {'resolved': str(path), 'sha256': sha(raw)}
    value = {'schema': 1, 'source_sha256': sha(regular(ROOT / 'manifest.json', MAX_SOURCE, 0)),
             'packages': packages, 'commands': commands}
    core.verify_prerequisites(value, time.monotonic() + min(120, clock.remaining('stage')))
    exclusive(ROOT / 'packages.json', encoded(value))
    return value


def set_phase(clock, name):
    clock.remaining(name)
    atomic(ROOT / 'phase.json', {'phase': name})


def docker_account(clock):
    """Fixed dedicated-guest adaptation, never an arbitrary account/group tool."""
    mark('stage', 'docker-account')
    user = pwd.getpwnam('ubuntu')
    group = grp.getgrnam('docker')
    require(user.pw_uid >= 1000 and user.pw_gid != 0 and user.pw_dir == '/home/ubuntu'
            and user.pw_shell == '/bin/bash' and group.gr_gid > 0
            and all(member == 'ubuntu' for member in group.gr_mem), 'unexpected account/group policy')
    before = (user.pw_uid, user.pw_gid, group.gr_gid)
    original = data(regular(ROOT / 'account-intent.json', 4096, 0))
    require(original == {'uid': user.pw_uid, 'gid': user.pw_gid, 'home': user.pw_dir},
            'dedicated account identity changed')
    # Package-created group identity is checked against its socket after start.
    run(['/usr/sbin/usermod', '--append', '--groups', 'docker', 'ubuntu'], clock, 'stage')
    after_user, after_group = pwd.getpwnam('ubuntu'), grp.getgrnam('docker')
    require((after_user.pw_uid, after_user.pw_gid, after_group.gr_gid) == before
            and after_group.gr_mem == ['ubuntu'], 'account adaptation changed identity')
    mark('stage', 'docker-socket')
    socket = Path('/run/docker.sock').lstat()
    require(stat.S_ISSOCK(socket.st_mode) and socket.st_uid == 0 and socket.st_gid == group.gr_gid
            and stat.S_IMODE(socket.st_mode) == 0o660, 'Docker socket policy refused')
    # runuser starts a NEW credential context and obtains supplementary groups;
    # existing SSH processes are never assumed to have gained docker membership.
    mark('stage', 'docker-fresh-groups')
    actual = run(['/usr/bin/id', '-G'], clock, 'stage', user=True).decode().split()
    require(str(group.gr_gid) in actual and '0' not in actual, 'fresh ubuntu groups refused')
    mark('stage', 'docker-daemons')
    for unit, executable in (('docker.service', '/usr/bin/dockerd'), ('containerd.service', '/usr/bin/containerd')):
        rows = run([SYSTEMCTL, 'show', unit, '-p', 'MainPID', '-p', 'ActiveState'], clock, 'stage')
        fields = dict(line.split('=', 1) for line in rows.decode().splitlines())
        require(fields.get('ActiveState') == 'active' and re.fullmatch('[1-9][0-9]{0,9}', fields.get('MainPID', '')))
        proc = Path('/proc') / fields['MainPID']
        require(os.readlink(proc / 'exe') == executable
                and next(row for row in (proc / 'status').read_text().splitlines() if row.startswith('Uid:')).split()[1:] == ['0'] * 4,
                'daemon process identity refused')
    mark('stage', 'docker-access')
    require(run(['/usr/bin/docker', 'info', '--format', '{{.ServerVersion}}'], clock, 'stage', user=True).strip() == b'29.1.3',
            'daemon version/access refused')
    exclusive(ROOT / 'account-receipt.json', encoded({'uid': user.pw_uid, 'gid': user.pw_gid,
              'docker_gid': group.gr_gid, 'socket_mode': '0660', 'fresh_ubuntu_access': True}))


def bounded_allocations(paths, clock, phase):
    """Offline inode/physical allocation observations, never against live disks."""
    pending = list(paths)
    seen = set()
    count, allocated, logical = 0, 0, 0
    while pending:
        clock.remaining(phase)
        path = pending.pop()
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode) and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)),
                'offline allocation special path refused')
        inode = (info.st_dev, info.st_ino)
        require(inode not in seen, 'allocation hardlink/mount overlap refused')
        seen.add(inode)
        count += 1
        require(count <= 16384, 'allocation observation count bound')
        allocated += info.st_blocks * 512
        logical += info.st_size
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    require(len(pending) + count < 16384, 'allocation observation count bound')
                    pending.append(Path(entry.path))
    return {'files': count, 'allocated_bytes': allocated, 'logical_bytes': logical}


def offline_observations(core, clock, complete=False):
    # Public core stop must have completed before complete=True. No qemu-img
    # probe, recursive walk or backing-chain observation runs on live disks.
    phase = 'resume' if complete else 'stage'
    staging = bounded_allocations([ROOT, core.CACHE, core.WORK / 'result'], clock, phase)
    require(staging['allocated_bytes'] <= 160 * GIB, 'staging/cache cap exceeded')
    record = {'staging': staging, 'cold_preboot_complete': False, 'images': {}}
    if complete:
        for name, kind in sorted(core.VMS.items()):
            clock.remaining(phase)
            path = core.WORK / 'vlab/vms' / name / 'os.img'
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            image = data(run(['/usr/bin/qemu-img', 'info', '--output=json', str(path)], clock, phase, 10))
            require(image.get('format') in ('raw', 'qcow2') and not image.get('backing-filename')
                    and not image.get('full-backing-filename')
                    and image.get('virtual-size') == core.SIZES[kind]['disk'] * GIB,
                    'offline selected image/chain refused')
            record['images'][name] = {'format': image['format'], 'virtual_bytes': image['virtual-size'],
                                     'allocated_bytes': info.st_blocks * 512, 'backing_chain': []}
        require(len(record['images']) == 18)
        record['offline_after_stop_complete'] = True
    exclusive(ROOT / ('offline-images.json' if complete else 'prestart-observation.json'), encoded(record))


def core_call(action, clock, phase, extra=(), cap=2700):
    return run([PYTHON, str(ROOT / 'vlab_core.py'), action, *extra], clock, phase, cap)


def worker():
    global _WORKER
    value = contract(data(regular(ROOT / 'contract.json', MAX_SOURCE, 0)))
    started = data(regular(ROOT / 'started.json', 4096, 0))
    # Identity of the original guardian child BEFORE any write. A failure here, or
    # a claim collision, leaves an incumbent's worker-status.json untouched.
    require(started['lease'] == value['lease'] and started['nonce'] == value['nonce']
            and started['boot'] == value['boot_uuid'] and started['guardian_pid'] == os.getppid(),
            'worker requires original active guardian')
    require(own_cgroup() == '0::/system.slice/' + UNIT, 'worker requires original active guardian cgroup')
    status = WorkerStatus(value['nonce'])
    status.claim()
    _WORKER = status
    try:
        try:
            code = provision(value)
        except BaseException as error:
            try:
                status.finish(error)
            except BaseException:
                pass  # the primary failure stays primary
            raise
        status.finish(None)
        return code
    finally:
        _WORKER = None


INSTALL_OPERATIONS = {'install-qemu.py': 'install-qemu', 'install-docker.py': 'install-docker',
                      'install-hhfab.py': 'install-hhfab', 'install-kubectl.py': 'install-kubectl'}


def provision(value):
    clock = Clock(value)
    require(own_cgroup() == '0::/system.slice/' + UNIT, 'worker requires original active guardian cgroup')
    if auth_armed():
        # Defense in depth behind the guardian gate: provisioning needs the verified credential.
        mark('stage', 'auth-check')
        auth_verify(value)
    mark('stage', 'account-policy')
    set_phase(clock, 'stage')
    user = pwd.getpwnam('ubuntu')
    require(user.pw_uid >= 1000 and user.pw_gid != 0 and user.pw_dir == '/home/ubuntu'
            and user.pw_shell == '/bin/bash')
    try:
        grp.getgrnam('docker')
    except KeyError:
        pass
    else:
        raise Failure('preexisting docker group refused')
    exclusive(ROOT / 'account-intent.json', encoded({'uid': user.pw_uid, 'gid': user.pw_gid, 'home': user.pw_dir}))
    # Record exact ownership BEFORE package scripts may start these new daemons.
    # A stock/preexisting installation is refused, never adopted or stopped.
    mark('stage', 'daemon-absent-check')
    for name in ('docker.socket', 'docker.service', 'containerd.service'):
        code, raw = call_bounded([SYSTEMCTL, 'show', name, '-p', 'LoadState'], min(10, clock.remaining('stage')))
        require(code in (0, 1, 5))
        require(raw == b'LoadState=not-found\n', 'preexisting daemon refused')
    exclusive(ROOT / 'daemon-intent.json', encoded({'units': ['docker.socket', 'docker.service', 'containerd.service']}))
    provision_aux(clock)
    for script, args, cap in (
            ('install-qemu.py', ['--selection', 'baseline-20260114'], 235),
            ('install-docker.py', ['--receipt', str(ROOT / 'docker-receipt.json')], 235),
            ('install-hhfab.py', ['--version', '0.43.1', '--archive', str(ROOT / 'hhfab.tar.gz')], 125),
            ('install-kubectl.py', ['--version', '1.35.0', '--platform', 'linux/amd64', '--binary', str(ROOT / 'kubectl')], 30)):
        mark('stage', INSTALL_OPERATIONS[script])
        previous = os.umask(0o022)
        try:
            out = run([PYTHON, str(ROOT / script), *args], clock, 'stage', cap)
        finally:
            os.umask(previous)
        exclusive(ROOT / (script + '.receipt'), out)
    mark('stage', 'sudo-check')
    require(pwd.getpwnam('ubuntu').pw_dir == '/home/ubuntu')
    run(['/usr/bin/sudo', '-n', '/usr/bin/true'], clock, 'stage', user=True)
    mark('stage', 'daemon-start')
    run([SYSTEMCTL, 'start', 'containerd.service', 'docker.service'], clock, 'stage', 30)
    docker_account(clock)
    guest_devices()
    mark('stage', 'parser-check')
    import yaml
    require(yaml.__version__.startswith('6.0') and getattr(yaml, '__with_libyaml__', False)
            and hasattr(yaml, 'CSafeLoader'), 'distribution parser refused')
    mark('stage', 'core-load')
    core = load_sibling('vlab_core')
    mark('stage', 'fab-validate')
    core.validate_fab(regular(ROOT / 'fab.yaml', MAX_SOURCE, 0))
    mark('stage', 'package-receipt')
    receipt = package_receipt(clock, core)
    mark('stage', 'core-contract')
    core_contract = {'schema': 1, 'dedicated_guest': True, 'nonce': value['nonce'],
                     'fab': str(ROOT / 'fab.yaml'), 'fab_sha256': sha(regular(ROOT / 'fab.yaml', MAX_SOURCE, 0)),
                     'wiring': str(ROOT / 'wiringd.yaml'), 'wiring_sha256': core.WIRING_SHA,
                     'package_receipt': str(ROOT / 'packages.json'), 'package_receipt_sha256': sha(encoded(receipt)),
                     'candidate_policy': {'bridge': '172.30.0.2/21', 'netfilter': 'all-three-off',
                                          'forwarded_ports': '0.0.0.0-isolated-by-route', 'build': 'iso',
                                          'controls_restricted': True, 'servers_restricted': True}}
    exclusive(ROOT / 'core-contract.json', encoded(core_contract))
    mark('stage', 'resource-check')
    resources(poststage=True)
    mark('stage', 'core-prepare')
    core_call('prepare', clock, 'stage', ['--input', str(ROOT / 'core-contract.json')], 120)
    mark('stage', 'prestart-audit')
    offline_observations(core, clock)
    if auth_armed():
        auth_verify(value)  # config and absence of fallback stores re-proved immediately before acquisition
    # A phase transition is labelled with the first operation of the new phase.
    mark('fresh', 'core-start-fresh')
    set_phase(clock, 'fresh')
    core_call('start-fresh', clock, 'fresh')
    if auth_armed():
        # Acquisition is complete: remove and positively verify absence BEFORE strict checks,
        # stop, resume or success. A failure here is the primary failure; guardian retries.
        mark('fresh', 'auth-remove')
        auth_remove()
        auth_absent()
        exclusive(ROOT / AUTH_REMOVED, encoded({'schema': 1, 'nonce': value['nonce']}))
    mark('strict', 'strict-inspect')
    set_phase(clock, 'strict')
    before = strict_checks(core, clock, 'strict')
    nonce = Nonce(core, clock, value['nonce'])
    nonce.create()
    mark('resume', 'core-stop')
    set_phase(clock, 'resume')
    core_call('stop', clock, 'resume', cap=70)
    mark('resume', 'offline-audit')
    offline_observations(core, clock, complete=True)
    mark('resume', 'core-activate-resume')
    core_call('activate-resume', clock, 'resume', cap=120)
    mark('resume', 'core-start-resume')
    if auth_armed():
        auth_absent()  # resume must never see recreated credentials
    core_call('start-resume', clock, 'resume', cap=900)
    mark('persistence', 'strict-inspect')
    set_phase(clock, 'persistence')
    require(strict_checks(core, clock, 'persistence') == before, 'cluster identity changed')
    nonce.verify()
    nonce.remove()
    mark('persistence', 'core-final-stop')
    core_call('stop', clock, 'persistence', cap=70)
    mark('persistence', 'complete')
    exclusive(ROOT / 'success.json', encoded({'schema': 1, 'nonce': value['nonce'], 'cluster': before}))
    return 0


def guest_devices():
    # Fixed real device opens; no broad chmod/group repair. Failure preserves
    # the actual unsupported stock account/device policy for lead review.
    import fcntl
    for path, operation in (('/dev/kvm', 'kvm-device'), ('/dev/net/tun', 'tun-device')):
        mark('stage', operation)
        try:
            mode = Path(path).stat().st_mode
        except FileNotFoundError:
            # Explicit local capability check; any other OSError stays `exception`.
            raise Failure('device absent', 1, 'capability') from None
        require(stat.S_ISCHR(mode), 'device type refused', 'capability')
        fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
        try:
            if path == '/dev/kvm':
                require(fcntl.ioctl(fd, 0xAE00, 0) == 12, 'KVM API refused', 'capability')
        finally:
            os.close(fd)


def core_failure(error, message):
    """Reduce an in-process core Failure by its FIXED message literals only.

    The core folds a signal-killed child into status 1, so a status is reported
    only when it is unambiguous (2..255). Message text is never copied out.
    """
    text = str(error)
    code = getattr(error, 'code', 1)
    status = None
    if text == 'child command failed':
        status = code if type(code) is int and 2 <= code <= 255 else None
        category = 'child-exit' if status is not None else 'core-refusal'
    elif text == 'child deadline exceeded':
        category = 'child-timeout'
    elif text == 'deadline exceeded':
        category = 'phase-cutoff'
    else:
        category = 'core-refusal'
    failure = Failure(message, code, category, status)
    failure.cleanup_uncertain = bool(getattr(error, 'cleanup_uncertain', False))
    return failure


def strict_checks(core, clock, phase):
    end = time.monotonic() + clock.remaining(phase)
    try:
        mark(phase, 'strict-inspect')
        core.hhfab(['vlab', 'inspect-switches'], end, ['--strict=true', '--wait-applied-for', '30'], cap=600)
        # Real fixed SSH operation, with no interactive shell or arbitrary command.
        mark(phase, 'strict-ssh')
        core.hhfab(['vlab', 'ssh'], end, ['-n', 'server-01', '--', 'true'], cap=30)
        mark(phase, 'api-ready')
        return core.api_ready(end)
    except core.Failure as error:
        raise core_failure(error, 'core strict check refused') from None


class Nonce:
    """Only two locator-named default-namespace objects; exact UID preconditions.

    The name is a deterministic RFC1123 locator of at most 11 characters, which
    the pinned Fabric VPC webhook admits; it can collide and is NEVER ownership
    authority. Ownership is the full nonce annotation on both objects plus the
    receipt UID and expected spec, checked on every read.
    """
    ANNOTATION = 'labapp.hedgehog.com/trial-nonce'

    def __init__(self, core, clock, nonce):
        require(re.fullmatch('[a-f0-9]{32}', nonce))
        self.core, self.clock = core, clock
        self.nonce = nonce
        self.name = 'l' + hashlib.sha256(nonce.encode()).hexdigest()[:10]
        self.objects = []

    def owned(self, doc, obj):
        """Exact annotation, name/namespace, UID and spec; never adopt by name alone."""
        meta = doc.get('metadata') if isinstance(doc, dict) else None
        annotations = meta.get('annotations') if isinstance(meta, dict) else None
        require(isinstance(meta, dict) and meta.get('name') == self.name and meta.get('namespace') == 'default'
                and isinstance(annotations, dict) and annotations.get(self.ANNOTATION) == self.nonce
                and meta.get('uid') == obj['uid'] and doc.get('spec') == obj['spec'], 'nonce ownership differs')

    def call(self, args, phase):
        try:
            return self.core.kubectl(args, time.monotonic() + self.clock.remaining(phase))
        except self.core.Failure as error:
            raise core_failure(error, 'nonce API operation refused') from None

    def current(self, resource, phase):
        raw = self.call(['get', resource, self.name, '-n', 'default', '--ignore-not-found', '-o', 'json'], phase)
        return data(raw) if raw.strip() else None

    def create(self):
        mark('strict', 'nonce-create')
        for resource in ('vpcs.vpc.githedgehog.com', 'vpcattachments.vpc.githedgehog.com'):
            require(self.current(resource, 'strict') is None, 'nonce collision')
        existing = data(self.call(['get', 'vpcs.vpc.githedgehog.com', '-A', '-o', 'json'], 'strict'))
        require(len(existing['items']) <= 128)
        import ipaddress
        for obj in existing['items']:
            for subnet in obj.get('spec', {}).get('subnets', {}).values():
                require(not ipaddress.ip_network(subnet['subnet']).overlaps(ipaddress.ip_network('10.0.254.0/24'))
                        and subnet.get('vlan') != 2998, 'fixed nonce subnet/VLAN occupied')
        specs = [('vpcs.vpc.githedgehog.com', 'VPC', {'ipv4Namespace': 'default', 'vlanNamespace': 'default',
                 'subnets': {'trial': {'subnet': '10.0.254.0/24', 'vlan': 2998}}}),
                 ('vpcattachments.vpc.githedgehog.com', 'VPCAttachment',
                  {'connection': 'server-01--mclag--leaf-01--leaf-02', 'subnet': self.name + '/trial'})]
        for resource, kind, spec in specs:
            doc = {'apiVersion': 'vpc.githedgehog.com/v1beta1', 'kind': kind,
                   'metadata': {'name': self.name, 'namespace': 'default',
                                'annotations': {self.ANNOTATION: self.nonce}}, 'spec': spec}
            path = ROOT / (kind + '.json')
            exclusive(path, encoded(doc))
            # kubectl executes as ubuntu; give it a private owner copy via the
            # already private core work directory, never expose root staging.
            target = self.core.WORK / (kind + '-trial.json')
            exclusive(target, encoded(doc))
            user = pwd.getpwnam('ubuntu')
            os.chown(target, user.pw_uid, user.pw_gid)
            try:
                result = data(self.call(['create', '-f', str(target), '-o', 'json'], 'strict'))
                annotations = result['metadata'].get('annotations')
                require(result['metadata']['name'] == self.name and result['metadata']['namespace'] == 'default'
                        and result['kind'] == kind and result['apiVersion'] == doc['apiVersion']
                        and type(result['metadata']['uid']) is str and result['metadata']['uid']
                        and isinstance(annotations, dict) and annotations.get(self.ANNOTATION) == self.nonce,
                        'nonce create response not owned')
                if kind == 'VPC':
                    observed = result['spec']
                    require(observed.get('ipv4Namespace') == 'default' and observed.get('vlanNamespace') == 'default'
                            and observed['subnets']['trial']['subnet'] == '10.0.254.0/24'
                            and observed['subnets']['trial']['vlan'] == 2998, 'nonce admission changed fixed fields')
                else:
                    require(all(result['spec'].get(k) == v for k, v in spec.items()), 'attachment admission changed fixed fields')
                self.objects.append({'resource': resource, 'name': self.name, 'nonce': self.nonce,
                                     'uid': result['metadata']['uid'], 'spec': result['spec']})
                atomic(ROOT / 'nonce-receipt.json', self.objects)
            finally:
                primary = sys.exc_info()[1]
                try:
                    target.unlink()
                except BaseException:
                    if primary is not None:
                        primary.cleanup_uncertain = True
                    else:
                        error = Failure('nonce input cleanup uncertain')
                        error.cleanup_uncertain = True
                        raise error

    def verify(self):
        mark('persistence', 'nonce-verify')
        for obj in self.objects:
            current = self.current(obj['resource'], 'persistence')
            require(current is not None, 'nonce persistence differs')
            self.owned(current, obj)

    def remove(self):
        self.verify()
        mark('persistence', 'nonce-remove')
        for obj in reversed(self.objects):
            plural = obj['resource'].split('.')[0]
            options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': obj['uid']}}
            target = self.core.WORK / (plural + '-delete-trial.json')
            exclusive(target, encoded(options))
            user = pwd.getpwnam('ubuntu')
            os.chown(target, user.pw_uid, user.pw_gid)
            try:
                # Attachment deletion/polling can outlive the initial verify.
                # Re-read each object immediately before its own DELETE.
                current = self.current(obj['resource'], 'persistence')
                require(current is not None, 'nonce persistence differs')
                self.owned(current, obj)
                self.call(['delete', '--raw=/apis/vpc.githedgehog.com/v1beta1/namespaces/default/' + plural + '/' + self.name,
                           '-f', str(target)], 'persistence')
            finally:
                primary = sys.exc_info()[1]
                try:
                    target.unlink()
                except BaseException:
                    if primary is not None:
                        primary.cleanup_uncertain = True
                    else:
                        error = Failure('nonce input cleanup uncertain')
                        error.cleanup_uncertain = True
                        raise error
            while True:
                current = self.current(obj['resource'], 'persistence')
                if current is None:
                    break
                self.owned(current, obj)
                time.sleep(min(1, self.clock.remaining('persistence')))


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('action', choices=('bootstrap', 'guardian', 'worker', 'heartbeat', 'contain', 'export-failure'))
    parser.add_argument('--incoming', type=Path)
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--nonce')
    parser.add_argument('--sequence', type=int)
    args = parser.parse_args(argv)
    require(os.geteuid() == 0, 'root required')
    os.umask(0o077)
    if args.action == 'bootstrap':
        require(args.incoming is not None and args.manifest_sha256 is not None
                and args.nonce is None and args.sequence is None)
        bootstrap(args.incoming, args.manifest_sha256)
    elif args.action == 'heartbeat':
        require(args.incoming is None and args.manifest_sha256 is None)
        heartbeat(args.nonce, args.sequence)
    elif args.action == 'export-failure':
        require(args.incoming is None and args.manifest_sha256 is None and args.sequence is None)
        try:
            out = export_failure(args.nonce)
        except Exception:
            out = b'invalid'  # fixed token; never text from the failure or any path
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
    else:
        require(all(v is None for v in (args.incoming, args.manifest_sha256, args.nonce, args.sequence)))
        return {'guardian': guardian, 'worker': worker, 'contain': containment}[args.action]() or 0
    return 0


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise Failure('signal', 143 if signum == signal.SIGTERM else 130, 'interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        sys.exit(main())
    except Failure as error:
        print('vlab-trial: refused', file=sys.stderr)
        sys.exit(error.code)
    except Exception:
        print('vlab-trial: operational failure', file=sys.stderr)
        sys.exit(1)
