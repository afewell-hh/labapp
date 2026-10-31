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
import grp
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
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
        'vlab_trial.py', 'labapp-vlab-trial.service', 'vlab_core.py',
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
    def __init__(self, message='fixed trial refused', code=1):
        super().__init__(message)
        self.code = code


def require(condition, message='fixed trial refused'):
    if not condition:
        raise Failure(message)


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
              'external': {'interface': 'enp2s0', 'ip': 'dhcp'}, 'management': {'interface': 'enp2s1', 'ip': '172.30.0.5/21'}}}]
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


def regular(path, limit, uid=None):
    path = no_links(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_size <= limit and (uid is None or info.st_uid == uid),
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
            raise Failure('absolute phase cutoff', 124)
        return left

    def cleanup_remaining(self):
        end = stamp(self.value['deadline'])
        left = min(end - self.wall(), end - self.started_wall - (self.mono() - self.started_mono))
        if left <= 0:
            raise Failure('immutable cleanup cutoff', 124)
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


def run(argv, clock, phase, cap=30, user=False):
    # Existing bounded implementation caps output and kills/reaps exact process
    # groups. The guardian additionally contains independent systemd services.
    from hhfab_release import bounded, Refusal
    args = [str(a) for a in argv]
    if user:
        args = ['/usr/sbin/runuser', '-u', 'ubuntu', '--', *args]
    try:
        code, out = bounded(args, min(cap, clock.remaining(phase)), limit=1024**2, env=ENV)
    except Refusal as error:
        raise Failure('bounded child failed', 124 if 'timeout' in str(error) else 1) from None
    if code:
        raise Failure('fixed child failed', code if code > 0 else 128 - code)
    return out


def bootstrap(incoming, expected_manifest):
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
    ROOT.mkdir(mode=0o700)
    for name, item in table['files'].items():
        raw = regular(incoming / name, item['bytes'], uid)
        require(len(raw) == item['bytes'] and sha(raw) == item['sha256'])
        exclusive(ROOT / name, raw)
    exclusive(ROOT / 'manifest.json', encoded(table))
    exclusive(ROOT / 'phase.json', encoded({'phase': 'stage'}))
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
    except BaseException:
        # The fixed unit's ExecStopPost owns containment even if startup reply
        # was lost. Do not delete the reservation or retry a bootstrap.
        try:
            run([SYSTEMCTL, 'stop', UNIT], clock, 'stage', 30)
        except BaseException:
            pass
        raise


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
            and mem >= (96 if poststage else 16) * GIB, 'resource stop')
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
    require(ok, 'exact service containment uncertain')


def guardian():
    value = contract(data(regular(ROOT / 'contract.json', MAX_SOURCE, 0)))
    clock = Clock(value)
    require(kernel_boot() == value['boot_uuid'])
    # EXCL start reservation prevents restart/reset/renewal, including after reboot.
    exclusive(ROOT / 'started.json', encoded({'boot': value['boot_uuid'], 'lease': value['lease'],
              'nonce': value['nonce'], 'guardian_pid': os.getpid(), 'remaining': clock.remaining('stage')}))
    original_oom = oom_count()
    child = None
    result = 1
    contained = False
    children_absent = True
    try:
        # Initial heartbeat grace is bounded by the same thirty-second loss
        # window; no provisioning starts before the guardian checks it.
        beat = data(regular(ROOT / 'heartbeat.json', 4096, 0))
        require(0 <= time.monotonic() - beat['received'] <= 30)
        child = subprocess.Popen([PYTHON, str(ROOT / 'vlab_trial.py'), 'worker'],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, env=ENV, start_new_session=True)
        minimum = None
        while True:
            phase = data(regular(ROOT / 'phase.json', 4096, 0))['phase']
            clock.remaining(phase)
            require(kernel_boot() == value['boot_uuid'])
            beat = data(regular(ROOT / 'heartbeat.json', 4096, 0))
            require(0 <= time.monotonic() - beat['received'] <= 30, 'heartbeat lost')
            require(oom_count() == original_oom, 'OOM event')
            sample = resources()
            minimum = sample if minimum is None else {k: min(v, minimum[k]) for k, v in sample.items()}
            atomic(ROOT / 'measurements.json', minimum)
            observed = child.poll()
            if observed is not None:
                result = observed if observed >= 0 else 128 - observed
                break
            time.sleep(min(5, clock.remaining(phase)))
    except Failure as error:
        result = error.code
    except KeyboardInterrupt:
        result = 130
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
            atomic(ROOT / 'result.json', {'schema': 1, 'code': result,
                                         'contained': contained, 'nonce': value['nonce']})
        except BaseException:
            # The host cannot claim success without this exact receipt.
            contained = False
    # Secondary cleanup never overwrites the primary result. An uncontained
    # success is still operational failure and cannot become clean acceptance.
    return result if result else (0 if contained else 1)


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
    import qemu_offline
    before = installed(clock)
    require(not run(['/usr/bin/dpkg', '--audit'], clock, 'stage').strip())
    require(not run(['/usr/bin/apt-mark', 'showhold'], clock, 'stage').strip())
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
    from hhfab_release import bounded
    def apt_run(args):
        code, out = bounded(args, min(180, clock.remaining('stage')), limit=1024**2, env=apt_env)
        if code:
            raise Failure('authenticated auxiliary APT refused', code if code > 0 else 128 - code)
        return out
    try:
        apt_run([*apt, '-o', 'APT::Update::Error-Mode=any', 'update'])
        apt_run([*apt, 'check'])
        missing = [name for name in AUX if name not in before]
        simulate = [*apt, '--simulate', '--no-remove', '--no-install-recommends', 'install', *missing]
        plan = auxiliary_plan(apt_run(simulate), before) if missing else {}
        require(set(missing) <= set(plan), 'auxiliary closure missing requirements')
        # Pin EVERY selected dependency before mutation. Re-simulate this exact
        # closure, so solver drift or an unexpected additional dependency fails.
        selected = [name + '=' + version for name, version in sorted(plan.items())]
        if selected:
            require(auxiliary_plan(apt_run([*apt, '--simulate', '--no-remove', '--no-install-recommends',
                                             'install', *selected]), before) == plan)
            apt_run([*apt, '--download-only', '--yes', '--no-remove', '--no-install-recommends', 'install', *selected])
        files = qemu_offline.inventory(public_apt)
        receipt = {'schema': 1, 'snapshot': AUX_SNAPSHOT, 'before': before, 'closure': plan,
                   'sources_sha256': sha(regular(public_apt / 'sources.list', 16384)), 'files': files}
        exclusive(ROOT / 'aux-intent.json', encoded(receipt))
        if selected:
            apt_run([*apt, '--no-download', '--yes', '--no-remove', '--no-install-recommends', 'install', *selected])
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
    socket = Path('/run/docker.sock').lstat()
    require(stat.S_ISSOCK(socket.st_mode) and socket.st_uid == 0 and socket.st_gid == group.gr_gid
            and stat.S_IMODE(socket.st_mode) == 0o660, 'Docker socket policy refused')
    # runuser starts a NEW credential context and obtains supplementary groups;
    # existing SSH processes are never assumed to have gained docker membership.
    actual = run(['/usr/bin/id', '-G'], clock, 'stage', user=True).decode().split()
    require(str(group.gr_gid) in actual and '0' not in actual, 'fresh ubuntu groups refused')
    for unit, executable in (('docker.service', '/usr/bin/dockerd'), ('containerd.service', '/usr/bin/containerd')):
        rows = run([SYSTEMCTL, 'show', unit, '-p', 'MainPID', '-p', 'ActiveState'], clock, 'stage')
        fields = dict(line.split('=', 1) for line in rows.decode().splitlines())
        require(fields.get('ActiveState') == 'active' and re.fullmatch('[1-9][0-9]{0,9}', fields.get('MainPID', '')))
        proc = Path('/proc') / fields['MainPID']
        require(os.readlink(proc / 'exe') == executable
                and next(row for row in (proc / 'status').read_text().splitlines() if row.startswith('Uid:')).split()[1:] == ['0'] * 4,
                'daemon process identity refused')
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
    value = contract(data(regular(ROOT / 'contract.json', MAX_SOURCE, 0)))
    clock = Clock(value)
    started = data(regular(ROOT / 'started.json', 4096, 0))
    require(started['lease'] == value['lease'] and started['nonce'] == value['nonce']
            and started['boot'] == value['boot_uuid'] and started['guardian_pid'] == os.getppid()
            and own_cgroup() == '0::/system.slice/' + UNIT,
            'worker requires original active guardian cgroup')
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
    for name in ('docker.socket', 'docker.service', 'containerd.service'):
        from hhfab_release import bounded
        code, raw = bounded([SYSTEMCTL, 'show', name, '-p', 'LoadState'], min(10, clock.remaining('stage')), env=ENV)
        require(code in (0, 1, 5))
        require(raw == b'LoadState=not-found\n', 'preexisting daemon refused')
    exclusive(ROOT / 'daemon-intent.json', encoded({'units': ['docker.socket', 'docker.service', 'containerd.service']}))
    provision_aux(clock)
    for script, args, cap in (
            ('install-qemu.py', ['--selection', 'baseline-20260114'], 235),
            ('install-docker.py', ['--receipt', str(ROOT / 'docker-receipt.json')], 235),
            ('install-hhfab.py', ['--version', '0.43.1', '--archive', str(ROOT / 'hhfab.tar.gz')], 125),
            ('install-kubectl.py', ['--version', '1.35.0', '--platform', 'linux/amd64', '--binary', str(ROOT / 'kubectl')], 30)):
        previous = os.umask(0o022)
        try:
            out = run([PYTHON, str(ROOT / script), *args], clock, 'stage', cap)
        finally:
            os.umask(previous)
        exclusive(ROOT / (script + '.receipt'), out)
    require(pwd.getpwnam('ubuntu').pw_dir == '/home/ubuntu')
    run(['/usr/bin/sudo', '-n', '/usr/bin/true'], clock, 'stage', user=True)
    run([SYSTEMCTL, 'start', 'containerd.service', 'docker.service'], clock, 'stage', 30)
    docker_account(clock)
    guest_devices()
    import yaml
    require(yaml.__version__.startswith('6.0') and getattr(yaml, '__with_libyaml__', False)
            and hasattr(yaml, 'CSafeLoader'), 'distribution parser refused')
    core = load_sibling('vlab_core')
    core.validate_fab(regular(ROOT / 'fab.yaml', MAX_SOURCE, 0))
    receipt = package_receipt(clock, core)
    core_contract = {'schema': 1, 'dedicated_guest': True, 'nonce': value['nonce'],
                     'fab': str(ROOT / 'fab.yaml'), 'fab_sha256': sha(regular(ROOT / 'fab.yaml', MAX_SOURCE, 0)),
                     'wiring': str(ROOT / 'wiringd.yaml'), 'wiring_sha256': core.WIRING_SHA,
                     'package_receipt': str(ROOT / 'packages.json'), 'package_receipt_sha256': sha(encoded(receipt)),
                     'candidate_policy': {'bridge': '172.30.0.2/21', 'netfilter': 'all-three-off',
                                          'forwarded_ports': '0.0.0.0-isolated-by-route', 'build': 'iso',
                                          'controls_restricted': True, 'servers_restricted': True}}
    exclusive(ROOT / 'core-contract.json', encoded(core_contract))
    resources(poststage=True)
    core_call('prepare', clock, 'stage', ['--input', str(ROOT / 'core-contract.json')], 120)
    offline_observations(core, clock)
    set_phase(clock, 'fresh')
    core_call('start-fresh', clock, 'fresh')
    set_phase(clock, 'strict')
    before = strict_checks(core, clock, 'strict')
    nonce = Nonce(core, clock, value['nonce'])
    nonce.create()
    set_phase(clock, 'resume')
    core_call('stop', clock, 'resume', cap=70)
    offline_observations(core, clock, complete=True)
    core_call('activate-resume', clock, 'resume', cap=120)
    core_call('start-resume', clock, 'resume', cap=900)
    set_phase(clock, 'persistence')
    require(strict_checks(core, clock, 'persistence') == before, 'cluster identity changed')
    nonce.verify()
    nonce.remove()
    core_call('stop', clock, 'persistence', cap=70)
    exclusive(ROOT / 'success.json', encoded({'schema': 1, 'nonce': value['nonce'], 'cluster': before}))
    return 0


def guest_devices():
    # Fixed real device opens; no broad chmod/group repair. Failure preserves
    # the actual unsupported stock account/device policy for lead review.
    import fcntl
    for path in ('/dev/kvm', '/dev/net/tun'):
        require(stat.S_ISCHR(Path(path).stat().st_mode))
        fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
        try:
            if path == '/dev/kvm':
                require(fcntl.ioctl(fd, 0xAE00, 0) == 12, 'KVM API refused')
        finally:
            os.close(fd)


def strict_checks(core, clock, phase):
    end = time.monotonic() + clock.remaining(phase)
    core.hhfab(['vlab', 'inspect-switches'], end, ['--strict=true', '--wait-applied-for', '30'], cap=600)
    # Real fixed SSH operation, with no interactive shell or arbitrary command.
    core.hhfab(['vlab', 'ssh'], end, ['-n', 'server-01', '--', 'true'], cap=30)
    return core.api_ready(end)


class Nonce:
    """Only two nonce-named default-namespace objects; exact UID preconditions."""
    def __init__(self, core, clock, nonce):
        require(re.fullmatch('[a-f0-9]{32}', nonce))
        self.core, self.clock = core, clock
        self.name = 'labapp-trial-' + nonce
        self.objects = []

    def call(self, args, phase):
        return self.core.kubectl(args, time.monotonic() + self.clock.remaining(phase))

    def current(self, resource, phase):
        raw = self.call(['get', resource, self.name, '-n', 'default', '--ignore-not-found', '-o', 'json'], phase)
        return data(raw) if raw.strip() else None

    def create(self):
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
                   'metadata': {'name': self.name, 'namespace': 'default'}, 'spec': spec}
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
            finally:
                target.unlink()
            require(result['metadata']['name'] == self.name and result['metadata']['namespace'] == 'default'
                    and result['kind'] == kind and result['apiVersion'] == doc['apiVersion']
                    and type(result['metadata']['uid']) is str and result['metadata']['uid'])
            if kind == 'VPC':
                observed = result['spec']
                require(observed.get('ipv4Namespace') == 'default' and observed.get('vlanNamespace') == 'default'
                        and observed['subnets']['trial']['subnet'] == '10.0.254.0/24'
                        and observed['subnets']['trial']['vlan'] == 2998, 'nonce admission changed fixed fields')
            else:
                require(all(result['spec'].get(k) == v for k, v in spec.items()), 'attachment admission changed fixed fields')
            self.objects.append({'resource': resource, 'uid': result['metadata']['uid'], 'spec': result['spec']})
            atomic(ROOT / 'nonce-receipt.json', self.objects)

    def verify(self):
        for obj in self.objects:
            current = self.current(obj['resource'], 'persistence')
            require(current is not None and current['metadata']['uid'] == obj['uid']
                    and current['spec'] == obj['spec'], 'nonce persistence differs')

    def remove(self):
        self.verify()
        for obj in reversed(self.objects):
            plural = obj['resource'].split('.')[0]
            options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': obj['uid']}}
            target = self.core.WORK / (plural + '-delete-trial.json')
            exclusive(target, encoded(options))
            user = pwd.getpwnam('ubuntu')
            os.chown(target, user.pw_uid, user.pw_gid)
            try:
                self.call(['delete', '--raw=/apis/vpc.githedgehog.com/v1beta1/namespaces/default/' + plural + '/' + self.name,
                           '-f', str(target)], 'persistence')
            finally:
                target.unlink()
            while True:
                current = self.current(obj['resource'], 'persistence')
                if current is None:
                    break
                require(current['metadata']['uid'] == obj['uid'] and current['spec'] == obj['spec'],
                        'nonce changed while awaiting deletion')
                time.sleep(min(1, self.clock.remaining('persistence')))


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('action', choices=('bootstrap', 'guardian', 'worker', 'heartbeat', 'contain'))
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
    else:
        require(all(v is None for v in (args.incoming, args.manifest_sha256, args.nonce, args.sequence)))
        return {'guardian': guardian, 'worker': worker, 'contain': containment}[args.action]() or 0
    return 0


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise Failure('signal', 143 if signum == signal.SIGTERM else 130)
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
