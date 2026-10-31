#!/usr/bin/python3
"""Fixed dedicated-guest VLAB core (Ubuntu24.04 / Python3.12 + PyYAML CSafeLoader).

Root public CLI; unit-only run starts root with systemd !, retains its mount
namespace, then initgroups/gid/uid -> ubuntu and execs pinned hhfab0.43.1.
No environment overrides, shell, installer, download or provider operations.
Cwd independent, noninteractive, fixed paths/argv/environment. Already installed
baseline .11 QEMU/tools, systemd255, sudo/KVM/TUN and private FAB are prerequisites.
Candidate addressing/service policy is NOT a recovered production configuration.
No hostile root or concurrent mutation is supported. Stop contains processes,
not guest OS shutdown. Resume never initializes, repairs, resets or rebuilds.
"""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

import owned_process

ROOT = Path('/var/lib/labapp-vlab-core')
WORK = Path('/home/ubuntu/hhfab')
CACHE = Path('/home/ubuntu/.cache/hhfab')
LIB = Path('/usr/local/lib/labapp')
UNITS = Path('/etc/systemd/system')
JOURNAL = Path('/etc/systemd/journald@labapp-vlab.conf')
JOURNAL_DROPINS = tuple(Path(prefix) / 'systemd/journald@labapp-vlab.conf.d'
                       for prefix in ('/etc', '/run', '/usr/local/lib', '/usr/lib'))
MOUNTINFO = Path('/proc/self/mountinfo')
CGROUP = Path('/sys/fs/cgroup')
ROOT_UID = 0
HHFAB = '/usr/local/bin/hhfab'
KUBECTL = '/usr/local/bin/kubectl'
PYTHON = '/usr/bin/python3'
SYSTEMCTL = '/usr/bin/systemctl'
JOURNALCTL = '/usr/bin/journalctl'
DPKG = '/usr/bin/dpkg-query'
BRIDGE = LIB / 'ensure-bridge-ipv4.py'
SAFE_ENV = {'PATH': '/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME': '/home/ubuntu', 'LC_ALL': 'C.UTF-8', 'LANG': 'C.UTF-8'}
UNIT = {'fresh': 'labapp-vlab-fresh.service', 'resume': 'hhfab-vlab-resume.service'}
LIMIT = 1024 * 1024
STATIC_LIMIT = 4 * LIMIT
TREE_FILES = 4096
TREE_BYTES = 32 * 1024**3
START_SECONDS = {'fresh': 2700, 'resume': 900}
SIZES = {'control': {'cpu': 6, 'ram': 6144, 'disk': 100},
         'switch': {'cpu': 4, 'ram': 5120, 'disk': 50},
         'server': {'cpu': 2, 'ram': 768, 'disk': 10},
         'gateway': {'cpu': 8, 'ram': 6144, 'disk': 50},
         'external': {'cpu': 4, 'ram': 5120, 'disk': 50}}
VMS = {'control-1': 'control', **{f'leaf-{n:02}': 'switch' for n in range(1, 6)},
       **{f'spine-{n:02}': 'switch' for n in range(1, 3)},
       **{f'server-{n:02}': 'server' for n in range(1, 11)}}
WIRING_SHA = 'c522c64d80515c7484a67c27646acebf86073192f0f6ff9597497b990548806a'
TOOL_PINS = {HHFAB: (170709176, 'b5c7e0265339b9b95fa1073967bfb6c6fede6086755c85eca24cb80637b04e37'),
             KUBECTL: (58597560, 'a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989')}
PACKAGE_PINS = {'qemu-system-x86': '1:8.2.2+ds-0ubuntu1.11',
                'qemu-utils': '1:8.2.2+ds-0ubuntu1.11',
                'docker-ce': '5:29.1.3-1~ubuntu.24.04~noble',
                'docker-ce-cli': '5:29.1.3-1~ubuntu.24.04~noble',
                'containerd.io': '2.2.1-1~ubuntu.24.04~noble'}
AUX = {'/usr/bin/sudo': 'sudo', '/usr/bin/qemu-img': 'qemu-utils',
       '/usr/bin/qemu-system-x86_64': 'qemu-system-x86', '/usr/bin/socat': 'socat',
       '/usr/bin/ssh': 'openssh-client', '/usr/bin/less': 'less',
       '/usr/sbin/ip': 'iproute2', SYSTEMCTL: 'systemd',
       '/usr/sbin/modprobe': 'kmod', '/usr/sbin/sysctl': 'procps',
       PYTHON: 'python3-minimal'}
# #368 first-failure bundle: fixed root-private diagnostic, never readiness authority.
FIRST_FAILURE = 'first-failure.json'
FIRST_FAILURE_LIMIT = 32 * 1024  # SERIALIZED bytes, enforced after JSON/base64 encoding
FAILURE_CAPS = {'primary': 2048, 'command_context': 2048, 'manager': 2048, 'journal': 8192}
FAILURE_CONTEXT = 'last failed command output observed before manager-wrapper overwrite/core cleanup'
SNAPSHOT_SECONDS = 10      # one shared absolute budget for BOTH queries incl. their reaping
SNAPSHOT_REAP = 1.0        # held back inside each query's end to kill/reap its child
MANAGER_SECONDS, JOURNAL_SECONDS = 2, 8
JOURNAL_NAMESPACE = 'labapp-vlab'
JOURNAL_LINES = 64
MANAGER_PROPERTIES = 'ActiveState,SubState,Result,InvocationID,ExecMainCode,ExecMainStatus,ExecMainPID'
NETFILTER = ('bridge-nf-call-iptables', 'bridge-nf-call-ip6tables', 'bridge-nf-call-arptables')
RESULT = 'control--control-1--install'
DEV_PASSWORD = '$5$8nAYPGcl4l6G7Av1$Qi4/gnM0yPtGv9kjpMh78NuNSfQWy7vR1rulHpurL36'
DEV_KEY = 'AAAAC3NzaC1lZDI1NTE5AAAAIGpF2+9I1Nj4BcN7y6DjzTbq1VcUYIRGyfzId5ZoBEFj'


class Failure(Exception):
    """Only fixed nonsecret diagnostics; never interpolate private inputs."""
    def __init__(self, message='operation refused', code=1, private_output=b''):
        super().__init__(message)
        self.code = code
        self.private_output = private_output


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Failure('invalid arguments')


class Pending(Failure):
    """Only bounded initial API discovery may poll this transient condition."""


def require(condition, message='contract refused'):
    if not condition:
        raise Failure(message)


def pairs(items):
    out = {}
    for key, value in items:
        require(key not in out, 'duplicate key')
        out[key] = value
    return out


def json_data(raw):
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Failure('invalid JSON')))
    except (ValueError, TypeError, RecursionError):
        raise Failure('invalid JSON') from None


def keys(value, required, optional=()):
    require(type(value) is dict and set(required) <= set(value)
            and set(value) <= set(required) | set(optional), 'unexpected fields')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def no_links(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'unsafe path')
    for ancestor in [*reversed(path.parents), path]:
        require(not ancestor.is_symlink(), 'symlink refused')
    return path


def stable_stat(value):
    # Reading may legitimately update atime; mutation/identity timestamps may not.
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read(path, limit=STATIC_LIMIT, private=False):
    path = no_links(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'invalid file')
        if private:
            require(before.st_uid in (0, ubuntu().pw_uid) and not before.st_mode & 0o077,
                    'private file permissions refused')
        raw = bytearray()
        while True:
            chunk = os.read(fd, min(LIMIT, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            require(len(raw) <= limit, 'file overflow')
        require(stable_stat(os.fstat(fd)) == stable_stat(before)
                and stable_stat(path.lstat()) == stable_stat(before), 'file changed')
        return bytes(raw)
    finally:
        os.close(fd)


def identity(path, hashed=False, deadline=None, limit=TREE_BYTES):
    path = no_links(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) or stat.S_ISDIR(before.st_mode), 'critical type refused')
    record = {'dev': before.st_dev, 'ino': before.st_ino, 'mode': before.st_mode,
              'uid': before.st_uid, 'gid': before.st_gid}
    if stat.S_ISREG(before.st_mode):
        record['links'] = before.st_nlink
    if hashed:
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'hash input refused')
        h = hashlib.sha256()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            require(stable_stat(os.fstat(fd)) == stable_stat(before), 'hash identity changed')
            total = 0
            while True:
                if deadline is not None:
                    remaining(deadline)
                chunk = os.read(fd, LIMIT)
                if not chunk:
                    break
                total += len(chunk)
                require(total <= limit, 'hash overflow')
                h.update(chunk)
            require(stable_stat(os.fstat(fd)) == stable_stat(before)
                    and stable_stat(path.lstat()) == stable_stat(before), 'hash input changed')
        finally:
            os.close(fd)
        record.update(size=before.st_size, sha256=h.hexdigest())
    return record


def yaml_documents(raw):
    require(len(raw) <= STATIC_LIMIT, 'YAML overflow')
    import yaml
    require(yaml.__with_libyaml__ and hasattr(yaml, 'CSafeLoader')
            and re.fullmatch(r'6\.0(?:\.[0-9]+)?', yaml.__version__), 'distribution parser required')
    class Loader(yaml.CSafeLoader):
        pass
    def mapping(loader, node, deep=False):
        # No merge keys, aliases or duplicate mappings; bounded depth before construction.
        return pairs([(loader.construct_object(k, deep=deep), loader.construct_object(v, deep=deep))
                      for k, v in node.value])
    Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        depth = count = 0
        for event in yaml.parse(raw, Loader=Loader):
            count += 1
            require(count <= 100000, 'YAML event overflow')
            require(not isinstance(event, yaml.events.AliasEvent), 'YAML alias refused')
            if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
                depth += 1
                require(depth <= 32, 'YAML depth overflow')
            if isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
                depth -= 1
        docs = list(yaml.load_all(raw, Loader=Loader))
        require(len(docs) <= 128 and all(type(d) is dict for d in docs), 'YAML documents refused')
        return docs
    except (yaml.YAMLError, ValueError, TypeError, RecursionError):
        raise Failure('invalid YAML') from None


def ubuntu():
    user = pwd.getpwnam('ubuntu')
    require(user.pw_uid > 0 and user.pw_dir == '/home/ubuntu', 'ubuntu identity refused')
    return user


def boot():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch(r'[0-9a-f-]{36}', value), 'boot identity refused')
    return value


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise Failure('deadline exceeded', 124)
    return value


def retain_failure_output(raw):
    """One bounded last-failure diagnostic, private to this owned component.

    No forwarding or append/rotation subsystem. Before prepare reserves ROOT,
    no diagnostics file is created. Unknown/replaced existing paths are refused.
    """
    if not ROOT.exists():
        return
    no_links(ROOT)
    require(ROOT.is_dir() and ROOT.stat().st_uid == ROOT_UID
            and stat.S_IMODE(ROOT.stat().st_mode) == 0o700, 'diagnostic root refused')
    target = ROOT / 'last-command-output'
    before = None
    if target.exists() or target.is_symlink():
        before = target.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_uid == ROOT_UID
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
                'diagnostic path refused')
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
    if before is None:
        flags |= os.O_EXCL
    fd = os.open(target, flags, 0o600)
    try:
        observed = os.fstat(fd)
        require(before is None or stable_stat(observed) == stable_stat(before), 'diagnostic identity changed')
        require(observed.st_uid == ROOT_UID and stat.S_IMODE(observed.st_mode) == 0o600,
                'diagnostic ownership refused')
        os.ftruncate(fd, 0)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw[:LIMIT])
    finally:
        os.close(fd)


def execute(argv, deadline, cap=30, user=False, *, retain=True):
    """Bounded capture, never forward raw output. Only direct children are reaped.

    systemd owns long-lived VLAB descendants; short private CLI queries get their
    own process group. Forced kill is containment, not successful guest shutdown.
    """
    end = min(deadline, time.monotonic() + cap)
    kwargs = {}
    if user:
        account = ubuntu()
        kwargs = {'user': account.pw_uid, 'group': account.pw_gid,
                  'extra_groups': os.getgrouplist('ubuntu', account.pw_gid)}
    child = subprocess.Popen(argv, cwd='/', env=SAFE_ENV, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             start_new_session=True, **kwargs)
    raw = bytearray()
    primary = None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                if not selector.select(remaining(end)):
                    raise Failure('child deadline exceeded', 124)
                chunk = os.read(child.stdout.fileno(), 65536)
                if not chunk:
                    break
                raw.extend(chunk)
                require(len(raw) <= LIMIT, 'private child output overflow')
        try:
            code = child.wait(timeout=remaining(end))
        except subprocess.TimeoutExpired:
            raise Failure('child deadline exceeded', 124) from None
        if code:
            raise Failure('child command failed', code if 0 < code < 256 else 1, bytes(raw))
        return bytes(raw)
    except BaseException as exc:
        primary = exc
        if retain:
            try:
                retain_failure_output(bytes(raw))
            except BaseException:
                print('vlab-core: private diagnostics unverified', file=sys.stderr)
        raise
    finally:
        try:
            # The direct process can exit while descendants retain the pipe.
            # The new session/PGID is ours even after that direct child exits.
            if primary is not None or child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            child.wait(timeout=2)
            if primary is None:
                try:
                    os.killpg(child.pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    os.killpg(child.pid, signal.SIGKILL)
                    raise Failure('unexpected child group remains')
        except (OSError, subprocess.TimeoutExpired):
            if primary is None:
                raise Failure('child containment unverified') from None
            print('vlab-core: child group containment unverified', file=sys.stderr)
        finally:
            child.stdout.close()


def diagnostic_run(argv, end, keep):
    """Fixed bounded diagnostic query -> (status, tail bytes, truncated, cleanup).

    ``end`` is one absolute monotonic deadline for spawn, I/O AND kill/reap; the
    last SNAPSHOT_REAP seconds are held back for containment. Output beyond
    ``keep`` bytes drops the oldest bytes (a tail). ``cleanup`` is ``confirmed``
    only after the direct child was reaped and its process group is positively
    gone (ESRCH); anything else is ``uncertain`` and is never reported as clean.
    This is the guest's process namespace and says nothing about owner-host processes.
    """
    work_end = end - SNAPSHOT_REAP
    if time.monotonic() >= work_end:
        return 'unavailable', b'', False, 'confirmed'
    child = group = None
    cleanup = 'confirmed'
    status, tail, truncated = 'unavailable', bytearray(), False
    try:
        try:
            child = subprocess.Popen(argv, cwd='/', env=SAFE_ENV, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     start_new_session=True)
        except OSError:
            return 'unavailable', b'', False, ('confirmed' if time.monotonic() < end else 'uncertain')
        cleanup = 'uncertain'
        group = owned_process.OwnedGroup(child)
        # Popen cannot be interrupted by this helper. A late return is uncertain,
        # never permission to renew the absolute budget or send a late signal.
        if time.monotonic() >= work_end:
            raise Failure('diagnostic work deadline exhausted')
        complete = False
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                left = work_end - time.monotonic()
                if left <= 0 or not selector.select(left):
                    break
                if time.monotonic() >= work_end:
                    break
                chunk = os.read(child.stdout.fileno(), 65536)
                if not chunk:
                    complete = True
                    break
                tail.extend(chunk)
                if len(tail) > keep:
                    truncated = True
                    del tail[:-keep]
        if complete and time.monotonic() < work_end:
            # Observation only: retain the unreaped leader anchor through KILL.
            code = group.status()
            while code is None and time.monotonic() < work_end:
                left = work_end - time.monotonic()
                if left <= 0:
                    break
                time.sleep(min(.01, left))
                code = group.status()
            if code == 0 and time.monotonic() < work_end:
                status = 'truncated' if truncated else 'ok'
    except BaseException:
        status, tail, truncated = 'unavailable', bytearray(), False
        cleanup = 'uncertain'
    finally:
        if child is not None:
            if group is not None:
                try:
                    cleanup = 'confirmed' if group.close(0, until=end) else 'uncertain'
                except BaseException:
                    cleanup = 'uncertain'
            try:
                child.stdout.close()
            except BaseException:
                cleanup = 'uncertain'
            if time.monotonic() >= end:
                cleanup = 'uncertain'
                status = 'unavailable'
    if status == 'unavailable':
        tail = bytearray()
    return status, bytes(tail), truncated, cleanup


def render_failure(header, parts):
    """Fixed-key JSON; ``parts`` = {section: (status, raw bytes)}. Size is measured on the result."""
    body = dict(header)
    for name, (status, raw) in parts.items():
        body[name] = {**header[name], 'status': status, 'output': base64.b64encode(raw).decode()}
    return json.dumps(body, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def last_failure_context():
    """One fixed descriptor-checked tail; observed context, never inner provenance."""
    fd = None
    try:
        no_links(ROOT)
        root = ROOT.lstat()
        require(stat.S_ISDIR(root.st_mode) and root.st_uid == ROOT_UID
                and stat.S_IMODE(root.st_mode) == 0o700)
        path = ROOT / 'last-command-output'
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == ROOT_UID
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and 0 <= before.st_size <= LIMIT)
        cap = FAILURE_CAPS['command_context']
        os.lseek(fd, max(0, before.st_size - cap), os.SEEK_SET)
        raw = os.read(fd, cap + 1)
        require(len(raw) == min(cap, before.st_size)
                and stable_stat(os.fstat(fd)) == stable_stat(before)
                and stable_stat(path.lstat()) == stable_stat(before))
        return ('truncated' if before.st_size > cap else 'ok', raw) if raw else ('unavailable', b'')
    except BaseException:
        return 'unavailable', b''
    finally:
        if fd is not None:
            os.close(fd)


def write_first_failure(raw):
    """First failure wins: link() fails if a bundle already exists, so nothing is overwritten."""
    no_links(ROOT)
    require(ROOT.is_dir() and ROOT.stat().st_uid == ROOT_UID
            and stat.S_IMODE(ROOT.stat().st_mode) == 0o700, 'diagnostic root refused')
    temp, target = ROOT / (FIRST_FAILURE + '.new'), ROOT / FIRST_FAILURE
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temp, target)
        except FileExistsError:
            pass
    finally:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass


def capture_first_failure(mode, value, primary, deadline):
    """One root-private diagnostic bundle BEFORE cleanup_start; diagnostic only.

    It never changes the primary exception, grants readiness/containment or
    extends any deadline. ``value`` is None for a reservation refusal (this call
    committed no operation): operation/invocation are then null, and no older
    state operation or unbound manager/journal history is ever selected.
    """
    if time.monotonic() >= deadline:
        return  # FULL skip: no file-only exception after the original work cutoff.
    target = ROOT / FIRST_FAILURE
    if target.exists() or target.is_symlink():
        return
    end = min(deadline, time.monotonic() + SNAPSHOT_SECONDS)
    try:
        current = state()
        current_ok = True
    except BaseException:
        current, current_ok = None, False
    nonce = value['nonce'] if value is not None else (current or {}).get('nonce')
    if not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{32}', nonce):
        return
    operation = value['operation'] if value is not None else None
    state_status = 'ok' if current_ok else 'unavailable'
    if current_ok and (current['nonce'] != nonce or (value is not None and (
            current.get('operation') != operation or current.get('mode') != mode))):
        current, state_status = None, 'invalid'
    if value is None and (current is None or current.get('phase') != 'prepared'
                          or any(key in current for key in ('mode', 'operation', 'invocation'))):
        return  # A null reservation must never mask an older live binding.
    invocation = None
    if value is not None and current is not None \
            and re.fullmatch(r'[0-9a-f]{32}', str(current.get('invocation', ''))):
        invocation = current['invocation']
    try:
        boot_id = boot()
    except BaseException:
        boot_id = None
    phase = (current or {}).get('phase')
    if value is None:
        stage = 'reserve'
    elif invocation is None:
        stage = 'manager'
    elif phase == 'ready':
        stage = 'final'
    else:
        stage = 'unit'

    def token(key):
        text = (current or {}).get(key)
        return text if isinstance(text, str) and re.fullmatch(r'[a-z0-9-]{1,32}', text) else None
    message = code = None
    out = b''
    if isinstance(primary, Failure):
        text = str(primary)
        message = text if re.fullmatch(r'[ -~]{1,128}', text) else None
        code = primary.code if type(primary.code) is int and 0 <= primary.code < 256 else None
        out = primary.private_output if isinstance(primary.private_output, (bytes, bytearray)) else b''
    out = bytes(out)
    primary_status = 'unavailable' if not out else ('truncated' if len(out) > FAILURE_CAPS['primary'] else 'ok')
    parts = {'primary': (primary_status, out[-FAILURE_CAPS['primary']:]),
             'command_context': last_failure_context() if operation is not None else ('unavailable', b''),
             'manager': ('unavailable', b''), 'journal': ('unavailable', b'')}
    cleanup = 'confirmed'
    unit = UNIT[mode]
    if invocation is not None:
        status, raw, _, result = diagnostic_run(
            [SYSTEMCTL, 'show', unit, '--no-pager', '--property=' + MANAGER_PROPERTIES],
            min(end, time.monotonic() + MANAGER_SECONDS), FAILURE_CAPS['manager'])
        cleanup = 'uncertain' if result == 'uncertain' else cleanup
        if status in ('ok', 'truncated'):
            reported = None
            for line in raw.decode('ascii', 'replace').splitlines():
                if line.startswith('InvocationID='):
                    reported = line[len('InvocationID='):]
            if reported == '':
                status, raw = 'unavailable', b''      # manager forgot the unit
            elif reported != invocation:
                status, raw = 'invalid', b''          # different/absent identity: untrusted
        parts['manager'] = (status, raw)
    if invocation is not None and boot_id is not None:
        # Exact frozen original boot + invocation + unit in the existing namespace.
        # journald stores _BOOT_ID as 32 hex without dashes. No unit-only fallback.
        status, raw, _, result = diagnostic_run(
            [JOURNALCTL, '--no-pager', '--namespace=' + JOURNAL_NAMESPACE, '--lines=%d' % JOURNAL_LINES,
             '--output=short-monotonic', '_BOOT_ID=' + boot_id.replace('-', ''),
             '_SYSTEMD_INVOCATION_ID=' + invocation, '_SYSTEMD_UNIT=' + unit],
            min(end, time.monotonic() + JOURNAL_SECONDS), FAILURE_CAPS['journal'])
        cleanup = 'uncertain' if result == 'uncertain' else cleanup
        parts['journal'] = (status, raw)
    header = {'schema': 1, 'source': 'vlab_core', 'nonce': nonce, 'mode': mode, 'operation': operation,
              'invocation': invocation, 'boot': boot_id, 'stage': stage, 'query_cleanup': cleanup,
              'state': {'status': state_status, 'phase': token('phase'),
                        'containment': token('containment'), 'service_result': token('service_result')},
              'primary': {'message': message, 'code': code},
              'command_context': {'label': FAILURE_CONTEXT}, 'manager': {}, 'journal': {}}
    rendered = render_failure(header, parts)
    for name in ('journal', 'primary', 'command_context', 'manager'):
        # Serialized (not raw) bound: shed the oldest output until it fits.
        while len(rendered) > FIRST_FAILURE_LIMIT and parts[name][1]:
            parts[name] = ('truncated', parts[name][1][len(parts[name][1]) // 2 + 1:])
            rendered = render_failure(header, parts)
    if len(rendered) > FIRST_FAILURE_LIMIT:
        return
    if time.monotonic() >= end:
        return
    write_first_failure(rendered)


def hhfab(command, deadline, extra=(), cap=30):
    return execute([HHFAB, *command, '--workdir', str(WORK), '--cache-dir', str(CACHE), *extra],
                   deadline, cap, user=True)


def atomic(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    require(len(raw) <= 8 * LIMIT, 'state overflow')
    temp = path.with_name(path.name + '.new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    except BaseException:
        # Do not guess cleanup/adopt an unobserved replacement.
        raise


@contextmanager
def locked(wait=0, *, deadline=None):
    # wait=0 is the default: a competing operation is an immediate refusal.
    # Only the sibling unit-run/unit-ready actions of one systemd start pass a
    # small bounded wait, because systemd may run them concurrently.
    no_links(ROOT)
    require(ROOT.is_dir() and ROOT.stat().st_uid == ROOT_UID
            and stat.S_IMODE(ROOT.stat().st_mode) == 0o700, 'state root refused')
    fd = os.open(ROOT / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_uid == ROOT_UID
                and stat.S_IMODE(os.fstat(fd).st_mode) == 0o600 and os.fstat(fd).st_nlink == 1,
                'lock identity refused')
        # No unbounded flock wait. Competing operation must return a refusal.
        limit = time.monotonic() + wait
        if deadline is not None:
            remaining(deadline)
            limit = min(limit, deadline)
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if deadline is not None:
                    remaining(deadline)
                if wait:
                    remaining(limit)
                break
            except BlockingIOError:
                if time.monotonic() >= limit:
                    raise Failure('another operation owns the lock') from None
                time.sleep(min(0.01, max(0, limit - time.monotonic())))
        yield
    finally:
        os.close(fd)


@contextmanager
def stop_controller():
    """Exclusive owner of outstanding unit-name stops, separate from state.

    Never wait for this lock. ExecStopPost needs only locked(), so the manager
    can finish while this controller retains ownership through containment.
    Start reservations briefly take this lock before their short state commit.
    """
    no_links(ROOT)
    require(ROOT.is_dir() and ROOT.stat().st_uid == ROOT_UID
            and stat.S_IMODE(ROOT.stat().st_mode) == 0o700, 'controller root refused')
    fd = os.open(ROOT / 'stop-controller.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        observed = os.fstat(fd)
        require(stat.S_ISREG(observed.st_mode) and observed.st_uid == ROOT_UID
                and stat.S_IMODE(observed.st_mode) == 0o600 and observed.st_nlink == 1,
                'stop controller identity refused')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Failure('another stop controller is active') from None
        yield
    finally:
        os.close(fd)


def state():
    value = json_data(read(ROOT / 'state.json', 8 * LIMIT, private=True))
    require(value.get('schema') == 1 and re.fullmatch(r'[0-9a-f]{32}', value.get('nonce', '')),
            'state identity refused')
    return value


def save(value):
    atomic(ROOT / 'state.json', value)


def source_snapshot(directory):
    records = {name: identity(directory / name, True, limit=STATIC_LIMIT)
               for name in ('vlab_core.py', 'owned_process.py', 'ensure-bridge-ipv4.py',
                            'journald@labapp-vlab.conf', *UNIT.values())}
    require(all(r['uid'] == ROOT_UID and stat.S_IMODE(r['mode']) == 0o644
                and r['links'] == 1 for r in records.values()),
            'component ownership refused')
    return records


def verify_sources(value):
    require(source_snapshot(LIB) == value['source'], 'installed component changed')
    for name in UNIT.values():
        require(read(UNITS / name) == read(LIB / name), 'installed unit changed')
        record = identity(UNITS / name)
        require(record['uid'] == ROOT_UID and stat.S_IMODE(record['mode']) == 0o644
                and record['links'] == 1, 'installed unit ownership refused')
    require(read(JOURNAL) == read(LIB / JOURNAL.name), 'journal configuration changed')
    record = identity(JOURNAL)
    require(record['uid'] == ROOT_UID and stat.S_IMODE(record['mode']) == 0o644
            and record['links'] == 1, 'journal configuration ownership refused')
    for directory in JOURNAL_DROPINS:
        require(not directory.exists() or not list(directory.iterdir()), 'journal overrides refused')


def system_show(mode, deadline):
    raw = execute([SYSTEMCTL, 'show', UNIT[mode], '--no-pager',
                   '--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlGroup,FragmentPath,DropInPaths,NeedDaemonReload'],
                  deadline, 5)
    try:
        fields = pairs([line.split('=', 1) for line in raw.decode().splitlines() if line])
    except (UnicodeError, ValueError):
        raise Failure('invalid service response') from None
    require(fields.get('Id') == UNIT[mode] and fields.get('LoadState') == 'loaded'
            and fields.get('FragmentPath') == str(UNITS / UNIT[mode])
            and fields.get('DropInPaths') == '' and fields.get('NeedDaemonReload') == 'no',
            'effective unit refused')
    return fields


def service_identity(fields):
    invocation = fields.get('InvocationID', '')
    require(re.fullmatch(r'[0-9a-f]{32}', invocation), 'invocation identity refused')
    group = fields.get('ControlGroup', '')
    require(group in ('/system.slice/' + name for name in UNIT.values()), 'cgroup path refused')
    pid = fields.get('MainPID', '')
    require(re.fullmatch(r'[1-9][0-9]*', pid), 'main process absent')
    proc = Path('/proc') / pid
    # comm may contain whitespace/parentheses; starttime field22 follows final ')'.
    start = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    require(re.fullmatch(r'[0-9]+', start), 'process identity refused')
    return {'invocation': invocation, 'group': group, 'pid': int(pid), 'start': start}


def check_live(value, deadline):
    fields = system_show(value['mode'], deadline)
    require(fields['ActiveState'] in ('activating', 'active'), 'service is not running')
    observed = service_identity(fields)
    require(observed['invocation'] == value['invocation']
            and observed['group'] == '/system.slice/' + UNIT[value['mode']],
            'service invocation or cgroup changed')
    if 'service' in value:
        require(observed == value['service'], 'service identity changed')
    return observed


def operation_deadline(value):
    require(value['boot'] == boot() and type(value['deadline']) in (int, float)
            and type(value['started']) in (int, float)
            and value['deadline'] - value['started'] == START_SECONDS[value['mode']],
            'operation clock refused')
    remaining(value['deadline'])
    return value['deadline']


def verify_prerequisites(receipt, deadline):
    keys(receipt, ('schema', 'source_sha256', 'packages', 'commands'))
    require(receipt['schema'] == 1 and re.fullmatch(r'[0-9a-f]{64}', receipt['source_sha256']),
            'provisioning receipt refused')
    packages = receipt['packages']
    require(type(packages) is dict and set(packages) == set(PACKAGE_PINS) | set(AUX.values()),
            'package set refused')
    for name, version in PACKAGE_PINS.items():
        require(packages[name] == version, 'baseline package pin refused')
    require(type(packages['systemd']) is str
            and re.fullmatch(r'255\.[0-9][A-Za-z0-9.+:~_-]{0,127}', packages['systemd']),
            'systemd compatibility family refused')
    os_release = read(Path('/usr/lib/os-release')).decode()
    for literal in ('ID=ubuntu', 'VERSION_ID="24.04"', 'VERSION_CODENAME=noble'):
        require(literal in os_release.splitlines(), 'Ubuntu baseline refused')
    require(os.uname().machine == 'x86_64', 'guest architecture refused')
    for name, version in packages.items():
        require(type(version) is str and re.fullmatch(r'[A-Za-z0-9.+:~_-]{1,128}', version),
                'package version refused')
        output = execute([DPKG, '-W', '-f=${db:Status-Status}\t${Architecture}\t${Version}\n', name], deadline)
        require(output == f'installed\tamd64\t{version}\n'.encode(), 'installed package differs')
    commands = receipt['commands']
    require(type(commands) is dict and set(commands) == set(AUX) | set(TOOL_PINS),
            'command receipt set refused')
    observed = {}
    for name in commands:
        resolved = Path(name).resolve(strict=True)
        record = identity(resolved, True, deadline)
        expected_mode = 0o4755 if name == '/usr/bin/sudo' else 0o755
        require(record['uid'] == 0 and stat.S_IMODE(record['mode']) == expected_mode,
                'command permissions refused')
        require(type(commands[name]) is dict and commands[name] ==
                {'resolved': str(resolved), 'sha256': record['sha256']}, 'command receipt mismatch')
        if name in TOOL_PINS:
            require((record['size'], record['sha256']) == TOOL_PINS[name], 'tool pin refused')
        observed[name] = {'resolved': str(resolved), **record}
    return observed


def validate_fab(raw):
    docs = yaml_documents(raw)
    require([(d.get('kind'), d.get('metadata', {}).get('name'), d.get('metadata', {}).get('namespace'))
             for d in docs] == [('Fabricator', 'default', 'fab'), ('ControlNode', 'control-1', 'fab')],
            'FAB object set refused')
    config = docs[0]['spec']['config']
    control, fabric = config['control'], config['fabric']
    node = docs[1]['spec']
    require(all(d.get('apiVersion') == 'fabricator.githedgehog.com/v1beta1' for d in docs)
            and not docs[1]['metadata'].get('annotations')
            and node['bootstrap']['disk'] == '/dev/sda'
            and node['external'] == {'interface': 'enp2s0', 'ip': 'dhcp'}
            and node['management']['interface'] == 'enp2s1'
            and node['management'].get('ip', '172.30.0.5/21') == '172.30.0.5/21',
            'control candidate policy refused')
    selected_control = {'managementSubnet': '172.30.0.0/21', 'controlVIP': '172.30.0.1/32',
                        'kubeClusterSubnet': '172.28.0.0/16', 'kubeServiceSubnet': '172.29.0.0/16',
                        'kubeClusterDNS': '172.29.0.10', 'dummySubnet': '172.30.90.0/24'}
    selected_fabric = {'mode': 'spine-leaf', 'managementDHCPStart': '172.30.4.0',
                       'managementDHCPEnd': '172.30.7.254', 'spineASN': 65100,
                       'leafASNStart': 65101, 'leafASNEnd': 65533,
                       'protocolSubnet': '172.30.8.0/22', 'vtepSubnet': '172.30.12.0/22',
                       'fabricSubnet': '172.30.128.0/17', 'mclagSessionSubnet': '172.30.95.0/31',
                       'vpcWorkaroundSubnet': '172.30.96.0/19'}
    # Inputs must spell out candidates; do not silently infer missing originals.
    require(all(control.get(k) == v for k, v in selected_control.items())
            and all(fabric.get(k) == v for k, v in selected_fabric.items())
            and config.get('registry') == {'mode': 'airgap'}
            and not config.get('gateway', {}).get('enable', False)
            and config.get('observability', {}).get('defaults') == '', 'candidate FAB policy refused')
    require(type(control.get('joinToken')) is str and len(control['joinToken']) >= 32,
            'stable private join token required')
    users = [control['defaultUser'], *fabric['defaultSwitchUsers'].values()]
    require('admin' in fabric['defaultSwitchUsers'], 'admin user required')
    for user in users:
        require(type(user.get('password')) is str and user['password'].startswith('$5$')
                and user['password'] != DEV_PASSWORD and type(user.get('authorizedKeys')) is list
                and user['authorizedKeys'] and all(type(k) is str and DEV_KEY not in k
                                                  and k.startswith('ssh-ed25519 ') for k in user['authorizedKeys']),
                'private nondevelopment credentials required')
    require(DEV_PASSWORD.encode() not in raw and DEV_KEY.encode() not in raw, 'development credentials refused')
    return docs


def canonical_nics():
    docs = yaml_documents(read(WORK / 'include/wiring-input.yaml'))
    out = {name: {'enp2s0': 'usernet'} for name, kind in VMS.items() if kind != 'switch'}
    out['control-1']['enp2s1'] = 'management'
    for doc in docs:
        if doc['kind'] == 'Switch':
            out[doc['metadata']['name']] = {'M1': 'management:' + doc['spec']['boot']['mac']}

    def links(value):
        if isinstance(value, dict):
            ports = [item['port'] for item in value.values()
                     if isinstance(item, dict) and set(item) == {'port'}]
            if ports:
                require(len(ports) == 2, 'wiring link refused')
                yield ports
            else:
                for item in value.values():
                    yield from links(item)
        elif isinstance(value, list):
            for item in value:
                yield from links(item)

    for doc in docs:
        if doc['kind'] == 'Connection':
            for a, b in links(doc['spec']):
                for local, peer in ((a, b), (b, a)):
                    name, nic = local.split('/', 1)
                    require(name in out and nic not in out[name], 'wiring endpoint refused')
                    out[name][nic] = 'direct:' + peer
    return out


def prepare(input_path):
    deadline = time.monotonic() + 120
    contract = json_data(read(no_links(input_path), private=True))
    keys(contract, ('schema', 'dedicated_guest', 'nonce', 'fab', 'fab_sha256', 'wiring', 'wiring_sha256',
                    'package_receipt', 'package_receipt_sha256', 'candidate_policy'))
    require(contract['schema'] == 1 and contract['dedicated_guest'] is True
            and re.fullmatch(r'[0-9a-f]{32}', contract['nonce']), 'dedicated guest assertion required')
    require(contract['candidate_policy'] == {'bridge': '172.30.0.2/21', 'netfilter': 'all-three-off',
            'forwarded_ports': '0.0.0.0-isolated-by-route', 'build': 'iso',
            'controls_restricted': True, 'servers_restricted': True}, 'candidate policy refused')
    fab = read(Path(contract['fab']), private=True)
    wiring = read(Path(contract['wiring']))
    receipt_raw = read(Path(contract['package_receipt']), private=True)
    require(digest(fab) == contract['fab_sha256'] and digest(wiring) == contract['wiring_sha256'] == WIRING_SHA
            and digest(receipt_raw) == contract['package_receipt_sha256'], 'input hash refused')
    validate_fab(fab)
    yaml_documents(wiring)
    receipt = json_data(receipt_raw)
    tools = verify_prerequisites(receipt, deadline)
    cache_preflight()
    no_links(WORK)
    require(not WORK.exists() and not ROOT.exists(), 'existing state refused')
    ROOT.mkdir(mode=0o700)
    user = ubuntu()
    with locked():
        value = {'schema': 1, 'nonce': contract['nonce'], 'phase': 'preparing',
                 'contract': contract, 'packages': receipt, 'tools': tools}
        save(value)
        WORK.mkdir(mode=0o700)
        os.chown(WORK, user.pw_uid, user.pw_gid)
        value['work'] = identity(WORK)
        save(value)
    try:
        # Stage reviewed maintained siblings exactly; conflicts are never overwritten.
        for directory in (LIB, UNITS):
            no_links(directory)
            if not directory.exists():
                directory.mkdir(mode=0o755, parents=True)
                os.chmod(directory, 0o755)
            require(directory.is_dir() and directory.stat().st_uid == ROOT_UID
                    and stat.S_IMODE(directory.stat().st_mode) == 0o755,
                    'installation directory refused')
        source = Path(__file__).resolve().parent
        for name in ('vlab_core.py', 'owned_process.py', 'ensure-bridge-ipv4.py',
                     'journald@labapp-vlab.conf', *UNIT.values()):
            raw = read(source / name)
            target = LIB / name
            if target.exists():
                require(read(target) == raw, 'component installation conflict')
            else:
                fd = os.open(no_links(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
                os.fchmod(fd, 0o644)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
            if name in UNIT.values() or name == 'journald@labapp-vlab.conf':
                unit_target = UNITS / name if name in UNIT.values() else JOURNAL
                if unit_target.exists():
                    require(read(unit_target) == raw, 'unit installation conflict')
                else:
                    fd = os.open(no_links(unit_target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
                    os.fchmod(fd, 0o644)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(raw)
        value['source'] = source_snapshot(LIB)
        for name, raw in (('fab-input.yaml', fab), ('wiring-input.yaml', wiring)):
            target = WORK / name
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
            os.chown(target, user.pw_uid, user.pw_gid)
        value['stage'] = 'import'
        with locked():
            save(value)
        hhfab(['init'], deadline, ['--config', str(WORK / 'fab-input.yaml'),
                                  '--registry-repo', 'ghcr.io', '--registry-prefix', 'githedgehog',
                                  '--wiring', str(WORK / 'wiring-input.yaml')])
        value['stage'] = 'validate'
        with locked():
            save(value)
        for _ in range(2):
            hhfab(['validate'], deadline, ['--hydrate-mode', 'if-not-present'])
            require(read(WORK / 'fab.yaml', private=True) == fab
                    and read(WORK / 'include/wiring-input.yaml') == wiring
                    and yaml_documents(read(WORK / '.registry.yaml')) ==
                    [{'repo': 'ghcr.io', 'prefix': 'githedgehog'}], 'import preservation refused')
        value['static'] = prepared_snapshot(deadline)
        fresh_preflight(value)
        execute([SYSTEMCTL, 'daemon-reload'], deadline, 10)
        for mode in UNIT:
            require(system_show(mode, deadline)['ActiveState'] in ('inactive', 'failed'),
                    'active service refused')
        value['phase'] = 'prepared'
        with locked():
            save(value)
    except BaseException:
        try:
            value['phase'] = 'failed'
            with locked():
                save(value)
        except BaseException:
            print('vlab-core: failure recording unverified', file=sys.stderr)
        raise


def prepared_snapshot(deadline):
    paths = ('fab.yaml', '.registry.yaml', 'fab-input.yaml', 'wiring-input.yaml',
             'include', 'include/wiring-input.yaml', 'result')
    require({p.name for p in (WORK / 'include').iterdir()} == {'wiring-input.yaml'},
            'unexpected include entries')
    return {name: identity(WORK / name, not (WORK / name).is_dir(), deadline,
                           limit=STATIC_LIMIT) for name in paths}


def verify_contract(value, deadline):
    require(identity(WORK) == value['work'], 'work directory replaced')
    require(prepared_snapshot(deadline) == value['static'], 'static inputs changed')
    verify_sources(value)
    require(verify_prerequisites(value['packages'], deadline) == value['tools'], 'tools changed')
    cache_preflight()


def cache_preflight():
    no_links(CACHE)
    for directory in (CACHE.parent, CACHE):
        if directory.exists():
            observed = directory.lstat()
            require(stat.S_ISDIR(observed.st_mode) and observed.st_uid == ubuntu().pw_uid
                    and not observed.st_mode & 0o022, 'cache directory refused')


def fresh_preflight(value):
    require(identity(WORK / 'result') == value['static']['result'], 'fresh result identity differs')
    require({p.name for p in WORK.iterdir()} == {'fab.yaml', '.registry.yaml', 'fab-input.yaml',
            'wiring-input.yaml', 'include', 'result'} and not list((WORK / 'result').iterdir()),
            'fresh state adoption refused')


def optional_runtime_paths():
    """Mutable outputs may be recreated, but cannot redirect privileged writes."""
    user = ubuntu().pw_uid
    for name, private in (('kubeconfig', True), ('sshkey.pub', False)):
        path = WORK / 'vlab' / name
        if path.exists() or path.is_symlink():
            observed = no_links(path).lstat()
            require(stat.S_ISREG(observed.st_mode) and observed.st_uid == user
                    and observed.st_nlink == 1 and not observed.st_mode & (0o077 if private else 0o022),
                    'generated runtime file refused')
    for name in VMS:
        directory = WORK / 'vlab/vms' / name
        for filename in ('serial.log', 'serial.sock', 'mon.sock', 'qmp.sock'):
            path = directory / filename
            if path.exists() or path.is_symlink():
                observed = no_links(path).lstat()
                valid_type = stat.S_ISREG(observed.st_mode) if filename == 'serial.log' else stat.S_ISSOCK(observed.st_mode)
                require(valid_type and observed.st_uid in (ROOT_UID, user)
                        and not observed.st_mode & 0o022
                        and (filename != 'serial.log' or observed.st_nlink == 1),
                        'mutable runtime path refused')


def up_argv():
    return [HHFAB, 'vlab', 'up', '--workdir', str(WORK), '--cache-dir', str(CACHE),
            '--hydrate-mode', 'if-not-present', '--build-mode', 'iso',
            '--controls-restricted=true', '--servers-restricted=true', '--auto-upgrade=false',
            '--kill-stale=false', '--fail-fast=true', '--ready', 'wait',
            '--control-cpus', '6', '--control-ram', '6144', '--control-disk', '100',
            '--server-cpus', '2', '--server-ram', '768', '--server-disk', '10',
            '--gateway-cpus', '8', '--gateway-ram', '6144', '--gateway-disk', '50']


def vm_config():
    docs = yaml_documents(read(WORK / 'vlab/config.yaml', private=True))
    require(len(docs) == 1, 'VM config documents refused')
    cfg = docs[0]
    keys(cfg, ('sizes', 'vms'), ('externals',))
    require(cfg['sizes'] == SIZES and set(cfg['vms']) == set(VMS)
            and cfg.get('externals', {}) in ({}, {'nics': {}, 'vrfs': {}}), 'VM topology refused')
    expected_nics = canonical_nics()
    for name, kind in VMS.items():
        vm = cfg['vms'][name]
        keys(vm, ('type', 'nics'))
        require(vm['type'] == kind and type(vm['nics']) is dict and vm['nics'], 'VM type refused')
        require(vm['nics'] == expected_nics[name], 'VM canonical NICs differ')
        for nic, peer in vm['nics'].items():
            require(type(nic) is str and type(peer) is str, 'VM NIC refused')
            if peer.startswith('direct:'):
                endpoint = peer[7:].split('/', 1)
                require(len(endpoint) == 2 and endpoint[0] in VMS
                        and cfg['vms'][endpoint[0]]['nics'].get(endpoint[1]) == f'direct:{name}/{nic}',
                        'VM reciprocal NIC refused')
            else:
                require(peer in ('usernet', 'management') or re.fullmatch(r'management:[0-9a-f:]{17}', peer),
                        'VM NIC policy refused')
    return cfg


def critical_snapshot(deadline):
    """Complete no-rebuild inputs; mutable disk bytes/size/times are intentionally omitted."""
    vm_config()
    optional_runtime_paths()
    require({p.name for p in WORK.iterdir()} == {'fab.yaml', '.registry.yaml', 'fab-input.yaml',
            'wiring-input.yaml', 'include', 'result', 'vlab'}, 'unexpected work entries')
    require({p.name for p in (WORK / 'vlab').iterdir()} <=
            {'config.yaml', 'sshkey', 'sshkey.pub', 'vms', 'kubeconfig'}, 'unexpected VLAB entries')
    paths = {'vlab': False, 'vlab/vms': False, 'vlab/config.yaml': True, 'vlab/sshkey': True,
             'result': False, f'result/{RESULT}.inhash': True,
             f'result/{RESULT}-usb.iso': True}
    install = WORK / 'result' / RESULT
    require(install.is_dir() and not install.is_symlink(), 'cached installer absent')
    require({f'{RESULT}.inhash', RESULT, f'{RESULT}-usb.iso'} ==
            {p.name for p in (WORK / 'result').iterdir()}, 'cached result incomplete')
    count = total = 0
    stack = [install]
    while stack:
        parent = stack.pop()
        paths[str(parent.relative_to(WORK))] = False
        for entry in parent.iterdir():
            count += 1
            require(count <= TREE_FILES and not entry.is_symlink(), 'result enumeration refused')
            if entry.is_dir():
                stack.append(entry)
            else:
                st = entry.lstat()
                require(stat.S_ISREG(st.st_mode), 'result type refused')
                total += st.st_size
                require(total <= TREE_BYTES, 'result bytes overflow')
                paths[str(entry.relative_to(WORK))] = True
    for name in ('fab.yaml', 'include.yaml', 'hhfab-recipe'):
        require(install.joinpath(name).is_file(), 'installer payload absent')
    require(re.fullmatch(rb'[A-Za-z0-9_-]{43}=', read(WORK / f'result/{RESULT}.inhash')),
            'cached hash format refused')
    require({p.name for p in (WORK / 'vlab/vms').iterdir()} == set(VMS), 'VM directory set refused')
    for name, kind in VMS.items():
        prefix = f'vlab/vms/{name}'
        paths[prefix] = False
        for filename, hashed in (('os.img', False), ('efi_code.fd', True), ('efi_vars.fd', False)):
            paths[prefix + '/' + filename] = hashed
        if kind == 'control':
            paths[prefix + '/usb.iso'] = True
        if kind == 'server':
            paths[prefix + '/ignition.json'] = True
            paths[prefix + '/butane.yaml'] = True
        allowed = {'os.img', 'efi_code.fd', 'efi_vars.fd', 'serial.log', 'serial.sock', 'mon.sock', 'qmp.sock'}
        allowed |= {'usb.iso'} if kind == 'control' else set()
        allowed |= {'ignition.json', 'butane.yaml'} if kind == 'server' else set()
        require({p.name for p in (WORK / prefix).iterdir()} <= allowed, 'unexpected VM entries')
    result = {name: identity(WORK / name, hashed, deadline) for name, hashed in sorted(paths.items())}
    require(all(record['uid'] == ubuntu().pw_uid and not record['mode'] & 0o022
                for record in result.values()), 'critical ownership refused')
    require(all(record.get('links', 1) == 1 for record in result.values()), 'critical hardlink refused')
    require(sum(record.get('size', 0) for record in result.values()) <= TREE_BYTES,
            'critical hash bytes overflow')
    return result


def readonly_paths():
    return [WORK / 'result', WORK / 'fab.yaml', WORK / '.registry.yaml', WORK / 'include',
            WORK / 'vlab/config.yaml', WORK / 'vlab/sshkey']


def verify_readonly_mounts():
    # Mount flags apply to this run action's actual namespace, not the root gate.
    entries = []
    for line in MOUNTINFO.read_text().splitlines():
        fields = line.split()
        require(len(fields) >= 10 and ' - ' in line, 'mountinfo refused')
        mount = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])
        entries.append((Path(mount), set(fields[5].split(','))))
    for target in readonly_paths():
        matches = [(p, flags) for p, flags in entries if target == p or p in target.parents]
        require(matches, 'resume read-only mount absent')
        selected = max(matches, key=lambda item: len(item[0].parts))
        require('ro' in selected[1], 'resume path is writable')
        # A writable nested mount must not punch a hole in protected result/include.
        require(not any(target in p.parents and 'ro' not in flags for p, flags in entries),
                'writable nested mount refused')


def reserve(mode, deadline=None):
    with stop_controller(), locked():
        value = state()
        phase = 'prepared' if mode == 'fresh' else 'resumable'
        require(value['phase'] == phase, 'startup phase refused')
        if mode == 'resume':
            require(value.get('stop_verified') == {'operation': value['operation'],
                                                  'invocation': value['invocation']},
                    'verified resume stop absent')
    end = deadline if deadline is not None else time.monotonic() + START_SECONDS[mode]
    for other in UNIT:
        require(system_show(other, end)['ActiveState'] in ('inactive', 'failed'),
                'conflicting active unit refused')
    verify_contract(value, end)
    if mode == 'resume':
        require(critical_snapshot(end) == value['critical'], 'resume critical state changed')
    else:
        fresh_preflight(value)
    with stop_controller(), locked():
        require(state() == value, 'competing operation changed state')
        started = end - START_SECONDS[mode]
        value.update(phase='starting', mode=mode, operation=uuid.uuid4().hex,
                     boot=boot(), started=started, deadline=end)
        value.pop('invocation', None)
        value.pop('service', None)
        value.pop('stopping', None)
        value.pop('stop_verified', None)
        save(value)
        return value


def invocation_env():
    invocation = os.environ.get('INVOCATION_ID', '')
    require(re.fullmatch(r'[0-9a-f]{32}', invocation), 'unit invocation required')
    return invocation


def unit_gate(mode):
    invocation = invocation_env()
    # Enabled resume starts at boot without a coordinator. It may reserve only
    # a sealed resumable state; never revive failed/partial fresh state.
    with stop_controller(), locked():
        value = state()
        if mode == 'resume' and value['phase'] == 'resumable':
            require(value.get('stop_verified') == {'operation': value['operation'],
                                                  'invocation': value['invocation']},
                    'verified boot stop absent')
            now = time.monotonic()
            require(system_show('fresh', now + 5)['ActiveState'] in ('inactive', 'failed'),
                    'conflicting fresh unit refused')
            end = now + START_SECONDS[mode]
            value.update(phase='starting', mode=mode, operation=uuid.uuid4().hex, boot=boot(),
                         started=end - START_SECONDS[mode], deadline=end)
            value.pop('service', None)
            value.pop('invocation', None)
            value.pop('stopping', None)
            value.pop('stop_verified', None)
        require(value['phase'] == 'starting' and value['mode'] == mode
                and 'invocation' not in value, 'unit startup reservation refused')
        value['invocation'] = invocation
        save(value)
    deadline = operation_deadline(value)
    verify_contract(value, deadline)
    if mode == 'resume':
        require(critical_snapshot(deadline) == value['critical'], 'resume critical state changed')
    else:
        fresh_preflight(value)
    execute(['/usr/sbin/modprobe', 'br_netfilter'], deadline, 5)
    execute(['/usr/sbin/sysctl', '-w', *[f'net.bridge.{key}=0' for key in NETFILTER]], deadline, 5)
    verify_netfilter()


def verify_netfilter():
    for key in NETFILTER:
        require(read(Path('/proc/sys/net/bridge') / key, 16).strip() == b'0', 'netfilter policy differs')


SIBLING_LOCK_SECONDS = 10


def startup_snapshot(mode):
    # Atomic replacement makes this preliminary read coherent, but not authority.
    # Bind the clock before waiting; the locked reread must retain every field
    # except a genuine service publication by the concurrent readiness action.
    value = state()
    require(value['phase'] == 'starting' and value['mode'] == mode
            and value['invocation'] == invocation_env(), 'startup invocation refused')
    deadline = operation_deadline(value)
    return value, deadline


def same_start(current, original, pin):
    expected = dict(original)
    if 'service' not in original and 'service' in current:
        require(current['service'] == pin, 'service publication changed')
        expected['service'] = pin
    require(current == expected, 'startup operation changed')


def unit_run(mode):
    value, deadline = startup_snapshot(mode)
    with locked(SIBLING_LOCK_SECONDS, deadline=deadline):
        current = state()
        pin = check_live(value, deadline)
        require(pin['pid'] == os.getpid(), 'run main process differs')
        same_start(current, value, pin)
        value = current
    verify_contract(value, deadline)
    if mode == 'resume':
        require(critical_snapshot(deadline) == value['critical'], 'resume critical state changed')
        verify_readonly_mounts()
    else:
        fresh_preflight(value)
    with locked(SIBLING_LOCK_SECONDS, deadline=deadline):
        current = state()
        same_start(current, value, pin)
        # Reobserve every branch, including absent and already published service.
        # The initial main PID/start pin must survive until this final gate.
        require(check_live(current, deadline) == pin, 'run main process changed')
        operation_deadline(current)
        # Keep state writers excluded until exec closes Python's non-inheritable
        # lock descriptor (also released by the context on any refusal).
        user = ubuntu()
        os.initgroups('ubuntu', user.pw_gid)
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
        require(os.getuid() == user.pw_uid and os.geteuid() == user.pw_uid, 'privilege drop failed')
        os.chdir(str(WORK))
        os.umask(0o077)
        remaining(deadline)
        os.execve(HHFAB, up_argv(), SAFE_ENV)


def kubeconfig():
    docs = yaml_documents(read(WORK / 'vlab/kubeconfig', private=True))
    require(len(docs) == 1, 'kubeconfig documents refused')
    cfg = docs[0]
    keys(cfg, ('apiVersion', 'kind', 'clusters', 'contexts', 'current-context', 'users'), ('preferences',))
    require(cfg['apiVersion'] == 'v1' and cfg['kind'] == 'Config'
            and all(type(cfg[k]) is list and len(cfg[k]) == 1 for k in ('clusters', 'contexts', 'users')),
            'kubeconfig set refused')
    cluster, context, user = cfg['clusters'][0], cfg['contexts'][0], cfg['users'][0]
    keys(cluster, ('name', 'cluster'))
    keys(context, ('name', 'context'))
    keys(user, ('name', 'user'))
    keys(cluster['cluster'], ('server', 'certificate-authority-data'))
    keys(context['context'], ('cluster', 'user'), ('namespace',))
    keys(user['user'], ('client-certificate-data', 'client-key-data'))
    require(cluster['cluster']['server'] == 'https://127.0.0.1:6443'
            and context['context']['cluster'] == cluster['name']
            and context['context']['user'] == user['name'] and cfg['current-context'] == context['name'],
            'kubeconfig identity refused')
    try:
        ca = base64.b64decode(cluster['cluster']['certificate-authority-data'], validate=True)
        for key in ('client-certificate-data', 'client-key-data'):
            require(len(base64.b64decode(user['user'][key], validate=True)) > 0, 'client credential absent')
    except (ValueError, TypeError):
        raise Failure('kubeconfig credentials refused') from None
    require(ca.startswith(b'-----BEGIN CERTIFICATE-----'), 'CA data refused')
    return digest(ca)


def kubectl(args, deadline):
    try:
        return execute([KUBECTL, '--kubeconfig', str(WORK / 'vlab/kubeconfig'),
                        '--request-timeout=10s', *args], deadline, 10, user=True)
    except Failure as error:
        # v1.35.0 kubectl cmd/util/helpers.go formats these known cases. Never
        # treat arbitrary exit1/authentication/x509 failures as startup pending.
        raw = error.private_output
        refused = (b'The connection to the server 127.0.0.1:6443 was refused - '
                   b'did you specify the right host or port?\n')
        unavailable = re.fullmatch(rb'Error from server \(ServiceUnavailable\): [^\r\n]{1,4096}\n?', raw)
        if error.code == 1 and str(error) == 'child command failed' and (raw == refused or unavailable):
            raise Pending('API discovery pending') from None
        raise


def object_identity(doc):
    meta = doc['metadata']
    # Server metadata/status are excluded explicitly; specs remain exact.
    return (doc['apiVersion'], doc['kind'], meta.get('namespace', 'default'), meta['name'])


def object_value(doc):
    meta = doc['metadata']
    return {'identity': object_identity(doc), 'labels': meta.get('labels', {}),
            'annotations': meta.get('annotations', {}), 'spec': doc.get('spec', {})}


def api_objects(resource, namespace, deadline):
    args = ['get', resource, '-o', 'json']
    args += ['-A'] if namespace is None else ['-n', namespace]
    data = json_data(kubectl(args, deadline))
    require(type(data) is dict and type(data.get('items')) is list and len(data['items']) <= 128,
            'API object list refused')
    return data['items']


def api_ready(deadline):
    ca = kubeconfig()
    if kubectl(['get', '--raw=/readyz'], deadline).strip() != b'ok':
        raise Pending('API not ready')
    nodes = api_objects('nodes', None, deadline)
    if not nodes:
        raise Pending('control node pending')
    require(len(nodes) == 1 and nodes[0]['metadata']['name'] == 'control-1', 'control node identity differs')
    if not any(c.get('type') == 'Ready' and c.get('status') == 'True'
               for c in nodes[0].get('status', {}).get('conditions', [])):
        raise Pending('control node not ready')
    ns = json_data(kubectl(['get', 'namespace', 'kube-system', '-o', 'json'], deadline))
    cluster_uid = ns['metadata']['uid']
    require(type(cluster_uid) is str and 0 < len(cluster_uid) <= 128, 'cluster UID refused')
    installer = WORK / 'result' / RESULT
    expected = yaml_documents(read(installer / 'fab.yaml')) + yaml_documents(read(installer / 'include.yaml'))
    kinds = {'Fabricator': ('fabricators.fabricator.githedgehog.com', 1),
             'ControlNode': ('controlnodes.fabricator.githedgehog.com', 1),
             'FabNode': ('fabnodes.fabricator.githedgehog.com', 0),
             'Switch': ('switches.wiring.githedgehog.com', 7),
             'Server': ('servers.wiring.githedgehog.com', 10),
             'Connection': ('connections.wiring.githedgehog.com', 21),
             'SwitchGroup': ('switchgroups.wiring.githedgehog.com', 3),
             'VLANNamespace': ('vlannamespaces.wiring.githedgehog.com', 1),
             'IPv4Namespace': ('ipv4namespaces.vpc.githedgehog.com', 1)}
    require(all(d.get('kind') in kinds for d in expected), 'unexpected installer kind')
    observed = []
    for kind, (resource, count) in kinds.items():
        items = api_objects(resource, None, deadline)
        if len(items) < count:
            raise Pending('canonical API objects pending')
        require(len(items) == count and all(d.get('kind') == kind for d in items),
                'canonical API counts differ')
        observed.extend(items)
    expected_map = {object_identity(d): object_value(d) for d in expected}
    actual_map = {object_identity(d): object_value(d) for d in observed}
    require(len(expected_map) == len(expected) and len(actual_map) == len(observed)
            and actual_map == expected_map, 'canonical API objects differ')
    require({d['metadata']['name'] for d in observed if d['kind'] == 'Switch'} ==
            {name for name, kind in VMS.items() if kind == 'switch'}
            and {d['metadata']['name'] for d in observed if d['kind'] == 'Server'} ==
            {name for name, kind in VMS.items() if kind == 'server'}, 'canonical API identities differ')
    vm_config()
    return {'ca_sha256': ca, 'cluster_uid': cluster_uid}


def bridge_ready(deadline):
    execute([PYTHON, str(BRIDGE), '--bridge', 'hhbr', '--cidr', '172.30.0.2/21',
             '--wait-seconds', '60', '--poll-ms', '250'], deadline, 60)
    output = json_data(execute(['/usr/sbin/ip', '-j', '-d', 'link', 'show', 'dev', 'hhbr'], deadline, 3))
    require(type(output) is list and len(output) == 1, 'bridge query refused')
    link = output[0]
    require(link.get('ifname') == 'hhbr' and type(link.get('ifindex')) is int
            and link['ifindex'] > 0 and link.get('linkinfo', {}).get('info_kind') == 'bridge',
            'bridge identity refused')
    info = link['linkinfo'].get('info_data', {})
    require(all(info.get(key) == 0 for key in ('nf_call_iptables', 'nf_call_ip6tables', 'nf_call_arptables')),
            'bridge filtering differs')
    verify_netfilter()
    return link['ifindex']


def unit_ready(mode):
    original, deadline = startup_snapshot(mode)
    with locked(SIBLING_LOCK_SECONDS, deadline=deadline):
        value = state()
        pin = check_live(original, deadline)
        same_start(value, original, pin)
        value['service'] = pin
        save(value)
    bridge_index = bridge_ready(deadline)
    # Only file/API-discovery refusal may poll; strict inspection never retries.
    while True:
        remaining(deadline)
        check_live(value, deadline)
        try:
            observed = api_ready(deadline)
            break
        except (Pending, FileNotFoundError):
            time.sleep(min(5, remaining(deadline)))
    if mode == 'resume':
        require(observed == value['cluster'], 'resumed cluster identity differs')
    hhfab(['vlab', 'wait-switches'], deadline, cap=600)
    hhfab(['vlab', 'inspect-switches'], deadline, ['--strict=true', '--wait-applied-for', '30'], cap=600)
    require(api_ready(deadline) == observed and bridge_ready(deadline) == bridge_index,
            'post-inspection identity differs')
    check_live(value, deadline)
    critical = critical_snapshot(deadline)
    if mode == 'resume':
        require(critical == value['critical'], 'resume changed critical state')
    check_live(value, deadline)
    with locked(SIBLING_LOCK_SECONDS, deadline=deadline):
        current = state()
        require(current == value, 'readiness state changed')
        check_live(current, deadline)
        operation_deadline(current)
        current.update(phase='ready', critical=critical, cluster=observed)
        save(current)


def unit_finished(mode):
    # Called by ExecStopPost even on partial startup failure; never synchronously
    # stop this same unit from inside a unit command.
    with locked():
        value = state()
        require(value.get('mode') == mode and value.get('invocation') == invocation_env(),
                'finished invocation refused')
        if value['phase'] in ('starting', 'ready'):
            clean = os.environ.get('SERVICE_RESULT') == 'success'
            owned_stop = value.get('stopping') == {'operation': value['operation'],
                                                  'invocation': value['invocation']}
            # ExecStopPost observes manager completion, not final cgroup absence.
            # No new start may reserve until the public exact stop verifies it.
            value['phase'] = 'stop-observed' if value['phase'] == 'ready' and owned_stop else 'failed'
            value['service_result'] = ('owned-stop-process-termination' if owned_stop else
                                       'success' if clean else 'failed-or-unavailable')
            save(value)


def verify_inactive(mode, invocation, observed, deadline):
    """Positive post-stop receipt for only this fixed service and cgroup."""
    fields = system_show(mode, deadline)
    require(fields['ActiveState'] in ('inactive', 'failed') and fields.get('MainPID') == '0',
            'service stop unverified')
    require(fields.get('InvocationID') in ('', invocation) if invocation else
            fields.get('InvocationID') == '', 'post-stop invocation differs')
    group = '/system.slice/' + UNIT[mode]
    require(fields.get('ControlGroup') in ('', group)
            and (observed is None or observed['group'] == group), 'post-stop cgroup differs')
    cgroup = no_links(CGROUP / group.lstrip('/'))
    remaining(deadline)
    if cgroup.exists():
        events = pairs([line.split() for line in read(cgroup / 'cgroup.events', 4096).decode().splitlines()])
        require(events.get('populated') == '0', 'service cgroup remains populated')
    remaining(deadline)


def stop_owned(value, deadline):
    with stop_controller():
        return _stop_owned_locked(value, deadline)


def _stop_owned_locked(value, deadline):
    """Only called while stop_controller owns every outstanding manager stop."""
    with locked():
        current = state()
        require(current['operation'] == value['operation'] and current['mode'] == value['mode']
                and current.get('invocation') == value.get('invocation'), 'stop controller operation changed')
    fields = system_show(value['mode'], deadline)
    require(fields.get('InvocationID') in ('', value.get('invocation', '')),
            'stop invocation differs')
    observed = value.get('service')
    if fields['ActiveState'] not in ('inactive', 'failed'):
        require(value.get('invocation') and fields.get('InvocationID') == value['invocation'],
                'unowned service stop refused')
        if observed is not None and fields.get('MainPID') != '0':
            require(service_identity(fields) == observed, 'stop process changed')
        with locked():
            current = state()
            require(current['operation'] == value['operation']
                    and current.get('invocation') == value['invocation'], 'stop operation changed')
            current['stopping'] = {'operation': value['operation'], 'invocation': value['invocation']}
            save(current)
        execute([SYSTEMCTL, 'stop', UNIT[value['mode']]], deadline, 30)
    verify_inactive(value['mode'], value.get('invocation'), observed, deadline)
    with locked():
        current = state()
        require(current['operation'] == value['operation']
                and current.get('invocation') == value.get('invocation'), 'stop commit operation changed')
        if current['phase'] == 'stop-observed':
            binding = {'operation': value['operation'], 'invocation': value['invocation']}
            require(current.get('stopping') == binding, 'stop observation intent differs')
            current['phase'] = 'resumable' if current['mode'] == 'resume' else 'stopped'
            current['stop_verified'] = binding
            save(current)
        elif current['phase'] in ('stopped', 'resumable'):
            require(current.get('stop_verified') == {'operation': value['operation'],
                                                    'invocation': value['invocation']},
                    'previous stop verification absent')
        elif current['phase'] == 'ready':
            current['phase'] = 'failed'
            save(current)
            raise Failure('owned stop completion not observed')
        elif current['phase'] == 'starting':
            current['phase'] = 'failed'
            save(current)
    return True


def cleanup_start(value, deadline):
    """Keep failed startup reserved until all manager calls and receipts finish."""
    mode = value['mode']
    with stop_controller():
        with locked():
            current = state()
            require(current['operation'] == value['operation'] and current['mode'] == mode,
                    'cleanup operation changed')
        if 'invocation' not in current:
            fields = system_show(mode, deadline)
            with locked():
                current = state()
                require(current['operation'] == value['operation'] and current['mode'] == mode,
                        'cleanup operation changed')
            if 'invocation' in current:
                _stop_owned_locked(current, deadline)
            else:
                require(fields.get('InvocationID', '') == '' and fields.get('MainPID') == '0',
                        'ungated service identity uncertain')
                execute([SYSTEMCTL, 'stop', UNIT[mode]], deadline, 30)
                with locked():
                    current = state()
                    require(current['operation'] == value['operation'] and current['mode'] == mode,
                            'cleanup operation changed')
                verify_inactive(mode, current.get('invocation'), current.get('service'), deadline)
        else:
            _stop_owned_locked(current, deadline)
        with locked():
            current = state()
            require(current['operation'] == value['operation'] and current['mode'] == mode,
                    'cleanup operation changed')
            current['phase'] = 'failed'
            current['containment'] = 'verified'
            save(current)


def start(mode):
    end = time.monotonic() + START_SECONDS[mode]
    value = None
    try:
        # Reservation is inside the capture-first path: a refusal here has no
        # operation of its own, so the bundle binds null operation/invocation.
        value = reserve(mode, end)
        # The lock is RELEASED before synchronous manager/dependency waiting.
        # Preserve the fixed last failed command before the generic manager wrapper
        # could overwrite it. The primary Failure still carries that wrapper's bytes.
        execute([SYSTEMCTL, 'start', UNIT[mode]], end, START_SECONDS[mode], retain=False)
        with locked():
            current = state()
            require(current['operation'] == value['operation'] and current['phase'] == 'ready',
                    'service did not establish readiness')
            check_live(current, end)
    except BaseException as primary:
        # First evidence is frozen BEFORE cleanup can overwrite last-command-output
        # or stop the unit. Diagnostic only: any failure here is swallowed and
        # cleanup below always runs with its own unchanged 35s budget.
        try:
            capture_first_failure(mode, value, primary, end)
        except BaseException:
            print('vlab-core: first-failure capture unverified', file=sys.stderr)
        # Preserve primary return/signal/timeout if exact cleanup cannot be verified.
        if value is not None:
            try:
                cleanup_start(value, time.monotonic() + 35)
            except BaseException:
                print('vlab-core: owned containment unverified', file=sys.stderr)
        raise


def stop():
    with locked():
        value = state()
        require(value['phase'] in ('ready', 'starting', 'stopped', 'failed', 'resumable', 'stop-observed'),
                'stop phase refused')
    stop_owned(value, time.monotonic() + 35)
    with locked():
        current = state()
        require(current['operation'] == value['operation'], 'stop operation changed')
        require(current['phase'] in ('failed', 'stopped', 'resumable'), 'stop state unverified')


def activate_resume():
    with locked():
        value = state()
        require(value['mode'] == 'fresh' and value['phase'] in ('ready', 'stopped')
                and 'critical' in value and 'cluster' in value, 'resume activation refused')
    stop_owned(value, time.monotonic() + 35)
    deadline = time.monotonic() + 120
    verify_contract(value, deadline)
    require(critical_snapshot(deadline) == value['critical'], 'post-stop critical state changed')
    with locked():
        current = state()
        require(current['operation'] == value['operation'] and current['phase'] == 'stopped'
                and current.get('stop_verified') == {'operation': value['operation'],
                                                     'invocation': value['invocation']},
                'activation operation changed')
        current['phase'] = 'resumable'
        save(current)
    execute([SYSTEMCTL, 'enable', UNIT['resume']], deadline, 10)


def main(argv=None):
    parser = Parser(allow_abbrev=False)
    parser.add_argument('action', choices=('prepare', 'start-fresh', 'activate-resume', 'start-resume',
                                        'stop', 'unit-gate', 'unit-run', 'unit-ready', 'unit-finished'))
    parser.add_argument('--input')
    parser.add_argument('--mode', choices=('fresh', 'resume'))
    try:
        tokens = sys.argv[1:] if argv is None else argv
        require(tokens.count('--input') <= 1 and tokens.count('--mode') <= 1, 'duplicate argument')
        args = parser.parse_args(tokens)
        require(os.geteuid() == 0, 'root required')
        require((args.action == 'prepare') == (args.input is not None)
                and args.action.startswith('unit-') == (args.mode is not None), 'invalid arguments')
        os.umask(0o077)
        if args.action == 'prepare':
            prepare(Path(args.input))
        elif args.action.startswith('start-'):
            start(args.action[6:])
        elif args.action == 'activate-resume':
            activate_resume()
        elif args.action == 'stop':
            stop()
        else:
            {'unit-gate': unit_gate, 'unit-run': unit_run, 'unit-ready': unit_ready,
             'unit-finished': unit_finished}[args.action](args.mode)
        print('vlab-core: operation complete')
        return 0
    except Failure as exc:
        print('vlab-core: ' + str(exc), file=sys.stderr)
        return exc.code
    except KeyboardInterrupt:
        print('vlab-core: interrupted', file=sys.stderr)
        return 130
    except Exception:
        print('vlab-core: operational failure', file=sys.stderr)
        return 1


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise Failure('terminated', 143 if signum == signal.SIGTERM else 130)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    sys.exit(main())
