"""Narrow owner caller: ONE manual private-image clone VM, two real boots, exact disposal (#546).

Python 3.12 stdlib. Trusted owner/Root host only; no import-time IO. This is NOT the managed
lifecycle: it never touches the canonical ledger, slot, Context, OwnerRegistration, Master or
managed access records, and it never claims a canonical FREE. It reuses only low-level accepted
parts: ``auth_http`` bearer/HTTP, ``oslogin.SelfLogin`` primitives, canonical public-key helpers,
``hostkey.extract_ed25519``, ``vlab_trial.ssh_options``/``command`` and ``owned_process``.

Commands (``private_clone.main`` via the fixed protected-source bootstrap, see ``unit_argv``):
``arm`` writes the immutable manifest into a fresh private workdir; ``run`` performs the one serial
attempt as the MainPID of the exact owner systemd service; ``cleanup`` and ``watch`` are the
independent disposal interface (the durable watch service). Independent disposal first stops that
bound owner service and positively proves it inactive with an empty cgroup; only the live caller's
own ``OwnedGroup`` reaps its children in-process. There is no PID/pgid based cross-process reaper.
Code grants no permission: fresh admission facts, the units and a reviewed Ops wrapper are separate
Root obligations.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import urlencode

from . import owned_process
from . import vlab_trial as host
from .inspection.hostkey import extract_ed25519
from .lifecycle import spec
from .lifecycle.access_records import AccessError, canonical, digest, public_key
from .lifecycle.auth_http import HttpTransport, bearer_headers, gcloud_token
from .lifecycle.oslogin import SelfLogin, _identity, _match, _wire

PROJECT, ZONE, REGION = spec.PROJECT, spec.ZONE, spec.REGION
OWNER = host.OWNER
SELF_USER = 'users/110405050082684214272'
IMAGE_NAME = 'labapp-private-r42446688327-a1'
IMAGE_ID = '1649408968157411841'
SOURCE_DISK_ID = '7292285895271663486'
MACHINE, DISK_GB, DISK_TYPE = 'n2-standard-32', '500', 'pd-balanced'
LABEL_OWNER, LABEL_UUID, OWNER_VALUE = 'labapp-manual-clone', 'labapp-manual-clone-uuid', 'private-clone-v1'
BASE = 'https://compute.googleapis.com/compute/v1'

DELETE_SECONDS = 60 * 60        # absolute provider DELETE (scheduling.terminationTime)
WORK_SECONDS = 45 * 60          # work deadline; the remaining 15 minutes are the cleanup reserve
KEY_SECONDS = 20 * 60           # per-boot OS Login key TTL (clipped to the work deadline)
READY_SECONDS = 13 * 60         # host readiness observation inside one access phase
STOP_SECONDS = 360              # stop-verified cap; the rest of the 20 minutes covers teardown
STOP_MIN_SECONDS = 120
TEARDOWN_SECONDS = 30
MIN_ACCESS_SECONDS = 600        # least usable access window worth importing a key for
RESET_MIN_SECONDS = MIN_ACCESS_SECONDS + 120
LAUNCH_WINDOW_SECONDS = 600     # `run` must start this soon after `arm`; never renewed
CLEANUP_POLL_SECONDS = 300      # bound on one polling pass; elapsed time never settles a mutation
STOP_RUN_SECONDS = 90           # `systemctl stop` of the owner: TimeoutStopUSec 30s + final SIGKILL margin
MASTER_ATTEMPTS = 4
LIMIT = 65536

UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')
NAME_RE = re.compile(r'labapp-clone-[0-9a-f]{12}\Z')
OP_RE = re.compile(r'[A-Za-z0-9_-]{1,200}\Z')
DIGITS = re.compile(r'[1-9][0-9]{0,19}\Z')
BOOT_RE = re.compile(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
HEX32, HEX64 = re.compile(r'[0-9a-f]{32}\Z'), re.compile(r'[0-9a-f]{64}\Z')
UNIT_RE = re.compile(r'labapp-clone-(watch|run)-[0-9a-f]{12}\.service\Z')
KIND_RE = re.compile(r'[a-z0-9]+(-[a-z0-9]+)*\Z')
# Accepted runtime and protected source on the owner host (#349/#266 lineage); never configurable.
RUNTIME_PYTHON = '/home/ubuntu/.local/opt/labapp-cpython-3.12.16-20261026/python/bin/python3.12'
PROTECTED_SOURCE = '/home/ubuntu/.local/share/labapp-trial-egress-349/source'
SERVICE_USER = 'ubuntu'
SYSTEMCTL = '/usr/bin/systemctl'
OWNER_STOP_TIMEOUT = '30s'
# Isolated (-I), no-bytecode (-B) run of the protected source. No whitespace, so the ExecStart argv is exact.
BOOTSTRAP = ('__import__("sys").path.insert(0,"' + PROTECTED_SOURCE + '");'
             '__import__("sys").exit(__import__("build.gcp.private_clone",fromlist=["main"]).main())')
UNIT_PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlGroup', 'InvocationID', 'Type',
                   'User', 'WorkingDirectory', 'Restart', 'KillMode', 'SendSIGKILL', 'TimeoutStopUSec',
                   'RemainAfterExit', 'ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost',
                   'ExecReload')
LOCAL_FILES = ('oslogin', 'oslogin.pub', 'known_hosts', 'master.sock')
METADATA = (('block-project-ssh-keys', 'TRUE'), ('enable-oslogin', 'TRUE'),
            ('enable-guest-attributes', 'TRUE'), ('labapp-stage', 'none'))


class CloneError(Exception):
    """Fixed nonsecret failure; messages never carry URLs, tokens, keys or server text."""


class NotSent(CloneError):
    """Provably nothing was submitted (credential or deadline gate)."""


class Expired(NotSent):
    pass


class NotFound(CloneError):
    pass


class Uncertain(CloneError):
    """Transport/5xx/malformed outcome: a mutation may or may not have happened."""


class Rejected(CloneError):
    def __init__(self, status):
        super().__init__('Compute request rejected')
        self.status = status


class Unreconciled(CloneError):
    """An issued mutation has no exact terminal operation/outcome yet: the obligation stays open."""


class Refused(CloneError):
    pass


class Mismatch(Refused):
    pass


def require(ok, message='private clone refused'):
    if not ok:
        raise Refused(message)


def stamp(value):
    try:
        moment = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        require(spec.rfc3339(moment) == value)
        return moment.timestamp()
    except (ValueError, TypeError):
        raise Refused('invalid timestamp') from None


def iso(epoch):
    return spec.rfc3339(datetime.fromtimestamp(int(epoch), timezone.utc))


# ------------------------------------------------------------------------------ injection ----
@dataclass
class Deps:
    """Everything with side effects. Tests inject synthetic versions of each member."""
    http: object
    token_provider: Callable[[], str]
    runner: Callable
    wall: Callable[[], float] = time.time
    mono: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    popen: Callable = subprocess.Popen
    master_factory: Optional[Callable] = None
    proc_root: str = '/proc'
    cgroup_root: str = '/sys/fs/cgroup'
    shield: Callable[[], None] = lambda: None
    env: dict = field(default_factory=lambda: dict(os.environ))

    def now(self):
        return datetime.fromtimestamp(self.wall(), timezone.utc)

    @classmethod
    def real(cls):
        return cls(HttpTransport(), gcloud_token, host.command)


class Budget:
    """Wall AND monotonic work bound anchored once; nothing renews it."""
    def __init__(self, manifest, deps):
        self.deps = deps
        self.work_end = stamp(manifest['work_deadline'])
        self.w0, self.m0 = deps.wall(), deps.mono()
        require(stamp(manifest['admitted_at']) <= self.w0 < self.work_end, 'admission window over')
        self.mono_end = self.m0 + (self.work_end - self.w0)

    def work(self):
        left = min(self.work_end - self.deps.wall(), self.mono_end - self.deps.mono())
        if left <= 0:
            raise Expired('work deadline reached')
        return left


class Window:
    """One access/readiness window with TWO independent original ends (wall and monotonic), both
    anchored by the creator BEFORE the work they bound and always clipped to the work deadline.
    A child can only shorten, never re-anchor or extend, its parent's original ends."""
    def __init__(self, deps, budget, end_wall, end_mono):
        self.deps, self.budget, self.end_wall, self.end_mono = deps, budget, end_wall, end_mono

    def remaining(self):
        left = min(self.end_wall - self.deps.wall(), self.end_mono - self.deps.mono(), self.budget.work())
        if left <= 0:
            raise Expired('access window ended')
        return left

    def sub(self, seconds):
        return Window(self.deps, self.budget, min(self.end_wall, self.deps.wall() + seconds),
                      min(self.end_mono, self.deps.mono() + seconds))


# ------------------------------------------------------------------------------ manifest ------
MANIFEST_FIELDS = {'schema', 'uuid', 'request_id', 'name', 'project', 'zone', 'image_name', 'image_id',
                   'source_disk_id', 'admitted_at', 'work_deadline', 'termination'}


def new_manifest(deps):
    ownership = str(uuid.uuid4())
    admitted = int(deps.wall())
    return {'schema': 1, 'uuid': ownership, 'request_id': str(uuid.uuid4()),
            'name': 'labapp-clone-' + ownership.replace('-', '')[:12], 'project': PROJECT, 'zone': ZONE,
            'image_name': IMAGE_NAME, 'image_id': IMAGE_ID, 'source_disk_id': SOURCE_DISK_ID,
            'admitted_at': iso(admitted), 'work_deadline': iso(admitted + WORK_SECONDS),
            'termination': iso(admitted + DELETE_SECONDS)}


def check_manifest(m):
    require(isinstance(m, dict) and set(m) == MANIFEST_FIELDS and m['schema'] == 1, 'manifest fields')
    require(all(isinstance(m[k], str) and UUID_RE.fullmatch(m[k]) for k in ('uuid', 'request_id'))
            and m['uuid'] != m['request_id'], 'manifest UUIDs')
    require(m['name'] == 'labapp-clone-' + m['uuid'].replace('-', '')[:12], 'manifest name')
    require((m['project'], m['zone'], m['image_name'], m['image_id'], m['source_disk_id']) ==
            (PROJECT, ZONE, IMAGE_NAME, IMAGE_ID, SOURCE_DISK_ID), 'manifest pins')
    admitted = stamp(m['admitted_at'])
    require(stamp(m['work_deadline']) == admitted + WORK_SECONDS and
            stamp(m['termination']) == admitted + DELETE_SECONDS, 'manifest deadlines')
    return m


def load_manifest(directory, sha):
    raw = Store(directory).raw('manifest', 4096)
    require(raw is not None and re.fullmatch(r'[0-9a-f]{64}', str(sha)) and
            hashlib.sha256(raw).hexdigest() == sha, 'manifest digest mismatch')
    return check_manifest(json.loads(raw))


def watch_unit(manifest):
    return 'labapp-clone-watch-' + manifest['name'][-12:] + '.service'


def owner_unit(manifest):
    return 'labapp-clone-run-' + manifest['name'][-12:] + '.service'


def unit_argv(manifest, directory, sha, verb):
    """Exact ExecStart argv for the owner (``run``), the watch (``watch``) or a one-shot ``cleanup``.

    One accepted runtime and one protected source for all three; isolated (-I) and no bytecode (-B).
    """
    require(verb in ('run', 'watch', 'cleanup'), 'unit verb refused')
    argv = [RUNTIME_PYTHON, '-I', '-B', '-c', BOOTSTRAP, verb, '--workdir', str(directory),
            '--owner-unit', owner_unit(manifest)]
    if verb == 'run':
        argv += ['--watchdog-unit', watch_unit(manifest)]
    return argv + ['--manifest-sha256', sha]


def build_body(m):
    zone = 'zones/' + ZONE
    labels = {LABEL_OWNER: OWNER_VALUE, LABEL_UUID: m['uuid']}
    return {
        'name': m['name'], 'machineType': f'{zone}/machineTypes/{MACHINE}', 'labels': labels,
        'minCpuPlatform': 'Intel Cascade Lake',
        'advancedMachineFeatures': {'enableNestedVirtualization': True},
        'disks': [{'boot': True, 'autoDelete': True, 'mode': 'READ_WRITE', 'deviceName': 'boot',
                   'type': 'PERSISTENT',
                   'initializeParams': {'diskName': m['name'],
                                        'sourceImage': f'projects/{PROJECT}/global/images/{IMAGE_NAME}',
                                        'diskSizeGb': DISK_GB, 'diskType': f'{zone}/diskTypes/{DISK_TYPE}',
                                        'labels': labels}}],
        'networkInterfaces': [{'subnetwork': f'regions/{REGION}/subnetworks/default'}],
        'serviceAccounts': [], 'canIpForward': False, 'deletionProtection': False,
        'scheduling': {'provisioningModel': 'STANDARD', 'onHostMaintenance': 'TERMINATE',
                       'automaticRestart': False, 'terminationTime': m['termination'],
                       'instanceTerminationAction': 'DELETE'},
        'metadata': {'items': [{'key': k, 'value': v} for k, v in METADATA]},
    }


# ------------------------------------------------------------------------------ durable store -
class Store:
    """Exclusive one-shot records in the trusted private workdir (also the recovery evidence)."""
    def __init__(self, directory):
        self.dir = Path(directory)

    def path(self, kind):
        require(isinstance(kind, str) and len(kind) <= 48 and KIND_RE.fullmatch(kind), 'record kind')
        return self.dir / (kind + '.json')

    def has(self, kind):
        return os.path.lexists(self.path(kind))

    def create(self, kind, value):
        raw = canonical(value)
        require(len(raw) <= LIMIT, 'record too large')
        try:
            fd = os.open(self.path(kind), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            raise Refused('one-shot record already exists') from None
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(self.dir, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return raw

    def raw(self, kind, limit=LIMIT):
        try:
            fd = os.open(self.path(kind), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                    and not info.st_mode & 0o077 and info.st_size <= limit, 'record identity refused')
            return os.read(fd, limit + 1)
        finally:
            os.close(fd)

    def read(self, kind):
        raw = self.raw(kind)
        if raw is None:
            return None
        try:
            value = json.loads(raw)
        except ValueError:
            raise Refused('record unreadable') from None
        require(isinstance(value, dict), 'record shape')
        return value

    def try_create(self, kind, value):
        with contextlib.suppress(CloneError, OSError):
            self.create(kind, value)


def private_directory(path, *, empty=False):
    path = host.guest.no_links(path)
    require(re.fullmatch('/[A-Za-z0-9_./-]+', str(path)) and len(str(path)) <= 60, 'workdir path refused')
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'owner private workdir required')
    if empty:
        require(not any(path.iterdir()), 'workdir must be fresh and empty')
    return path


def proc_start(pid, root='/proc'):
    try:
        text = Path(root, str(pid), 'stat').read_text()
        rest = text[text.rindex(')') + 2:].split()
        return int(rest[19]), rest[0]
    except (OSError, ValueError, IndexError):
        return None


# ------------------------------------------------------------------------------ Compute -------
def link_ok(path, value):
    return isinstance(value, str) and spec.resource_link(f'projects/{PROJECT}/{path}', value)


class CloneCompute:
    """Fixed-URL Compute v1 client for this one manual VM; never retries, never reshapes a body."""
    def __init__(self, http, token_provider):
        self.http, self.token_provider = http, token_provider

    def _call(self, method, url, body=None, gate=None):
        try:
            headers = bearer_headers(self.token_provider)
        except Exception:
            raise NotSent('credential acquisition failed') from None
        if gate is not None:
            gate()  # deadline check AFTER the token, immediately before submission
        headers['Accept'] = 'application/json'
        headers['Accept-Encoding'] = 'identity'
        if body:
            headers['Content-Type'] = 'application/json'
        try:
            response = self.http.request(method, url, headers=headers, body=body, timeout=20,
                                         max_bytes=1_048_576)
        except Exception:
            raise Uncertain('Compute transport outcome unavailable') from None
        status = getattr(response, 'status', None)
        if status == 404:
            raise NotFound('Compute resource not found')
        if type(status) is not int or status in (408, 429) or status >= 500:
            raise Uncertain('Compute outcome unavailable')
        if not 200 <= status < 300:
            raise Rejected(status)
        try:
            data = json.loads(response.body)
        except (ValueError, TypeError, UnicodeError):
            raise Uncertain('invalid Compute response') from None
        if not isinstance(data, dict):
            raise Uncertain('invalid Compute response')
        if gate is not None:
            try:
                gate()  # the response itself must also arrive inside the ORIGINAL wall+monotonic budget
            except Expired:
                raise Uncertain('deadline passed while the request was in flight') from None
        return data

    @staticmethod
    def _name(value):
        require(isinstance(value, str) and NAME_RE.fullmatch(value), 'resource name refused')
        return value

    def _zonal(self, collection, name=None, suffix=''):
        url = f'{BASE}/projects/{PROJECT}/zones/{ZONE}/{collection}'
        return url + ('/' + self._name(name) if name is not None else '') + suffix

    def image(self):
        return self._call('GET', f'{BASE}/projects/{PROJECT}/global/images/{IMAGE_NAME}')

    def instance(self, name):
        return self._call('GET', self._zonal('instances', name))

    def disk(self, name):
        return self._call('GET', self._zonal('disks', name))

    def operation(self, name):
        require(isinstance(name, str) and OP_RE.fullmatch(name), 'operation name refused')
        return self._call('GET', f'{BASE}/projects/{PROJECT}/zones/{ZONE}/operations/{name}')

    def operations_for(self, request_id):
        require(UUID_RE.fullmatch(request_id), 'request id refused')
        query = urlencode({'filter': f'clientOperationId = "{request_id}"', 'maxResults': 20})
        page = self._call('GET', f'{BASE}/projects/{PROJECT}/zones/{ZONE}/operations?{query}')
        if page.get('nextPageToken'):
            raise Uncertain('operation list is paginated; completeness unprovable')
        items = page.get('items', [])
        require(isinstance(items, list) and len(items) <= 20 and all(isinstance(i, dict) for i in items),
                'operation list refused')
        return items

    def insert(self, manifest, body, request_id, gate):
        require(body == build_body(manifest) and request_id == manifest['request_id'], 'insert body refused')
        payload = json.dumps(body, sort_keys=True, separators=(',', ':')).encode()
        return self._call('POST', self._zonal('instances', suffix='?' + urlencode({'requestId': request_id})),
                          payload, gate)

    def reset(self, name, request_id, gate):
        require(UUID_RE.fullmatch(request_id), 'request id refused')
        return self._call('POST', self._zonal('instances', name, '/reset?' + urlencode({'requestId': request_id})),
                          b'', gate)

    def delete(self, collection, name, request_id):
        require(collection in ('instances', 'disks') and UUID_RE.fullmatch(request_id), 'delete refused')
        return self._call('DELETE', self._zonal(collection, name, '?' + urlencode({'requestId': request_id})))


def check_operation(op, *, kind, collection, name, request_id, target_id=None, done, strict=False,
                    op_name=None, op_id=None):
    """Kind, principal, client request ID, target link and ID, and (when terminal) no error.

    ``strict`` additionally requires ``compute#operation``, the numeric immutable operation ID and the
    zone link; ``op_name``/``op_id`` pin one already-learned operation so polling cannot drift to
    another. An error or httpErrorStatusCode is only legal on a DONE operation.
    """
    ok = (isinstance(op, dict) and op.get('operationType') == kind and op.get('clientOperationId') == request_id
          and op.get('user') == OWNER and isinstance(op.get('name'), str) and OP_RE.fullmatch(op['name'])
          and link_ok(f'zones/{ZONE}/{collection}/{name}', op.get('targetLink'))
          and (op.get('zone') is None or link_ok(f'zones/{ZONE}', op.get('zone')))
          and op.get('status') in ('PENDING', 'RUNNING', 'DONE')
          and (target_id is None or op.get('targetId') == target_id)
          and op.get('kind', 'compute#operation') == 'compute#operation'
          and (op.get('id') is None or (isinstance(op['id'], str) and DIGITS.fullmatch(op['id'])))
          and (op_name is None or op.get('name') == op_name) and (op_id is None or op.get('id') == op_id)
          and (op.get('status') == 'DONE' or not (op.get('error') or op.get('httpErrorStatusCode'))))
    if ok and strict:
        ok = (op.get('kind') == 'compute#operation' and isinstance(op.get('id'), str)
              and link_ok(f'zones/{ZONE}', op.get('zone')))
    if not ok:
        raise Mismatch('operation identity mismatch')
    if done and (op.get('status') != 'DONE' or op.get('error') or op.get('httpErrorStatusCode')):
        raise Mismatch('operation not successfully terminal')
    return op


def failed_operation(op):
    """True for a DONE operation that carries an error (a definite, terminal, unsuccessful outcome)."""
    return bool(op.get('error') or op.get('httpErrorStatusCode'))


def wait_operation(cloud, deps, first, check, expired):
    """Poll ONE operation (same name and numeric ID throughout). ``expired`` gates every answer, even DONE."""
    op = first
    name, ident = first.get('name'), first.get('id')
    while True:
        check(op, False)
        if op.get('name') != name or op.get('id') != ident:
            raise Mismatch('operation identity changed while polling')
        expired()
        if op.get('status') == 'DONE':
            check(op, True)
            return op
        deps.sleep(2)
        op = cloud.operation(name)


def verify_image(image):
    require(isinstance(image, dict) and image.get('name') == IMAGE_NAME and image.get('id') == IMAGE_ID
            and image.get('status') == 'READY' and image.get('sourceDiskId') == SOURCE_DISK_ID,
            'private image identity/provenance mismatch')


def verify_disk(disk, m, disk_id=None, *, ready=True):
    labels = disk.get('labels') or {}
    ok = (disk.get('name') == m['name'] and (disk.get('status') == 'READY' or not ready)
          and str(disk.get('sizeGb')) == DISK_GB
          and link_ok(f'zones/{ZONE}/diskTypes/{DISK_TYPE}', disk.get('type'))
          and disk.get('sourceImageId') == IMAGE_ID
          and link_ok(f'global/images/{IMAGE_NAME}', disk.get('sourceImage'))
          and labels.get(LABEL_UUID) == m['uuid'] and labels.get(LABEL_OWNER) == OWNER_VALUE
          and isinstance(disk.get('id'), str) and DIGITS.fullmatch(disk['id'])
          and (disk_id is None or disk['id'] == disk_id))
    if not ok:
        raise Mismatch('boot disk identity/provenance mismatch')
    return disk['id']


def verify_vm(vm, m, vm_id=None):
    expected = build_body(m)
    sched = vm.get('scheduling') or {}
    nics = vm.get('networkInterfaces') or []
    disks = vm.get('disks') or []
    items = (vm.get('metadata') or {}).get('items', [])
    try:
        ends = datetime.fromisoformat(sched['terminationTime'].replace('Z', '+00:00')).timestamp()
    except (KeyError, ValueError, TypeError, AttributeError):
        ends = None
    ok = (vm.get('name') == m['name'] and vm.get('status') == 'RUNNING'
          and isinstance(vm.get('id'), str) and DIGITS.fullmatch(vm['id']) and (vm_id is None or vm['id'] == vm_id)
          and (vm.get('labels') or {}) == expected['labels']
          and link_ok(f'zones/{ZONE}/machineTypes/{MACHINE}', vm.get('machineType'))
          and vm.get('minCpuPlatform') == expected['minCpuPlatform']
          and (vm.get('advancedMachineFeatures') or {}).get('enableNestedVirtualization') is True
          and not vm.get('serviceAccounts') and not vm.get('guestAccelerators')
          and vm.get('canIpForward') is False and vm.get('deletionProtection') is False
          and sched.get('onHostMaintenance') == 'TERMINATE' and sched.get('automaticRestart') is False
          and sched.get('instanceTerminationAction') == 'DELETE' and ends == stamp(m['termination'])
          and len(nics) == 1 and not nics[0].get('accessConfigs') and not nics[0].get('ipv6AccessConfigs')
          and link_ok(f'regions/{REGION}/subnetworks/default', nics[0].get('subnetwork'))
          and isinstance(items, list) and all(isinstance(i, dict) and set(i) == {'key', 'value'} for i in items)
          and {i['key']: i['value'] for i in items} == dict(METADATA) and len(items) == len(METADATA)
          and len(disks) == 1 and disks[0].get('boot') is True and disks[0].get('autoDelete') is True
          and disks[0].get('mode') == 'READ_WRITE'
          and link_ok(f'zones/{ZONE}/disks/{m["name"]}', disks[0].get('source')))
    if not ok:
        raise Mismatch('VM identity/envelope mismatch')
    return vm['id']


# ------------------------------------------------------------------------------ guest summary --
SUMMARY = r'''import hashlib,json,os,subprocess,sys
def load(p,n):
    f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(f,'rb') as s:
        i=os.fstat(s.fileno())
        if i.st_uid!=0 or i.st_nlink!=1 or i.st_mode&0o077 or i.st_size>n: sys.exit(3)
        return json.loads(s.read(n+1))
def h(v): return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def unit(u):
    t=subprocess.run(['/usr/bin/systemctl','show',u,'-p','ActiveState','-p','InvocationID','-p','Result'],capture_output=True,text=True,timeout=10,check=True).stdout.splitlines()
    d=dict(l.split('=',1) for l in t)
    return {k:d.get(k) for k in ('ActiveState','InvocationID','Result')}
seal=load('/var/lib/labapp-vlab-image/seal.json',16384)
try: cp=load('/var/lib/labapp-vlab-image/clone-start.json',4096)
except FileNotFoundError: cp=None
st=load('/var/lib/labapp-vlab-core/state.json',8388608)
sv=st.get('stop_verified')
core={k:st.get(k) for k in ('nonce','phase','mode','boot','operation','invocation')}
core['stop_verified']={k:sv.get(k) for k in ('operation','invocation')} if isinstance(sv,dict) else None
core['critical_sha256']=h(st['critical']) if 'critical' in st else None
core['cluster_sha256']=h(st['cluster']) if 'cluster' in st else None
out={'boot':open('/proc/sys/kernel/random/boot_id').read().strip(),
 'seal':{k:seal.get(k) for k in ('state','owned_sealed','nonce','build_boot','core_operation','core_invocation')},
 'checkpoint':{k:cp.get(k) for k in ('boot','operation','invocation')} if isinstance(cp,dict) else None,
 'core':core,'clone':unit('labapp-vlab-clone.service'),'resume':unit('hhfab-vlab-resume.service')}
sys.stdout.write(json.dumps(out,sort_keys=True,separators=(',',':')))
'''
# The only remote commands this caller can ever run (no argument, path or shell input).
REMOTE = {
    'summary': ['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-c', SUMMARY],
    'stop-verified': ['/usr/bin/sudo', '-n', '/usr/bin/python3', '/usr/local/lib/labapp/vlab_image.py',
                      'stop-verified'],
}
STOP_MARKER = b'checkpointed backend stop verified'


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate summary field')
        result[key] = value
    return result


def _text(value, pattern=None, optional=False):
    if value is None and optional:
        return None
    require(isinstance(value, str) and len(value) <= 128 and (pattern is None or pattern.fullmatch(value)),
            'summary field refused')
    return value


def _unit(value):
    require(isinstance(value, dict) and set(value) == {'ActiveState', 'InvocationID', 'Result'}, 'summary unit')
    return {k: _text(value[k], None, True) for k in value}


def parse_summary(raw):
    """Exact closed schema of the fixed read-only summary; anything else is refused."""
    try:
        require(isinstance(raw, bytes) and 0 < len(raw) <= 4096)
        v = json.loads(raw.decode('ascii'), object_pairs_hook=_unique)
        require(isinstance(v, dict) and set(v) == {'boot', 'seal', 'checkpoint', 'core', 'clone', 'resume'})
        seal, core, cp = v['seal'], v['core'], v['checkpoint']
        require(isinstance(seal, dict) and set(seal) == {'state', 'owned_sealed', 'nonce', 'build_boot',
                                                         'core_operation', 'core_invocation'}
                and isinstance(core, dict) and set(core) == {'nonce', 'phase', 'mode', 'boot', 'operation',
                                                             'invocation', 'stop_verified', 'critical_sha256',
                                                             'cluster_sha256'})
        out = {'boot': _text(v['boot'], BOOT_RE),
               'seal': {'state': _text(seal['state']), 'owned_sealed': seal['owned_sealed'] is True,
                        'nonce': _text(seal['nonce'], HEX32), 'build_boot': _text(seal['build_boot'], BOOT_RE),
                        'core_operation': _text(seal['core_operation'], HEX32),
                        'core_invocation': _text(seal['core_invocation'], HEX32)}}
        if cp is None:
            out['checkpoint'] = None
        else:
            require(isinstance(cp, dict) and set(cp) == {'boot', 'operation', 'invocation'})
            out['checkpoint'] = {'boot': _text(cp['boot'], BOOT_RE), 'operation': _text(cp['operation'], HEX32),
                                 'invocation': _text(cp['invocation'], HEX32)}
        sv = core['stop_verified']
        require(sv is None or (isinstance(sv, dict) and set(sv) == {'operation', 'invocation'}))
        out['core'] = {'nonce': _text(core['nonce'], HEX32, True), 'phase': _text(core['phase'], None, True),
                       'mode': _text(core['mode'], None, True), 'boot': _text(core['boot'], BOOT_RE, True),
                       'operation': _text(core['operation'], HEX32, True),
                       'invocation': _text(core['invocation'], HEX32, True),
                       'stop_verified': None if sv is None else {k: _text(sv[k], HEX32, True) for k in sv},
                       'critical_sha256': _text(core['critical_sha256'], HEX64, True),
                       'cluster_sha256': _text(core['cluster_sha256'], HEX64, True)}
        out['clone'], out['resume'] = _unit(v['clone']), _unit(v['resume'])
        return out
    except (ValueError, UnicodeError, KeyError, TypeError, RecursionError):
        raise Refused('guest summary refused') from None


def readiness(s, prior=None):
    """'ready' | 'pending'; any contradiction of the clone-boot contract is a hard Mismatch."""
    seal, core, cp, clone, resume = s['seal'], s['core'], s['checkpoint'], s['clone'], s['resume']
    if not (seal['state'] == 'sealed' and seal['owned_sealed']):
        raise Mismatch('image is not the sealed image')
    if s['boot'] == seal['build_boot']:
        raise Mismatch('boot is the builder boot')
    if prior is not None and (s['boot'] == prior['boot'] or
                              (seal['nonce'], seal['build_boot']) != (prior['nonce'], prior['build_boot'])):
        raise Mismatch('second boot is not a new boot of the same sealed image')
    if core['nonce'] not in (None, seal['nonce']):
        raise Mismatch('core nonce differs from the sealed nonce')
    if clone['ActiveState'] == 'failed':
        raise Mismatch('unchanged clone auto-start failed')
    if core['phase'] != 'ready' or clone['ActiveState'] != 'active':
        return 'pending'
    older = {(seal['core_operation'], seal['core_invocation'])}
    if prior is not None:
        older.add((prior['operation'], prior['invocation']))
    pair = (core['operation'], core['invocation'])
    ok = (core['nonce'] == seal['nonce'] and core['mode'] == 'resume' and core['boot'] == s['boot']
          and cp is not None and cp['boot'] == s['boot'] and (cp['operation'], cp['invocation']) == pair
          and None not in pair and pair not in older and clone['Result'] == 'success'
          and resume['ActiveState'] == 'active' and resume['InvocationID'] == core['invocation']
          and core['critical_sha256'] is not None and core['cluster_sha256'] is not None
          and (prior is None or (core['critical_sha256'], core['cluster_sha256']) ==
               (prior['critical'], prior['cluster'])))
    if not ok:
        raise Mismatch('ready state does not match the clone-boot checkpoint contract')
    return 'ready'


def ready_record(s):
    core, seal = s['core'], s['seal']
    return {'boot': s['boot'], 'nonce': seal['nonce'], 'build_boot': seal['build_boot'],
            'operation': core['operation'], 'invocation': core['invocation'],
            'critical': core['critical_sha256'], 'cluster': core['cluster_sha256']}


def check_offline(s, ready):
    core, seal = s['core'], s['seal']
    pair = {'operation': ready['operation'], 'invocation': ready['invocation']}
    ok = (s['boot'] == ready['boot'] and (seal['nonce'], seal['build_boot']) == (ready['nonce'], ready['build_boot'])
          and core['phase'] == 'resumable' and core['boot'] == ready['boot'] and core['nonce'] == ready['nonce']
          and core['stop_verified'] == pair
          and {'operation': core['operation'], 'invocation': core['invocation']} == pair
          and s['clone']['ActiveState'] != 'active' and s['resume']['ActiveState'] != 'active'
          and core['critical_sha256'] in (None, ready['critical'])
          and core['cluster_sha256'] in (None, ready['cluster']))
    if not ok:
        raise Mismatch('backend is not positively offline at the verified stop')


def compare_boots(first, second):
    ok = (first['boot'] != second['boot'] and first['nonce'] == second['nonce']
          and first['build_boot'] == second['build_boot'] and first['critical'] == second['critical']
          and first['cluster'] == second['cluster']
          and (first['operation'], first['invocation']) != (second['operation'], second['invocation'])
          and first['operation'] != second['operation'] and first['invocation'] != second['invocation'])
    if not ok:
        raise Mismatch('boot proofs are inconsistent')


# ------------------------------------------------------------------------------ SSH master ----
class CloneMaster:
    """Explicit per-boot IAP/SSH master for ONE named VM; fixed remote commands only."""
    def __init__(self, directory, name, vm_id, username, deps, record=None):
        self.directory, self.name, self.deps, self.record = Path(directory), name, deps, record
        self.options = host.ssh_options(self.directory, vm_id, username)
        self.target = 'labapp-trial-' + vm_id
        self.proc = self.group = self.socket_identity = None
        self.spawn_attempted = self.started = False

    def proxy(self):
        return shlex.join(['gcloud', 'compute', 'start-iap-tunnel', self.name, '22', '--project=' + PROJECT,
                           '--zone=' + ZONE, '--listen-on-stdin', '--quiet', '--verbosity=error'])

    def start_argv(self):
        return ['/usr/bin/ssh', *self.options, '-M', '-N', '-o', 'ControlMaster=yes',
                '-o', 'ProxyCommand=' + self.proxy(), self.target]

    def check_argv(self):
        return ['/usr/bin/ssh', *self.options, '-o', 'ProxyCommand=/usr/bin/false', '-O', 'check', self.target]

    def remote_argv(self, key):
        # ControlMaster=no alone would reconnect; the failing ProxyCommand is mandatory on every call.
        return ['/usr/bin/ssh', *self.options, '-o', 'ControlMaster=no', '-o', 'ProxyCommand=/usr/bin/false',
                self.target, shlex.join(REMOTE[key])]

    def live(self):
        try:
            return self.group is not None and self.group.status() is None
        except owned_process.OwnershipUncertain:
            return False

    def check(self, until):
        require(self.live() and self.socket_identity is not None, 'original master lost')
        info = (self.directory / 'master.sock').lstat()
        require((info.st_dev, info.st_ino) == self.socket_identity, 'original master socket replaced')
        self.deps.runner(self.check_argv(), host.Master.slice(5, until), until=until)

    def start(self, window):
        require(not self.started, 'master replacement refused')
        self.started = True
        until = owned_process.monotonic() + min(30, window.remaining())
        self.spawn_attempted = True
        try:
            self.proc = self.deps.popen(self.start_argv(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, start_new_session=True)
            self.group = owned_process.OwnedGroup(self.proc)
            if self.record is not None:
                self.record(self.proc.pid)
        except BaseException as error:
            error.cleanup_uncertain = True
            raise
        while owned_process.monotonic() < until:
            require(self.live(), 'original master exited')
            path = self.directory / 'master.sock'
            if path.exists():
                info = path.lstat()
                require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid(), 'master socket refused')
                self.socket_identity = (info.st_dev, info.st_ino)
                self.check(until)
                return
            self.deps.sleep(.1)
        raise Expired('master startup timed out')

    def remote(self, key, window, cap=30):
        require(key in REMOTE, 'remote command refused')
        seconds = min(cap, window.remaining())
        until = owned_process.monotonic() + seconds
        self.check(until)
        raw = self.deps.runner(self.remote_argv(key), host.Master.slice(seconds, until), limit=8192, until=until)
        self.check(until)
        try:
            window.remaining()
        except Expired:
            raise Uncertain('access window passed after a remote command') from None
        return raw

    def close(self):
        if self.group is None:
            return self.proc is None and not self.spawn_attempted
        try:
            if self.group.outcome is not None:
                return self.group.close(0)
            return self.group.close(owned_process.TERM_GRACE_SECONDS, owned_process.CLEANUP_SECONDS,
                                    until=owned_process.monotonic() + 15)
        except BaseException:
            return False


# ------------------------------------------------------------------------------ units ---------
def parse_unit_show(raw):
    """Parse requested properties; systemctl omits empty Exec command arrays on the owner host.

    Only these five known empty arrays may be omitted. A configured command is rendered and
    remains nonempty for Units.check to refuse. Other missing properties still fail closed.
    """
    fields = {}
    for line in raw.decode('utf-8', 'replace').splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            require(key not in fields, 'duplicate unit property')
            fields[key] = value
    for prop in ('ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecReload'):
        fields.setdefault(prop, '')
    require(set(UNIT_PROPERTIES) <= set(fields), 'unit properties incomplete')
    return fields


EXEC_RE = re.compile(r'\{ path=(\S+) ; argv\[\]=(.*?) ; ignore_errors=(\S+) ;')


class Units:
    """The exact, manifest-bound owner and watch services.

    ``owner`` (``labapp-clone-run-<12>.service``) runs ``run``; ``watch`` (``labapp-clone-watch-<12>.service``)
    runs ``watch``. Both use ONLY the accepted runtime and protected source (``unit_argv``). Verification
    reads typed ``systemctl show`` properties and compares the whole ExecStart path/argv exactly; it never
    uses substring matching or a self-reported "armed" value. ``quiesce`` is the only way independent
    disposal may start: stop the bound owner, then prove it inactive with an empty cgroup.
    """
    def __init__(self, directory, sha, manifest, deps):
        self.dir, self.sha, self.m, self.deps = Path(directory), sha, manifest, deps
        self.owner, self.watch = owner_unit(manifest), watch_unit(manifest)

    def argv(self, role):
        return unit_argv(self.m, self.dir, self.sha, 'run' if role == 'owner' else 'watch')

    def name(self, role):
        return self.owner if role == 'owner' else self.watch

    def show(self, role):
        unit = self.name(role)
        require(UNIT_RE.fullmatch(unit), 'unit name refused')
        command = [SYSTEMCTL, 'show', unit]
        for prop in UNIT_PROPERTIES:
            command += ['-p', prop]
        return parse_unit_show(self._systemctl(command, 10))

    def _systemctl(self, command, seconds):
        try:
            return self.deps.runner(command, seconds, limit=16384)
        except Exception:
            raise Uncertain('systemctl outcome unavailable') from None

    def check(self, props, role):
        """Exact static configuration: identity, user, working directory, no restart, bounded kill, ExecStart."""
        expect = {'Id': self.name(role), 'LoadState': 'loaded', 'Type': 'simple', 'User': SERVICE_USER,
                  'WorkingDirectory': PROTECTED_SOURCE, 'Restart': 'no', 'RemainAfterExit': 'no',
                  'ExecStartPre': '', 'ExecStartPost': '', 'ExecStop': '', 'ExecStopPost': '', 'ExecReload': ''}
        if role == 'owner':
            expect.update({'KillMode': 'mixed', 'SendSIGKILL': 'yes', 'TimeoutStopUSec': OWNER_STOP_TIMEOUT})
        require(all(props.get(key) == value for key, value in expect.items()), 'unit configuration refused')
        argv, value = self.argv(role), props['ExecStart']
        require(value.count('{ path=') == 1 and EXEC_RE.findall(value) == [(argv[0], ' '.join(argv), 'no')],
                'unit ExecStart is not the exact reviewed argv')
        return props

    def running(self, role):
        """Verified, active unit. The owner must be this very process as the unit's MainPID in its cgroup."""
        props = self.check(self.show(role), role)
        require(props['ActiveState'] == 'active' and props['SubState'] == 'running', 'unit is not running')
        if role == 'owner':
            require(props['MainPID'] == str(os.getpid())
                    and props['ControlGroup'] == '/system.slice/' + self.owner
                    and HEX32.fullmatch(props['InvocationID']), 'owner unit is not this process')
        return props

    def owner_gone(self):
        try:
            props = self.check(self.show('owner'), 'owner')
        except CloneError:
            return False
        return props['ActiveState'] in ('inactive', 'failed')

    def procs(self):
        path = Path(self.deps.cgroup_root, 'system.slice', self.owner, 'cgroup.procs')
        try:
            return path.read_text().split()
        except FileNotFoundError:
            return []
        except OSError:
            raise Uncertain('owner cgroup unreadable') from None

    def quiesce(self):
        """Stop the BOUND owner unit (mixed kill + bounded final whole-cgroup SIGKILL) and prove it gone.

        Positive proof = verified unit config, ActiveState inactive/failed, SubState dead/failed, MainPID 0,
        no ControlGroup and an empty (or removed) cgroup.procs. Anything else is Uncertain: no disposal.
        """
        props = self.check(self.show('owner'), 'owner')
        if not (props['ActiveState'] in ('inactive', 'failed') and props['MainPID'] == '0'
                and not props['ControlGroup']):
            self._systemctl([SYSTEMCTL, 'stop', self.owner], STOP_RUN_SECONDS)
        after = self.check(self.show('owner'), 'owner')
        if not (after['ActiveState'] in ('inactive', 'failed') and after['SubState'] in ('dead', 'failed')
                and after['MainPID'] == '0' and not after['ControlGroup'] and not self.procs()):
            raise Uncertain('owner service is not proven inactive with an empty cgroup')


# ------------------------------------------------------------------------------ cleanup -------
class Cleaner:
    """Independent, idempotent disposal of exactly this manifest's resources.

    Two modes. In-process (``units is None``, used by ``Run``): the live caller has closed its own
    ``OwnedGroup`` masters and states so through ``quiet``; it never stops its own owner service.
    Independent (``units`` given: ``cleanup``/``watch``): the bound owner service is stopped and proven
    empty FIRST, then an exclusive work lock proves no work holder remains, then a durable ``disposal``
    marker forbids any later work mutation. Every issued mutation (INSERT/RESET/VM and disk DELETE)
    must reconcile to an exact terminal operation or a proven not-sent/rejected outcome; elapsed time and
    404 never settle anything. Every delete is a one-shot durable intent plus one request; nothing is
    replayed. It never claims a canonical FREE.
    """
    def __init__(self, store, manifest, deps, units=None, quiet=None):
        self.store, self.m, self.deps, self.units = store, manifest, deps, units
        self.cloud = CloneCompute(deps.http, deps.token_provider)
        self.login = SelfLogin.for_owner(SELF_USER, token_provider=deps.token_provider, transport=deps.http)
        self.quiet = quiet if quiet is not None else (lambda: True)
        self._quiesced = units is None
        self._depth = 0
        self._fd = None

    @contextlib.contextmanager
    def lock(self):
        if self._depth == 0:
            fd = os.open(self.store.dir / 'cleanup.lock', os.O_RDWR | os.O_NOFOLLOW)
            end = self.deps.mono() + 120
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if self.deps.mono() >= end:
                        os.close(fd)
                        raise Uncertain('another cleanup holds the lock') from None
                    self.deps.sleep(1)
            self._fd = fd
        self._depth += 1
        try:
            yield
        finally:
            self._depth -= 1
            if self._depth == 0:
                os.close(self._fd)
                self._fd = None

    @contextlib.contextmanager
    def work_exclusive(self):
        """Exclusive work lock: held shared for the whole life of ``run``, so this proves no active work."""
        fd = os.open(self.store.dir / 'work.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Uncertain('work lock is still held; owner not quiescent') from None
            yield
        finally:
            os.close(fd)

    # --- local files (no process action: closure is proven by OwnedGroup or by the owner cgroup)
    def local(self):
        clean = bool(self._quiesced and self.quiet())
        for n in (1, 2):
            directory = self.store.dir / f'b{n}'
            if not os.path.lexists(directory):
                continue
            for name in LOCAL_FILES:
                with contextlib.suppress(FileNotFoundError):
                    (directory / name).unlink()
            try:
                directory.rmdir()
            except OSError:
                clean = False
        return clean

    # --- own OS Login keys
    def remove_key(self, n):
        """-> 'none' | 'absent' | 'removed' | 'unresolved' for key ``n`` (exact wire only).

        Closed ONLY when a canonical SELF profile read proves the exact intended wire absent; a TTL expiry
        with the key still listed is 'unresolved'. One DELETE per key, never repeated; unrelated keys untouched.
        """
        with self.lock():
            intent = self.store.read(f'a{n}-intent')
            if intent is None:
                return 'none'
            wire = intent['public_key']
            previous = self.store.read(f'a{n}-removed')
            attempted = self.store.has(f'a{n}-delete')
            try:
                found = _match(self.login.profile(), wire)
                if found is None:
                    if previous is None:
                        self.store.create(f'a{n}-removed', {'outcome': 'absent'})
                        return 'removed' if attempted else 'absent'
                    return 'absent'
                if attempted:
                    return 'unresolved'   # one-shot: never a second DELETE
                self.store.create(f'a{n}-delete', {'fingerprint': found['fingerprint'], 'name': found['name']})
                with contextlib.suppress(AccessError):
                    self.login._delete_exact(found)
                if _match(self.login.profile(), wire) is None:
                    self.store.try_create(f'a{n}-removed', {'outcome': 'removed'})
                    return 'removed'
                return 'unresolved'
            except (AccessError, CloneError, OSError):
                return 'unresolved'

    # --- operations: exact identity, terminal outcome, no time-based settlement
    def _find_op(self, recorded, **identity):
        """The ONE operation issued for ``identity['request_id']`` (or None when none is listed)."""
        if recorded is not None:
            require(isinstance(recorded, dict) and isinstance(recorded.get('name'), str)
                    and OP_RE.fullmatch(recorded['name']) and isinstance(recorded.get('id'), str)
                    and DIGITS.fullmatch(recorded['id']), 'operation record refused')
            op = self.cloud.operation(recorded['name'])
            return check_operation(op, done=False, strict=True, op_name=recorded['name'], op_id=recorded['id'],
                                   **identity)
        ops = self.cloud.operations_for(identity['request_id'])
        if not ops:
            return None
        if len(ops) != 1:
            raise Mismatch('ambiguous operations for one request')
        return check_operation(ops[0], done=False, strict=True, **identity)

    def _terminal(self, first, **identity):
        """Poll the SAME operation (name and numeric ID) to DONE -> 'ok' | 'failed'; else Uncertain."""
        end = self.deps.mono() + CLEANUP_POLL_SECONDS
        name, ident, op = first['name'], first['id'], first
        while True:
            check_operation(op, done=False, strict=True, op_name=name, op_id=ident, **identity)
            if op['status'] == 'DONE':
                return 'failed' if failed_operation(op) else 'ok'
            if self.deps.mono() >= end:
                raise Uncertain('operation not terminal in the cleanup budget')
            self.deps.sleep(2)
            op = self.cloud.operation(name)

    def _settle_op(self, recorded, **identity):
        op = self._find_op(recorded, **identity)
        if op is None:
            raise Unreconciled('issued mutation has no exact operation; submission cannot be ruled out')
        return self._terminal(op, **identity)

    @staticmethod
    def _definite(outcome):
        return outcome is not None and outcome.get('state') in ('not-sent', 'rejected')

    def _known_ids(self):
        return self.store.read('ids') or self.store.read('bound') or {}

    def settled_insert(self):
        m, store = self.m, self.store
        if not self._definite(store.read('insert-outcome')):
            self._settle_op(store.read('insert-op'), kind='insert', collection='instances', name=m['name'],
                            request_id=m['request_id'], target_id=self._known_ids().get('vm_id'))
        return True

    def settled_reset(self):
        reset, store = self.store.read('reset-intent'), self.store
        if reset is not None and not self._definite(store.read('reset-outcome')):
            self._settle_op(store.read('reset-op'), kind='reset', collection='instances', name=self.m['name'],
                            request_id=reset['request_id'], target_id=reset['vm_id'])
        return True

    def settled(self):
        """True only when every issued INSERT/RESET is proven not-sent/rejected or exactly terminal."""
        return self.settled_insert() and self.settled_reset()

    # --- VM and boot disk
    def _owned_vm(self, vm):
        labels = vm.get('labels') or {}
        known, deleting = self._known_ids(), self.store.read('vm-delete-intent')
        disks = vm.get('disks')
        return (vm.get('name') == self.m['name'] and labels.get(LABEL_UUID) == self.m['uuid']
                and labels.get(LABEL_OWNER) == OWNER_VALUE and isinstance(vm.get('id'), str)
                and DIGITS.fullmatch(vm['id']) and known.get('vm_id') in (None, vm['id'])
                and (deleting is None or deleting.get('resource_id') == vm['id'])
                and isinstance(disks, list) and len(disks) == 1
                and link_ok(f'zones/{ZONE}/disks/{self.m["name"]}', disks[0].get('source')))

    def _settle_delete(self, collection, kind_prefix):
        """Reconcile an ALREADY ISSUED delete (also when the resource is already 404). Never re-sends."""
        previous = self.store.read(f'{kind_prefix}-delete-intent')
        require(previous is not None, 'no delete intent to reconcile')
        if self._definite(self.store.read(f'{kind_prefix}-delete-outcome')):
            return 'rejected'
        require(isinstance(previous.get('resource_id'), str) and DIGITS.fullmatch(previous['resource_id'])
                and UUID_RE.fullmatch(str(previous.get('request_id'))), 'delete intent refused')
        return self._settle_op(self.store.read(f'{kind_prefix}-delete-op'), kind='delete', collection=collection,
                               name=self.m['name'], request_id=previous['request_id'],
                               target_id=previous['resource_id'])

    def _delete(self, collection, kind_prefix, resource_id):
        """One-shot delete: durable intent, one request, terminal checked operation. Never replayed."""
        name, intent_kind = self.m['name'], f'{kind_prefix}-delete-intent'
        previous = self.store.read(intent_kind)
        if previous is not None:
            require(previous.get('resource_id') == resource_id, 'delete intent binds a different resource')
            return self._settle_delete(collection, kind_prefix)
        request = str(uuid.uuid4())
        self.store.create(intent_kind, {'request_id': request, 'resource_id': resource_id,
                                        'at': iso(self.deps.wall())})
        identity = dict(kind='delete', collection=collection, name=name, request_id=request, target_id=resource_id)
        try:
            first = self.cloud.delete(collection, name, request)
        except (NotFound, Rejected):
            self.store.try_create(f'{kind_prefix}-delete-outcome', {'state': 'rejected'})
            raise
        check_operation(first, done=False, strict=True, **identity)
        self.store.create(f'{kind_prefix}-delete-op', {'name': first['name'], 'id': first['id']})
        return self._terminal(first, **identity)

    def _absent(self, call):
        try:
            call(self.m['name'])
        except NotFound:
            return True
        return False

    def dispose(self):
        """-> (vm_state, disk_state), each 'never'|'absent'|'deleted'|'unresolved:<reason>'."""
        name, store = self.m['name'], self.store
        if not store.has('insert-intent'):
            return 'never', 'never'
        try:
            self.settled_insert()
        except (CloneError, KeyError, ValueError):
            return 'unresolved:insert-unsettled', 'unresolved:not-attempted'
        try:
            self.settled_reset()
        except (CloneError, KeyError, ValueError):
            return 'unresolved:reset-unsettled', 'unresolved:not-attempted'
        try:
            vm = self.cloud.instance(name)
        except NotFound:
            vm = None
        except CloneError:
            return 'unresolved:vm-read', 'unresolved:not-attempted'
        vm_state = 'absent'
        if vm is not None:
            if not self._owned_vm(vm):
                return 'unresolved:vm-ownership-mismatch', 'unresolved:not-attempted'
            try:
                disk = self.cloud.disk(name)
                disk_id = verify_disk(disk, self.m, self._known_ids().get('boot_id'), ready=False)
            except (CloneError, KeyError):
                return 'unresolved:disk-provenance', 'unresolved:not-attempted'
            if not store.has('ids'):
                store.try_create('bound', {'vm_id': vm['id'], 'boot_id': disk_id})
            try:
                self._delete('instances', 'vm', vm['id'])
                if not self._absent(self.cloud.instance):
                    return 'unresolved:vm-still-present', 'unresolved:not-attempted'
            except (CloneError, KeyError, ValueError):
                return 'unresolved:vm-delete', 'unresolved:not-attempted'
            vm_state = 'deleted'
        elif store.has('vm-delete-intent'):
            try:
                vm_state = 'absent' if self._settle_delete('instances', 'vm') == 'rejected' else 'deleted'
            except (CloneError, KeyError, ValueError):
                return 'unresolved:vm-delete', 'unresolved:not-attempted'
        try:
            disk = self.cloud.disk(name)
        except NotFound:
            if store.has('disk-delete-intent'):
                try:
                    self._settle_delete('disks', 'disk')
                except (CloneError, KeyError, ValueError):
                    return vm_state, 'unresolved:disk-delete'
                return vm_state, 'deleted'
            return vm_state, 'absent'
        except CloneError:
            return vm_state, 'unresolved:disk-read'
        try:
            disk_id = verify_disk(disk, self.m, self._known_ids().get('boot_id'), ready=False)
            self._delete('disks', 'disk', disk_id)
            if not self._absent(self.cloud.disk):
                return vm_state, 'unresolved:disk-still-present'
        except (CloneError, KeyError, ValueError):
            return vm_state, 'unresolved:disk-delete'
        return vm_state, 'deleted'

    def run(self):
        result = {'local': False, 'keys': {}, 'vm': 'unresolved:not-run', 'disk': 'unresolved:not-run',
                  'quiesced': 'in-process' if self.units is None else False, 'closed': False}
        try:
            if self.units is not None:
                self._quiesced = False
                self.units.quiesce()      # stop the bound owner and prove it empty BEFORE any disposal
                self._quiesced = True
                result['quiesced'] = True
            with contextlib.ExitStack() as stack:
                if self.units is not None:
                    stack.enter_context(self.work_exclusive())   # no active work can coexist
                stack.enter_context(self.lock())
                self.store.try_create('disposal', {'at': iso(self.deps.wall())})   # no work mutation may start
                result['local'] = self.local()
                result['keys'] = {str(n): self.remove_key(n) for n in (1, 2)}
                result['vm'], result['disk'] = self.dispose()
                result['local'] = self.local() and result['local']
                good = ('none', 'absent', 'removed')
                result['closed'] = (result['local'] and all(v in good for v in result['keys'].values())
                                    and result['vm'] in ('never', 'absent', 'deleted')
                                    and result['disk'] in ('never', 'absent', 'deleted'))
                if result['closed']:
                    self.store.try_create('closed', {'at': iso(self.deps.wall())})
        except (CloneError, OSError):
            pass
        return result


# ------------------------------------------------------------------------------ orchestration -
class Run:
    def __init__(self, directory, manifest, sha, deps, unit):
        self.dir, self.m, self.sha, self.deps, self.unit = Path(directory), manifest, sha, deps, unit
        self.store = Store(directory)
        self.budget = Budget(manifest, deps)
        self.cloud = CloneCompute(deps.http, deps.token_provider)
        self.units = Units(directory, sha, manifest, deps)
        self.unclosed = []     # masters whose OwnedGroup closure was not proven
        self.cleaner = Cleaner(self.store, manifest, deps, quiet=lambda: not self.unclosed)
        self.phase = 'start'
        self.ids = None
        self.boots = {}
        self.active_window = None
        self.work_fd = None

        def gated_token():
            token = deps.token_provider()
            self.gate()  # after token acquisition, before any SELF request
            if self.active_window is not None:
                self.active_window.remaining()
            return token
        self.login = SelfLogin.for_owner(SELF_USER, token_provider=gated_token, transport=deps.http)

    # --- guards
    def gate(self):
        """Original wall+monotonic work budget, and no work once disposal has begun."""
        if self.store.has('disposal'):
            raise Expired('disposal has begun')
        return self.budget.work()

    def late(self):
        """Gate for an answer that arrived AFTER a possible submission: expiry is Uncertain, never NotSent."""
        try:
            self.gate()
        except Expired:
            raise Uncertain('deadline passed after a possible submission') from None

    def hold_work_lock(self):
        """Shared work lock for the whole life of ``run``; independent disposal needs it exclusively."""
        fd = os.open(self.dir / 'work.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise Refused('work lock unavailable; disposal may be running') from None
        self.work_fd = fd
        require(not self.store.has('disposal'), 'disposal already begun')

    def release_work_lock(self):
        if self.work_fd is not None:
            os.close(self.work_fd)
            self.work_fd = None

    def verify_watchdog(self):
        """Exact owner (this process, MainPID, cgroup) and watch service; typed properties, exact argv."""
        require(self.unit == watch_unit(self.m), 'watchdog unit is not bound to this manifest')
        owner = self.units.running('owner')
        self.units.running('watch')
        return owner

    def identity(self):
        vm = self.cloud.instance(self.m['name'])
        verify_vm(vm, self.m, self.ids['vm_id'])
        verify_disk(self.cloud.disk(self.m['name']), self.m, self.ids['boot_id'])

    # --- preflight and create
    def preflight(self):
        self.phase = 'preflight'
        account = self.deps.runner(['gcloud', 'auth', 'list', '--filter=status:ACTIVE',
                                    '--format=value(account)'], 15).decode().strip()
        require(account == OWNER, 'active account differs')
        imp = self.deps.runner(['gcloud', 'config', 'get-value', 'auth/impersonate_service_account',
                                '--quiet'], 15).decode().strip()
        require(imp in ('', '(unset)') and not self.deps.env.get('CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT'),
                'impersonation unsupported')
        self.login.profile()  # profile.name must equal the canonical SELF user
        verify_image(self.cloud.image())
        for read in (self.cloud.instance, self.cloud.disk):
            try:
                read(self.m['name'])
            except NotFound:
                continue
            raise Refused('target name already exists')

    def create_vm(self):
        self.phase = 'insert'
        m, store = self.m, self.store
        body = build_body(m)
        self.verify_watchdog()
        self.gate()
        store.create('insert-intent', {'request_id': m['request_id'], 'body': body, 'body_sha256': digest(body),
                                       'at': iso(self.deps.wall())})
        try:
            op = self.cloud.insert(m, body, m['request_id'], self.gate)
        except NotSent:
            store.try_create('insert-outcome', {'state': 'not-sent'})
            raise
        except Rejected:
            store.try_create('insert-outcome', {'state': 'rejected'})
            raise
        except CloneError:
            store.try_create('insert-outcome', {'state': 'uncertain'})
            raise
        store.create('insert-outcome', {'state': 'accepted'})
        identity = dict(kind='insert', collection='instances', name=m['name'], request_id=m['request_id'],
                        strict=True)
        check_operation(op, done=False, **identity)
        store.create('insert-op', {'name': op['name'], 'id': op['id']})
        done = wait_operation(self.cloud, self.deps, op, lambda o, d: check_operation(o, done=d, **identity),
                              self.late)
        target = done.get('targetId')
        require(isinstance(target, str) and DIGITS.fullmatch(target), 'insert target ID missing')
        verify_vm(self.cloud.instance(m['name']), m, target)
        boot_id = verify_disk(self.cloud.disk(m['name']), m)
        self.late()
        self.ids = {'vm_id': target, 'boot_id': boot_id}
        store.create('ids', self.ids)

    # --- access
    def import_key(self, n, wire):
        m, store, login = self.m, self.store, self.login
        # Both original ends of the per-access window are anchored BEFORE intent/import, never after the response.
        w0, m0 = self.deps.wall(), self.deps.mono()
        now = datetime.fromtimestamp(int(w0), timezone.utc)
        work_end = datetime.fromtimestamp(self.budget.work_end, timezone.utc)
        end = min(datetime.fromtimestamp(now.timestamp() + KEY_SECONDS, timezone.utc), work_end)
        window = Window(self.deps, self.budget, end.timestamp(), min(m0 + KEY_SECONDS, self.budget.mono_end))
        self.active_window = window   # bounds every token/SELF request below, including confirmation
        try:
            profile = login.profile()
            require(_match(profile, wire) is None, 'intended key preexists; cannot import or adopt')
            posix = _identity(profile)
            if window.remaining() < MIN_ACCESS_SECONDS:
                raise Expired('insufficient time for an access window')
            expiry = str(int(end.timestamp() * 1_000_000))
            baseline = digest(sorted(_wire(k['key']) for k in profile.get('sshPublicKeys', {}).values()))
            store.create(f'a{n}-intent', {'n': n, 'public_key': wire, 'expiration_usec': expiry, 'posix': posix,
                                          'baseline_sha256': baseline, 'created_at': spec.rfc3339(now)})

            def import_clock():
                window.remaining()   # both original clocks, after the token, immediately before submission
                self.gate()
                return self.deps.now()
            profile, response = login._import_once(wire, expiry, now=import_clock, work_deadline=work_end)
            self._within(window)
            entry = _match(profile, wire)
            require(entry is not None and entry.get('expirationTimeUsec') == expiry, 'import response mismatch')
            entry = login._confirm_import(entry, wire, expiry)
            self._within(window)
            store.create(f'a{n}-import', {'server_name': entry['name'], 'fingerprint': entry['fingerprint'],
                                          'expiration_usec': expiry, 'response_sha256': response})
        finally:
            self.active_window = None
        return posix['username'], window

    def _within(self, window):
        try:
            window.remaining()
            self.gate()
        except Expired:
            raise Refused('access expired during import') from None

    def generate_key(self, directory):
        os.mkdir(directory, 0o700)
        self.deps.runner(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(directory / 'oslogin')], 10)
        text = host.guest.regular(directory / 'oslogin.pub', 4096, os.geteuid()).decode().strip()
        return public_key(text)[0]

    def capture_hostkey(self, window):
        command = ['gcloud', 'compute', 'instances', 'get-guest-attributes', self.m['name'],
                   '--project=' + PROJECT, '--zone=' + ZONE, '--query-path=hostkeys/ssh-ed25519',
                   '--format=json']
        while True:
            window.remaining()
            self.identity()
            try:
                line = extract_ed25519(self.deps.runner(command, min(20, window.remaining()), limit=4096))
            except (ValueError, host.guest.Failure):
                self.deps.sleep(10)
                continue
            self.identity()
            return line

    def start_master(self, n, directory, username, window):
        for k in range(1, MASTER_ATTEMPTS + 1):
            window.remaining()

            def record(pid, k=k):
                seen = proc_start(pid, self.deps.proc_root)
                self.store.create(f'master-{n}-{k}', {'pid': pid, 'start': seen[0] if seen else None,
                                                       'control': str(directory / 'master.sock')})
            factory = self.deps.master_factory or CloneMaster
            master = factory(directory, self.m['name'], self.ids['vm_id'], username, self.deps, record=record)
            try:
                master.start(window)
                self.accept_remote(window)
                return master
            except BaseException as error:
                try:
                    closed = master.close()
                except BaseException:
                    closed = False
                if not closed:
                    self.unclosed.append(master)
                # Cancellation is control flow, including during startup/closure. Preserve it
                # after recording whether the original group was positively closed.
                if not isinstance(error, Exception):
                    raise
                if not closed:
                    raise Uncertain('master process cleanup uncertain') from None
                if k == MASTER_ATTEMPTS:
                    raise
                self.deps.sleep(15)

    def accept_remote(self, window):
        """A remote answer/proof cannot outlive its original access window or work authority."""
        self.late()
        try:
            window.remaining()
        except Expired:
            raise Uncertain('access window passed before remote proof acceptance') from None

    def await_ready(self, master, window, prior):
        while True:
            raw = master.remote('summary', window, 30)
            self.accept_remote(window)
            summary = parse_summary(raw)
            if readiness(summary, prior) == 'ready':
                self.accept_remote(window)
                return summary
            window.remaining()
            self.deps.sleep(10)

    def boot_phase(self, n, prior=None):
        self.phase = f'boot{n}'
        directory = self.dir / f'b{n}'
        wire = self.generate_key(directory)
        username, window = self.import_key(n, wire)
        ready_window = window.sub(READY_SECONDS)
        line = self.capture_hostkey(ready_window)
        known = directory / 'known_hosts'
        host.guest.exclusive(known, ('labapp-trial-' + self.ids['vm_id'] + ' ' + line).encode())
        self.deps.runner(['/usr/bin/ssh-keygen', '-l', '-f', str(known), '-E', 'sha256'], 10)
        master = self.start_master(n, directory, username, ready_window)
        try:
            summary = self.await_ready(master, ready_window, prior)
            record = ready_record(summary)
            self.accept_remote(ready_window)
            self.store.create(f'checkpoint-{n}', {**record, 'hostkey_sha256': hashlib.sha256(line.encode()).hexdigest()})
            self.accept_remote(ready_window)
            if prior is not None:
                compare_boots(prior, record)
            left = window.remaining()
            require(left >= STOP_MIN_SECONDS + TEARDOWN_SECONDS, 'insufficient time to stop the backend')
            out = master.remote('stop-verified', window, min(STOP_SECONDS, left - TEARDOWN_SECONDS))
            self.accept_remote(window)
            require(STOP_MARKER in out, 'stop-verified did not report success')
            raw = master.remote('summary', window, 30)
            self.accept_remote(window)
            check_offline(parse_summary(raw), record)
            self.accept_remote(window)
            self.store.create(f'stopped-{n}', {'boot': record['boot']})
            self.accept_remote(window)
        finally:
            closed = master.close()
            if closed:
                self.cleaner.local()
            else:
                self.unclosed.append(master)
        require(closed, 'master process cleanup uncertain')
        require(self.cleaner.local(), 'local secret files remain')
        state = self.cleaner.remove_key(n)   # closed only by a canonical SELF read proving the exact wire absent
        require(state in ('absent', 'removed'), 'own key removal not proven before continuing')
        return record

    def reset_vm(self):
        self.phase = 'reset'
        m, store = self.m, self.store
        require(self.gate() >= RESET_MIN_SECONDS, 'insufficient time for a second boot')
        self.identity()
        request = str(uuid.uuid4())
        store.create('reset-intent', {'request_id': request, 'vm_id': self.ids['vm_id'],
                                      'boot_id': self.ids['boot_id'], 'at': iso(self.deps.wall())})
        try:
            op = self.cloud.reset(m['name'], request, self.gate)
        except CloneError as error:
            state = 'not-sent' if isinstance(error, NotSent) else 'rejected' if isinstance(error, Rejected) \
                else 'uncertain'
            store.try_create('reset-outcome', {'state': state})
            raise
        store.create('reset-outcome', {'state': 'accepted'})
        identity = dict(kind='reset', collection='instances', name=m['name'], request_id=request,
                        target_id=self.ids['vm_id'], strict=True)
        check_operation(op, done=False, **identity)
        store.create('reset-op', {'name': op['name'], 'id': op['id']})
        wait_operation(self.cloud, self.deps, op, lambda o, d: check_operation(o, done=d, **identity),
                       self.late)
        self.identity()

    def execute(self):
        """-> (exit code, closed JSON-able result). Cleanup always runs; success needs a closed cleanup."""
        passed, code, failure = False, 1, None
        result = {'status': 'failed', 'name': self.m['name']}
        try:
            self.hold_work_lock()
            require(0 <= self.deps.wall() - stamp(self.m['admitted_at']) <= LAUNCH_WINDOW_SECONDS,
                    'arm is stale; launch window over')
            owner = self.verify_watchdog()
            # Evidence only; independent disposal never signals a PID. The owner service cgroup is the bound.
            self.store.create('run', {'pid': os.getpid(), 'start': (proc_start(os.getpid(), self.deps.proc_root)
                                                                   or (None,))[0],
                                      'owner_unit': self.units.owner, 'watch_unit': self.unit,
                                      'control_group': owner['ControlGroup'],
                                      'invocation_id': owner['InvocationID']})
            self.preflight()
            self.create_vm()
            first = self.boot_phase(1)
            self.reset_vm()
            second = self.boot_phase(2, first)
            compare_boots(first, second)
            self.late()
            self.store.create('result', {'first': first, 'second': second})
            result.update(boots=[first, second])
            passed = True
        except host.HostCancelled as error:
            code, failure = error.code, 'cancelled'
        except BaseException as error:
            failure = type(error).__name__
        if failure is not None:
            self.store.try_create('failure', {'phase': self.phase, 'type': failure})
            result.update(phase=self.phase, failure=failure)
        try:
            self.deps.shield()
        except Exception:
            pass
        try:
            cleanup = self.cleaner.run()   # in-process: this caller's OwnedGroups are already closed (or flagged)
        finally:
            self.release_work_lock()
        result['cleanup'] = cleanup
        if passed and cleanup['closed']:
            result['status'] = 'passed'
            return 0, result
        return code, result


def watch(directory, sha, deps, *, passes=6, pause=60):
    """Independent watchdog loop: at the work deadline (wall or monotonic), or once the bound owner service
    is inactive after having recorded a run, stop the bound owner, prove it empty, then dispose."""
    manifest = load_manifest(directory, sha)
    store, end = Store(directory), stamp(manifest['work_deadline'])
    units = Units(directory, sha, manifest, deps)
    w0, m0 = deps.wall(), deps.mono()
    while True:
        if store.has('closed'):
            return 0
        if deps.wall() >= end or deps.mono() - m0 >= end - w0:
            break
        if store.has('run') and units.owner_gone():
            break
        deps.sleep(5)
    cleaner = Cleaner(store, manifest, deps, units=units)
    for attempt in range(passes):
        if cleaner.run()['closed']:
            return 0
        if attempt + 1 < passes:
            deps.sleep(pause)
    return 1


# ------------------------------------------------------------------------------ CLI ----------
def arm(directory, deps):
    path = private_directory(directory, empty=True)
    manifest = new_manifest(deps)
    raw = Store(path).create('manifest', manifest)
    for lock in ('cleanup.lock', 'work.lock'):
        fd = os.open(path / lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
    sha = hashlib.sha256(raw).hexdigest()
    return {'manifest_sha256': sha, 'name': manifest['name'], 'watchdog_unit': watch_unit(manifest),
            'owner_unit': owner_unit(manifest),
            'owner_exec_start': unit_argv(manifest, path, sha, 'run'),
            'watchdog_exec_start': unit_argv(manifest, path, sha, 'watch'),
            'cleanup_exec': unit_argv(manifest, path, sha, 'cleanup'),
            'runtime': {'python': RUNTIME_PYTHON, 'source': PROTECTED_SOURCE, 'user': SERVICE_USER,
                        'owner_kill_mode': 'mixed', 'owner_timeout_stop': OWNER_STOP_TIMEOUT},
            'admitted_at': manifest['admitted_at'], 'work_deadline': manifest['work_deadline'],
            'termination': manifest['termination']}


def _ignore_signals():
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, signal.SIG_IGN)


def main(argv=None, deps=None):
    parser = argparse.ArgumentParser(prog='private_clone', allow_abbrev=False)
    sub = parser.add_subparsers(dest='action', required=True)
    for name in ('arm', 'run', 'cleanup', 'watch'):
        item = sub.add_parser(name, allow_abbrev=False)
        item.add_argument('--workdir', required=True)
        if name != 'arm':
            item.add_argument('--manifest-sha256', required=True)
            item.add_argument('--owner-unit', required=True)
        if name == 'run':
            item.add_argument('--watchdog-unit', required=True)
    args = parser.parse_args(argv)
    deps = deps if deps is not None else Deps.real()
    os.umask(0o077)
    try:
        if args.action == 'arm':
            print(json.dumps(arm(args.workdir, deps), sort_keys=True))
            return 0
        directory = private_directory(args.workdir)
        manifest = load_manifest(directory, args.manifest_sha256)
        require(args.owner_unit == owner_unit(manifest), 'owner unit is not bound to this manifest')
        if args.action == 'watch':
            return watch(directory, args.manifest_sha256, deps)
        if args.action == 'cleanup':
            units = Units(directory, args.manifest_sha256, manifest, deps)
            result = Cleaner(Store(directory), manifest, deps, units=units).run()
            print(json.dumps(result, sort_keys=True))
            return 0 if result['closed'] else 1
        # A fresh attempt only: any earlier record means recovery (cleanup), never a second run.
        require(set(os.listdir(directory)) <= {'manifest.json', 'cleanup.lock', 'work.lock'}, 'workdir is not fresh')
        for number in (signal.SIGTERM, signal.SIGINT):
            signal.signal(number, host.interrupted)
        deps.shield = _ignore_signals
        code, result = Run(directory, manifest, args.manifest_sha256, deps, args.watchdog_unit).execute()
        print(json.dumps(result, sort_keys=True))
        return code
    except host.HostCancelled as error:
        return error.code
    except Exception as error:
        print(json.dumps({'status': 'refused', 'error': type(error).__name__}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
