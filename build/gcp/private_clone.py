"""Narrow owner caller: ONE manual private-image clone VM, two real boots, exact disposal (#546).

Python 3.12 stdlib. Trusted owner/Root host only; no import-time IO. This is NOT the managed
lifecycle: it never touches the canonical ledger, slot, Context, OwnerRegistration, Master or
managed access records, and it never claims a canonical FREE. It reuses only low-level accepted
parts: ``auth_http`` bearer/HTTP, ``oslogin.SelfLogin`` primitives, canonical public-key helpers,
``hostkey.extract_ed25519``, ``vlab_trial.ssh_options``/``command`` and ``owned_process``.

Commands (``python3 -m build.gcp.private_clone``): ``arm`` writes the immutable manifest into a
fresh private workdir; ``run`` performs the one serial attempt; ``cleanup`` and ``watch`` are the
independent disposal interface for the Root-installed systemd watchdog. Code grants no permission:
fresh admission facts, the watchdog and a reviewed Ops wrapper are separate Root obligations.
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
SETTLE_SECONDS = 300            # an uncertain insert with no operation is only settled after this
CLEANUP_POLL_SECONDS = 300
MASTER_ATTEMPTS = 4
LIMIT = 65536

UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')
NAME_RE = re.compile(r'labapp-clone-[0-9a-f]{12}\Z')
OP_RE = re.compile(r'[A-Za-z0-9_-]{1,200}\Z')
DIGITS = re.compile(r'[1-9][0-9]{0,19}\Z')
BOOT_RE = re.compile(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
HEX32, HEX64 = re.compile(r'[0-9a-f]{32}\Z'), re.compile(r'[0-9a-f]{64}\Z')
UNIT_RE = re.compile(r'labapp-clone-watch-[0-9a-f]{12}\.service\Z')
KIND_RE = re.compile(r'[a-z0-9]+(-[a-z0-9]+)*\Z')
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
    killpg: Callable = os.killpg
    getpgid: Callable = os.getpgid
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

    def work(self):
        left = min(self.work_end - self.deps.wall(),
                   self.work_end - self.w0 - (self.deps.mono() - self.m0))
        if left <= 0:
            raise Expired('work deadline reached')
        return left


class Window:
    """One access/readiness window: absolute wall end, monotonic-safe, clipped to the work deadline."""
    def __init__(self, deps, budget, end_wall):
        self.deps, self.budget, self.end = deps, budget, end_wall
        self.w0, self.m0 = deps.wall(), deps.mono()

    def remaining(self):
        left = min(self.end - self.deps.wall(), self.end - self.w0 - (self.deps.mono() - self.m0),
                   self.budget.work())
        if left <= 0:
            raise Expired('access window ended')
        return left

    def sub(self, seconds):
        return Window(self.deps, self.budget, min(self.end, self.deps.wall() + seconds))


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


def cleanup_argv(directory, sha, verb='watch'):
    """Exact argv the Root-installed systemd unit must run (ExecStart)."""
    return ['/usr/bin/python3', '-m', 'build.gcp.private_clone', verb, '--workdir', str(directory),
            '--manifest-sha256', sha]


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


def alive(record, deps):
    seen = proc_start(record.get('pid'), deps.proc_root) if type(record.get('pid')) is int else None
    return seen is not None and seen[0] == record.get('start') and seen[1] != 'Z'


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
        items = self._call('GET', f'{BASE}/projects/{PROJECT}/zones/{ZONE}/operations?{query}').get('items', [])
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


def check_operation(op, *, kind, collection, name, request_id, target_id=None, done):
    """Kind, principal, client request ID, target link and ID, and (when terminal) no error."""
    ok = (isinstance(op, dict) and op.get('operationType') == kind and op.get('clientOperationId') == request_id
          and op.get('user') == OWNER and isinstance(op.get('name'), str) and OP_RE.fullmatch(op['name'])
          and link_ok(f'zones/{ZONE}/{collection}/{name}', op.get('targetLink'))
          and (op.get('zone') is None or link_ok(f'zones/{ZONE}', op.get('zone')))
          and op.get('status') in ('PENDING', 'RUNNING', 'DONE')
          and (target_id is None or op.get('targetId') == target_id))
    if not ok:
        raise Mismatch('operation identity mismatch')
    if done and (op.get('status') != 'DONE' or op.get('error')):
        raise Mismatch('operation not successfully terminal')
    return op


def wait_operation(cloud, deps, first, check, expired):
    op = first
    while True:
        check(op, False)
        if op.get('status') == 'DONE':
            check(op, True)
            return op
        expired()
        deps.sleep(2)
        op = cloud.operation(op['name'])


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


# ------------------------------------------------------------------------------ cleanup -------
class Cleaner:
    """Independent, idempotent disposal of exactly this manifest's resources.

    Used by ``run`` (normal/failure/cancel) AND by the Root watchdog (``cleanup``/``watch``).
    Reads evidence first and binds actual owned IDs/provenance before any delete. Every delete
    is a one-shot durable intent plus one request; nothing is replayed. It never claims a
    canonical FREE.
    """
    def __init__(self, store, manifest, deps):
        self.store, self.m, self.deps = store, manifest, deps
        self.cloud = CloneCompute(deps.http, deps.token_provider)
        self.login = SelfLogin.for_owner(SELF_USER, token_provider=deps.token_provider, transport=deps.http)
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

    # --- local files and recorded processes
    def reap(self, record):
        pid = record['pid']
        if not alive(record, self.deps):
            return True
        try:
            if self.deps.getpgid(pid) != pid:
                return False
            for number, wait in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
                self.deps.killpg(pid, number)
                end = self.deps.mono() + wait
                while self.deps.mono() < end:
                    if not alive(record, self.deps):
                        return True
                    self.deps.sleep(.2)
        except OSError:
            return not alive(record, self.deps)
        return not alive(record, self.deps)

    def local(self):
        clean = True
        for n in (1, 2):
            for k in range(1, MASTER_ATTEMPTS + 1):
                record = self.store.read(f'master-{n}-{k}')
                if record is not None and not self.reap(record):
                    clean = False
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
        """-> 'none' | 'absent' | 'removed' | 'expired' | 'unresolved' for key ``n`` (exact wire only)."""
        with self.lock():
            intent = self.store.read(f'a{n}-intent')
            if intent is None:
                return 'none'
            wire, expiry = intent['public_key'], int(intent['expiration_usec'])
            expired = self.deps.wall() * 1_000_000 >= expiry
            previous = self.store.read(f'a{n}-removed')
            try:
                found = _match(self.login.profile(), wire)
                if found is None:
                    if previous is None:
                        self.store.create(f'a{n}-removed', {'outcome': 'absent'})
                    return 'removed' if previous is None and self.store.has(f'a{n}-delete') else 'absent'
                if self.store.has(f'a{n}-delete'):
                    return 'expired' if expired else 'unresolved'   # one-shot: never a second DELETE
                self.store.create(f'a{n}-delete', {'fingerprint': found['fingerprint'], 'name': found['name']})
                with contextlib.suppress(AccessError):
                    self.login._delete_exact(found)
                if _match(self.login.profile(), wire) is None:
                    self.store.try_create(f'a{n}-removed', {'outcome': 'removed'})
                    return 'removed'
                return 'expired' if expired else 'unresolved'
            except (AccessError, CloneError, OSError):
                return 'unresolved'

    # --- VM and boot disk
    def settled(self):
        intent, outcome = self.store.read('insert-intent'), self.store.read('insert-outcome')
        if outcome is not None and outcome['state'] in ('not-sent', 'rejected'):
            return True
        op = self.store.read('insert-op')
        if op is not None:
            return self.cloud.operation(op['name']).get('status') == 'DONE'
        ops = self.cloud.operations_for(self.m['request_id'])
        if ops:
            return all(o.get('status') == 'DONE' for o in ops)
        return self.deps.wall() >= stamp(intent['at']) + SETTLE_SECONDS

    def _owned_vm(self, vm):
        labels = vm.get('labels') or {}
        ids, deleting = self.store.read('ids'), self.store.read('vm-delete-intent')
        disks = vm.get('disks')
        return (vm.get('name') == self.m['name'] and labels.get(LABEL_UUID) == self.m['uuid']
                and labels.get(LABEL_OWNER) == OWNER_VALUE and isinstance(vm.get('id'), str)
                and DIGITS.fullmatch(vm['id']) and (ids is None or ids['vm_id'] == vm['id'])
                and (deleting is None or deleting['vm_id'] == vm['id'])
                and isinstance(disks, list) and len(disks) == 1
                and link_ok(f'zones/{ZONE}/disks/{self.m["name"]}', disks[0].get('source')))

    def _await(self, first, **identity):
        end = self.deps.mono() + CLEANUP_POLL_SECONDS

        def expired():
            if self.deps.mono() >= end:
                raise Uncertain('operation not terminal in the cleanup budget')
        return wait_operation(self.cloud, self.deps, first,
                              lambda op, done: check_operation(op, done=done, **identity), expired)

    def _delete(self, collection, kind_prefix, resource_id):
        """One-shot delete: durable intent, one request, terminal checked operation. Never replayed."""
        name, intent_kind, op_kind = self.m['name'], f'{kind_prefix}-delete-intent', f'{kind_prefix}-delete-op'
        previous = self.store.read(intent_kind)
        if previous is not None:
            require(previous['resource_id'] == resource_id, 'delete intent binds a different resource')
            recorded = self.store.read(op_kind)
            if recorded is None:
                ops = self.cloud.operations_for(previous['request_id'])
                require(len(ops) == 1, 'earlier delete operation unknown; no replay')
                first = ops[0]
            else:
                first = self.cloud.operation(recorded['name'])
        else:
            request = str(uuid.uuid4())
            self.store.create(intent_kind, {'request_id': request, 'resource_id': resource_id,
                                            'at': iso(self.deps.wall())})
            previous = {'request_id': request}
            first = self.cloud.delete(collection, name, request)
            check_operation(first, kind='delete', collection=collection, name=name, request_id=request,
                            target_id=resource_id, done=False)
            self.store.create(op_kind, {'name': first['name']})
        self._await(first, kind='delete', collection=collection, name=name,
                    request_id=previous['request_id'], target_id=resource_id)

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
                disk_id = verify_disk(disk, self.m, (store.read('ids') or {}).get('boot_id'), ready=False)
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
        else:
            try:
                if not self.settled():
                    return 'unresolved:insert-unsettled', 'unresolved:not-attempted'
            except (CloneError, KeyError, ValueError):
                return 'unresolved:insert-unsettled', 'unresolved:not-attempted'
        try:
            disk = self.cloud.disk(name)
        except NotFound:
            return vm_state, 'absent'
        except CloneError:
            return vm_state, 'unresolved:disk-read'
        try:
            known = store.read('ids') or store.read('bound') or {}
            disk_id = verify_disk(disk, self.m, known.get('boot_id'), ready=False)
            self._delete('disks', 'disk', disk_id)
            if not self._absent(self.cloud.disk):
                return vm_state, 'unresolved:disk-still-present'
        except (CloneError, KeyError, ValueError):
            return vm_state, 'unresolved:disk-delete'
        return vm_state, 'deleted'

    def run(self):
        result = {'local': False, 'keys': {}, 'vm': 'unresolved:not-run', 'disk': 'unresolved:not-run',
                  'closed': False}
        try:
            with self.lock():
                result['local'] = self.local()
                result['keys'] = {str(n): self.remove_key(n) for n in (1, 2)}
                result['vm'], result['disk'] = self.dispose()
                result['local'] = self.local() and result['local']
                good = ('none', 'absent', 'removed', 'expired')
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
        self.cleaner = Cleaner(self.store, manifest, deps)
        self.phase = 'start'
        self.ids = None
        self.boots = {}

        def gated_token():
            token = deps.token_provider()
            self.budget.work()  # after token acquisition, before any SELF request
            return token
        self.login = SelfLogin.for_owner(SELF_USER, token_provider=gated_token, transport=deps.http)

    # --- guards
    def verify_watchdog(self):
        require(self.unit == watch_unit(self.m), 'watchdog unit is not bound to this manifest')
        raw = self.deps.runner(['/usr/bin/systemctl', 'show', self.unit, '-p', 'LoadState', '-p', 'ActiveState',
                                '-p', 'ExecStart'], 10, limit=4096).decode('utf-8', 'replace')
        fields = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
        exec_start = fields.get('ExecStart', '')
        need = [' watch ', '--workdir ' + str(self.dir), '--manifest-sha256 ' + self.sha,
                'build.gcp.private_clone']
        require(fields.get('LoadState') == 'loaded' and fields.get('ActiveState') == 'active'
                and all(token in exec_start for token in need), 'independent cleanup watchdog is not armed')

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
        self.budget.work()
        store.create('insert-intent', {'request_id': m['request_id'], 'body': body, 'body_sha256': digest(body),
                                       'at': iso(self.deps.wall())})
        try:
            op = self.cloud.insert(m, body, m['request_id'], self.budget.work)
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
        identity = dict(kind='insert', collection='instances', name=m['name'], request_id=m['request_id'])
        check_operation(op, done=False, **identity)
        store.create('insert-op', {'name': op['name']})
        done = wait_operation(self.cloud, self.deps, op, lambda o, d: check_operation(o, done=d, **identity),
                              self.budget.work)
        target = done.get('targetId')
        require(isinstance(target, str) and DIGITS.fullmatch(target), 'insert target ID missing')
        verify_vm(self.cloud.instance(m['name']), m, target)
        boot_id = verify_disk(self.cloud.disk(m['name']), m)
        self.ids = {'vm_id': target, 'boot_id': boot_id}
        store.create('ids', self.ids)

    # --- access
    def import_key(self, n, wire):
        m, store, login = self.m, self.store, self.login
        profile = login.profile()
        require(_match(profile, wire) is None, 'intended key preexists; cannot import or adopt')
        posix = _identity(profile)
        now = self.deps.now().replace(microsecond=0)
        work_end = datetime.fromtimestamp(self.budget.work_end, timezone.utc)
        end = min(datetime.fromtimestamp(now.timestamp() + KEY_SECONDS, timezone.utc), work_end)
        if (end - now).total_seconds() < MIN_ACCESS_SECONDS:
            raise Expired('insufficient time for an access window')
        expiry = str(int(end.timestamp() * 1_000_000))
        baseline = digest(sorted(_wire(k['key']) for k in profile.get('sshPublicKeys', {}).values()))
        store.create(f'a{n}-intent', {'n': n, 'public_key': wire, 'expiration_usec': expiry, 'posix': posix,
                                      'baseline_sha256': baseline, 'created_at': spec.rfc3339(now)})
        profile, response = login._import_once(wire, expiry, now=self.deps.now, work_deadline=work_end)
        entry = _match(profile, wire)
        require(entry is not None and entry.get('expirationTimeUsec') == expiry, 'import response mismatch')
        entry = login._confirm_import(entry, wire, expiry)
        after = self.deps.now()
        self.budget.work()
        require(after < end, 'access expired during import')
        store.create(f'a{n}-import', {'server_name': entry['name'], 'fingerprint': entry['fingerprint'],
                                      'expiration_usec': expiry, 'response_sha256': response})
        return posix['username'], Window(self.deps, self.budget, end.timestamp())

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
                return master
            except Exception:
                if not master.close():
                    raise Uncertain('master process cleanup uncertain') from None
                if k == MASTER_ATTEMPTS:
                    raise
                self.deps.sleep(15)

    def await_ready(self, master, window, prior):
        while True:
            summary = parse_summary(master.remote('summary', window, 30))
            if readiness(summary, prior) == 'ready':
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
            self.store.create(f'checkpoint-{n}', {**record, 'hostkey_sha256': hashlib.sha256(line.encode()).hexdigest()})
            if prior is not None:
                compare_boots(prior, record)
            left = window.remaining()
            require(left >= STOP_MIN_SECONDS + TEARDOWN_SECONDS, 'insufficient time to stop the backend')
            out = master.remote('stop-verified', window, min(STOP_SECONDS, left - TEARDOWN_SECONDS))
            require(STOP_MARKER in out, 'stop-verified did not report success')
            check_offline(parse_summary(master.remote('summary', window, 30)), record)
            self.store.create(f'stopped-{n}', {'boot': record['boot']})
        finally:
            closed = master.close()
            if closed:
                self.cleaner.local()
        require(closed, 'master process cleanup uncertain')
        require(self.cleaner.local(), 'local secret files remain')
        state = self.cleaner.remove_key(n)
        require(state in ('absent', 'removed'), 'own key removal not proven before continuing')
        return record

    def reset_vm(self):
        self.phase = 'reset'
        m, store = self.m, self.store
        require(self.budget.work() >= RESET_MIN_SECONDS, 'insufficient time for a second boot')
        self.identity()
        request = str(uuid.uuid4())
        store.create('reset-intent', {'request_id': request, 'vm_id': self.ids['vm_id'],
                                      'boot_id': self.ids['boot_id'], 'at': iso(self.deps.wall())})
        try:
            op = self.cloud.reset(m['name'], request, self.budget.work)
        except CloneError as error:
            store.try_create('reset-outcome', {'state': 'not-sent' if isinstance(error, NotSent) else 'uncertain'})
            raise
        store.create('reset-outcome', {'state': 'accepted'})
        identity = dict(kind='reset', collection='instances', name=m['name'], request_id=request,
                        target_id=self.ids['vm_id'])
        wait_operation(self.cloud, self.deps, op, lambda o, d: check_operation(o, done=d, **identity),
                       self.budget.work)
        self.identity()

    def execute(self):
        """-> (exit code, closed JSON-able result). Cleanup always runs; success needs a closed cleanup."""
        passed, code, failure = False, 1, None
        result = {'status': 'failed', 'name': self.m['name']}
        try:
            self.store.create('run', {'pid': os.getpid(), 'start': (proc_start(os.getpid(), self.deps.proc_root)
                                                                   or (None,))[0], 'unit': self.unit})
            require(0 <= self.deps.wall() - stamp(self.m['admitted_at']) <= LAUNCH_WINDOW_SECONDS,
                    'arm is stale; launch window over')
            self.verify_watchdog()
            self.preflight()
            self.create_vm()
            first = self.boot_phase(1)
            self.reset_vm()
            second = self.boot_phase(2, first)
            compare_boots(first, second)
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
        cleanup = self.cleaner.run()
        result['cleanup'] = cleanup
        if passed and cleanup['closed']:
            result['status'] = 'passed'
            return 0, result
        return code, result


def watch(directory, sha, deps, *, passes=6, pause=60):
    """Independent watchdog loop: cleanup at the work deadline or as soon as the run process is gone."""
    manifest = load_manifest(directory, sha)
    store, end = Store(directory), stamp(manifest['work_deadline'])
    while True:
        if store.has('closed'):
            return 0
        record = store.read('run')
        if deps.wall() >= end or (record is not None and not alive(record, deps)):
            break
        deps.sleep(5)
    cleaner = Cleaner(store, manifest, deps)
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
    fd = os.open(path / 'cleanup.lock', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    sha = hashlib.sha256(raw).hexdigest()
    return {'manifest_sha256': sha, 'name': manifest['name'], 'watchdog_unit': watch_unit(manifest),
            'watchdog_exec_start': cleanup_argv(path, sha), 'cleanup_exec': cleanup_argv(path, sha, 'cleanup'),
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
        if args.action == 'watch':
            return watch(directory, args.manifest_sha256, deps)
        manifest = load_manifest(directory, args.manifest_sha256)
        if args.action == 'cleanup':
            result = Cleaner(Store(directory), manifest, deps).run()
            print(json.dumps(result, sort_keys=True))
            return 0 if result['closed'] else 1
        # A fresh attempt only: any earlier record means recovery (cleanup), never a second run.
        require(set(os.listdir(directory)) <= {'manifest.json', 'cleanup.lock'}, 'workdir is not fresh')
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
