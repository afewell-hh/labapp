"""Trusted owner-local entrypoint for ONE closed disposable GCP trial.

Python 3.12 stdlib, invoked from accepted trusted main as
``python3 -m build.gcp.vlab_trial --snapshot PRIVATE --payloads PRIVATE --output PRIVATE``.
No cloud authority is supplied to workers. Input snapshot is a private captured
creator correlation, checked against GitHub/main, occupied ledger and immutable
cloud identity. It cannot select a command/profile/path/ref for remote work.
Only owner registration CAS/own-key evidence are mutations here; independent
fixed trusted workflows own creation/deletion. No credential files leave host.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import threading
import time

from build.provision import vlab_trial as guest
from .inspection.hostkey import extract_ed25519
from .lifecycle import spec
from .lifecycle.access_records import GcsAccessRecords, canonical
from .lifecycle.auth_http import gcloud_token
from .lifecycle.cli import BUCKET, CREATOR_PATH, REPOSITORY, verify_disk_provenance
from .lifecycle.cloud import PolicyCloud, ForbiddenOperation
from .lifecycle.compute import ComputeRestTransport
from .lifecycle.controller import Config, Controller, Refused
from .lifecycle.gcs import GcsSlotStore
from .lifecycle.oslogin import OwnKeyImport, SelfLogin, cleanup_own_key

OWNER = 'art@githedgehog.com'
SNAPSHOT_FIELDS = ('profile', 'request_id', 'epoch', 'run_id', 'attempt', 'body_hash',
                   'ids', 'boot_image', 'boot_image_id', 'reserved_at', 'deadline', 'operation')
MAX_JSON = 256 * 1024
SAFE_ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}


class ReadCloud:
    """Owner operation cannot reach creator/delete/capture verbs."""
    def __init__(self, cloud):
        self.__cloud = cloud

    def call(self, resource, verb, **kwargs):
        if (resource, verb) not in {('instances', 'get'), ('disks', 'get'), ('zoneOperations', 'get')}:
            raise ForbiddenOperation('owner trial allows fixed identity reads only')
        return self.__cloud.call(resource, verb, **kwargs)


def expected_snapshot(value):
    guest.require(type(value) is dict and set(value) == {*SNAPSHOT_FIELDS, 'source_sha', 'self_user', 'preflight'})
    guest.require(value['profile'] == spec.UBUNTU_VLAB_CORE and set(value['ids']) == {'instance', 'boot'}
                  and all(re.fullmatch('[1-9][0-9]{0,19}', i) for i in value['ids'].values())
                  and re.fullmatch('[a-f0-9]{40}', value['source_sha']))
    guest.require(value['attempt'] == 1, 'canonical run retries are unsupported')
    guest.require(all(type(value[k]) is int and value[k] > 0 for k in ('epoch', 'run_id', 'attempt')))
    # Explicit bounded lead evidence IDs, not booleans which pretend to prove
    # actual effective ingress/NAT/IAM. The lead separately assesses these
    # fresh reads; the coordinator neither creates networks nor fixes denial.
    preflight = value['preflight']
    guest.require(type(preflight) is dict and set(preflight) == {'lease', 'vm_id', 'source_sha', 'checked_at',
                   'quota_sha256', 'network_sha256', 'images_sha256', 'access_sha256', 'egress_sha256'})
    guest.require(preflight['lease'] == value['request_id'] and preflight['vm_id'] == value['ids']['instance']
                  and preflight['source_sha'] == value['source_sha'])
    for field in ('quota_sha256', 'network_sha256', 'images_sha256', 'access_sha256', 'egress_sha256'):
        guest.require(re.fullmatch('[a-f0-9]{64}', preflight[field]))
    guest.require(0 <= time.time() - guest.stamp(preflight['checked_at']) <= 900, 'preflight evidence stale')
    return {k: value[k] for k in SNAPSHOT_FIELDS}


def private_directory(path):
    path = guest.no_links(path)
    info = path.lstat()
    guest.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                  and stat.S_IMODE(info.st_mode) == 0o700, 'owner private directory required')
    guest.require(not any(path.iterdir()), 'output directory must be fresh and empty')
    guest.require(re.fullmatch('/[A-Za-z0-9_./-]+', str(path)), 'private staging path characters refused')
    return path


def command(argv, seconds, *, input_bytes=None, limit=65536, failed=None, env=None):
    """Bounded combined output; every exit kills/reaps owned process group."""
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            start_new_session=True, env=env)
    deadline = time.monotonic() + seconds
    output = bytearray()
    try:
        if input_bytes is not None:
            guest.require(len(input_bytes) <= 4096)
            proc.stdin.write(input_bytes)
            proc.stdin.close()
        with selectors.DefaultSelector() as select:
            select.register(proc.stdout, selectors.EVENT_READ)
            while select.get_map():
                guest.require(not (failed and failed.is_set()), 'heartbeat/master failed')
                if time.monotonic() >= deadline:
                    raise guest.Failure('bounded host child timeout', 124)
                for key, _ in select.select(min(.2, deadline - time.monotonic())):
                    raw = os.read(key.fileobj.fileno(), 65536)
                    if not raw:
                        select.unregister(key.fileobj)
                    else:
                        guest.require(len(output) + len(raw) <= limit, 'host output bound')
                        output.extend(raw)
        code = proc.wait(timeout=max(.01, deadline - time.monotonic()))
        if code:
            raise guest.Failure('host child failed', code if code > 0 else 128 - code)
        return bytes(output)
    finally:
        primary = sys.exc_info()[1]
        clean = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException:
            clean = False
        try:
            proc.wait(timeout=3)
        except BaseException:
            clean = False
        try:
            proc.stdout.close()
        except BaseException:
            clean = False
        if not clean:
            if primary is not None:
                primary.cleanup_uncertain = True
            else:
                failure = guest.Failure('host child cleanup uncertain')
                failure.cleanup_uncertain = True
                raise failure from None


def github(path, limit=MAX_JSON):
    # Owner's existing authenticated gh context stays host-only. Unauthenticated
    # polling would exceed GitHub's documented sixty-requests/hour allowance.
    guest.require(path.startswith(('actions/runs/', 'git/ref/heads/main', 'contents/'))
                  and '..' not in path and limit <= 512 * 1024)
    raw = command(['gh', 'api', '--method', 'GET', '-H', 'X-GitHub-Api-Version: 2022-11-28',
                   'repos/' + REPOSITORY + '/' + path], 20, limit=limit)
    return guest.data(raw)


def trusted_source(snapshot, *, initial=False):
    run = github('actions/runs/' + str(snapshot['run_id']) + '/attempts/' + str(snapshot['attempt']))
    guest.require(run.get('id') == snapshot['run_id'] and run.get('run_attempt') == snapshot['attempt']
                  and run.get('path') == CREATOR_PATH and run.get('event') == 'workflow_dispatch'
                  and run.get('head_branch') == 'main' and run.get('head_sha') == snapshot['source_sha']
                  and run.get('repository', {}).get('full_name') == REPOSITORY
                  and run.get('status') == 'in_progress', 'creator cancelled/completed/untrusted')
    if initial:
        main = github('git/ref/heads/main')
        guest.require(main.get('object', {}).get('sha') == snapshot['source_sha'], 'source must be accepted current trusted main')


class OwnerRegistration:
    """One explicit registration operation; no controller method selector."""
    def __init__(self, store, cloud, records, snapshot):
        self.expected = expected_snapshot(snapshot)
        self.snapshot, self.store, self.cloud, self.records = snapshot, store, ReadCloud(cloud), records
        self.__controller = Controller(store, self.cloud,
                                       Config(boot_image=spec.COMPONENT_IMAGE, profile=spec.UBUNTU_VLAB_CORE),
                                       access_records=records)

    def current(self):
        rec, _ = self.store.read('slots/slot-1.json')
        guest.require(rec is not None and rec.get('state') == 'ACTIVE'
                      and {k: rec.get(k) for k in SNAPSHOT_FIELDS} == self.expected,
                      'owner lease changed')
        self.__controller._lease_kinds(rec)
        guest.require(all(rec['ids'].values()))
        op = self.cloud.call('zoneOperations', 'get', name=rec['operation'])
        proof, error = self.__controller._insert_target_id(rec, [op])
        guest.require(not error and not op.get('error') and proof == rec['ids']['instance'], 'insert not terminal')
        reason, found = self.__controller._inspect(rec, proof)
        guest.require(not reason and set(found) == {'instance', 'boot'})
        inst, boot = found['instance'], found['boot']
        expected = spec.build_body(boot_image=spec.COMPONENT_IMAGE, request_id=rec['request_id'],
                                  run_id=rec['run_id'], attempt=rec['attempt'],
                                  deadline=datetime.fromisoformat(rec['deadline'].replace('Z', '+00:00')),
                                  profile=spec.UBUNTU_VLAB_CORE)
        guest.require(inst.get('status') == 'RUNNING' and inst.get('id') == rec['ids']['instance']
                      and spec.resource_link('projects/' + spec.PROJECT + '/' + expected['machineType'], inst.get('machineType'))
                      and inst.get('minCpuPlatform') == expected['minCpuPlatform']
                      and inst.get('advancedMachineFeatures', {}).get('enableNestedVirtualization') is True
                      and inst.get('serviceAccounts', []) == []
                      and not inst.get('guestAccelerators') and inst.get('canIpForward') is False
                      and inst.get('deletionProtection') is False
                      and datetime.fromisoformat(inst.get('scheduling', {})['terminationTime'].replace('Z', '+00:00')).timestamp() == guest.stamp(rec['deadline'])
                      and inst.get('scheduling', {}).get('onHostMaintenance') == 'TERMINATE'
                      and inst.get('scheduling', {}).get('automaticRestart') is False
                      and inst.get('scheduling', {}).get('instanceTerminationAction') == 'DELETE')
        nics = inst.get('networkInterfaces', [])
        guest.require(len(nics) == 1 and not nics[0].get('accessConfigs') and not nics[0].get('ipv6AccessConfigs')
                      and spec.resource_link('projects/' + spec.PROJECT + '/' + expected['networkInterfaces'][0]['subnetwork'],
                                             nics[0].get('subnetwork')))
        wanted_metadata = {i['key']: i['value'] for i in expected['metadata']['items']}
        metadata = inst.get('metadata', {}).get('items', [])
        guest.require(len(metadata) == len(wanted_metadata)
                      and all(set(i) == {'key', 'value'} for i in metadata)
                      and {i['key']: i['value'] for i in metadata} == wanted_metadata)
        guest.require(str(boot.get('sizeGb')) == '500' and
                      spec.resource_link('projects/' + spec.PROJECT + '/zones/' + spec.ZONE + '/diskTypes/pd-balanced', boot.get('type')))
        verify_disk_provenance(self.__controller, rec)
        # Reads and owner tokens can consume time; original allowance remains.
        guest.require(time.time() < guest.stamp(rec['deadline']) - 900)
        return rec

    def register(self, public_key):
        self.current()
        return self.__controller.register_access(self.expected['request_id'],
                 producer_run_id=self.expected['run_id'], producer_attempt=self.expected['attempt'],
                 self_user=self.snapshot['self_user'], public_key_text=public_key, expected_trial=self.expected)


def source_files(snapshot, output):
    result = {}
    for name, path in guest.SOURCES.items():
        value = github('contents/' + path + '?ref=' + snapshot['source_sha'], 512 * 1024)
        guest.require(value.get('type') == 'file' and value.get('path') == path and value.get('encoding') == 'base64'
                      and type(value.get('size')) is int and 0 < value['size'] <= guest.MAX_SOURCE)
        raw = base64.b64decode(value['content'].replace('\n', ''), validate=True)
        guest.require(len(raw) == value['size'])
        guest.exclusive(output / name, raw)
        result[name] = {'bytes': len(raw), 'sha256': guest.sha(raw)}
    return result


def candidate_fab(public_key, password_hash, token):
    return guest.candidate_fab(public_key, password_hash, token)


def ssh_options(directory, vm_id, username):
    guest.require(re.fullmatch('[a-z_][a-z0-9_-]{0,63}', username))
    return ['-F', '/dev/null', '-o', 'ControlPath=' + str(directory / 'master.sock'), '-i', str(directory / 'oslogin'),
            '-o', 'User=' + username, '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'IdentityAgent=none', '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(directory / 'known_hosts'),
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'HostKeyAlias=labapp-trial-' + vm_id,
            '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'UpdateHostKeys=no',
            '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
            '-o', 'KbdInteractiveAuthentication=no', '-o', 'ConnectTimeout=15',
            '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=3',
            '-o', 'ControlPersist=no', '-o', 'LogLevel=ERROR']


class Master:
    def __init__(self, directory, snapshot, username, clock, failed):
        self.directory, self.clock, self.failed = directory, clock, failed
        self.options = ssh_options(directory, snapshot['ids']['instance'], username)
        self.target = 'labapp-trial-' + snapshot['ids']['instance']
        self.proc = None
        self.socket_identity = None
        self.started = False
        self.instance = spec.names(snapshot['run_id'], snapshot['attempt'], spec.UBUNTU_VLAB_CORE)['instance']

    def start(self):
        guest.require(not self.started, 'master replacement refused')
        self.started = True
        proxy = shlex.join(['gcloud', 'compute', 'start-iap-tunnel', self.instance, '22',
                            '--project=' + spec.PROJECT, '--zone=' + spec.ZONE,
                            '--listen-on-stdin', '--quiet', '--verbosity=error'])
        self.proc = subprocess.Popen(['/usr/bin/ssh', *self.options, '-M', '-N',
                         '-o', 'ControlMaster=yes', '-o', 'ProxyCommand=' + proxy, self.target],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
        until = time.monotonic() + min(30, self.clock.remaining('access'))
        while time.monotonic() < until:
            guest.require(self.proc.poll() is None, 'original master exited')
            path = self.directory / 'master.sock'
            if path.exists():
                info = path.lstat()
                guest.require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid())
                self.socket_identity = (info.st_dev, info.st_ino)
                self.check()
                return
            time.sleep(.1)
        raise guest.Failure('master startup timed out', 124)

    def check(self):
        guest.require(self.proc is not None and self.proc.poll() is None and self.socket_identity is not None,
                      'original master lost')
        info = (self.directory / 'master.sock').lstat()
        guest.require((info.st_dev, info.st_ino) == self.socket_identity, 'original master socket replaced')
        command(['/usr/bin/ssh', *self.options, '-o', 'ProxyCommand=/usr/bin/false', '-O', 'check', self.target], 5)

    def remote(self, args, phase, cap=30, cleanup=False):
        self.check()
        # ControlMaster=no alone reconnects. This deliberately failing transport
        # is mandatory on EVERY subordinate invocation, including cleanup/SFTP.
        seconds = min(cap, self.clock.cleanup_remaining() if cleanup else self.clock.remaining(phase))
        raw = command(['/usr/bin/ssh', *self.options, '-o', 'ControlMaster=no', '-o', 'ProxyCommand=/usr/bin/false',
                       self.target, shlex.join(args)], seconds, failed=None if cleanup else self.failed)
        self.check()
        return raw

    def transfer(self, incoming, names, phase='stage'):
        self.check()
        batch = self.directory / 'sftp.batch'
        lines = [f'put {shlex.quote(str(self.directory / name))} {incoming}/{name}' for name in names]
        guest.exclusive(batch, ('\n'.join(lines) + '\n').encode())
        try:
            command(['/usr/bin/sftp', '-b', str(batch), *self.options,
                     '-o', 'ControlMaster=no', '-o', 'ProxyCommand=/usr/bin/false', self.target],
                     min(600, self.clock.remaining(phase)), failed=self.failed)
            self.check()
        finally:
            primary = sys.exc_info()[1]
            try:
                batch.unlink()
            except BaseException:
                if primary is not None:
                    primary.cleanup_uncertain = True
                else:
                    error = guest.Failure('transfer input cleanup uncertain')
                    error.cleanup_uncertain = True
                    raise error

    def close(self):
        if self.proc is None:
            return True
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait(timeout=3)
        # Process group absence is separate from remote service containment.
        try:
            os.killpg(self.proc.pid, 0)
        except ProcessLookupError:
            return True
        return False


# Minimal root bootstrap authenticates the source bytes BEFORE executing them.
# The complete incoming table is subsequently checked/copied by that exact
# verified coordinator. Isolated stdlib lookup avoids owner-directory imports.
BOOTSTRAP = """import hashlib,os,stat,sys
from pathlib import Path
p=Path(sys.argv[1]); expected=sys.argv[2]
f=os.open(p/'vlab_trial.py',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
s=os.fstat(f)
assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=262144
b=os.read(f,262145); os.close(f)
assert len(b)==s.st_size and hashlib.sha256(b).hexdigest()==expected
n={'__name__':'labapp_root_bootstrap','__file__':str(p/'vlab_trial.py')}
exec(compile(b,str(p/'vlab_trial.py'),'exec'),n)
n['bootstrap'](p,sys.argv[3])
"""


def cleanup_dispatch(snapshot):
    # Cancel ONLY this captured trusted creator. Its completed workflow_run is
    # checked against the lease by the independent cleanup workflow. The API
    # cancels by run ID, not attempt: new canonical admission is first-attempt
    # only, and a different current attempt must refuse. Never force-clean the
    # current slot with a manual dispatch after a read-then-dispatch race.
    current = github('actions/runs/' + str(snapshot['run_id']))
    guest.require(current.get('id') == snapshot['run_id'] and current.get('run_attempt') == 1
                  and current.get('path') == CREATOR_PATH and current.get('event') == 'workflow_dispatch'
                  and current.get('head_branch') == 'main' and current.get('head_sha') == snapshot['source_sha']
                  and current.get('repository', {}).get('full_name') == REPOSITORY)
    if current.get('status') != 'completed':
        command(['gh', 'api', '--method', 'POST', '-H', 'X-GitHub-Api-Version: 2022-11-28',
                 'repos/' + REPOSITORY + '/actions/runs/' + str(snapshot['run_id']) + '/cancel'], 20)
    # 202 means accepted cancellation, never observed resource cleanup/FREE.


def trial(snapshot, payloads, output, *, registration, records, login):
    expected_snapshot(snapshot)
    rec = dict(snapshot, names=spec.names(snapshot['run_id'], snapshot['attempt'], spec.UBUNTU_VLAB_CORE))
    nonce = secrets.token_hex(16)
    initial = {'schema': 1, 'nonce': nonce, 'lease': rec['request_id'], 'epoch': rec['epoch'],
               'run_id': rec['run_id'], 'attempt': rec['attempt'], 'body_sha256': rec['body_hash'],
               'vm_id': rec['ids']['instance'], 'boot_id': rec['ids']['boot'], 'image_id': rec['boot_image_id'],
               'admitted_at': rec['reserved_at'], 'deadline': rec['deadline'], 'boot_uuid': '00000000-0000-0000-0000-000000000000',
               'source_sha': snapshot['source_sha']}
    failed, stop = threading.Event(), threading.Event()
    process_uncertain = threading.Event()
    master = context = heartbeat_thread = None
    result, contained, process_absent, key_absent, dispatched = 1, False, False, False, False
    try:
        clock = guest.Clock(initial)
        clock.remaining('access')
        trusted_source(snapshot, initial=True)
        rec = registration.current()
        # Confirm exact active owner, no account switch/impersonation/key agent.
        account = command(['gcloud', 'auth', 'list', '--filter=status:ACTIVE', '--format=value(account)'], 15).decode().strip()
        guest.require(account == OWNER)
        impersonation = command(['gcloud', 'config', 'get-value', 'auth/impersonate_service_account', '--quiet'], 15).decode().strip()
        guest.require(impersonation in ('', '(unset)') and not os.environ.get('CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT'),
                      'owner impersonation unsupported')
        owner_profile = guest.data(command(['gcloud', 'compute', 'os-login', 'describe-profile', '--format=json'], 20))
        guest.require(owner_profile.get('name') == snapshot['self_user'] == login.user, 'canonical SELF identity differs')
        version = guest.data(command(['gcloud', 'version', '--format=json'], 15))
        guest.require(version.get('Google Cloud SDK') == '575.0.0')
        command(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(output / 'oslogin')], 10)
        public_key = guest.regular(output / 'oslogin.pub', 4096, os.geteuid()).decode().strip()
        context = registration.register(public_key)
        importer = OwnKeyImport(records, context, login, producer_run_id=rec['run_id'], producer_attempt=rec['attempt'],
                                now=lambda: datetime.now(timezone.utc))
        intent, _ = importer.prepare(public_key)
        importer.import_once()
        registration.current()
        hostkey = command(['gcloud', 'compute', 'instances', 'get-guest-attributes', rec['names']['instance'],
                           '--project=' + spec.PROJECT, '--zone=' + spec.ZONE,
                           '--query-path=hostkeys/ssh-ed25519', '--format=json'], min(20, clock.remaining('access')), limit=4096)
        key_line = extract_ed25519(hostkey)
        registration.current()
        guest.exclusive(output / 'known_hosts', ('labapp-trial-' + rec['ids']['instance'] + ' ' + key_line).encode())
        command(['/usr/bin/ssh-keygen', '-l', '-f', str(output / 'known_hosts'), '-E', 'sha256'], 10)
        master = Master(output, snapshot, intent['posix']['username'], clock, failed)
        master.start()
        # Harmless marker transfer and sudo/boot proof before appliance bytes.
        boot = master.remote(['/usr/bin/cat', '/proc/sys/kernel/random/boot_id'], 'access').decode().strip()
        guest.require(re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', boot))
        initial['boot_uuid'] = boot
        guest.contract(initial)
        registration.current()
        master.remote(['/usr/bin/sudo', '-n', '/usr/bin/true'], 'access')
        incoming = '/tmp/labapp-vlab-' + nonce
        master.remote(['/usr/bin/mkdir', '-m', '0700', incoming], 'access')
        guest.exclusive(output / 'marker', nonce.encode())
        master.transfer(incoming, ['marker'], 'access')
        guest.require(master.remote(['/usr/bin/cat', incoming + '/marker'], 'access') == nonce.encode())
        master.remote(['/usr/bin/rm', '--', incoming + '/marker'], 'access')
        source = source_files(snapshot, output)
        for name, pin in guest.PAYLOADS.items():
            raw = guest.regular(guest.no_links(payloads / name), pin[0], os.geteuid())
            guest.require((len(raw), guest.sha(raw)) == pin)
            guest.exclusive(output / name, raw)
        command(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(output / 'candidate')], 10)
        candidate_key = guest.regular(output / 'candidate.pub', 4096, os.geteuid()).decode().split()
        password = secrets.token_urlsafe(36)
        guest.exclusive(output / 'candidate.password', password.encode())
        password_hash = command(['/usr/bin/openssl', 'passwd', '-5', '-stdin'], 10, input_bytes=(password + '\n').encode(),
                                limit=4096, env=SAFE_ENV).decode().strip()
        guest.exclusive(output / 'fab.yaml', candidate_fab(' '.join(candidate_key[:2]), password_hash, secrets.token_hex(32)))
        guest.exclusive(output / 'contract.json', canonical(initial))
        for name in guest.FILES - set(source):
            raw = guest.regular(output / name, guest.PAYLOADS[name][0] if name in guest.PAYLOADS else guest.MAX_SOURCE, os.geteuid())
            source[name] = {'bytes': len(raw), 'sha256': guest.sha(raw)}
        table = guest.manifest({'schema': 1, 'source_sha': snapshot['source_sha'], 'files': source})
        guest.exclusive(output / 'manifest.json', canonical(table))
        registration.current()
        trusted_source(snapshot)
        master.transfer(incoming, [*sorted(guest.FILES), 'manifest.json'])
        registration.current()
        master.remote(['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-c', BOOTSTRAP, incoming,
                       source['vlab_trial.py']['sha256'], guest.sha(canonical(table))], 'stage', cap=60)
        # Heartbeat starts immediately after bounded root bootstrap. Startup
        # grace is thirty seconds; worker cannot extend it or update itself.
        def heartbeat():
            sequence = 0
            try:
                while not stop.is_set():
                    sequence += 1
                    master.remote(['/usr/bin/sudo', '-n', '/usr/bin/python3', str(guest.ROOT / 'vlab_trial.py'), 'heartbeat',
                                   '--nonce', nonce, '--sequence', str(sequence)], 'persistence', cap=8)
                    stop.wait(10)
            except BaseException as error:
                if getattr(error, 'cleanup_uncertain', False):
                    process_uncertain.set()
                failed.set()
        heartbeat_thread = threading.Thread(target=heartbeat, daemon=True)
        heartbeat_thread.start()
        while True:
            guest.require(not failed.is_set(), 'heartbeat failed')
            registration.current()
            trusted_source(snapshot)
            clock.remaining('persistence')
            # No private guest diagnostics/FAB/kubeconfigs are pulled. One fixed
            # sanitized result is read after the guardian has contained services.
            raw = master.remote(['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-c',
                       "from pathlib import Path; p=Path('/var/lib/labapp-vlab-trial/result.json'); print(p.read_text() if p.exists() else '{}')"],
                       'persistence', cap=8)
            observed = guest.data(raw)
            if observed:
                guest.require(set(observed) == {'schema', 'code', 'contained', 'nonce'} and observed['schema'] == 1
                              and observed['nonce'] == nonce and type(observed['code']) is int
                              and type(observed['contained']) is bool)
                result, contained = observed['code'], observed['contained']
                break
            stop.wait(5)
    except guest.Failure as error:
        result = error.code
        if getattr(error, 'cleanup_uncertain', False):
            process_uncertain.set()
    except KeyboardInterrupt:
        result = 130
    except Exception as error:
        result = 1
        if getattr(error, 'cleanup_uncertain', False):
            process_uncertain.set()
    finally:
        stop.set()
        heartbeat_absent = True
        if heartbeat_thread:
            heartbeat_thread.join(timeout=25)
            heartbeat_absent = not heartbeat_thread.is_alive()
        process_absent = master is None and heartbeat_absent and not process_uncertain.is_set()
        if master is not None:
            if not contained:
                try:
                    master.remote(['/usr/bin/sudo', '-n', '/usr/bin/systemctl', 'stop', guest.UNIT],
                                  'persistence', cap=120, cleanup=True)
                    # Stop success alone cannot attest ExecStopPost result;
                    # preserve uncertainty unless guardian already reported it.
                except BaseException:
                    pass
            try:
                process_absent = master.close() and heartbeat_absent and not process_uncertain.is_set()
            except BaseException:
                process_absent = False
        # Fixed owned table only. Verify no unexpected local file before delete;
        # socket may survive master exit but its original inode is bound above.
        owned = {*guest.FILES, 'manifest.json', 'oslogin', 'oslogin.pub', 'candidate', 'candidate.pub',
                 'candidate.password', 'known_hosts', 'marker', 'sftp.batch', 'master.sock'}
        local_absent = process_absent
        for name in (owned if process_absent else ()):
            path = output / name
            try:
                info = path.lstat()
                guest.require(info.st_uid == os.geteuid() and not stat.S_ISLNK(info.st_mode)
                              and info.st_nlink == 1
                              and (stat.S_ISREG(info.st_mode) or name == 'master.sock' and stat.S_ISSOCK(info.st_mode)))
                path.unlink()
                guest.require(not path.exists())
            except FileNotFoundError:
                pass
            except BaseException:
                local_absent = False
        local_absent = local_absent and not any(output.iterdir())
        # Withhold the final removed receipt if owned processes/files are
        # unresolved. Independent cloud cleanup still runs but cannot FREE this
        # access lease until the owner supplies positive cleanup evidence.
        if context is not None and process_absent and local_absent:
            try:
                cleanup_own_key(records, context, login, now=lambda: datetime.now(timezone.utc))
                key_absent = True
            except BaseException:
                pass
        try:
            cleanup_dispatch(snapshot)
            dispatched = True
        except BaseException:
            pass
        receipt = {'schema': 1, 'code': result, 'contained': contained, 'process_absent': process_absent,
                   'own_key_absent': key_absent, 'local_files_absent': local_absent,
                   'independent_cleanup_dispatched': dispatched, 'lease': rec['request_id']}
        # Publicly safe fixed statuses only; cloud deletion/FREE still require
        # independent immutable404/terminal-operation/access-archive receipts.
        print(json.dumps(receipt, sort_keys=True))
    return result if result else (0 if all((contained, process_absent, key_absent, local_absent, dispatched)) else 1)


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--payloads', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    snapshot = guest.data(guest.regular(args.snapshot, MAX_JSON, os.geteuid()))
    output = private_directory(args.output)
    expected_snapshot(snapshot)
    token = gcloud_token  # existing owner identity only; never impersonates
    records = GcsAccessRecords(BUCKET, token_provider=token)
    registration = OwnerRegistration(GcsSlotStore(BUCKET, token_provider=token),
                     PolicyCloud(ComputeRestTransport(token_provider=token), spec.PROJECT, spec.ZONE), records, snapshot)
    login = SelfLogin(snapshot['self_user'], token_provider=token)
    return trial(snapshot, args.payloads, output, registration=registration, records=records, login=login)


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise guest.Failure('signal', 143 if signum == signal.SIGTERM else 130)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        exit_code = main()
    except guest.Failure as error:
        print('Owner trial refused; inspect private cleanup evidence.', file=sys.stderr)
        exit_code = error.code
    except Exception:
        print('Owner trial failed closed; inspect private cleanup evidence.', file=sys.stderr)
        exit_code = 1
    sys.exit(exit_code)
