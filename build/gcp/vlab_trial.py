"""Trusted owner-local entrypoint for ONE closed disposable GCP trial.

Python 3.12 stdlib, invoked from accepted trusted main as
``python3 -m build.gcp.vlab_trial --snapshot PRIVATE --payloads PRIVATE --output PRIVATE``.
No cloud authority is supplied to workers. Input snapshot is a private captured
creator correlation, checked against GitHub/main, occupied ledger and immutable
cloud identity. It cannot select a command/profile/path/ref for remote work.
Only owner registration CAS/own-key evidence are mutations here; independent
fixed trusted workflows own creation/deletion. No cloud/SDK/private credential files leave
host. The ONE narrow exception is an explicit owner-protected GHCR record (#378) sent over
the original bootstrap stdin; see ``ghcr_credentials``.
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
from . import owned_process
from .inspection.hostkey import extract_ed25519
from .lifecycle import spec
from .lifecycle.access_records import AccessError, GcsAccessRecords, canonical
from .lifecycle.auth_http import gcloud_token
from .lifecycle.cli import BUCKET, CREATOR_PATH, REPOSITORY, verify_disk_provenance
from .lifecycle.cloud import PolicyCloud, ForbiddenOperation
from .lifecycle.compute import ComputeRestTransport
from .lifecycle.controller import Config, Controller, Refused
from .lifecycle.gcs import GcsSlotStore
from .lifecycle.oslogin import OwnKeyImport, SelfLogin, cleanup_own_key, profile_user

OWNER = 'art@githedgehog.com'
SNAPSHOT_FIELDS = ('profile', 'request_id', 'epoch', 'run_id', 'attempt', 'body_hash',
                   'ids', 'boot_image', 'boot_image_id', 'reserved_at', 'deadline', 'operation')
MAX_JSON = 256 * 1024
# Heartbeat remote: ONE monotonic budget covering both control checks (<=5s each),
# transport (<=8s) and every nested cleanup; 5+8+5=18 <= 22 <= join 25 - 3s margin.
HEARTBEAT_BUDGET_SECONDS = 22.0
HEARTBEAT_JOIN_SECONDS = 25
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


def command(argv, seconds, *, input_bytes=None, limit=65536, failed=None, env=None, until=None):
    """Bounded combined output; ``seconds`` is the TOTAL cap including cleanup.

    The leader stays an unreaped owned child until the original group received
    KILL; ``owned_process`` is the sole reaper and requires positive group ESRCH.
    """
    started = owned_process.monotonic()
    finish = min(started + seconds, until) if until is not None else started + seconds
    reserve = min(owned_process.CLEANUP_SECONDS, max(0, finish - started) / 2)
    deadline = finish - reserve
    proc = group = None
    attempted = False
    try:
        if input_bytes is not None:
            guest.require(len(input_bytes) <= 4096)
        if owned_process.monotonic() >= deadline:
            raise guest.Failure('bounded host child timeout', 124)
        attempted = True
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                start_new_session=True, env=env, bufsize=0)
        group = owned_process.OwnedGroup(proc)
        output = bytearray()
        pending = memoryview(input_bytes) if input_bytes is not None else None
        os.set_blocking(proc.stdout.fileno(), False)
        if proc.stdin is not None:
            os.set_blocking(proc.stdin.fileno(), False)
        with selectors.DefaultSelector() as select:
            select.register(proc.stdout, selectors.EVENT_READ)
            if pending:
                select.register(proc.stdin, selectors.EVENT_WRITE)
            elif proc.stdin is not None:
                proc.stdin.close()
            while select.get_map():
                guest.require(not (failed and failed.is_set()), 'heartbeat/master failed')
                if owned_process.monotonic() >= deadline:
                    raise guest.Failure('bounded host child timeout', 124)
                for key, _ in select.select(max(0, min(.2, deadline - owned_process.monotonic()))):
                    if owned_process.monotonic() >= deadline:
                        raise guest.Failure('bounded host child timeout', 124)
                    if key.fileobj is proc.stdin:
                        try:
                            pending = pending[os.write(proc.stdin.fileno(), pending):]
                        except BlockingIOError:
                            continue
                        if not pending:
                            select.unregister(proc.stdin)
                            proc.stdin.close()  # unbuffered FileIO: no flush/write in close
                        continue
                    try:
                        raw = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not raw:
                        select.unregister(key.fileobj)
                    else:
                        guest.require(len(output) + len(raw) <= limit, 'host output bound')
                        output.extend(raw)
        while True:  # non-reaping completion observation
            if owned_process.monotonic() >= deadline:
                raise guest.Failure('bounded host child timeout', 124)
            code = group.status()
            if owned_process.monotonic() >= deadline:
                raise guest.Failure('bounded host child timeout', 124)
            if code is not None:
                break
            guest.require(not (failed and failed.is_set()), 'heartbeat/master failed')
            if owned_process.monotonic() >= deadline:
                raise guest.Failure('bounded host child timeout', 124)
            owned_process.sleep(.01)
        if code:
            raise guest.Failure('host child failed', code if code > 0 else 128 - code)
        return bytes(output)
    finally:
        primary = sys.exc_info()[1]
        clean = not attempted
        try:
            if group is not None:
                clean = group.close(0, reserve, until=finish)
        except BaseException:
            clean = False
        finally:
            for pipe in (getattr(proc, 'stdin', None), getattr(proc, 'stdout', None)):
                try:
                    if pipe is not None:
                        pipe.close()
                except BaseException:
                    clean = False
            if owned_process.monotonic() >= finish:
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


def ghcr_credentials(path, output):
    """Protected owner-supplied GHCR record -> canonical validated bytes (<=1KiB).

    Explicit path only: nothing is sourced, discovered or read from the environment or any
    credential store. Owner-private 0600 regular file, no links, not under the output tree.
    Only the four validated fields survive canonicalization. Refusal text is fixed.
    """
    try:
        guest.harden_secret_process()
        path = guest.no_links(path)
        parent = path.parent.lstat()
        guest.require(parent.st_uid == os.geteuid() and not parent.st_mode & 0o022
                      and output.resolve() not in path.resolve().parents and path.resolve() != output.resolve())
        raw = guest.regular(path, guest.AUTH_INPUT_LIMIT, os.geteuid(), 0o600)
        return guest.encoded(guest.auth_credentials(raw))
    except BaseException:
        raise guest.Failure('GHCR credential input refused') from None


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
        self.spawn_attempted = False
        self.group = None
        self.socket_identity = None
        self.started = False
        self.instance = spec.names(snapshot['run_id'], snapshot['attempt'], spec.UBUNTU_VLAB_CORE)['instance']

    def start(self):
        guest.require(not self.started, 'master replacement refused')
        self.started = True
        proxy = shlex.join(['gcloud', 'compute', 'start-iap-tunnel', self.instance, '22',
                            '--project=' + spec.PROJECT, '--zone=' + spec.ZONE,
                            '--listen-on-stdin', '--quiet', '--verbosity=error'])
        until = owned_process.monotonic() + min(30, self.clock.remaining('access'))
        self.spawn_attempted = True
        try:
            self.proc = subprocess.Popen(['/usr/bin/ssh', *self.options, '-M', '-N',
                         '-o', 'ControlMaster=yes', '-o', 'ProxyCommand=' + proxy, self.target],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
            self.group = owned_process.OwnedGroup(self.proc)
        except BaseException as error:
            error.cleanup_uncertain = True
            raise
        while owned_process.monotonic() < until:
            guest.require(self.live(), 'original master exited')
            path = self.directory / 'master.sock'
            if path.exists():
                info = path.lstat()
                guest.require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid())
                self.socket_identity = (info.st_dev, info.st_ino)
                self.check(until)
                return
            time.sleep(.1)
        raise guest.Failure('master startup timed out', 124)

    def live(self):
        """Non-reaping liveness; lost ownership counts as not live (never as clean)."""
        try:
            return self.group is not None and self.group.status() is None
        except owned_process.OwnershipUncertain:
            return False

    @staticmethod
    def slice(cap, until):
        """Clip a total command cap to the shared monotonic budget; never renews it."""
        if until is None:
            return cap
        left = until - owned_process.monotonic()
        if left <= .5:
            raise guest.Failure('bounded heartbeat budget exhausted', 124)
        return min(cap, left)

    def check(self, until=None):
        guest.require(self.live() and self.socket_identity is not None, 'original master lost')
        info = (self.directory / 'master.sock').lstat()
        guest.require((info.st_dev, info.st_ino) == self.socket_identity, 'original master socket replaced')
        command(['/usr/bin/ssh', *self.options, '-o', 'ProxyCommand=/usr/bin/false', '-O', 'check', self.target],
                self.slice(5, until), until=until)

    def remote(self, args, phase, cap=30, cleanup=False, until=None, limit=65536, input_bytes=None):
        phase_end = owned_process.monotonic() + (self.clock.cleanup_remaining() if cleanup else self.clock.remaining(phase))
        until = phase_end if until is None else min(until, phase_end)
        self.check(until)
        # ControlMaster=no alone reconnects. This deliberately failing transport
        # is mandatory on EVERY subordinate invocation, including cleanup/SFTP.
        seconds = self.slice(min(cap, self.clock.cleanup_remaining() if cleanup else self.clock.remaining(phase)), until)
        raw = command(['/usr/bin/ssh', *self.options, '-o', 'ControlMaster=no', '-o', 'ProxyCommand=/usr/bin/false',
                       self.target, shlex.join(args)], seconds, limit=limit, failed=None if cleanup else self.failed, until=until,
                      **({} if input_bytes is None else {'input_bytes': input_bytes}))
        self.check(until)
        return raw

    def transfer(self, incoming, names, phase='stage'):
        until = owned_process.monotonic() + self.clock.remaining(phase)
        self.check(until)
        batch = self.directory / 'sftp.batch'
        lines = [f'put {shlex.quote(str(self.directory / name))} {incoming}/{name}' for name in names]
        guest.exclusive(batch, ('\n'.join(lines) + '\n').encode())
        try:
            command(['/usr/bin/sftp', '-b', str(batch), *self.options,
                     '-o', 'ControlMaster=no', '-o', 'ProxyCommand=/usr/bin/false', self.target],
                     min(600, self.clock.remaining(phase)), failed=self.failed, until=until)
            self.check(until)
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
        # TERM, bounded 5s grace, then KILL to the SAME still-anchored original
        # group (leader exit never proves group absence), then one shared 3s
        # reap/ESRCH convergence. Idempotent: repeats return the stored outcome.
        # Process group absence is separate from remote service containment.
        if self.group is None:
            return self.proc is None and not self.spawn_attempted
        try:
            if self.group.outcome is not None:
                return self.group.close(0)  # stored result, no renewed deadline or signals
            until = owned_process.monotonic() + self.clock.cleanup_remaining()
            return self.group.close(owned_process.TERM_GRACE_SECONDS, owned_process.CLEANUP_SECONDS, until=until)
        except BaseException:
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
n['bootstrap'](p,sys.argv[3],sys.argv[4:])
"""


# Fixed stdlib-only reader for the ONE guardian result. It imports nothing from the
# guest tree, so a failed/corrupt guest module cannot hide the observation. No path,
# action or command selector exists. It prints the exact <=4096 file bytes or the
# fixed token ``absent``/``invalid``; every byte is re-validated by the host.
READ_RESULT = """import os,stat,sys
def out(b):
    sys.stdout.buffer.write(b)
    sys.exit(0)
d='/var/lib/labapp-vlab-trial'
try:
    for q in ('/var','/var/lib',d):
        s=os.lstat(q)
        if stat.S_ISLNK(s.st_mode) or not stat.S_ISDIR(s.st_mode) or s.st_uid!=0: out(b'invalid')
    if stat.S_IMODE(s.st_mode)!=0o700: out(b'invalid')
except FileNotFoundError:
    out(b'absent')
except OSError:
    out(b'invalid')
try:
    f=os.open(d+'/result.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
except FileNotFoundError:
    out(b'absent')
except OSError:
    out(b'invalid')
try:
    s=os.fstat(f)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>4096: out(b'invalid')
    b=os.read(f,4097)
    t=os.fstat(f)
    if len(b)!=s.st_size or (s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)!=(t.st_ino,t.st_size,t.st_mtime_ns,t.st_ctime_ns): out(b'invalid')
finally:
    os.close(f)
out(b)
"""
RESULT_COMMAND = ['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-c', READ_RESULT]
RESULT_READ_LIMIT = guest.MAX_RESULT + 128
# Exact reviewed manager properties and closed values (systemd 255 service docs).
SERVICE_COMMAND = ['/usr/bin/sudo', '-n', '/usr/bin/systemctl', 'show', guest.UNIT, '-p', 'ActiveState',
                   '-p', 'Result', '-p', 'ExecMainCode', '-p', 'ExecMainStatus']
SERVICE_PROPERTIES = ('ActiveState', 'Result', 'ExecMainCode', 'ExecMainStatus')
SERVICE_ACTIVE = ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading', 'maintenance')
SERVICE_RESULTS = ('success', 'resources', 'timeout', 'exit-code', 'signal', 'core-dump', 'watchdog',
                   'start-limit-hit', 'oom-kill', 'protocol', 'exec-condition')


def guest_result(raw, nonce):
    """-> (state, record). Nothing is copied from the bytes before full validation.

    ``absent`` is pending evidence only, never success. Unsupported schema 1,
    oversize, duplicate/nonfinite/extra/mistyped fields and a wrong nonce are ``invalid``.
    """
    if raw == b'absent':
        return 'absent', None
    if type(raw) is not bytes or not raw or raw == b'invalid' or len(raw) > guest.MAX_RESULT:
        return 'invalid', None
    try:
        return 'valid', guest.result_record(guest.data(raw), nonce)
    except Exception:
        return 'invalid', None


def service_observation(raw):
    """Closed parse of the fixed manager properties; anything else is unknown (None).

    Diagnostic only: it can never produce a result, `contained` or any receipt, and
    signal 9 here is not an OOM attribution.
    """
    try:
        if type(raw) is not bytes or len(raw) > 512:
            return None
        fields = {}
        for line in raw.decode('ascii').splitlines():
            key, separator, value = line.partition('=')
            if not separator or key not in SERVICE_PROPERTIES or key in fields:
                return None
            fields[key] = value
        if set(fields) != set(SERVICE_PROPERTIES) or fields['ActiveState'] not in SERVICE_ACTIVE \
                or fields['Result'] not in SERVICE_RESULTS \
                or not re.fullmatch('[0-9]{1,3}', fields['ExecMainCode']) \
                or not re.fullmatch('[0-9]{1,3}', fields['ExecMainStatus']) \
                or int(fields['ExecMainCode']) > 7 or int(fields['ExecMainStatus']) > 255:
            return None
        return {'active_state': fields['ActiveState'], 'result': fields['Result'],
                'exec_code': int(fields['ExecMainCode']), 'exec_status': int(fields['ExecMainStatus'])}
    except Exception:
        return None


def observe_guest(master, nonce, status, process_uncertain):
    """One best-effort bounded observation through the SAME original master.

    Called BEFORE the fixed stop (a stop makes the guardian publish its own SIGTERM
    result). No reconnect, retry, key or private artifact. Supplements, never replaces,
    the primary failure and never grants `contained`.
    """
    detail = service = None
    try:
        raw = master.remote(RESULT_COMMAND, 'persistence', cap=8, cleanup=True, limit=RESULT_READ_LIMIT)
        state, record = guest_result(raw, nonce)
        status = 'pending' if state == 'absent' else state
        detail = record['diagnostic'] if state == 'valid' else None
    except BaseException as error:
        if getattr(error, 'cleanup_uncertain', False):
            process_uncertain.set()
    try:
        service = service_observation(master.remote(SERVICE_COMMAND, 'persistence', cap=8, cleanup=True, limit=1024))
    except BaseException as error:
        if getattr(error, 'cleanup_uncertain', False):
            process_uncertain.set()
    return status, detail, service


# Fixed one-shot private first-failure export (#368). The remote command has no path or
# selector argument. Budget: ONE absolute `until` over both control checks, transport and
# nested cleanup, with an explicit reserve left for the existing master close (TERM grace +
# reap) inside the unchanged immutable cleanup window.
EXPORT_CAP_SECONDS = 15
EXPORT_TEARDOWN_RESERVE = 12
EXPORT_MIN_SECONDS = 6
EXPORT_READ_LIMIT = guest.FAILURE_LIMIT + 1024
ZERO_BOOT = '00000000-0000-0000-0000-000000000000'  # initial contract placeholder: boot unknown
PRIVATE_DIAGNOSTIC = ('captured', 'absent', 'invalid', 'unavailable', 'skipped')


def export_command(nonce):
    return ['/usr/bin/sudo', '-n', '/usr/bin/python3', str(guest.ROOT / 'vlab_trial.py'),
            'export-failure', '--nonce', nonce]


def accept_failure(raw, source_sha, nonce, boot):
    """-> ('absent'|'invalid'|'captured', bundle). Expected values are HOST-held.

    The envelope (live guest state + contract + live boot) and the bundle header are two
    independent guest records; both must match the host's own source/nonce/fixed mode/boot.
    A self-consistent but foreign, stale or replaced bundle fails here. Mandatory, never optional.
    """
    if raw == b'absent':
        return 'absent', None
    try:
        guest.require(type(boot) is str and re.fullmatch(guest.UUID, boot) and boot != ZERO_BOOT)
        guest.require(type(raw) is bytes and 0 < len(raw) <= EXPORT_READ_LIMIT and raw != b'invalid')
        first, separator, rest = raw.partition(b'\n')
        guest.require(separator == b'\n')
        envelope = guest.data(first)
        guest.require(type(envelope) is dict and set(envelope) == {'schema', 'source_sha', 'nonce', 'mode',
                      'operation', 'invocation', 'boot'} and envelope['schema'] == 1
                      and type(envelope['schema']) is int)
        guest.require(envelope['source_sha'] == source_sha and envelope['nonce'] == nonce
                      and envelope['mode'] == 'fresh' and envelope['boot'] == boot)
        for key in ('operation', 'invocation'):
            guest.require(envelope[key] is None or type(envelope[key]) is str
                          and re.fullmatch(guest.HEX32, envelope[key]))
        bundle = guest.first_failure_bundle(rest)
        guest.require(bundle['nonce'] == nonce and bundle['mode'] == 'fresh' and bundle['boot'] == boot)
        guest.require(bundle['operation'] == envelope['operation']
                      and bundle['invocation'] == envelope['invocation'])
        return 'captured', raw
    except Exception:
        return 'invalid', None


def retain_private(directory, lease, raw):
    """Exclusive 0600 file in the owner-private directory outside ``output``; no overwrite."""
    guest.require(re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', lease))
    guest.exclusive(directory / ('first-failure-' + lease + '.bin'), raw)


def extract_failure(master, clock, nonce, snapshot, boot, directory, lease, process_uncertain):
    """Diagnostic-only; returns a closed status. Owner-local cleanup uncertainty is NEVER swallowed."""
    try:
        try:
            left = clock.cleanup_remaining() - EXPORT_TEARDOWN_RESERVE
        except guest.Failure:
            return 'skipped'
        if left < EXPORT_MIN_SECONDS:
            return 'skipped'
        until = owned_process.monotonic() + min(EXPORT_CAP_SECONDS, left)
        raw = master.remote(export_command(nonce), 'persistence', cap=EXPORT_CAP_SECONDS, cleanup=True,
                            until=until, limit=EXPORT_READ_LIMIT)
        state, kept = accept_failure(raw, snapshot['source_sha'], nonce, boot)
        if state != 'captured':
            return state
        retain_private(directory, lease, kept)
        # A guest query child whose cleanup was not confirmed is contained by the guardian and
        # VM disposal (a different process namespace); the capture must not look clean.
        return 'invalid' if guest.first_failure_bundle(kept.partition(b'\n')[2])['query_cleanup'] != 'confirmed' \
            else 'captured'
    except BaseException as error:
        if getattr(error, 'cleanup_uncertain', False):
            process_uncertain.set()
        return 'unavailable'


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


# Callsite context only, never inferred from exception text/type or guest output.
HOST_OPERATIONS = frozenset({
    'preflight', 'source-check', 'registration-check', 'owner-check', 'key-generation',
    'key-registration', 'access-prepare', 'access-import', 'host-key', 'master-start',
    'guest-boot', 'guest-probe', 'source-stage', 'payload-stage', 'candidate-generation',
    'manifest-generation', 'source-transfer', 'bootstrap', 'heartbeat-start', 'poll-check',
    'result-read', 'service-read', 'result-validate',
})


def trial(snapshot, payloads, output, *, registration, records, login, private=None, ghcr=None):
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
    phase, failure_category = 'preflight', 'none'
    host_operation = 'preflight'
    # Public guest diagnostic: `unavailable` until a bounded read or observation says otherwise.
    guest_status, guest_detail, guest_service = 'unavailable', None, None
    private_diagnostic = 'skipped'
    try:
        clock = guest.Clock(initial)
        clock.remaining('access')
        host_operation = 'source-check'
        trusted_source(snapshot, initial=True)
        host_operation = 'registration-check'
        rec = registration.current()
        # Confirm exact active owner, no account switch/impersonation/key agent.
        host_operation = 'owner-check'
        account = command(['gcloud', 'auth', 'list', '--filter=status:ACTIVE', '--format=value(account)'], 15).decode().strip()
        guest.require(account == OWNER)
        impersonation = command(['gcloud', 'config', 'get-value', 'auth/impersonate_service_account', '--quiet'], 15).decode().strip()
        guest.require(impersonation in ('', '(unset)') and not os.environ.get('CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT'),
                      'owner impersonation unsupported')
        owner_profile = guest.data(command(['gcloud', 'compute', 'os-login', 'describe-profile', '--format=json'], 20))
        guest.require(profile_user(owner_profile.get('name')) == snapshot['self_user'] == login.user,
                      'canonical SELF identity differs')
        version = guest.data(command(['gcloud', 'version', '--format=json'], 15))
        guest.require(version.get('Google Cloud SDK') == '575.0.0')
        host_operation = 'key-generation'
        command(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(output / 'oslogin')], 10)
        public_key = guest.regular(output / 'oslogin.pub', 4096, os.geteuid()).decode().strip()
        host_operation = 'key-registration'
        context = registration.register(public_key)
        importer = OwnKeyImport(records, context, login, producer_run_id=rec['run_id'], producer_attempt=rec['attempt'],
                                now=lambda: datetime.now(timezone.utc))
        phase = 'access-prepare'
        host_operation = 'access-prepare'
        intent, _ = importer.prepare(public_key)
        phase = 'access-import'
        host_operation = 'access-import'
        importer.import_once()
        phase = 'guest-access'
        host_operation = 'registration-check'
        registration.current()
        host_operation = 'host-key'
        hostkey = command(['gcloud', 'compute', 'instances', 'get-guest-attributes', rec['names']['instance'],
                           '--project=' + spec.PROJECT, '--zone=' + spec.ZONE,
                           '--query-path=hostkeys/ssh-ed25519', '--format=json'], min(20, clock.remaining('access')), limit=4096)
        key_line = extract_ed25519(hostkey)
        host_operation = 'registration-check'
        registration.current()
        host_operation = 'host-key'
        guest.exclusive(output / 'known_hosts', ('labapp-trial-' + rec['ids']['instance'] + ' ' + key_line).encode())
        command(['/usr/bin/ssh-keygen', '-l', '-f', str(output / 'known_hosts'), '-E', 'sha256'], 10)
        host_operation = 'master-start'
        master = Master(output, snapshot, intent['posix']['username'], clock, failed)
        master.start()
        # Harmless marker transfer and sudo/boot proof before appliance bytes.
        host_operation = 'guest-boot'
        boot = master.remote(['/usr/bin/cat', '/proc/sys/kernel/random/boot_id'], 'access').decode().strip()
        guest.require(re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', boot))
        initial['boot_uuid'] = boot
        guest.contract(initial)
        host_operation = 'registration-check'
        registration.current()
        host_operation = 'guest-probe'
        master.remote(['/usr/bin/sudo', '-n', '/usr/bin/true'], 'access')
        incoming = '/tmp/labapp-vlab-' + nonce
        master.remote(['/usr/bin/mkdir', '-m', '0700', incoming], 'access')
        guest.exclusive(output / 'marker', nonce.encode())
        master.transfer(incoming, ['marker'], 'access')
        guest.require(master.remote(['/usr/bin/cat', incoming + '/marker'], 'access') == nonce.encode())
        master.remote(['/usr/bin/rm', '--', incoming + '/marker'], 'access')
        phase = 'guest-work'
        host_operation = 'source-stage'
        source = source_files(snapshot, output)
        host_operation = 'payload-stage'
        for name, pin in guest.PAYLOADS.items():
            raw = guest.regular(guest.no_links(payloads / name), pin[0], os.geteuid())
            guest.require((len(raw), guest.sha(raw)) == pin)
            guest.exclusive(output / name, raw)
        host_operation = 'candidate-generation'
        command(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(output / 'candidate')], 10)
        candidate_key = guest.regular(output / 'candidate.pub', 4096, os.geteuid()).decode().split()
        password = secrets.token_urlsafe(36)
        guest.exclusive(output / 'candidate.password', password.encode())
        password_hash = command(['/usr/bin/openssl', 'passwd', '-5', '-stdin'], 10, input_bytes=(password + '\n').encode(),
                                limit=4096, env=SAFE_ENV).decode().strip()
        guest.exclusive(output / 'fab.yaml', candidate_fab(' '.join(candidate_key[:2]), password_hash, secrets.token_hex(32)))
        host_operation = 'manifest-generation'
        guest.exclusive(output / 'contract.json', canonical(initial))
        for name in guest.FILES - set(source):
            raw = guest.regular(output / name, guest.PAYLOADS[name][0] if name in guest.PAYLOADS else guest.MAX_SOURCE, os.geteuid())
            source[name] = {'bytes': len(raw), 'sha256': guest.sha(raw)}
        table = guest.manifest({'schema': 1, 'source_sha': snapshot['source_sha'], 'files': source})
        guest.exclusive(output / 'manifest.json', canonical(table))
        host_operation = 'registration-check'
        registration.current()
        host_operation = 'source-check'
        trusted_source(snapshot)
        host_operation = 'source-transfer'
        master.transfer(incoming, [*sorted(guest.FILES), 'manifest.json'])
        host_operation = 'registration-check'
        registration.current()
        host_operation = 'bootstrap'
        bootstrap = ['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-c', BOOTSTRAP, incoming,
                     source['vlab_trial.py']['sha256'], guest.sha(canonical(table))]
        if ghcr is None:
            master.remote(bootstrap, 'stage', cap=60)
        else:
            # The record travels only on the original master's stdin (never argv/SFTP/files);
            # bootstrap accepts it only after the guardian is running and cleanup is armed.
            master.remote([*bootstrap, 'ghcr-auth'], 'stage', cap=60, input_bytes=ghcr)
        # Heartbeat starts immediately after bounded root bootstrap. Startup
        # grace is thirty seconds; worker cannot extend it or update itself.
        def heartbeat():
            sequence = 0
            try:
                while not stop.is_set():
                    sequence += 1
                    master.remote(['/usr/bin/sudo', '-n', '/usr/bin/python3', str(guest.ROOT / 'vlab_trial.py'), 'heartbeat',
                                   '--nonce', nonce, '--sequence', str(sequence)], 'persistence', cap=8,
                                  until=owned_process.monotonic() + HEARTBEAT_BUDGET_SECONDS)
                    stop.wait(10)
            except BaseException as error:
                if getattr(error, 'cleanup_uncertain', False):
                    process_uncertain.set()
                failed.set()
        host_operation = 'heartbeat-start'
        heartbeat_thread = threading.Thread(target=heartbeat, daemon=True)
        heartbeat_thread.start()
        while True:
            host_operation = 'poll-check'
            guest.require(not failed.is_set(), 'heartbeat failed')
            host_operation = 'registration-check'
            registration.current()
            host_operation = 'source-check'
            trusted_source(snapshot)
            host_operation = 'poll-check'
            clock.remaining('persistence')
            # No FAB/kubeconfigs are pulled; the only private pull is the ONE fixed
            # first-failure export in `finally` (#368). One fixed sanitized result
            # is read after the guardian has contained services.
            host_operation = 'result-read'
            raw = master.remote(RESULT_COMMAND, 'persistence', cap=8, limit=RESULT_READ_LIMIT)
            host_operation = 'result-validate'
            state, record = guest_result(raw, nonce)
            if state == 'absent':
                guest_status = 'pending'
                # A simple service may have failed exec/import before it could
                # publish anything. Observe only the original channel, within the
                # existing work clock; manager data never supplies a result.
                try:
                    host_operation = 'service-read'
                    guest_service = service_observation(master.remote(
                        SERVICE_COMMAND, 'persistence', cap=8, limit=1024))
                except BaseException as error:
                    if getattr(error, 'cleanup_uncertain', False):
                        process_uncertain.set()
                    raise
                if guest_service is None or guest_service['active_state'] not in ('failed', 'inactive'):
                    host_operation = 'poll-check'
                    stop.wait(5)
                    continue
                # Bounded recheck closes the normal result-publication race.
                # A terminal service without a genuine record fails promptly.
                host_operation = 'result-read'
                raw = master.remote(RESULT_COMMAND, 'persistence', cap=8, limit=RESULT_READ_LIMIT)
                host_operation = 'result-validate'
                state, record = guest_result(raw, nonce)
                if state == 'absent':
                    guest_status = 'missing'
                    raise guest.Failure('terminal guest service without result')
            guest_status = state
            guest.require(state == 'valid', 'guest result invalid')
            result, contained = record['code'], record['contained']
            guest_detail = record['diagnostic']
            phase = 'guest-result'
            failure_category = 'guest' if result else 'none'
            break
    except guest.Failure as error:
        result = error.code
        failure_category = 'guest'
        if getattr(error, 'cleanup_uncertain', False):
            process_uncertain.set()
    except KeyboardInterrupt as error:
        result = 130
        failure_category = 'interrupted'
        if getattr(error, 'cleanup_uncertain', False):
            process_uncertain.set()
    except Exception as error:
        result = 1
        failure_category = 'access' if isinstance(error, AccessError) else 'unknown'
        if getattr(error, 'cleanup_uncertain', False):
            process_uncertain.set()
    finally:
        # Keep primary callsite context frozen throughout supplemental diagnostics/cleanup.
        stop.set()
        heartbeat_absent = True
        if heartbeat_thread:
            try:
                heartbeat_thread.join(timeout=HEARTBEAT_JOIN_SECONDS)
                heartbeat_absent = not heartbeat_thread.is_alive()
            except BaseException:
                heartbeat_absent = False
                process_uncertain.set()
        process_absent = master is None and heartbeat_absent and not process_uncertain.is_set()
        if master is not None:
            if not contained and heartbeat_absent:
                if guest_status in ('unavailable', 'pending'):
                    # Before the stop below; the primary failure above is retained.
                    guest_status, guest_detail, guest_service = observe_guest(master, nonce, guest_status, process_uncertain)
                try:
                    master.remote(['/usr/bin/sudo', '-n', '/usr/bin/systemctl', 'stop', guest.UNIT],
                                  'persistence', cap=120, cleanup=True)
                    # Stop success alone cannot attest ExecStopPost result;
                    # preserve uncertainty unless guardian already reported it.
                except BaseException as error:
                    if getattr(error, 'cleanup_uncertain', False):
                        process_uncertain.set()
            if private is not None and result != 0 and heartbeat_absent and initial['boot_uuid'] != ZERO_BOOT:
                # After the joined heartbeat and the fixed stop, before the original master
                # closes: no reconnect, reauthentication or retry. Diagnostic only; it
                # cannot change `result`, `contained` or the stop above.
                private_diagnostic = extract_failure(master, clock, nonce, snapshot, initial['boot_uuid'],
                                                     private, rec['request_id'], process_uncertain)
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
                   'phase': phase, 'failure_category': failure_category, 'host_operation': host_operation,
                   'own_key_absent': key_absent, 'local_files_absent': local_absent,
                   'independent_cleanup_dispatched': dispatched, 'lease': rec['request_id'],
                   # Closed values only; never text, argv, paths or raw manager output.
                   'guest_diagnostic_status': guest_status, 'guest_diagnostic': guest_detail,
                   'guest_service': guest_service,
                   # Closed status of the fixed owner-private first-failure capture; never a path or bytes.
                   'private_diagnostic': private_diagnostic}
        # Publicly safe fixed statuses only; cloud deletion/FREE still require
        # independent immutable404/terminal-operation/access-archive receipts.
        print(json.dumps(receipt, sort_keys=True))
    return result if result else (0 if all((contained, process_absent, key_absent, local_absent, dispatched)) else 1)


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--payloads', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    # Optional lead-owned retention directory for the fixed private first-failure capture.
    # Without it the capture is `skipped`. It must be outside `output` (which stays empty).
    parser.add_argument('--private-diagnostics', type=Path)
    # Optional owner-protected GHCR record {"schema":1,"registry":"ghcr.io","username":..,"token":..};
    # prepared by the lead outside repository code. Never sourced, discovered or echoed.
    parser.add_argument('--ghcr-credentials', type=Path)
    args = parser.parse_args(argv)
    os.umask(0o077)
    snapshot = guest.data(guest.regular(args.snapshot, MAX_JSON, os.geteuid()))
    output = private_directory(args.output)
    private = None
    if args.private_diagnostics is not None:
        private = guest.no_links(args.private_diagnostics)
        info = private.lstat()
        guest.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                      and stat.S_IMODE(info.st_mode) == 0o700, 'private diagnostic directory required')
        guest.require(re.fullmatch('/[A-Za-z0-9_./-]+', str(private)) and private != output
                      and output not in private.parents and private not in output.parents,
                      'private diagnostic directory must be outside output')
    expected_snapshot(snapshot)
    ghcr = None if args.ghcr_credentials is None else ghcr_credentials(args.ghcr_credentials, output)
    token = gcloud_token  # existing owner identity only; never impersonates
    records = GcsAccessRecords(BUCKET, token_provider=token)
    registration = OwnerRegistration(GcsSlotStore(BUCKET, token_provider=token),
                     PolicyCloud(ComputeRestTransport(token_provider=token), spec.PROJECT, spec.ZONE), records, snapshot)
    login = SelfLogin.for_owner(snapshot['self_user'], token_provider=token)
    return trial(snapshot, args.payloads, output, registration=registration, records=records, login=login,
                 private=private, ghcr=ghcr)


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
