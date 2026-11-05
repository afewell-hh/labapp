"""Trusted owner-local caller for the ONE fixed management guest program (issue #506).

SOURCE-INACTIVE. ``main`` and ``trial`` refuse unconditionally through
``program.refuse_activation`` before any file, credential, network or cloud object is touched;
there is no flag, argument or environment value that bypasses it and this source does not record any
approval. ``sequence`` is the internal body a later, separately reviewed activation would expose;
it is exercised only by offline synthetic tests.

It adds NO command selector, controller, provider/profile/IAM change or student CLI. Everything
that protects the VLAB trial is reused unchanged from ``build.gcp.vlab_trial``: trusted-main source
binding, owner registration (CAS/lease), OS Login own-key import and cleanup, pinned host key, the
ONE original ControlMaster with its failing fallback proxy (``Master.remote``/``transfer``/``check``),
heartbeat, bounded private captures, creator cancellation and positive cleanup. The only differences
are the fixed management tables (``build.provision.management_trial``), the admission-anchored
management clock and (#508) ONE authenticated guest clock correlation staged as an immutable capsule.
The guest owns the lifetime (fixed guardian, boot-monotonic expiry timer, stop service); the host only
samples the clock once, bootstraps, heartbeats, reads the typed result, forwards the Viewer, and
requests ``cancel``. It never executes, retries or reorders a step. ``contained`` is never claimed.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import sys
import threading
import time

from build.provision import management_trial as program
from build.provision import vlab_trial as guest
from . import owned_process
from .inspection.hostkey import extract_ed25519
from .lifecycle import spec
from .lifecycle.access_records import AccessError, canonical
from .lifecycle.oslogin import OwnKeyImport, cleanup_own_key, profile_user
from . import vlab_trial as owner

PROGRESS_CAP = 15              # one fixed read-only ``result`` poll over the original Master
PROGRESS_INTERVAL = 5          # seconds between polls; no step is executed or retried by the host
CANCEL_CAP = 15
TEARDOWN_CAP = 240             # upper bound for waiting on the guest's own poststop receipt
RESULT_CAP = 15
CLOCK_SAMPLE_CAP = 15
INVALID_POLLS = 3              # consecutive unreadable results tolerated (atomic-replace read race)
EXPORT_CAP = 15
BROWSER_MIN_SECONDS = 60       # less work time than this -> browser step skipped, never faked
BROWSER_WAIT_SECONDS = 600     # upper bound; always clipped to the original remaining work time
FORWARD_HOST, FORWARD_PORT = '127.0.0.1', program.GRAFANA_PORT
FORWARD_SPEC = '%s:%d:%s:%d' % (FORWARD_HOST, FORWARD_PORT, program.BIND_ADDRESS, program.GRAFANA_PORT)
# Private OWNER-ATTESTED completion record. It binds the attestation to this trial's nonce, lease,
# Viewer identity and the discovered dashboard UID/panel. No source here observes a browser, so no
# input can ever make the status ``verified``: the highest status is ``owner-attested``.
BROWSER_FIELDS = {'schema', 'nonce', 'lease', 'attestation', 'login', 'role', 'dashboard_uid', 'panel_id',
                  'datasource_type', 'ui_result'}
BROWSER_RESULTS = ('viewer-panel-seen', 'viewer-panel-failed')
BROWSER_ATTESTATION = 'owner-attested'
BROWSER_VERIFIED = 'verified'  # reserved; no code path in this source produces it

# Hash-verifying root stub. It authenticates BOTH vlab_trial.py (primitives) and management_trial.py
# against host-held digests BEFORE executing either, then calls the (activation-gated) bootstrap.
# It selects nothing: no path, action or command comes from arguments other than the fixed layout.
STUB = """import hashlib,os,stat,sys,types
from pathlib import Path
p=Path(sys.argv[1])
def load(name,expected,module):
    f=os.open(p/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    s=os.fstat(f)
    assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=262144
    b=os.read(f,262145); os.close(f)
    assert len(b)==s.st_size and hashlib.sha256(b).hexdigest()==expected
    m=types.ModuleType(module); m.__file__=str(p/name)
    sys.modules[module]=m
    exec(compile(b,str(p/name),'exec'),m.__dict__)
    return m
load('vlab_trial.py',sys.argv[2],'vlab_trial')
load('owned_process.py',sys.argv[3],'owned_process')
m=load('management_trial.py',sys.argv[4],'management_trial')
m.bootstrap(p,sys.argv[5])
"""
MANAGEMENT_SCRIPT = str(program.MROOT / 'management_trial.py')
SUDO = ['/usr/bin/sudo', '-n', '/usr/bin/python3']


def fixed_command(action, nonce, sequence=None):
    """Closed host actions only. No step, teardown or worker selector exists on the host (#508)."""
    guest.require(action in program.HOST_ACTIONS and re.fullmatch('[a-f0-9]{32}', nonce))
    extra = [] if sequence is None else ['--sequence', str(sequence)]
    return [*SUDO, MANAGEMENT_SCRIPT, action, '--nonce', nonce, *extra]


def management_source_files(snapshot, output):
    """Management twin of ``vlab_trial.source_files``: the fixed table only, from the trusted-main SHA."""
    result = {}
    for name, path in program.SOURCES.items():
        value = owner.github('contents/' + path + '?ref=' + snapshot['source_sha'], 512 * 1024)
        guest.require(value.get('type') == 'file' and value.get('path') == path and value.get('encoding') == 'base64'
                      and type(value.get('size')) is int and 0 < value['size'] <= guest.MAX_SOURCE)
        raw = base64.b64decode(value['content'].replace('\n', ''), validate=True)
        guest.require(len(raw) == value['size'])
        guest.exclusive(output / name, raw)
        result[name] = {'bytes': len(raw), 'sha256': guest.sha(raw)}
    return result


def guest_clock_capsule(master, clock, initial):
    """ONE bounded authenticated guest clock sample through the original Master (no reconnect).

    The caller's ONCE-retained original clock supplies the send and RESPONSE readings; the guest
    sample is bound to boot and a fresh one-shot nonce. Round trip <= 10s, wall within the caller
    bracket +-5s, safety allowance subtracted, round trip never added back (all in
    ``program.build_capsule``). Never resampled after an ambiguous bootstrap: the capsule is staged once.
    """
    sample_nonce = secrets.token_hex(16)
    send = (clock.wall(), clock.mono())
    raw = master.remote(['/usr/bin/python3', '-I', '-c', program.SAMPLE_STUB, sample_nonce], 'access',
                        cap=CLOCK_SAMPLE_CAP, limit=1024)
    receive = (clock.wall(), clock.mono())
    return program.build_capsule(initial, clock, guest.data(raw), sample_nonce, send, receive)


def stage_program(snapshot, payloads, output, initial, capsule=None):
    """Fixed source + hash/size-pinned payloads + contract + clock capsule -> verified manifest table."""
    guest.require(capsule is not None or 'capsule.json' not in program.FILES, 'clock capsule required')
    source = management_source_files(snapshot, output)
    for name, pin in program.PAYLOADS.items():
        raw = guest.regular(guest.no_links(payloads / name), pin[0], os.geteuid())
        guest.require((len(raw), guest.sha(raw)) == pin, 'payload bytes refused')
        guest.exclusive(output / name, raw)
    guest.exclusive(output / 'contract.json', canonical(initial))
    if capsule is not None:
        guest.exclusive(output / 'capsule.json', canonical(program.validate_capsule(capsule, initial)))
    for name in program.FILES - set(source):
        raw = guest.regular(output / name, program.PAYLOADS[name][0] if name in program.PAYLOADS else guest.MAX_SOURCE,
                            os.geteuid())
        source[name] = {'bytes': len(raw), 'sha256': guest.sha(raw)}
    table = program.manifest({'schema': 1, 'source_sha': snapshot['source_sha'], 'files': source})
    guest.exclusive(output / 'manifest.json', canonical(table))
    return source, table


def bootstrap_command(incoming, source, table):
    return [*SUDO, '-I', '-c', STUB, incoming, source['vlab_trial.py']['sha256'],
            source['owned_process.py']['sha256'], source['management_trial.py']['sha256'], guest.sha(canonical(table))]


def management_result(raw, nonce):
    """-> (state, record). Nothing is trusted before the strict closed validator accepts all of it."""
    if raw == b'absent':
        return 'absent', None
    try:
        guest.require(type(raw) is bytes and 0 < len(raw) <= 4096 and raw != b'invalid')
        return 'valid', program.validate_result(guest.data(raw), nonce)
    except Exception:
        return 'invalid', None


def forward_command(master, verb):
    guest.require(verb in ('forward', 'cancel'))
    # Same original socket and the same deliberately failing fallback proxy as every other call.
    return ['/usr/bin/ssh', *master.options, '-o', 'ControlMaster=no', '-o', 'ProxyCommand=/usr/bin/false',
            '-O', verb, '-L', FORWARD_SPEC, master.target]


def listening():
    """True for a listener, False only for definite refusal, None for indeterminate failure."""
    try:
        with socket.create_connection((FORWARD_HOST, FORWARD_PORT), timeout=2):
            return True
    except OSError as error:
        return False if error.errno == errno.ECONNREFUSED else None


def browser_session(master, clock, nonce, lease, raw_handoff, private, failed, process_uncertain):
    """Original-master loopback forward -> owner-completed browser check -> explicit teardown.

    -> (browser_status, forward_absent). The best status is ``owner-attested``: what the owner wrote
    in the private completion file under the original clock, bound to nonce/lease/Viewer/dashboard.
    It is NOT verified browser evidence; curl/API/admin evidence can never produce either.
    """
    if private is None:
        return 'skipped', True
    try:
        left = clock.remaining('work')
    except guest.Failure:
        return 'skipped', True
    if left < BROWSER_MIN_SECONDS:
        return 'skipped', True  # nothing was opened by this program
    present = listening()
    if present is not False:
        if present is None:
            process_uncertain.set()
        return 'skipped', present is True
    handoff = private / ('viewer-handoff-' + lease + '.json')
    done = private / ('browser-complete-' + lease + '.json')
    guest.no_links(private)
    directory = private.lstat()
    guest.require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == os.geteuid()
                  and stat.S_IMODE(directory.st_mode) == 0o700 and not os.path.lexists(done)
                  and not os.path.lexists(handoff), 'private handoff refused')
    owned = {}

    def remember(path):
        info = path.lstat()
        guest.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                      and stat.S_IMODE(info.st_mode) == 0o600, 'private file identity refused')
        identity = info.st_dev, info.st_ino
        guest.require(path not in owned or owned[path] == identity, 'private file replaced')
        owned[path] = identity

    status, attempted = 'forward-failed', False
    try:
        program.validate_handoff(guest.data(raw_handoff), nonce)
        fd = os.open(handoff, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            owned[handoff] = info.st_dev, info.st_ino
            stream = os.fdopen(fd, 'wb')
            fd = None
            with stream:
                stream.write(raw_handoff)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if fd is not None:
                os.close(fd)
        remember(handoff)
        until = owned_process.monotonic() + min(15, left)
        master.check(until)
        attempted = True
        owner.command(forward_command(master, 'forward'), owner.Master.slice(15, until), until=until, failed=failed)
        master.check()
        guest.require(listening() is True, 'forward not listening')
        status = 'timeout'
        end = owned_process.monotonic() + min(BROWSER_WAIT_SECONDS, clock.remaining('work') - 30)
        while owned_process.monotonic() < end:
            guest.require(not failed.is_set(), 'heartbeat/master failed')
            master.check()  # original socket identity + liveness on every poll: no reconnect, no new auth
            guest.require(listening() is True, 'forward lost')
            if done.exists():
                remember(done)
                value = guest.data(guest.regular(done, 512, os.geteuid(), 0o600))
                expected = guest.data(raw_handoff)
                uid, panel = re.fullmatch(r'/d/([A-Za-z0-9_-]{1,40})\?viewPanel=([0-9]{1,6})', expected['path']).groups()
                guest.require(type(value) is dict and set(value) == BROWSER_FIELDS and value['schema'] == 2
                              and value['nonce'] == nonce and value['lease'] == lease
                              and value['attestation'] == BROWSER_ATTESTATION
                              and value['login'] == expected['login'] and value['role'] == 'Viewer'
                              and value['dashboard_uid'] == uid and type(value['panel_id']) is int
                              and value['panel_id'] == int(panel) and value['datasource_type'] == 'prometheus'
                              and value['ui_result'] in BROWSER_RESULTS)
                status = BROWSER_ATTESTATION if value['ui_result'] == 'viewer-panel-seen' else 'failed'
                break
            time.sleep(2)
    except BaseException as error:
        if getattr(error, 'cleanup_uncertain', False):
            process_uncertain.set()
        if status == 'timeout':
            status = 'forward-failed'
    finally:
        absent = not attempted
        if attempted:
            try:
                owner.command(forward_command(master, 'cancel'), 10)
            except BaseException as error:
                if getattr(error, 'cleanup_uncertain', False):
                    process_uncertain.set()
            try:
                absent = listening() is False
            except BaseException:
                absent = False
        if not absent:
            process_uncertain.set()
        try:
            current = private.lstat()
            guest.require((current.st_dev, current.st_ino) == (directory.st_dev, directory.st_ino)
                          and stat.S_ISDIR(current.st_mode) and current.st_uid == os.geteuid()
                          and stat.S_IMODE(current.st_mode) == 0o700, 'private directory replaced')
            for path in (handoff, done):
                if os.path.lexists(path):
                    guest.require(path in owned or path == done and attempted, 'unowned private file')
                    remember(path)
                    path.unlink()
                guest.require(not os.path.lexists(path), 'private file remains')
        except BaseException:
            process_uncertain.set()
    return status, absent


HOST_OPERATIONS = frozenset({
    'preflight', 'source-check', 'registration-check', 'owner-check', 'key-generation', 'key-registration',
    'access-prepare', 'access-import', 'host-key', 'master-start', 'guest-boot', 'guest-probe', 'program-stage',
    'source-transfer', 'bootstrap', 'heartbeat-start', 'management-progress', 'viewer-export', 'browser',
    'clock-sample', 'cancel', 'result-read'})


class Held:
    """Resources that the finalizer must release even after a partial enrollment."""
    def __init__(self):
        self.master = self.context = self.thread = None
        self.attempted = False  # a guest bootstrap was attempted, so fixed teardown must be tried
        self.operation = 'preflight'


def enroll(snapshot, output, registration, records, login, rec, clock, failed, initial, held):
    """Mirror of the VLAB enrollment up to the verified original master (same checks, same order)."""
    held.operation = 'source-check'
    owner.trusted_source(snapshot, initial=True)
    held.operation = 'registration-check'
    rec = registration.current()
    held.operation = 'owner-check'
    account = owner.command(['gcloud', 'auth', 'list', '--filter=status:ACTIVE', '--format=value(account)'], 15).decode().strip()
    guest.require(account == owner.OWNER)
    impersonation = owner.command(['gcloud', 'config', 'get-value', 'auth/impersonate_service_account', '--quiet'], 15).decode().strip()
    guest.require(impersonation in ('', '(unset)') and not os.environ.get('CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT'),
                  'owner impersonation unsupported')
    profile = guest.data(owner.command(['gcloud', 'compute', 'os-login', 'describe-profile', '--format=json'], 20))
    guest.require(profile_user(profile.get('name')) == snapshot['self_user'] == login.user, 'canonical SELF identity differs')
    version = guest.data(owner.command(['gcloud', 'version', '--format=json'], 15))
    guest.require(version.get('Google Cloud SDK') == '575.0.0')
    held.operation = 'key-generation'
    owner.command(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(output / 'oslogin')], 10)
    public_key = guest.regular(output / 'oslogin.pub', 4096, os.geteuid()).decode().strip()
    held.operation = 'key-registration'
    held.context = registration.register(public_key)
    importer = OwnKeyImport(records, held.context, login, producer_run_id=rec['run_id'], producer_attempt=rec['attempt'],
                            now=lambda: datetime.now(timezone.utc))
    held.operation = 'access-prepare'
    intent, _ = importer.prepare(public_key)
    held.operation = 'access-import'
    importer.import_once()
    held.operation = 'registration-check'
    registration.current()
    held.operation = 'host-key'
    hostkey = owner.command(['gcloud', 'compute', 'instances', 'get-guest-attributes', rec['names']['instance'],
                             '--project=' + spec.PROJECT, '--zone=' + spec.ZONE, '--query-path=hostkeys/ssh-ed25519',
                             '--format=json'], min(20, clock.remaining('access')), limit=4096)
    key_line = extract_ed25519(hostkey)
    registration.current()
    guest.exclusive(output / 'known_hosts', ('labapp-trial-' + rec['ids']['instance'] + ' ' + key_line).encode())
    owner.command(['/usr/bin/ssh-keygen', '-l', '-f', str(output / 'known_hosts'), '-E', 'sha256'], 10)
    held.operation = 'master-start'
    held.master = owner.Master(output, snapshot, intent['posix']['username'], clock, failed)
    held.master.start()
    held.operation = 'guest-boot'
    boot = held.master.remote(['/usr/bin/cat', '/proc/sys/kernel/random/boot_id'], 'access').decode().strip()
    guest.require(re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', boot))
    initial['boot_uuid'] = boot
    guest.contract(initial)
    registration.current()
    held.operation = 'guest-probe'
    held.master.remote(['/usr/bin/sudo', '-n', '/usr/bin/true'], 'access')
    return rec


def native_code(failure):
    """Process code for a typed guest failure. Native precedence: a positive exit stays itself, a negative
    raw signal maps to 128+signal exactly like ``child_failure``; only non-native categories collapse to 1."""
    status = failure['child_status']
    if type(status) is int and 0 < status < 256:
        return status
    if type(status) is int and -64 <= status < 0:
        return 128 - status
    return 1


TERMINAL_AMBIGUOUS_CODE = 1  # fixed code for a closure-window negative status (see ``terminal_code``)


def terminal_code(terminal):
    """Process code for the guest's separate typed terminal evidence; 0 = nothing to reconcile.

    Fixed honest policy: an observed positive exit keeps itself whichever window saw it (a closure-window 17
    is an observed terminal 17, not proof it preceded cleanup signals). A ``pre-close`` raw negative signal
    is native and maps to 128+signal. A ``closure-window`` negative status may be the signal OUR closure
    delivered, so it is never claimed as a native pre-closure failure: it returns the fixed code 1. Status 0,
    unknown or unobserved reconcile nothing, and are never verified success either."""
    status, origin = terminal['status'], terminal['origin']
    if origin == 'unobserved' or type(status) is not int or status == 0:
        return 0
    if status > 0:
        return status
    return 128 - status if origin == 'pre-close' else TERMINAL_AMBIGUOUS_CODE


def sequence(snapshot, payloads, output, *, registration, records, login, private=None):
    """INTERNAL body; never reachable from ``main``/``trial`` while activation is held."""
    owner.expected_snapshot(snapshot)
    rec = dict(snapshot, names=spec.names(snapshot['run_id'], snapshot['attempt'], spec.UBUNTU_VLAB_CORE))
    nonce = secrets.token_hex(16)
    initial = {'schema': 1, 'nonce': nonce, 'lease': rec['request_id'], 'epoch': rec['epoch'],
               'run_id': rec['run_id'], 'attempt': rec['attempt'], 'body_sha256': rec['body_hash'],
               'vm_id': rec['ids']['instance'], 'boot_id': rec['ids']['boot'], 'image_id': rec['boot_image_id'],
               'admitted_at': rec['reserved_at'], 'deadline': rec['deadline'],
               'boot_uuid': '00000000-0000-0000-0000-000000000000', 'source_sha': snapshot['source_sha']}
    failed, stop, process_uncertain = threading.Event(), threading.Event(), threading.Event()
    held = Held()
    result, phase, category, dispatched, key_absent = 1, 'preflight', 'none', False, False
    typed_state, typed, browser, forward_absent = 'absent', None, 'skipped', True
    try:
        clock = program.ManagementClock(initial)
        clock.remaining('access')
        rec = enroll(snapshot, output, registration, records, login, rec, clock, failed, initial, held)
        master = held.master
        registration.current()
        owner.trusted_source(snapshot)
        incoming = '/tmp/labapp-vlab-' + nonce
        master.remote(['/usr/bin/mkdir', '-m', '0700', incoming], 'access')
        guest.exclusive(output / 'marker', nonce.encode())
        master.transfer(incoming, ['marker'], 'access')
        guest.require(master.remote(['/usr/bin/cat', incoming + '/marker'], 'access') == nonce.encode())
        master.remote(['/usr/bin/rm', '--', incoming + '/marker'], 'access')
        phase, held.operation = 'clock-sample', 'clock-sample'
        capsule = guest_clock_capsule(master, clock, initial)
        phase, held.operation = 'program-stage', 'program-stage'
        source, table = stage_program(snapshot, payloads, output, initial, capsule)
        registration.current()
        owner.trusted_source(snapshot)
        held.operation = 'source-transfer'
        master.transfer(incoming, [*sorted(program.FILES), 'manifest.json'])
        registration.current()
        held.operation = 'bootstrap'
        held.attempted = True
        master.remote(bootstrap_command(incoming, source, table), 'stage', cap=60)

        def heartbeat():
            number = 0
            try:
                while not stop.is_set():
                    number += 1
                    master.remote(fixed_command('heartbeat', nonce, number), 'persistence', cap=8,
                                  until=owned_process.monotonic() + owner.HEARTBEAT_BUDGET_SECONDS)
                    stop.wait(10)
            except BaseException as error:
                if getattr(error, 'cleanup_uncertain', False):
                    process_uncertain.set()
                failed.set()
        held.operation = 'heartbeat-start'
        held.thread = threading.Thread(target=heartbeat, daemon=True)
        held.thread.start()
        phase = 'guest-work'
        invalid = 0
        while True:  # observe the guest's ONE worker; the host never executes, retries or reorders a step
            held.operation = 'management-progress'
            guest.require(not failed.is_set(), 'heartbeat failed')
            registration.current()
            owner.trusted_source(snapshot)
            clock.remaining('work')
            state, record = management_result(
                master.remote(fixed_command('result', nonce), 'work', cap=PROGRESS_CAP, limit=4096 + 128), nonce)
            if state != 'valid':
                invalid += 1
                guest.require(invalid < INVALID_POLLS, 'guest result unreadable')
            else:
                invalid = 0
                failure = record['failure']
                if failure is not None:
                    raise guest.Failure('fixed child failed', native_code(failure))
                guest.require(record['teardown'] == 'pending', 'guest ended before the steps finished')
                if all(v == 'ok' for v in record['steps'].values()):
                    break
            stop.wait(PROGRESS_INTERVAL)
        phase = 'guest-browser'
        held.operation = 'viewer-export'
        raw = master.remote(fixed_command('export-viewer', nonce), 'work', cap=EXPORT_CAP, limit=2048)
        program.validate_handoff(guest.data(raw), nonce)
        held.operation = 'browser'
        browser, forward_absent = browser_session(master, clock, nonce, rec['request_id'], raw, private, failed,
                                                  process_uncertain)
        phase = 'guest-result'
        result = 0
    except guest.Failure as error:
        result, category = error.code, 'guest'
        if getattr(error, 'cleanup_uncertain', False):
            process_uncertain.set()
    except KeyboardInterrupt as error:
        result, category = 130, 'interrupted'
        if getattr(error, 'cleanup_uncertain', False):
            process_uncertain.set()
    except Exception as error:
        result, category = 1, 'access' if isinstance(error, AccessError) else 'unknown'
        if getattr(error, 'cleanup_uncertain', False):
            process_uncertain.set()
    finally:
        stop.set()
        heartbeat_absent = True
        if held.thread:
            try:
                held.thread.join(timeout=owner.HEARTBEAT_JOIN_SECONDS)
                heartbeat_absent = not held.thread.is_alive()
            except BaseException:
                heartbeat_absent = False
                process_uncertain.set()
        master = held.master
        process_absent = master is None and heartbeat_absent and not process_uncertain.is_set()
        if master is not None:
            if heartbeat_absent and held.attempted:
                # Fixed cancel request, then the guest's OWN poststop receipt, through the SAME original
                # master. The guest (not the host) performs the serialized cleanup; the host only waits
                # a bounded time and reports a still-pending receipt as unknown.
                try:
                    master.remote(fixed_command('cancel', nonce), 'persistence', cap=CANCEL_CAP, cleanup=True)
                except BaseException as error:
                    if getattr(error, 'cleanup_uncertain', False):
                        process_uncertain.set()
                receipt_until = owned_process.monotonic() + TEARDOWN_CAP
                while True:
                    try:
                        typed_state, typed = management_result(
                            master.remote(fixed_command('result', nonce), 'persistence', cap=RESULT_CAP, cleanup=True,
                                          limit=4096 + 128), nonce)
                    except BaseException as error:
                        typed_state, typed = 'invalid', None
                        if getattr(error, 'cleanup_uncertain', False):
                            process_uncertain.set()
                    if (typed_state == 'valid' and typed['teardown'] != 'pending') \
                            or owned_process.monotonic() >= receipt_until:
                        break
                    time.sleep(PROGRESS_INTERVAL)
                # A native failure first discovered during finalization is reconciled into BOTH the return
                # code and the printed receipt, but never replaces an earlier primary failure. A cancel
                # acknowledgement or a non-pending receipt is not terminal proof of anything.
                if result == 0 and typed_state == 'valid' and typed['failure'] is not None:
                    result, category, phase = native_code(typed['failure']), 'guest', 'guest-result'
                elif result == 0 and typed_state == 'valid' and terminal_code(typed['terminal']):
                    # Finalization-only observation (no earlier primary): all 18 steps may be ok. The separate
                    # typed ``terminal`` record stays visible in the receipt; an earlier primary always wins.
                    result, category, phase = terminal_code(typed['terminal']), 'guest', 'guest-result'
            try:
                process_absent = master.close() and heartbeat_absent and not process_uncertain.is_set()
            except BaseException:
                process_absent = False
        owned = {*program.FILES, 'manifest.json', 'oslogin', 'oslogin.pub', 'known_hosts', 'marker', 'sftp.batch', 'master.sock'}
        local_absent = process_absent
        for name in (owned if process_absent else ()):
            path = output / name
            try:
                info = path.lstat()
                guest.require(info.st_uid == os.geteuid() and not stat.S_ISLNK(info.st_mode) and info.st_nlink == 1
                              and (stat.S_ISREG(info.st_mode) or name == 'master.sock' and stat.S_ISSOCK(info.st_mode)))
                path.unlink()
            except FileNotFoundError:
                pass
            except BaseException:
                local_absent = False
        local_absent = local_absent and not any(output.iterdir())
        if held.context is not None and process_absent and local_absent:
            try:
                cleanup_own_key(records, held.context, login, now=lambda: datetime.now(timezone.utc))
                key_absent = True
            except BaseException:
                pass
        try:
            owner.cleanup_dispatch(snapshot)
            dispatched = True
        except BaseException:
            pass
        receipt = {'schema': 1, 'code': result, 'process_absent': process_absent, 'phase': phase,
                   'failure_category': category, 'host_operation': held.operation, 'own_key_absent': key_absent,
                   'local_files_absent': local_absent, 'independent_cleanup_dispatched': dispatched,
                   'lease': rec['request_id'], 'forward_absent': forward_absent, 'browser': browser,
                   'browser_verified': browser == BROWSER_VERIFIED,
                   'management_status': typed_state, 'management': typed}
        print(json.dumps(receipt, sort_keys=True))
    if result:
        return result
    good = typed_state == 'valid' and program.succeeded(typed) and browser == BROWSER_VERIFIED and forward_absent  # owner-attested never suffices
    return 0 if good and all((process_absent, key_absent, local_absent, dispatched)) else 1


def trial(*_args, **_kwargs):
    """Public surface: refuses before reading anything. Activation is a later reviewed change."""
    program.refuse_activation()


def main(argv=None):
    program.refuse_activation()
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--payloads', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--private-diagnostics', type=Path)
    parser.parse_args(argv)
    return trial()


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise guest.Failure('signal', 143 if signum == signal.SIGTERM else 130)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        exit_code = main()
    except guest.Failure as error:
        print('Management trial held; no activation is authorized.', file=sys.stderr)
        exit_code = error.code
    except Exception:
        print('Management trial failed closed.', file=sys.stderr)
        exit_code = 1
    sys.exit(exit_code)
