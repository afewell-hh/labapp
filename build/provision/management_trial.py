#!/usr/bin/env python3
"""ONE fixed, SOURCE-INACTIVE management guest program (issue #506).

Ubuntu 24.04 amd64 Python 3.12, root, native k3d/Helm/kubectl/Grafana/Prometheus APIs only.
This module is a closed table of steps, not a command loader: the host names a step from
``STEP_NAMES`` and nothing else (no path, argv, script or command selector exists). It reuses
the original VLAB primitives (Failure, contract, Clock rules, private file helpers, bounded
child runner) from the unchanged ``vlab_trial`` sibling and never weakens them.

Activation is HELD. ``refuse_activation`` always raises while ``ACTIVATION_BLOCKERS`` is
non-empty; no flag, environment value or argument bypasses it, and source code does not record
any approval. Importing this module performs no IO or privileged action.

Lifetime ownership (issue #508, SOURCE-INACTIVE): three FIXED units (guardian service, boot-monotonic
expiry timer, expiry stop service; see ``UNIT_NAMES``) own ONE worker that runs all 18 steps with one
Context. The caller supplies an immutable authenticated clock capsule (``build_capsule`` /
``validate_capsule``). Every number below is explicit source policy, not measured systemd behavior.

Per-step supervision (unchanged from #506; no generic controller exists). Every step
re-checks contract, boot, heartbeat freshness and the management clock before each child, and
``stdin_bounded`` re-runs that same gate on every <=0.1s tick while a child is live, so heartbeat
loss, boot change, phase cutoff, deadline, interruption or cancel kill the child's exact process
group through ``owned_process`` before reaping its leader, including after clean exit. Positive
group absence is required; uncertainty is retained on the failure and in private teardown state.
Teardown children honor only the immutable 60-minute ceiling. An orphan left by SIGKILL of the
step runner itself is still bounded only by lease/VM expiry. Nothing here ever claims ``contained``.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

try:  # package import (host tests); plain sibling import (guest script / provision tests)
    from . import vlab_trial as base
    from . import owned_process
except ImportError:
    import vlab_trial as base
    import owned_process

MROOT = Path('/var/lib/labapp-management-trial')
WORK = MROOT / 'work'
STORAGE = Path('/var/lib/labapp/management-storage')
KUBECONFIG = WORK / 'kubeconfig'
CLUSTER, CONTEXT, NAMESPACE = 'labapp-mgmt', 'k3d-labapp-mgmt', 'monitoring'
SECRET, RELEASE = 'labapp-grafana-admin', 'kube-prometheus-stack'
KUBECTL, HELM, K3D = '/usr/local/bin/kubectl', '/usr/local/bin/helm', '/usr/local/bin/k3d'
SYSTEMCTL, PYTHON, BASH, DOCKER = '/usr/bin/systemctl', '/usr/bin/python3', '/usr/bin/bash', '/usr/bin/docker'
PROMETHEUS_URL, GRAFANA_URL = 'http://127.0.0.1:9090', 'http://127.0.0.1:3000'
BIND_ADDRESS = '127.0.0.1'  # guest loopback only; no host/switch/Alloy reachability is tested

# ---- Time model -------------------------------------------------------------------------
# Offsets in minutes from durable ADMISSION (never from process start, never renewed). Work
# phases end at 54; the 60-minute CEILING (work+cleanup) leaves a six-minute cleanup reserve that
# failed or slow work cannot consume. Every value is additionally clipped to the unchanged
# provider lease (admission+7200s deadline, VLAB persistence cutoff). The provider envelope is
# NOT changed here: ``base.contract`` still requires exactly 7200 seconds, and running a
# 60-minute component inside it is an unresolved owner/runtime decision (ACTIVATION_BLOCKERS).
MGMT_PHASES = {'access': 15, 'stage': 30, 'work': 37, 'persistence': 38}
CEILING_MINUTES = 60
PROVIDER_ENVELOPE_SECONDS = 7200
# #508 SOURCE budget (explicit policy, not measured runtime). Five systemd stop intervals of
# TimeoutStopSec plus timer/dispatch allowance and slack must fit between the fixed expiry E and the
# 60-minute ceiling D: E <= D - (5T + J + 60) = D - 1320s = admission + 38 minutes.
STOP_TIMEOUT_SECONDS = 240      # T: TimeoutStopSec of the guardian unit
STOP_JITTER_SECONDS = 60        # J: timer accuracy/dispatch/stop-request allowance
EXTRA_SLACK_SECONDS = 60
STOP_INTERVALS = 5
EXPIRY_RESERVE_SECONDS = STOP_INTERVALS * STOP_TIMEOUT_SECONDS + STOP_JITTER_SECONDS + EXTRA_SLACK_SECONDS
assert EXPIRY_RESERVE_SECONDS == 1320
assert MGMT_PHASES['persistence'] * 60 == CEILING_MINUTES * 60 - EXPIRY_RESERVE_SECONDS
POSTSTOP_OUTER_SECONDS = STOP_TIMEOUT_SECONDS - 5   # ONE outer deadline for ALL poststop work
ABSENCE_SECONDS = 20
# Initial guest clock correlation: FAIL-CLOSED policy limits, not NTP/performance measurements.
CLOCK_ROUNDTRIP_MAX = 10
CLOCK_SKEW_MAX = 5
CLOCK_SAFETY_SECONDS = 5
CAPSULE_MAX_AGE = 300
PHASE_MINUTES = dict(MGMT_PHASES, ceiling=CEILING_MINUTES)

GUARDIAN_UNIT = 'labapp-management-trial.service'
TIMER_UNIT = 'labapp-management-expiry.timer'
STOP_UNIT = 'labapp-management-expiry.service'
UNIT_NAMES = (GUARDIAN_UNIT, TIMER_UNIT, STOP_UNIT)
UNIT_DIR = Path('/etc/systemd/system')
RUNTIME_DIR = Path('/run/systemd/system')
CGROUP_DIR = Path('/sys/fs/cgroup/system.slice') / GUARDIAN_UNIT   # the guardian cgroup AND its descendants
CGROUP_PROCS = CGROUP_DIR / 'cgroup.procs'
DAEMON_UNITS = ('docker.socket', 'docker.service', 'containerd.service')
DAEMON_CGROUPS = tuple(Path('/sys/fs/cgroup/system.slice') / name for name in DAEMON_UNITS[1:])
# Fixed guest clock sample program. Its digest is bound into the capsule; it is not a command loader.
SAMPLE_STUB = (
    "import json,sys,time\n"
    "b=open('/proc/sys/kernel/random/boot_id').read().strip()\n"
    "print(json.dumps({'boot':b,'nonce':sys.argv[1],'wall':time.time(),'mono':time.monotonic()},sort_keys=True))\n")

ACTIVATION_BLOCKERS = (
    'provider-envelope-7200s-versus-60-minute-component-decision',
    'artifact-egress-and-image-inventory-unresolved',
    'viewer-dashboard-runtime-discovery-unobserved',
    'private-viewer-handoff-and-browser-forward-review',
    'no-authorized-verified-browser-observer',
    'native-systemd-guardian-timer-and-clock-capsule-runtime-behavior-unobserved',
    'poststop-all-work-deadline-unenforceable-for-uninterruptible-filesystem-calls-in-process',
    'quota-shape-budget-unresolved',
    'reviewed-activation-and-separate-experiment-authorization',
)


def refuse_activation():
    """Fixed refusal; the message never varies and nothing can disable it."""
    raise base.Failure('management activation held', 1, 'policy')


# ---- Fixed source and payload tables ---------------------------------------------------------
SOURCES = {name: 'build/provision/' + name for name in (
    'management_trial.py', 'vlab_trial.py', 'hhfab_release.py', 'owned_process.py',
    'install-docker.py', 'install-kubectl.py', 'install-helm.py', 'install-k3d.sh',
    'management-cluster.yaml', 'management-observability-values.yaml', 'observability-values.yaml',
    *UNIT_NAMES)}
# Binary acquisition table. kubectl reuses the VLAB pin object. Helm client archive and the
# chart package repeat the accepted install-helm.py / observability-inputs.yaml pins (a test
# guards drift; no second independent ledger). k3d is NOT a host payload: install-k3d.sh pins
# only the sha256 (no size is pinned anywhere) and downloads from upstream at runtime, so it is
# an actual future egress and inventory item, never a verified byte count.
PAYLOADS = {
    'kubectl': base.PAYLOADS['kubectl'],
    'helm.tar.gz': (18014603, '759c656fbd9c11e6a47784ecbeac6ad1eb16a9e76d202e51163ab78504848862'),
    'kube-prometheus-stack-65.2.0.tgz': (591234, 'fa80a64847ba4e59224554ef57a3d243088d43375a75caffbd4592e34f3923e7'),
}
FILES = {*SOURCES, *PAYLOADS, 'contract.json', 'capsule.json'}
ARTIFACT_INVENTORY = {
    'host-payloads': tuple(sorted(PAYLOADS)),
    'runtime-download-sha-only': ('k3d v5.7.4 binary via install-k3d.sh (size unpinned)',),
    'installer-egress-unresolved': ('install-docker.py package sources', 'upstream k3d release host'),
}
MANAGEMENT_IMAGE = 'docker.io/rancher/k3s@sha256:81fc7349ba265f842f9b67311fabd9e7d72698798ba513b7cdf41ffdf1e923e4'
# EXPERIMENTAL candidate only; not a maintained/release selection, signature or compatibility claim.
IMAGE_INVENTORY = {
    'k3s-server': MANAGEMENT_IMAGE,
    'persistence-init': 'busybox:1.31.1 (chart-declared tag, no digest pinned here)',
    'k3d-loadbalancer': None,
    'k3d-tools': None,
    'chart-and-k3s-internal-images': None,
}  # None = unresolved runtime preflight; K3D_IMAGE_* overrides are not a security closure
MAX_TOTAL = base.MAX_TOTAL

# ---- Closed step table and typed result -----------------------------------------------------
STEPS = (
    ('install-docker', 'stage'), ('install-kubectl', 'stage'), ('install-helm', 'stage'),
    ('install-k3d', 'stage'), ('daemon-start', 'stage'),
    ('storage', 'work'), ('cluster', 'work'), ('namespace', 'work'), ('secret', 'work'),
    ('helm', 'work'), ('health', 'work'), ('probe-push', 'work'), ('probe-read', 'work'),
    ('principal', 'work'), ('restart', 'work'), ('historical', 'work'),
    ('persisted-principal', 'work'), ('viewer-ready', 'work'))
STEP_NAMES = tuple(name for name, _ in STEPS)
STEP_PHASE = dict(STEPS)
OBSERVED = {  # closed boolean observations -> the step that produces them
    'storage_new': 'storage', 'cluster_context': 'cluster', 'secret_private': 'secret',
    'pvc_bound': 'health', 'workloads_ready': 'health', 'probe_pushed': 'probe-push',
    'probe_fresh': 'probe-read', 'unused_nonce_empty': 'probe-read', 'repeat_reads_stable': 'probe-read',
    'principal_viewer': 'principal', 'prometheus_restarted': 'restart', 'grafana_restarted': 'restart',
    'pvc_uid_unchanged': 'restart', 'historical_sample': 'historical',
    'principal_persisted': 'persisted-principal', 'viewer_handoff_ready': 'viewer-ready'}
STEP_STATES = ('ok', 'failed', 'not-run')
TEARDOWN_STATES = ('pending', 'complete', 'uncertain')
RESULT_SCHEMA = 2  # management result contract v2: adds the closed ``terminal`` evidence object (#510)
RESULT_FIELDS = {'schema', 'nonce', 'steps', 'failure', 'observed', 'teardown', 'terminal'}
# Closed, nonsecret terminal evidence of the ONE worker, independent of the ordered steps and of the
# primary ``failure``. ``status`` is the worker's observed exit (0..255) or raw negative signal, else None.
# ``origin``: 'pre-close' = a non-reaping look BEFORE the closure transition could signal anything;
# 'closure-window' = read from the unchanged OwnedGroup after its sole close (a positive value is an
# observed terminal status but NOT proof it preceded cleanup signals; a negative one may be our own
# closure's signal); 'unobserved' = nothing known. ``group`` is 'closure-reported' only when the guardian
# recorded a positive close AND worker absence held, else 'uncertain' (sticky). Neither is verified success.
TERMINAL_FIELDS = {'status', 'origin', 'group'}
TERMINAL_ORIGINS = ('pre-close', 'closure-window', 'unobserved')
TERMINAL_GROUPS = ('closure-reported', 'uncertain')


def terminal_status_ok(status):
    return type(status) is int and (0 <= status <= 255 or -64 <= status <= -1)


def initial_terminal():
    return {'status': None, 'origin': 'unobserved', 'group': 'uncertain'}


def terminal_ok(value):
    if not (type(value) is dict and set(value) == TERMINAL_FIELDS
            and type(value['origin']) is str and value['origin'] in TERMINAL_ORIGINS
            and type(value['group']) is str and value['group'] in TERMINAL_GROUPS):
        return False
    if value['origin'] == 'unobserved':
        return value['status'] is None
    return terminal_status_ok(value['status'])
PRIVATE_FILES = ('grafana-admin-user', 'grafana-admin-password', 'viewer.json', 'viewer-handoff.json', 'kubeconfig')

# Synthetic-probe vocabulary: a TEST receiver sample, not Alloy, target-page or course proof.
PROBE_METRIC = 'labapp_management_trial_probe'
PROBE_FRESH_SECONDS = 120
QUERY_TIMEOUT = 5
HTTP_LIMIT = 262144
# Existing chart dashboard, read from the RAW pinned source (prometheus-community/helm-charts
# 05fcb4c0, kube-prometheus-stack/templates/grafana/dashboards-1.14/prometheus.yaml; read through a
# summarising fetch, so the constants are qualified until the lead re-reads the bytes): title
# "Prometheus / Overview", tag "prometheus-mixin", uid "" (Grafana assigns the UID at runtime), panel
# id 7 "Head Series", type graph, datasource "$datasource" from a template variable of type
# datasource / query prometheus. The runtime UID is DISCOVERED as the Viewer, never pinned. Viewer
# Explore, editing and ViewersCanEdit are not used. Runtime behavior is unobserved.
VIEWER_DASHBOARD = {'title': 'Prometheus / Overview', 'tag': 'prometheus-mixin', 'panel_id': 7,
                    'panel_title': 'Head Series', 'panel_types': ('graph', 'timeseries'),
                    'datasource_variable': 'datasource', 'datasource_type': 'prometheus'}
VIEWER_LOGIN = r'labapp-viewer-[a-f0-9]{6}'
VIEWER_PASSWORD = r'[A-Za-z0-9_-]{16,64}'
HANDOFF_FIELDS = {'schema', 'nonce', 'login', 'password', 'path', 'port'}
HANDOFF_PATH = r'/d/[A-Za-z0-9_-]{1,40}\?viewPanel=[0-9]{1,6}'
GRAFANA_PORT = 3000


def manifest(value):
    base.require(type(value) is dict and set(value) == {'schema', 'source_sha', 'files'}
                 and value['schema'] == 1 and re.fullmatch('[a-f0-9]{40}', value['source_sha']))
    base.require(type(value['files']) is dict and set(value['files']) == FILES)
    total = 0
    for name, item in value['files'].items():
        base.require(type(item) is dict and set(item) == {'bytes', 'sha256'}
                     and type(item['bytes']) is int and item['bytes'] > 0
                     and re.fullmatch('[a-f0-9]{64}', item['sha256']))
        base.require(item['bytes'] <= (PAYLOADS[name][0] if name in PAYLOADS else base.MAX_SOURCE))
        if name in PAYLOADS:
            base.require((item['bytes'], item['sha256']) == PAYLOADS[name], 'tool bytes refused')
        total += item['bytes']
    base.require(total <= MAX_TOTAL)
    return value


class ManagementClock(base.Clock):
    """Admission-anchored wall AND monotonic bounds; clips to the unchanged lease, never renews.

    With an immutable ``capsule`` (#508) every phase is additionally bounded by the capsule's absolute
    guest CLOCK_MONOTONIC cutoff, so a fresh process, a guest wall rollback or a restart can never renew
    time, and a guest forward wall jump can only shorten it (the wall term is still evaluated).
    Without a capsule only the legacy per-process bounds apply (synthetic/internal use only).
    """
    def __init__(self, value, wall=time.time, mono=time.monotonic, capsule=None):
        super().__init__(value, wall, mono)
        self.capsule = capsule

    def _end(self, minutes):
        admitted = base.stamp(self.value['admitted_at'])
        return min(admitted + minutes * 60, base.phase_end(self.value, 'persistence'),
                   base.stamp(self.value['deadline']))

    def _left(self, end):
        return min(end - self.wall(), end - self.started_wall - (self.mono() - self.started_mono))

    def left_at(self, minutes, wall, mono):
        """Remaining seconds to a cutoff at EXPLICIT original-clock readings (caller response time)."""
        end = self._end(minutes)
        return min(end - wall, end - self.started_wall - (mono - self.started_mono))

    def _capsule_left(self, key):
        return float('inf') if self.capsule is None else self.capsule['cutoffs'][key] - self.mono()

    def remaining(self, phase):
        base.require(phase in MGMT_PHASES, 'unknown management phase')
        left = min(self._left(self._end(MGMT_PHASES[phase])), self._capsule_left(phase))
        if left <= 0:
            raise base.Failure('absolute phase cutoff', 124, 'phase-cutoff')
        return left

    def cleanup_remaining(self):
        left = min(self._left(self._end(CEILING_MINUTES)), self._capsule_left('ceiling'))
        if left <= 0:
            raise base.Failure('immutable cleanup cutoff', 124, 'phase-cutoff')
        return left


# ---- Authenticated guest clock capsule (#508) -------------------------------------------------------
CAPSULE_COPIED = ('nonce', 'lease', 'epoch', 'run_id', 'attempt', 'body_sha256', 'vm_id', 'boot_id',
                  'source_sha', 'boot_uuid', 'admitted_at', 'deadline')
CAPSULE_FIELDS = {'schema', 'stub_sha256', 'sample', 'caller', 'safety', 'left', 'cutoffs', *CAPSULE_COPIED}
SAMPLE_FIELDS = {'boot', 'nonce', 'wall', 'mono'}
CALLER_FIELDS = {'send_wall', 'recv_wall', 'send_eff', 'recv_eff', 'roundtrip'}


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def sample_valid(sample, contract, sample_nonce):
    """Strict guest sample: bound to boot and the one-shot sample nonce; finite non-negative clocks."""
    base.require(type(sample) is dict and set(sample) == SAMPLE_FIELDS, 'clock sample refused')
    base.require(sample['boot'] == contract['boot_uuid'] and type(sample_nonce) is str and sample['nonce'] == sample_nonce
                 and re.fullmatch('[a-f0-9]{32}', sample_nonce) is not None, 'clock sample refused')
    base.require(_number(sample['wall']) and _number(sample['mono']) and sample['wall'] > 0 and sample['mono'] > 0,
                 'clock sample refused')
    return sample


def build_capsule(contract, clock, sample, sample_nonce, send, receive):
    """Caller side: map each cutoff conservatively onto the returned guest monotonic sample.

    ``send``/``receive`` are (wall, monotonic) readings of the caller's ONCE-retained original clock
    taken immediately before the request and at RESPONSE reception. The remaining time of every
    cutoff is computed at reception from that clock and subtracted from nothing else: the round trip
    is never added back (the guest sample was taken earlier, so its true remaining time is at least
    this) and a fixed safety allowance is subtracted. Limits are fail-closed policy, not measurements.
    """
    (send_wall, send_mono), (recv_wall, recv_mono) = send, receive
    base.require(all(_number(x) for x in (send_wall, send_mono, recv_wall, recv_mono)), 'clock readings refused')
    sample = sample_valid(sample, contract, sample_nonce)
    roundtrip = recv_mono - send_mono
    base.require(0 <= roundtrip <= CLOCK_ROUNDTRIP_MAX and recv_wall >= send_wall, 'clock round trip refused')
    # The ORIGINAL effective clock (admission-anchored, monotonic-derived) brackets the sample; the raw
    # caller wall is only a cross-check, so a caller wall rollback or jump cannot widen the correlation.
    send_eff = clock.started_wall + (send_mono - clock.started_mono)
    recv_eff = clock.started_wall + (recv_mono - clock.started_mono)
    base.require(abs(send_wall - send_eff) <= CLOCK_SKEW_MAX and abs(recv_wall - recv_eff) <= CLOCK_SKEW_MAX,
                 'caller wall differs from the original effective clock')
    base.require(send_eff - CLOCK_SKEW_MAX <= sample['wall'] <= recv_eff + CLOCK_SKEW_MAX, 'guest clock skew refused')
    left = {key: clock.left_at(minutes, recv_wall, recv_mono) for key, minutes in PHASE_MINUTES.items()}
    cutoffs = {key: sample['mono'] + seconds - CLOCK_SAFETY_SECONDS for key, seconds in left.items()}
    capsule = {'schema': 1, 'stub_sha256': base.sha(SAMPLE_STUB.encode()), 'sample': dict(sample),
               'caller': {'send_wall': send_wall, 'recv_wall': recv_wall, 'send_eff': send_eff,
                          'recv_eff': recv_eff, 'roundtrip': roundtrip},
               'safety': CLOCK_SAFETY_SECONDS, 'left': left, 'cutoffs': cutoffs,
               **{key: contract[key] for key in CAPSULE_COPIED}}
    return validate_capsule(capsule, contract)


def validate_capsule(value, contract, now=None):
    """Strict closed validator. ``now`` = (guest wall, guest monotonic) is given ONLY by the one-shot
    bootstrap, which then also refuses late/skewed/stale samples; later loads re-validate bindings and
    ordering but cannot renew anything because every cutoff is an absolute boot-monotonic value."""
    base.require(type(value) is dict and set(value) == CAPSULE_FIELDS and value['schema'] == 1
                 and type(value['schema']) is int, 'capsule refused')
    for key in CAPSULE_COPIED:
        base.require(type(value[key]) is type(contract[key]) and value[key] == contract[key], 'capsule binding differs')
    base.require(value['stub_sha256'] == base.sha(SAMPLE_STUB.encode()) and value['safety'] == CLOCK_SAFETY_SECONDS
                 and type(value['safety']) is int, 'capsule refused')
    sample = sample_valid(value['sample'], contract, value['sample'].get('nonce') if type(value['sample']) is dict else None)
    caller, left, cutoffs = value['caller'], value['left'], value['cutoffs']
    base.require(type(caller) is dict and set(caller) == CALLER_FIELDS and all(_number(v) for v in caller.values())
                 and 0 <= caller['roundtrip'] <= CLOCK_ROUNDTRIP_MAX and caller['recv_wall'] >= caller['send_wall']
                 and abs(caller['send_wall'] - caller['send_eff']) <= CLOCK_SKEW_MAX
                 and abs(caller['recv_wall'] - caller['recv_eff']) <= CLOCK_SKEW_MAX
                 and abs((caller['recv_eff'] - caller['send_eff']) - caller['roundtrip']) <= 1e-6
                 and caller['send_eff'] - CLOCK_SKEW_MAX <= sample['wall'] <= caller['recv_eff'] + CLOCK_SKEW_MAX,
                 'capsule clock bracket refused')
    base.require(type(left) is dict and type(cutoffs) is dict and set(left) == set(cutoffs) == set(PHASE_MINUTES)
                 and all(_number(v) for v in (*left.values(), *cutoffs.values())), 'capsule cutoffs refused')
    for key in PHASE_MINUTES:
        base.require(abs(cutoffs[key] - (sample['mono'] + left[key] - CLOCK_SAFETY_SECONDS)) <= 1e-6,
                     'capsule cutoff mapping differs')
    order = [cutoffs[key] for key in ('access', 'stage', 'work', 'persistence', 'ceiling')]
    base.require(sample['mono'] < order[0] and order == sorted(order), 'capsule cutoff order refused')
    base.require(cutoffs['ceiling'] - cutoffs['persistence'] >= EXPIRY_RESERVE_SECONDS - 1e-3,
                 'capsule expiry reserve refused')
    if now is not None:
        wall_now, mono_now = now
        base.require(_number(wall_now) and _number(mono_now) and sample['mono'] <= mono_now
                     <= sample['mono'] + CAPSULE_MAX_AGE, 'capsule sample stale or from the future')
        base.require(abs((wall_now - sample['wall']) - (mono_now - sample['mono'])) <= CLOCK_SKEW_MAX,
                     'guest wall clock moved since the sample')
    return value


def load_capsule(value):
    """Immutable root-private capsule bound to this contract; a missing capsule NEVER falls back."""
    return validate_capsule(base.data(base.regular(MROOT / 'capsule.json', base.MAX_SOURCE, 0, 0o600)), value)


def production_clock(value):
    return ManagementClock(value, capsule=load_capsule(value))


# ---- Private state ------------------------------------------------------------------------------
def contract_value(nonce):
    value = base.contract(base.data(base.regular(MROOT / 'contract.json', base.MAX_SOURCE, 0)))
    base.require(type(nonce) is str and nonce == value['nonce'])
    return value


def contract_any():
    """Unit entrypoints carry no argument: the root-private contract is the sole nonce source."""
    return base.contract(base.data(base.regular(MROOT / 'contract.json', base.MAX_SOURCE, 0)))


def initial_state(nonce):
    return {'schema': RESULT_SCHEMA, 'nonce': nonce, 'steps': {n: 'not-run' for n in STEP_NAMES}, 'failure': None,
            'observed': {k: False for k in OBSERVED}, 'teardown': 'pending', 'terminal': initial_terminal(),
            'private': {}}


def load_state(nonce):
    state = base.data(base.regular(MROOT / 'steps.json', 65536, 0))
    base.require(type(state) is dict and set(state) == {*RESULT_FIELDS, 'private'} and state['nonce'] == nonce
                 and type(state['private']) is dict)
    return state


def present(path):
    """Strict observation: False ONLY for a genuine FileNotFoundError. Any other lstat error (EACCES, EIO,
    ENOTDIR, ...) raises, so an unobservable path is unknown and is never read as absent."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def durable_atomic(path, value):
    """Management-local durable publication: file fsync + rename (``base.atomic``, unchanged) THEN the
    parent directory fsync, so a published record survives a crash before any effect depends on it."""
    base.atomic(path, value)
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


POSTSTOP_CLAIM = 'poststop.json'
RELEASE_OPEN, RELEASE_CLOSED, CANCEL_MARK = 'release.json', 'release-closed.json', 'cancel.json'


class state_lock:
    """Advisory flock serializing every steps.json writer (worker, poststop) for a bounded time."""
    def __init__(self, seconds=5.0):
        self.until, self.fd = time.monotonic() + seconds, None

    def __enter__(self):
        fd = os.open(base.no_links(MROOT / 'state.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    base.require(time.monotonic() < self.until, 'state lock unavailable', 'child-timeout')
                    time.sleep(.01)
        except BaseException:
            os.close(fd)
            raise
        self.fd = fd
        return self

    def __exit__(self, *_exc):
        os.close(self.fd)  # closing the descriptor releases the lock


def save_state(state, *, poststop=False, until=None, durable=False):
    """Single-writer discipline: the worker writes until poststop CLAIMS the state under the same lock
    (exclusive poststop.json); afterwards worker writes are refused and only poststop may write.
    A ``complete`` receipt is NEVER published: the timeliness of the fsync/rename that would publish it
    cannot be proven in-process (ACTIVATION_BLOCKERS), so it is written as ``uncertain``. ``durable``
    also fsyncs the parent directory (used before an effect that depends on the record)."""
    with state_lock() if until is None else state_lock(max(.1, min(5.0, until - time.monotonic()))):
        claimed = present(MROOT / POSTSTOP_CLAIM)
        base.require(claimed == poststop, 'state writer superseded')
        if state['teardown'] == 'complete':
            state['teardown'] = 'uncertain'
        (durable_atomic if durable else base.atomic)(MROOT / 'steps.json', state)


def public_record(state):
    return {k: state[k] for k in RESULT_FIELDS}


def validate_result(value, nonce):
    """Closed strict validator for the nonsecret typed result (host and guest share it)."""
    base.require(type(value) is dict and set(value) == RESULT_FIELDS, 'result refused')
    base.require(type(value['schema']) is int and value['schema'] == RESULT_SCHEMA and value['nonce'] == nonce
                 and type(value['teardown']) is str and value['teardown'] in TEARDOWN_STATES
                 and terminal_ok(value['terminal']), 'result refused')
    steps, observed, failure = value['steps'], value['observed'], value['failure']
    base.require(type(steps) is dict and set(steps) == set(STEP_NAMES)
                 and all(type(v) is str and v in STEP_STATES for v in steps.values()), 'result refused')
    base.require(type(observed) is dict and set(observed) == set(OBSERVED)
                 and all(type(v) is bool for v in observed.values()), 'result refused')
    seen_failed = False
    for name in STEP_NAMES:
        state = steps[name]
        base.require(not (seen_failed and state != 'not-run'), 'result refused')  # stop at first failure
        base.require(state != 'ok' or all(steps[n] == 'ok' for n in STEP_NAMES[:STEP_NAMES.index(name)]),
                     'result refused')
        seen_failed = seen_failed or state == 'failed'
    for key, producer in OBSERVED.items():
        base.require(not observed[key] or steps[producer] != 'not-run', 'result refused')
    if seen_failed:
        base.require(type(failure) is dict and set(failure) == {'step', 'category', 'child_status'}
                     and type(failure['step']) is str and steps.get(failure['step']) == 'failed'
                     and type(failure['category']) is str and failure['category'] in base.CATEGORIES
                     and failure['category'] != 'none'
                     and base.child_status_ok(failure['category'], failure['child_status']), 'result refused')
    else:
        base.require(failure is None, 'result refused')
    return {k: value[k] for k in RESULT_FIELDS}


def succeeded(record):
    return (all(v == 'ok' for v in record['steps'].values()) and record['failure'] is None
            and record['teardown'] == 'complete' and all(record['observed'].values())
            and record['terminal']['status'] in (None, 0))  # an observed nonzero terminal status is never success


def failure_record(step, error):
    category, status = 'exception', None
    if isinstance(error, base.Failure) and error.category in base.CATEGORIES and error.category != 'none' \
            and base.child_status_ok(error.category, error.child_status):
        category, status = error.category, error.child_status
    elif isinstance(error, KeyboardInterrupt):
        category = 'interrupted'
    return {'step': step, 'category': category, 'child_status': status}


# ---- Bounded process and API helpers -----------------------------------------------------------
def tool_env(extra=None):
    env = dict(base.ENV, HOME=str(WORK / 'home'), HELM_CACHE_HOME=str(WORK / 'helm-cache'),
               HELM_CONFIG_HOME=str(WORK / 'helm-config'), HELM_DATA_HOME=str(WORK / 'helm-data'))
    if extra:
        env.update(extra)
    return env  # never KUBECONFIG: every kubectl/helm call names the private file explicitly


def stdin_bounded(argv, seconds, data, env, limit=1024**2, watch=None):
    """ONE supervised child: bounded stdin/output/time plus continuous ``watch`` while it is live.

    ``watch`` (the fixed gate from ``run_tool``) runs on every poll tick (<=0.1s), during output
    reads AND while waiting for exit. Whatever it raises (heartbeat/owner loss, boot change, phase
    or cleanup cutoff) or any interruption/cancel requests group closure while the leader remains
    unreaped. The accepted ownership helper is the sole reaper; failed absence proof propagates
    cleanup uncertainty, including when another failure is primary. Closure also follows clean exit.
    """
    base.require(type(data) is bytes and len(data) <= 4096)
    finish = time.monotonic() + seconds
    deadline = finish - min(owned_process.CLEANUP_SECONDS, seconds / 2)
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env=env, start_new_session=True)
    group = owned_process.OwnedGroup(proc)
    primary = observed_failure = None
    try:
        try:
            proc.stdin.write(data)
            proc.stdin.close()
        except BrokenPipeError:
            pass  # child exited before reading; its exit status is judged below
        output = bytearray()
        os.set_blocking(proc.stdout.fileno(), False)
        with selectors.DefaultSelector() as select:
            select.register(proc.stdout, selectors.EVENT_READ)
            while select.get_map():
                if watch is not None:
                    watch()
                left = deadline - time.monotonic()
                if left <= 0:
                    raise base.Failure('bounded child failed', 124, 'child-timeout')
                for key, _ in select.select(min(left, .1)):
                    try:
                        block = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not block:
                        select.unregister(key.fileobj)
                        continue
                    if len(output) + len(block) > limit:
                        raise base.Failure('bounded child failed', 1, 'output-overflow')
                    output.extend(block)
        while True:
            if watch is not None:
                watch()
            left = deadline - time.monotonic()
            if left <= 0:
                raise base.Failure('bounded child failed', 124, 'child-timeout')
            code = group.status()
            if code is not None:
                if code:
                    observed_failure = base.child_failure(code, 'fixed child failed')
                break
            time.sleep(min(left, .01))
        return code, bytes(output)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            closed = group.close(0, until=finish)
        except BaseException:
            closed = False
        for pipe in (proc.stdin, proc.stdout):
            try:
                pipe.close()
            except BaseException:
                pass
        if not closed:
            failure = primary if primary is not None else observed_failure
            if failure is None:
                failure = base.Failure('owned child teardown uncertain', 1, 'exception')
            failure.cleanup_uncertain = True
            if primary is None:
                raise failure


def watcher(ctx, phase, cleanup):
    """Fixed continuous gate for a live child. Cleanup honors only the immutable ceiling: host,
    heartbeat or phase loss must never stop teardown itself."""
    if cleanup:
        return lambda: ctx.clock.cleanup_remaining()

    def watch():
        gate(ctx.value, ctx.clock).remaining(phase)
    return watch


class Context:
    def __init__(self, value, clock, state):
        self.value, self.state = value, state
        self.clock = clock if clock is not None else ManagementClock(value)
        self.private = state['private']
        self.poll_deadlines = []

    def poll_remaining(self):
        left = min(self.poll_deadlines) - time.monotonic() if self.poll_deadlines else float('inf')
        base.require(left > 0, 'bounded wait elapsed', 'child-timeout')
        return left

    def observe(self, key):
        self.state['observed'][key] = True


def heartbeat_fresh():
    beat = base.data(base.regular(MROOT / 'heartbeat.json', 4096, 0))
    base.require(0 <= time.monotonic() - beat['received'] <= 30, 'heartbeat lost', 'heartbeat-loss')


def gate(value, clock=None):
    """Contract, boot, heartbeat and management clock; evaluated before every step and child."""
    base.require(base.kernel_boot() == value['boot_uuid'], 'boot changed', 'boot-change')
    heartbeat_fresh()
    if clock is not None:
        base.require(clock.value == value, 'clock contract differs')
        return clock
    return ManagementClock(value)


def run_tool(ctx, argv, phase, cap, *, data=None, env=None, cleanup=False):
    """ONE bounded child. Re-checks the gate; the cap is clipped to the remaining phase/cleanup time."""
    clock = gate(ctx.value, ctx.clock) if not cleanup else ctx.clock
    seconds = min(cap, clock.cleanup_remaining() if cleanup else clock.remaining(phase), ctx.poll_remaining())
    args = [str(a) for a in argv]
    environment = env if env is not None else tool_env()
    # Every child is supervised continuously (heartbeat/boot/clock on each tick), with or without stdin.
    code, out = stdin_bounded(args, seconds, data or b'', environment, watch=watcher(ctx, phase, cleanup))
    if code:
        raise base.child_failure(code, 'fixed child failed')
    return out


def kubectl(ctx, args, cap=60, data=None, phase='work'):
    # Explicit private kubeconfig AND context on every command; no global kubeconfig is read or written.
    return run_tool(ctx, [KUBECTL, '--kubeconfig', KUBECONFIG, '--context', CONTEXT, *args], phase, cap, data=data)


def kget(ctx, resource, *extra):
    return base.data(kubectl(ctx, ['--namespace', NAMESPACE, 'get', resource, *extra, '--output', 'json']))


def http(method, url, *, auth=None, body=None, timeout=QUERY_TIMEOUT):
    """Loopback-only bounded HTTP. Response bodies of failures are never read or reported."""
    base.require(url.startswith((PROMETHEUS_URL + '/', GRAFANA_URL + '/')), 'endpoint refused')
    base.require(0 < timeout <= QUERY_TIMEOUT, 'HTTP timeout refused')
    headers = {'Accept': 'application/json'}
    payload = None
    if body is not None:
        payload = base.encoded(body)
        headers['Content-Type'] = 'application/json'
    if auth is not None:
        headers['Authorization'] = 'Basic ' + base64.b64encode((auth[0] + ':' + auth[1]).encode()).decode()
    request = urllib.request.Request(url, data=payload, method=method, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(HTTP_LIMIT + 1)
            status = response.status
    except urllib.error.HTTPError as error:
        error.close()
        return error.code, b''
    except (urllib.error.URLError, OSError):
        raise base.Failure('endpoint unavailable', 1, 'capability') from None
    base.require(len(raw) <= HTTP_LIMIT, 'response bound', 'output-overflow')
    return status, raw


def prom(ctx, query, at=None):
    """Prometheus instant query -> data dict. HTTP/status errors RAISE; an empty result is success."""
    ctx_gate(ctx)
    params = {'query': query}
    if at is not None:
        params['time'] = '%.3f' % at
    status, raw = http('GET', PROMETHEUS_URL + '/api/v1/query?' + urllib.parse.urlencode(params),
                       timeout=min(QUERY_TIMEOUT, ctx.poll_remaining()))
    base.require(status == 200, 'query error', 'status-invalid')
    body = base.data(raw)
    base.require(type(body) is dict and body.get('status') == 'success' and type(body.get('data')) is dict
                 and type(body['data'].get('result')) is list, 'query error', 'status-invalid')
    return body['data']


def ctx_gate(ctx):
    gate(ctx.value, ctx.clock).remaining('work')
    ctx.poll_remaining()


def grafana(ctx, method, path, auth, body=None):
    ctx_gate(ctx)
    status, raw = http(method, GRAFANA_URL + path, auth=auth, body=body,
                       timeout=min(QUERY_TIMEOUT, ctx.poll_remaining()))
    return status, (base.data(raw) if raw else None)


def private_text(name, limit=256):
    return base.regular(WORK / name, limit, 0, 0o600).decode()


def admin_auth():
    return private_text('grafana-admin-user'), private_text('grafana-admin-password')


def poll(ctx, phase, seconds, attempt):
    """Bounded retry under the original clock; ``attempt`` returns a truthy value when finished."""
    end = time.monotonic() + seconds
    ctx.poll_deadlines.append(end)
    try:
        while True:
            gate(ctx.value, ctx.clock).remaining(phase)
            ctx.poll_remaining()
            result = attempt()
            gate(ctx.value, ctx.clock).remaining(phase)
            left = ctx.poll_remaining()
            if result:
                return result
            time.sleep(min(2, left))
    finally:
        ctx.poll_deadlines.pop()


def ready_pod(ctx, selector):
    items = kget(ctx, 'pods', '--selector', selector)['items']
    base.require(type(items) is list and len(items) <= 1, 'workload pod set refused')
    if not items:
        return None, None, False
    meta, status = items[0]['metadata'], items[0]['status']
    name, uid = meta['name'], meta['uid']
    base.require(re.fullmatch(r'[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?', name) is not None)
    containers = status.get('containerStatuses') or []
    ready = (status.get('phase') == 'Running' and 'deletionTimestamp' not in meta and bool(containers)
             and all(c.get('ready') is True for c in containers)
             and any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in status.get('conditions') or []))
    return name, uid, ready


def wait_pod(ctx, selector, seconds, old_uid=None):
    def attempt():
        name, uid, ready = ready_pod(ctx, selector)
        return (name, uid) if ready and uid != old_uid else None
    return poll(ctx, 'work', seconds, attempt)


def claims(ctx):
    found = {}
    for item in kget(ctx, 'persistentvolumeclaims')['items']:
        base.require(item['status'].get('phase') == 'Bound', 'claim not bound')
        found[item['metadata']['name']] = {'uid': item['metadata']['uid'],
                                           'storage': item['spec']['resources']['requests']['storage']}
    base.require(sorted(c['storage'] for c in found.values()) == ['1Gi', '8Gi'], 'claim set differs')
    return found


PROMETHEUS_SELECTOR = 'app.kubernetes.io/name=prometheus'
GRAFANA_SELECTOR = 'app.kubernetes.io/name=grafana'


# ---- Steps ---------------------------------------------------------------------------------------
def install_script(ctx, script, args, cap, env=None):
    previous = os.umask(0o022)
    try:
        out = run_tool(ctx, [PYTHON, MROOT / script, *args], 'stage', cap, env=env)
    finally:
        os.umask(previous)
    base.exclusive(MROOT / (script + '.receipt'), out)


def step_install_docker(ctx):
    for name in ('docker.socket', 'docker.service', 'containerd.service'):
        clock = gate(ctx.value, ctx.clock)
        code, raw = base.call_bounded([SYSTEMCTL, 'show', name, '-p', 'LoadState'], min(10, clock.remaining('stage')))
        base.require(code in (0, 1, 5) and raw == b'LoadState=not-found\n', 'preexisting daemon refused')
    base.exclusive(MROOT / 'daemon-intent.json',
                   base.encoded({'units': ['docker.socket', 'docker.service', 'containerd.service']}))
    ctx.private['docker_intent'] = True
    save_state(ctx.state)
    install_script(ctx, 'install-docker.py', ['--receipt', MROOT / 'docker-receipt.json'], 235)


def step_install_kubectl(ctx):
    install_script(ctx, 'install-kubectl.py', ['--version', '1.35.0', '--platform', 'linux/amd64',
                                               '--binary', MROOT / 'kubectl'], 30)


def step_install_helm(ctx):
    install_script(ctx, 'install-helm.py', ['--version', '3.19.4', '--platform', 'linux/amd64',
                                            '--archive', MROOT / 'helm.tar.gz'], 125)


def step_install_k3d(ctx):
    # The accepted installer verifies its own pinned sha256. Only its documented timeout
    # overrides are set (bounded below the work phase); the digest override is never used.
    env = tool_env({'K3D_DOWNLOAD_MAX_TIME': '60', 'K3D_DOWNLOAD_TOTAL_TIMEOUT': '150'})
    previous = os.umask(0o022)
    try:
        out = run_tool(ctx, [BASH, MROOT / 'install-k3d.sh'], 'stage', 180, env=env)
    finally:
        os.umask(previous)
    base.exclusive(MROOT / 'install-k3d.sh.receipt', out)


def step_daemon_start(ctx):
    run_tool(ctx, [SYSTEMCTL, 'start', 'containerd.service', 'docker.service'], 'stage', 30)
    ctx.private['docker_started'] = True
    save_state(ctx.state)


def step_storage(ctx):
    base.no_links(STORAGE)
    base.require(not present(STORAGE), 'preexisting storage refused')
    base.no_links(STORAGE.parent)
    os.makedirs(STORAGE.parent, mode=0o755, exist_ok=True)
    ctx.private['storage_intent'] = True  # crash-durable (file, rename AND directory fsync) BEFORE the effect
    save_state(ctx.state, durable=True)    # a failure here refuses the mkdir below
    os.mkdir(STORAGE, 0o700)
    info = os.lstat(STORAGE)
    base.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
    ctx.private['storage_ino'] = [info.st_dev, info.st_ino]
    save_state(ctx.state, durable=True)  # identity durable immediately, not only when the whole step completes
    ctx.observe('storage_new')


def step_cluster(ctx):
    base.require(re.fullmatch(r'docker\.io/rancher/k3s@sha256:[0-9a-f]{64}', MANAGEMENT_IMAGE) is not None)
    # Recorded BEFORE the attempt so teardown deletes the exact cluster name even after a lost reply.
    ctx.private['cluster_attempted'] = True
    save_state(ctx.state)
    env = tool_env({'LABAPP_MANAGEMENT_IMAGE': MANAGEMENT_IMAGE, 'LABAPP_PROMETHEUS_BIND_ADDRESS': BIND_ADDRESS})
    run_tool(ctx, [K3D, 'cluster', 'create', '--config', MROOT / 'management-cluster.yaml',
                   '--kubeconfig-update-default=false', '--kubeconfig-switch-context=false'],
             'work', 330, env=env)
    run_tool(ctx, [K3D, 'kubeconfig', 'write', CLUSTER, '--output', KUBECONFIG,
                   '--kubeconfig-switch-context=false'], 'work', 30)
    os.chmod(KUBECONFIG, 0o600)
    base.regular(KUBECONFIG, 65536, 0, 0o600)
    contexts = kubectl(ctx, ['config', 'get-contexts', '--output', 'name'], 30).decode().split()
    base.require(contexts == [CONTEXT], 'private kubeconfig context differs')
    ctx.observe('cluster_context')


def step_namespace(ctx):
    kubectl(ctx, ['create', 'namespace', NAMESPACE])


def step_secret(ctx):
    # Throwaway guest-local credentials: private 0600 files only, never argv, logs or the result.
    base.exclusive(WORK / 'grafana-admin-user', b'admin')
    base.exclusive(WORK / 'grafana-admin-password', secrets.token_urlsafe(24).encode())
    kubectl(ctx, ['--namespace', NAMESPACE, 'create', 'secret', 'generic', SECRET,
                  '--from-file=admin-user=' + str(WORK / 'grafana-admin-user'),
                  '--from-file=admin-password=' + str(WORK / 'grafana-admin-password')])
    ctx.observe('secret_private')


def step_helm(ctx):
    timeout = min(600, int(ctx.clock.remaining('work')) - 30)
    base.require(timeout >= 120, 'insufficient time for chart install', 'phase-cutoff')
    run_tool(ctx, [HELM, 'upgrade', '--install', RELEASE, MROOT / 'kube-prometheus-stack-65.2.0.tgz',
                   '--kubeconfig', KUBECONFIG, '--kube-context', CONTEXT, '--namespace', NAMESPACE,
                   '--values', MROOT / 'observability-values.yaml',
                   '--values', MROOT / 'management-observability-values.yaml',
                   '--wait', '--timeout', str(timeout) + 's'], 'work', timeout + 30)


def step_health(ctx):
    ctx.private['claims'] = claims(ctx)
    ctx.observe('pvc_bound')
    wait_pod(ctx, PROMETHEUS_SELECTOR, 120)
    wait_pod(ctx, GRAFANA_SELECTOR, 120)
    ctx.observe('workloads_ready')


def probe_query(label):
    base.require(re.fullmatch('[a-f0-9]{16}', label) is not None)
    return PROBE_METRIC + '{nonce="' + label + '"}'


def step_probe_push(ctx):
    pod, _ = wait_pod(ctx, PROMETHEUS_SELECTOR, 60)
    label, value = secrets.token_hex(8), 1000 + secrets.randbelow(9000)
    ctx.private['probe'] = {'label': label, 'value': value, 'pushed_at': time.time(), 'timestamp': None}
    save_state(ctx.state)
    text = (probe_query(label) + ' ' + str(value) + '\n').encode()  # no explicit timestamp: promtool assigns now
    kubectl(ctx, ['--namespace', NAMESPACE, 'exec', '-i', pod, '-c', 'prometheus', '--', '/bin/promtool',
                  'push', 'metrics', '--label=job=promtool', '--timeout=10s', PROMETHEUS_URL + '/api/v1/write'], 30, data=text)
    ctx.observe('probe_pushed')


def probe_series(ctx, label, value):
    data = prom(ctx, probe_query(label) + '[2m]')
    base.require(data.get('resultType') == 'matrix' and len(data['result']) == 1, 'probe series refused')
    series = data['result'][0]
    base.require(series['metric'] == {'__name__': PROBE_METRIC, 'nonce': label, 'job': 'promtool'}, 'probe labels differ')
    samples = series['values']
    base.require(type(samples) is list and samples and all(len(s) == 2 and s[1] == str(value) for s in samples),
                 'probe value differs')
    return samples


def step_probe_read(ctx):
    probe = ctx.private['probe']
    label, value = probe['label'], probe['value']
    samples = poll(ctx, 'work', 90, lambda: _probe_or_none(ctx, label, value))
    timestamp = float(samples[-1][0])
    # Bounded freshness against the recorded push time and the guest clock (sample timestamp, not eval time).
    base.require(probe['pushed_at'] - 5 <= timestamp <= time.time() + 5
                 and time.time() - timestamp <= PROBE_FRESH_SECONDS, 'probe sample not fresh')
    probe['timestamp'] = timestamp
    ctx.observe('probe_fresh')
    unused = prom(ctx, probe_query(secrets.token_hex(8)) + '[2m]')  # unused nonce: successful EMPTY data
    base.require(unused.get('resultType') == 'matrix' and unused['result'] == [], 'unused nonce not empty')
    ctx.observe('unused_nonce_empty')
    for _ in range(2):
        time.sleep(1)
        base.require(probe_series(ctx, label, value) == samples, 'repeat read changed')
    ctx.observe('repeat_reads_stable')


def _probe_or_none(ctx, label, value):
    try:
        return probe_series(ctx, label, value)
    except base.Failure as error:
        if error.category in ('capability', 'status-invalid'):
            raise  # a query ERROR is never treated as "not yet visible"
        return None


def step_principal(ctx):
    admin = admin_auth()
    poll(ctx, 'work', 90, lambda: _grafana_healthy(ctx))
    login = 'labapp-viewer-' + secrets.token_hex(3)
    password = secrets.token_urlsafe(18)
    base.exclusive(WORK / 'viewer.json', base.encoded({'login': login, 'password': password}))
    status, _ = grafana(ctx, 'POST', '/api/admin/users', admin,
                        {'name': login, 'email': login + '@labapp.invalid', 'login': login, 'password': password})
    base.require(status == 200, 'principal create refused')
    verify_viewer(ctx, admin, (login, password))
    status, datasources = grafana(ctx, 'GET', '/api/datasources', admin)
    base.require(status == 200 and type(datasources) is list and datasources, 'datasources unavailable')
    ctx.private['datasources'] = sorted(d['uid'] for d in datasources)
    ctx.observe('principal_viewer')


def _grafana_healthy(ctx):
    try:
        status, body = grafana(ctx, 'GET', '/api/health', None)
    except base.Failure as error:
        if error.category == 'capability':
            return None
        raise
    return status == 200 and type(body) is dict and body.get('database') == 'ok'


def viewer_credentials():
    value = base.data(base.regular(WORK / 'viewer.json', 1024, 0, 0o600))
    base.require(set(value) == {'login', 'password'} and re.fullmatch(VIEWER_LOGIN, value['login'])
                 and re.fullmatch(VIEWER_PASSWORD, value['password']))
    return value['login'], value['password']


def verify_viewer(ctx, admin, viewer):
    """Exact TEST principal and role by native API; the role is verified, never elevated."""
    status, members = grafana(ctx, 'GET', '/api/org/users', admin)
    base.require(status == 200 and type(members) is list, 'org users unavailable')
    rows = [m for m in members if m.get('login') == viewer[0]]
    base.require(len(rows) == 1 and rows[0].get('role') == 'Viewer', 'principal role is not Viewer')
    status, me = grafana(ctx, 'GET', '/api/user', viewer)
    base.require(status == 200 and me.get('login') == viewer[0] and me.get('isGrafanaAdmin') is False,
                 'principal login refused')
    status, _ = grafana(ctx, 'GET', '/api/admin/settings', viewer)
    base.require(status in (401, 403), 'principal has admin access')


def step_restart(ctx):
    before = ctx.private['claims']
    for selector, key in ((PROMETHEUS_SELECTOR, 'prometheus_restarted'), (GRAFANA_SELECTOR, 'grafana_restarted')):
        pod, uid = wait_pod(ctx, selector, 60)
        # Pod deletion only: PVCs, the namespace and the cluster are never deleted here.
        kubectl(ctx, ['--namespace', NAMESPACE, 'delete', 'pod', pod, '--wait=true'], 120)
        wait_pod(ctx, selector, 240, old_uid=uid)
        ctx.observe(key)
    base.require(claims(ctx) == before, 'claim identity changed')
    ctx.observe('pvc_uid_unchanged')
    poll(ctx, 'work', 120, lambda: _prometheus_ready(ctx))


def _prometheus_ready(ctx):
    try:
        ctx_gate(ctx)
        return http('GET', PROMETHEUS_URL + '/-/ready', timeout=min(QUERY_TIMEOUT, ctx.poll_remaining()))[0] == 200
    except base.Failure as error:
        if error.category == 'capability':
            return False  # connection refused while the restarted pod comes up
        raise


def step_historical(ctx):
    probe = ctx.private['probe']
    label, value, timestamp = probe['label'], probe['value'], probe['timestamp']
    # Historical query AT the recorded sample time; the sample is NOT pushed again.
    data = prom(ctx, probe_query(label), at=timestamp)
    base.require(data.get('resultType') == 'vector' and len(data['result']) == 1, 'historical sample missing')
    row = data['result'][0]
    base.require(row['metric'] == {'__name__': PROBE_METRIC, 'nonce': label, 'job': 'promtool'}
                 and row['value'][1] == str(value),
                 'historical sample differs')
    ctx.observe('historical_sample')


def step_persisted_principal(ctx):
    admin, viewer = admin_auth(), viewer_credentials()
    poll(ctx, 'work', 90, lambda: _grafana_healthy(ctx))
    verify_viewer(ctx, admin, viewer)
    status, datasources = grafana(ctx, 'GET', '/api/datasources', admin)
    base.require(status == 200 and type(datasources) is list
                 and sorted(d['uid'] for d in datasources) == ctx.private['datasources'], 'datasource state changed')
    ctx.observe('principal_persisted')


def panel_matches(dashboard):
    """Panels (top level or inside collapsed rows) with the pinned source panel id."""
    found = []
    for item in dashboard.get('panels') or []:
        if type(item) is not dict:
            continue
        found.extend([item] if item.get('id') == VIEWER_DASHBOARD['panel_id'] else [])
        found.extend(p for p in item.get('panels') or [] if type(p) is dict and p.get('id') == VIEWER_DASHBOARD['panel_id'])
    return found


def discover_viewer_panel(ctx, viewer):
    """Find the ONE existing chart dashboard as the Viewer; the runtime UID is only ever read, never invented.

    The pinned chart source has uid "" so Grafana assigns the UID at provisioning time. Zero or
    several matches, a wrong title/panel/datasource, or a Viewer that can edit/save/administer
    the dashboard all refuse. Nothing is created, edited, shared or elevated here.
    """
    spec = VIEWER_DASHBOARD
    query = urllib.parse.urlencode({'type': 'dash-db', 'query': spec['title'], 'tag': spec['tag'], 'limit': 20})
    status, rows = grafana(ctx, 'GET', '/api/search?' + query, viewer)
    base.require(status == 200 and type(rows) is list, 'viewer dashboard search unavailable')
    rows = [r for r in rows if type(r) is dict and r.get('title') == spec['title'] and r.get('type') == 'dash-db']
    base.require(len(rows) == 1, 'viewer dashboard missing or ambiguous')
    uid = rows[0].get('uid')
    base.require(type(uid) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,40}', uid) is not None, 'dashboard uid refused')
    status, body = grafana(ctx, 'GET', '/api/dashboards/uid/' + uid, viewer)
    base.require(status == 200 and type(body) is dict and type(body.get('dashboard')) is dict
                 and type(body.get('meta')) is dict, 'viewer cannot read panel dashboard')
    dashboard, meta = body['dashboard'], body['meta']
    base.require(dashboard.get('title') == spec['title'] and dashboard.get('uid') == uid, 'dashboard identity differs')
    base.require(all(meta.get(k) is False for k in ('canSave', 'canEdit', 'canAdmin')), 'viewer can modify dashboard')
    matches = panel_matches(dashboard)
    base.require(len(matches) == 1, 'panel absent or ambiguous')
    panel = matches[0]
    base.require(panel.get('title') == spec['panel_title'] and panel.get('type') in spec['panel_types'], 'panel differs')
    source = panel.get('datasource')
    source = source.get('uid') if type(source) is dict else source
    base.require(source in ('$datasource', '${datasource}'), 'panel datasource differs')
    variables = [v for v in (dashboard.get('templating') or {}).get('list') or []
                 if type(v) is dict and v.get('name') == spec['datasource_variable']]
    base.require(len(variables) == 1 and variables[0].get('type') == 'datasource'
                 and variables[0].get('query') == spec['datasource_type'], 'datasource variable differs')
    return {'uid': uid, 'panel_id': spec['panel_id']}


def step_viewer_ready(ctx):
    admin, viewer = admin_auth(), viewer_credentials()
    verify_viewer(ctx, admin, viewer)  # still exactly a non-admin Viewer before any dashboard is read
    status, datasources = grafana(ctx, 'GET', '/api/datasources', admin)
    base.require(status == 200 and type(datasources) is list
                 and len([d for d in datasources if d.get('type') == VIEWER_DASHBOARD['datasource_type']]) == 1,
                 'prometheus datasource missing or ambiguous')
    panel = discover_viewer_panel(ctx, viewer)
    ctx.private['viewer_panel'] = panel
    record = {'schema': 1, 'nonce': ctx.value['nonce'], 'login': viewer[0], 'password': viewer[1],
              'path': '/d/%s?viewPanel=%d' % (panel['uid'], panel['panel_id']), 'port': GRAFANA_PORT}
    validate_handoff(record, ctx.value['nonce'])
    base.exclusive(WORK / 'viewer-handoff.json', base.encoded(record))
    ctx.observe('viewer_handoff_ready')


STEP_FUNCTIONS = {
    'install-docker': step_install_docker, 'install-kubectl': step_install_kubectl,
    'install-helm': step_install_helm, 'install-k3d': step_install_k3d, 'daemon-start': step_daemon_start,
    'storage': step_storage, 'cluster': step_cluster, 'namespace': step_namespace, 'secret': step_secret,
    'helm': step_helm, 'health': step_health, 'probe-push': step_probe_push, 'probe-read': step_probe_read,
    'principal': step_principal, 'restart': step_restart, 'historical': step_historical,
    'persisted-principal': step_persisted_principal, 'viewer-ready': step_viewer_ready}


def validate_handoff(value, nonce):
    """Viewer-only handoff schema. Admin credentials and kubeconfig can never be expressed here."""
    base.require(type(value) is dict and set(value) == HANDOFF_FIELDS and value['schema'] == 1
                 and type(value['schema']) is int and value['nonce'] == nonce
                 and type(value['login']) is str and re.fullmatch(VIEWER_LOGIN, value['login'])
                 and type(value['password']) is str and re.fullmatch(VIEWER_PASSWORD, value['password'])
                 and type(value['path']) is str and re.fullmatch(HANDOFF_PATH, value['path'])
                 and type(value['port']) is int and value['port'] == GRAFANA_PORT, 'handoff refused')
    return value


def execute_step(ctx, name):
    """ONE step of the closed table under the caller's single Context (worker and ``run_step``)."""
    state = ctx.state
    base.require(name in STEP_NAMES, 'unknown step')
    base.require(state['failure'] is None and state['teardown'] == 'pending', 'sequence stopped')
    index = STEP_NAMES.index(name)
    base.require(all(state['steps'][n] == 'ok' for n in STEP_NAMES[:index]) and state['steps'][name] == 'not-run',
                 'step order refused')
    try:
        ctx.clock = gate(ctx.value, ctx.clock)
        ctx.clock.remaining(STEP_PHASE[name])
        STEP_FUNCTIONS[name](ctx)
    except BaseException as error:
        state['steps'][name] = 'failed'
        state['failure'] = failure_record(name, error)
        if getattr(error, 'cleanup_uncertain', False):
            state['private']['child_cleanup_uncertain'] = True
        try:
            save_state(state)
        except BaseException:
            pass  # the primary failure stays primary
        raise
    state['steps'][name] = 'ok'
    save_state(state)


def run_step(nonce, name, clock=None):
    """Internal single-step entry (no host command reaches it). ``clock`` defaults to the legacy
    per-process clock for synthetic tests; the worker always passes the capsule clock."""
    base.require(name in STEP_NAMES, 'unknown step')
    value = contract_value(nonce)
    state = load_state(nonce)
    execute_step(Context(value, clock, state), name)


def worker():
    """The ONE worker process: all 18 closed steps, one Context, native failures stay primary."""
    value = contract_any()
    clock = production_clock(value)
    ctx = Context(value, clock, load_state(value['nonce']))
    for name in STEP_NAMES:
        execute_step(ctx, name)


# ---- Fixed export, result, heartbeat and teardown --------------------------------------------------
def export_viewer(nonce):
    value = contract_value(nonce)
    state = load_state(nonce)
    base.require(state['steps']['viewer-ready'] == 'ok' and state['failure'] is None
                 and state['terminal']['status'] in (None, 0), 'handoff unavailable')  # observed nonzero terminal refuses
    gate(value)
    raw = base.regular(WORK / 'viewer-handoff.json', 1024, 0, 0o600)
    validate_handoff(base.data(raw), nonce)
    return raw


def result(nonce):
    contract_value(nonce)
    return base.encoded(validate_result(public_record(load_state(nonce)), nonce))


def cancel(nonce):
    """Closed host action: request the normal end of the trial. Idempotent; the guardian exits and the
    fixed ExecStopPost performs the cleanup. Nothing here runs cleanup or selects anything."""
    value = contract_value(nonce)
    base.require(base.kernel_boot() == value['boot_uuid'], 'boot changed', 'boot-change')
    try:
        base.exclusive(MROOT / CANCEL_MARK, base.encoded({'nonce': nonce}))
    except FileExistsError:
        pass


def heartbeat(nonce, sequence):
    value = contract_value(nonce)
    base.require(type(sequence) is int and sequence > 0)
    production_clock(value).remaining('persistence')
    base.require(base.kernel_boot() == value['boot_uuid'])
    old = base.data(base.regular(MROOT / 'heartbeat.json', 4096, 0))
    base.require(sequence == old['sequence'] + 1)
    base.atomic(MROOT / 'heartbeat.json', {'sequence': sequence, 'received': time.monotonic()})


def bounded_rmtree(path, deadline):
    """Remove one directory tree without following links or crossing devices, checking ONE outer
    deadline before every entry. Raises on any refusal; never reports success it did not observe.
    NOT called by any production path (#510: management storage is always retained); kept only as a
    bounded filesystem utility exercised by its own tests. Do not wire it into cleanup."""
    root_dev = os.lstat(path).st_dev

    def walk(directory):
        entries = []
        with os.scandir(directory) as scan:
            for entry in scan:  # a Python-level loop: the deadline also bounds the enumeration itself
                base.require(time.monotonic() < deadline, 'cleanup deadline elapsed', 'child-timeout')
                entries.append(entry)
        for entry in entries:
            base.require(time.monotonic() < deadline, 'cleanup deadline elapsed', 'child-timeout')
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode) and info.st_dev == root_dev:
                walk(entry.path)
                os.rmdir(entry.path)
            else:
                os.unlink(entry.path)  # mount points and non-directories: unlink/rmdir refusal propagates
    walk(path)
    base.require(time.monotonic() < deadline, 'cleanup deadline elapsed', 'child-timeout')
    os.rmdir(path)


def teardown(nonce, *, clock=None, outer=None, storage_allowed=True, final=False, extra_private=None,
             outcome=None):
    """Idempotent removal of exactly what this program created; uncertainty is reported and the
    published receipt is never ``complete`` (always returns 1: final-publication timeliness is unproved).

    ``outer`` (monotonic) bounds the child, polling and enumeration steps this function performs; it is
    NOT a hard bound on an uninterruptible filesystem call or the final state write. ``storage_allowed``
    is False when worker absence is unproven (storage is never removed then); ``final`` marks the
    poststop writer, which already holds the state claim.
    """
    value = contract_value(nonce)
    state = load_state(nonce)  # a stored ``complete`` is not trusted: cleanup is idempotent and re-observed
    ctx = Context(value, clock if clock is not None else ManagementClock(value), state)
    if outer is not None:
        ctx.poll_deadlines.append(outer)
    private = state['private']
    if extra_private:
        private.update(extra_private)
    if outcome is not None:
        apply_terminal(state, outcome)
        record_terminal(state, outcome, storage_allowed)
        try:
            validate_result(public_record(state), nonce)
        except BaseException:  # an inexpressible terminal outcome is never published as a half record
            state['failure'] = None
            state['terminal'] = initial_terminal()
            state['steps'] = {n: ('not-run' if s == 'failed' else s) for n, s in state['steps'].items()}
            private['terminal_unpublished'] = True
            private['child_cleanup_uncertain'] = True  # receipt cannot be clean without its terminal outcome
    clean = not private.get('child_cleanup_uncertain', False) and storage_allowed
    # ``absent`` = POSITIVE evidence that nothing can still write the storage: the worker (storage_allowed),
    # the cluster/containers and the daemons. Any failed, unknown or unobserved proof withholds the
    # destructive step below and makes the receipt uncertain; credentials are removed regardless.
    absent = storage_allowed
    deadline = outer if outer is not None else time.monotonic() + 120

    def in_time():
        return outer is None or time.monotonic() < outer

    def attempt(argv, cap):
        try:
            return run_tool(ctx, argv, None, cap, cleanup=True)
        except BaseException:
            return None

    if private.get('cluster_attempted'):
        if attempt([K3D, 'cluster', 'delete', CLUSTER], 120) is None:
            clean = absent = False
        listing = attempt([DOCKER, 'ps', '--all', '--quiet', '--filter', 'name=k3d-' + CLUSTER], 30)
        if listing is None or listing.strip() != b'':
            clean = absent = False
    if private.get('docker_started') or private.get('docker_intent'):
        units = [SYSTEMCTL, 'stop', *DAEMON_UNITS]
        if attempt(units, 30) is None or not daemons_absent(deadline):  # a successful stop is not absence
            clean = absent = False
    for name in PRIVATE_FILES:  # protective: credentials are removed even when worker absence is unproven
        path = WORK / name
        try:
            base.require(in_time(), 'cleanup deadline elapsed', 'child-timeout')
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1:
                path.unlink()
            else:
                clean = False
        except FileNotFoundError:
            pass
        except BaseException:
            clean = False
    recorded = private.get('storage_ino')
    try:
        exists = present(STORAGE)  # None = unobservable (EACCES/EIO/...): unknown, never absent
    except BaseException:
        exists, clean, absent = None, False, False
    # STORAGE RETENTION (#510): this program has NO migration-safe quiescence boundary (cgroup population
    # reads are sequential and unproven against migration), so NO reachable path removes management
    # storage, whatever ``storage_allowed``, the worker/daemon checks, the recorded inode or any private
    # observation says. There is no flag or marker that re-enables it. The recorded inode and intent stay
    # untouched, unknown or foreign paths are never adopted, and any existing (or unobservable) storage
    # keeps the receipt uncertain. Credential removal and the native cluster/daemon cleanup above remain.
    if exists is not False:  # present (ours, foreign or unrecorded) or unobservable: retained, never clean
        clean = False
        private['storage_retained'] = True
    clean = clean and in_time()
    # Diagnostic only (private): whether every observed absence held. It is NEVER published as ``complete``:
    # ``save_state`` refuses a positive complete while final-publication timeliness is unproved.
    private['teardown_observed_clean'] = bool(clean)
    state['teardown'] = 'uncertain'
    save_state(state, poststop=final, until=outer)
    return 1


# ---- Guardian, expiry and poststop (fixed units; #508) -------------------------------------------------
class Cancelled(Exception):
    """The host requested the normal end of the trial (closed ``cancel`` action)."""


def gate_state(value):
    """'closed' once the expiry/poststop marker exists (permanent), 'open' once bootstrap released the
    worker, else 'unopened'. Closure always wins; nothing ever reopens the gate."""
    if present(MROOT / RELEASE_CLOSED):
        return 'closed'
    if present(MROOT / RELEASE_OPEN):
        record = base.data(base.regular(MROOT / RELEASE_OPEN, 4096, 0, 0o600))
        base.require(type(record) is dict and record.get('nonce') == value['nonce'], 'release binding differs')
        return 'open'
    return 'unopened'


def close_release(value):
    """Permanently close the worker-release gate. Idempotent (an existing marker is the closure)."""
    try:
        base.exclusive(MROOT / RELEASE_CLOSED, base.encoded({'nonce': value['nonce'], 'boot': value['boot_uuid']}))
    except FileExistsError:
        pass


def fresh_heartbeat():
    try:
        heartbeat_fresh()
    except base.Failure as error:
        if error.category == 'heartbeat-loss':
            raise
        heartbeat_fresh()  # ONE retry for the atomic-replace read race; a second failure is the primary


def supervise(value, clock):
    """Boot, heartbeat freshness, persistence cutoff and permanent gate closure; raises the primary."""
    base.require(base.kernel_boot() == value['boot_uuid'], 'boot changed', 'boot-change')
    fresh_heartbeat()
    clock.remaining('persistence')
    base.require(gate_state(value) != 'closed', 'release closed', 'phase-cutoff')
    if present(MROOT / CANCEL_MARK):
        raise Cancelled()


def supervise_worker(value, clock):
    """The guardian's OWN immutable phase cutoffs while the worker runs, independent of any worker or
    host progress: nothing the worker does may outlive the work cutoff, and the first unfinished step's
    phase cutoff (derived read-only from the step record; cutoffs only grow with later phases) must not
    have passed. The persistence cutoff applies only to the completed worker's Viewer hold."""
    clock.remaining('work')
    state = load_state(value['nonce'])
    unfinished = [n for n in STEP_NAMES if state['steps'][n] != 'ok']
    if unfinished:
        clock.remaining(STEP_PHASE[unfinished[0]])


def wait_release(value, clock):
    while True:
        supervise(value, clock)
        clock.remaining('stage')
        if gate_state(value) == 'open':
            return
        time.sleep(.1)


def guardian():
    """Fixed owner of exactly ONE worker. It never writes steps.json (the worker, then poststop, do);
    its only record is its own ``outcome.json``. The unchanged OwnedGroup is the sole reaper."""
    value = contract_any()
    clock = production_clock(value)
    base.require(base.kernel_boot() == value['boot_uuid'], 'boot changed', 'boot-change')
    base.exclusive(MROOT / 'guardian.json', base.encoded({'boot': value['boot_uuid'], 'lease': value['lease'],
                   'nonce': value['nonce'], 'guardian_pid': os.getpid()}))
    outcome = {'schema': 1, 'nonce': value['nonce'], 'worker': None, 'closed': None, 'guardian': None,
               'terminal': initial_terminal()}
    group, code = None, 1
    try:
        wait_release(value, clock)
        proc = subprocess.Popen([PYTHON, str(MROOT / 'management_trial.py'), 'worker'], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=dict(base.ENV),
                                start_new_session=True)
        group = owned_process.OwnedGroup(proc)
        while True:
            status = group.status()  # non-reaping and FIRST: an already exited native status is never obscured
            if status is not None:
                outcome['worker'], code = status, (status if status >= 0 else 128 - status)
                break
            supervise(value, clock)
            supervise_worker(value, clock)
            time.sleep(.2)
        if status == 0:  # keep the cluster up for the private Viewer handoff until cancel/expiry/loss
            base.require(all(load_state(value['nonce'])['steps'][n] == 'ok' for n in STEP_NAMES),
                         'worker ended before the Viewer hold', 'status-invalid')
            while True:
                supervise(value, clock)
                time.sleep(.2)
    except Cancelled:
        code = code if outcome['worker'] is not None else 130
        outcome['guardian'] = {'category': 'interrupted', 'child_status': None}
    except BaseException as error:
        record = failure_record('guardian', error)
        outcome['guardian'] = {'category': record['category'], 'child_status': record['child_status']}
        code = error.code if isinstance(error, base.Failure) and type(error.code) is int and 0 < error.code < 256 else 1
    finally:
        if group is None:
            outcome['closed'] = True
        else:
            if outcome['worker'] is None:
                try:  # last non-reaping look BEFORE closure signals anything: a status seen now is native
                    seen = group.status()
                    if seen is not None:
                        outcome['worker'] = seen
                except BaseException:
                    pass  # unknown stays unknown (a status produced by our own closure is never recorded)
            try:
                outcome['closed'] = bool(group.close(owned_process.TERM_GRACE_SECONDS, until=time.monotonic() + 15))
            except BaseException:
                outcome['closed'] = False
            # Independent terminal evidence, whatever ``close`` returned: an earlier pre-close observation
            # wins; otherwise the unchanged OwnedGroup's already-settled returncode (read ONCE, never a
            # second wait/poll/PID reconstruction) is a closure-window observation, not a causal claim.
            try:
                if terminal_status_ok(outcome['worker']):
                    outcome['terminal'] = {'status': outcome['worker'], 'origin': 'pre-close', 'group': 'uncertain'}
                else:
                    settled = group.proc.returncode
                    if terminal_status_ok(settled):
                        outcome['terminal'] = {'status': settled, 'origin': 'closure-window', 'group': 'uncertain'}
            except BaseException:
                pass  # stays unobserved
        try:
            base.atomic(MROOT / 'outcome.json', outcome)
        except BaseException:
            pass
    return code


def expire():
    """Fixed expiry stop service body. The fixed non-blocking native stop request is initiated FIRST,
    before and independent of any contract or gate I/O (a stop job also replaces a still-pending start
    job); the permanent gate closure is then still attempted and verified. Never restarts, rearms or
    renews anything; the guardian unit is a constant, so no record selects the target."""
    stop_error = None
    try:
        code, _ = base.call_bounded([SYSTEMCTL, 'stop', '--no-block', GUARDIAN_UNIT], 10)
        if code:
            stop_error = base.child_failure(code, 'fixed child failed')
    except BaseException as error:
        stop_error = error
    primary = None
    try:  # a gate/contract failure stays the primary failure; it can no longer prevent the stop above
        value = contract_any()
        close_release(value)
        base.require(gate_state(value) == 'closed', 'release closure unconfirmed')
    except BaseException as error:
        primary = error
    if primary is not None:
        raise primary
    if stop_error is not None:
        raise stop_error
    return 0


CGROUP_MAX_DIRS, CGROUP_MAX_DEPTH = 256, 8


def cgroup_processes(directory, deadline=None):
    """Every pid in this cgroup AND all descendant cgroups (subgroup survivors count). Links are never
    followed; a read error, a bound overrun or a vanished subgroup raises, so it is never absence."""
    found, seen = set(), [0]

    def walk(path, depth):
        base.require(depth <= CGROUP_MAX_DEPTH and seen[0] < CGROUP_MAX_DIRS, 'cgroup tree too large')
        base.require(deadline is None or time.monotonic() < deadline, 'cleanup deadline elapsed', 'child-timeout')
        seen[0] += 1
        with (path / 'cgroup.procs').open('rb') as stream:
            raw = stream.read(65537)  # cgroup pseudo-files report zero size: separate byte bound
        base.require(len(raw) <= 65536 and all(re.fullmatch(rb'[1-9][0-9]{0,9}', p) for p in raw.split()))
        found.update(int(p) for p in raw.split())
        children = []
        with os.scandir(path) as scan:
            for entry in scan:
                base.require(len(children) < CGROUP_MAX_DIRS, 'cgroup tree too large')
                if entry.is_dir(follow_symlinks=False):
                    children.append(entry.path)
        for child in children:
            walk(Path(child), depth + 1)
    walk(directory, 0)
    return found


def quiescent_processes(directory, deadline=None):
    """Conservative absence evidence for ONE cgroup. The recursive walk above is a survivor DIAGNOSTIC:
    sequential reads are not migration-safe, so a tree with ANY descendant cgroup has unprovable
    quiescence and raises (never absence). Only a flat cgroup is accepted, read before AND after the
    child check; no stronger kernel-backed recursive emptiness exists within this ownership boundary."""
    first = cgroup_processes(directory, deadline)
    with os.scandir(directory) as scan:
        if any(entry.is_dir(follow_symlinks=False) for entry in scan):
            raise base.Failure('descendant cgroup present: quiescence unprovable', 1, 'status-invalid')
    return first | cgroup_processes(directory, deadline)


def unit_processes(deadline=None):
    return cgroup_processes(CGROUP_DIR, deadline)


def poll_absent(check, outer):
    """Retry a positive-absence ``check(deadline)`` until ``outer``/ABSENCE_SECONDS; any error is False."""
    until = min(outer, time.monotonic() + ABSENCE_SECONDS)
    while True:
        try:
            if check(until):
                return True
        except BaseException:
            return False
        if time.monotonic() >= until:
            return False
        time.sleep(.2)


def workers_absent(outer):
    """True only when the guardian cgroup is flat (no descendant cgroup: quiescence is otherwise
    unprovable) and holds nothing but this poststop process. Entering poststop proves nothing (v255
    enters it even when SIGKILL survivors remain)."""
    me = os.getpid()
    return poll_absent(lambda until: quiescent_processes(CGROUP_DIR, until) <= {me}, outer)


def daemon_cgroups_empty(until):
    parent = DAEMON_CGROUPS[0].parent
    base.require(stat.S_ISREG(os.lstat(parent / 'cgroup.procs').st_mode) and parent.is_dir(),
                 'cgroup hierarchy unobserved')  # an unreadable hierarchy is never "absent"
    with os.scandir(parent) as scan:
        if any(re.fullmatch(r'(docker|containerd)-.*\.scope', entry.name) for entry in scan):
            return False
    for path in DAEMON_CGROUPS:
        if present(path) and quiescent_processes(path, until):  # unobservable raises: never absence
            return False
    return True


def daemons_absent(outer):
    """Positive daemon-process absence after the stop request: no docker/containerd unit or container
    scope cgroup holds any process. A successful ``systemctl stop`` alone is not evidence."""
    return poll_absent(daemon_cgroups_empty, outer)


def _alarm(_signum, _frame):
    raise base.Failure('cleanup deadline elapsed', 124, 'child-timeout')


def poststop():
    """Fixed ExecStopPost body. The outer deadline starts at ENTRY (before the first read). Where the
    interpreter can express it, a one-shot ITIMER_REAL interrupts INTERRUPTIBLE blocking calls: first at
    entry+235s, then clipped (never extended) to the original remaining cleanup deadline once that is
    known. It does NOT bound preparation reads before that point, an uninterruptible filesystem call, or
    the final state write, and nothing here proves publication timeliness: a positive ``complete`` is
    therefore never published (ACTIVATION_BLOCKERS). A receipt this process does not finish is whatever
    state was last published (``pending`` is not evidence of anything)."""
    entry = time.monotonic()
    previous = None
    armed = threading.current_thread() is threading.main_thread() and hasattr(signal, 'setitimer')

    def clip(outer):
        if armed:  # outer <= entry + POSTSTOP_OUTER_SECONDS, so this can only shorten the armed alarm
            signal.setitimer(signal.ITIMER_REAL, max(.001, outer - time.monotonic()))
    if armed:
        previous = signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, POSTSTOP_OUTER_SECONDS)
    try:
        return _poststop(entry, clip)
    finally:
        if previous is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)


def apply_terminal(state, outcome):
    """Carry the authoritative terminal outcome into the strict public record when the worker could not
    (SIGKILL, guardian-side loss, cancel): native exit/signal first, else the guardian's own category.
    An already recorded failure stays primary. Once all 18 steps are ok nothing is rewritten: a later
    nonzero worker status lives ONLY in the separate ``terminal`` evidence (``record_terminal``), never as
    a falsified failed last step. A missing outcome adds nothing (the caller records it as unknown)."""
    if state['failure'] is not None or outcome is None:
        return
    worker, guardian = outcome.get('worker'), outcome.get('guardian')
    native = type(worker) is int and worker != 0
    pending = [n for n in STEP_NAMES if state['steps'][n] != 'ok']
    if not pending:
        return
    if any(state['steps'][n] != 'not-run' for n in pending):
        return
    carrier = pending[0]
    if native:
        category, status = ('child-signal', worker) if worker < 0 else ('child-exit', worker)
    elif type(guardian) is dict:
        category, status = guardian.get('category'), guardian.get('child_status')
    else:
        return
    if not (type(category) is str and category in base.CATEGORIES and category != 'none'
            and base.child_status_ok(category, status)):
        category, status = 'exception', None
    state['steps'][carrier] = 'failed'
    state['failure'] = {'step': carrier, 'category': category, 'child_status': status}


def record_terminal(state, outcome, storage_allowed):
    """Carry the guardian's independent terminal observation into ``state['terminal']``. Never touches
    steps or the primary failure. A genuine earlier ``pre-close`` observation is kept; a missing or
    malformed observation stays unobserved; ``group`` uncertainty is sticky and is 'closure-reported'
    only for a positive recorded close with worker absence proven."""
    current = state['terminal']
    seen = outcome.get('terminal') if type(outcome) is dict else None
    if terminal_ok(seen) and seen['origin'] != 'unobserved' and current['origin'] != 'pre-close':
        current = {'status': seen['status'], 'origin': seen['origin'], 'group': 'uncertain'}
    reported = (type(outcome) is dict and outcome.get('closed') is True and storage_allowed
                and not state['private'].get('worker_uncertain') and not state['private'].get('child_cleanup_uncertain'))
    state['terminal'] = {'status': current['status'], 'origin': current['origin'],
                         'group': 'closure-reported' if reported else 'uncertain'}


def _poststop(entry, clip=None):
    value = contract_any()
    nonce = value['nonce']
    clock = production_clock(value)
    try:
        left = clock.cleanup_remaining()
    except base.Failure:
        left = 0
    outer = entry + max(0, min(POSTSTOP_OUTER_SECONDS, left))
    if clip is not None:
        clip(outer)  # derived once from the original clock; no later read renews it
    close_release(value)
    duplicate = False
    with state_lock(max(1.0, outer - time.monotonic())):
        try:
            base.exclusive(MROOT / POSTSTOP_CLAIM, base.encoded({'nonce': nonce, 'pid': os.getpid()}))
        except FileExistsError:
            duplicate = True
    if duplicate:  # read-only duplicate: never a second writer, never a positive completion
        return 1
    absent = workers_absent(outer)
    try:
        outcome = base.data(base.regular(MROOT / 'outcome.json', 4096, 0))
        base.require(type(outcome) is dict and outcome.get('nonce') == nonce)
    except Exception:
        outcome = None  # missing/invalid guardian record: the terminal result is UNKNOWN (sticky uncertainty)
    uncertain = not absent or outcome is None or outcome.get('closed') is not True
    extra = {}
    if uncertain:
        extra['worker_uncertain'] = True  # sticky: never cleared
    if outcome is not None and type(outcome.get('worker')) is int:
        extra['worker_exit'] = outcome['worker']  # the native primary exit/signal, preserved
    return teardown(nonce, clock=clock, outer=outer, storage_allowed=not uncertain, final=True, extra_private=extra,
                    outcome=outcome)


TIMER_TOLERANCE_SECONDS = 2.0
TIMESPAN_UNITS = {'us': 1e-6, 'ms': 1e-3, 's': 1.0, 'min': 60.0, 'h': 3600.0, 'd': 86400.0}


def timespan_seconds(text):
    """Seconds from a ``systemctl show`` time span: bare microseconds or ``1h 3min 5.5s`` tokens.
    Anything else (empty, ``infinity``, unknown unit) raises: fail closed, never a guess."""
    base.require(type(text) is str and 0 < len(text) <= 64, 'timespan refused')
    if re.fullmatch(r'[0-9]{1,18}', text):
        return int(text) / 1e6
    tokens = text.split(' ')
    total = 0.0
    for token in tokens:
        match = re.fullmatch(r'([0-9]{1,9}(?:\.[0-9]{1,6})?)(us|ms|s|min|h|d)', token)
        base.require(match is not None, 'timespan refused')
        total += float(match.group(1)) * TIMESPAN_UNITS[match.group(2)]
    base.require(total > 0, 'timespan refused')
    return total


# ---- Root bootstrap (executed by the host's hash-verifying stub) -----------------------------------
def bootstrap(incoming, expected_manifest):
    refuse_activation()
    return _bootstrap(incoming, expected_manifest)


def _bootstrap(incoming, expected_manifest):
    base.require(os.geteuid() == 0 and re.fullmatch('[a-f0-9]{64}', expected_manifest))
    incoming = base.no_links(incoming)
    base.require(re.fullmatch('/tmp/labapp-vlab-[a-f0-9]{32}', str(incoming)))
    info = incoming.lstat()
    base.require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid != 0)
    uid = info.st_uid
    raw = base.regular(incoming / 'manifest.json', base.MAX_SOURCE, uid)
    base.require(base.sha(raw) == expected_manifest)
    table = manifest(base.data(raw))
    with os.scandir(incoming) as entries:
        found = {entry.name for entry in entries}
    base.require(found == FILES | {'manifest.json'})
    for name, item in table['files'].items():
        base.require(base.sha(base.regular(incoming / name, item['bytes'], uid)) == item['sha256'])
    value = base.contract(base.data(base.regular(incoming / 'contract.json', base.MAX_SOURCE, uid)))
    base.require(incoming.name == 'labapp-vlab-' + value['nonce'] and table['source_sha'] == value['source_sha'])
    base.require(base.kernel_boot() == value['boot_uuid'])
    # The capsule is authenticated by the manifest hash like every other byte, then re-validated
    # against this contract and refused when late (age), from the future, or after a guest wall jump.
    capsule = validate_capsule(base.data(base.regular(incoming / 'capsule.json', base.MAX_SOURCE, uid)), value,
                               now=(time.time(), time.monotonic()))
    clock = ManagementClock(value, capsule=capsule)
    clock.remaining('stage')
    base.require(not MROOT.exists(), 'one-shot root reservation collision')
    base.require(all(not (unit_base / name).exists() and not (unit_base / name).is_symlink()
                     for unit_base in base.UNIT_BASES for unit in UNIT_NAMES for name in (unit, unit + '.d')),
                 'management unit override refused')
    base.no_links(MROOT.parent)
    MROOT.mkdir(mode=0o700)
    for directory in (WORK, WORK / 'home', WORK / 'helm-cache', WORK / 'helm-config', WORK / 'helm-data'):
        directory.mkdir(mode=0o700)
    for name, item in table['files'].items():
        raw = base.regular(incoming / name, item['bytes'], uid)
        base.require(len(raw) == item['bytes'] and base.sha(raw) == item['sha256'])
        base.exclusive(MROOT / name, raw)
    base.exclusive(MROOT / 'manifest.json', base.encoded(table))
    base.exclusive(MROOT / 'steps.json', base.encoded(initial_state(value['nonce'])))
    base.exclusive(MROOT / 'heartbeat.json', base.encoded({'sequence': 0, 'received': time.monotonic()}))
    # No package, Docker or Secret effect exists until every step below succeeded. Failure leaves the
    # reservation: the guardian's fixed ExecStopPost owns cleanup; nothing is retried or rearmed.
    try:
        for name in UNIT_NAMES:
            base.exclusive(UNIT_DIR / name, base.regular(MROOT / name, base.MAX_SOURCE, 0), 0o644)
        dropin = RUNTIME_DIR / (TIMER_UNIT + '.d')
        base.no_links(dropin.parent)
        dropin.mkdir(mode=0o755)
        expiry = int(capsule['cutoffs']['persistence'])  # floor: boot-monotonic seconds, never later
        base.require(expiry > 0, 'expiry refused')
        base.exclusive(dropin / '10-bound.conf', ('[Timer]\nOnBootSec=%ds\n' % expiry).encode(), 0o644)
        sys.path.insert(0, str(MROOT))
        base.run([SYSTEMCTL, 'daemon-reload'], clock, 'stage', 10)
        base.run([SYSTEMCTL, 'start', TIMER_UNIT], clock, 'stage', 10)
        shown = base.run([SYSTEMCTL, 'show', TIMER_UNIT, '-p', 'ActiveState', '-p', 'Unit',
                          '-p', 'NextElapseUSecMonotonic'], clock, 'stage', 5)
        fields = dict(line.split('=', 1) for line in shown.decode().splitlines())
        # The ACTUAL loaded deadline must equal the capsule-derived trigger written above (not a constant
        # or any non-empty string); an unknown rendering fails closed (runtime format is unobserved).
        base.require(set(fields) == {'ActiveState', 'Unit', 'NextElapseUSecMonotonic'}
                     and fields['ActiveState'] == 'active' and fields['Unit'] == STOP_UNIT
                     and abs(timespan_seconds(fields['NextElapseUSecMonotonic']) - expiry) <= TIMER_TOLERANCE_SECONDS,
                     'expiry timer unconfirmed')
        base.run([SYSTEMCTL, 'start', GUARDIAN_UNIT], clock, 'stage', 15)
        until = time.monotonic() + min(10, clock.remaining('stage'))
        while not (MROOT / 'guardian.json').exists():
            base.require(time.monotonic() < until, 'guardian readiness unconfirmed')
            time.sleep(.1)
        started = base.data(base.regular(MROOT / 'guardian.json', 4096, 0))
        base.require(started['boot'] == value['boot_uuid'] and started['lease'] == value['lease']
                     and started['nonce'] == value['nonce'], 'guardian binding differs')
        observed = base.run([SYSTEMCTL, 'show', GUARDIAN_UNIT, '-p', 'MainPID', '-p', 'ActiveState'], clock, 'stage', 5)
        fields = dict(line.split('=', 1) for line in observed.decode().splitlines())
        base.require(fields == {'MainPID': str(started['guardian_pid']), 'ActiveState': 'active'},
                     'original guardian process not active')
        # Only now is the permanently closable worker-release gate opened.
        base.exclusive(MROOT / RELEASE_OPEN, base.encoded({'nonce': value['nonce'], 'boot': value['boot_uuid']}))
    except BaseException:
        try:
            base.run([SYSTEMCTL, 'stop', GUARDIAN_UNIT], clock, 'stage', 30)
        except BaseException:
            pass  # the primary failure below stays primary
        raise


def main(argv=None):
    refuse_activation()
    return dispatch(argv)


HOST_ACTIONS = ('heartbeat', 'export-viewer', 'result', 'cancel')   # closed, over the original Master only
UNIT_ACTIONS = ('guardian', 'worker', 'poststop', 'expire')         # only the three fixed units run these


def dispatch(argv=None):
    """Internal fixed dispatcher; reachable only through ``main`` after a future reviewed activation."""
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('action', choices=(*HOST_ACTIONS, *UNIT_ACTIONS))
    parser.add_argument('--nonce')
    parser.add_argument('--sequence', type=int)
    args = parser.parse_args(argv)
    base.require(os.geteuid() == 0, 'root required')
    os.umask(0o077)
    sys.path.insert(0, str(MROOT))
    if args.action in UNIT_ACTIONS:  # fixed systemd entrypoints carry no argument at all
        base.require(args.nonce is None and args.sequence is None)
        return {'guardian': guardian, 'worker': worker, 'poststop': poststop, 'expire': expire}[args.action]() or 0
    base.require(args.nonce is not None)
    if args.action == 'heartbeat':
        base.require(args.sequence is not None)
        heartbeat(args.nonce, args.sequence)
    else:
        base.require(args.sequence is None)
        if args.action == 'cancel':
            cancel(args.nonce)
            return 0
        try:
            out = export_viewer(args.nonce) if args.action == 'export-viewer' else result(args.nonce)
        except Exception:
            out = b'invalid'  # fixed token; never text from a failure or any path
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
    return 0


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise base.Failure('signal', 143 if signum == signal.SIGTERM else 130, 'interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        sys.exit(main())
    except base.Failure as error:
        print('management-trial: refused', file=sys.stderr)
        sys.exit(error.code)
    except Exception:
        print('management-trial: operational failure', file=sys.stderr)
        sys.exit(1)
