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

Supervision: this is not the VLAB guardian service and adds no unit or controller. Every step
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
MGMT_PHASES = {'access': 15, 'stage': 30, 'work': 50, 'persistence': 54}
CEILING_MINUTES = 60
PROVIDER_ENVELOPE_SECONDS = 7200

ACTIVATION_BLOCKERS = (
    'provider-envelope-7200s-versus-60-minute-component-decision',
    'artifact-egress-and-image-inventory-unresolved',
    'viewer-dashboard-runtime-discovery-unobserved',
    'private-viewer-handoff-and-browser-forward-review',
    'no-authorized-verified-browser-observer',
    'independent-lifetime-supervision-and-cross-step-monotonic-anchor-unimplemented',
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
    'management-cluster.yaml', 'management-observability-values.yaml', 'observability-values.yaml')}
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
FILES = {*SOURCES, *PAYLOADS, 'contract.json'}
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
RESULT_FIELDS = {'schema', 'nonce', 'steps', 'failure', 'observed', 'teardown'}
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
    """Admission-anchored wall AND monotonic bounds; clips to the unchanged lease, never renews."""
    def _end(self, minutes):
        admitted = base.stamp(self.value['admitted_at'])
        return min(admitted + minutes * 60, base.phase_end(self.value, 'persistence'),
                   base.stamp(self.value['deadline']))

    def _left(self, end):
        return min(end - self.wall(), end - self.started_wall - (self.mono() - self.started_mono))

    def remaining(self, phase):
        base.require(phase in MGMT_PHASES, 'unknown management phase')
        left = self._left(self._end(MGMT_PHASES[phase]))
        if left <= 0:
            raise base.Failure('absolute phase cutoff', 124, 'phase-cutoff')
        return left

    def cleanup_remaining(self):
        left = self._left(self._end(CEILING_MINUTES))
        if left <= 0:
            raise base.Failure('immutable cleanup cutoff', 124, 'phase-cutoff')
        return left


# ---- Private state ------------------------------------------------------------------------------
def contract_value(nonce):
    value = base.contract(base.data(base.regular(MROOT / 'contract.json', base.MAX_SOURCE, 0)))
    base.require(type(nonce) is str and nonce == value['nonce'])
    return value


def initial_state(nonce):
    return {'schema': 1, 'nonce': nonce, 'steps': {n: 'not-run' for n in STEP_NAMES}, 'failure': None,
            'observed': {k: False for k in OBSERVED}, 'teardown': 'pending', 'private': {}}


def load_state(nonce):
    state = base.data(base.regular(MROOT / 'steps.json', 65536, 0))
    base.require(type(state) is dict and set(state) == {*RESULT_FIELDS, 'private'} and state['nonce'] == nonce
                 and type(state['private']) is dict)
    return state


def save_state(state):
    base.atomic(MROOT / 'steps.json', state)


def public_record(state):
    return {k: state[k] for k in RESULT_FIELDS}


def validate_result(value, nonce):
    """Closed strict validator for the nonsecret typed result (host and guest share it)."""
    base.require(type(value) is dict and set(value) == RESULT_FIELDS, 'result refused')
    base.require(type(value['schema']) is int and value['schema'] == 1 and value['nonce'] == nonce
                 and type(value['teardown']) is str and value['teardown'] in TEARDOWN_STATES, 'result refused')
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
            and record['teardown'] == 'complete' and all(record['observed'].values()))


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
    base.require(not os.path.lexists(STORAGE), 'preexisting storage refused')
    base.no_links(STORAGE.parent)
    os.makedirs(STORAGE.parent, mode=0o755, exist_ok=True)
    os.mkdir(STORAGE, 0o700)
    info = os.lstat(STORAGE)
    base.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
    ctx.private['storage_ino'] = [info.st_dev, info.st_ino]
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


def run_step(nonce, name):
    base.require(name in STEP_NAMES, 'unknown step')
    value = contract_value(nonce)
    state = load_state(nonce)
    base.require(state['failure'] is None and state['teardown'] == 'pending', 'sequence stopped')
    index = STEP_NAMES.index(name)
    base.require(all(state['steps'][n] == 'ok' for n in STEP_NAMES[:index]) and state['steps'][name] == 'not-run',
                 'step order refused')
    ctx = Context(value, None, state)
    try:
        ctx.clock = gate(value, ctx.clock)
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


# ---- Fixed export, result, heartbeat and teardown --------------------------------------------------
def export_viewer(nonce):
    value = contract_value(nonce)
    state = load_state(nonce)
    base.require(state['steps']['viewer-ready'] == 'ok' and state['failure'] is None, 'handoff unavailable')
    gate(value)
    raw = base.regular(WORK / 'viewer-handoff.json', 1024, 0, 0o600)
    validate_handoff(base.data(raw), nonce)
    return raw


def result(nonce):
    contract_value(nonce)
    return base.encoded(validate_result(public_record(load_state(nonce)), nonce))


def heartbeat(nonce, sequence):
    value = contract_value(nonce)
    base.require(type(sequence) is int and sequence > 0)
    ManagementClock(value).remaining('persistence')
    base.require(base.kernel_boot() == value['boot_uuid'])
    old = base.data(base.regular(MROOT / 'heartbeat.json', 4096, 0))
    base.require(sequence == old['sequence'] + 1)
    base.atomic(MROOT / 'heartbeat.json', {'sequence': sequence, 'received': time.monotonic()})


def teardown(nonce):
    """Positive, idempotent removal of exactly what this program created; uncertainty is reported."""
    value = contract_value(nonce)
    state = load_state(nonce)
    if state['teardown'] == 'complete':
        return 0
    ctx = Context(value, ManagementClock(value), state)
    private = state['private']
    clean = not private.get('child_cleanup_uncertain', False)

    def attempt(argv, cap):
        try:
            return run_tool(ctx, argv, None, cap, cleanup=True)
        except BaseException:
            return None

    if private.get('cluster_attempted'):
        if attempt([K3D, 'cluster', 'delete', CLUSTER], 120) is None:
            clean = False
        listing = attempt([DOCKER, 'ps', '--all', '--quiet', '--filter', 'name=k3d-' + CLUSTER], 30)
        clean = clean and listing is not None and listing.strip() == b''
    if private.get('docker_started') or private.get('docker_intent'):
        units = [SYSTEMCTL, 'stop', 'docker.socket', 'docker.service', 'containerd.service']
        clean = attempt(units, 30) is not None and clean
    for name in PRIVATE_FILES:
        path = WORK / name
        try:
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
    if recorded is not None:
        try:
            info = os.lstat(STORAGE)
            if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and [info.st_dev, info.st_ino] == recorded:
                shutil.rmtree(STORAGE)
            clean = clean and not os.path.lexists(STORAGE)
        except FileNotFoundError:
            pass
        except BaseException:
            clean = False
    state['teardown'] = 'complete' if clean else 'uncertain'
    save_state(state)
    return 0 if clean else 1


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
    ManagementClock(value).remaining('stage')
    base.require(not MROOT.exists(), 'one-shot root reservation collision')
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


def main(argv=None):
    refuse_activation()
    return dispatch(argv)


def dispatch(argv=None):
    """Internal fixed dispatcher; reachable only through ``main`` after a future reviewed activation."""
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('action', choices=('step', 'heartbeat', 'export-viewer', 'result', 'teardown'))
    parser.add_argument('--nonce', required=True)
    parser.add_argument('--name', choices=STEP_NAMES)
    parser.add_argument('--sequence', type=int)
    args = parser.parse_args(argv)
    base.require(os.geteuid() == 0, 'root required')
    os.umask(0o077)
    sys.path.insert(0, str(MROOT))
    if args.action == 'step':
        base.require(args.name is not None and args.sequence is None)
        run_step(args.nonce, args.name)
    elif args.action == 'heartbeat':
        base.require(args.name is None and args.sequence is not None)
        heartbeat(args.nonce, args.sequence)
    else:
        base.require(args.name is None and args.sequence is None)
        if args.action == 'teardown':
            return teardown(args.nonce)
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
