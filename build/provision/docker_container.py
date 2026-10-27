"""Test-only driver inside the one owned Docker package container; never a cloud entrypoint.

Runs as root in a fresh Ubuntu 24.04 amd64 container with Python 3.12 and real
native APT. It denies service startup, then runs the unchanged install-docker.py
twice in this SAME target (install, then rerun), with its own independent
before/after probes. It does not install, repair or retry anything itself, and a
failure is never rerun or widened. Daemon/systemd readiness is not proved here.
"""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import sys
import time

from hhfab_release import Refusal, bounded, digest

RECEIPT = Path('/var/tmp/labapp-docker-receipt.json')
POLICY = Path('/usr/sbin/policy-rc.d')
SENTINEL = Path('/var/lib/docker/.labapp-sentinel')
APT_ROOT = Path('/etc/apt')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'}
FIXTURE_PACKAGES = ('python3', 'python3.12', 'curl', 'libcurl4t64', 'ca-certificates',
                    'ubuntu-keyring', 'apt', 'dpkg')
DAEMONS = ('dockerd', 'containerd', 'containerd-shim')  # /proc comm names (15 chars max)
# Installer stages that prove authentication/transaction order; other calls are ignored.
KEYED = ('key-fetch', 'update', 'check', 'simulate', 'download', 'install')
FIRST = ['key-fetch', 'update', 'check', 'simulate', 'download', 'simulate', 'install', 'check']
RERUN = ['key-fetch', 'update', 'check', 'check']
TRANSPORT = re.compile(rb'(?i)\b50[0-9]\b|bad gateway|service unavailable|gateway time-?out|'
                       rb'connection (timed out|failed|reset)|could not (connect|resolve)|'
                       rb'temporary failure|timed out')
MAX_STDOUT, MAX_LOG, DETAIL, BUDGET_MAX = 1024 * 1024, 256, 4096, 600


class Finding(Exception):
    """A harness assertion about observed state failed; fixed safe message."""


def stage_of(args):
    """Stage label for an installer child command (name only, never arguments)."""
    name = Path(args[0]).name
    if name == 'curl':
        return 'key-fetch'
    if name != 'apt-get':
        return name
    if '--simulate' in args:
        return 'simulate'
    for stage in ('update', 'check'):
        if args[-1] == stage:
            return stage
    if '--download-only' in args:
        return 'download'
    return 'install' if 'install' in args else 'other'


def instrument(original, log, clock=time.monotonic):
    """Observe the installer's own call(); results and exceptions pass through unchanged."""
    def call(args, seconds=10, env=None):
        started = clock()
        status = 'failed'
        try:
            result = original(args, seconds, env)
            status = 'ok'
            return result
        finally:
            # Never raise here: it would replace the installer's primary error. An
            # overflowing log is dropped and fails the stage-sequence check instead.
            if len(log) < MAX_LOG:
                log.append([stage_of(args), status, round(clock() - started, 3)])
    return call


class System:
    """Real read-only probes of this container (plus fixture planting); tests inject a fake."""
    def run(self, args, seconds=10):
        code, output = bounded(args, seconds, env=dict(ENV))
        if code:
            raise Refusal(f'probe failed: {Path(args[0]).name} code={code!r}')
        return output

    def packages(self):
        rows = self.run(['/usr/bin/dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\\n'])
        parts = [row.split('\t') for row in rows.decode().splitlines()]
        return {p[0]: p[1] for p in parts if len(p) == 3 and p[2] == 'installed'}

    def holds(self):
        rows = self.run(['/usr/bin/dpkg', '--get-selections']).decode().splitlines()
        return sorted(row.split()[0] for row in rows if row.split()[-1:] == ['hold'])

    def audit(self):
        return self.run(['/usr/bin/dpkg', '--audit']).decode().strip()

    def apt_tree(self):
        tree = {}
        for path in sorted(APT_ROOT.rglob('*')):
            rel = str(path.relative_to(APT_ROOT))
            if path.is_symlink():
                tree[rel] = 'link:' + os.readlink(path)
            elif path.is_file():
                tree[rel] = digest(path)
        return tree

    def payloads(self, relatives):
        found = {}
        for relative in relatives:
            info = os.lstat('/' + relative)
            found[relative] = [digest('/' + relative), info.st_ino, info.st_mtime_ns]
        return found

    def receipt(self):
        if not os.path.lexists(RECEIPT):
            return None
        info = os.lstat(RECEIPT)
        if info.st_size > 1024 * 1024:
            raise Refusal('oversized receipt')
        return {'identity': [digest(RECEIPT), info.st_ino, info.st_mtime_ns, info.st_size],
                'data': json.loads(RECEIPT.read_bytes())}

    def sentinel(self):
        if not os.path.lexists(SENTINEL):
            return None
        info = os.lstat(SENTINEL)
        return [info.st_ino, info.st_size, info.st_mtime_ns]

    def daemons(self):
        found = []
        for entry in Path('/proc').iterdir():
            if entry.name.isdigit():
                try:
                    comm = (entry / 'comm').read_text().strip()
                except OSError:
                    continue
                if comm in DAEMONS:
                    found.append(comm)
        return sorted(found)

    def fixture(self):
        installed = self.packages()
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        return {'os_release': {k: release.get(k) for k in ('ID', 'VERSION_ID', 'VERSION_CODENAME')},
                'packages': {name: installed.get(name) for name in FIXTURE_PACKAGES},
                'architecture': self.run(['/usr/bin/dpkg', '--print-architecture']).decode().strip()}

    def plant(self):
        """Explicitly deny service startup and add a Docker-data sentinel; refuse a used target."""
        for path in (POLICY, SENTINEL):
            if os.path.lexists(path):
                raise Refusal('fixture path already exists; target is not fresh')
        descriptor = os.open(POLICY, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(b'#!/bin/sh\nexit 101\n')
        POLICY.chmod(0o755)
        if bounded([str(POLICY), 'docker', 'start'], 5, env=dict(ENV))[0] != 101:
            raise Refusal('service startup denial policy is not effective')
        SENTINEL.parent.mkdir(mode=0o755, parents=True)
        descriptor = os.open(SENTINEL, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(b'labapp docker data sentinel\n')
        return {'policy_rc_d': 'exit 101 (service startup denied)', 'docker_data_sentinel': True}


def snapshot(system, payload_paths):
    return {'packages': system.packages(), 'holds': system.holds(), 'audit': system.audit(),
            'apt': system.apt_tree(), 'payloads': system.payloads(payload_paths),
            'receipt': system.receipt(), 'sentinel': system.sentinel(), 'daemons': system.daemons()}


def common(state):
    if state['holds']:
        raise Finding('held packages present')
    if state['audit']:
        raise Finding('dpkg audit reports problems')
    if state['sentinel'] is None:
        raise Finding('Docker data sentinel removed')
    if state['daemons']:
        raise Finding('a Docker daemon process is running; service startup was denied')


def keyed(log):
    return [stage for stage, _, _ in log if stage in KEYED]


def receipt_matches(out, state, sources):
    receipt = state['receipt']
    if receipt is None:
        raise Finding('receipt missing')
    data = receipt['data']
    if any(out.get(key) != value for key, value in data.items()):
        raise Finding('installer output does not match its receipt')
    if data.get('installed') != state['packages']:
        raise Finding('receipt installed state differs from dpkg state')
    if data.get('payload_sha256') != {rel: row[0] for rel, row in state['payloads'].items()}:
        raise Finding('receipt payload hashes differ from installed payloads')
    if data.get('module') != {name: sources[name] for name in ('install-docker.py', 'hhfab_release.py')}:
        raise Finding('receipt module hashes differ from source hashes')


def check_first(c, before, after, out, log, sources):
    if keyed(log) != FIRST:
        raise Finding('first-run APT stage sequence is not the reviewed sequence')
    common(before)
    common(after)
    if any(after['packages'].get(n) != v for n, v in before['packages'].items()):
        raise Finding('a preexisting package was removed or changed')
    if after['holds'] != before['holds'] or after['apt'] != before['apt']:
        raise Finding('holds or global APT configuration changed')
    if any(after['packages'].get(n) != v for n, v in c['pins'].items()):
        raise Finding('exact Docker trio versions are not installed')
    closure = {n: v for n, v in after['packages'].items() if n not in before['packages']}
    if not set(c['pins']) <= set(closure) or len(closure) > c['max_plan']:
        raise Finding('selected dependency closure is not a fresh bounded trio install')
    archives = {row['package']: row for row in out.get('downloaded_archives', [])}
    if ({n: row['version'] for n, row in archives.items()} != closure
            or any(archives[n]['sha256'] != sha for n, sha in c['archives'].items())):
        raise Finding('downloaded archives differ from installed closure or declared trio hashes')
    if (out.get('pins'), out.get('archives'), out.get('key_sha256')) != (c['pins'], c['archives'], c['key_sha256']):
        raise Finding('installer identity differs from reviewed pins/hashes/key')
    if out.get('changed') is not True:
        raise Finding('first run did not report a change')
    receipt_matches(out, after, sources)
    return closure


def check_rerun(c, first, second, out, log, sources):
    if keyed(log) != RERUN:
        raise Finding('rerun did not re-authenticate and recheck without acquisition or install')
    common(second)
    if second['packages'] != first['packages'] or second['holds'] != first['holds'] or second['apt'] != first['apt']:
        raise Finding('rerun changed packages, holds or global APT configuration')
    if second['payloads'] != first['payloads']:
        raise Finding('rerun changed payload identity')
    if second['receipt'] != first['receipt']:
        raise Finding('rerun changed receipt identity')
    if out.get('changed') is not False or out.get('downloaded_archives') != []:
        raise Finding('rerun reported a change or acquired archives')
    receipt_matches(out, second, sources)


def load_installer(path):
    return runpy.run_path(str(path), run_name='labapp_docker_installer')


def run_once(load, installer, receipt, remaining, log, clock):
    module = load(installer)
    if remaining < module['ALARM'] + 5:
        raise Refusal('insufficient total budget for a bounded installer run')
    globals_ = module['install'].__globals__
    globals_['call'] = instrument(globals_['call'], log, clock)
    captured, argv = io.StringIO(), sys.argv
    sys.argv = [str(installer), '--receipt', str(receipt)]
    try:
        with contextlib.redirect_stdout(captured):
            module['main']()
    finally:
        sys.argv = argv
    text = captured.getvalue()
    if len(text) > MAX_STDOUT:
        raise Refusal('installer output overflow')
    return module, json.loads(text)


def execute(system, installer, budget, base, load=load_installer, clock=time.monotonic,
            receipt=RECEIPT, sources=None):
    """Returns (report, exit code). The first failure is final: no rerun, retry or repair."""
    started = clock()
    report = {'harness': 'labapp-docker-container-v1', 'base': base, 'budget_seconds': budget,
              'python': sys.version.split()[0], 'runs': [], 'phase': 'fixture', 'result': 'fail'}
    try:
        probe = load(installer)
        c = {'pins': probe['PINS'], 'archives': probe['ARCHIVES'], 'key_sha256': probe['KEY_SHA256'],
             'max_plan': probe['MAX_PLAN']}
        paths = [*probe['PAYLOADS'].values(), *probe['EXTRA_PAYLOADS']]
        report['source_sha256'] = sources = sources or {
            p.name: digest(p) for p in (installer, installer.with_name('hhfab_release.py'), Path(__file__))}
        report['fixture'] = {**system.fixture(), **system.plant()}
        before = snapshot(system, [])
        report['before_package_count'] = len(before['packages'])
        previous = None
        for number in (1, 2):
            report['phase'] = 'install' if number == 1 else 'rerun'
            log = []
            report['runs'].append({'run': number, 'stages': log})
            run_started = clock()
            _, out = run_once(load, installer, receipt, budget - (clock() - started), log, clock)
            report['runs'][-1]['seconds'] = round(clock() - run_started, 3)
            state = snapshot(system, paths)
            if number == 1:
                report['closure'] = check_first(c, before, state, out, log, sources)
            else:
                check_rerun(c, previous, state, out, log, sources)
            previous = state
        report['result'] = 'pass'
        report['phase'] = 'complete'
        report['receipt_sha256'] = previous['receipt']['identity'][0]
        code = 0
    except KeyboardInterrupt:
        report['result'], code = 'interrupted', 130
    except (Refusal, Finding, OSError, ValueError, KeyError) as exc:
        # Keep the primary error; the installer's own message already bounds APT output.
        message = str(exc)[:DETAIL]
        report['error'] = ascii(message)
        report['transport_suspected'] = bool(TRANSPORT.search(message.encode(errors='replace')))
        code = 1
    report['seconds'] = round(clock() - started, 3)
    return report, code


def main(argv=None, system=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['run'])
    parser.add_argument('--budget', type=int, required=True)
    parser.add_argument('--base', default='unrecorded')
    args = parser.parse_args(argv)
    if not 0 < args.budget <= BUDGET_MAX:
        parser.error('budget must be 1..%d seconds' % BUDGET_MAX)
    report, code = execute(system or System(), Path(__file__).with_name('install-docker.py'),
                           args.budget, args.base)
    print(json.dumps(report, sort_keys=True), flush=True)
    return code


if __name__ == '__main__':
    sys.exit(main())
