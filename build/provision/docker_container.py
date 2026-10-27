"""Test-only driver inside the one owned Docker package container; never a cloud entrypoint.

Runs as root in a fresh Ubuntu 24.04 amd64 container with Python 3.12 and real
native APT. It denies service startup, then runs the unchanged install-docker.py
twice in this SAME target (install, then rerun), with its own independent
before/after probes. It does not install, repair or retry anything itself, and a
failure is never rerun or widened. Daemon/systemd readiness is not proved here.
"""
import argparse
import json
import os
from pathlib import Path
import re
import runpy
import sys
import stat
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
TRANSPORT = re.compile(rb'(?i)\b50[0-9]\b|bad gateway|service unavailable|gateway time-?out|'
                       rb'connection (timed out|failed|reset)|could not (connect|resolve)|'
                       rb'temporary failure|timed out')
MAX_STDOUT, MAX_REPORT, DETAIL, BUDGET_MAX = 1024 * 1024, 60 * 1024, 4096, 600


class Finding(Exception):
    """A harness assertion about observed state failed; fixed safe message."""


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
        return [digest(SENTINEL), info.st_ino, info.st_size, info.st_mtime_ns]

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
        if os.path.lexists(SENTINEL):
            raise Refusal('fixture path already exists; target is not fresh')
        policy_existing = os.path.lexists(POLICY)
        original_sha = None
        if policy_existing:
            info = POLICY.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > 4096):
                raise Refusal('unsafe existing service denial policy')
            # Preserve the original trusted image fixture, but never execute it.
            original_sha = digest(POLICY)
            backup = POLICY.with_name('policy-rc.d.labapp-original')
            if os.path.lexists(backup):
                raise Refusal('service policy backup collision')
            os.link(POLICY, backup, follow_symlinks=False)
            POLICY.unlink()
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
        return {'policy_rc_d': 'exit 101 (service startup denied)',
                'policy_preexisting': policy_existing, 'original_policy_sha256': original_sha, 'policy_sha256': digest(POLICY),
                'docker_data_sentinel': True}


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


def unqualified(packages, arch):
    """Comparison-only view: strip dpkg's native `:arch` qualifier (Multi-Arch: same `${binary:Package}`).

    Any other qualifier or a name collision after stripping is drift, never normalized away.
    The caller's original keys remain the state/receipt identity.
    """
    result = {}
    for name, version in packages.items():
        base, sep, qualifier = name.partition(':')
        if sep and (qualifier != arch or not base):
            raise Finding('installed package has an unexpected architecture qualifier')
        if base in result:
            raise Finding('package names collide after architecture normalization')
        result[base] = version
    return result


def check_first(c, before, after, out, sources, arch='amd64'):
    common(before)
    common(after)
    if any(after['packages'].get(n) != v for n, v in before['packages'].items()):
        raise Finding('a preexisting package was removed or changed')
    if after['sentinel'] != before['sentinel']:
        raise Finding('Docker data sentinel identity changed')
    if after['holds'] != before['holds'] or after['apt'] != before['apt']:
        raise Finding('holds or global APT configuration changed')
    if any(after['packages'].get(n) != v for n, v in c['pins'].items()):
        raise Finding('exact Docker trio versions are not installed')
    closure = {n: v for n, v in after['packages'].items() if n not in before['packages']}
    bare = unqualified(closure, arch)
    if not set(c['pins']) <= set(bare) or len(closure) > c['max_plan']:
        raise Finding('selected dependency closure is not a fresh bounded trio install')
    archives = {row['package']: row for row in out.get('downloaded_archives', [])}
    if ({n: row['version'] for n, row in archives.items()} != bare
            or any(archives[n]['sha256'] != sha for n, sha in c['archives'].items())):
        raise Finding('downloaded archives differ from installed closure or declared trio hashes')
    if (out.get('pins'), out.get('archives'), out.get('key_sha256')) != (c['pins'], c['archives'], c['key_sha256']):
        raise Finding('installer identity differs from reviewed pins/hashes/key')
    if out.get('changed') is not True:
        raise Finding('first run did not report a change')
    receipt_matches(out, after, sources)
    return closure


def check_rerun(c, first, second, out, sources):
    common(second)
    if second['sentinel'] != first['sentinel']:
        raise Finding('Docker data sentinel identity changed')
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


def run_once(installer, receipt, remaining, run=bounded):
    """Run the unchanged normal CLI in a bounded, clean-environment subprocess."""
    if remaining < 240:
        raise Refusal('insufficient total budget for a bounded installer run')
    code, output = run(['/usr/bin/python3', str(installer), '--receipt', str(receipt)],
                       240, limit=MAX_STDOUT, env=dict(ENV))
    if code:
        raise Refusal(f'installer CLI failed: code={code!r} output_tail={output[-DETAIL:]!r}')
    return json.loads(output)


def execute(system, installer, budget, base, load=load_installer, clock=time.monotonic,
            receipt=RECEIPT, sources=None, run=bounded):
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
        report['prepared_packages'] = before['packages']
        previous = None
        for number in (1, 2):
            report['phase'] = 'install' if number == 1 else 'rerun'
            report['runs'].append({'run': number, 'invocation': 'python3 install-docker.py --receipt PATH'})
            run_started = clock()
            out = run_once(installer, receipt, budget - (clock() - started), run=run)
            report['runs'][-1]['seconds'] = round(clock() - run_started, 3)
            report['runs'][-1]['installer_output'] = out
            state = snapshot(system, paths)
            if number == 1:
                report['closure'] = check_first(c, before, state, out, sources,
                                                  report['fixture']['architecture'])
            else:
                check_rerun(c, previous, state, out, sources)
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
    encoded = json.dumps(report, sort_keys=True)
    if len(encoded.encode()) > MAX_REPORT:
        # A bounded explicit failure, preserving an existing primary exit status.
        code = code or 1
        encoded = json.dumps({'result': 'fail', 'error': 'aggregate evidence report exceeds byte cap',
                              'primary_exit_code': code, 'report_byte_cap': MAX_REPORT})
    print(encoded, flush=True)
    return code


if __name__ == '__main__':
    sys.exit(main())
