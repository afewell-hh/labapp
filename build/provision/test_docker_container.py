"""Offline lifecycle/failure tests for the Docker package container harness.

No APT, network, container, Docker daemon or system change: the driver runs against a
synthetic in-memory target and installer, and the host launcher runs against a fake
`docker` executable that models daemon state. These tests cannot show that the pinned
Docker packages install; only the separately authorized native run can.
"""
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import docker_container as dc
from contextlib import redirect_stdout
from hhfab_release import Refusal

RUNNER = Path(__file__).with_name('test-docker.sh')
V, C = '5:29.1.3-1~ubuntu.24.04~noble', '2.2.1-1~ubuntu.24.04~noble'
SOURCES = {'install-docker.py': 's1' * 32, 'hhfab_release.py': 's2' * 32}
ARCHIVES = {'docker-ce': 'a' * 64, 'docker-ce-cli': 'b' * 64, 'containerd.io': 'c' * 64}
PINS = {'docker-ce': V, 'docker-ce-cli': V, 'containerd.io': C}
KEY = 'k' * 64
APT = '/usr/bin/apt-get'


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class FakeSystem:
    """In-memory target exposing the same probes as dc.System."""
    def __init__(self):
        self.pkgs = {'bash': '5.2', 'curl': '8.5'}
        self.hold_list, self.audit_text, self.daemon_list = [], '', []
        self.apt = {'apt.conf.d/10': 'h'}
        self.payload_map, self.receipt_value, self.sentinel_value = {}, None, None

    def fixture(self):
        return {'os_release': {'ID': 'ubuntu'}, 'packages': dict(self.pkgs), 'architecture': 'amd64'}

    def plant(self):
        self.sentinel_value = [1, 2, 3]
        return {'policy_rc_d': 'exit 101', 'docker_data_sentinel': True}

    def packages(self):
        return dict(self.pkgs)

    def holds(self):
        return list(self.hold_list)

    def audit(self):
        return self.audit_text

    def apt_tree(self):
        return dict(self.apt)

    def payloads(self, relatives):
        return {r: list(self.payload_map[r]) for r in relatives}

    def receipt(self):
        return json.loads(json.dumps(self.receipt_value))

    def sentinel(self):
        return self.sentinel_value

    def daemons(self):
        return list(self.daemon_list)


def receipt_data(system):
    return {'pins': PINS, 'archives': ARCHIVES, 'key_sha256': KEY, 'installed': dict(system.pkgs),
            'payload_sha256': {r: row[0] for r, row in system.payload_map.items()},
            'module': dict(SOURCES)}


def install_effect(system):
    system.pkgs.update({**PINS, 'iptables': '1.8'})
    system.payload_map = {'usr/bin/dockerd': ['p' * 64, 10, 20]}
    system.receipt_value = {'identity': ['r' * 64, 30, 40, 100], 'data': receipt_data(system)}


def archive_rows(system):
    return [{'package': n, 'version': v, 'sha256': ARCHIVES.get(n, 'd' * 64), 'bytes': 1}
            for n, v in system.pkgs.items() if n not in ('bash', 'curl')]


class World:
    """Synthetic CLI boundary; never starts the native installer."""
    def __init__(self, system, clock, plans):
        self.system, self.clock, self.plans, self.count = system, clock, plans, 0
        self.fail_stage, self.fail_message = None, ''

    def run(self, args, seconds, limit, env):
        assert args == ['/usr/bin/python3', 'install-docker.py', '--receipt', str(dc.RECEIPT)]
        assert seconds == 240 and limit == dc.MAX_STDOUT and env == dc.ENV
        plan = self.plans[self.count]
        self.count += 1
        if self.fail_stage:
            return 1, self.fail_message.encode()
        self.clock.now += plan.get('elapsed', 1)
        if plan.get('interrupt'):
            raise KeyboardInterrupt
        plan['effect'](self.system)
        out = {**receipt_data(self.system), 'changed': plan['changed'],
               'downloaded_archives': plan['archives'](self.system), 'seconds': 1.0}
        plan.get('tweak', lambda o: None)(out)
        return 0, json.dumps(out).encode()


def run_case(first=None, rerun=None, budget=600, fail_stage=None, fail_message='', mutate=None):
    system, clock = FakeSystem(), Clock()
    first_plan = {'effect': install_effect, 'changed': True, 'archives': archive_rows}
    rerun_plan = {'effect': lambda s: None, 'changed': False, 'archives': lambda s: []}
    first_plan.update(first or {})
    rerun_plan.update(rerun or {})
    world = World(system, clock, [first_plan, rerun_plan])
    world.fail_stage, world.fail_message = fail_stage, fail_message
    if mutate:
        mutate(system)

    def load(_path):
        return {'PINS': PINS, 'ARCHIVES': ARCHIVES, 'KEY_SHA256': KEY, 'MAX_PLAN': 32,
                'PAYLOADS': {'docker-ce': 'usr/bin/dockerd'}, 'EXTRA_PAYLOADS': ()}
    report, code = dc.execute(system, Path('install-docker.py'), budget, 'ubuntu@sha256:test',
                              load=load, clock=clock, sources=SOURCES, run=world.run)
    return report, code, system, world


class DriverTests(unittest.TestCase):
    def test_install_then_rerun_in_same_target_passes_with_evidence(self):
        report, code, system, world = run_case()
        self.assertEqual((code, report['result'], world.count), (0, 'pass', 2))
        self.assertEqual(len(report['runs']), 2)
        self.assertEqual(report['closure'], {**PINS, 'iptables': '1.8'})
        self.assertEqual(report['base'], 'ubuntu@sha256:test')
        self.assertEqual(report['source_sha256'], SOURCES)
        self.assertEqual(report['fixture']['docker_data_sentinel'], True)
        self.assertEqual(report['receipt_sha256'], 'r' * 64)
        self.assertEqual(report['prepared_packages'], {'bash': '5.2', 'curl': '8.5'})
        self.assertEqual(report['runs'][0]['installer_output']['downloaded_archives'], archive_rows(system))
        self.assertEqual(report['runs'][1]['installer_output']['module'], SOURCES)
        json.dumps(report)

    def failure(self, expected, **kw):
        report, code, _, world = run_case(**kw)
        self.assertEqual((code, report['result']), (1, 'fail'), report)
        self.assertIn(expected, report['error'])
        return report, world

    def test_rerun_state_and_identity_must_be_preserved(self):
        def package(s): s.pkgs['extra'] = '1'
        def payload(s): s.payload_map['usr/bin/dockerd'] = ['p' * 64, 11, 20]
        def receipt(s): s.receipt_value['identity'][1] = 99
        def sentinel(s): s.sentinel_value = [9, 2, 3]
        for effect, text in ((package, 'rerun changed packages'), (payload, 'payload identity'),
                             (receipt, 'receipt identity'), (sentinel, 'sentinel')):
            with self.subTest(text):
                self.failure(text, rerun={'effect': effect})
        self.failure('reported a change', rerun={'changed': True})
        self.failure('reported a change', rerun={'archives': archive_rows})

    def test_removal_upgrade_hold_policy_and_data_changes_fail(self):
        def remove(s): install_effect(s); s.pkgs.pop('bash')
        def upgrade(s): install_effect(s); s.pkgs['bash'] = '5.3'
        def hold(s): install_effect(s); s.hold_list.append('bash')
        def policy(s): install_effect(s); s.apt['apt.conf.d/99'] = 'new'
        def sentinel(s): install_effect(s); s.sentinel_value = None
        def replace_sentinel(s): install_effect(s); s.sentinel_value = [9, 2, 3]
        def daemon(s): install_effect(s); s.daemon_list.append('dockerd')
        def audit(s): install_effect(s); s.audit_text = 'half-installed'
        for effect, text in ((remove, 'removed or changed'), (upgrade, 'removed or changed'),
                             (hold, 'held packages'), (policy, 'global APT'),
                             (sentinel, 'sentinel'), (replace_sentinel, 'sentinel'), (daemon, 'daemon'), (audit, 'audit')):
            with self.subTest(effect.__name__):
                report, world = self.failure(text, first={'effect': effect})
                self.assertEqual(world.count, 1, 'a failure must never trigger the rerun')

    def test_exact_trio_archive_hash_and_closure_identity(self):
        def wrong_hash(out): out['downloaded_archives'][0]['sha256'] = 'z' * 64
        def missing(out): out['downloaded_archives'].pop()
        def wrong_key(out): out['key_sha256'] = '0' * 64
        def trio_missing(s): install_effect(s); s.pkgs.pop('docker-ce-cli')
        self.failure('downloaded archives differ', first={'tweak': wrong_hash})
        self.failure('downloaded archives differ', first={'tweak': missing})
        self.failure('installer identity differs', first={'tweak': wrong_key})
        self.failure('Docker trio', first={'effect': trio_missing})
        self.failure('fresh bounded', mutate=lambda s: s.pkgs.update(PINS))

    def test_receipt_must_bind_state_payload_and_source_hashes(self):
        def installed(s): install_effect(s); s.receipt_value['data']['installed'] = {}
        def payload(s): install_effect(s); s.receipt_value['data']['payload_sha256'] = {'usr/bin/dockerd': 'q' * 64}
        def module(s): install_effect(s); s.receipt_value['data']['module'] = {}
        def gone(s): install_effect(s); s.receipt_value = None
        for effect in (installed, payload, module):
            with self.subTest(effect.__name__):
                report, _ = self.failure('', first={'effect': effect})
                self.assertTrue(report['error'])
        self.failure('receipt missing', first={'effect': gone})

    def test_transport_failure_is_final_with_primary_error_and_no_rerun(self):
        message = "command failed: apt-get code=100 output_tail=b'E: Failed to fetch 503 Service Unavailable'"
        report, code, system, world = run_case(fail_stage='update', fail_message=message)
        self.assertEqual((code, report['result'], world.count), (1, 'fail', 1))
        self.assertTrue(report['transport_suspected'])
        self.assertIn('503 Service Unavailable', report['error'])
        self.assertEqual(len(report['runs']), 1)
        self.assertEqual(system.pkgs, {'bash': '5.2', 'curl': '8.5'})

    def test_unresolved_dependency_failure_is_not_classified_as_transport(self):
        report, code, _, world = run_case(
            fail_stage='simulate', fail_message="command failed: apt-get code=100 output_tail=b'E: Unable to locate package'")
        self.assertEqual((code, world.count), (1, 1))
        self.assertFalse(report['transport_suspected'])
        self.assertIn('Unable to locate package', report['error'])

    def test_error_text_is_bounded_and_escaped(self):
        report, code, _, _ = run_case(fail_stage='update', fail_message='\x1b[31m' + 'x' * 10000)
        self.assertEqual(code, 1)
        self.assertLessEqual(len(report['error']), 2 * dc.DETAIL + 256)
        self.assertNotIn('\x1b', report['error'])

    def test_total_budget_is_not_widened(self):
        report, code, _, world = run_case(budget=100)
        self.assertEqual((code, world.count), (1, 0))
        self.assertIn('insufficient total budget', report['error'])
        report, code, _, world = run_case(first={'elapsed': 400})
        self.assertEqual((code, world.count, len(report['runs'])), (1, 1, 2))
        self.assertIn('insufficient total budget', report['error'])
        self.assertEqual(report['phase'], 'rerun')

    def test_interruption_is_reported_as_130_without_rerun(self):
        report, code, _, world = run_case(first={'interrupt': True})
        self.assertEqual((code, report['result'], world.count), (130, 'interrupted', 1))

    def test_cli_boundary_preserves_failure_and_bounded_output(self):
        with self.assertRaisesRegex(Refusal, 'CLI failed'):
            dc.run_once(Path('installer'), Path('receipt'), 500,
                        run=lambda *a, **kw: (130, b'interrupted'))
        with self.assertRaisesRegex(Refusal, 'insufficient'):
            dc.run_once(Path('installer'), Path('receipt'), 239)

    def test_real_installer_exposes_every_value_the_driver_reads(self):
        module = dc.load_installer(Path(__file__).with_name('install-docker.py'))
        for name in ('PINS', 'ARCHIVES', 'KEY_SHA256', 'MAX_PLAN', 'ALARM', 'PAYLOADS', 'EXTRA_PAYLOADS', 'main', 'call'):
            self.assertIn(name, module)
        self.assertIs(module['install'].__globals__['call'], module['call'])
        self.assertGreater(dc.BUDGET_MAX, 2 * 240)


class SystemProbeTests(unittest.TestCase):
    def probe(self, output, code=0):
        return patch.object(dc, 'bounded', lambda args, seconds, env=None, **kw: (code, output))

    def test_package_hold_and_audit_parsing(self):
        with self.probe(b'bash\t5.2\tinstalled\nold\t1\tconfig-files\n'):
            self.assertEqual(dc.System().packages(), {'bash': '5.2'})
        with self.probe(b'bash\tinstall\nfoo\thold\n'):
            self.assertEqual(dc.System().holds(), ['foo'])
        with self.probe(b' half-installed\n'):
            self.assertEqual(dc.System().audit(), 'half-installed')
        with self.probe(b'secret-looking output', code=2), self.assertRaises(Refusal) as raised:
            dc.System().packages()
        self.assertNotIn('secret', str(raised.exception))

    def test_file_probes_hash_links_and_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'apt' / 'sub').mkdir(parents=True)
            (root / 'apt' / 'sub' / 'f').write_text('x')
            os.symlink('target', root / 'apt' / 'l')
            receipt, sentinel = root / 'receipt.json', root / 'sentinel'
            receipt.write_text('{"a": 1}')
            sentinel.write_text('s')
            with patch.object(dc, 'APT_ROOT', root / 'apt'), patch.object(dc, 'RECEIPT', receipt), \
                    patch.object(dc, 'SENTINEL', sentinel):
                system = dc.System()
                tree = system.apt_tree()
                self.assertEqual(tree['l'], 'link:target')
                self.assertEqual(set(tree), {'l', 'sub/f'})
                self.assertEqual(system.receipt()['data'], {'a': 1})
                self.assertEqual(system.receipt(), system.receipt())
                self.assertEqual(len(system.sentinel()), 4)
                rows = system.payloads([str(receipt).lstrip('/')])
                self.assertEqual(len(next(iter(rows.values()))), 3)
                sentinel.unlink()
                self.assertIsNone(system.sentinel())

    def test_plant_denies_services_and_refuses_used_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, sentinel = root / 'policy-rc.d', root / 'lib' / 'docker' / '.sentinel'
            with patch.object(dc, 'POLICY', policy), patch.object(dc, 'SENTINEL', sentinel):
                result = dc.System().plant()
                self.assertTrue(result['docker_data_sentinel'] and sentinel.is_file())
                self.assertEqual(subprocess.run([str(policy), 'docker', 'start']).returncode, 101)
                with self.assertRaisesRegex(Refusal, 'not fresh'):
                    dc.System().plant()
            policy.unlink()
            sentinel.unlink()
            sentinel.parent.rmdir()
            with patch.object(dc, 'POLICY', policy), patch.object(dc, 'SENTINEL', sentinel), \
                    patch.object(dc, 'bounded', lambda *a, **k: (0, b'')):
                with self.assertRaisesRegex(Refusal, 'not effective'):
                    dc.System().plant()

    def test_existing_regular_service_policy_is_preserved_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, sentinel = root / 'policy-rc.d', root / 'data' / 'sentinel'
            original = b'#!/bin/sh\nexit 42\n'
            policy.write_bytes(original)
            policy.chmod(0o755)
            with patch.object(dc, 'POLICY', policy), patch.object(dc, 'SENTINEL', sentinel):
                result = dc.System().plant()
            self.assertTrue(result['policy_preexisting'])
            self.assertEqual(policy.with_name('policy-rc.d.labapp-original').read_bytes(), original)
            self.assertEqual(policy.read_bytes(), b'#!/bin/sh\nexit 101\n')
            self.assertEqual(result['original_policy_sha256'], dc.digest(policy.with_name('policy-rc.d.labapp-original')))

    def test_aggregate_report_overflow_is_failure_and_preserves_primary_status(self):
        for primary, expected in ((0, 1), (1, 1), (130, 130)):
            with patch.object(dc, 'execute', return_value=({'result': 'pass', 'large': 'x' * dc.MAX_REPORT}, primary)), \
                    patch('sys.stdout', io.StringIO()) as out:
                code = dc.main(['run', '--budget', '500'], system=object())
            self.assertEqual(code, expected)
            report = json.loads(out.getvalue())
            self.assertEqual(report['result'], 'fail')
            self.assertIn('exceeds byte cap', report['error'])
            self.assertLess(len(out.getvalue().encode()), dc.MAX_REPORT)

    def test_cli_validates_budget_and_returns_driver_exit_code(self):
        for bad in ('0', '601'):
            with patch('sys.stderr', io.StringIO()), self.assertRaises(SystemExit):
                dc.main(['run', '--budget', bad])
        for code in (0, 1, 130):
            with patch.object(dc, 'execute', return_value=({'result': 'x'}, code)), \
                    patch('sys.stdout', io.StringIO()) as out:
                self.assertEqual(dc.main(['run', '--budget', '500', '--base', 'b'], system=object()), code)
            self.assertEqual(json.loads(out.getvalue()), {'result': 'x'})


FAKE_DOCKER = r'''#!/usr/bin/python3
import hashlib, json, os, sys, time
from pathlib import Path

path = Path(os.environ['FAKE_DOCKER_STATE'])
s = json.loads(path.read_text())
a = sys.argv[1:]
modes = set(os.environ['FAKE_DOCKER_MODE'].split('+'))
s['calls'].append(a)
s.setdefault('config', os.environ.get('DOCKER_CONFIG'))

def save():
    path.write_text(json.dumps(s))

def option(name):
    return a[a.index(name) + 1]

if a[0] == 'version':
    print('Docker server synthetic')
elif a[0] == 'create':
    name, label = option('--name'), option('--label')
    ident = hashlib.sha256(name.encode()).hexdigest()
    s['create'] = a
    if 'name_collision' in modes:
        s['containers'][ident] = {'id': ident, 'name': name, 'label': 'foreign-owner=1'}
        save()
        sys.exit(125)
    s['containers'][ident] = {'id': ident, 'name': name, 'label': label}
    s['containers']['f' * 64] = {'id': 'f' * 64, 'name': name + '-foreign', 'label': label}
    save()
    if 'create_lost' in modes:
        sys.exit(124)
    print(ident)
elif a[:2] == ['image', 'inspect']:
    print('Base sha256:synthetic ["ubuntu@sha256:synthetic"]')
elif a[0] == 'start':
    save()
    if 'hang' in modes:
        Path(os.environ['FAKE_DOCKER_MARK']).write_text(str(os.getpid()))
        time.sleep(60)
    if 'timeout' in modes:
        sys.exit(124)
    ok = 'guest_fail' not in modes
    print(json.dumps({'result': 'pass' if ok else 'fail'}))
    sys.exit(0 if ok else 1)
elif a[0] == 'inspect':
    fmt = option('--format')
    create = s['create']
    if 'State.ExitCode' in fmt:
        print('1' if 'guest_fail' in modes else '124' if 'timeout' in modes else '0')
    elif 'OOMKilled' in fmt:
        print('true' if 'oom' in modes else 'false')
    elif 'HostConfig.Privileged' in fmt:
        bind = create[create.index('-v') + 1]
        print('privileged=%s memory=%d nano_cpus=%d pids=%s binds=%s' % (
            'true' if 'privileged' in modes else 'false', 1 << 30, 2 * 10 ** 9,
            [x for x in create if x.startswith('--pids-limit=')][0].split('=')[1], json.dumps([bind])))
    else:
        print('swap=%s network=default security=["no-new-privileges"] cap_drop=["NET_RAW"] devices=[]' % ('0' if 'swap_drift' in modes else '1073741824'))
elif a[:2] == ['container', 'ls']:
    if 'daemon_down' in modes:
        save()
        sys.exit(1)
    filters = [a[i + 1] for i, v in enumerate(a) if v == '--filter']
    for obj in s['containers'].values():
        if all({'name': lambda v: v == '^/' + obj['name'] + '$', 'label': lambda v: v == obj['label']}[f.split('=', 1)[0]](f.split('=', 1)[1])
               for f in filters):
            print(obj['id'])
elif a[0] == 'rm':
    assert a[1] == '-fv' and not s['containers'][a[-1]]['name'].endswith('-foreign')
    s['containers'].pop(a[-1])
else:
    raise AssertionError(a)
save()
'''


class HostLauncherTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        fake = root / 'docker'
        fake.write_text(FAKE_DOCKER)
        fake.chmod(0o755)
        self.state = root / 'state.json'
        self.state.write_text(json.dumps({'containers': {}, 'calls': []}))
        self.mark = root / 'mark'
        self.root = root

    def environment(self, mode):
        return dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ['PATH'],
                    FAKE_DOCKER_STATE=str(self.state), FAKE_DOCKER_MODE=mode, FAKE_DOCKER_MARK=str(self.mark),
                    AWS_SECRET_ACCESS_KEY='host-secret')

    def launch(self, mode, *args):
        result = subprocess.run(['bash', str(RUNNER), *args], env=self.environment(mode),
                                capture_output=True, text=True, timeout=30)
        return result, json.loads(self.state.read_text())

    def assert_owned_gone(self, state):
        names = [obj['name'] for obj in state['containers'].values()]
        self.assertTrue(names and all(name.endswith('-foreign') for name in names), names)

    def test_success_uses_one_contained_target_and_removes_it(self):
        result, state = self.launch('success')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"result": "pass"', result.stdout)
        self.assert_owned_gone(state)
        create = state['create']
        text = ' '.join(create)
        for required in ('--platform=linux/amd64', '--init', '--memory=1g', '--memory-swap=1g', '--cpus=2', '--pids-limit=128',
                         '--security-opt=no-new-privileges', '--cap-drop=NET_RAW', '--label'):
            self.assertIn(required, create)
        for flag in ('--privileged', '--network', '--net', '--pid', '--ipc', '--uts', '--userns', '--device',
                     '--volumes-from', '--env-file', '--add-host', '--cap-add', '--pull'):
            self.assertFalse([arg for arg in create if arg == flag or arg.startswith(flag + '=')], flag)
        for forbidden in ('docker.sock', 'host-secret', 'hello-world'):
            self.assertNotIn(forbidden, text)
        mounts = [create[i + 1] for i, v in enumerate(create) if v in ('-v', '--volume', '--mount')]
        self.assertEqual(len(mounts), 1)
        self.assertTrue(mounts[0].endswith(':/suite:ro'))
        self.assertIn('ubuntu@sha256:', text)
        self.assertEqual([c[0] for c in state['calls']].count('create'), 1)
        self.assertEqual([c[0] for c in state['calls']].count('start'), 1)
        self.assertLessEqual({c[0] for c in state['calls']}, {'version', 'create', 'image', 'start', 'inspect', 'container', 'rm'})
        self.assertIn('docker-config', state['config'])
        self.assertFalse(os.path.exists(state['config']), 'private config/workdir must be removed')

    def test_guest_failure_keeps_primary_result_and_cleans_up(self):
        result, state = self.launch('guest_fail')
        self.assertEqual(result.returncode, 1)
        self.assertIn('"result": "fail"', result.stdout)
        self.assert_owned_gone(state)

    def test_supervisor_timeout_is_labeled_and_not_pass(self):
        result, state = self.launch('timeout')
        self.assertEqual(result.returncode, 124)
        self.assertIn('supervisor timeout; not native APT evidence', result.stderr)
        self.assert_owned_gone(state)

    def test_cleanup_failure_never_replaces_primary_failure(self):
        result, _ = self.launch('timeout+daemon_down')
        self.assertEqual(result.returncode, 124)
        self.assertIn('owned cleanup failed', result.stderr)
        result, _ = self.launch('daemon_down')
        self.assertEqual(result.returncode, 1, 'cleanup failure alone is a failure')

    def test_unapplied_containment_or_oom_is_failure(self):
        for mode, text in (('privileged', 'containment differs'), ('swap_drift', 'containment differs'), ('oom', 'oom=true')):
            with self.subTest(mode):
                self.state.write_text(json.dumps({'containers': {}, 'calls': []}))
                result, state = self.launch(mode)
                self.assertEqual(result.returncode, 1)
                self.assertIn(text, result.stderr)
                self.assert_owned_gone(state)

    def test_lost_create_response_recovers_exact_owned_container(self):
        result, state = self.launch('create_lost')
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assert_owned_gone(state)
        self.assertFalse(any(c[0] == 'start' for c in state['calls']))

    def test_exact_name_with_foreign_label_is_never_removed(self):
        result, state = self.launch('name_collision')
        self.assertEqual(result.returncode, 125)
        self.assertFalse(any(c[0] == 'rm' for c in state['calls']))
        self.assertEqual(len(state['containers']), 1)

    def test_cancellation_removes_target_and_stops_supervising_client(self):
        process = subprocess.Popen(['bash', str(RUNNER)], env=self.environment('hang'),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(process.kill)
        deadline = time.monotonic() + 20
        while not self.mark.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(self.mark.exists(), 'fake start never began')
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=30)
        self.assertEqual(process.returncode, 143)
        self.assert_owned_gone(json.loads(self.state.read_text()))
        pid = int(self.mark.read_text())
        for _ in range(100):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            self.fail('supervising docker client survived cancellation')

    def test_arguments_are_rejected_before_any_docker_call(self):
        result, state = self.launch('success', '--unexpected')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state['calls'], [])

    def test_script_declares_budget_and_has_no_cloud_or_secret_surface(self):
        text = RUNNER.read_text()
        for expected in ('total=600', 'timeout --kill-after=5s 570s', '--pids-limit=128', '--cpus=2',
                         'docker rm -fv', 'DOCKER_CONFIG', 'ubuntu@sha256:'):
            self.assertIn(expected, text)
        for forbidden in ('gcloud', 'docker run', 'docker pull', 'hello-world', '--privileged', 'docker.sock'):
            self.assertNotIn(forbidden, text)


if __name__ == '__main__':
    unittest.main()
