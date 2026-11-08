"""Source tests for student_vpc_pilot.py (issue #550). Temp directories, fakes and tiny local children only.

No guest, kubectl, dpkg, cluster, cloud or credential access: ``run_child`` is replaced by a synthetic kubectl/jq/dpkg
world, except ``RunChildTests`` which runs the real bounded runner on tiny ``sys.executable`` children. The only
credential-shaped values are synthetic canaries that must never reach any output or error. AUTHOR TESTS: NOT RUN by
the author; nothing here proves native kubectl, plugin, jq, dpkg or Fabric behavior.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import student_vpc_pilot as pilot

UID = '11111111-2222-3333-4444-555555555555'
CANARY = 'CANARY-SECRET-BYTES'
ORIGINAL_PACKAGE_STATE, ORIGINAL_STUDENT_CHILD = pilot.package_state, pilot.student_child


def good_spec():
    return {'ipv4Namespace': 'default', 'vlanNamespace': 'default', 'subnets': {
        'web-servers': {'subnet': '10.10.10.0/24', 'gateway': '10.10.10.1', 'vlan': 1010},
        'worker-nodes': {'subnet': '10.10.20.0/24', 'gateway': '10.10.20.1', 'vlan': 1020,
                         'dhcp': {'enable': True, 'range': {'start': '10.10.20.10', 'end': '10.10.20.250'}}}}}


def vpc(uid=UID, spec=None):
    return {'apiVersion': 'vpc.githedgehog.com/v1beta1', 'kind': 'VPC',
            'metadata': {'name': 'webapp-prod', 'namespace': 'default', 'uid': uid},
            'spec': spec if spec is not None else good_spec()}


def agents(count=7, applied=True, condition='True'):
    return {'items': [{'metadata': {'name': 'leaf-%02d' % n, 'generation': 3},
                       'status': {'lastAppliedGen': 3 if applied else 2,
                                  'conditions': [{'type': 'Applied', 'status': condition}]}}
                      for n in range(count)]}


class Cluster:
    """Synthetic ordinary-kubectl/jq world installed in place of ``run_child``."""
    def __init__(self):
        self.calls, self.vpc, self.others = [], None, []
        self.polls, self.converge_after = 0, 2
        self.apply_state, self.keep_on_delete, self.deleted = 'ok', False, 0
        self.agent_count, self.output_state, self.on_call = 7, None, {}
        self.ipv4 = {'spec': {'subnets': ['10.10.0.0/16']}}
        self.vlans = {'spec': {'ranges': [{'from': 1000, 'to': 1999}]}}

    def __call__(self, argv, seconds, *, env, limit=65536, stdin=None, account=None):
        self.calls.append((list(argv), env, stdin))
        if argv[0] == 'jq':
            if argv[1:] == ['--version']:
                return 0, b'jq-1.7.1\n', 'ok'
            return 0, json.dumps(json.loads(stdin), indent=2).encode(), 'ok'
        assert argv[0] == 'kubectl', argv
        a = tuple(argv[1:])
        for key, hook in self.on_call.items():
            if a[:len(key)] == key:
                hook()
        if self.output_state and a[:1] == ('describe',):
            return 0, b'x', self.output_state
        ok = lambda data: (0, data if isinstance(data, bytes) else json.dumps(data).encode(), 'ok')
        if a == ('config', 'current-context'):
            return ok(b'vlab\n')
        if a == ('config', 'get-contexts', '-o', 'name'):
            return ok(b'vlab\n')
        if a == ('plugin', 'list'):
            return ok(b'The following compatible plugins are available:\n\n' + pilot.PLUGIN.encode() + b'\n')
        if a[0] == 'fabric':
            return ok(b'10.0.0.1\n' if a[1:] == ('switch', 'ip', '--name', 'leaf-01') else b'usage\n')
        if a[0] == 'apply':
            assert Path(a[2]).read_text() == pilot.VPC_YAML
            self.vpc = vpc()
            return (0, b'vpc.vpc.githedgehog.com/webapp-prod created\n', 'ok') if self.apply_state == 'ok' \
                else (-9, b'', self.apply_state)
        if a[0] == 'describe':
            return ok(b'Name: webapp-prod\n10.10.10.0/24 1010\n10.10.20.0/24 1020\n')
        if a[0] == 'delete':
            self.deleted += 1
            if not self.keep_on_delete:
                self.vpc = None
            return ok(b'deleted\n')
        assert a[0] == 'get', a
        if a[1:] == ('ipv4namespace', 'default', '-o', 'json'):
            return ok(self.ipv4)
        if a[1:] == ('vlannamespace', 'default', '-o', 'json'):
            return ok(self.vlans)
        if a[1:] == ('vpcs', '-o', 'json'):
            return ok({'items': self.others + ([self.vpc] if self.vpc else [])})
        if a[1] in ('vpcs', 'agents'):
            if a[1:] == ('agents', '-o', 'json'):
                self.polls += 1
                return ok(agents(self.agent_count, applied=self.polls > self.converge_after))
            return ok(b'table\n')
        if a[1:3] == ('agent', 'leaf-01'):
            return ok(b'status:\n  conditions:\n')
        assert a[1:3] == ('vpc', 'webapp-prod'), a
        if self.vpc is None:
            return ok(b'') if '--ignore-not-found' in a else (1, b'NotFound', 'ok')
        if a[3:5] == ('-o', 'name'):
            return ok(b'vpc.vpc.githedgehog.com/webapp-prod\n')
        if a[3] == '-o' and a[4].startswith('jsonpath='):
            return ok(self.vpc['spec']['subnets']['worker-nodes']['dhcp'])
        return ok(self.vpc if a[4] == 'json' else b'yaml\n')

    def argvs(self):
        return [c[0] for c in self.calls]


class LessonHarness(unittest.TestCase):
    def setUp(self):
        self.cluster = Cluster()
        self.events = []
        for name, value in (('run_child', self.cluster), ('verify_kubectl', lambda: None), ('SLEEP', lambda s: None),
                            ('shield', lambda: None),
                            ('student_identity', lambda: SimpleNamespace(pw_uid=os.geteuid())),
                            ('emit', self.events.append)):
            patcher = patch.object(pilot, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(pilot.shutil, 'which', lambda *a, **k: pilot.KUBECTL)
        patcher.start()
        self.addCleanup(patcher.stop)

    def done(self):
        return [e for e in self.events if e.get('event') == 'done'][0]


class PinTests(unittest.TestCase):
    def test_public_pins_match_the_source_contracts(self):
        spec = importlib.util.spec_from_file_location('kfabric', Path(__file__).with_name('install-kubectl-fabric.py'))
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        pin = installer.PINS['0.96.2']
        self.assertEqual(pilot.ARCHIVE, (os.path.basename(pin['url']), pin['size'], pin['sha256']))
        self.assertEqual(pin['size'], 13620070)
        self.assertEqual({d[3]: d[4] for d in pilot.DEBS},
                         {'jq': '1.7.1-3ubuntu0.24.04.2', 'libjq1': '1.7.1-3ubuntu0.24.04.2',
                          'libonig5': '6.9.9-1build1'})
        self.assertEqual({d[0]: (d[1], d[2]) for d in pilot.DEBS}, {
            'jq_1.7.1-3ubuntu0.24.04.2_amd64.deb':
                (65694, 'f59183392f84fe67b407b494d8ba6185e9b0e4a106ffcb369490bd20a83fd40e'),
            'libjq1_1.7.1-3ubuntu0.24.04.2_amd64.deb':
                (141902, '078fbf38b2e7c3f24cc5dc894d1bb03b617894b887a6e13d5943e13818e724f3'),
            'libonig5_6.9.9-1build1_amd64.deb':
                (172336, '605f42287d2bcb6c84f5a02377c7cd777090c5e857259a4030a571989f19dde2')})
        self.assertEqual(len(pilot.CACHE_PINS), 4)

    def test_budget_keeps_the_teardown_reserve(self):
        phases = (pilot.PREFLIGHT_SECONDS + pilot.PACKAGE_SECONDS + pilot.PLUGIN_SECONDS + pilot.CONFIG_SECONDS
                  + pilot.ACCEPT_SECONDS + pilot.TEARDOWN_SECONDS)
        self.assertLessEqual(pilot.ACCEPT_SECONDS + 5 + pilot.TEARDOWN_SECONDS, pilot.TOTAL_SECONDS)
        self.assertGreater(phases, 0)

    def test_manifest_text_is_exactly_the_lesson_spec(self):
        text = pilot.VPC_YAML
        for line in ('name: webapp-prod', 'namespace: default', 'ipv4Namespace: default', 'vlanNamespace: default',
                     'web-servers:', 'subnet: 10.10.10.0/24', 'gateway: 10.10.10.1', 'vlan: 1010',
                     'worker-nodes:', 'subnet: 10.10.20.0/24', 'gateway: 10.10.20.1', 'vlan: 1020',
                     'enable: true', 'start: 10.10.20.10', 'end: 10.10.20.250'):
            self.assertIn(line, text)
        self.assertEqual(text.count('subnet:'), 2)
        self.assertEqual(pilot.SUBNETS, {'web-servers': ('10.10.10.0/24', '10.10.10.1', 1010),
                                         'worker-nodes': ('10.10.20.0/24', '10.10.20.1', 1020)})


class ParsingTests(unittest.TestCase):
    def test_exact_spec_and_each_drift(self):
        self.assertTrue(pilot.vpc_spec_ok(vpc()))
        tolerated = good_spec()
        tolerated['mode'] = 'default'
        self.assertTrue(pilot.vpc_spec_ok(vpc(spec=tolerated)))
        edits = (lambda s: s.update(ipv4Namespace='other'), lambda s: s.update(vlanNamespace='other'),
                 lambda s: s['subnets']['web-servers'].update(vlan=1011),
                 lambda s: s['subnets']['web-servers'].update(gateway='10.10.10.2'),
                 lambda s: s['subnets']['web-servers'].update(subnet='10.10.11.0/24'),
                 lambda s: s['subnets']['web-servers'].update(dhcp={'enable': True}),
                 lambda s: s['subnets']['worker-nodes'].update(vlan='1020'),
                 lambda s: s['subnets']['worker-nodes']['dhcp'].update(enable=False),
                 lambda s: s['subnets']['worker-nodes']['dhcp']['range'].update(end='10.10.20.249'),
                 lambda s: s['subnets']['worker-nodes'].pop('dhcp'),
                 lambda s: s['subnets'].update(extra={'subnet': '10.10.30.0/24', 'gateway': '10.10.30.1', 'vlan': 1}),
                 lambda s: s['subnets'].pop('web-servers'))
        for edit in edits:
            spec = good_spec()
            edit(spec)
            with self.subTest(edit=edit):
                self.assertFalse(pilot.vpc_spec_ok(vpc(spec=spec)))
        self.assertFalse(pilot.vpc_spec_ok({'spec': 'x'}))

    def test_exactly_seven_agents_applied_equals_current(self):
        self.assertEqual(pilot.agents_state(agents()), (7, True))
        self.assertEqual(pilot.agents_state(agents(applied=False)), (7, False))
        self.assertEqual(pilot.agents_state(agents(condition='False')), (7, False))
        self.assertEqual(pilot.agents_state(agents(count=6)), (6, False))
        broken = agents()
        broken['items'][3]['status'].pop('conditions')
        self.assertEqual(pilot.agents_state(broken), (7, False))
        doubled = agents()
        doubled['items'][0]['status']['conditions'].append({'type': 'Applied', 'status': 'True'})
        self.assertEqual(pilot.agents_state(doubled), (7, False))
        generation = agents()
        generation['items'][0]['metadata']['generation'] = '3'
        self.assertEqual(pilot.agents_state(generation), (7, False))

    def test_namespace_and_conflict_checks(self):
        ipv4, vlan = {'spec': {'subnets': ['10.10.0.0/16']}}, {'spec': {'ranges': [{'from': 1000, 'to': 1999}]}}
        self.assertTrue(pilot.namespaces_ok(ipv4, vlan))
        self.assertFalse(pilot.namespaces_ok({'spec': {'subnets': ['10.20.0.0/16']}}, vlan))
        self.assertFalse(pilot.namespaces_ok(ipv4, {'spec': {'ranges': [{'from': 1000, 'to': 1015}]}}))
        self.assertFalse(pilot.namespaces_ok({}, {}))
        other = lambda cidr, vlan_id: {'items': [{'spec': {'ipv4Namespace': 'default', 'vlanNamespace': 'default',
                                                          'subnets': {'s': {'subnet': cidr, 'vlan': vlan_id}}}}]}
        self.assertFalse(pilot.cidr_conflict({'items': []}))
        self.assertFalse(pilot.cidr_conflict(other('10.30.0.0/24', 3000)))
        self.assertTrue(pilot.cidr_conflict(other('10.10.10.128/25', 3000)))
        self.assertTrue(pilot.cidr_conflict(other('10.30.0.0/24', 1020)))

    def test_events_are_closed_and_ignore_everything_else(self):
        good = json.dumps({'event': 'done', 'code': 'ok', 'cleanup': 'removed', 'agents': 7})
        raw = '\n'.join([CANARY, '{"event":"uid","uid":"%s"}' % UID, '{"event":"uid","uid":"%s","x":1}' % 'bad',
                         '{"event":"uid","uid":"not-a-uid"}', '{"event":"config","status":"-"}', good,
                         '{"event":"done","code":"nope","cleanup":"removed","agents":7}',
                         '{"event":"x","pad":"' + 'a' * 600 + '"}']).encode()
        events = pilot.parse_events(raw)
        self.assertEqual(events['uid'], UID)
        self.assertEqual(events['done']['cleanup'], 'removed')
        self.assertNotIn('config', events)
        self.assertEqual(set(events), {'uid', 'done'})


class PackageTests(unittest.TestCase):
    WANT = {'jq': ('ii', '1.7.1-3ubuntu0.24.04.2'), 'libjq1': ('ii', '1.7.1-3ubuntu0.24.04.2'),
            'libonig5': ('ii', '6.9.9-1build1'), 'libc6': ('ii', '2.39-0ubuntu8.6')}

    def setUp(self):
        self.calls, self.states, self.libc_ok, self.dpkg = [], [], True, (0, b'', 'ok')
        self.jq = Path(tempfile.mkdtemp()) / 'jq'
        self.addCleanup(shutil.rmtree, self.jq.parent, True)
        for name, value in (('run_child', self.child), ('package_state', self.state), ('JQ', str(self.jq))):
            patcher = patch.object(pilot, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def state(self):
        return dict(self.states.pop(0) if len(self.states) > 1 else self.states[0])

    def child(self, argv, seconds, **kwargs):
        self.calls.append(argv)
        if argv[1] == '--compare-versions':
            return (0 if self.libc_ok else 1), b'', 'ok'
        self.assertEqual(kwargs['env'], pilot.ROOT_ENV)
        return self.dpkg

    def test_equal_state_is_unchanged_and_runs_no_dpkg_install(self):
        self.states = [self.WANT]
        self.assertEqual(pilot.install_packages(pilot.Clock(60)), 'unchanged')
        self.assertEqual([c for c in self.calls if c[1] == '--install'], [])

    def test_absent_installs_exactly_the_three_pinned_files_without_force(self):
        self.states = [{'libc6': self.WANT['libc6']}, self.WANT]
        self.assertEqual(pilot.install_packages(pilot.Clock(60)), 'installed')
        (install,) = [c for c in self.calls if c[1] == '--install']
        self.assertEqual(install[0], pilot.DPKG)
        self.assertEqual(install[2], '--refuse-downgrade')
        self.assertEqual(sorted(Path(p).name for p in install[3:]), sorted(d[0] for d in pilot.DEBS))
        self.assertFalse([a for a in install if a.startswith('--force')])

    def test_partial_state_installs_only_the_missing_packages(self):
        self.states = [{'libc6': self.WANT['libc6'], 'libonig5': self.WANT['libonig5']}, self.WANT]
        self.assertEqual(pilot.install_packages(pilot.Clock(60)), 'installed')
        (install,) = [c for c in self.calls if c[1] == '--install']
        self.assertEqual(sorted(Path(p).name for p in install[3:]),
                         sorted(d[0] for d in pilot.DEBS if d[3] != 'libonig5'))

    def test_conflicts_refuse_before_any_mutation(self):
        for change in ({'jq': ('ii', '1.6-2.1')}, {'libonig5': ('ii', '6.9.9-1')}, {'libjq1': ('rc', '1.7.1-3ubuntu0.24.04.2')},
                       {'jq': ('hi', '1.7.1-3ubuntu0.24.04.2')}):
            with self.subTest(change):
                self.calls.clear()
                self.states = [dict(self.WANT, **change)]
                with self.assertRaises(pilot.Conflict):
                    pilot.install_packages(pilot.Clock(60))
                self.assertEqual([c for c in self.calls if c[1] == '--install'], [])

    def test_other_refusals_and_failure_modes(self):
        self.states = [{'jq': None}]
        with self.assertRaises(pilot.Refused):          # libc6 absent
            pilot.install_packages(pilot.Clock(60))
        self.states, self.libc_ok = [dict(self.WANT)], False
        with self.assertRaises(pilot.Refused):
            pilot.install_packages(pilot.Clock(60))
        self.libc_ok, self.states = True, [{'libc6': self.WANT['libc6']}]
        self.jq.write_text('foreign jq')
        with self.assertRaises(pilot.Refused):          # jq file without the package: nothing is overwritten
            pilot.install_packages(pilot.Clock(60))
        self.assertEqual(self.jq.read_text(), 'foreign jq')
        self.jq.unlink()
        self.dpkg = (1, CANARY.encode(), 'ok')
        with self.assertRaises(pilot.Refused) as caught:
            pilot.install_packages(pilot.Clock(60))
        self.assertNotIn(CANARY, str(caught.exception))
        self.dpkg = (-9, b'', 'timeout')
        with self.assertRaises(pilot.Uncertain):
            pilot.install_packages(pilot.Clock(60))

    def test_not_verified_after_install_is_refused(self):
        self.states = [{'libc6': self.WANT['libc6']}, {'libc6': self.WANT['libc6']}]
        with self.assertRaises(pilot.Refused):
            pilot.install_packages(pilot.Clock(60))

    def test_package_state_parses_status_lines_and_ignores_noise(self):
        out = b'ii |libc6|2.39-0ubuntu8.6\ndpkg-query: no packages found matching jq\nii |libonig5|6.9.9-1build1\n'
        with patch.object(pilot, 'run_child', lambda *a, **k: (1, out, 'ok')):
            self.assertEqual(ORIGINAL_PACKAGE_STATE(), {'libc6': ('ii', '2.39-0ubuntu8.6'),
                                                        'libonig5': ('ii', '6.9.9-1build1')})


class PluginTests(unittest.TestCase):
    def run_plugin(self, code, out, state='ok'):
        seen = []

        def child(argv, seconds, **kwargs):
            seen.append((argv, kwargs))
            return code, out, state
        with patch.object(pilot, 'run_child', child):
            try:
                return pilot.install_plugin(pilot.Clock(60)), seen
            finally:
                self.seen = seen

    def test_statuses_and_the_unchanged_installer_argv(self):
        for status in ('installed', 'unchanged', 'mode-repaired'):
            line = json.dumps({'tool': 'kubectl-fabric', 'status': status}).encode()
            result, seen = self.run_plugin(0, line + b'\n')
            self.assertEqual(result, status)
        argv, kwargs = seen[0]
        self.assertEqual(argv, [pilot.PYTHON, '-B', str(pilot.PAYLOAD / 'install-kubectl-fabric.py'), '--version',
                                '0.96.2', '--platform', 'linux/amd64', '--archive', str(pilot.PAYLOAD / pilot.ARCHIVE[0])])
        self.assertEqual(kwargs['env'], pilot.ROOT_ENV)

    def test_conflict_refusal_overflow_and_timeout(self):
        with self.assertRaises(pilot.Conflict):
            self.run_plugin(1, b'kubectl-fabric install: existing kubectl-fabric differs from the archive member; no force')
        with self.assertRaises(pilot.Refused) as caught:
            self.run_plugin(1, CANARY.encode())
        self.assertNotIn(CANARY, str(caught.exception))
        with self.assertRaises(pilot.Refused):
            self.run_plugin(0, b'{"tool":"kubectl-fabric","status":"weird"}')
        with self.assertRaises(pilot.Refused):
            self.run_plugin(0, b'', 'overflow')
        with self.assertRaises(pilot.Uncertain):
            self.run_plugin(-9, b'', 'timeout')


class ConfigureTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix='hm'))
        self.addCleanup(shutil.rmtree, self.home, True)
        os.chmod(self.home, 0o700)
        (self.home / 'hhfab/vlab').mkdir(parents=True)
        self.source = self.home / 'hhfab/vlab/kubeconfig'
        self.write_source(self.config())
        for name, value in (('HOME', self.home), ('SOURCE_KUBECONFIG', self.source), ('TARGET_DIR', self.home / '.kube'),
                            ('TARGET', self.home / '.kube/config'), ('verify_kubectl', lambda: None),
                            ('student_identity', lambda: SimpleNamespace(pw_uid=os.geteuid())),
                            ('view_json', lambda path, clock: json.loads(Path(path).read_text()))):
            patcher = patch.object(pilot, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.target = self.home / '.kube/config'

    @staticmethod
    def config(server=None, extra_cluster=False, context='kind-vlab'):
        value = {'kind': 'Config', 'apiVersion': 'v1', 'preferences': {},
                 'clusters': [{'name': 'cl', 'cluster': {'server': server or pilot.API_SERVER,
                                                         'certificate-authority-data': 'CA' + CANARY}}],
                 'users': [{'name': 'adm', 'user': {'client-certificate-data': 'CERT' + CANARY,
                                                    'client-key-data': 'KEY' + CANARY}}],
                 'contexts': [{'name': context, 'context': {'cluster': 'cl', 'user': 'adm'}}],
                 'current-context': context}
        if extra_cluster:
            value['clusters'].append({'name': 'two', 'cluster': dict(value['clusters'][0]['cluster'])})
        return value

    def write_source(self, value, mode=0o600):
        self.source.write_text(json.dumps(value))
        os.chmod(self.source, mode)

    def test_installs_the_single_real_binding_with_default_context_vlab(self):
        self.assertEqual(pilot.configure(pilot.Clock(30)), 'installed')
        written = json.loads(self.target.read_text())
        self.assertEqual(written['current-context'], 'vlab')
        self.assertEqual([c['name'] for c in written['contexts']], ['vlab'])
        source = self.config()
        self.assertEqual(written['clusters'], source['clusters'])      # actual API/CA/cluster identity preserved
        self.assertEqual(written['users'], source['users'])
        self.assertEqual(written['contexts'][0]['context'], {'cluster': 'cl', 'user': 'adm'})
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.home / '.kube').stat().st_mode), 0o700)
        self.assertEqual(self.target.stat().st_nlink, 1)
        self.assertEqual([p.name for p in (self.home / '.kube').iterdir()], ['config'])    # stage removed
        self.assertEqual(json.loads(self.source.read_text()), source)                      # source untouched

    def test_rerun_is_unchanged_and_preserves_the_file(self):
        pilot.configure(pilot.Clock(30))
        before = self.target.stat()
        self.assertEqual(pilot.configure(pilot.Clock(30)), 'unchanged')
        after = self.target.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))

    def test_semantically_equal_existing_config_is_unchanged(self):
        (self.home / '.kube').mkdir(mode=0o700)
        candidate = pilot.student_candidate(self.config())
        self.target.write_text(json.dumps(candidate, indent=4))
        os.chmod(self.target, 0o600)
        original = self.target.read_bytes()
        self.assertEqual(pilot.configure(pilot.Clock(30)), 'unchanged')
        self.assertEqual(self.target.read_bytes(), original)

    def test_conflicting_existing_config_is_refused_and_preserved(self):
        (self.home / '.kube').mkdir(mode=0o700)
        self.target.write_text(json.dumps(self.config(context='mine')))
        os.chmod(self.target, 0o600)
        original = self.target.read_bytes()
        with self.assertRaises(pilot.Conflict) as caught:
            pilot.configure(pilot.Clock(30))
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertEqual(self.target.read_bytes(), original)
        self.assertEqual([p.name for p in (self.home / '.kube').iterdir()], ['config'])

    def test_symlink_and_wide_mode_targets_are_refused(self):
        (self.home / '.kube').mkdir(mode=0o700)
        real = self.home / 'real'
        real.write_text(json.dumps(pilot.student_candidate(self.config())))
        os.chmod(real, 0o600)
        self.target.symlink_to(real)
        with self.assertRaises(pilot.Refused):
            pilot.configure(pilot.Clock(30))
        self.target.unlink()
        shutil.copy(real, self.target)
        os.chmod(self.target, 0o644)
        with self.assertRaises(pilot.Refused):
            pilot.configure(pilot.Clock(30))

    def test_source_shape_and_identity_refusals_leave_nothing_behind(self):
        for source, mode in ((self.config(server='https://10.0.0.1:6443'), 0o600), (self.config(extra_cluster=True), 0o600),
                             (self.config(), 0o644)):
            with self.subTest(mode=mode):
                self.write_source(source, mode)
                with self.assertRaises(pilot.Refused) as caught:
                    pilot.configure(pilot.Clock(30))
                self.assertNotIn(CANARY, str(caught.exception))
                self.assertFalse(self.target.exists())

    def test_failure_after_staging_cleans_the_stage_and_keeps_prior_state(self):
        (self.home / '.kube').mkdir(mode=0o700)
        calls = []

        def view(path, clock):
            calls.append(path)
            if len(calls) == 2:
                raise pilot.Refused('boom')
            return json.loads(Path(path).read_text())
        with patch.object(pilot, 'view_json', view), self.assertRaises(pilot.Refused):
            pilot.configure(pilot.Clock(30))
        self.assertEqual(list((self.home / '.kube').iterdir()), [])


class IdentityTests(unittest.TestCase):
    def test_student_identity_requires_real_user_home_path_and_no_kubeconfig(self):
        me = SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
        env = {'HOME': '/home/ubuntu', 'PATH': pilot.STUDENT_ENV['PATH']}
        with patch.object(pilot, 'account', lambda: me), patch.dict(os.environ, env, clear=True):
            self.assertIs(pilot.student_identity(), me)
            with patch.dict(os.environ, {'KUBECONFIG': '/x'}):
                with self.assertRaises(pilot.Refused):
                    pilot.student_identity()
            with patch.dict(os.environ, {'HOME': '/root'}), self.assertRaises(pilot.Refused):
                pilot.student_identity()
        other = SimpleNamespace(pw_uid=os.geteuid() + 1, pw_gid=os.getegid())
        with patch.object(pilot, 'account', lambda: other), patch.dict(os.environ, env, clear=True):
            with self.assertRaises(pilot.Refused):
                pilot.student_identity()

    def test_student_env_is_ordinary_and_carries_no_kubeconfig(self):
        self.assertEqual(pilot.STUDENT_ENV['HOME'], '/home/ubuntu')
        self.assertNotIn('KUBECONFIG', pilot.STUDENT_ENV)
        self.assertIn('/usr/local/bin', pilot.STUDENT_ENV['PATH'].split(':'))


class LessonTests(LessonHarness):
    def test_happy_path_uses_ordinary_kubectl_and_removes_only_the_owned_vpc(self):
        self.assertEqual(pilot.accept(), 0)
        done = self.done()
        self.assertEqual((done['code'], done['cleanup'], done['agents']), ('ok', 'removed', 7))
        self.assertIn({'event': 'uid', 'uid': UID}, self.events)
        self.assertIsNone(self.cluster.vpc)
        self.assertEqual(self.cluster.deleted, 1)
        for argv, env, _ in self.cluster.calls:
            self.assertEqual(env, pilot.STUDENT_ENV)                       # normal HOME/PATH, no KUBECONFIG
            self.assertNotIn('KUBECONFIG', env)
            self.assertFalse([a for a in argv if a.startswith(('--kubeconfig', '--context', '--as', '--token'))])
        kube = [a for a in self.cluster.argvs() if a[0] == 'kubectl']
        for step in (['apply', '-f'], ['describe', 'vpc', 'webapp-prod'], ['get', 'agents'],
                     ['get', 'agent', 'leaf-01', '-o', 'yaml'], ['plugin', 'list'], ['fabric', '--help'],
                     ['fabric', 'switch', 'ip', '--name', 'leaf-01']):
            self.assertTrue(any(a[1:1 + len(step)] == step for a in kube), step)
        jq = [c for c in self.cluster.calls if c[0] == ['jq', '.']]
        self.assertEqual(len(jq), 1)                                    # kubectl JSONPath piped to jq
        self.assertEqual(json.loads(jq[0][2])['range']['end'], '10.10.20.250')

    def test_preexisting_webapp_prod_is_refused_and_never_touched(self):
        self.cluster.vpc = vpc(uid='99999999-2222-3333-4444-555555555555')
        self.pilot_run()
        done = self.done()
        self.assertEqual((done['code'], done['cleanup']), ('refused', 'not-needed'))
        self.assertEqual(self.cluster.deleted, 0)
        self.assertEqual(self.cluster.vpc['metadata']['uid'], '99999999-2222-3333-4444-555555555555')
        self.assertFalse([a for a in self.cluster.argvs() if a[1:2] == ['apply']])

    def pilot_run(self):
        return pilot.accept()

    def test_conflicting_cidr_or_missing_namespace_range_refuses_before_apply(self):
        self.cluster.others = [{'spec': {'ipv4Namespace': 'default', 'vlanNamespace': 'default',
                                         'subnets': {'x': {'subnet': '10.10.10.0/24', 'vlan': 5}}}}]
        pilot.accept()
        self.assertEqual(self.done()['code'], 'conflict')
        self.assertFalse([a for a in self.cluster.argvs() if a[1:2] == ['apply']])
        self.events.clear()
        self.cluster.others = []
        self.cluster.vlans = {'spec': {'ranges': [{'from': 1, 'to': 100}]}}
        pilot.accept()
        self.assertEqual(self.done()['code'], 'refused')

    def test_foreign_replacement_after_create_is_preserved(self):
        def swap():
            self.cluster.vpc = vpc(uid='99999999-2222-3333-4444-555555555555')
        self.cluster.on_call[('describe',)] = swap
        pilot.accept()
        done = self.done()
        self.assertEqual(done['cleanup'], 'preserved')
        self.assertEqual(self.cluster.deleted, 0)
        self.assertIsNotNone(self.cluster.vpc)

    def test_agents_that_never_converge_time_out_and_still_clean_up(self):
        self.cluster.converge_after = 10 ** 9
        with patch.object(pilot, 'AGENT_WAIT_SECONDS', 0.05):
            pilot.accept()
        done = self.done()
        self.assertEqual((done['code'], done['cleanup']), ('timeout', 'removed'))
        self.assertIsNone(self.cluster.vpc)

    def test_wrong_agent_count_refuses_and_cleans_up(self):
        self.cluster.agent_count = 6
        pilot.accept()
        done = self.done()
        self.assertEqual((done['code'], done['cleanup']), ('refused', 'removed'))

    def test_ambiguous_apply_is_adopted_by_exact_spec_and_removed(self):
        self.cluster.apply_state = 'timeout'
        pilot.accept()
        done = self.done()
        self.assertEqual((done['code'], done['cleanup']), ('timeout', 'removed'))
        self.assertIsNone(self.cluster.vpc)

    def test_ambiguous_apply_with_a_different_spec_is_never_adopted(self):
        self.cluster.apply_state = 'timeout'
        self.cluster.on_call[('get', 'vpc', 'webapp-prod', '-o', 'json', '--ignore-not-found')] = \
            lambda: setattr(self.cluster, 'vpc', vpc(spec=dict(good_spec(), ipv4Namespace='other')))
        pilot.accept()
        self.assertEqual(self.done()['cleanup'], 'preserved')
        self.assertEqual(self.cluster.deleted, 0)

    def test_cancellation_preserves_the_primary_code_and_runs_teardown(self):
        def cancel():
            raise pilot.Interrupted
        self.cluster.on_call[('describe',)] = cancel
        pilot.accept()
        done = self.done()
        self.assertEqual((done['code'], done['cleanup']), ('cancelled', 'removed'))
        self.assertIsNone(self.cluster.vpc)

    def test_cleanup_uncertainty_is_reported_not_hidden(self):
        self.cluster.keep_on_delete = True
        pilot.accept()
        done = self.done()
        self.assertEqual((done['code'], done['cleanup']), ('ok', 'uncertain'))

    def test_overflowing_kubectl_output_is_refused(self):
        self.cluster.output_state = 'overflow'
        pilot.accept()
        self.assertEqual(self.done()['code'], 'refused')
        self.assertEqual(self.done()['cleanup'], 'removed')

    def test_teardown_only_preserves_unknown_ownership(self):
        self.cluster.vpc = vpc()
        self.assertEqual(pilot.teardown_only('-'), 0)
        self.assertEqual(self.done()['cleanup'], 'preserved')
        self.assertEqual(self.cluster.deleted, 0)
        self.events.clear()
        pilot.teardown_only(UID)
        self.assertEqual(self.done()['cleanup'], 'removed')
        self.events.clear()
        pilot.teardown_only(UID)
        self.assertEqual(self.done()['cleanup'], 'absent')


class RunTests(unittest.TestCase):
    def setUp(self):
        self.out, self.children = [], []
        self.plan = {'configure': (0, {'config': 'installed'}, 'ok'),
                     'accept': (0, {'uid': UID, 'done': {'event': 'done', 'code': 'ok', 'cleanup': 'removed',
                                                         'agents': 7}}, 'ok'),
                     'teardown': (0, {'done': {'event': 'done', 'code': 'ok', 'cleanup': 'removed', 'agents': 0}}, 'ok')}

        def child(mode, seconds, source, extra=()):
            self.children.append((mode, tuple(extra)))
            return self.plan[mode]
        for name, value in (('preflight', lambda: None), ('install_packages', lambda clock: 'installed'),
                            ('install_plugin', lambda clock: 'installed'), ('student_child', child),
                            ('emit', self.out.append), ('shield', lambda: None)):
            patcher = patch.object(pilot, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_pass_requires_everything_and_reports_a_closed_line(self):
        self.assertEqual(pilot.run(), 0)
        (result,) = self.out
        self.assertEqual(set(result), set(pilot.RESULT_KEYS))
        self.assertEqual((result['status'], result['phase'], result['code'], result['cleanup'], result['agents'],
                          result['vpc_uid'], result['packages'], result['plugin'], result['config']),
                         ('passed', 'done', 'ok', 'removed', 7, UID, 'installed', 'installed', 'installed'))
        self.assertLessEqual(len(json.dumps(result)), pilot.OUTPUT_LIMIT)
        self.assertEqual([c[0] for c in self.children], ['configure', 'accept'])

    def test_failed_phases_report_phase_and_code_without_text(self):
        def boom(clock):
            raise pilot.Conflict(CANARY)
        with patch.object(pilot, 'install_plugin', boom):
            pilot.run()
        result = self.out[-1]
        self.assertEqual((result['status'], result['phase'], result['code'], result['config']),
                         ('failed', 'plugin', 'conflict', '-'))
        self.assertNotIn(CANARY, json.dumps(result))
        self.assertEqual(self.children, [])

        def cancel(clock):
            raise pilot.Interrupted
        with patch.object(pilot, 'install_packages', cancel):
            pilot.run()
        self.assertEqual((self.out[-1]['phase'], self.out[-1]['code']), ('packages', 'cancelled'))

        def odd(clock):
            raise RuntimeError(CANARY)
        with patch.object(pilot, 'preflight', lambda: odd(None)):
            pilot.run()
        self.assertEqual((self.out[-1]['phase'], self.out[-1]['code']), ('preflight', 'failed'))
        self.assertNotIn(CANARY, json.dumps(self.out[-1]))

    def test_config_conflict_exit_code_is_a_conflict(self):
        self.plan['configure'] = (3, {}, 'ok')
        pilot.run()
        self.assertEqual((self.out[-1]['phase'], self.out[-1]['code']), ('config', 'conflict'))
        self.assertEqual([c[0] for c in self.children], ['configure'])

    def test_child_failure_codes_pass_through(self):
        self.plan['accept'] = (0, {'uid': UID, 'done': {'event': 'done', 'code': 'timeout', 'cleanup': 'removed',
                                                         'agents': 3}}, 'ok')
        pilot.run()
        result = self.out[-1]
        self.assertEqual((result['status'], result['code'], result['agents'], result['cleanup']),
                         ('failed', 'timeout', 3, 'removed'))
        self.assertEqual([c[0] for c in self.children], ['configure', 'accept'])     # finished child: no safety net

    def test_unfinished_acceptance_runs_the_teardown_safety_net_with_the_actual_uid(self):
        self.plan['accept'] = (-9, {'uid': UID}, 'timeout')
        pilot.run()
        result = self.out[-1]
        self.assertEqual((result['status'], result['cleanup'], result['vpc_uid']), ('failed', 'removed', UID))
        self.assertEqual(self.children[-1], ('teardown', (UID,)))

    def test_unfinished_acceptance_without_a_uid_uses_the_unknown_marker(self):
        self.plan['accept'] = (1, {}, 'ok')
        self.plan['teardown'] = (0, {'done': {'event': 'done', 'code': 'ok', 'cleanup': 'absent', 'agents': 0}}, 'ok')
        pilot.run()
        self.assertEqual(self.children[-1], ('teardown', ('-',)))
        self.assertEqual((self.out[-1]['cleanup'], self.out[-1]['status']), ('not-needed', 'failed'))

    def test_cleanup_uncertainty_can_never_pass(self):
        for cleanup in ('uncertain', 'preserved', 'absent', 'not-needed'):
            with self.subTest(cleanup):
                self.plan['accept'] = (0, {'uid': UID, 'done': {'event': 'done', 'code': 'ok', 'cleanup': cleanup,
                                                                 'agents': 7}}, 'ok')
                pilot.run()
                self.assertEqual(self.out[-1]['status'], 'failed')
        self.plan['accept'] = (-9, {'uid': UID}, 'timeout')
        self.plan['teardown'] = (0, {}, 'ok')
        pilot.run()
        self.assertEqual((self.out[-1]['status'], self.out[-1]['cleanup']), ('failed', 'uncertain'))

    def test_children_are_the_real_ubuntu_user_with_the_ordinary_environment(self):
        seen = []
        user = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name='ubuntu', pw_dir='/home/ubuntu')
        with patch.object(pilot, 'account', lambda: user), \
                patch.object(pilot, 'run_child', lambda argv, seconds, **kw: seen.append((argv, kw)) or (0, b'', 'ok')):
            ORIGINAL_STUDENT_CHILD('accept', 10, b'SOURCE')
            ORIGINAL_STUDENT_CHILD('teardown', 10, b'SOURCE', (UID,))
        self.assertEqual(seen[0][0], [pilot.PYTHON, '-I', '-', 'accept'])
        self.assertEqual(seen[1][0], [pilot.PYTHON, '-I', '-', 'teardown', UID])
        for _, kw in seen:
            self.assertIs(kw['account'], user)
            self.assertEqual(kw['env'], pilot.STUDENT_ENV)
            self.assertEqual(kw['stdin'], b'SOURCE')

    def test_main_dispatch_is_closed(self):
        with patch.object(pilot.signal, 'signal'), patch.object(pilot.os, 'umask'):
            self.assertEqual(pilot.main(['x']), 2)
            self.assertEqual(pilot.main(['x', 'bogus']), 2)
            self.assertEqual(pilot.main(['x', 'run', 'extra']), 2)
            self.assertEqual(pilot.main(['x', 'teardown', 'not-a-uid']), 2)
            self.assertEqual(pilot.main(['x', 'accept', '--kubeconfig', '/x']), 2)


class RunChildTests(unittest.TestCase):
    ENV = {'PATH': os.environ.get('PATH', '/usr/bin:/bin')}

    def python(self, code, seconds=10, **kwargs):
        return pilot.run_child([sys.executable, '-c', code], seconds, env=self.ENV, **kwargs)

    def test_output_exit_code_and_stdin(self):
        self.assertEqual(self.python('print("hi")'), (0, b'hi\n', 'ok'))
        self.assertEqual(self.python('import sys;sys.exit(3)')[0], 3)
        self.assertEqual(self.python('import sys;sys.stdout.write(sys.stdin.read().upper())', stdin=b'abc')[1:], (b'ABC', 'ok'))

    def test_output_bound_keeps_the_prefix_and_kills_the_child(self):
        code, out, state = self.python('import sys,time\nsys.stdout.write("x"*100000);sys.stdout.flush();time.sleep(30)',
                                       limit=1000)
        self.assertEqual((state, len(out)), ('overflow', 1000))

    def test_timeout_keeps_partial_output_and_kills_the_whole_group(self):
        marker = Path(tempfile.mkdtemp()) / 'pid'
        self.addCleanup(shutil.rmtree, marker.parent, True)
        script = ('import subprocess,sys,time\n'
                  'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"])\n'
                  'open(%r,"w").write(str(p.pid));print("partial",flush=True);time.sleep(60)' % str(marker))
        started = time.monotonic()
        code, out, state = self.python(script, seconds=2)
        self.assertEqual((state, out), ('timeout', b'partial\n'))
        self.assertLess(time.monotonic() - started, 10)
        pid = int(marker.read_text())
        for _ in range(40):
            try:
                alive = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()[0] not in ('Z', 'X')
            except OSError:
                alive = False
            if not alive:
                break
            time.sleep(.05)
        self.assertFalse(alive)

    def test_descendant_holding_the_pipe_does_not_outlive_a_normal_exit(self):
        script = ('import subprocess,sys\n'
                  'subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"])\n'
                  'print("done",flush=True)')
        started = time.monotonic()
        code, out, state = self.python(script, seconds=5)
        self.assertLess(time.monotonic() - started, 4.5)
        self.assertEqual((code, out), (0, b'done\n'))


if __name__ == '__main__':
    unittest.main()
