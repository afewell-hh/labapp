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
CANONICAL = ['leaf-01', 'leaf-02', 'leaf-03', 'leaf-04', 'leaf-05', 'spine-01', 'spine-02']
OWNED_FILE = Path(__file__).with_name('owned_process.py')


REPO = Path(__file__).resolve().parents[2]
COURSE_WIRING = REPO / 'build/provision/course-wiring.yaml'
ROOT_WIRING = REPO / 'wiringd.yaml'
EMPTY = {key: None for key in pilot.CAPACITY_KEYS}
CLOSED = {'step': '-', 'capacity': EMPTY, 'agent_snapshot': pilot.empty_agent_snapshot()}
COMPLETE = {'step': 'post-apply', 'capacity': dict.fromkeys(pilot.CAPACITY_KEYS, True),
            'agent_snapshot': pilot.empty_agent_snapshot()}


def real_namespaces(path):
    """The default IPv4Namespace and VLANNamespace objects PARSED from a real repository wiring file (not hand-made)."""
    import yaml
    found = {}
    for doc in yaml.safe_load_all(path.read_bytes()):
        if isinstance(doc, dict) and doc.get('kind') in ('IPv4Namespace', 'VLANNamespace') \
                and doc['metadata']['name'] == 'default':
            found[doc['kind']] = doc
    return found['IPv4Namespace'], found['VLANNamespace']


def reset_sticky(test):
    """Sticky state is process-global: every test starts and ends with it clear."""
    pilot.STICKY.clear()
    test.addCleanup(pilot.STICKY.clear)


def use_sibling_owned(test):
    """Load the pinned owned_process.py from the repository copy (same SHA256 as the guest asset). Only the
    root-ownership check is replaced, because a source checkout is not root-owned; the pin check stays real."""
    for name, value in (('OWNED_PROCESS', OWNED_FILE), ('regular', lambda *a, **k: SimpleNamespace(st_mode=0o100644))):
        patcher = patch.object(pilot, name, value)
        patcher.start()
        test.addCleanup(patcher.stop)
    pilot.OWNED.clear()
    test.addCleanup(pilot.OWNED.clear)
    reset_sticky(test)


def good_spec():
    return {'ipv4Namespace': 'default', 'vlanNamespace': 'default', 'subnets': {
        'web-servers': {'subnet': '10.10.10.0/24', 'gateway': '10.10.10.1', 'vlan': 1010},
        'worker-nodes': {'subnet': '10.10.20.0/24', 'gateway': '10.10.20.1', 'vlan': 1020,
                         'dhcp': {'enable': True, 'range': {'start': '10.10.20.10', 'end': '10.10.20.250'}}}}}


def vpc(uid=UID, spec=None):
    return {'apiVersion': 'vpc.githedgehog.com/v1beta1', 'kind': 'VPC',
            'metadata': {'name': 'webapp-prod', 'namespace': 'default', 'uid': uid, 'generation': 1},
            'spec': spec if spec is not None else good_spec()}


def agents(count=7, applied=True, condition='True', names=None):
    names = names or (CANONICAL + ['leaf-%02d' % n for n in range(6, 20)])[:count]
    return {'items': [{'metadata': {'name': name, 'generation': 3},
                       'status': {'lastAppliedGen': 3 if applied else 2,
                                  'conditions': [{'type': 'Applied', 'status': condition}]}}
                      for name in names]}


class Cluster:
    """Synthetic ordinary-kubectl/jq world installed in place of ``run_child``."""
    def __init__(self):
        self.calls, self.vpc, self.others = [], None, []
        self.polls, self.converge_after = 0, 2
        self.apply_state, self.keep_on_delete, self.deleted = 'ok', False, 0
        self.apply_creates, self.apply_mutate, self.deletes = True, None, []
        self.agent_count, self.output_state, self.on_call = 7, None, {}
        # The happy world serves the REAL parsed course wiring namespaces, never a hand-made alternate.
        self.ipv4, self.vlans = real_namespaces(COURSE_WIRING)

    def __call__(self, argv, seconds, *, env, limit=65536, stdin=None, account=None):
        self.calls.append((list(argv), env, stdin))
        if argv[0] == 'jq':
            if argv[1:] == ['--version']:
                return 0, b'jq-1.7\n', 'ok'      # what the signed 1.7.1-3ubuntu0.24.04.2 binary prints
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
            if a[1:] == ('--version',):
                return ok(b'v0.96.2\n')
            return ok(b'10.0.0.1\n' if a[1:] == ('switch', 'ip', '--name', 'leaf-01') else b'usage\n')
        if a[0] == 'apply':
            assert a[1] == '-f' and a[3:] == ('-o', 'json'), a
            assert Path(a[2]).read_text() == pilot.VPC_YAML
            if self.apply_creates:
                self.vpc = vpc()
            if self.apply_state != 'ok':    # ambiguous: the object may or may not exist, the response is lost
                return -9, b'', self.apply_state
            response = json.loads(json.dumps(self.vpc))
            replaced = self.apply_mutate(response) if self.apply_mutate else None
            return ok(response if replaced is None else replaced)
        if a[0] == 'describe':
            return ok(b'Name: webapp-prod\n10.10.10.0/24 1010\n10.10.20.0/24 1020\n')
        if a[0] == 'delete':
            # Harness teardown only: one raw DELETE with DeleteOptions preconditions.uid, never a name-only delete.
            assert a[1:4] == ('--raw', pilot.VPC_PATH, '-f') and len(a) == 5, a
            body = json.loads(Path(a[4]).read_text())
            assert body == {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': body['preconditions']['uid']}}
            self.deletes.append(body['preconditions']['uid'])
            if self.vpc is None:
                return 1, b'NotFound', 'ok'
            if self.vpc['metadata']['uid'] != body['preconditions']['uid']:   # the server refuses atomically
                return 1, b'Conflict: precondition failed', 'ok'
            self.deleted += 1
            if not self.keep_on_delete:
                self.vpc = None
            return ok(b'{}')
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
        reset_sticky(self)
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

    def test_budget_is_short_and_keeps_the_teardown_reserve(self):
        # The host pilot cap is 240 s including 70 s of transfer/staging; the guest total must be well inside it.
        self.assertLessEqual(pilot.TOTAL_SECONDS, 150)
        self.assertLessEqual(pilot.ACCEPT_SECONDS + 5 + pilot.TEARDOWN_SECONDS, pilot.TOTAL_SECONDS)
        self.assertLess(pilot.TEARDOWN_SECONDS, pilot.ACCEPT_SECONDS)
        for phase in (pilot.PREFLIGHT_SECONDS, pilot.PACKAGE_SECONDS, pilot.PLUGIN_SECONDS, pilot.CONFIG_SECONDS):
            self.assertLess(phase, pilot.TOTAL_SECONDS - pilot.TEARDOWN_SECONDS)
        self.assertLess(pilot.AGENT_WAIT_SECONDS, pilot.ACCEPT_SECONDS - pilot.TEARDOWN_SECONDS)
        self.assertLess(pilot.CHILD_CLOSE_SECONDS, pilot.TEARDOWN_SECONDS)

    def test_bounds_and_pins_of_the_reused_closure_module_and_agent_names(self):
        self.assertEqual(pilot.KUBE_LIMIT, 1 << 20)              # the accepted core's finite allowance, unmeasured fit
        self.assertEqual(pilot.OWNED_PROCESS, Path('/usr/local/lib/labapp/owned_process.py'))
        import hashlib
        self.assertEqual(hashlib.sha256(OWNED_FILE.read_bytes()).hexdigest(), pilot.OWNED_PROCESS_SHA256)
        self.assertEqual(pilot.OWNED_PROCESS_SHA256, '873c77d857d62280fbf9202a3544102f83e6cab39de0ddb05cd37107ca56e599')
        self.assertEqual(pilot.AGENT_NAMES, frozenset(CANONICAL))
        wiring = Path(__file__).resolve().parents[2] / 'wiringd.yaml'
        if wiring.exists():     # the repository's own canonical VLAB wiring names exactly these seven switches
            import re
            names = set(re.findall(r'^  name: ((?:leaf|spine)-\d\d)$', wiring.read_text(), re.M))
            self.assertEqual(names, set(CANONICAL))

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
        # Exactly the seven canonical names: seven agents with a wrong or duplicated name are not the fabric.
        self.assertEqual(pilot.agents_state(agents(names=CANONICAL[:6] + ['leaf-06'])), (7, False))
        self.assertEqual(pilot.agents_state(agents(names=CANONICAL[:6] + ['leaf-01'])), (7, False))
        self.assertEqual(pilot.agents_state(agents(names=list(reversed(CANONICAL)))), (7, True))

    def test_real_input_canonical_fails_capacity_and_course_passes(self):
        canon_ipv4, canon_vlan = real_namespaces(ROOT_WIRING)
        course_ipv4, course_vlan = real_namespaces(COURSE_WIRING)
        self.assertEqual(canon_ipv4['spec']['subnets'], ['10.0.0.0/16'])
        self.assertEqual(course_ipv4['spec']['subnets'], ['10.0.0.0/16', '10.10.0.0/16'])
        self.assertEqual(canon_vlan, course_vlan)
        self.assertFalse(pilot.namespaces_ok(canon_ipv4, canon_vlan))
        self.assertEqual(pilot.ipv4_capacity(canon_ipv4), {'ipv4_web': False, 'ipv4_worker': False})
        self.assertEqual(pilot.vlan_capacity(canon_vlan), {'vlan_web': True, 'vlan_worker': True})
        self.assertTrue(pilot.namespaces_ok(course_ipv4, course_vlan))
        self.assertEqual(pilot.ipv4_capacity(course_ipv4), {'ipv4_web': True, 'ipv4_worker': True})

    def test_course_wiring_is_the_root_wiring_plus_exactly_one_namespace_prefix(self):
        import hashlib
        root, course = ROOT_WIRING.read_bytes(), COURSE_WIRING.read_bytes()
        marker = b'  - 10.0.0.0/16\n'
        self.assertEqual(root.count(marker), 1)
        self.assertEqual(course, root.replace(marker, marker + b'  - 10.10.0.0/16\n'))
        self.assertEqual((len(root), len(course)), (10048, 10065))
        self.assertEqual(hashlib.sha256(root).hexdigest(),
                         'c522c64d80515c7484a67c27646acebf86073192f0f6ff9597497b990548806a')
        # Expected value supplied by Root in issue #552 (not independently derived or verified by this author).
        self.assertEqual(hashlib.sha256(course).hexdigest(),
                         '3294005892759029ef1a22f6fecc64a01ce5db07c44338a91ce89acdb4af1060')

    def test_capacity_helpers_are_closed_and_report_only_observed_booleans(self):
        self.assertIsNone(pilot.ipv4_capacity({'spec': {'subnets': ['not-a-cidr']}}))
        self.assertIsNone(pilot.vlan_capacity({'spec': {'ranges': [{'from': 1}]}}))
        self.assertIsNone(pilot.ipv4_capacity('x'))
        self.assertTrue(pilot.capacity_valid(dict(EMPTY)))
        self.assertTrue(pilot.capacity_valid({k: True for k in pilot.CAPACITY_KEYS}))
        for bad in (None, {}, dict(EMPTY, extra=True), dict(EMPTY, ipv4_web=1), dict(EMPTY, ipv4_web='true'),
                    {k: None for k in pilot.CAPACITY_KEYS[:-1]}):
            with self.subTest(bad=bad):
                self.assertFalse(pilot.capacity_valid(bad))

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
        good = json.dumps({'event': 'done', 'code': 'ok', 'cleanup': 'removed', 'agents': 7, **CLOSED})
        raw = '\n'.join([CANARY, '{"event":"uid","uid":"%s"}' % UID, '{"event":"uid","uid":"%s","x":1}' % 'bad',
                         '{"event":"uid","uid":"not-a-uid"}', '{"event":"config","status":"-"}', good,
                         '{"event":"done","code":"nope","cleanup":"removed","agents":7}',
                         '{"event":"x","pad":"' + 'a' * 600 + '"}']).encode()
        events = pilot.parse_events(raw)
        self.assertEqual(events['uid'], UID)
        self.assertEqual(events['done']['cleanup'], 'removed')
        self.assertNotIn('config', events)
        self.assertEqual(set(events), {'uid', 'done'})

    def test_done_event_with_missing_unknown_or_malformed_diagnostics_is_refused(self):
        base = {'event': 'done', 'code': 'refused', 'cleanup': 'not-needed', 'agents': 0, **CLOSED}
        self.assertIn('done', pilot.parse_events(json.dumps(base).encode()))
        ok_caps = dict(EMPTY, ipv4_web=False)
        self.assertEqual(pilot.parse_events(json.dumps(dict(base, step='namespaces', capacity=ok_caps)).encode())
                         ['done']['capacity'], ok_caps)
        bad = [{k: v for k, v in base.items() if k != 'step'}, {k: v for k, v in base.items() if k != 'capacity'},
               dict(base, step='bogus'), dict(base, step=CANARY), dict(base, step=3), dict(base, step=None),
               dict(base, extra=1), dict(base, capacity=None), dict(base, capacity=dict(EMPTY, ipv4_web='yes')),
               dict(base, capacity=dict(EMPTY, other=True)), dict(base, capacity={'ipv4_web': True}),
               dict(base, capacity=dict(EMPTY, ipv4_web=CANARY))]
        for event in bad:
            with self.subTest(event=event):
                self.assertNotIn('done', pilot.parse_events(json.dumps(event).encode()))

    def test_every_step_name_is_a_short_closed_token(self):
        self.assertEqual(len(set(pilot.STEPS)), len(pilot.STEPS))
        for step in pilot.STEPS:
            self.assertRegex(step, r'\A(-|[a-z][a-z0-9]*(-[a-z0-9]+)*)\Z')
        self.assertEqual(set(pilot.RESULT_KEYS) - {'agents', 'cleanup', 'code', 'config', 'packages', 'phase',
                                                   'plugin', 'status', 'vpc_uid'}, {'capacity', 'step', 'agent_snapshot'})


class AgentSnapshotTests(unittest.TestCase):
    def test_bootstrap_current_generation_empty_conditions_is_observed_but_still_fails(self):
        document = agents()
        for item in document['items']:
            item['status']['conditions'] = []  # pinned v0.96.2 bootstrap-compatible status
        before = json.dumps(document, sort_keys=True)
        snapshot = pilot.project_agent_snapshot(document)
        self.assertEqual(snapshot, {'shape': 'complete', 'rows': [[name, 3, 3, 'missing'] for name in CANONICAL]})
        self.assertEqual(pilot.agents_state(document), (7, False))
        self.assertEqual(json.dumps(document, sort_keys=True), before)

    def test_generation_sanitization_and_condition_precedence(self):
        # Invalid structure wins over duplicate Applied entries; valid other conditions are ignored.
        cases = [(None, 'missing'), ([], 'missing'),
                 ([{'type': 'Other', 'status': 'True'}], 'missing'),
                 *[([{'type': 'Applied', 'status': v}], v) for v in ('True', 'False', 'Unknown')],
                 ([{'type': 'Applied', 'status': 'True'}] * 2, 'duplicate'),
                 ([{'type': 'Applied', 'status': 'True'}] * 2 + [CANARY], 'malformed'),
                 ([{'type': 'Applied', 'status': CANARY}] * 2, 'malformed'),
                 ({}, 'malformed'), ([{}], 'malformed'), ([{'type': [], 'status': 'True'}], 'malformed')]
        for conditions, expected in cases:
            with self.subTest(expected=expected, conditions=conditions):
                document = agents()
                document['items'][0]['status']['conditions'] = conditions
                document['items'][0]['metadata']['generation'] = True
                document['items'][0]['status']['lastAppliedGen'] = 1 << 63
                snapshot = pilot.project_agent_snapshot(document)
                self.assertEqual(snapshot['shape'], 'complete')
                self.assertEqual(snapshot['rows'][0], ['leaf-01', None, None, expected])
                self.assertNotIn(CANARY, json.dumps(snapshot))
                self.assertTrue(pilot.agent_snapshot_valid(snapshot))
        for value in (-1, '3', 3.0, False, 1 << 63):
            self.assertFalse(pilot.agent_generation(value))
        for value in (0, (1 << 63) - 1):
            self.assertTrue(pilot.agent_generation(value))

    def test_membership_shape_precedence_and_never_selecting_duplicate_input(self):
        document = agents(names=CANONICAL[:6] + ['leaf-01'])
        snapshot = pilot.project_agent_snapshot(document)
        self.assertEqual(snapshot['shape'], 'names-invalid')
        self.assertEqual(snapshot['rows'][0], ['leaf-01', None, None, 'duplicate'])
        self.assertEqual(snapshot['rows'][-1], ['spine-02', None, None, 'missing'])
        document['items'].append({'metadata': {'name': CANARY}})
        self.assertEqual(pilot.project_agent_snapshot(document)['shape'], 'names-invalid')
        document['items'].append({'metadata': {'name': []}})
        snapshot = pilot.project_agent_snapshot(document)
        self.assertEqual(snapshot['shape'], 'malformed')
        self.assertEqual(len(snapshot['rows']), 7)
        self.assertNotIn(CANARY, json.dumps(snapshot))
        for document in (None, [], {}, {'items': None}):
            self.assertEqual(pilot.project_agent_snapshot(document), {'shape': 'malformed', 'rows': []})
        self.assertEqual(pilot.project_agent_snapshot({'items': [None]})['shape'], 'malformed')

    def test_worst_integer_snapshot_roundtrips_above_old_line_limit(self):
        snapshot = {'shape': 'complete', 'rows': [[n, (1 << 63) - 1, (1 << 63) - 1, 'Unknown'] for n in CANONICAL]}
        event = {'event': 'done', 'code': 'timeout', 'cleanup': 'removed', 'agents': 7,
                 **dict(COMPLETE, agent_snapshot=snapshot)}
        raw = json.dumps(event).encode()
        self.assertGreater(len(raw), 512)
        self.assertLessEqual(len(raw), 2048)
        self.assertEqual(pilot.parse_events(raw), {'done': event})
        self.assertEqual(pilot.parse_events(raw + b' ' * (2048 - len(raw))), {'done': event})
        self.assertEqual(pilot.parse_events(raw + b' ' * (2049 - len(raw))), {})
        self.assertEqual(pilot.parse_events(b'{"event":"done",' + raw[1:]), {})
        for kind in ({'event': 'uid', 'uid': UID}, {'event': 'config', 'status': 'installed'}):
            raw = json.dumps(kind).encode()
            self.assertEqual(pilot.parse_events(raw + b' ' * (513 - len(raw))), {})

    def test_snapshot_validator_rejects_open_or_malformed_values(self):
        valid = pilot.project_agent_snapshot(agents())
        bad = [None, {}, dict(valid, extra=CANARY), dict(valid, shape=CANARY), dict(valid, rows=[]),
               dict(valid, rows=valid['rows'][:-1]), {'shape': 'unobserved', 'rows': valid['rows']},
               dict(valid, rows=list(reversed(valid['rows'])))]
        for column, value in ((0, CANARY), (1, True), (1, -1), (2, 1 << 63), (3, CANARY)):
            rows = [list(r) for r in valid['rows']]
            rows[0][column] = value
            bad.append(dict(valid, rows=rows))
        base = {'event': 'done', 'code': 'timeout', 'cleanup': 'removed', 'agents': 7, **COMPLETE}
        for snapshot in bad:
            self.assertFalse(pilot.agent_snapshot_valid(snapshot))
            self.assertEqual(pilot.parse_events(json.dumps(dict(base, agent_snapshot=snapshot)).encode()), {})
        self.assertEqual(pilot.parse_events(json.dumps({k: v for k, v in base.items() if k != 'agent_snapshot'}).encode()), {})


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

    def test_package_state_parses_status_lines_and_definite_absence(self):
        out = (b'ii |libc6|2.39-0ubuntu8.6\ndpkg-query: no packages found matching jq\n'
               b'ii |libonig5|6.9.9-1build1\ndpkg-query: no packages found matching libjq1\n')
        with patch.object(pilot, 'run_child', lambda *a, **k: (1, out, 'ok')):
            self.assertEqual(ORIGINAL_PACKAGE_STATE(), {'libc6': ('ii', '2.39-0ubuntu8.6'),
                                                        'libonig5': ('ii', '6.9.9-1build1')})


class PackageParserThroughInstallTests(unittest.TestCase):
    """The REAL ``package_state`` parser feeding the REAL ``install_packages``; only the child runner is synthetic."""
    GOOD = {'libc6': ('ii ', '2.39-0ubuntu8.6'), 'libonig5': ('ii ', '6.9.9-1build1'),
            'libjq1': ('ii ', '1.7.1-3ubuntu0.24.04.2'), 'jq': ('ii ', '1.7.1-3ubuntu0.24.04.2')}

    def setUp(self):
        self.calls = []
        self.query = (0, b'', 'ok')
        self.jq = Path(tempfile.mkdtemp()) / 'jq'
        self.addCleanup(shutil.rmtree, self.jq.parent, True)
        for name, value in (('run_child', self.child), ('JQ', str(self.jq))):
            patcher = patch.object(pilot, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def rows(self, **change):
        rows = dict(self.GOOD, **change)
        out = b''
        for name, value in rows.items():
            out += (b'dpkg-query: no packages found matching %s\n' % name.encode()) if value is None else \
                ('%s|%s|%s\n' % (value[0], name, value[1])).encode()
        return out

    def child(self, argv, seconds, **kwargs):
        self.calls.append(argv)
        if argv[0] == pilot.DPKG_QUERY:
            return self.query
        if argv[1] == '--compare-versions':
            return 0, b'', 'ok'
        return 0, b'', 'ok'

    def installs(self):
        return [c for c in self.calls if len(c) > 1 and c[1] == '--install']

    def test_equal_state_and_definite_absence_still_work(self):
        self.query = (0, self.rows(), 'ok')
        self.assertEqual(pilot.install_packages(pilot.Clock(60)), 'unchanged')
        self.assertEqual(self.installs(), [])
        # absent (dpkg's own message, or an 'un' row with no version) is repaired by installing only that package
        states = [self.rows(libonig5=None), self.rows()]
        self.child_query = None

        def child(argv, seconds, **kwargs):
            if argv[0] == pilot.DPKG_QUERY:
                return 0 if len(self.installs()) else 1, states[1 if self.installs() else 0], 'ok'
            return self.child(argv, seconds, **kwargs)
        with patch.object(pilot, 'run_child', child):
            self.assertEqual(pilot.install_packages(pilot.Clock(60)), 'installed')
        self.assertEqual([Path(p).name for p in self.installs()[0][3:]], ['libonig5_6.9.9-1build1_amd64.deb'])
        unpacked_absent = self.rows().replace(b'ii |libonig5|6.9.9-1build1', b'un |libonig5|')
        self.assertEqual(self.parse(unpacked_absent).get('libonig5'), None)

    def parse(self, out):
        with patch.object(pilot, 'run_child', lambda *a, **k: (0, out, 'ok')):
            return ORIGINAL_PACKAGE_STATE()

    def test_real_dpkg_partial_unknown_and_error_states_are_refused_before_any_dpkg_mutation(self):
        for status in ('iU ', 'iF ', 'iH ', 'iW ', 'it ', 'iHR', 'iUR', 'ri ', 'rc ', 'hi ', 'pn ', 'un ', 'in ', 'ic '):
            for name in ('libonig5', 'libjq1', 'jq'):
                with self.subTest(status=status, name=name):
                    self.calls.clear()
                    version = '6.9.9-1build1' if name == 'libonig5' else '1.7.1-3ubuntu0.24.04.2'
                    self.query = (0, self.rows(**{name: (status, version)}), 'ok')
                    with self.assertRaises(pilot.Conflict):
                        pilot.install_packages(pilot.Clock(60))
                    self.assertEqual(self.installs(), [])

    def test_a_missing_jq_cannot_hide_a_partially_installed_library(self):
        # jq absent -> would install; the partially configured libjq1 row must still stop everything first.
        self.query = (1, self.rows(jq=None, libjq1=('iU ', '1.7.1-3ubuntu0.24.04.2')), 'ok')
        with self.assertRaises(pilot.Conflict):
            pilot.install_packages(pilot.Clock(60))
        self.assertEqual(self.installs(), [])

    def test_incomplete_duplicated_foreign_or_failed_queries_are_refused(self):
        good = self.rows()
        for query in ((0, good.replace(b'ii |jq|1.7.1-3ubuntu0.24.04.2\n', b''), 'ok'),     # jq unaccounted for
                      (0, good + good.splitlines(True)[0], 'ok'),                             # duplicate row
                      (0, good + b'ii |bash|5.2\n', 'ok'),                                    # foreign package
                      (0, good + b'garbage line\n', 'ok'),                                    # unknown line
                      (0, good.replace(b'ii |jq|1.7.1-3ubuntu0.24.04.2', b'ii |jq|'), 'ok'), # installed, no version
                      (2, good, 'ok'), (0, good, 'timeout'), (0, good, 'overflow')):
            with self.subTest(code=query[0], state=query[2]):
                self.query = query
                with self.assertRaises(pilot.Refused):
                    pilot.install_packages(pilot.Clock(60))
                self.assertEqual(self.installs(), [])


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
    def test_last_poll_snapshot_survives_cleanup_and_decoded_document_is_unchanged(self):
        documents = []
        cluster = self.cluster
        original = pilot.agents_state

        def predicate(document):
            documents.append(json.loads(json.dumps(document)))
            return original(document)
        with patch.object(pilot, 'agents_state', predicate):
            pilot.accept()
        self.assertGreater(len(documents), 1)
        self.assertEqual(self.done()['agent_snapshot'], pilot.project_agent_snapshot(documents[-1]))
        self.assertEqual(self.done()['agent_snapshot']['rows'], [[n, 3, 3, 'True'] for n in CANONICAL])
        self.assertEqual(cluster.deleted, 1)

    def test_projection_failure_preserves_primary_refusal_and_uid_cleanup(self):
        self.cluster.agent_count = 6
        with patch.object(pilot, 'project_agent_snapshot', side_effect=RuntimeError(CANARY)):
            pilot.accept()
        done = self.done()
        self.assertEqual((done['code'], done['cleanup']), ('refused', 'removed'))
        self.assertEqual(done['agent_snapshot'], {'shape': 'malformed', 'rows': []})
        self.assertEqual(self.cluster.deletes, [UID])
        self.assertNotIn(CANARY, json.dumps(self.events))

    def test_projection_cancellation_is_not_suppressed_and_uid_cleanup_still_runs(self):
        with patch.object(pilot, 'project_agent_snapshot', side_effect=pilot.Interrupted):
            pilot.accept()
        self.assertEqual((self.done()['code'], self.done()['cleanup']), ('cancelled', 'removed'))
        self.assertEqual(self.done()['agent_snapshot'], pilot.empty_agent_snapshot())
        self.assertEqual(self.cluster.deletes, [UID])

    def test_later_projection_cancellation_retains_last_closed_observation(self):
        project = pilot.project_agent_snapshot
        snapshots = []

        def cancel_second(document):
            if snapshots:
                raise pilot.Interrupted
            snapshots.append(project(document))
            return snapshots[-1]
        with patch.object(pilot, 'project_agent_snapshot', cancel_second):
            pilot.accept()
        self.assertEqual((self.done()['code'], self.done()['cleanup']), ('cancelled', 'removed'))
        self.assertEqual(self.done()['agent_snapshot'], snapshots[0])
        self.assertEqual(self.cluster.deletes, [UID])

    def test_bootstrap_condition_snapshot_does_not_make_lesson_pass(self):
        cluster = self.cluster
        now = [100.0]

        def sleep(seconds):
            now[0] += seconds

        def child(argv, seconds, **kw):
            if argv == ['kubectl', 'get', 'agents', '-o', 'json']:
                document = agents()
                for item in document['items']:
                    item['status']['conditions'] = []
                return 0, json.dumps(document).encode(), 'ok'
            return cluster(argv, seconds, **kw)
        with patch.object(pilot, 'run_child', child), patch.object(pilot, 'AGENT_WAIT_SECONDS', 10), \
                patch.object(pilot.time, 'monotonic', lambda: now[0]), patch.object(pilot, 'SLEEP', sleep):
            pilot.accept()
        self.assertEqual((self.done()['code'], self.done()['cleanup']), ('timeout', 'removed'))
        self.assertEqual(self.done()['agent_snapshot'],
                         {'shape': 'complete', 'rows': [[n, 3, 3, 'missing'] for n in CANONICAL]})

    def test_happy_path_uses_ordinary_kubectl_and_removes_only_the_owned_vpc(self):
        self.assertEqual(pilot.accept(), 0)
        done = self.done()
        self.assertEqual((done['code'], done['cleanup'], done['agents']), ('ok', 'removed', 7))
        self.assertIn({'event': 'uid', 'uid': UID}, self.events)
        self.assertIsNone(self.cluster.vpc)
        self.assertEqual(self.cluster.deleted, 1)
        self.assertEqual(self.cluster.deletes, [UID])                  # one atomic UID-preconditioned harness delete
        self.assertEqual(self.events[-1]['agents'], 7)
        for argv, env, _ in self.cluster.calls:
            self.assertEqual(env, pilot.STUDENT_ENV)                       # normal HOME/PATH, no KUBECONFIG
            self.assertNotIn('KUBECONFIG', env)
            self.assertFalse([a for a in argv if a.startswith(('--kubeconfig', '--context', '--as', '--token'))])
        kube = [a for a in self.cluster.argvs() if a[0] == 'kubectl']
        for step in (['apply', '-f'], ['describe', 'vpc', 'webapp-prod'], ['get', 'agents'],
                     ['get', 'agent', 'leaf-01', '-o', 'yaml'], ['plugin', 'list'], ['fabric', '--help'],
                     ['fabric', '--version'], ['fabric', 'switch', 'ip', '--name', 'leaf-01']):
            self.assertTrue(any(a[1:1 + len(step)] == step for a in kube), step)
        self.assertEqual([a for a in kube if a[1:2] == ['apply']][0][-2:], ['-o', 'json'])
        self.assertTrue(any(c[0] == ['jq', '--version'] for c in self.cluster.calls))    # real jq modality
        # The only delete is the harness raw DELETE, issued after every lesson command including the end state.
        names = [a[1] for a in kube]
        self.assertEqual(names.count('delete'), 1)
        last_lesson = max(i for i, a in enumerate(kube)
                          if a[1:4] == ['get', 'vpc', 'webapp-prod'] and '--ignore-not-found' not in a)
        self.assertLess(last_lesson, names.index('delete'))
        self.assertFalse([a for a in kube if a[1:3] == ['delete', 'vpc']])
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

    def intercept(self, prefix, reply):
        cluster = self.cluster

        def child(argv, seconds, **kw):
            if tuple(argv[:len(prefix)]) == prefix:
                return reply
            return cluster(argv, seconds, **kw)
        patcher = patch.object(pilot, 'run_child', child)
        patcher.start()
        self.addCleanup(patcher.stop)

    def assert_refused_before_mutation(self, code, step, capacity=None):
        done = self.done()
        self.assertEqual((done['code'], done['step'], done['cleanup'], done['agents']), (code, step, 'not-needed', 0))
        self.assertEqual(done['capacity'], dict(EMPTY, **(capacity or {})))
        self.assertTrue(pilot.capacity_valid(done['capacity']) and done['step'] in pilot.STEPS)
        self.assertEqual(set(done), {'event', 'code', 'cleanup', 'agents', 'step', 'capacity', 'agent_snapshot'})
        # Closed round trip through the host-side parser: a free string could never survive it.
        self.assertEqual(pilot.parse_events(json.dumps(done).encode())['done'], done)
        argvs = self.cluster.argvs()
        self.assertFalse([a for a in argvs if a[1:2] in (['apply'], ['delete'], ['create'], ['patch'])])
        self.assertIsNone(self.cluster.vpc)
        self.assertEqual((self.cluster.deleted, self.cluster.deletes), (0, []))
        self.assertNotIn(CANARY, json.dumps(done))

    def test_every_pre_apply_refusal_reports_its_closed_step_and_observed_capacity_without_mutation(self):
        kubectl, bad = 'kubectl', lambda data: (0, data, 'ok')
        cases = (
            ('context', (kubectl, 'config', 'current-context'), bad(CANARY.encode() + b'\n'), 'refused', {}),
            ('contexts', (kubectl, 'config', 'get-contexts'), bad(b'vlab\nother\n'), 'refused', {}),
            ('plugin', (kubectl, 'plugin', 'list'), bad(b'unrelated\n'), 'refused', {}),
            ('fabric', (kubectl, 'fabric', '--version'), bad(b'  \n'), 'refused', {}),
            ('jq', ('jq', '--version'), bad(b'jq-1.6\n'), 'refused', {}),
            ('vpc-absent', (kubectl, 'get', 'vpc', 'webapp-prod', '-o', 'name'), bad(b'vpc.vpc/webapp-prod\n'),
             'refused', {}),
            ('ipv4-read', (kubectl, 'get', 'ipv4namespace'), bad(CANARY.encode()), 'refused', {}),
            ('vlan-read', (kubectl, 'get', 'vlannamespace'), bad(b'[]'), 'refused', {'ipv4_web': True, 'ipv4_worker': True}),
            ('context', (kubectl, 'config', 'current-context'), (-9, b'', 'timeout'), 'timeout', {}),
        )
        for step, prefix, reply, code, capacity in cases:
            with self.subTest(step=step, code=code):
                self.setUp()
                self.intercept(prefix, reply)
                pilot.accept()
                self.assert_refused_before_mutation(code, step, capacity)

    def test_binary_refusal_is_a_closed_step(self):
        with patch.object(pilot, 'verify_kubectl', side_effect=pilot.Refused(CANARY)):
            pilot.accept()
        self.assert_refused_before_mutation('refused', 'binary')

    def test_real_canonical_input_refuses_at_namespaces_with_observed_capacity_and_course_input_does_not(self):
        self.cluster.ipv4, self.cluster.vlans = real_namespaces(ROOT_WIRING)
        pilot.accept()
        self.assert_refused_before_mutation('refused', 'namespaces',
                                            {'ipv4_web': False, 'ipv4_worker': False,
                                             'vlan_web': True, 'vlan_worker': True})
        self.setUp()
        pilot.accept()      # the cluster now serves the REAL course wiring namespaces
        done = self.done()
        self.assertEqual((done['code'], done['cleanup'], done['agents']), ('ok', 'removed', 7))
        self.assertEqual(done['capacity'], {'ipv4_web': True, 'ipv4_worker': True, 'vlan_web': True,
                                            'vlan_worker': True, 'no_conflict': True})
        self.assertEqual(done['step'], 'post-apply')

    def test_vlan_and_ipv4_capacity_each_reported_separately(self):
        self.cluster.vlans = {'spec': {'ranges': [{'from': 1000, 'to': 1005}, {'from': 1020, 'to': 1020}]}}
        pilot.accept()
        self.assert_refused_before_mutation('refused', 'namespaces',
                                            {'ipv4_web': True, 'ipv4_worker': True,
                                             'vlan_web': False, 'vlan_worker': True})

    def test_conflict_reports_the_conflicts_step_and_false_no_conflict(self):
        self.cluster.others = [{'spec': {'ipv4Namespace': 'default', 'vlanNamespace': 'default',
                                         'subnets': {'x': {'subnet': '10.10.10.0/24', 'vlan': 5}}}}]
        pilot.accept()
        self.assert_refused_before_mutation('conflict', 'conflicts',
                                            {'ipv4_web': True, 'ipv4_worker': True, 'vlan_web': True,
                                             'vlan_worker': True, 'no_conflict': False})

    def test_malformed_namespace_leaves_capacity_unobserved_null(self):
        self.cluster.ipv4 = {'spec': {'subnets': ['not-a-cidr']}}
        pilot.accept()
        self.assert_refused_before_mutation('refused', 'namespaces', {'vlan_web': True, 'vlan_worker': True})

    def test_diagnostics_never_replace_the_primary_failure_or_cleanup(self):
        self.cluster.on_call[('describe',)] = lambda: setattr(self.cluster, 'vpc', vpc(uid='99999999-2222-3333-4444-555555555555'))
        pilot.accept()
        done = self.done()
        self.assertEqual((done['code'], done['cleanup'], done['step']), ('refused', 'preserved', 'endstate'))
        self.assertEqual(self.cluster.deleted, 0)
        # An unexpected step/capacity in state degrades to the empty closed form and never raises or leaks.
        self.events.clear()
        self.cluster.vpc = None

        def corrupt(clock, state):
            state['step'], state['capacity'] = CANARY, {'ipv4_web': CANARY}
            raise pilot.Refused(CANARY)
        with patch.object(pilot, 'lesson', corrupt):
            pilot.accept()
        done = self.done()
        self.assertEqual((done['code'], done['step'], done['capacity']), ('refused', '-', EMPTY))
        self.assertNotIn(CANARY, json.dumps(done))

    def test_foreign_replacement_after_create_is_preserved(self):
        def swap():
            self.cluster.vpc = vpc(uid='99999999-2222-3333-4444-555555555555')
        self.cluster.on_call[('describe',)] = swap
        pilot.accept()
        done = self.done()
        self.assertEqual((done['code'], done['cleanup']), ('refused', 'preserved'))   # end-state checkpoint failed
        self.assertEqual(self.cluster.deleted, 0)
        self.assertEqual(self.cluster.deletes, [])
        self.assertEqual(self.cluster.vpc['metadata']['uid'], '99999999-2222-3333-4444-555555555555')

    def test_replacement_between_the_observation_and_the_delete_is_refused_atomically(self):
        other = '99999999-2222-3333-4444-555555555555'
        self.cluster.on_call[('delete',)] = lambda: setattr(self.cluster, 'vpc', vpc(uid=other))
        pilot.accept()
        done = self.done()
        self.assertEqual((done['code'], done['cleanup']), ('ok', 'preserved'))
        self.assertEqual(self.cluster.deletes, [UID])              # the delete carried the observed UID...
        self.assertEqual(self.cluster.deleted, 0)                  # ...and the server refused it for the new object
        self.assertEqual(self.cluster.vpc['metadata']['uid'], other)

    def test_vanished_before_the_delete_is_absent_not_removed(self):
        self.cluster.on_call[('delete',)] = lambda: setattr(self.cluster, 'vpc', None)
        pilot.accept()
        self.assertEqual(self.done()['cleanup'], 'absent')

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

    def timed_accept(self, *, latency=0, converge_at=None, deadline=225, late_poll=None, late_positive=False):
        """Actual lesson/Clock/cleanup, synthetic child latency and independent elapsed time."""
        now, calls = [100.0], []
        cluster = self.cluster

        def child(argv, seconds, **kw):
            poll = argv == ['kubectl', 'get', 'agents', '-o', 'json']
            delay = late_poll if poll and late_poll is not None else latency
            calls.append((list(argv), seconds))
            now[0] += delay if late_positive and poll else min(delay, seconds)
            if delay > seconds and not (late_positive and poll):
                return -9, b'', 'timeout'
            reply = cluster(argv, seconds, **kw)
            if poll and converge_at is not None:
                return 0, json.dumps(agents(applied=now[0] - 100 >= converge_at)).encode(), 'ok'
            return reply

        def sleep(seconds):
            now[0] += seconds
        with patch.object(pilot.time, 'monotonic', lambda: now[0]), \
                patch.object(pilot, 'SLEEP', sleep), patch.object(pilot, 'run_child', child):
            pilot.accept(deadline)
        return now[0] - 100, calls

    def test_healthy_real_lesson_over_old_fifty_second_work_budget_fits_parent(self):
        elapsed, calls = self.timed_accept(latency=2)
        self.assertGreater(elapsed, 50)
        self.assertLess(elapsed, 125)
        self.assertEqual((self.done()['code'], self.done()['cleanup'], self.done()['step']),
                         ('ok', 'removed', 'post-apply'))
        self.assertEqual(self.cluster.deletes, [UID])
        self.assertTrue(all(seconds <= 15 for argv, seconds in calls if argv[1] != 'delete'))

    def test_declared_sixty_second_agent_policy_allows_forty_second_convergence(self):
        elapsed, _ = self.timed_accept(latency=0.1, converge_at=40)
        self.assertEqual(pilot.AGENT_WAIT_SECONDS, 60)
        self.assertGreater(elapsed, 40)
        self.assertEqual((self.done()['code'], self.done()['cleanup']), ('ok', 'removed'))

    def test_late_second_good_poll_cannot_pass_and_cleans_the_captured_uid(self):
        self.cluster.converge_after = 0
        with patch.object(pilot, 'AGENT_WAIT_SECONDS', 20):
            _, calls = self.timed_accept(late_poll=14.9)
        self.assertEqual((self.done()['code'], self.done()['cleanup'], self.done()['step']),
                         ('timeout', 'removed', 'agents-query'))
        polls = [seconds for argv, seconds in calls if argv == ['kubectl', 'get', 'agents', '-o', 'json']]
        self.assertEqual(len(polls), 2)
        self.assertLess(polls[1], 1)
        self.assertEqual(self.cluster.deletes, [UID])

    def test_late_positive_second_poll_is_rejected_at_original_agent_end(self):
        self.cluster.converge_after = 0
        with patch.object(pilot, 'AGENT_WAIT_SECONDS', 20):
            self.timed_accept(late_poll=14.9, late_positive=True)
        self.assertEqual((self.done()['code'], self.done()['cleanup'], self.done()['step']),
                         ('timeout', 'removed', 'agent-budget'))
        self.assertEqual(self.cluster.polls, 2)

    def test_parent_clipped_acceptance_cleans_up_without_renewing_work_budget(self):
        elapsed, _ = self.timed_accept(latency=2, deadline=145)
        self.assertLess(elapsed, 45)
        self.assertEqual((self.done()['code'], self.done()['cleanup']), ('timeout', 'removed'))
        self.assertEqual(self.cluster.deletes, [UID])

    def test_clock_cutoff_reports_closed_site_and_uses_separate_uid_teardown(self):
        self.cluster.converge_after = 10 ** 9
        _, _ = self.timed_accept(latency=0, deadline=145)
        self.assertEqual((self.done()['code'], self.done()['cleanup'], self.done()['step']),
                         ('timeout', 'removed', 'agent-budget'))
        self.assertEqual(pilot.parse_events(json.dumps(self.done()).encode())['done'], self.done())

    def test_actual_cli_expired_absolute_end_never_applies_or_deletes(self):
        with patch.object(pilot.time, 'monotonic', lambda: 100), \
                patch.object(pilot.signal, 'signal'), patch.object(pilot.os, 'umask'):
            self.assertEqual(pilot.main(['x', 'accept', '99.000000000']), 0)
        self.assertEqual((self.done()['code'], self.done()['step'], self.done()['cleanup']),
                         ('timeout', 'accept-budget', 'not-needed'))
        self.assertEqual(self.cluster.calls, [])
        self.assertEqual(self.cluster.deletes, [])

    def test_actual_cli_delayed_entry_keeps_delegated_end_and_never_restarts_allowance(self):
        # Parent delegated end=145 at t=100; child starts at t=120. With its
        # unchanged 20s UID reserve, only 5s of lesson work remains, not 105s.
        now, caps = [120.0], []
        cluster = self.cluster

        def child(argv, seconds, **kw):
            caps.append(seconds)
            now[0] += min(2, seconds)
            if seconds < 2:
                return -9, b'', 'timeout'
            return cluster(argv, seconds, **kw)
        with patch.object(pilot.time, 'monotonic', lambda: now[0]), \
                patch.object(pilot, 'run_child', child), patch.object(pilot.signal, 'signal'), \
                patch.object(pilot.os, 'umask'):
            self.assertEqual(pilot.main(['x', 'accept', '145.000000000']), 0)
        self.assertEqual(caps, [5, 3, 1])
        self.assertEqual(now[0], 125)
        self.assertEqual((self.done()['code'], self.done()['step'], self.done()['cleanup']),
                         ('timeout', 'plugin', 'not-needed'))
        self.assertFalse([a for a in self.cluster.argvs() if a[1] in ('apply', 'delete')])
        self.assertEqual(self.cluster.deletes, [])

    def test_ambiguous_apply_with_a_matching_object_is_never_adopted_or_deleted(self):
        # The create response was lost; an object with exactly the requested spec exists. A matching spec is NOT
        # ownership: nothing is read back, adopted or deleted, and the result stays unresolved.
        for state in ('timeout', 'overflow'):
            with self.subTest(state):
                self.setUp()
                self.cluster.apply_state = state
                pilot.accept()
                done = self.done()
                self.assertEqual((done['code'], done['cleanup']), ('timeout' if state == 'timeout' else 'refused',
                                                                    'uncertain'))
                self.assertEqual((self.cluster.deleted, self.cluster.deletes), (0, []))
                self.assertIsNotNone(self.cluster.vpc)
                self.assertFalse([e for e in self.events if e.get('event') == 'uid'])
                after = [a for a in self.cluster.argvs()[self.apply_index():]]
                self.assertEqual(after, [])                          # no kubectl call at all after the ambiguous apply

    def apply_index(self):
        return [a[1:2] == ['apply'] for a in self.cluster.argvs()].index(True) + 1

    def test_unproven_apply_responses_leave_the_object_unresolved(self):
        def foreign_uid(r):
            r['metadata']['uid'] = 'not-a-uid'

        def configured(r):
            r['metadata']['generation'] = 2          # an existing object was reconfigured, not created

        def other_spec(r):
            r['spec']['ipv4Namespace'] = 'other'
        def no_uid(r):
            r['metadata'].pop('uid')
        for mutate in (foreign_uid, configured, other_spec, lambda r: b'vpc.vpc.githedgehog.com/webapp-prod created\n',
                       lambda r: b'', no_uid):
            with self.subTest(mutate):
                self.setUp()
                self.cluster.apply_mutate = mutate
                pilot.accept()
                done = self.done()
                self.assertEqual((done['code'], done['cleanup']), ('refused', 'uncertain'))
                self.assertEqual((self.cluster.deleted, self.cluster.deletes), (0, []))
                self.assertIsNotNone(self.cluster.vpc)
                self.assertFalse([e for e in self.events if e.get('event') == 'uid'])

    def test_the_uid_comes_only_from_the_create_response_and_is_published_immediately(self):
        early, original = [], self.cluster.__call__

        def spy(argv, seconds, **kw):
            if argv[1:2] == ['get'] and argv[2:4] == ['vpc', 'webapp-prod'] and '--ignore-not-found' not in argv \
                    and {'event': 'uid', 'uid': UID} not in self.events:
                early.append(argv)          # a follow-up read before the UID was published
            return original(argv, seconds, **kw)
        with patch.object(pilot, 'run_child', spy):
            pilot.accept()
        self.assertEqual(early, [])
        self.assertEqual((self.done()['code'], self.done()['cleanup']), ('ok', 'removed'))

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
        with patch.object(pilot, 'TEARDOWN_SECONDS', 1.0):       # the object never disappears: bounded polling
            pilot.accept()
        done = self.done()
        self.assertEqual((done['code'], done['cleanup']), ('ok', 'uncertain'))
        self.assertEqual(self.cluster.deletes, [UID])

    def test_overflowing_kubectl_output_is_refused(self):
        self.cluster.output_state = 'overflow'
        pilot.accept()
        self.assertEqual(self.done()['code'], 'refused')
        self.assertEqual(self.done()['cleanup'], 'removed')

    def test_teardown_only_preserves_unknown_ownership(self):
        self.cluster.vpc = vpc()
        self.assertEqual(pilot.teardown_only('-'), 0)
        self.assertEqual(self.done()['cleanup'], 'uncertain')       # unknown ownership: nothing is read or deleted
        self.assertEqual((self.cluster.deleted, self.cluster.calls), (0, []))
        self.events.clear()
        self.cluster.vpc = vpc(uid='99999999-2222-3333-4444-555555555555')
        pilot.teardown_only(UID)
        self.assertEqual(self.done()['cleanup'], 'preserved')
        self.assertEqual(self.cluster.deleted, 0)
        self.cluster.vpc = vpc()
        self.events.clear()
        pilot.teardown_only(UID)
        self.assertEqual(self.done()['cleanup'], 'removed')
        self.events.clear()
        pilot.teardown_only(UID)
        self.assertEqual(self.done()['cleanup'], 'absent')


class RunTests(unittest.TestCase):
    def setUp(self):
        reset_sticky(self)
        self.out, self.children = [], []
        self.plan = {'configure': (0, {'config': 'installed'}, 'ok'),
                     'accept': (0, {'uid': UID, 'done': {'event': 'done', 'code': 'ok', 'cleanup': 'removed',
                                                         'agents': 7, **COMPLETE}}, 'ok'),
                     'teardown': (0, {'done': {'event': 'done', 'code': 'ok', 'cleanup': 'removed', 'agents': 0,
                                               **CLOSED}}, 'ok')}

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

    def test_snapshot_is_carried_to_root_without_overriding_child_primary_failure(self):
        snapshot = pilot.project_agent_snapshot(agents(applied=False))
        done = {'event': 'done', 'code': 'timeout', 'cleanup': 'removed', 'agents': 7,
                **dict(COMPLETE, agent_snapshot=snapshot)}
        self.plan['accept'] = (0, {'uid': UID, 'done': done}, 'ok')
        pilot.run()
        result = self.out[-1]
        self.assertEqual((result['status'], result['code'], result['cleanup']), ('failed', 'timeout', 'removed'))
        self.assertEqual(result['agent_snapshot'], snapshot)
        self.assertLessEqual(len(json.dumps(result).encode()), pilot.OUTPUT_LIMIT)

    def test_delegation_carries_original_root_end_after_setup_elapsed(self):
        now, delegated = [100.0], []

        def packages(clock):
            now[0] += 80
            return 'unchanged'

        def child(mode, seconds, source, extra=()):
            if mode == 'accept':
                delegated.append((seconds, float(extra[0])))
            return self.plan[mode]
        with patch.object(pilot.time, 'monotonic', lambda: now[0]), \
                patch.object(pilot, 'install_packages', packages), patch.object(pilot, 'student_child', child):
            pilot.run()
        self.assertEqual(delegated, [(50, 225)])  # 45 child total, including its unchanged 20s UID reserve
        self.assertEqual(self.out[-1]['status'], 'passed')

    def test_insufficient_original_root_budget_refuses_before_accept_or_apply(self):
        now = [100.0]

        def packages(clock):
            now[0] += 109
            return 'unchanged'
        with patch.object(pilot.time, 'monotonic', lambda: now[0]), \
                patch.object(pilot, 'install_packages', packages):
            pilot.run()
        self.assertEqual([mode for mode, extra in self.children], ['configure'])
        self.assertEqual((self.out[-1]['code'], self.out[-1]['step'], self.out[-1]['cleanup']),
                         ('timeout', 'accept-budget', 'not-needed'))

    def test_late_child_success_cannot_pass_but_primary_failures_and_safety_survive(self):
        for verdict in ('ok', 'cancelled', 'refused', 'uncertain', 'forced'):
            with self.subTest(verdict=verdict):
                pilot.STICKY.clear()
                now, calls = [100.0], []

                def child(mode, seconds, source, extra=()):
                    calls.append(mode)
                    if mode == 'configure':
                        return self.plan[mode]
                    self.assertEqual(mode, 'accept')
                    now[0] = 231  # original root work end=230 (150 total minus 20 reserve)
                    done = {'event': 'done', 'code': 'ok' if verdict == 'forced' else verdict,
                            'cleanup': 'removed', 'agents': 7, **COMPLETE}
                    return (-9 if verdict == 'forced' else 0), {'uid': UID, 'done': done}, 'ok'

                with patch.object(pilot.time, 'monotonic', lambda: now[0]), \
                        patch.object(pilot, 'student_child', child):
                    pilot.run()
                result = self.out[-1]
                expected = 'timeout' if verdict == 'ok' else 'uncertain' if verdict == 'forced' else verdict
                self.assertEqual((result['status'], result['code']), ('failed', expected))
                self.assertEqual(result['vpc_uid'], UID)
                self.assertEqual((result['agents'], result['capacity']), (7, COMPLETE['capacity']))
                self.assertEqual(result['cleanup'], 'uncertain' if verdict == 'forced' else 'removed')
                self.assertEqual(bool(pilot.STICKY), verdict == 'forced')
                self.assertEqual(calls, ['configure', 'accept'])

    def test_success_requires_completed_step_and_every_capacity_observed_true(self):
        cases = [(step, dict(COMPLETE['capacity'])) for step in pilot.STEPS if step != 'post-apply']
        cases.extend(('post-apply', dict(COMPLETE['capacity'], **{key: value}))
                     for key in pilot.CAPACITY_KEYS for value in (False, None))
        for step, capacity in cases:
            with self.subTest(step=step, capacity=capacity):
                self.children.clear()
                self.plan['accept'] = (0, {'uid': UID, 'done': {
                    'event': 'done', 'code': 'ok', 'cleanup': 'removed', 'agents': 7,
                    'step': step, 'capacity': capacity, 'agent_snapshot': pilot.empty_agent_snapshot()}}, 'ok')
                pilot.run()
                result = self.out[-1]
                self.assertEqual((result['status'], result['phase'], result['code']),
                                 ('failed', 'accept', 'refused'))
                self.assertEqual((result['step'], result['capacity']), (step, capacity))
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
                                                         'agents': 3, **CLOSED}}, 'ok')
        pilot.run()
        result = self.out[-1]
        self.assertEqual((result['status'], result['code'], result['agents'], result['cleanup']),
                         ('failed', 'timeout', 3, 'removed'))

    def test_child_pre_apply_diagnostics_reach_the_report_and_keep_the_primary_code(self):
        caps = dict(EMPTY, ipv4_web=False, ipv4_worker=False, vlan_web=True, vlan_worker=True)
        self.plan['accept'] = (0, {'done': {'event': 'done', 'code': 'refused', 'cleanup': 'not-needed', 'agents': 0,
                                            'step': 'namespaces', 'capacity': caps,
                                            'agent_snapshot': pilot.empty_agent_snapshot()}}, 'ok')
        pilot.run()
        result = self.out[-1]
        self.assertEqual((result['status'], result['phase'], result['code'], result['cleanup'], result['vpc_uid']),
                         ('failed', 'accept', 'refused', 'not-needed', ''))
        self.assertEqual((result['step'], result['capacity']), ('namespaces', caps))
        self.assertEqual(set(result), set(pilot.RESULT_KEYS))
        self.assertLessEqual(len(json.dumps(result)), pilot.OUTPUT_LIMIT)
        self.assertEqual([c[0] for c in self.children], ['configure', 'accept'])     # no teardown, no further mutation

    def test_non_accept_failures_and_malformed_child_diagnostics_stay_empty_or_refuse(self):
        pilot.run()
        self.assertEqual((self.out[-1]['step'], self.out[-1]['capacity']),
                         (COMPLETE['step'], COMPLETE['capacity']))
        self.plan['configure'] = (3, {}, 'ok')
        pilot.run()
        self.assertEqual((self.out[-1]['code'], self.out[-1]['step'], self.out[-1]['capacity']), ('conflict', '-', EMPTY))
        # A done event with a free-string step never reaches parse_events' result, so the worker is "unfinished".
        raw = json.dumps({'event': 'done', 'code': 'refused', 'cleanup': 'not-needed', 'agents': 0,
                          'step': CANARY, 'capacity': EMPTY}).encode()
        self.assertEqual(pilot.parse_events(raw), {})
        self.assertEqual([c[0] for c in self.children], ['configure', 'accept', 'configure'])

    def test_a_worker_that_exited_by_itself_without_done_gets_the_teardown_safety_net_for_its_reported_uid(self):
        self.plan['accept'] = (1, {'uid': UID}, 'ok')
        pilot.run()
        result = self.out[-1]
        self.assertEqual((result['status'], result['cleanup'], result['vpc_uid']), ('failed', 'removed', UID))
        self.assertEqual(self.children[-1], ('teardown', (UID,)))
        self.assertFalse(pilot.STICKY)

    def test_a_forcibly_stopped_worker_is_sticky_uncertain_with_no_further_guest_work(self):
        for plan in ((-9, {'uid': UID}, 'timeout'), (-9, {'uid': UID}, 'ok'), (0, {'uid': UID}, 'overflow'),
                     (-15, {}, 'timeout')):
            with self.subTest(state=plan[2], code=plan[0]):
                pilot.STICKY.clear()
                self.children.clear()
                self.plan['accept'] = plan
                pilot.run()
                result = self.out[-1]
                self.assertEqual((result['status'], result['code'], result['cleanup']), ('failed', 'uncertain', 'uncertain'))
                self.assertEqual([c[0] for c in self.children], ['configure', 'accept'])   # no teardown, nothing after
                self.assertTrue(pilot.STICKY)
        # a worker that finished AND reported a clean removal is still never a pass once it was forcibly stopped
        pilot.STICKY.clear()
        self.plan['accept'] = (-9, {'uid': UID, 'done': {'event': 'done', 'code': 'ok', 'cleanup': 'removed',
                                                          'agents': 7, **CLOSED}}, 'timeout')
        pilot.run()
        self.assertEqual((self.out[-1]['status'], self.out[-1]['cleanup']), ('failed', 'uncertain'))

    def test_a_forcibly_stopped_configure_worker_is_sticky_and_stops_everything(self):
        self.plan['configure'] = (-9, {}, 'timeout')
        pilot.run()
        self.assertEqual((self.out[-1]['status'], self.out[-1]['code'], self.out[-1]['config']),
                         ('failed', 'uncertain', '-'))
        self.assertEqual([c[0] for c in self.children], ['configure'])
        self.assertTrue(pilot.STICKY)

    def test_an_unreported_possibly_created_object_is_never_touched(self):
        self.plan['accept'] = (1, {}, 'ok')
        pilot.run()
        self.assertEqual([c[0] for c in self.children], ['configure', 'accept'])      # no teardown child, no '-' marker
        self.assertEqual((self.out[-1]['cleanup'], self.out[-1]['status']), ('uncertain', 'failed'))

    def test_sticky_state_can_never_pass(self):
        pilot.STICKY.append('earlier child not proven closed')
        pilot.run()
        self.assertEqual(self.out[-1]['status'], 'failed')

    def test_cleanup_uncertainty_can_never_pass(self):
        for cleanup in ('uncertain', 'preserved', 'absent', 'not-needed'):
            with self.subTest(cleanup):
                self.plan['accept'] = (0, {'uid': UID, 'done': {'event': 'done', 'code': 'ok', 'cleanup': cleanup,
                                                                 'agents': 7, **CLOSED}}, 'ok')
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

    def test_accept_deadline_dispatch_is_numeric_bounded_and_not_renewed(self):
        with patch.object(pilot.signal, 'signal'), patch.object(pilot.os, 'umask'), \
                patch.object(pilot.time, 'monotonic', lambda: 100), patch.object(pilot, 'accept', return_value=0) as accept:
            for bad in ('nan', 'inf', '-1', '226', '200x', '200.1234567890'):
                self.assertEqual(pilot.main(['x', 'accept', bad]), 2)
            accept.assert_not_called()
            self.assertEqual(pilot.main(['x', 'accept', '145.000000000']), 0)
            accept.assert_called_once_with(145.0)


class RunChildTests(unittest.TestCase):
    ENV = {'PATH': os.environ.get('PATH', '/usr/bin:/bin')}

    def setUp(self):
        use_sibling_owned(self)

    def python(self, code, seconds=10, **kwargs):
        try:
            return pilot.run_child([sys.executable, '-c', code], seconds, env=self.ENV, **kwargs)
        except pilot.Uncertain:
            if pilot.STICKY and 'sleep(60)' in code:
                # Positive group absence needs an init that reaps orphaned zombies of killed descendants; a
                # container without one cannot show it. That is NOT passing evidence for this test.
                self.skipTest('orphan zombies are not reaped here; group absence cannot be shown')
            raise

    def test_the_pinned_closure_module_is_loaded_from_exactly_the_hashed_bytes(self):
        module = pilot.load_owned()
        self.assertTrue(hasattr(module, 'OwnedGroup'))
        self.assertIs(pilot.load_owned(), module)
        pilot.OWNED.clear()
        tampered = Path(tempfile.mkdtemp()) / 'owned_process.py'
        self.addCleanup(shutil.rmtree, tampered.parent, True)
        tampered.write_bytes(OWNED_FILE.read_bytes() + b'\n# tampered\n')
        with patch.object(pilot, 'OWNED_PROCESS', tampered), self.assertRaises(pilot.Refused):
            pilot.load_owned()
        self.assertEqual(pilot.OWNED, [])

    def test_an_unproven_closure_is_sticky_and_refuses_every_later_child(self):
        class Lost:
            def __init__(self, proc):
                self.proc = proc

            def status(self):
                return None

            def close(self, term_grace, final=3.0, *, until=None):
                os.killpg(self.proc.pid, 9)       # the test's own child; the owner reports closure NOT proven
                self.proc.wait(timeout=5)
                return False
        module = pilot.load_owned()
        with patch.object(module, 'OwnedGroup', Lost):
            with self.assertRaises(pilot.Uncertain):
                self.python('import time;time.sleep(30)', seconds=.3)
        self.assertTrue(pilot.STICKY)
        spawned = []
        with patch.object(pilot.subprocess, 'Popen', lambda *a, **k: spawned.append(a)), \
                self.assertRaises(pilot.Uncertain):
            self.python('print(1)')
        self.assertEqual(spawned, [])             # refused before any process (hence any mutation) is started

    def test_a_primary_exception_is_preserved_when_closure_is_unproven(self):
        class Lost:
            def __init__(self, proc):
                self.proc = proc

            def status(self):
                raise KeyboardInterrupt('primary')

            def close(self, term_grace, final=3.0, *, until=None):
                os.killpg(self.proc.pid, 9)
                self.proc.wait(timeout=5)
                return False
        module = pilot.load_owned()
        with patch.object(module, 'OwnedGroup', Lost), self.assertRaises(KeyboardInterrupt):
            self.python('import time;time.sleep(30)')
        self.assertTrue(pilot.STICKY)

    def test_a_nested_child_in_its_own_session_outlives_the_forced_stop_of_its_worker(self):
        """Why a forcibly stopped worker is sticky uncertain: the group kill of the outer child does not reach the
        nested kubectl-like child that the worker's own run_child put in a separate session."""
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, True)
        marker = work / 'nested.pid'
        script = (
            'import os,sys\nfrom pathlib import Path\nfrom types import SimpleNamespace\n'
            'sys.path.insert(0,%r)\nimport student_vpc_pilot as p\n'
            'p.OWNED_PROCESS=Path(%r)\np.regular=lambda *a,**k: SimpleNamespace(st_mode=0o100644)\n'
            'nested="import os,time;open(%r,\'w\').write(str(os.getpid()));time.sleep(120)"\n'
            'p.run_child([sys.executable,"-c",nested],120,env={"PATH":os.environ["PATH"]})\n'
            % (str(Path(__file__).parent), str(OWNED_FILE), str(marker)))
        started = time.monotonic()
        code, out, state = pilot.run_child([sys.executable, '-c', script], 3, env=self.ENV)
        self.assertEqual(state, 'timeout')                     # the worker was forcibly stopped by its parent
        self.assertLess(time.monotonic() - started, 15)
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(.05)
        pid = int(marker.read_text())
        self.assertGreater(pid, 1)
        self.addCleanup(lambda: os.kill(pid, 9) if os.path.exists('/proc/%d' % pid) else None)   # the test's own child
        stat_text = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()[0]
        self.assertNotIn(stat_text, ('Z', 'X'))                # still alive: outside the group the parent killed
        self.assertNotEqual(os.getpgid(pid), 0)

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
