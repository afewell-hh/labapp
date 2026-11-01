"""Public upstream serializer/default fixtures through actual api_ready.

The hosted wrapper supplies three bounded public files; absence fails, never skips.
They come from the unchanged canonical wiringd.yaml (43 objects) plus a public
installer-shaped Fabricator/ControlNode, run through the pinned real loaders,
printers and typed defaults. GuestEnvironment supplies readiness/node/kubeconfig/
VM-config fakes. No native commands, credentials or network are used by this suite.
Expected metadata below is written from endpoint/type tables, not derived by
reusing the production matcher.
"""
from collections import Counter
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import unittest
from unittest.mock import patch

import yaml
import vlab_core as core
from test_vlab_core import GuestEnvironment

PREFIX = 'fabric.githedgehog.com/'
NAMES = ('expected.yaml', 'observed.json', 'meta.json')
COUNTS = {'Fabricator': 1, 'ControlNode': 1, 'Switch': 7, 'Server': 10,
          'Connection': 21, 'SwitchGroup': 3, 'VLANNamespace': 1, 'IPv4Namespace': 1}
WIRING_COUNTS = {k: v for k, v in COUNTS.items() if k not in ('Fabricator', 'ControlNode')}

# Independent endpoint/type tables for the canonical objects.
SWITCH_GROUPS = {'leaf-01': ['mclag-1'], 'leaf-02': ['mclag-1'], 'leaf-03': ['eslag-1'],
                 'leaf-04': ['eslag-1'], 'leaf-05': [], 'spine-01': [], 'spine-02': []}
CONNECTIONS = {
    'leaf-01--mclag-domain--leaf-02': ('mclag-domain', 'mclagDomain', ['leaf-01', 'leaf-02'], []),
    'server-01--mclag--leaf-01--leaf-02': ('mclag', 'mclag', ['leaf-01', 'leaf-02'], ['server-01']),
    'server-02--mclag--leaf-01--leaf-02': ('mclag', 'mclag', ['leaf-01', 'leaf-02'], ['server-02']),
    'server-03--unbundled--leaf-01': ('unbundled', 'unbundled', ['leaf-01'], ['server-03']),
    'server-04--bundled--leaf-02': ('bundled', 'bundled', ['leaf-02'], ['server-04']),
    'server-05--eslag--leaf-03--leaf-04': ('eslag', 'eslag', ['leaf-03', 'leaf-04'], ['server-05']),
    'server-06--eslag--leaf-03--leaf-04': ('eslag', 'eslag', ['leaf-03', 'leaf-04'], ['server-06']),
    'server-07--unbundled--leaf-03': ('unbundled', 'unbundled', ['leaf-03'], ['server-07']),
    'server-08--bundled--leaf-04': ('bundled', 'bundled', ['leaf-04'], ['server-08']),
    'server-09--unbundled--leaf-05': ('unbundled', 'unbundled', ['leaf-05'], ['server-09']),
    'server-10--bundled--leaf-05': ('bundled', 'bundled', ['leaf-05'], ['server-10']),
}
for _spine in ('spine-01', 'spine-02'):
    for _leaf in ('leaf-01', 'leaf-02', 'leaf-03', 'leaf-04', 'leaf-05'):
        CONNECTIONS[f'{_spine}--fabric--{_leaf}'] = ('fabric', 'fabric', [_spine, _leaf], [])
# One canonical representative per Connection variant.
VARIANTS = {'mclag-domain': 'leaf-01--mclag-domain--leaf-02',
            'mclag': 'server-01--mclag--leaf-01--leaf-02',
            'unbundled': 'server-03--unbundled--leaf-01',
            'bundled': 'server-04--bundled--leaf-02',
            'eslag': 'server-05--eslag--leaf-03--leaf-04',
            'fabric': 'spine-01--fabric--leaf-01'}

# Hardcoded public mirror of the Go producer's installer-shaped input (the key,
# hash and token placeholders are checked by shape, not copied from Go).
PUBLIC_CONFIG = {
    'registry': {'mode': 'airgap'},
    'control': {'managementSubnet': '172.30.0.0/21', 'controlVIP': '172.30.0.1/32',
                'kubeClusterSubnet': '172.28.0.0/16', 'kubeServiceSubnet': '172.29.0.0/16',
                'kubeClusterDNS': '172.29.0.10', 'dummySubnet': '172.30.90.0/24'},
    'fabric': {'mode': 'spine-leaf', 'managementDHCPStart': '172.30.4.0',
               'managementDHCPEnd': '172.30.7.254', 'spineASN': 65100, 'leafASNStart': 65101,
               'leafASNEnd': 65533, 'protocolSubnet': '172.30.8.0/22', 'vtepSubnet': '172.30.12.0/22',
               'fabricSubnet': '172.30.128.0/17', 'mclagSessionSubnet': '172.30.95.0/31',
               'vpcWorkaroundSubnet': '172.30.96.0/19'},
    'observability': {'defaults': ''},
}
PUBLIC_CONTROL = {'bootstrap': {'disk': '/dev/sda'}, 'external': {'interface': 'enp2s0', 'ip': 'dhcp'},
                  'management': {'interface': 'enp2s1'}}
# Pinned ControlNodeSpec.Dummy is a value struct: encoding/json's omitempty
# retains it as {}, including through PrintFab. The raw renderer omits it.
EXPECTED_TYPED_CONTROL = {**PUBLIC_CONTROL, 'dummy': {}}
TYPED_EMPTY_OVERRIDES = {'versions': {'platform': {}, 'fabricator': {}, 'fabric': {},
                                    'gateway': {}, 'vlab': {}}}
EMPTY = ('""', '0', 'false', 'null', '[]', '{}')


def flat(value, prefix='', out=None):
    out = {} if out is None else out
    if isinstance(value, dict) and value:
        for key, item in value.items():
            flat(item, key if not prefix else prefix + '.' + key, out)
    else:
        out[prefix] = json.dumps(value, separators=(',', ':'))
    return out


def fixture_files():
    root = Path(os.environ['LABAPP_PINNED_API_FIXTURE_DIR'])
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
        raise AssertionError('fixture directory must be owned mode0700')
    if {p.name for p in root.iterdir()} != set(NAMES):
        raise AssertionError('required fixture files absent or unexpected entries present')
    files = {}
    total = 0
    for name in NAMES:
        path = root / name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.getuid() or info.st_nlink != 1
                or not 0 < info.st_size <= 1 << 20):
            raise AssertionError('fixture file identity or size refused: ' + name)
        total += info.st_size
        if total > 1 << 20:
            raise AssertionError('fixture total byte limit exceeded')
        files[name] = path.read_bytes()
    if sum(map(len, files.values())) > 1 << 20:
        raise AssertionError('fixture total byte limit exceeded')
    return files


def named(docs, kind, name):
    found = [d for d in docs if d['kind'] == kind and d['metadata']['name'] == name]
    if len(found) != 1:
        raise AssertionError('fixed public representative absent or duplicated')
    return found[0]


def ports(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == 'port':
                yield item
            else:
                yield from ports(item)
    elif isinstance(value, list):
        for item in value:
            yield from ports(item)


class PinnedApiAsymmetry(GuestEnvironment, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        files = fixture_files()
        cls.printed = core.yaml_documents(files['expected.yaml'])
        observed = core.json_data(files['observed.json'])
        cls.meta = core.json_data(files['meta.json'])
        if set(observed) != {'canonical', 'synthetic'}:
            raise AssertionError('observed fixture sections differ')
        cls.defaulted = observed['canonical']
        cls.syn_defaulted = observed['synthetic']
        cls.syn_printed = core.yaml_documents(cls.meta['synthetic']['printed'].encode())
        wiring = Path(__file__).resolve().parents[2] / 'wiringd.yaml'
        raw = wiring.read_bytes()
        if hashlib.sha256(raw).hexdigest() != core.WIRING_SHA:
            raise AssertionError('canonical wiring differs from pinned value')
        cls.raw = core.yaml_documents(raw)
        if Counter(d['kind'] for d in cls.raw) != Counter(WIRING_COUNTS):
            raise AssertionError('canonical wiring set differs')
        for docs in (cls.printed, cls.defaulted):
            if Counter(d['kind'] for d in docs) != Counter(COUNTS):
                raise AssertionError('fixed canonical fixture set differs')
        expected = Counter({'Switch': 2, 'Server': 1, 'Connection': 1})
        for docs in (cls.syn_printed, cls.syn_defaulted, cls.meta['synthetic']['originals'],
                     cls.meta['synthetic']['beforeDefault']):
            if Counter(d['kind'] for d in docs) != expected:
                raise AssertionError('fixed public synthetic set differs')

    def setUp(self):
        super().setUp()
        self.actual_docs = None
        self.prepared()
        self.runtime_files()
        self.assertEqual(len(self.defaulted), 45)

    def command(self, argv, deadline, *args, **kwargs):
        # Keep readyz/node/cluster UID and every non-kubectl command under the
        # existing fail-closed GuestEnvironment spy. Only nine CR lists change.
        if self.actual_docs is not None and argv[0] == core.KUBECTL and 'get' in argv:
            resource = argv[argv.index('get') + 1]
            kinds = {'fabricators': 'Fabricator', 'controlnodes': 'ControlNode',
                     'fabnodes': 'FabNode', 'switches': 'Switch', 'servers': 'Server',
                     'connections': 'Connection', 'switchgroups': 'SwitchGroup',
                     'vlannamespaces': 'VLANNamespace', 'ipv4namespaces': 'IPv4Namespace'}
            kind = kinds.get(resource.split('.')[0])
            if kind is not None:
                self.calls.append((list(argv), deadline, args, kwargs))
                core.remaining(deadline)
                self.assertIn('-A', argv)
                return json.dumps({'items': [d for d in self.actual_docs if d['kind'] == kind]}).encode()
        return super().command(argv, deadline, *args, **kwargs)

    def assembled(self, representatives):
        # These explicitly matched synthetic controls start with the independently
        # defaulted canonical objects; unrelated raw wiring would now require its
        # own observed defaults and would obscure the representative under test.
        docs = copy.deepcopy(self.defaulted)
        for replacement in representatives:
            kind, name = replacement['kind'], replacement['metadata']['name']
            if kind == 'Connection':
                # Synthetic Connection has no VM-name gate; replace one canonical
                # item at the same count with the fixed public representative.
                index = next(i for i, doc in enumerate(docs) if doc['kind'] == kind)
            else:
                index = next(i for i, doc in enumerate(docs)
                             if doc['kind'] == kind and doc['metadata']['name'] == name)
            docs[index] = copy.deepcopy(replacement)
        self.assertEqual(Counter(d['kind'] for d in docs), COUNTS)
        return docs

    def check_api(self, expected, actual):
        installer = core.WORK / 'result' / core.RESULT
        groups = (('fab.yaml', ('Fabricator', 'ControlNode', 'FabNode')),
                  ('include.yaml', tuple(k for k in COUNTS if k not in ('Fabricator', 'ControlNode'))))
        for filename, selected in groups:
            path = installer / filename
            path.write_text(yaml.safe_dump_all([d for d in expected if d['kind'] in selected], sort_keys=False))
            path.chmod(0o600)
        self.actual_docs = copy.deepcopy(actual)
        return core.api_ready(core.time.monotonic() + 10)

    def matched(self, expected):
        # Matched matcher control, explicitly copied from observed documents.
        # Independent serializer/admission evidence is tested separately below.
        actual = copy.deepcopy(expected)
        result = self.check_api(expected, actual)
        self.assertEqual(result['cluster_uid'], self.cluster_uid)
        return expected, actual

    def passing(self):
        """Synthetic representatives replacing same-name canonical objects."""
        return self.matched(self.assembled(self.syn_defaulted))

    def full(self):
        """All 45 independently produced public objects, actual per-kind counts."""
        return self.matched(copy.deepcopy(self.defaulted))

    def refused(self, expected, actual):
        with self.assertRaises(core.Failure) as caught:
            self.check_api(expected, actual)
        self.assertEqual(str(caught.exception), 'canonical API objects differ')
        self.assertEqual(caught.exception.code, 1)

    def negative(self, kind, name, mutate, baseline=None):
        expected, actual = (baseline or self.independent)()
        mutate(named(actual, kind, name))
        self.refused(expected, actual)

    # ---- independent serializer/default refusal -------------------------------

    def independent(self):
        """Printed expected -> production projection -> independent upstream full45 observed."""
        expected, actual = copy.deepcopy(self.printed), copy.deepcopy(self.defaulted)
        result = self.check_api(expected, actual)
        self.assertEqual(result['cluster_uid'], self.cluster_uid)
        return expected, actual

    def expected_refused(self, kind, name, mutate, message='expected projection refused'):
        expected, actual = self.independent()
        mutate(named(expected, kind, name))
        before_expected, before_actual = copy.deepcopy(expected), copy.deepcopy(actual)
        with self.assertRaises(core.Failure) as caught:
            self.check_api(expected, actual)
        self.assertEqual(str(caught.exception), message)
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(expected, before_expected)
        self.assertEqual(actual, before_actual)
        with self.assertRaises(core.Failure):
            core.project_expected(expected)
        self.assertEqual(expected, before_expected)

    def test_raw_serializer_asymmetry_is_preserved(self):
        # The unprojected comparison key still differs for exactly Switch/Connection.
        printed = {core.object_identity(d): core.object_value(d) for d in self.printed}
        defaulted = {core.object_identity(d): core.object_value(d) for d in self.defaulted}
        self.assertEqual(set(printed), set(defaulted))
        differing = Counter(i[1] for i in printed if printed[i] != defaulted[i])
        self.assertEqual(differing, Counter({'Switch': 7, 'Connection': 21}))

    def test_independent_printed_projects_to_upstream_observed(self):
        before = copy.deepcopy(self.printed)
        observed_before = copy.deepcopy(self.defaulted)
        expected, actual = self.independent()
        self.assertEqual(expected, before)
        self.assertEqual(actual, observed_before)
        self.assertEqual(self.defaulted, observed_before)
        projected = core.project_expected(self.printed)
        self.assertEqual(self.printed, before)
        self.assertEqual([core.object_identity(d) for d in projected],
                         [core.object_identity(d) for d in self.printed])
        for kind in ('Fabricator', 'ControlNode', 'Server', 'SwitchGroup', 'VLANNamespace', 'IPv4Namespace'):
            self.assertEqual([d for d in projected if d['kind'] == kind],
                             [d for d in self.printed if d['kind'] == kind])

    def test_synthetic_unsupported_forms_are_not_inferred(self):
        # Group insertion/sorting and SPEED_* rewrites remain unsupported, not guessed.
        self.passing()
        with self.assertRaises(core.Failure) as caught:
            self.check_api(self.assembled(self.syn_printed), self.assembled(self.syn_defaulted))
        self.assertEqual(str(caught.exception), 'expected projection refused')

    def test_independent_observed_negatives(self):
        cases = (
            ('Switch', 'leaf-01', lambda d: d['metadata']['labels'].pop(PREFIX + 'profile')),
            ('Switch', 'leaf-01', lambda d: d['metadata']['labels'].update({PREFIX + 'profile': 'other'})),
            ('Switch', 'leaf-01', lambda d: d['metadata']['labels'].update({'vlanns.' + PREFIX + 'extra': 'true'})),
            ('Switch', 'leaf-01', lambda d: d['metadata']['labels'].update({'example.com/extra': 'public'})),
            ('Switch', 'leaf-01', lambda d: d['metadata']['labels'].update({PREFIX + 'unknown': 'public'})),
            ('Switch', 'leaf-01', lambda d: d['metadata'].update(annotations={'example.com/note': 'public'})),
            ('Switch', 'leaf-01', lambda d: d['spec'].update(unknownField=True)),
            ('Switch', 'leaf-01', lambda d: d['spec'].update(vlanNamespaces=[])),
            ('Switch', 'leaf-01', lambda d: d['spec'].update(asn=65102)),
            ('Switch', 'leaf-01', lambda d: d['spec'].update(ip='172.30.0.9/21')),
            ('Switch', 'leaf-01', lambda d: d['spec'].update(profile='other')),
            ('Switch', 'leaf-01', lambda d: d['spec'].update(role='spine')),
            ('Connection', VARIANTS['mclag'], lambda d: d['spec']['mclag']['links'].reverse()),
            ('Connection', VARIANTS['unbundled'], lambda d: d['spec']['unbundled']['link']['switch'].update(port='leaf-01/E1/99')),
            ('Connection', VARIANTS['mclag-domain'], lambda d: d['spec']['mclagDomain']['sessionLinks'].reverse()),
            ('Connection', VARIANTS['fabric'], lambda d: d['metadata']['labels'].pop('switch.' + PREFIX + 'spine-01')),
            ('Connection', VARIANTS['fabric'], lambda d: d['metadata']['labels'].update({'server.' + PREFIX + 'server-99': 'true'})),
            ('Connection', VARIANTS['eslag'], lambda d: d['metadata']['labels'].update({PREFIX + 'connection-type': 'mclag'})),
            ('Connection', VARIANTS['bundled'], lambda d: d['metadata']['labels'].update({'vpc.' + PREFIX + 'x': 'true'})),
            ('Connection', VARIANTS['mclag'], lambda d: d['metadata'].update(annotations={'example.com/note': 'public'})),
            ('Connection', VARIANTS['mclag'], lambda d: d['spec']['mclag'].update(unknownField=True)),
        )
        for index, (kind, name, mutate) in enumerate(cases):
            with self.subTest(index=index, kind=kind, name=name):
                self.negative(kind, name, mutate, baseline=self.independent)

    def test_independent_identity_count_and_duplicate_negatives(self):
        expected, actual = self.independent()
        actual.remove(named(actual, 'Server', 'server-10'))
        with self.assertRaises(core.Pending) as caught:
            self.check_api(expected, actual)
        self.assertEqual(str(caught.exception), 'canonical API objects pending')
        expected, actual = self.independent()
        actual.append(copy.deepcopy(named(actual, 'Server', 'server-10')))
        with self.assertRaises(core.Failure) as caught:
            self.check_api(expected, actual)
        self.assertEqual(str(caught.exception), 'canonical API counts differ')
        expected, actual = self.independent()
        expected.append(copy.deepcopy(named(expected, 'Switch', 'leaf-01')))
        self.refused(expected, actual)
        expected, actual = self.independent()
        expected.remove(named(expected, 'Switch', 'leaf-02'))
        index = next(i for i, d in enumerate(actual) if d['kind'] == 'Switch' and d['metadata']['name'] == 'leaf-02')
        actual[index] = copy.deepcopy(named(actual, 'Switch', 'leaf-01'))
        self.refused(expected, actual)
        expected, actual = self.independent()
        named(actual, 'Server', 'server-01')['metadata']['name'] = 'server-99'
        self.refused(expected, actual)

    def test_version_binding_negatives(self):
        for label, pin in (('stale', (170709176, '0' * 64)), ('malformed', 'v0.43.1'), ('missing', None)):
            expected, actual = self.independent()
            tools = dict(core.TOOL_PINS)
            if pin is None:
                del tools[core.HHFAB]
            else:
                tools[core.HHFAB] = pin
            with self.subTest(label), patch.dict(core.TOOL_PINS, tools, clear=True):
                with self.assertRaises(core.Failure) as caught:
                    self.check_api(expected, actual)
                self.assertEqual(str(caught.exception), 'expected projection version binding refused')
        # Mutate actual installer-selected fields, independently of TOOL_PINS.
        for field in ('api', 'controller', 'agent'):
            for label, value in (('missing', None), ('stale', 'v0.96.1'),
                                 ('devel', '(devel)'), ('malformed', ['v0.96.2']),
                                 ('empty', ''), ('numeric', 96)):
                def mutate(doc, field=field, value=value):
                    selected = doc['status']['versions']['fabric']
                    if value is None:
                        del selected[field]
                    else:
                        selected[field] = value
                with self.subTest(field=field, label=label):
                    self.expected_refused('Fabricator', 'default', mutate,
                                          'expected projection version binding refused')
        for path in ('status', 'versions', 'fabric'):
            for value in (None, [], 'v0.96.2', {}):
                def mutate(doc, path=path, value=value):
                    parent = doc if path == 'status' else doc['status'] if path == 'versions' else doc['status']['versions']
                    parent[path] = value
                with self.subTest(path=path, value=value):
                    self.expected_refused('Fabricator', 'default', mutate,
                                          'expected projection version binding refused')
        for label, value in (('fabric api override', {'versions': {'fabric': {'api': 'v0.96.3'}}}),
                             ('controller override', {'versions': {'fabric': {'controller': 'v0.1.0'}}}),
                             ('agent override', {'versions': {'fabric': {'agent': 'v0.1.0'}}}),
                             ('malformed', 'v0.96.2'), ('list', [])):
            with self.subTest(label):
                self.expected_refused('Fabricator', 'default', lambda d, v=value: d['spec'].update(overrides=v))

    def test_actual_typed_empty_overrides_and_honest_oracle_versions(self):
        expected, _actual = self.independent()
        fab = named(expected, 'Fabricator', 'default')
        self.assertEqual(fab['spec']['overrides'], TYPED_EMPTY_OVERRIDES)
        self.assertEqual({k: fab['status']['versions']['fabric'][k] for k in ('api', 'controller', 'agent')},
                         {'api': 'v0.96.2', 'controller': 'v0.96.2', 'agent': 'v0.96.2'})
        # This is the real public Go build, not a forged release-version fixture.
        self.assertEqual(fab['status']['versions']['fabricator']['api'], '(devel)')
        self.assertEqual(fab['status']['versions']['fabricator']['controller'], '(devel)')
        for group in ('platform', 'fabricator', 'fabric', 'gateway', 'vlab'):
            with self.subTest(group=group):
                self.expected_refused('Fabricator', 'default', lambda d, group=group:
                    d['spec']['overrides']['versions'][group].update(unknownVersion='v0.96.2'))
        for field in ('api', 'controller', 'agent'):
            with self.subTest(field=field):
                self.expected_refused('Fabricator', 'default', lambda d, field=field:
                    d['spec']['overrides']['versions']['fabric'].update({field: 'v0.96.2'}))
        for value in (None, {'versions': None}, {'versions': {'fabric': {}}},
                      {**TYPED_EMPTY_OVERRIDES, 'unknown': {}}, {'versions': {'unknown': {}}}):
            with self.subTest(overrides=value):
                self.expected_refused('Fabricator', 'default', lambda d, value=value:
                    d['spec'].update(overrides=copy.deepcopy(value)))

    def test_missing_fabricator_refuses_projection(self):
        expected, actual = self.independent()
        expected.remove(named(expected, 'Fabricator', 'default'))
        with self.assertRaises(core.Failure) as caught:
            self.check_api(expected, actual)
        self.assertEqual(str(caught.exception), 'expected projection refused')

    def test_unsupported_and_conflicting_expected_forms_refused(self):
        def link_key(variant, key):
            return lambda d: d['spec'][variant]['links'][0].update({key: {'port': 'x/E1/1'}})
        cases = (
            ('Switch', 'leaf-01', lambda d: d['spec'].update(portSpeeds={'E1/2': 'SPEED_25G'})),
            ('Switch', 'leaf-01', lambda d: d['spec'].update(portGroupSpeeds={'1': 'SPEED_10G'})),
            ('Switch', 'leaf-01', lambda d: d['spec'].update(groups=['zeta', 'alpha'])),
            ('Switch', 'leaf-01', lambda d: d['spec'].update(groups=['mclag-1', 'mclag-1'])),
            ('Switch', 'leaf-01', lambda d: d['spec'].update(vlanNamespaces=['b', 'a'])),
            ('Switch', 'leaf-01', lambda d: d['spec'].update(redundancy={'group': 'other', 'type': 'mclag'})),
            ('Switch', 'leaf-01', lambda d: d['spec'].pop('profile')),
            ('Switch', 'leaf-01', lambda d: d['metadata'].update(labels={PREFIX + 'profile': 'other'})),
            ('Switch', 'leaf-01', lambda d: d['metadata'].update(labels={'switchgroup.' + PREFIX + 'mclag-1': 'false'})),
            ('Connection', VARIANTS['mclag'], lambda d: d['metadata'].update(labels={PREFIX + 'connection-type': 'eslag'})),
            ('Connection', VARIANTS['mclag'], lambda d: d['spec'].update(unbundled={})),
            ('Connection', VARIANTS['mclag'], lambda d: d.update(spec={})),
            ('Connection', VARIANTS['mclag'], lambda d: d['spec']['mclag'].update(links=[])),
            ('Connection', VARIANTS['mclag'], link_key('mclag', 'extra')),
            ('Connection', VARIANTS['bundled'], lambda d: d['spec']['bundled'].update(fallback=True)),
            ('Connection', VARIANTS['mclag-domain'], lambda d: d['spec']['mclagDomain'].pop('peerLinks')),
        )
        for index, (kind, name, mutate) in enumerate(cases):
            with self.subTest(index=index, kind=kind, name=name):
                self.expected_refused(kind, name, mutate)

    def test_unsupported_endpoint_forms_refuse_before_adding_labels(self):
        def server_links(variant, count):
            # Every full port is unique; only the device cardinality is invalid.
            return lambda d: d['spec'][variant].update(links=[
                {'server': {'port': f'server-01/enp2s{index}'},
                 'switch': {'port': f'leaf-{index:02}/E1/1'}} for index in range(1, count + 1)])

        cases = (
            ('unbundled', lambda d: d['spec']['unbundled']['link']['switch'].update(port='leaf-01/')),
            ('unbundled', lambda d: d['spec']['unbundled']['link']['switch'].update(port='/E1/1')),
            ('unbundled', lambda d: d['spec']['unbundled']['link']['switch'].update(port='leaf-01')),
            ('unbundled', lambda d: d['spec']['unbundled']['link']['switch'].update(unknown=True)),
            ('unbundled', lambda d: d['spec']['unbundled']['link']['switch'].update(port='server-03/enp2s1')),
            ('bundled', lambda d: d['spec']['bundled']['links'].append(copy.deepcopy(d['spec']['bundled']['links'][0]))),
            ('bundled', lambda d: d['spec']['bundled']['links'][1]['server'].update(port='server-99/enp2s9')),
            ('bundled', server_links('bundled', 2)),
            ('mclag', server_links('mclag', 3)),
            ('eslag', server_links('eslag', 5)),
            ('mclag', lambda d: d['spec']['mclag'].update(fallback='true')),
            ('mclag-domain', lambda d: d['spec']['mclagDomain']['sessionLinks'][0]['switch1'].update(port='leaf-03/E1/1')),
            ('mclag-domain', lambda d: d['spec']['mclagDomain']['sessionLinks'].append(
                copy.deepcopy(d['spec']['mclagDomain']['peerLinks'][0]))),
            ('fabric', lambda d: d['spec']['fabric']['links'].append(
                {'spine': {'port': 'spine-02/E1/99'}, 'leaf': {'port': 'leaf-01/E1/99'}})),
            ('fabric', lambda d: d['spec']['fabric']['links'][0]['leaf'].update(ip=[])),
        )
        for index, (variant, mutate) in enumerate(cases):
            with self.subTest(index=index, variant=variant):
                self.expected_refused('Connection', VARIANTS[variant], mutate)

    # ---- complete canonical objects -------------------------------------------

    def test_canonical_source_and_per_kind_coverage(self):
        self.assertEqual(self.meta['source']['wiringBytes'], len(self.wiring.read_bytes()))
        self.assertEqual(self.meta['source']['wiringSHA256'], core.WIRING_SHA)
        self.assertEqual(self.meta['source']['fabricator'], 'v0.43.1')
        self.assertEqual(self.meta['source']['fabric'], 'v0.96.2')
        self.assertEqual(self.meta['canonical']['typedDefaultInvoked'], WIRING_COUNTS)
        self.assertIs(self.meta['canonical']['originalsUnchanged'], True)
        self.assertEqual(self.meta['fabricator']['typedDefaultInvoked'], {'Fabricator': 1, 'ControlNode': 1})
        self.assertEqual(Counter(d['kind'] for d in self.defaulted), Counter(COUNTS))
        # All six Connection variants are present and keyed by exactly one spec variant.
        variants = {}
        for doc in self.raw:
            if doc['kind'] == 'Connection':
                self.assertEqual(len(doc['spec']), 1)
                variants[next(iter(doc['spec']))] = variants.get(next(iter(doc['spec'])), 0) + 1
        self.assertEqual(variants, {'mclagDomain': 1, 'mclag': 2, 'unbundled': 3, 'bundled': 3,
                                    'eslag': 2, 'fabric': 10})
        self.assertEqual({v[0] for v in CONNECTIONS.values()},
                         {'mclag-domain', 'mclag', 'unbundled', 'bundled', 'eslag', 'fabric'})

    def test_connection_tables_match_raw_endpoints(self):
        # Cross-check the hand-written tables against ports in the raw source.
        raw = {d['metadata']['name']: d for d in self.raw if d['kind'] == 'Connection'}
        self.assertEqual(set(raw), set(CONNECTIONS))
        for name, (_ctype, spec_key, switches, servers) in CONNECTIONS.items():
            self.assertEqual(list(raw[name]['spec']), [spec_key])
            names = {p.split('/')[0] for p in ports(raw[name]['spec'])}
            self.assertEqual(sorted(n for n in names if not n.startswith('server-')), sorted(switches))
            self.assertEqual(sorted(n for n in names if n.startswith('server-')), sorted(servers))

    def test_canonical_printed_original_and_defaulted_values(self):
        raw = {(d['kind'], d['metadata']['name']): d for d in self.raw}
        sections = {'originals': self.meta['canonical']['originals'],
                    'beforeDefault': self.meta['canonical']['beforeDefault']}
        for label, docs in sections.items():
            self.assertEqual(len(docs), 43, label)
        wiring_printed = [d for d in self.printed if d['kind'] in WIRING_COUNTS]
        wiring_defaulted = [d for d in self.defaulted if d['kind'] in WIRING_COUNTS]
        self.assertEqual(len(wiring_printed), 43)
        self.assertEqual(len(wiring_defaulted), 43)
        for doc in sections['originals'] + sections['beforeDefault'] + wiring_printed:
            source = raw[(doc['kind'], doc['metadata']['name'])]
            # Unchanged values and link order, before any typed default.
            self.assertEqual(doc['spec'], source['spec'])
            self.assertEqual(doc['metadata'].get('namespace'), 'default')
        for doc in sections['beforeDefault'] + wiring_printed:
            self.assertFalse(doc['metadata'].get('labels'))
            self.assertFalse(doc['metadata'].get('annotations'))
        for doc in wiring_defaulted:
            kind, name = doc['kind'], doc['metadata']['name']
            source = raw[(kind, name)]
            self.assertEqual(doc['apiVersion'], source['apiVersion'])
            self.assertEqual(doc['metadata']['namespace'], 'default')
            self.assertFalse(doc['metadata'].get('annotations'))
            spec = copy.deepcopy(source['spec'])
            labels = {}
            if kind == 'Switch':
                # Named defaults: omitted VLAN list becomes ['default'].
                self.assertNotIn('vlanNamespaces', spec)
                spec['vlanNamespaces'] = ['default']
                labels = {PREFIX + 'profile': 'vs', 'vlanns.' + PREFIX + 'default': 'true',
                          **{'switchgroup.' + PREFIX + g: 'true' for g in SWITCH_GROUPS[name]}}
            elif kind == 'Connection':
                ctype, _key, switches, servers = CONNECTIONS[name]
                labels = {PREFIX + 'connection-type': ctype,
                          **{'switch.' + PREFIX + s: 'true' for s in switches},
                          **{'server.' + PREFIX + s: 'true' for s in servers}}
            self.assertEqual(doc['spec'], spec, name)
            self.assertEqual(doc['metadata'].get('labels', {}), labels, name)

    def test_vlan_helper_is_not_presumed_normalizing(self):
        # Source evidence: Default() assigns normalized VLAN ranges only on the
        # helper's error path. The helper fills to=0 from from and sorts in place;
        # its merged return is unused on success. Only this canonical singleton
        # is asserted unchanged; no intended generic normalization is presumed.
        vlan = named(self.defaulted, 'VLANNamespace', 'default')
        self.assertEqual(vlan['spec'], {'ranges': [{'from': 1000, 'to': 2999}]})
        self.assertFalse(vlan['metadata'].get('labels'))

    def test_full_canonical_matched_baseline_passes(self):
        expected, actual = self.full()
        self.assertEqual(Counter(d['kind'] for d in actual), Counter(COUNTS))
        self.assertEqual(len(expected), 45)

    # ---- generated Fabricator / ControlNode -----------------------------------

    def test_fabricator_and_control_node_exact_public_data(self):
        fab_meta = self.meta['fabricator']
        self.assertEqual((fab_meta['controlNodes'], fab_meta['fabNodes']), (1, 0))
        for docs in (self.printed, self.defaulted):
            self.assertFalse([d for d in docs if d['kind'] == 'FabNode'])
        printed_fab, printed_control = named(self.printed, 'Fabricator', 'default'), named(self.printed, 'ControlNode', 'control-1')
        for doc in (printed_fab, printed_control, named(self.defaulted, 'Fabricator', 'default'),
                    named(self.defaulted, 'ControlNode', 'control-1')):
            self.assertEqual(doc['apiVersion'], 'fabricator.githedgehog.com/v1beta1')
            self.assertEqual(doc['metadata']['namespace'], 'fab')
            self.assertFalse(doc['metadata'].get('labels'))
            self.assertFalse(doc['metadata'].get('annotations'))
        # Assert the single named raw-input -> typed-serialization delta.
        self.assertNotIn('dummy', PUBLIC_CONTROL)
        self.assertEqual(set(EXPECTED_TYPED_CONTROL) - set(PUBLIC_CONTROL), {'dummy'})
        self.assertEqual(EXPECTED_TYPED_CONTROL['dummy'], {})
        for docs in (fab_meta['loadedBeforeMerge'], fab_meta['reloadLoadedBeforeMerge'],
                     fab_meta['afterReloadMergeBeforeExplicitDefault'], self.printed, self.defaulted):
            spec = named(docs, 'ControlNode', 'control-1')['spec']
            self.assertEqual(spec, EXPECTED_TYPED_CONTROL)
            self.assertEqual({k: v for k, v in spec.items() if k != 'dummy'}, PUBLIC_CONTROL)
        config = printed_fab['spec']['config']
        control = config['control']
        self.assertRegex(control['joinToken'], r'[a-f0-9]{64}')
        for user in [control['defaultUser'], *config['fabric']['defaultSwitchUsers'].values()]:
            self.assertRegex(user['password'], r'\$5\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{43}')
            self.assertEqual(len(user['authorizedKeys']), 1)
            self.assertRegex(user['authorizedKeys'][0], r'ssh-ed25519 [A-Za-z0-9+/=]+')
        self.assertEqual({k: v['role'] for k, v in config['fabric']['defaultSwitchUsers'].items()},
                         {'admin': 'admin', 'op': 'operator'})
        # Merge deltas: set public values survive; only empty public values may change.
        public, post = flat(PUBLIC_CONFIG), flat(config)
        changed, added = set(fab_meta['mergeChanged']), set(fab_meta['mergeAdded'])
        self.assertTrue(added, 'DefaultConfig merge branch did not execute')
        # Empty public values (and omitted-empty structs) may be filled by
        # defaults; a set public value may never be added over, changed or removed.
        for path in changed | (added & set(public)):
            self.assertIn(public.get(path), EMPTY, path)
        for path in fab_meta['mergeRemoved']:
            self.assertTrue(any(a.startswith(path + '.') for a in added), path)
        for path, value in public.items():
            if value not in EMPTY:
                self.assertEqual(post[path], value, path)
        for path in added:
            self.assertIn(path, post)

    def test_generated_fabricator_is_default_fixed_point(self):
        fab_meta = self.meta['fabricator']
        self.assertIs(fab_meta['printFixedPoint'], True)
        self.assertEqual(fab_meta['reloadMergeAdded'], [])
        self.assertEqual(fab_meta['reloadMergeChanged'], [])
        self.assertIs(fab_meta['typedDefaultFixedPoint'], True)
        for kind, name in (('Fabricator', 'default'), ('ControlNode', 'control-1')):
            self.assertEqual(core.object_value(named(self.printed, kind, name)),
                             core.object_value(named(self.defaulted, kind, name)))
        self.assertEqual(fab_meta['loadedBeforeMerge'], fab_meta['originals'])
        for doc in fab_meta['reloadLoadedBeforeMerge']:
            self.assertEqual(core.object_value(doc), core.object_value(named(
                self.printed, doc['kind'], doc['metadata']['name'])))
        for doc in fab_meta['afterReloadMergeBeforeExplicitDefault']:
            self.assertEqual(core.object_value(doc), core.object_value(named(
                self.defaulted, doc['kind'], doc['metadata']['name'])))
        for doc in (fab_meta['originals'] + fab_meta['loadedBeforeMerge']
                    + fab_meta['reloadLoadedBeforeMerge'] + fab_meta['afterReloadMergeBeforeExplicitDefault']):
            self.assertEqual(doc['metadata']['namespace'], 'fab')

    def test_separate_public_fabricator_controls_execute_branches(self):
        fab_meta = self.meta['fabricator']
        # A set non-default value survives the DefaultConfig merge ...
        self.assertEqual(fab_meta['controlOverrideSpineASN'], '65099')
        self.assertNotIn('fabric.spineASN', fab_meta['controlOverrideChanged'])
        self.assertEqual(named(self.printed, 'Fabricator', 'default')['spec']['config']['fabric']['spineASN'], 65100)
        # ... and the typed Fabricator.Default branch really resets a set field.
        self.assertIs(fab_meta['controlLoopbackDefaultReset'], True)

    def test_fabricator_and_control_negatives_start_from_passing_baseline(self):
        cases = (
            ('Fabricator', 'default', lambda d: d['spec']['config']['fabric'].update(spineASN=65101)),
            ('Fabricator', 'default', lambda d: d['spec']['config']['registry'].update(mode='other')),
            ('Fabricator', 'default', lambda d: d['spec']['config'].update(unknownField=True)),
            ('Fabricator', 'default', lambda d: d['metadata'].update(namespace='other')),
            ('ControlNode', 'control-1', lambda d: d['spec']['external'].update(ip='172.30.0.9/21')),
            ('ControlNode', 'control-1', lambda d: d['spec']['management'].update(interface='other')),
            ('ControlNode', 'control-1', lambda d: d['spec'].update(unknownField=True)),
            ('ControlNode', 'control-1', lambda d: d['metadata'].update(namespace='other')),
            ('ControlNode', 'control-1', lambda d: d['metadata'].update(name='control-2')),
        )
        for index, (kind, name, mutate) in enumerate(cases):
            with self.subTest(index=index, kind=kind):
                self.negative(kind, name, mutate)

    # ---- canonical per-kind negatives -----------------------------------------

    def test_canonical_connection_variant_negatives(self):
        for variant, name in VARIANTS.items():
            ctype, _key, switches, servers = CONNECTIONS[name]
            cases = {
                'missing type label': lambda d: d['metadata']['labels'].pop(PREFIX + 'connection-type'),
                'wrong type label': lambda d: d['metadata']['labels'].update({PREFIX + 'connection-type': 'other'}),
                'missing switch endpoint label': lambda d, s=switches[0]: d['metadata']['labels'].pop('switch.' + PREFIX + s),
                'wrong switch endpoint value': lambda d, s=switches[0]: d['metadata']['labels'].update({'switch.' + PREFIX + s: 'false'}),
                'extra endpoint label': lambda d: d['metadata']['labels'].update({'switch.' + PREFIX + 'leaf-99': 'true'}),
                'extra label': lambda d: d['metadata']['labels'].update({'example.com/extra': 'public'}),
                'annotation': lambda d: d['metadata'].update(annotations={'example.com/note': 'public'}),
                'spec value': lambda d, k=_key: d['spec'][k].update(unknownField=True),
            }
            if servers:
                cases['missing server endpoint label'] = lambda d, s=servers[0]: d['metadata']['labels'].pop('server.' + PREFIX + s)
            else:
                cases['extra server endpoint label'] = lambda d: d['metadata']['labels'].update({'server.' + PREFIX + 'server-99': 'true'})
            for label, mutate in cases.items():
                with self.subTest(variant=variant, case=label):
                    self.negative('Connection', name, mutate)

    def test_canonical_link_order_and_values_negatives(self):
        def reverse_links(d):
            spec = d['spec']['mclag']['links']
            spec.reverse()

        def swap_port(d):
            d['spec']['unbundled']['link']['switch']['port'] = 'leaf-01/E1/99'

        for label, name, mutate in (('mclag link order', VARIANTS['mclag'], reverse_links),
                                    ('unbundled port', VARIANTS['unbundled'], swap_port)):
            with self.subTest(label):
                self.negative('Connection', name, mutate)

    def test_canonical_switch_server_and_namespace_negatives(self):
        cases = (
            ('Switch', 'leaf-01', lambda d: d['metadata']['labels'].update({'switchgroup.' + PREFIX + 'mclag-1': 'false'})),
            ('Switch', 'leaf-01', lambda d: d['metadata']['labels'].pop('vlanns.' + PREFIX + 'default')),
            ('Switch', 'leaf-01', lambda d: d['metadata']['labels'].pop(PREFIX + 'profile')),
            ('Switch', 'leaf-05', lambda d: d['metadata']['labels'].update({'switchgroup.' + PREFIX + 'empty': 'true'})),
            ('Switch', 'leaf-01', lambda d: d['spec'].update(vlanNamespaces=[])),
            ('Switch', 'spine-01', lambda d: d['spec'].update(role='server-leaf')),
            ('Switch', 'leaf-01', lambda d: d['metadata'].update(annotations={'example.com/note': 'public'})),
            ('Server', 'server-01', lambda d: d['metadata'].update(labels={'example.com/extra': 'public'})),
            ('Server', 'server-01', lambda d: d['spec'].update(description='changed')),
            ('SwitchGroup', 'mclag-1', lambda d: d['metadata'].update(labels={'example.com/extra': 'public'})),
            ('SwitchGroup', 'mclag-1', lambda d: d['spec'].update(unknownField=True)),
            ('VLANNamespace', 'default', lambda d: d['spec']['ranges'][0].update(to=3000)),
            ('VLANNamespace', 'default', lambda d: d['metadata'].update(labels={'example.com/extra': 'public'})),
            ('IPv4Namespace', 'default', lambda d: d['spec'].update(subnets=['10.1.0.0/16'])),
            ('IPv4Namespace', 'default', lambda d: d['metadata'].update(labels={'example.com/extra': 'public'})),
        )
        for index, (kind, name, mutate) in enumerate(cases):
            with self.subTest(index=index, kind=kind, name=name):
                self.negative(kind, name, mutate)

    # ---- preserved synthetic controls -----------------------------------------

    def test_original_printer_and_explicit_default_controls(self):
        syn = self.meta['synthetic']
        self.assertIs(syn['originalsUnchanged'], True)
        self.assertEqual(syn['typedDefaultInvoked'], {'Switch': 2, 'Server': 1, 'Connection': 1})
        for doc in self.syn_printed:
            self.assertFalse([k for k in doc['metadata'].get('labels', {}) if PREFIX in k])
            self.assertNotIn('kubectl.kubernetes.io/last-applied-configuration', doc['metadata'].get('annotations', {}))
            # Reload itself supplies no typed defaults or metadata rewrites.
            self.assertEqual(core.object_value(doc), core.object_value(named(
                syn['beforeDefault'], doc['kind'], doc['metadata']['name'])))
        original = named(syn['originals'], 'Switch', 'leaf-01')
        self.assertEqual(original['metadata']['labels'][PREFIX + 'stale'], 'true')
        self.assertIn('kubectl.kubernetes.io/last-applied-configuration', original['metadata']['annotations'])
        for docs in (self.syn_printed, syn['beforeDefault']):
            sw = named(docs, 'Switch', 'leaf-01')
            self.assertEqual(sw['spec']['groups'], ['zeta', 'alpha'])
            self.assertEqual(sw['spec']['vlanNamespaces'], ['vlan-b', 'vlan-a'])
            self.assertEqual(sw['spec']['portGroupSpeeds'], {'1': 'SPEED_10G'})
            self.assertEqual(sw['spec']['portSpeeds'], {'E1/2': 'SPEED_25G'})
            self.assertNotIn('vlanNamespaces', named(docs, 'Switch', 'leaf-02')['spec'])
        sw = named(self.syn_defaulted, 'Switch', 'leaf-01')
        self.assertEqual(sw['spec']['groups'], ['alpha', 'pair-1', 'zeta'])
        self.assertEqual(sw['spec']['vlanNamespaces'], ['vlan-a', 'vlan-b'])
        self.assertEqual(sw['spec']['portGroupSpeeds'], {'1': '10G'})
        self.assertEqual(sw['spec']['portSpeeds'], {'E1/2': '25G'})
        self.assertEqual(sw['metadata']['labels'], {'example.com/keep': 'yes', PREFIX + 'profile': 'vs',
                         **{'switchgroup.' + PREFIX + g: 'true' for g in ('alpha', 'pair-1', 'zeta')},
                         **{'vlanns.' + PREFIX + n: 'true' for n in ('vlan-a', 'vlan-b')}})
        sw2 = named(self.syn_defaulted, 'Switch', 'leaf-02')
        self.assertEqual(sw2['spec']['vlanNamespaces'], ['default'])
        self.assertEqual(sw2['metadata']['labels'], {PREFIX + 'profile': 'vs', 'vlanns.' + PREFIX + 'default': 'true'})
        connection = named(self.syn_defaulted, 'Connection', 'server-01--unbundled--leaf-01')
        self.assertEqual(connection['metadata']['labels'], {PREFIX + 'connection-type': 'unbundled',
                         'switch.' + PREFIX + 'leaf-01': 'true', 'server.' + PREFIX + 'server-01': 'true'})
        for docs in (self.syn_printed, self.syn_defaulted):
            sw = named(docs, 'Switch', 'leaf-01')
            self.assertEqual(sw['metadata']['namespace'], 'default')
            self.assertEqual(sw['metadata']['annotations'], {'example.com/note': 'keep-me'})
        self.assertEqual(core.object_value(named(self.syn_printed, 'Server', 'server-01')),
                         core.object_value(named(self.syn_defaulted, 'Server', 'server-01')))

    def test_namespace_and_ordinary_server_metadata_controls(self):
        for baseline in (self.passing, self.full):
            expected, actual = baseline()
            del next(d for d in actual if d['kind'] == 'Switch')['metadata']['namespace']
            self.check_api(expected, actual)
            expected, actual = baseline()
            for doc in actual:
                doc['status'] = {'public': 'mutable'}
                doc['metadata'].update(uid='public-uid', resourceVersion='9', generation=3,
                                       creationTimestamp='2026-01-01T00:00:00Z', managedFields=[{'manager': 'public'}])
            self.check_api(expected, actual)

    def test_each_drift_starts_from_actual_passing_readiness(self):
        cases = {
            'IP': lambda d: d['spec'].update(ip='172.30.0.9/21'),
            'ASN': lambda d: d['spec'].update(asn=65102),
            'profile': lambda d: d['spec'].update(profile='other'),
            'unknown spec after typed decode': lambda d: d['spec'].update(unknownField=True),
            'label': lambda d: d['metadata']['labels'].update({'example.com/keep': 'no'}),
            'extra label': lambda d: d['metadata']['labels'].update({'example.com/extra': 'public'}),
            'annotation': lambda d: d['metadata']['annotations'].update({'example.com/note': 'changed'}),
            'nested order': lambda d: d['spec']['groups'].reverse(),
            'name': lambda d: d['metadata'].update(name='changed'),
            'namespace': lambda d: d['metadata'].update(namespace='other'),
            'GVK': lambda d: d.update(apiVersion='wiring.githedgehog.com/v1alpha1'),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                self.negative('Switch', 'leaf-01', mutate, baseline=self.passing)

    # ---- both production uniqueness guards, on the full canonical set ---------

    def test_expected_identity_uniqueness_with_equal_collapsed_map(self):
        expected, actual = self.independent()
        # Expected installer docs have no count gate. An exact duplicate leaves
        # the maps equal, isolating production's expected-length guard.
        expected.append(copy.deepcopy(named(expected, 'Server', 'server-01')))
        self.refused(expected, actual)

    def test_actual_identity_uniqueness_with_equal_collapsed_map(self):
        expected, actual = self.independent()
        expected.remove(named(expected, 'Server', 'server-02'))
        index = next(i for i, doc in enumerate(actual)
                     if doc['kind'] == 'Server' and doc['metadata']['name'] == 'server-02')
        actual[index] = copy.deepcopy(named(actual, 'Server', 'server-01'))
        # Actual still has ten Servers; expected is unique; collapsed maps
        # match. Only production's actual-length guard rejects this pair.
        self.refused(expected, actual)


if __name__ == '__main__':
    unittest.main()
