"""Public upstream serializer/default fixtures through actual api_ready.

The hosted wrapper supplies three bounded public files; absence fails, never skips.
GuestEnvironment supplies remaining canonical objects and fail-closed command
fakes. No native commands, credentials or network are used by this suite.
"""
from collections import Counter
import copy
import json
import os
from pathlib import Path
import stat
import unittest

import yaml
import vlab_core as core
from test_vlab_core import GuestEnvironment

PREFIX = 'fabric.githedgehog.com/'
NAMES = ('expected.yaml', 'observed.json', 'meta.json')
COUNTS = {'Fabricator': 1, 'ControlNode': 1, 'Switch': 7, 'Server': 10,
          'Connection': 21, 'SwitchGroup': 3, 'VLANNamespace': 1, 'IPv4Namespace': 1}


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


class PinnedApiAsymmetry(GuestEnvironment, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        files = fixture_files()
        cls.printed = core.yaml_documents(files['expected.yaml'])
        cls.defaulted = core.json_data(files['observed.json'])
        cls.meta = core.json_data(files['meta.json'])
        expected = Counter({'Switch': 2, 'Server': 1, 'Connection': 1})
        for docs in (cls.printed, cls.defaulted, cls.meta['originals'], cls.meta['beforeDefault']):
            if Counter(d['kind'] for d in docs) != expected:
                raise AssertionError('fixed public fixture set differs')

    def setUp(self):
        super().setUp()
        self.actual_docs = None
        self.prepared()
        self.runtime_files()
        self.canonical = self.fab + core.yaml_documents(self.wiring.read_bytes())
        self.assertEqual(len(self.canonical), 45)

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
        docs = copy.deepcopy(self.canonical)
        for replacement in representatives:
            kind, name = replacement['kind'], replacement['metadata']['name']
            if kind == 'Connection':
                # Connections have no VM-name gate; replace one canonical item
                # at the same count with the fixed public representative.
                index = next(i for i, doc in enumerate(docs) if doc['kind'] == kind)
            else:
                index = next(i for i, doc in enumerate(docs)
                             if doc['kind'] == kind and doc['metadata']['name'] == name)
            docs[index] = copy.deepcopy(replacement)
        self.assertEqual(Counter(d['kind'] for d in docs), COUNTS)
        return docs

    def check_api(self, expected, actual):
        self.assertEqual(Counter(d['kind'] for d in actual), COUNTS)
        installer = core.WORK / 'result' / core.RESULT
        groups = (('fab.yaml', ('Fabricator', 'ControlNode', 'FabNode')),
                  ('include.yaml', tuple(k for k in COUNTS if k not in ('Fabricator', 'ControlNode'))))
        for filename, selected in groups:
            path = installer / filename
            path.write_text(yaml.safe_dump_all([d for d in expected if d['kind'] in selected], sort_keys=False))
            path.chmod(0o600)
        self.actual_docs = copy.deepcopy(actual)
        return core.api_ready(core.time.monotonic() + 10)

    def passing(self):
        # Matched matcher control, explicitly copied from observed documents.
        # Independent serializer/admission evidence is tested separately below.
        expected = self.assembled(self.defaulted)
        actual = copy.deepcopy(expected)
        result = self.check_api(expected, actual)
        self.assertEqual(result['cluster_uid'], self.cluster_uid)
        return expected, actual

    def refused(self, expected, actual):
        with self.assertRaises(core.Failure) as caught:
            self.check_api(expected, actual)
        self.assertEqual(str(caught.exception), 'canonical API objects differ')
        self.assertEqual(caught.exception.code, 1)

    def test_real_api_ready_refuses_independent_upstream_difference(self):
        self.passing()
        self.refused(self.assembled(self.printed), self.assembled(self.defaulted))

    def test_original_printer_and_explicit_default_controls(self):
        self.assertIs(self.meta['originalsUnchanged'], True)
        self.assertEqual(self.meta['typedDefaultInvoked'], {'Switch': True, 'Server': True, 'Connection': True})
        for doc in self.printed:
            self.assertFalse([k for k in doc['metadata'].get('labels', {}) if PREFIX in k])
            self.assertNotIn('kubectl.kubernetes.io/last-applied-configuration', doc['metadata'].get('annotations', {}))
            # Reload itself supplies no typed defaults or metadata rewrites.
            self.assertEqual(core.object_value(doc), core.object_value(named(
                self.meta['beforeDefault'], doc['kind'], doc['metadata']['name'])))
        original = named(self.meta['originals'], 'Switch', 'leaf-01')
        self.assertEqual(original['metadata']['labels'][PREFIX + 'stale'], 'true')
        self.assertIn('kubectl.kubernetes.io/last-applied-configuration', original['metadata']['annotations'])
        for docs in (self.printed, self.meta['beforeDefault']):
            sw = named(docs, 'Switch', 'leaf-01')
            self.assertEqual(sw['spec']['groups'], ['zeta', 'alpha'])
            self.assertEqual(sw['spec']['vlanNamespaces'], ['vlan-b', 'vlan-a'])
            self.assertEqual(sw['spec']['portGroupSpeeds'], {'1': 'SPEED_10G'})
            self.assertEqual(sw['spec']['portSpeeds'], {'E1/2': 'SPEED_25G'})
            self.assertNotIn('vlanNamespaces', named(docs, 'Switch', 'leaf-02')['spec'])
        sw = named(self.defaulted, 'Switch', 'leaf-01')
        self.assertEqual(sw['spec']['groups'], ['alpha', 'pair-1', 'zeta'])
        self.assertEqual(sw['spec']['vlanNamespaces'], ['vlan-a', 'vlan-b'])
        self.assertEqual(sw['spec']['portGroupSpeeds'], {'1': '10G'})
        self.assertEqual(sw['spec']['portSpeeds'], {'E1/2': '25G'})
        self.assertEqual(sw['metadata']['labels'], {'example.com/keep': 'yes', PREFIX + 'profile': 'vs',
                         **{'switchgroup.' + PREFIX + g: 'true' for g in ('alpha', 'pair-1', 'zeta')},
                         **{'vlanns.' + PREFIX + n: 'true' for n in ('vlan-a', 'vlan-b')}})
        sw2 = named(self.defaulted, 'Switch', 'leaf-02')
        self.assertEqual(sw2['spec']['vlanNamespaces'], ['default'])
        self.assertEqual(sw2['metadata']['labels'], {PREFIX + 'profile': 'vs', 'vlanns.' + PREFIX + 'default': 'true'})
        connection = named(self.defaulted, 'Connection', 'server-01--unbundled--leaf-01')
        self.assertEqual(connection['metadata']['labels'], {PREFIX + 'connection-type': 'unbundled',
                         'switch.' + PREFIX + 'leaf-01': 'true', 'server.' + PREFIX + 'server-01': 'true'})
        for docs in (self.printed, self.defaulted):
            sw = named(docs, 'Switch', 'leaf-01')
            self.assertEqual(sw['metadata']['namespace'], 'default')
            self.assertEqual(sw['metadata']['annotations'], {'example.com/note': 'keep-me'})
        self.assertEqual(core.object_value(named(self.printed, 'Server', 'server-01')),
                         core.object_value(named(self.defaulted, 'Server', 'server-01')))

    def test_namespace_and_ordinary_server_metadata_controls(self):
        expected, actual = self.passing()
        del named(actual, 'Switch', 'leaf-01')['metadata']['namespace']
        self.check_api(expected, actual)
        expected, actual = self.passing()
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
                expected, actual = self.passing()
                mutate(named(actual, 'Switch', 'leaf-01'))
                self.refused(expected, actual)

    def test_expected_identity_uniqueness_with_equal_collapsed_map(self):
        expected, actual = self.passing()
        # Expected installer docs have no count gate. An exact duplicate leaves
        # the maps equal, isolating production's expected-length guard.
        expected.append(copy.deepcopy(named(expected, 'Server', 'server-01')))
        self.refused(expected, actual)

    def test_actual_identity_uniqueness_with_equal_collapsed_map(self):
        expected, actual = self.passing()
        expected.remove(named(expected, 'Server', 'server-02'))
        index = next(i for i, doc in enumerate(actual)
                     if doc['kind'] == 'Server' and doc['metadata']['name'] == 'server-02')
        actual[index] = copy.deepcopy(named(actual, 'Server', 'server-01'))
        # Actual still has ten Servers; expected is unique; collapsed maps
        # match. Only production's actual-length guard rejects this pair.
        self.refused(expected, actual)


if __name__ == '__main__':
    unittest.main()
