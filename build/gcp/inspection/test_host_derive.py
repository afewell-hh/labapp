"""Adversarial public report/YAML fixtures; never appliance-source inputs."""
import copy
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from . import host_baseline as h, host_derive as d

MARKER = 'PRIVATE_SYNTHETIC_MARKER'


def text_record(identity, body, key='id'):
    data = body.encode()
    return {key: identity, 'status': 'captured', 'length': len(data),
            'sha256': hashlib.sha256(data).hexdigest(), 'private_content': body}


def empty_report():
    return {'schema_version': 1, 'profile': h.PROFILE, 'private_review_required': True,
            'fixed_records': [{'id': x[0], 'status': 'missing'} for x in h.MANIFEST],
            'include': {'status': 'captured', 'entries_seen': 0, 'selected_count': 0, 'records': []},
            'collection_complete': False}


def put(report, identity, body):
    index = [x[0] for x in h.MANIFEST].index(identity)
    report['fixed_records'][index] = text_record(identity, body)


def wiring_report(body):
    report = empty_report()
    report['include'] = {'status': 'captured', 'entries_seen': 1, 'selected_count': 1,
                         'records': [text_record('private.yaml', body, 'basename')]}
    return report


def object_yaml(kind='Switch', spec='role: spine', api='wiring'):
    return ('apiVersion: ' + api + '.githedgehog.com/v1beta1\nkind: ' + kind +
            '\nmetadata: {name: private-name}\nspec: {' + spec + '}\n')


class ReportValidationTests(unittest.TestCase):
    def test_exact_envelope_and_all_nested_keys_and_types(self):
        original = empty_report()
        d.validate(original)
        changes = [lambda r: r.update(extra='SECRET'), lambda r: r.update(schema_version=True),
                   lambda r: r.update(profile='default'), lambda r: r.update(private_review_required=False),
                   lambda r: r.update(collection_complete=True), lambda r: r['fixed_records'].pop(),
                   lambda r: r['fixed_records'].reverse(),
                   lambda r: r['fixed_records'][0].update(id='outside'),
                   lambda r: r['fixed_records'][0].update(status='arbitrary'),
                   lambda r: r['fixed_records'][0].update(private_content='SECRET'),
                   lambda r: r['fixed_records'][0].update(reason='SECRET'),
                   lambda r: r['fixed_records'][0].update(reason='byte_budget'),
                   lambda r: r['include'].update(extra=1), lambda r: r['include'].update(entries_seen=True),
                   lambda r: r['include'].update(entries_seen=129),
                   lambda r: r['include'].update(selected_count=None),
                   lambda r: r['include'].update(status='missing')]
        for change in changes:
            report = copy.deepcopy(original)
            change(report)
            with self.subTest(change=change), self.assertRaises(d.Refused):
                d.derive(report)

    def test_content_digest_lengths_budgets_and_wrong_kinds(self):
        original = empty_report()
        put(original, 'fabric', '{}')
        d.validate(original)
        for key, value in (('length', True), ('length', 1), ('sha256', 'A' * 64),
                           ('private_content', MARKER), ('length', h.TEXT_LIMIT + 1)):
            report = copy.deepcopy(original)
            report['fixed_records'][4][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(d.Refused):
                d.validate(report)
        report = empty_report()
        report['fixed_records'][0] = text_record('hhfab', MARKER)
        with self.assertRaises(d.Refused):
            d.validate(report)
        report = empty_report()
        for identity in ('fabric', 'vlab', 'sysctl_bridge', 'sysctl', 'modules'):
            put(report, identity, 'x' * h.TEXT_LIMIT)
        with self.assertRaises(d.Refused):
            d.validate(report)
        report = empty_report()
        for item in report['fixed_records'][:2]:
            item.update(status='captured', length=384 * h.MIB, sha256='a' * 64)
        with self.assertRaises(d.Refused):
            d.validate(report)

    def test_include_names_counts_order_status_overflow(self):
        original = wiring_report('{}')
        d.validate(original)
        for name in ('../outside.yaml', 'x.yml', '\0.yaml', 'a' * 256 + '.yaml', '\udcff.yaml'):
            report = copy.deepcopy(original)
            report['include']['records'][0]['basename'] = name
            with self.subTest(name=repr(name)), self.assertRaises(d.Refused):
                d.validate(report)
        for mutation in (lambda r: r['include']['records'].append(r['include']['records'][0]),
                         lambda r: r['include'].update(selected_count=0),
                         lambda r: r['include'].update(status='incomplete'),
                         lambda r: r['include'].update(entries_seen=0)):
            report = copy.deepcopy(original)
            mutation(report)
            with self.assertRaises(d.Refused):
                d.validate(report)
        report = empty_report()
        report['include'].update(status='incomplete', entries_seen=129, selected_count=None)
        d.validate(report)
        self.assertFalse(d.derive(report)['topology']['collection_complete'])

    def test_report_ceiling_independent_of_byte_budgets(self):
        report = empty_report()
        with mock.patch.object(d, 'REPORT_LIMIT', 1), self.assertRaises(d.Refused):
            d.validate(report)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'guest'
            root.mkdir()
            private = Path(temp) / 'private'
            private.mkdir(mode=0o700)
            with mock.patch.object(h, 'REPORT_LIMIT', 1), self.assertRaises(h.Gap):
                h.write_private(root, private / 'report')
            self.assertFalse((private / 'report').exists())

    def test_known_binary_member_not_archive_and_shell_hash_withheld(self):
        report = empty_report()
        length, digest = next(iter(d.RELEASES))
        report['fixed_records'][0].update(status='captured', length=length, sha256=digest)
        report['fixed_records'][10] = {'id': 'ubuntu_profile', 'status': 'captured', 'length': 7, 'sha256': 'b' * 64}
        result = d.derive(report)
        self.assertEqual(next(x for x in result['binary_identities'] if x['id'] == 'hhfab')['release_match'], 'hhfab-v0.43.1-linux-amd64')
        self.assertNotIn('b' * 64, json.dumps(result))
        report['fixed_records'][0]['sha256'] = 'b1387342191a329772c2595504ec6ff129eb45980727c1c86d9901ef4d9f37a4'
        self.assertEqual(next(x for x in d.derive(report)['binary_identities'] if x['id'] == 'hhfab')['release_match'], 'unknown')

    def test_private_candidate_exclusive_output_and_duplicate_json(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            parent.chmod(0o700)
            source, output = parent / 'report', parent / 'candidate'
            source.write_text(json.dumps(empty_report()))
            source.chmod(0o600)
            receipt = d.write_candidate(source, output)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(receipt['candidate_sha256'], hashlib.sha256(output.read_bytes()).hexdigest())
            with self.assertRaises(FileExistsError):
                d.write_candidate(source, output)
            source.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaises(d.Refused):
                d.write_candidate(source, parent / 'other')
            source.unlink()
            source.symlink_to(output)
            with self.assertRaises(OSError):
                d.write_candidate(source, parent / 'other')

    def test_direct_deriver_sigterm_removes_owned_partial_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            parent.chmod(0o700)
            source, output, ready = parent / 'report', parent / 'candidate', parent / 'ready'
            source.write_text(json.dumps(empty_report()))
            source.chmod(0o600)
            code = """import os,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from inspection import host_derive as d
source,out,ready=sys.argv[2:]
real=os.fdopen
class Slow:
    def __init__(self,fd): self.file=real(fd,'wb')
    def __enter__(self): return self
    def __exit__(self,*args): self.file.close()
    def write(self,data):
        self.file.write(data[:1]);self.file.flush()
        Path(ready).write_text('ready')
        time.sleep(10)
def fdopen(fd,mode,*args,**kw):
    return Slow(fd) if mode=='wb' else real(fd,mode,*args,**kw)
d.os.fdopen=fdopen
sys.argv=['derive','--private-report',source,'--private-output',out]
d.main()
"""
            process = subprocess.Popen([sys.executable, '-c', code,
                str(Path(d.__file__).resolve().parents[1]), str(source), str(output), str(ready)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(ready.exists())
                self.assertEqual(output.stat().st_size, 1)
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 1)
                self.assertEqual(stdout, b'')
                self.assertEqual(stderr, b'Host derivation refused; no source content is printed.\n')
                self.assertFalse(output.exists())
                self.assertTrue(source.exists())
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=3)


class TypedYamlTests(unittest.TestCase):
    def test_scalar_types_are_not_coerced(self):
        result = d.YamlReader().read('a: 1\nb: true\nc: null\nd: "1"\ne: "true"\nf: "null"\ng: {}\n')[0]
        self.assertEqual([type(result[k]) for k in 'abcdefg'], [int, bool, type(None), str, str, str, dict])
        for body in ('a: 01', 'a: +1', 'a: -0', 'a: 0x10', 'a: 1_000', 'a: 1.5', 'a: .nan',
                     'a: yes', 'a: TRUE', 'a: ~', 'a:', 'a: Null', 'a: 2026-10-24', 'a: !!str x',
                     'a: &x y', 'a: *x', 'a: 1\na: 2', '1: x', 'true: x', 'a: {<<: x}', 'a:\rb: 1',
                     'a: "\x01"'):
            with self.subTest(body=repr(body)), self.assertRaises(d.Refused):
                d.YamlReader().read(body)

    def test_depth_scalar_document_and_aggregate_event_limits(self):
        for body in ('a: ' + 'x' * 4097, '[' * 33 + 'x' + ']' * 33,
                     '---\na: 1\n' * 65):
            with self.assertRaises(d.Refused):
                d.YamlReader().read(body)
        reader = d.YamlReader()
        reader.read('---\na: 1\n' * 64)
        reader.read('---\na: 1\n' * 64)
        reader.read('---\na: 1\n' * 64)
        reader.read('---\na: 1\n' * 64)
        with self.assertRaises(d.Refused):
            reader.read('a: 1')
        reader = d.YamlReader()
        reader.events = 100000
        with self.assertRaises(d.Refused):
            reader.read('a: 1')

    def test_official_separation_tab_accepted_with_safety_gates_intact(self):
        # Public upstream hhfab 0.43.1 template shape: tab between `ip:` and `dhcp`.
        pure = 'ip:\tdhcp # public upstream template\n'
        with self.assertRaises(d.yaml.YAMLError):
            d.yaml.safe_load(pure)  # pure SafeLoader refuses it; libyaml accepts it
        self.assertEqual(d.YamlReader().read(pure), [{'ip': 'dhcp'}])
        plain = d.yaml.compose('1', Loader=d.safe_loader())
        self.assertEqual(plain.style, '')  # CParser's plain style, not None.
        self.assertIs(type(d.YamlReader().convert(plain, 0)), int)
        result = d.YamlReader().read('a:\t1\nb:\ttrue\nc:\t"1"\nd:\tnull\n')[0]
        self.assertEqual([type(result[k]) for k in 'abcd'], [int, bool, str, type(None)])
        for body in ('ip:\t&x dhcp', 'ip:\t*x', 'ip:\t!!str dhcp', 'ip:\t{<<: x}', 'ip:\tdhcp\nip:\tdhcp',
                     '1:\tx', 'a:\tyes', 'a:\t01', 'a:\t1.5', 'a:\t' + 'x' * 4097):
            with self.subTest(body=repr(body)), self.assertRaises(d.Refused):
                d.YamlReader().read(body)

    def test_loader_preflight_has_no_permissive_fallback(self):
        self.assertIs(d.safe_loader(), d.yaml.CSafeLoader)
        for loader in (None, object(), d.yaml.SafeLoader):
            with self.subTest(loader=type(loader)), mock.patch.object(d.yaml, 'CSafeLoader', loader):
                with self.assertRaises(d.Refused):
                    d.YamlReader().read('a: 1')
        with mock.patch.object(d.yaml, '__with_libyaml__', False):
            with self.assertRaises(d.Refused):
                d.YamlReader().read('a: 1')
        for version in ('5.4.1', '', 'x', '6.0garbage', '6.0rc1', None, 6.0):
            with self.subTest(version=version), mock.patch.object(d.yaml, '__version__', version):
                with self.assertRaises(d.Refused):
                    d.YamlReader().read('a: 1')

    def test_unavailable_loader_aborts_derivation_and_leaves_no_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            parent.chmod(0o700)
            source, output = parent / 'report', parent / 'candidate'
            source.write_text(json.dumps(empty_report()))
            source.chmod(0o600)
            with mock.patch.object(d.yaml, 'CSafeLoader', None):
                with self.assertRaises(d.Refused):
                    d.derive(empty_report())
                with self.assertRaises(d.Refused):
                    d.write_candidate(source, output)
            self.assertFalse(output.exists())

    def test_composition_never_calls_constructors(self):
        with mock.patch.object(d.yaml.CSafeLoader, 'construct_document', side_effect=AssertionError):
            self.assertEqual(d.YamlReader().read('ip:\tdhcp\n'), [{'ip': 'dhcp'}])

    def test_preflight_rejects_before_composition(self):
        with mock.patch.object(d.yaml, 'compose_all', side_effect=AssertionError):
            with self.assertRaises(d.Refused):
                d.YamlReader().read('a: &x hi')


class ProjectionTests(unittest.TestCase):
    def test_complete_public_wiring_match_and_document_order(self):
        path = Path(__file__).resolve().parents[3] / 'wiringd.yaml'
        body = path.read_text()
        result = d.derive(wiring_report(body))['topology']
        self.assertEqual(result['public_wiring_match'], 'exact_parsed_documents')
        self.assertEqual(result['kind_counts'], {'Switch': 7, 'Server': 10, 'Connection': 21,
                         'SwitchGroup': 3, 'VLANNamespace': 1, 'IPv4Namespace': 1})
        self.assertEqual(result['switch_roles'], {'spine': 2, 'server-leaf': 5})
        self.assertTrue(result['projection_complete'])
        docs = list(reversed(body.split('\n---\n')))
        self.assertEqual(d.derive(wiring_report('\n---\n'.join(docs)))['topology']['public_wiring_match'], 'exact_parsed_documents')
        # Quoting even a safe integer changes complete-object catalog identity.
        changed = body.replace('from: 1000', 'from: "1000"')
        result = d.derive(wiring_report(changed))['topology']
        self.assertFalse(result['projection_complete'])
        self.assertNotEqual(result['public_wiring_match'], 'exact_parsed_documents')
        changed = body.replace('spec: {}', 'spec: {flag: true}', 1)
        changed2 = body.replace('spec: {}', 'spec: {flag: "true"}', 1)
        self.assertNotEqual(d.document_set(d.YamlReader().read(changed)), d.document_set(d.YamlReader().read(changed2)))

    def test_typed_document_set_absent_null_namespace_sequence(self):
        a = d.YamlReader().read(object_yaml('SwitchGroup', 'items: [1, 2]'))
        for alteration in ('items: [2, 1]', 'items: ["1", 2]', 'items: null'):
            b = d.YamlReader().read(object_yaml('SwitchGroup', alteration))
            self.assertNotEqual(d.document_set(a), d.document_set(b))
        b = copy.deepcopy(a)
        b[0]['metadata']['namespace'] = 'default'
        self.assertNotEqual(d.document_set(a), d.document_set(b))
        b[0]['metadata']['namespace'] = None
        with self.assertRaises(d.Refused):
            d.document_set(b)

    def test_different_wiring_roles_ranges_no_private_names(self):
        body = object_yaml() + '\n---\n' + object_yaml('VLANNamespace', 'ranges: [{from: 2, to: 4}]')
        body += '\n---\n' + object_yaml('IPv4Namespace', 'subnets: [10.1.0.0/16]', 'vpc')
        result = d.derive(wiring_report(body))
        topology = result['topology']
        self.assertEqual(topology['public_wiring_match'], 'different')
        self.assertTrue(topology['projection_complete'])
        self.assertEqual(topology['vlan_ranges'], [{'from': 2, 'to': 4}])
        self.assertEqual(topology['ipv4_subnets'], ['10.1.0.0/16'])
        self.assertNotIn('private-name', json.dumps(result))
        self.assertNotIn('private.yaml', json.dumps(result))
        self.assertFalse(result['effective'])
        self.assertEqual(result['runtime'], 'unknown')

    def test_unknown_duplicate_role_range_and_incomplete_selection(self):
        for body in (object_yaml('Unknown'), object_yaml(spec='role: private-unsupported-role'),
                     object_yaml() + '\n---\n' + object_yaml(),
                     object_yaml('VLANNamespace', 'ranges: [{from: true, to: 4}]'),
                     object_yaml('VLANNamespace', 'ranges: [{from: 4, to: 2}]'),
                     object_yaml('VLANNamespace', 'ranges: [{from: 1, to: 4095}]'),
                     object_yaml('IPv4Namespace', 'subnets: [10.0.1.0/16]', 'vpc')):
            with self.subTest(body=body):
                result = d.derive(wiring_report(body))['topology']
                self.assertFalse(result['projection_complete'])
                self.assertNotEqual(result['public_wiring_match'], 'exact_parsed_documents')
        report = wiring_report(object_yaml())
        report['include']['records'][0] = {'basename': 'private.yaml', 'status': 'timeout'}
        result = d.derive(report)['topology']
        self.assertFalse(result['collection_complete'])
        self.assertFalse(result['projection_complete'])
        self.assertEqual(result['public_wiring_match'], 'unknown')

    def test_fabric_typed_fields_membership_and_secret_adjacent(self):
        report = empty_report()
        body = '''apiVersion: fabricator.githedgehog.com/v1beta1
kind: Fabricator
metadata: {name: default}
spec:
  config:
    control:
      managementSubnet: 172.30.0.0/21
      kubeServiceSubnet: 10.96.0.0/16
      controlVIP: 172.30.0.1/21
      kubeClusterDNS: 10.96.0.10
      joinToken: PRIVATE_SYNTHETIC_MARKER
    fabric:
      mode: spine-leaf
      spineASN: 65100
      leafASNStart: 65101
      leafASNEnd: 65110
      managementDHCPStart: 172.30.0.10
      managementDHCPEnd: 172.30.0.20
      defaultSwitchUsers: {admin: PRIVATE_SYNTHETIC_MARKER}
'''
        put(report, 'fabric', body)
        result = d.derive(report)
        self.assertEqual(result['fabric']['selected']['fabric.spineASN'], 65100)
        self.assertNotIn(MARKER, json.dumps(result))
        self.assertFalse(result['fabric']['projection_complete'])
        for old, new in (('spineASN: 65100', 'spineASN: "65100"'),
                         ('spineASN: 65100', 'spineASN: true'),
                         ('leafASNEnd: 65110', 'leafASNEnd: 65000'),
                         ('172.30.0.1/21', '172.31.0.1/21'),
                         ('172.30.0.0/21', '172.30.0.1/21'),
                         ('10.96.0.10', '10.97.0.10'), ('mode: spine-leaf', 'mode: collapsed-core')):
            put(report, 'fabric', body.replace(old, new))
            with self.subTest(new=new):
                self.assertEqual(d.derive(report)['fabric']['status'], 'invalid')
        put(report, 'fabric', body + '\n---\n' + body)
        self.assertEqual(d.derive(report)['fabric']['status'], 'invalid')

    def test_vlab_sizes_counts_missing_and_unsupported(self):
        report = empty_report()
        body = 'vms: {private-name: {type: control, ssh: PRIVATE_SYNTHETIC_MARKER}, other: {type: switch}}\nsizes: {control: {cpu: 4, ram: 4096, disk: 25}}'
        put(report, 'vlab', body)
        result = d.derive(report)
        self.assertEqual(result['vlab']['type_counts'], {'control': 1, 'switch': 1})
        self.assertEqual(result['vlab']['sizes']['control']['ram'], 4096)
        self.assertNotIn(MARKER, json.dumps(result))
        for old, new in (('cpu: 4', 'cpu: "4"'), ('cpu: 4', 'cpu: true'),
                         ('ram: 4096', 'ram: 1048577'), ('type: switch', 'type: unsupported')):
            put(report, 'vlab', body.replace(old, new))
            self.assertFalse(d.derive(report)['vlab']['projection_complete'])
        put(report, 'vlab', '{}')
        self.assertFalse(d.derive(report)['vlab']['projection_complete'])

    def test_network_selected_booleans_and_ambiguous_lines(self):
        report = empty_report()
        put(report, 'sysctl', 'net.ipv4.ip_forward = 1 # public\nnet.bridge.bridge-nf-call-iptables=0\n')
        put(report, 'modules', 'br_netfilter # selected\n')
        result = d.derive(report)
        net = {x['id']: x for x in result['network']}
        self.assertEqual(net['sysctl']['values'], {'net.ipv4.ip_forward': True, 'net.bridge.bridge-nf-call-iptables': False})
        self.assertTrue(net['modules']['values']['br_netfilter'])
        for line in ('net.ipv4.ip_forward=0', 'net.ipv4.ip_forward=7', 'net/ipv4/ip_forward=1',
                     '-net.ipv4.ip_forward=1', 'net.ipv4.*=1', 'net.ipv4.ip_forward 1'):
            put(report, 'sysctl', 'net.ipv4.ip_forward=1\n' + line)
            selected = next(x for x in d.derive(report)['network'] if x['id'] == 'sysctl')
            self.assertNotIn('net.ipv4.ip_forward', selected['values'])
            self.assertEqual(selected['status'], 'incomplete')
        put(report, 'sysctl', 'PRIVATE_SYNTHETIC_MARKER=1')
        put(report, 'modules', 'br_netfilter option=PRIVATE_SYNTHETIC_MARKER')
        self.assertNotIn(MARKER, json.dumps(d.derive(report)))


if __name__ == '__main__':
    unittest.main()
