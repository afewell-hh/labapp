"""Trusted lead-only host-baseline-v1 projection; never publish automatically.

Python plus trusted PyYAML, on the trusted host only (not the inspector guest).
Input/candidate remain private. Provenance and independent exact-hash review are
separate mandatory gates. No source content is executed or used in diagnostics.
"""
import argparse
from collections import Counter
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat

import yaml
from yaml import events, nodes

from . import host_baseline as h
from .collector import REPORT_LIMIT

SHA = re.compile(r'[0-9a-f]{64}')
WIRING_SHA = 'c522c64d80515c7484a67c27646acebf86073192f0f6ff9597497b990548806a'
CATALOG_ID = 'labapp-wiringd-c522c64d'
RELEASES = {
    (170709176, 'b5c7e0265339b9b95fa1073967bfb6c6fede6086755c85eca24cb80637b04e37'): 'hhfab-v0.43.1-linux-amd64',
    (100860066, '75b630d3e568b14306ac63520b05b9e1e419fe4874bcf46c888ee2a3bc7d1d08'): 'hhfab-v0.47.4-linux-amd64',
}
KINDS = ('Switch', 'Server', 'Connection', 'SwitchGroup', 'VLANNamespace', 'IPv4Namespace')
ROLES = ('spine', 'server-leaf', 'border-leaf', 'mixed-leaf')
VM_TYPES = ('control', 'switch', 'server', 'gateway', 'external')
SYSCTL = ('net.bridge.bridge-nf-call-iptables', 'net.bridge.bridge-nf-call-ip6tables',
          'net.bridge.bridge-nf-call-arptables', 'net.ipv4.ip_forward')
COMPONENTS = frozenset(x[0] for x in h.MANIFEST) | {'topology'}
GAP_REASONS = frozenset(('collection', 'invalid_yaml', 'unsupported', 'invalid_fields',
                         'missing_fields', 'incomplete_selection'))


class Refused(ValueError):
    """Fixed, non-source-bearing diagnostic."""


def require(value):
    if not value:
        raise Refused('invalid private host baseline')


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def validate(report):
    require(type(report) is dict and set(report) == {'schema_version', 'profile',
            'private_review_required', 'fixed_records', 'include', 'collection_complete'})
    require(type(report['schema_version']) is int and report['schema_version'] == 1 and
            report['profile'] == h.PROFILE and report['private_review_required'] is True and
            type(report['collection_complete']) is bool)
    fixed = report['fixed_records']
    require(type(fixed) is list and len(fixed) == 16)
    used = {'text': 0, 'hash': 0}

    def record(item, key, expected, kind):
        require(type(item) is dict and {key, 'status'} <= set(item))
        require(type(item[key]) is str and item[key] == expected)
        status = item['status']
        require(type(status) is str and status in h.STATUSES)
        if status != 'captured':
            require(set(item) in ({key, 'status'}, {key, 'status', 'reason'}))
            if 'reason' in item:
                require(type(item['reason']) is str and item['reason'] in h.REASONS)
                require((status == 'incomplete' and item['reason'] in {'byte_budget', 'total_deadline'}) or
                        (status == 'invalid' and item['reason'] == 'nontext'))
            return
        keys = {key, 'status', 'length', 'sha256'}
        if kind == 'text':
            keys.add('private_content')
        require(set(item) == keys)
        limit = 384 * h.MIB if kind == 'binary' else h.TEXT_LIMIT
        require(integer(item['length'], 0, limit) and type(item['sha256']) is str and
                SHA.fullmatch(item['sha256']) is not None)
        if kind == 'text':
            require(type(item['private_content']) is str)
            try:
                data = item['private_content'].encode('utf-8')
            except UnicodeError:
                raise Refused('invalid private host baseline') from None
            require(len(data) == item['length'] and hashlib.sha256(data).hexdigest() == item['sha256'])
        used['text' if kind == 'text' else 'hash'] += item['length']

    for item, (identity, _, kind) in zip(fixed, h.MANIFEST):
        record(item, 'id', identity, kind)
    inc = report['include']
    require(type(inc) is dict and set(inc) == {'status', 'entries_seen', 'selected_count', 'records'})
    require(type(inc['status']) is str and inc['status'] in h.STATUSES and
            integer(inc['entries_seen'], 0, 129) and type(inc['records']) is list and
            len(inc['records']) <= 32)
    if inc['status'] == 'captured':
        require(integer(inc['selected_count'], 0, 32) and
                inc['selected_count'] == len(inc['records']) <= inc['entries_seen'] <= 128)
    else:
        require(inc['selected_count'] is None and inc['records'] == [])
        require(inc['status'] == 'incomplete' or inc['entries_seen'] == 0)
    names = []
    for item in inc['records']:
        require(type(item) is dict and type(item.get('basename')) is str)
        name = item['basename']
        try:
            size = len(name.encode('utf-8'))
        except UnicodeError:
            raise Refused('invalid private host baseline') from None
        require(0 < size <= 255 and '/' not in name and '\0' not in name and
                name not in ('.', '..') and name.endswith('.yaml'))
        names.append(name)
        record(item, 'basename', name, 'text')
    require(names == sorted(set(names)))
    require(used['text'] <= h.TEXT_TOTAL and used['hash'] <= h.HASH_TOTAL)
    require(17 + len(names) <= h.RECORD_LIMIT)
    complete = (inc['status'] == 'captured' and all(x['status'] == 'captured' for x in fixed + inc['records']))
    require(report['collection_complete'] == complete)
    try:
        require(len(json.dumps(report, ensure_ascii=True).encode('ascii')) <= REPORT_LIMIT)
    except (ValueError, UnicodeError):
        raise Refused('invalid private host baseline') from None
    return {r['id']: r for r in fixed}


class YamlReader:
    """Event preflight BEFORE composition; bounded SafeLoader nodes only."""
    def __init__(self):
        self.documents = 0
        self.events = 0

    def read(self, text):
        require(type(text) is str and len(text.encode('utf-8')) <= h.TEXT_LIMIT)
        text = text.replace('\r\n', '\n')
        require('\r' not in text and not any(ord(c) < 32 and c not in '\n\t' for c in text))
        depth = docs = 0
        try:
            for event in yaml.parse(text, Loader=yaml.SafeLoader):
                self.events += 1
                require(self.events <= 100000)
                require(not isinstance(event, events.AliasEvent) and
                        getattr(event, 'anchor', None) is None and getattr(event, 'tag', None) is None)
                if isinstance(event, events.DocumentStartEvent):
                    docs += 1
                    self.documents += 1
                    require(docs <= 64 and self.documents <= 256)
                if isinstance(event, (events.MappingStartEvent, events.SequenceStartEvent)):
                    depth += 1
                    require(depth <= 32)
                if isinstance(event, (events.MappingEndEvent, events.SequenceEndEvent)):
                    depth -= 1
                if isinstance(event, events.ScalarEvent):
                    require(len(event.value.encode('utf-8')) <= 4096)
            # SafeLoader COMPOSES nodes: no constructors, object hooks or coercion.
            return [self.convert(n, 0) for n in yaml.compose_all(text, Loader=yaml.SafeLoader)]
        except (yaml.YAMLError, RecursionError, UnicodeError):
            raise Refused('invalid private host baseline') from None

    def convert(self, node, depth):
        require(depth <= 32)
        if isinstance(node, nodes.MappingNode):
            result = {}
            for key, val in node.value:
                require(isinstance(key, nodes.ScalarNode) and key.tag == 'tag:yaml.org,2002:str')
                require(key.value != '<<' and key.value not in result)
                result[key.value] = self.convert(val, depth + 1)
            return result
        if isinstance(node, nodes.SequenceNode):
            return [self.convert(v, depth + 1) for v in node.value]
        require(isinstance(node, nodes.ScalarNode))
        tag, value = node.tag.removeprefix('tag:yaml.org,2002:'), node.value
        if tag == 'str':
            return value
        require(node.style is None)
        if tag == 'int':
            require(re.fullmatch(r'0|[1-9][0-9]*|-[1-9][0-9]*', value) is not None and len(value) <= 32)
            return int(value)
        if tag == 'bool':
            require(value in ('true', 'false'))
            return value == 'true'
        if tag == 'null':
            require(value == 'null')
            return None
        raise Refused('invalid private host baseline')


def identity(doc):
    require(type(doc) is dict and type(doc.get('apiVersion')) is str and type(doc.get('kind')) is str)
    meta = doc.get('metadata')
    require(type(meta) is dict and type(meta.get('name')) is str and
            re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', meta['name']) is not None)
    ns = meta.get('namespace')
    require('namespace' not in meta or (type(ns) is str and
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', ns) is not None))
    return (doc['apiVersion'], doc['kind'], 'namespace' in meta, ns, meta['name'])


def document_set(docs):
    result = {}
    for doc in docs:
        key = identity(doc)
        require(key not in result)
        # JSON is type preserving: bool/int/string/null are distinct. Mapping
        # order is irrelevant, sequence order and absent fields are retained.
        result[key] = json.dumps(doc, sort_keys=True, ensure_ascii=True, separators=(',', ':'))
    return result


def public_wiring():
    path = Path(__file__).resolve().parents[3] / 'wiringd.yaml'
    with path.open('rb') as stream:
        data = stream.read(h.TEXT_LIMIT + 1)
    require(len(data) <= h.TEXT_LIMIT and hashlib.sha256(data).hexdigest() == WIRING_SHA)
    return document_set(YamlReader().read(data.decode('utf-8')))


def network_projection(item, module=False):
    result = {'id': item['id'], 'status': item['status'], 'values': {}}
    if item['status'] != 'captured':
        return result, False
    text = item['private_content'].replace('\r\n', '\n')
    if '\r' in text or any(ord(c) > 126 or (ord(c) < 32 and c not in '\n\t') for c in text):
        result['status'] = 'invalid'
        return result, False
    good = True
    seen, invalid = set(), set()
    for line in text.split('\n'):
        active = line.split('#', 1)[0].strip(' \t')
        if not active:
            continue
        if module:
            if active == 'br_netfilter' and 'br_netfilter' not in seen:
                seen.add('br_netfilter')
                result['values']['br_netfilter'] = True
            else:
                good = False
                if active == 'br_netfilter':
                    invalid.add('br_netfilter')
            continue
        match = re.fullmatch(r'([^=]+)=[ \t]*([01])[ \t]*', active)
        key = match[1].strip(' \t') if match else active.split('=', 1)[0].strip(' \t')
        if key not in SYSCTL:
            # Slash/reset/negative/glob spellings can target the same kernel
            # setting: withhold affected selected keys, never claim precedence.
            good = False
            normalized = key.lstrip('-').replace('/', '.')
            for selected in SYSCTL:
                if (normalized == selected or any(c in key for c in '*?[') or
                        re.match(re.escape(selected) + r'(?:[ \t=]|$)', normalized)):
                    invalid.add(selected)
            continue
        if key in seen or not match:
            invalid.add(key)
            good = False
        else:
            result['values'][key] = match[2] == '1'
        seen.add(key)
    for key in invalid:
        result['values'].pop(key, None)
    result['values'] = dict(sorted(result['values'].items()))
    if not good:
        result['status'] = 'incomplete'
    return result, good


def canonical_ip(value, kind):
    require(type(value) is str)
    try:
        parsed = {'network': ipaddress.IPv4Network, 'interface': ipaddress.IPv4Interface,
                  'address': ipaddress.IPv4Address}[kind](value)
    except (ValueError, TypeError):
        raise Refused('invalid private host baseline') from None
    require(str(parsed) == value)
    return value


def fabric_projection(docs):
    result = {'status': 'captured', 'counts': {}, 'selected': {}}
    counts, selected, found = Counter(), {}, False
    seen = set()
    for doc in docs:
        key = identity(doc)
        require(key not in seen)
        seen.add(key)
        require(doc['apiVersion'] == 'fabricator.githedgehog.com/v1beta1' and
                doc['kind'] in ('Fabricator', 'ControlNode', 'FabNode'))
        counts[doc['kind']] += 1
        if doc['kind'] != 'Fabricator':
            continue
        require(not found)
        found = True
        spec = doc.get('spec')
        require(type(spec) is dict and type(spec.get('config')) is dict)
        config = spec['config']
        for section in ('control', 'fabric'):
            if section not in config:
                continue
            values = config[section]
            require(type(values) is dict)
            networks = ('managementSubnet', 'kubeClusterSubnet', 'kubeServiceSubnet', 'dummySubnet') if section == 'control' else (
                'protocolSubnet', 'vtepSubnet', 'fabricSubnet', 'mclagSessionSubnet')
            for field in networks:
                if field in values:
                    selected[section + '.' + field] = canonical_ip(values[field], 'network')
            fields = ('controlVIP', 'kubeClusterDNS') if section == 'control' else ('managementDHCPStart', 'managementDHCPEnd')
            for field in fields:
                if field in values:
                    selected[section + '.' + field] = canonical_ip(values[field], 'interface' if field == 'controlVIP' else 'address')
            if section == 'fabric':
                if 'mode' in values:
                    require(values['mode'] == 'spine-leaf')
                    selected['fabric.mode'] = 'spine-leaf'
                for field in ('spineASN', 'leafASNStart', 'leafASNEnd'):
                    if field in values:
                        require(integer(values[field], 1, 2**32 - 1))
                        selected['fabric.' + field] = values[field]
        if 'fabric.leafASNStart' in selected and 'fabric.leafASNEnd' in selected:
            require(selected['fabric.leafASNStart'] <= selected['fabric.leafASNEnd'])
        for field, subnet in (('control.controlVIP', 'control.managementSubnet'),
                              ('control.kubeClusterDNS', 'control.kubeServiceSubnet'),
                              ('fabric.managementDHCPStart', 'control.managementSubnet'),
                              ('fabric.managementDHCPEnd', 'control.managementSubnet')):
            if field in selected and subnet in selected:
                address = selected[field].split('/')[0]
                require(ipaddress.IPv4Address(address) in ipaddress.IPv4Network(selected[subnet]))
        if 'fabric.managementDHCPStart' in selected and 'fabric.managementDHCPEnd' in selected:
            require(ipaddress.IPv4Address(selected['fabric.managementDHCPStart']) <=
                    ipaddress.IPv4Address(selected['fabric.managementDHCPEnd']))
    require(found)
    result['counts'] = dict(sorted(counts.items()))
    result['selected'] = dict(sorted(selected.items()))
    expected = {'control.' + k for k in ('managementSubnet', 'kubeClusterSubnet',
                'kubeServiceSubnet', 'dummySubnet', 'controlVIP', 'kubeClusterDNS')}
    expected |= {'fabric.' + k for k in ('mode', 'protocolSubnet', 'vtepSubnet',
                 'fabricSubnet', 'mclagSessionSubnet', 'managementDHCPStart',
                 'managementDHCPEnd', 'spineASN', 'leafASNStart', 'leafASNEnd')}
    result['projection_complete'] = set(selected) == expected
    # No omitted value is hydrated into a default.
    return result


def topology_projection(docs, complete, parsed):
    result = {'collection_complete': complete, 'projection_complete': complete and parsed,
              'graph_semantics': 'unknown', 'kind_counts': {}, 'switch_roles': {},
              'vlan_ranges': [], 'ipv4_subnets': [], 'public_wiring_match': 'unknown'}
    counts, roles, ranges = Counter(), Counter(), 0
    seen = set()
    try:
        require(len(docs) <= 256)
        for doc in docs:
            key = identity(doc)
            require(key not in seen)
            seen.add(key)
            kind = doc['kind']
            expected = ('vpc' if kind == 'IPv4Namespace' else 'wiring') + '.githedgehog.com/v1beta1'
            if kind not in KINDS or doc['apiVersion'] != expected:
                result['projection_complete'] = False
                continue
            counts[kind] += 1
            spec = doc.get('spec')
            if kind in ('Switch', 'VLANNamespace', 'IPv4Namespace'):
                require(type(spec) is dict)
            if kind == 'Switch':
                role = spec.get('role')
                if type(role) is str and role in ROLES:
                    roles[role] += 1
                else:
                    result['projection_complete'] = False
            if kind == 'VLANNamespace':
                require(type(spec.get('ranges')) is list)
                for pair in spec['ranges']:
                    ranges += 1
                    require(ranges <= 256 and type(pair) is dict and set(pair) == {'from', 'to'} and
                            integer(pair['from'], 1, 4094) and integer(pair['to'], pair['from'], 4094))
                    result['vlan_ranges'].append({'from': pair['from'], 'to': pair['to']})
            if kind == 'IPv4Namespace':
                require(type(spec.get('subnets')) is list)
                for subnet in spec['subnets']:
                    ranges += 1
                    require(ranges <= 256)
                    result['ipv4_subnets'].append(canonical_ip(subnet, 'network'))
        if complete and parsed:
            result['public_wiring_match'] = 'exact_parsed_documents' if document_set(docs) == public_wiring() else 'different'
            if result['public_wiring_match'] == 'exact_parsed_documents':
                result['catalog_id'] = CATALOG_ID
    except Refused:
        result['projection_complete'] = False
        result['public_wiring_match'] = 'unknown'
        # Refuse ambiguous partial counts/ranges following duplicate/invalid docs.
        counts, roles = Counter(), Counter()
        result['vlan_ranges'], result['ipv4_subnets'] = [], []
    result['kind_counts'] = dict(sorted(counts.items()))
    result['switch_roles'] = dict(sorted(roles.items()))
    result['vlan_ranges'].sort(key=lambda x: (x['from'], x['to']))
    result['ipv4_subnets'].sort()
    return result


def vlab_projection(docs):
    require(len(docs) == 1 and type(docs[0]) is dict)
    config = docs[0]
    counts, sizes, complete = Counter(), {}, True
    if 'vms' in config:
        require(type(config['vms']) is dict and len(config['vms']) <= 256)
        for vm in config['vms'].values():
            if type(vm) is not dict or type(vm.get('type')) is not str or vm['type'] not in VM_TYPES:
                complete = False
            else:
                counts[vm['type']] += 1
    else:
        complete = False
    if 'sizes' in config:
        require(type(config['sizes']) is dict)
        for kind, item in config['sizes'].items():
            if kind not in VM_TYPES or type(item) is not dict:
                complete = False
                continue
            selected = {}
            for field, high in (('cpu', 256), ('ram', 1048576), ('disk', 65536)):
                if field in item:
                    if integer(item[field], 1, high):
                        selected[field] = item[field]
                    else:
                        complete = False
            if set(item) - {'cpu', 'ram', 'disk'}:
                complete = False
            sizes[kind] = selected
    else:
        complete = False
    return {'status': 'captured', 'projection_complete': complete,
            'type_counts': dict(sorted(counts.items())), 'sizes': dict(sorted(sizes.items()))}


def derive(report):
    fixed = validate(report)
    result = {'schema_version': 1, 'binary_identities': [], 'fabric': {}, 'topology': {},
              'vlab': {}, 'network': [], 'shell_catalog': [], 'gaps': [],
              'effective': False, 'runtime': 'unknown'}
    gaps = set()
    def gap(component, reason):
        require(component in COMPONENTS and reason in GAP_REASONS)
        gaps.add((component, reason))
    for identity, _, kind in h.MANIFEST:
        item = fixed[identity]
        if item['status'] != 'captured':
            gap(identity, 'collection')
        if kind == 'binary':
            selected = {'id': identity, 'status': item['status'], 'release_match': 'unknown'}
            if item['status'] == 'captured':
                selected.update(length=item['length'], sha256=item['sha256'])
                if identity == 'hhfab':
                    selected['release_match'] = RELEASES.get((item['length'], item['sha256']), 'unknown')
            result['binary_identities'].append(selected)
        elif kind == 'shell':
            result['shell_catalog'].append({'id': identity, 'status': item['status'], 'recipe': 'unknown'})
        elif identity not in ('fabric', 'vlab'):
            projection, good = network_projection(item, identity in ('modules_bridge', 'modules'))
            result['network'].append(projection)
            if not good:
                gap(identity, 'unsupported')
    reader = YamlReader()
    for identity, key, project in (('fabric', 'fabric', fabric_projection), ('vlab', 'vlab', vlab_projection)):
        item = fixed[identity]
        result[key] = {'status': item['status']}
        if item['status'] == 'captured':
            try:
                docs = reader.read(item['private_content'])
                result[key] = project(docs)
                if not result[key].get('projection_complete', True):
                    gap(identity, 'invalid_fields')
            except Refused:
                result[key] = {'status': 'invalid'}
                gap(identity, 'invalid_fields')
    inc = report['include']
    complete = inc['status'] == 'captured' and all(r['status'] == 'captured' for r in inc['records'])
    docs, parsed = [], True
    for item in inc['records']:
        if item['status'] == 'captured':
            try:
                docs.extend(reader.read(item['private_content']))
            except Refused:
                parsed = False
    result['topology'] = topology_projection(docs, complete, parsed)
    if not complete:
        gap('topology', 'incomplete_selection')
    if not result['topology']['projection_complete']:
        gap('topology', 'unsupported')
    for key in ('binary_identities', 'shell_catalog', 'network'):
        result[key].sort(key=lambda x: x['id'])
    result['gaps'] = [{'component': component, 'reason': reason} for component, reason in sorted(gaps)]
    return result


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def write_candidate(source, output):
    # Trusted local private storage only; no source guest paths are opened here.
    source, output = Path(source), Path(output)
    for parent in (source.parent.resolve(strict=True), output.parent.resolve(strict=True)):
        info = parent.stat()
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size <= REPORT_LIMIT)
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read(REPORT_LIMIT + 1)
        require(len(data) == info.st_size and h.stamp(info) == h.stamp(os.fstat(fd)))
    finally:
        os.close(fd)
    report = json.loads(data, object_pairs_hook=unique)
    candidate = derive(report)
    encoded = (json.dumps(candidate, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')
    require(len(encoded) <= REPORT_LIMIT)
    # Delay cancellation only across creation/ownership assignment; deliver it
    # inside the cleanup scope, including before fdopen enters its context.
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
    try:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(encoded)
        except BaseException:
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
            try:
                os.close(fd)
            except OSError:
                pass  # fdopen may already have closed its owned descriptor.
            output.unlink()
            raise
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    return {'candidate_sha256': hashlib.sha256(encoded).hexdigest(), 'private_review_required': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-report', required=True)
    parser.add_argument('--private-output', required=True)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        print(json.dumps(write_candidate(args.private_report, args.private_output), sort_keys=True))
    except (Refused, OSError, ValueError, UnicodeError, RecursionError, KeyboardInterrupt):
        parser.exit(1, 'Host derivation refused; no source content is printed.\n')


if __name__ == '__main__':
    main()
