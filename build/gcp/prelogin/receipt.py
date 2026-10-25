"""Strict data-only guest-attribute parsing. Does not authorize guest access.

Caller must authenticate reads, fence producer/import, check lease/VM/disks/
metadata/deadline before AND after, CAS archive exact bytes, then verify first
SSH boot UUID + evidence.json hash. None of that integration is installed here.
"""
import re
from . import hook as h


def attribute(raw, key):
    """Parse one bounded queryValue.items array (same shape as hostkey input)."""
    items = h.decode(raw, 8192)
    h.require(type(items) is list and len(items) == 1)
    obj = items[0]
    h.require(type(obj) is dict and set(obj) == {'namespace', 'key', 'value'})
    h.require(obj['namespace'] == 'labapp-prelogin' and obj['key'] == key)
    h.require(type(obj['value']) is str)
    try:
        value = obj['value'].encode('ascii')
    except UnicodeError:
        raise h.Refused('pre-login attribute refused') from None
    h.require(0 < len(value) <= 4096)
    return value


def fact(obj, allowed):
    h.require(type(obj) is dict and obj.get('id') in allowed)
    common = {'id', 'type', 'owner'}
    h.require(obj.get('type') in ('absent', 'unsupported', 'file', 'directory'))
    owner = obj.get('owner')
    h.require(type(owner) is dict)
    if owner != {'status': 'unknown'}:
        h.require(type(owner.get('name')) is str and re.fullmatch(r'[a-z0-9][a-z0-9+.:-]{0,127}', owner['name']))
        h.require(owner.get('status') in ('installed', 'missing'))
        h.require(set(owner) == ({'name', 'status'} if owner['status'] == 'missing' else {'name', 'status', 'version', 'architecture'}))
        if owner['status'] == 'installed':
            for key in ('version', 'architecture'):
                h.require(type(owner[key]) is str and re.fullmatch(r'[A-Za-z0-9.+:~_-]{1,128}', owner[key]))
    if obj['type'] in ('absent', 'unsupported'):
        h.require(set(obj) == common)
    else:
        h.require(obj['type'] in ('file', 'directory'))
        keys = common | {'uid', 'gid', 'mode', 'inode'}
        if obj['type'] == 'file':
            keys.add('sha256')
            h.require(type(obj.get('sha256')) is str and re.fullmatch(h.HEX, obj['sha256']))
        h.require(set(obj) == keys)
        for k in ('uid', 'gid', 'mode', 'inode'):
            h.integer(obj[k], 0, 0o7777 if k == 'mode' else 2**64-1)


def parse(summary_raw, parts_raw, expected, *, ready=False, reviewed_layouts=()):
    """Return validated summary only. inventory-only never satisfies ready=True."""
    h.identity(expected)
    summary = h.decode(summary_raw, 4096)
    keys = set(h.BIND) | {'schema', 'result', 'inventory_status', 'agent_generation',
                        'packages', 'layout_sha256', 'baseline_sha256', 'collisions', 'parts',
                        'unit_inventory_sha256', 'agent_config_layout_sha256',
                        'cache_layout_sha256', 'clean_hook_inventory_sha256'}
    h.require(type(summary) is dict and set(summary) == keys)
    h.require(summary['schema'] == 'prelogin-receipt-v1')
    h.require({k: summary[k] for k in h.BIND} == expected)
    h.identity({k: summary[k] for k in h.BIND})
    for key in ('layout_sha256', 'baseline_sha256'):
        h.require(type(summary[key]) is str and re.fullmatch(h.HEX, summary[key]))
    h.require(summary['result'] in ('ready', 'inventory-only'))
    h.require(summary['inventory_status'] in ('complete', 'missing-packages', 'incomplete', 'limit'))
    h.require(summary['agent_generation'] == 'unknown')
    packages = summary['packages']
    h.require(type(packages) is list and len(packages) == len(h.PACKAGES))
    for name, package in zip(h.PACKAGES, packages):
        h.require(type(package) is dict and package.get('name') == name)
        h.require(package.get('status') in ('installed', 'missing'))
        if package['status'] == 'missing':
            h.require(set(package) == {'name', 'status'})
        else:
            h.require(set(package) == {'name', 'status', 'version', 'architecture'})
            for key in ('version', 'architecture'):
                h.require(type(package[key]) is str and re.fullmatch(r'[A-Za-z0-9.+:~_-]{1,128}', package[key]))
    if summary['inventory_status'] in ('complete', 'missing-packages'):
        h.require((summary['inventory_status'] == 'complete') == all(p['status'] == 'installed' for p in packages))
    collisions = summary['collisions']
    h.require(type(collisions) is dict and set(collisions) == {'passwd', 'group', 'home', 'google_authorized_keys', '.google_authenticator'})
    h.require(all(type(v) is bool for v in collisions.values()))
    h.require(type(parts_raw) in (tuple, list) and len(parts_raw) == 4)
    h.require(type(summary['parts']) is list and len(summary['parts']) == 4)
    groups = []
    for i, (raw, descriptor) in enumerate(zip(parts_raw, summary['parts'])):
        h.require(type(descriptor) is dict and set(descriptor) == {'length', 'sha256'})
        h.integer(descriptor['length'], 1, 4096)
        h.require(type(raw) is bytes and len(raw) == descriptor['length'] and h.digest(raw) == descriptor['sha256'])
        part = h.decode(raw, 4096)
        h.require(type(part) is dict and set(part) == set(h.BIND) | {'schema', 'index', 'records'})
        h.require(part['schema'] == 'prelogin-part-v1' and type(part['index']) is int and part['index'] == i)
        h.identity({k: part[k] for k in h.BIND})
        h.require({k: part[k] for k in h.BIND} == expected)
        records = part['records']
        h.require(type(records) is list and len(records) <= (32 if i == 3 else len(h.GROUPS[i])))
        ids = []
        for record in records:
            h.require(type(record) is dict and type(record.get('id')) is str)
            allowed = h.GROUPS[i] if i < 3 else (record['id'],)
            if i == 3:
                h.require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', record['id']))
            fact(record, allowed)
            ids.append(record['id'])
        h.require(len(set(ids)) == len(ids))
        if i < 3:
            h.require(set(ids) == set(h.GROUPS[i]) or summary['inventory_status'] == 'limit' and not ids)
        else:
            h.require(ids == sorted(ids))
        groups.append(records)
    for key, group in zip(('unit_inventory_sha256', 'agent_config_layout_sha256',
                           'cache_layout_sha256', 'clean_hook_inventory_sha256'), groups):
        h.require(summary[key] == h.digest(h.canonical(group)))
    h.require(sum(map(len, parts_raw)) <= 16384)
    h.require(h.digest(h.canonical({'packages': packages, 'groups': groups})) == summary['layout_sha256'])
    if summary['result'] == 'ready' or ready:
        h.require(summary['result'] == 'ready' and summary['inventory_status'] == 'complete')
        h.require(summary['layout_sha256'] in reviewed_layouts and not any(collisions.values()))
        h.require(all(r['type'] != 'unsupported' for group in groups for r in group))
    return summary
