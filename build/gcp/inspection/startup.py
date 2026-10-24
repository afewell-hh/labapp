"""Derive allowlisted persisted startup settings, never effective/runtime state.

This intentionally recognizes a literal subset, not systemd or shell syntax.
Unknown material becomes fixed gap codes and never crosses into the candidate.
"""
import argparse
import json
from pathlib import Path
import re

from . import candidate, collector


DEPENDENCIES = frozenset(name + '.service' for name in collector.UNIT_NAMES) | {
    'network.target', 'network-online.target', 'multi-user.target',
    'docker.service', 'systemd-modules-load.service', 'sysinit.target',
}
BOOLEANS = frozenset(('yes', 'no', 'true', 'false', 'on', 'off', '0', '1'))
VALUES = {
    ('Service', 'Type'): frozenset(('simple', 'exec', 'forking', 'oneshot', 'idle', 'notify')),
    ('Service', 'Restart'): frozenset(('no', 'always', 'on-success', 'on-failure',
                                    'on-abnormal', 'on-watchdog', 'on-abort')),
    ('Service', 'RemainAfterExit'): BOOLEANS,
    ('Service', 'User'): frozenset(('root', 'ubuntu')),
    ('Service', 'Group'): frozenset(('root', 'ubuntu')),
    ('Service', 'WorkingDirectory'): frozenset(('/home/ubuntu/hhfab', '/opt/hedgehog/vlab', '/home/ubuntu')),
    ('Service', 'KillMode'): frozenset(('control-group', 'mixed', 'process', 'none')),
    ('Unit', 'ConditionPathExists'): frozenset(('/sys/class/net/hhbr',)),
    ('Unit', 'DefaultDependencies'): BOOLEANS,
}
LISTS = {('Unit', key): DEPENDENCIES for key in ('After', 'Before', 'Wants', 'Requires')}
LISTS[('Install', 'WantedBy')] = frozenset(('multi-user.target',))
TIMES = {('Service', key) for key in ('RestartSec', 'TimeoutStartSec', 'TimeoutStopSec')}
COMMAND_KEYS = frozenset(('ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecStop'))
COMMANDS = {f'/usr/local/bin/{name}': f'helper-{name}' for name in (
    'hhfab-vlab-resume.sh', 'hhbr-ip-setup.sh', 'fix-argocd-port.sh')}
# Exact public #130 recipe. Shell text is matched literally, never interpreted.
NETFILTER = "/bin/bash -c 'modprobe br_netfilter 2>/dev/null || true; sysctl -w net.bridge.bridge-nf-call-iptables=0; sysctl -w net.bridge.bridge-nf-call-ip6tables=0; sysctl -w net.bridge.bridge-nf-call-arptables=0'"
COMMANDS[NETFILTER] = 'netfilter-issue130'
for binary in ('/usr/local/bin/k3d', '/usr/bin/k3d'):
    COMMANDS[binary + ' kubeconfig merge k3d-observability -d'] = 'k3d-merge-' + binary.split('/')[1]
HHBR_RECIPE = Path(__file__).with_name('hhbr_ip_131.txt').read_text()


def normalized_body(text):
    """Only line-ending representation/final newline; no shell normalization."""
    return text.replace('\r\n', '\n').removesuffix('\n')


def unit_settings(text):
    text = text.replace('\r\n', '\n')
    # Python's splitlines/strip recognize Unicode separators that must never
    # invent systemd directives from the middle of an omitted private value.
    if '\r' in text or any(c.isspace() and c not in ' \t\n' for c in text):
        return {}, ['unsupported_syntax']
    fields, gaps, seen, blocked = {}, set(), set(), set()
    section = None
    for line in text.split('\n'):
        stripped = line.strip(' \t')
        if not stripped or stripped.startswith(('#', ';')):
            continue
        # Do not consume a continued line as a separate directive.
        if '\\' in line:
            return {}, ['unsupported_syntax']
        if stripped.startswith('['):
            section = stripped[1:-1] if stripped in ('[Unit]', '[Service]', '[Install]') else None
            if section is None:
                gaps.add('unknown_section')
            continue
        key, sep, value = stripped.partition('=')
        key, value = key.strip(' \t'), value.strip(' \t')
        if not sep or section is None:
            gaps.add('unsupported_syntax')
            continue
        pair = section, key
        # Description/documentation do not configure execution and are withheld.
        if section == 'Unit' and key in ('Description', 'Documentation'):
            continue
        known = pair in VALUES or pair in LISTS or pair in TIMES or (
            section == 'Service' and key in COMMAND_KEYS)
        if not known:
            gaps.add('unsupported_directive')
            continue
        # Reject repeat/reset rather than implement directive-specific semantics.
        if pair in seen:
            gaps.add('repeated_assignment')
            fields.pop(pair, None)
            blocked.add(pair)
        seen.add(pair)
        if not value:
            gaps.add('reset_assignment')
            fields.pop(pair, None)
            blocked.add(pair)
        if pair in blocked:
            continue
        if pair in VALUES:
            valid = value in VALUES[pair]
        elif pair in LISTS:
            valid = all(word in LISTS[pair] for word in value.split())
            value = ' '.join(value.split())
        elif pair in TIMES:
            # Literal seconds only; bounded configuration, not arbitrary strings.
            valid = re.fullmatch(r'[0-9]{1,4}', value) is not None and int(value) <= 3600
            if valid:
                value = str(int(value))
        else:
            valid = value in COMMANDS
        if valid:
            fields[pair] = value
        else:
            gaps.add('unsupported_value')
    result = {section: {key: value for (s, key), value in sorted(fields.items()) if s == section}
              for section in ('Unit', 'Service', 'Install')}
    return {s: values for s, values in result.items() if values}, sorted(gaps)


def format_unit(settings):
    """Render only revalidated public fields; no unvalidated candidate strings."""
    candidate.require(type(settings) is dict and all(type(v) is dict for v in settings.values()))
    text = ''.join('[' + section + ']\n' + ''.join(key + '=' + value + '\n'
                   for key, value in sorted(values.items())) + '\n'
                   for section, values in settings.items())
    parsed, gaps = unit_settings(text)
    candidate.require(not gaps and parsed == settings)
    return text


def derive(report):
    result = candidate.derive(report)  # Validate every raw field/hash first.
    units, helpers = [], []
    for record in report['records']:
        if record['status'] != 'captured':
            continue
        if record['kind'] == 'unit' and record['path'] in candidate.UNITS:
            settings, gaps = unit_settings(record['private_content'])
            units.append({'path': record['path'], 'sha256': record['sha256'],
                          'settings': settings, 'gaps': gaps,
                          'literal_subset_complete': not gaps,
                          'reusable_unit': format_unit(settings)})
        elif record['kind'] == 'helper':
            match = (record['path'] == '/usr/local/bin/hhbr-ip-setup.sh' and
                     normalized_body(record['private_content']) == normalized_body(HHBR_RECIPE))
            entry = {'path': record['path'], 'sha256': record['sha256'],
                     'recipe': 'hhbr-ip-issue131' if match else 'unknown'}
            if match:
                entry['reusable_script'] = HHBR_RECIPE
            helpers.append(entry)
    result['persisted_startup'] = {
        'schema_version': 1, 'effective': False, 'enabled_state': 'unknown',
        'runtime': 'unknown', 'units': sorted(units, key=lambda x: x['path']),
        'helpers': sorted(helpers, key=lambda x: x['path']),
        'limitations': ['dropins_not_composed', 'masks_aliases_not_resolved',
                        'generators_runtime_not_inspected', 'unknown_fields_withheld'],
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-input', required=True)
    parser.add_argument('--private-output', required=True)
    args = parser.parse_args()
    try:
        result = candidate.write_candidate(args.private_input, args.private_output, deriver=derive)
    except (OSError, ValueError, TypeError, RecursionError):
        parser.exit(1, 'Startup candidate refused: invalid_private_inventory.\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
