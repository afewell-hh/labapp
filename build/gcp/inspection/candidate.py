"""Derive a private, fixed-field inventory candidate; never publish automatically.

Input is private collector schema1, not executable configuration. Lead review
and independently verified provenance remain mandatory before publication.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import collector

PACKAGES = frozenset((
    'docker-ce', 'docker-ce-cli', 'docker.io', 'containerd', 'containerd.io',
    'qemu-kvm', 'qemu-system-x86', 'qemu-utils', 'libvirt-daemon-system',
    'libvirt-clients', 'xrdp', 'xfce4', 'xfce4-session', 'git', 'curl', 'jq',
    'python3', 'cloud-init', 'openssh-server', 'ubuntu-minimal',
))
GAPS = frozenset(('invalid_path', 'symlink_skipped', 'not_regular', 'missing',
                  'unreadable_or_changed', 'oversize', 'nontext', 'invalid_dpkg'))
STATUSES = GAPS | {'captured', 'too_many_entries'}
UNIMPLEMENTED = ['effective_systemd_configuration', 'recursive_helpers',
                 'environment_files', 'fabric_wiring', 'network_settings',
                 'shell_profiles', 'binary_versions', 'charts', 'runtime']
UNITS = frozenset(f'{d}/{n}.service' for d in collector.UNIT_DIRS for n in collector.UNIT_NAMES)
HELPERS = frozenset(f'{d}/{n}' for d in collector.HELPER_DIRS for n in collector.HELPER_NAMES)
SHA = re.compile(r'[0-9a-f]{64}')
VERSION = re.compile(r'[0-9][A-Za-z0-9.+:~\-]{0,255}')
NAME = re.compile(r'[a-z0-9][a-z0-9+.-]{0,254}')


class Refused(ValueError):
    """Fixed diagnostic only; never include rejected data."""


def require(condition):
    if not condition:
        raise Refused('invalid private inventory')


def derive(report):
    require(type(report) is dict and set(report) == {
        'schema_version', 'private_review_required', 'unimplemented', 'records'})
    require(type(report['schema_version']) is int and report['schema_version'] == 1)
    require(report['private_review_required'] is True and report['unimplemented'] == UNIMPLEMENTED)
    records = report['records']
    require(type(records) is list and len(records) <= collector.RECORD_LIMIT + len(UNITS))
    seen, counts, files, packages = set(), Counter(), [], []
    for record in records:
        require(type(record) is dict and {'path', 'kind', 'status'} <= set(record))
        path, kind, status = (record[k] for k in ('path', 'kind', 'status'))
        require(type(path) is str and len(path) <= 512 and type(kind) is str and type(status) is str)
        require(path not in seen and status in STATUSES)
        seen.add(path)
        if kind == 'os_release':
            valid = path in ('/etc/os-release', '/usr/lib/os-release')
        elif kind == 'packages':
            valid = path == '/var/lib/dpkg/status'
        elif kind == 'helper':
            valid = path in HELPERS
        elif kind == 'unit':
            base, _, name = path.rpartition('/')
            valid = path in UNITS or (base.endswith('.d') and base[:-2] in UNITS
                     and re.fullmatch(r'[A-Za-z0-9_.-]+\.conf', name) is not None)
        elif kind == 'dropin_directory':
            valid = path.endswith('.d') and path[:-2] in UNITS
        else:
            valid = False
        require(valid)
        if kind == 'dropin_directory':
            require(status in GAPS | {'too_many_entries'} and set(record) == {'path', 'kind', 'status'})
        elif status == 'captured':
            payload = 'packages' if kind == 'packages' else 'private_content'
            require(set(record) == {'path', 'kind', 'status', 'sha256', payload})
            require(type(record['sha256']) is str and SHA.fullmatch(record['sha256']))
            if payload == 'private_content':
                require(type(record[payload]) is str)
                body = record[payload].encode('utf-8')
                require(len(body) <= collector.FILE_LIMIT and
                        hashlib.sha256(body).hexdigest() == record['sha256'])
            else:
                require(type(record[payload]) is list and len(record[payload]) <= 50000)
                names = set()
                for package in record[payload]:
                    require(type(package) is dict and set(package) == {'name', 'version'})
                    name, version = package['name'], package['version']
                    require(type(name) is str and NAME.fullmatch(name) and type(version) is str and VERSION.fullmatch(version))
                    if name in PACKAGES:
                        require(name not in names)
                        names.add(name)
                        packages.append({'name': name, 'version': version})
        else:
            require(status in GAPS)
            expected = {'path', 'kind', 'status'}
            if status == 'invalid_dpkg':
                require(kind == 'packages' and type(record.get('sha256')) is str and SHA.fullmatch(record['sha256']))
                expected.add('sha256')
            require(set(record) == expected)
        counts[(kind, status)] += 1
        # Only compile-time fixed paths cross; dynamic drop-in names never do.
        if path in UNITS or path in HELPERS:
            entry = {'path': path, 'kind': kind, 'status': status}
            if status == 'captured':
                entry['sha256'] = record['sha256']
            files.append(entry)
    require(UNITS | {'/etc/os-release', '/var/lib/dpkg/status'} <= seen)
    return {'schema_version': 1, 'review_required': True,
            'provenance': 'lead-verification-required',
            'counts': [{'kind': k, 'status': s, 'count': n} for (k, s), n in sorted(counts.items())],
            'packages': sorted(packages, key=lambda p: p['name']),
            'files': sorted(files, key=lambda f: f['path'])}


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def private_parent(path):
    path = Path(path).absolute()
    parent = path.parent.resolve(strict=True)
    info = parent.stat()
    require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
    return parent / path.name


def write_candidate(source, destination, *, deriver=derive):
    source, destination = private_parent(source), private_parent(destination)
    # Check type before opening to avoid guest-like device/FIFO behavior.
    info = source.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= collector.REPORT_LIMIT)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600)
        data = stream.read(collector.REPORT_LIMIT + 1)
    require(len(data) <= collector.REPORT_LIMIT)
    candidate = deriver(json.loads(data, object_pairs_hook=pairs))
    output = (json.dumps(candidate, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')
    require(len(output) <= collector.REPORT_LIMIT)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(output)
    except BaseException:
        os.unlink(destination)
        raise
    return {'status': 'candidate-private-review-required', 'records': len(candidate['files']),
            'packages': len(candidate['packages']), 'sha256': hashlib.sha256(output).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-input', required=True)
    parser.add_argument('--private-output', required=True)
    args = parser.parse_args()
    try:
        result = write_candidate(args.private_input, args.private_output)
    except (OSError, ValueError, TypeError, RecursionError):
        parser.exit(1, 'Candidate refused; no private content is printed.\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
