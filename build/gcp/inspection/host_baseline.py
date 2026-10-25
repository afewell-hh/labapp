"""Fixed host-baseline-v1 collector; Linux/Python stdlib, no guest execution.

Invoke on an already immutable read-only tree, as the trusted mounted collector.
Every potentially blocking source operation runs in an owned, bounded child.
The root/path comes only from the trusted wrapper, never the private report.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import time

from .collector import Guest, Gap, REPORT_LIMIT, RECORD_LIMIT

PROFILE = 'host-baseline-v1'
MIB = 1024 * 1024
TEXT_LIMIT = 256 * 1024
TEXT_TOTAL = MIB
HASH_TOTAL = 512 * MIB
TOTAL_SECONDS = 120
INCLUDE = '/home/ubuntu/hhfab/include'
# Order is part of the private wire contract. IDs, never source paths, are derived.
MANIFEST = (
    ('hhfab', '/usr/local/bin/hhfab', 'binary'),
    ('k3d', '/usr/local/bin/k3d', 'binary'),
    ('kubectl', '/usr/local/bin/kubectl', 'binary'),
    ('helm', '/usr/local/bin/helm', 'binary'),
    ('fabric', '/home/ubuntu/hhfab/fab.yaml', 'text'),
    ('vlab', '/home/ubuntu/hhfab/vlab/config.yaml', 'text'),
    ('sysctl_bridge', '/etc/sysctl.d/99-vlab-bridge.conf', 'text'),
    ('modules_bridge', '/etc/modules-load.d/br_netfilter.conf', 'text'),
    ('sysctl', '/etc/sysctl.conf', 'text'),
    ('modules', '/etc/modules', 'text'),
    ('ubuntu_profile', '/home/ubuntu/.profile', 'shell'),
    ('ubuntu_bashrc', '/home/ubuntu/.bashrc', 'shell'),
    ('ubuntu_aliases', '/home/ubuntu/.bash_aliases', 'shell'),
    ('etc_profile', '/etc/profile', 'shell'),
    ('etc_bashrc', '/etc/bash.bashrc', 'shell'),
    ('motd', '/etc/motd', 'shell'),
)
STATUSES = frozenset(('captured', 'missing', 'symlink_skipped', 'not_regular',
                      'oversize', 'unreadable_or_changed', 'timeout', 'unsupported',
                      'invalid', 'incomplete'))
REASONS = frozenset(('byte_budget', 'total_deadline', 'entry_limit',
                     'selection_limit', 'invalid_name', 'nontext'))


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode)


def child_file(root, path, kind, remaining):
    guest = Guest(root)
    fd, count = None, 0
    try:
        fd = guest.open(path)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise Gap('not_regular')
        limit = 384 * MIB if kind == 'binary' else TEXT_LIMIT
        if before.st_size > limit:
            raise Gap('oversize')
        if before.st_size > remaining:
            return {'status': 'incomplete', 'reason': 'byte_budget'}
        digest, count, chunks = hashlib.sha256(), 0, []
        while count < before.st_size:
            data = os.read(fd, min(65536, before.st_size - count))
            if not data:
                break
            count += len(data)
            if count > limit or count > remaining:
                raise Gap('unreadable_or_changed')
            digest.update(data)
            if kind == 'text':
                chunks.append(data)
        # Reopen via the same pinned root: replacement and component-link races
        # cannot silently turn a stable old FD into an apparently current input.
        other = guest.open(path)
        try:
            if (count != before.st_size or stamp(before) != stamp(os.fstat(fd)) or
                    stamp(before) != stamp(os.fstat(other))):
                raise Gap('unreadable_or_changed')
        finally:
            os.close(other)
        result = {'status': 'captured', 'length': count, 'sha256': digest.hexdigest()}
        if kind == 'text':
            try:
                result['private_content'] = b''.join(chunks).decode('utf-8')
            except UnicodeError:
                return {'status': 'invalid', 'reason': 'nontext', '_consumed': count}
        return result
    except (Gap, OSError) as error:
        status = str(error) if isinstance(error, Gap) else 'unreadable_or_changed'
        if count:
            return {'status': status, '_consumed': count}
        raise
    finally:
        if fd is not None:
            os.close(fd)
        guest.close()


def child_entries(root):
    guest = Guest(root)
    fd = None
    try:
        fd = guest.open(INCLUDE, directory=True)
        before = os.fstat(fd)
        names, seen = [], 0
        with os.scandir(fd) as entries:
            for entry in entries:
                seen += 1
                if seen > 128:
                    return {'status': 'incomplete', 'reason': 'entry_limit',
                            'entries_seen': 129, 'names': []}
                name = entry.name
                try:
                    raw = name.encode('utf-8')
                except UnicodeError:
                    return {'status': 'incomplete', 'reason': 'invalid_name',
                            'entries_seen': seen, 'names': []}
                if name.endswith('.yaml'):
                    if len(raw) > 255 or '/' in name or '\0' in name:
                        return {'status': 'incomplete', 'reason': 'invalid_name',
                                'entries_seen': seen, 'names': []}
                    names.append(name)
        other = guest.open(INCLUDE, directory=True)
        try:
            if stamp(before) != stamp(os.fstat(fd)) or stamp(before) != stamp(os.fstat(other)):
                raise Gap('unreadable_or_changed')
        finally:
            os.close(other)
        if len(names) > 32:
            return {'status': 'incomplete', 'reason': 'selection_limit',
                    'entries_seen': seen, 'names': []}
        return {'status': 'captured', 'entries_seen': seen, 'names': sorted(names)}
    finally:
        if fd is not None:
            os.close(fd)
        guest.close()


def reap(pid):
    """Kill only our known child and require bounded successful waitpid."""
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            result, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return
        if result == pid:
            return
        time.sleep(.01)
    raise Gap('reader_cleanup_required')


def watchdog(function, args, seconds):
    """No source FD is opened by the parent. Bounded nonblocking socket IPC."""
    if seconds <= 0:
        return {'status': 'incomplete', 'reason': 'total_deadline'}
    deadline = time.monotonic() + seconds
    parent, child = socket.socketpair()
    pid = None
    # Cover the tiny fork-return/ownership-assignment window too. Pending
    # cancellation is delivered only after the parent enters its finally scope.
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
    try:
        pid = os.fork()
        if pid == 0:
            parent.close()
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
                try:
                    value = function(*args)
                except Gap as error:
                    status = str(error)
                    value = {'status': status if status in STATUSES else 'unreadable_or_changed'}
                except BaseException:
                    value = {'status': 'unreadable_or_changed'}
                child.sendall(json.dumps(value, ensure_ascii=True).encode('ascii'))
            except BaseException:
                pass
            finally:
                child.close()
                os._exit(0)
        child.close()
        parent.setblocking(False)
        data = bytearray()
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {'status': 'timeout'}
            if not select.select([parent], [], [], remaining)[0]:
                return {'status': 'timeout'}
            block = parent.recv(65536)
            if not block:
                break
            data.extend(block)
            # ensure_ascii can expand UTF-8 text up to six times its size.
            if len(data) > 6 * TEXT_LIMIT + 65536:
                raise Gap('reader_response_oversize')
        try:
            return json.loads(data)
        except (ValueError, UnicodeError):
            return {'status': 'unreadable_or_changed'}
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
        try:
            parent.close()
            child.close()
            if pid is not None:
                reap(pid)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def collect(root):
    return _collect(root, time.monotonic() + TOTAL_SECONDS)


def _collect(root, deadline):
    fixed, text_left, hash_left = [], TEXT_TOTAL, HASH_TOTAL
    for identity, path, kind in MANIFEST:
        remaining = text_left if kind == 'text' else hash_left
        record = watchdog(child_file, (root, path, kind, remaining),
                          min(60 if kind == 'binary' else 10, deadline - time.monotonic() - 1))
        consumed = record.pop('_consumed', record.get('length', 0))
        if record['status'] == 'timeout':
            # Reader progress is unknown after kill: conservatively charge its
            # full allowed allocation, never recycle an uncertain byte budget.
            consumed = min(remaining, 384 * MIB if kind == 'binary' else TEXT_LIMIT)
        fixed.append(dict(id=identity, **record))
        if kind == 'text':
            text_left -= consumed
        else:
            hash_left -= consumed
    enumeration = watchdog(child_entries, (root,), min(10, deadline - time.monotonic() - 1))
    include = {'status': enumeration['status'], 'entries_seen': enumeration.get('entries_seen', 0),
               'selected_count': None, 'records': []}
    if enumeration['status'] == 'captured':
        include['selected_count'] = len(enumeration['names'])
        for name in enumeration['names']:
            record = watchdog(child_file, (root, INCLUDE + '/' + name, 'text', text_left),
                              min(10, deadline - time.monotonic() - 1))
            consumed = record.pop('_consumed', record.get('length', 0))
            if record['status'] == 'timeout':
                consumed = min(text_left, TEXT_LIMIT)
            include['records'].append(dict(basename=name, **record))
            text_left -= consumed
    complete = (all(r['status'] == 'captured' for r in fixed) and
                include['status'] == 'captured' and
                all(r['status'] == 'captured' for r in include['records']))
    return {'schema_version': 1, 'profile': PROFILE, 'private_review_required': True,
            'fixed_records': fixed, 'include': include, 'collection_complete': complete}


def child_boundary(root, parent):
    resolved = Path(root).resolve(strict=True)
    if parent == resolved or resolved in parent.parents:
        return {'status': 'invalid'}
    return {'status': 'captured'}


def write_private(root, output):
    deadline = time.monotonic() + TOTAL_SECONDS
    root, output = Path(root).absolute(), Path(output).absolute()
    parent = output.parent.resolve(strict=True)
    info = parent.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Gap('private_parent_required')
    boundary = watchdog(child_boundary, (root, parent), min(10, deadline - time.monotonic() - 1))
    if boundary['status'] != 'captured':
        raise Gap('output_boundary_refused')
    report = _collect(root, deadline)
    data = (json.dumps(report, ensure_ascii=True, sort_keys=True) + '\n').encode('ascii')
    if len(data) > REPORT_LIMIT or len(report['fixed_records']) + 1 + len(report['include']['records']) > RECORD_LIMIT:
        raise Gap('report_oversize')
    fd = os.open(parent / output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
    except BaseException:
        os.unlink(parent / output.name)
        raise
    records = report['fixed_records'] + report['include']['records'] + [report['include']]
    return {'records': len(records), 'statuses': dict(Counter(r['status'] for r in records)),
            'private_report_sha256': hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--private-output', required=True)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        print(json.dumps(write_private(args.root, args.private_output), sort_keys=True))
    except (Gap, OSError, ValueError, KeyboardInterrupt):
        parser.exit(1, 'Host collection refused; no source content is printed.\n')


if __name__ == '__main__':
    main()
