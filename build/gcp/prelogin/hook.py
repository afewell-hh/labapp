#!/usr/bin/python3 -B
"""Fixed root hook, Python 3.10+ stdlib; not enabled."""
import hashlib
import http.client
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import time
import uuid

PACKAGES = ('cloud-init', 'google-guest-agent', 'gce-compute-image-packages',
            'google-compute-engine-oslogin', 'google-osconfig-agent',
            'openssh-server', 'systemd', 'dbus', 'rsyslog')
PATHS = {
    'startup-unit': '/usr/lib/systemd/system/google-startup-scripts.service',
    'agent-unit': '/usr/lib/systemd/system/google-guest-agent.service',
    'cache-unit': '/usr/lib/systemd/system/google-oslogin-cache.service',
    'cache-timer': '/usr/lib/systemd/system/google-oslogin-cache.timer',
    'ssh-unit': '/usr/lib/systemd/system/ssh.service',
    'cloud-final-unit': '/usr/lib/systemd/system/cloud-final.service',
    'agent-config': '/etc/default/instance_configs.cfg',
    'cache': '/etc/oslogin_passwd.cache',
    'cache-temp': '/etc/oslogin_passwd.cache.tmp',
    'group-cache': '/etc/oslogin_group.cache',
    'pam': '/etc/pam.d/sshd', 'nss': '/etc/nsswitch.conf',
    'clean-directory': '/etc/cloud/clean.d',
}
GROUPS = (tuple(k for k in PATHS if k.endswith(('unit', 'timer'))),
          ('agent-config', 'pam', 'nss', 'clean-directory'), ('cache', 'cache-temp', 'group-cache'))
MODE = 'inventory-only'
SUPPORTED_MANIFESTS = {}
META = '/computeMetadata/v1/'
BIND = ('lease', 'epoch', 'run', 'attempt', 'nonce', 'vm_id', 'boot_id',
        'profile_sha256', 'hook_sha256')
HEX = r'[0-9a-f]{64}'


class Refused(ValueError):
    pass


class Missing(Refused):
    pass


class Limit(Refused):
    pass


def require(ok):
    if not ok:
        raise Refused('pre-login evidence refused')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out)
        out[key] = value
    return out


def decode(raw, limit):
    require(type(raw) is bytes and 0 < len(raw) <= limit)
    try:
        return json.loads(raw.decode('ascii'), object_pairs_hook=unique,
                          parse_constant=lambda _: require(False))
    except (ValueError, UnicodeError, RecursionError):
        raise Refused('pre-login JSON refused') from None


def integer(n, low=1, high=2**63-1):
    require(type(n) is int and low <= n <= high)


def identity(value):
    require(type(value) is dict and set(value) == set(BIND))
    for key in ('lease', 'boot_id'):
        require(type(value[key]) is str)
        try:
            require(str(uuid.UUID(value[key])) == value[key] and int(uuid.UUID(value[key])) != 0)
        except ValueError:
            require(False)
    for key in ('nonce', 'profile_sha256', 'hook_sha256'):
        require(type(value[key]) is str and re.fullmatch(HEX, value[key]))
    for key in ('epoch', 'run', 'attempt'):
        integer(value[key])
    require(type(value['vm_id']) is str and re.fullmatch(r'[1-9][0-9]{0,19}', value['vm_id']))


def metadata(raw, now):
    obj = decode(raw, 2048)
    keys = {'schema', 'lease', 'epoch', 'run', 'attempt', 'nonce', 'profile_sha256',
            'deadline', 'source_name', 'source_id', 'username', 'uid', 'gid', 'home'}
    require(type(obj) is dict and set(obj) == keys and obj['schema'] == 'labapp-baseline-v1')
    for key in ('epoch', 'run', 'attempt', 'deadline', 'uid', 'gid'):
        integer(obj[key])
    require(type(obj['username']) is str and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', obj['username']))
    require(obj['home'] == '/home/' + obj['username'])
    require(type(obj['source_name']) is str and re.fullmatch(r'ubuntu-[a-z0-9-]{1,100}', obj['source_name']))
    require(type(obj['source_id']) is str and re.fullmatch(r'[1-9][0-9]{0,19}', obj['source_id']))
    require(now < obj['deadline'] <= now + 7200)
    identity({**{k: obj[k] for k in BIND if k in obj}, 'vm_id': '1',
              'boot_id': obj['lease'], 'hook_sha256': '0'*64})
    return obj


class Files:
    def __init__(self, root='/'):
        self.root = root
        self.uid = 0

    def parent(self, path):
        require(path.startswith('/') and all(p not in ('', '.', '..') for p in path[1:].split('/')))
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            dev = os.fstat(fd).st_dev
            for index, part in enumerate(path[1:].split('/')[:-1]):
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = nxt
                info = os.fstat(fd)
                require((info.st_dev == dev or index == 0 and part in ('run', 'proc')) and info.st_uid == self.uid and not info.st_mode & 0o022)
                dev = info.st_dev
            return fd, path.rsplit('/', 1)[1]
        except BaseException:
            os.close(fd)
            raise

    def read_file(self, fd, name, limit):
        """Read a stable owned regular file relative to an already checked FD."""
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(child)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_uid == self.uid and not before.st_mode & 0o022
                    and before.st_dev == os.fstat(fd).st_dev)
            data = os.read(child, limit + 1)
            after = os.fstat(child)
            if len(data) > limit:
                raise Limit('bounded file exceeded')
            require(before[:7] == after[:7] and before.st_mtime_ns == after.st_mtime_ns
                    and before.st_ctime_ns == after.st_ctime_ns)
            current = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(after[:7] == current[:7] and after.st_mtime_ns == current.st_mtime_ns
                    and after.st_ctime_ns == current.st_ctime_ns)
            return data
        finally:
            os.close(child)

    def read(self, path, limit):
        fd, name = self.parent(path)
        try:
            return self.read_file(fd, name, limit)
        finally:
            os.close(fd)

    def source(self, path):
        """Only the default runner's root-owned private directory in sticky /tmp.

        This exception is exclusive to self-source hashing. Snapshot/data walks
        retain their strict non-writable-ancestor policy. No source path comes
        from metadata or arguments; production passes this module's __file__.
        """
        match = re.fullmatch(r'/tmp/(metadata-scripts[A-Za-z0-9_-]{1,64})/startup-script', path)
        require(match is not None)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        root = os.open(self.root, flags)
        try:
            info = os.fstat(root)
            require(info.st_uid == self.uid and not info.st_mode & 0o022)
            temporary = os.open('tmp', flags, dir_fd=root)
            try:
                info = os.fstat(temporary)
                require(info.st_uid == self.uid and stat.S_IMODE(info.st_mode) == 0o1777)
                directory = os.open(match[1], flags, dir_fd=temporary)
                try:
                    private = os.fstat(directory)
                    require(private.st_uid == self.uid and stat.S_IMODE(private.st_mode) == 0o700
                            and private.st_dev == info.st_dev)
                    return self.read_file(directory, 'startup-script', 32768)
                finally:
                    os.close(directory)
            finally:
                os.close(temporary)
        finally:
            os.close(root)

    def fact(self, path, content=True):
        try:
            fd, name = self.parent(path)
        except FileNotFoundError:
            return {'type': 'absent'}
        try:
            try:
                s = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return {'type': 'absent'}
            require(s.st_dev == os.fstat(fd).st_dev and (not stat.S_ISREG(s.st_mode) or s.st_nlink == 1))
            kind = 'file' if stat.S_ISREG(s.st_mode) else 'directory' if stat.S_ISDIR(s.st_mode) else 'unsupported'
            require(kind != 'unsupported')
            out = {'type': kind, 'uid': s.st_uid, 'gid': s.st_gid,
                  'mode': stat.S_IMODE(s.st_mode), 'inode': s.st_ino}
            if content and kind == 'file':
                out['sha256'] = digest(self.read(path, 65536))
                after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(s[:7] == after[:7] and s.st_mtime_ns == after.st_mtime_ns
                        and s.st_ctime_ns == after.st_ctime_ns)
            return out
        finally:
            os.close(fd)

    def hooks(self):
        fd, name = self.parent('/etc/cloud/clean.d')
        try:
            try:
                directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                return []
            try:
                names = []
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if len(names) == 32:
                            raise Limit('clean-hook inventory limit')
                        names.append(entry.name)
                require(all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', n) for n in names))
                return sorted(names)
            finally:
                os.close(directory)
        finally:
            os.close(fd)

    def snapshot(self, lease, data, persistent=False):
        require(len(data) <= 65536)
        prefix = '/var/lib/' if persistent else '/run/'
        fd, name = self.parent(prefix + 'labapp-prelogin-' + lease)
        try:
            os.mkdir(name, 0o700, dir_fd=fd)
            directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                s = os.fstat(directory)
                require(s.st_uid == self.uid and stat.S_IMODE(s.st_mode) == 0o700)
                out = os.open('baseline.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=directory)
                try:
                    require(os.write(out, data) == len(data))
                    os.fsync(out)
                finally:
                    os.close(out)
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            os.close(fd)
        require(self.read(prefix + 'labapp-prelogin-' + lease + '/baseline.json', 65536) == data)


class Runtime:
    def __init__(self):
        self.start = time.monotonic()
        self.end = self.start + 210
        self.last_put = self.start - 1

    def check(self):
        require(time.monotonic() < self.end)

    def request(self, method, key, body=None):
        allowed = {'instance/attributes/labapp-baseline-v1', 'instance/attributes/labapp-stage', 'instance/id', 'instance/name'}
        allowed |= {'instance/guest-attributes/labapp-prelogin/' + k for k in
                    ('result', 'inventory', 'inventory-0', 'inventory-1', 'inventory-2', 'inventory-3')}
        require(key in allowed and method in ('GET', 'PUT'))
        require((method == 'PUT') == key.startswith('instance/guest-attributes/'))
        require((method == 'GET') == (body is None))
        self.check()
        if method == 'PUT':
            pause = max(0, 1 - (time.monotonic() - self.last_put))
            require(time.monotonic() + pause < self.end)
            time.sleep(pause)
            self.check()
            self.last_put = time.monotonic()
        # Standalone Linux main-thread hook: SIGALRM interrupts connect,
        # header parsing and buffered body reads under one absolute deadline.
        # Per-socket timeouts alone restart on trickled input. There is no
        # background worker to survive a refused request.
        deadline = min(self.end, time.monotonic() + 5)
        require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0))
        previous = signal.getsignal(signal.SIGALRM)
        def expired(signum, frame):
            raise Refused('metadata request deadline exceeded')
        signal.signal(signal.SIGALRM, expired)
        connection, response = None, None
        try:
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            signal.setitimer(signal.ITIMER_REAL, remaining)
            connection = http.client.HTTPConnection('169.254.169.254', timeout=remaining)
            connection.request(method, META + key, body, {'Metadata-Flavor': 'Google'})
            response = connection.getresponse()
            data = response.read(4097)
            require(response.status == 200 and response.getheader('Metadata-Flavor') == 'Google'
                    and len(data) <= 4096 and time.monotonic() < deadline)
            self.check()
            return data
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            try:
                if response is not None:
                    response.close()
            finally:
                try:
                    if connection is not None:
                        connection.close()
                finally:
                    signal.signal(signal.SIGALRM, previous)

    def command(self, argv, timeout, limit=65536):
        self.check()
        timeout = min(timeout, self.end-time.monotonic())
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                                              'PYTHONDONTWRITEBYTECODE': '1'})
        try:
            result = bytearray()
            until = time.monotonic() + timeout
            with selectors.DefaultSelector() as poll:
                poll.register(proc.stdout, selectors.EVENT_READ)
                while True:
                    remaining = until-time.monotonic()
                    require(remaining > 0)
                    require(poll.select(remaining))
                    chunk = os.read(proc.stdout.fileno(), min(4096, limit+1-len(result)))
                    if not chunk:
                        break
                    result.extend(chunk)
                    require(len(result) <= limit)
            code = proc.wait(timeout=max(.001, until-time.monotonic()))
            if code == 1 and argv[:2] in (['/usr/bin/dpkg-query', '-W'], ['/usr/bin/dpkg-query', '-S']):
                raise Missing('package absent')
            require(code == 0)
            self.check()
            return bytes(result)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            proc.stdout.close()


def package(runtime, name):
    try:
        raw = runtime.command(['/usr/bin/dpkg-query', '-W', '-f=${db:Status-Status}\t${Version}\t${Architecture}', name], 2, 512)
    except Missing:
        return {'name': name, 'status': 'missing'}
    fields = raw.decode('ascii').split('\t')
    require(len(fields) == 3 and fields[0] == 'installed')
    require(all(re.fullmatch(r'[A-Za-z0-9.+:~_-]{1,128}', v) for v in fields[1:]))
    return {'name': name, 'status': 'installed', 'version': fields[1], 'architecture': fields[2]}


def owner(runtime, path):
    try:
        raw = runtime.command(['/usr/bin/dpkg-query', '-S', path], 2, 512).decode('ascii')
    except Missing:
        return {'status': 'unknown'}
    match = re.fullmatch(r'([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?): ' + re.escape(path) + r'\n?', raw)
    return package(runtime, match[1]) if match else {'status': 'unknown'}


def wait_cloud(runtime):
    output = runtime.command(['/usr/bin/systemctl', 'show', 'google-startup-scripts.service',
                              'cloud-final.service', '-p', 'Id,After,Before,ActiveState'], 5, 8192).decode('ascii')
    sections = output.strip().split('\n\n')
    require(len(sections) == 2)
    units = {}
    for section in sections:
        fields = {}
        for line in section.splitlines():
            key, sep, value = line.partition('=')
            require(sep and key in ('Id', 'After', 'Before', 'ActiveState') and key not in fields)
            fields[key] = value
        require(set(fields) == {'Id', 'After', 'Before', 'ActiveState'})
        require(fields['Id'] not in units)
        units[fields['Id']] = fields
    require(set(units) == {'google-startup-scripts.service', 'cloud-final.service'})
    startup, final = units['google-startup-scripts.service'], units['cloud-final.service']
    require('cloud-final.service' not in startup['Before'].split())
    require('google-startup-scripts.service' not in final['After'].split())
    require(final['ActiveState'] != 'activating')
    raw = runtime.command(['/usr/bin/cloud-init', 'status', '--wait', '--format=json'], 180, 8192)
    status = decode(raw, 8192)
    require(type(status) is dict and status.get('status') == 'done' and not status.get('errors'))


def run(files, runtime, *, manifests=None, hook_bytes=None, now=None, mode=None):
    mode = MODE if mode is None else mode
    require(mode in ('inventory-only', 'baseline'))
    require(os.geteuid() == 0 or files.root != '/')
    require(runtime.request('GET', 'instance/attributes/labapp-stage') == b'base-prelogin-v1')
    raw = runtime.request('GET', 'instance/attributes/labapp-baseline-v1')
    obj = metadata(raw, time.time() if now is None else now)
    runtime.end = min(runtime.end, runtime.start + obj['deadline'] - (time.time() if now is None else now))
    vm = runtime.request('GET', 'instance/id').decode('ascii')
    name = runtime.request('GET', 'instance/name').decode('ascii')
    require(name == 'labapp-build-r' + str(obj['run']) + '-a' + str(obj['attempt']))
    boot = files.read('/proc/sys/kernel/random/boot_id', 64).decode('ascii').strip()
    hook_bytes = files.source(os.path.abspath(__file__)) if hook_bytes is None else hook_bytes
    binding = {**{k: obj[k] for k in BIND if k in obj}, 'vm_id': vm,
              'boot_id': boot, 'hook_sha256': digest(hook_bytes)}
    identity(binding)
    reservation = canonical({'schema': 'prelogin-reservation-v1', **binding})
    files.snapshot(obj['lease'], reservation, persistent=True)
    files.snapshot(obj['lease'], reservation)
    wait_cloud(runtime)
    runtime.end = min(runtime.end, time.monotonic() + 20)
    packages = [package(runtime, p) for p in PACKAGES]
    records = []
    inventory_status = 'complete' if all(p['status'] == 'installed' for p in packages) else 'missing-packages'
    for key, path in PATHS.items():
        try:
            fact = files.fact(path)
        except (OSError, Refused) as exc:
            inventory_status = 'limit' if isinstance(exc, Limit) else 'incomplete'
            fact = {'type': 'unsupported'}
        records.append({'id': key, **fact, 'owner': owner(runtime, path) if fact['type'] not in ('absent', 'unsupported') else {'status': 'unknown'}})
    hooks = []
    try:
        names = files.hooks()
    except (OSError, Refused) as exc:
        inventory_status = 'limit' if isinstance(exc, Limit) else 'incomplete'
        names = []
    for name in names:
        path = '/etc/cloud/clean.d/' + name
        try:
            value = files.fact(path)
        except (OSError, Refused) as exc:
            inventory_status = 'limit' if isinstance(exc, Limit) else 'incomplete'
            value = {'type': 'unsupported'}
        hooks.append({'id': name, **value, 'owner': owner(runtime, path) if value['type'] not in ('absent', 'unsupported') else {'status': 'unknown'}})
    groups = [[r for r in records if r['id'] in group] for group in GROUPS] + [hooks]
    for i, group in enumerate(groups):
        if len(canonical(group)) > 3000:
            groups[i], inventory_status = [], 'limit'
    layout = digest(canonical({'packages': packages, 'groups': groups}))
    collisions = {}
    for source, number in (('passwd', 'uid'), ('group', 'gid')):
        lines = files.read('/etc/' + source, 65536).decode('ascii').splitlines()
        collision = False
        for line in lines:
            fields = line.split(':')
            require(len(fields) == (7 if source == 'passwd' else 4) and fields[2].isdigit())
            collision |= fields[0] == obj['username'] or int(fields[2]) == obj[number]
        collisions[source] = collision
    collisions['home'] = files.fact(obj['home'], False)['type'] != 'absent'
    for key in ('google_authorized_keys', '.google_authenticator'):
        collisions[key] = files.fact(obj['home'] + '/' + key, False)['type'] != 'absent'
    supported = (SUPPORTED_MANIFESTS if manifests is None else manifests).get(layout)
    ready = (mode == 'baseline' and supported == {'reviewed': True} and not any(collisions.values())
            and inventory_status == 'complete')
    baseline = canonical({'schema': 'prelogin-baseline-v1', **binding, 'source_name': obj['source_name'],
                          'source_id': obj['source_id'], 'layout_sha256': layout,
                          'packages': packages, 'groups': groups, 'collisions': collisions})
    require(len(baseline) <= 65536)
    path = '/run/labapp-prelogin-' + obj['lease'] + '/evidence.json'
    fd, leaf = files.parent(path)
    try:
        out = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            require(os.write(out, baseline) == len(baseline))
            os.fsync(out)
        finally:
            os.close(out)
    finally:
        os.close(fd)
    require(files.read(path, 65536) == baseline)
    parts = [canonical({'schema': 'prelogin-part-v1', **binding, 'index': i, 'records': group})
            for i, group in enumerate(groups)]
    require(all(len(p) <= 4096 for p in parts) and sum(map(len, parts)) <= 16384)
    summary = {'schema': 'prelogin-receipt-v1', **binding, 'result': 'ready' if ready else 'inventory-only',
              'inventory_status': inventory_status,
              'agent_generation': 'unknown', 'packages': packages, 'layout_sha256': layout,
              'baseline_sha256': digest(baseline), 'collisions': collisions,
              'unit_inventory_sha256': digest(canonical(groups[0])),
              'agent_config_layout_sha256': digest(canonical(groups[1])),
              'cache_layout_sha256': digest(canonical(groups[2])),
              'clean_hook_inventory_sha256': digest(canonical(groups[3])),
              'parts': [{'length': len(p), 'sha256': digest(p)} for p in parts]}
    payload = canonical(summary)
    require(len(payload) <= 4096)
    for i, part in enumerate(parts):
        runtime.request('PUT', 'instance/guest-attributes/labapp-prelogin/inventory-' + str(i), part)
    runtime.check()
    require(files.read(path, 65536) == baseline)
    require(files.read('/proc/sys/kernel/random/boot_id', 64).decode('ascii').strip() == boot)
    runtime.request('PUT', 'instance/guest-attributes/labapp-prelogin/' + ('result' if ready else 'inventory'), payload)
    return summary


if __name__ == '__main__':
    try:
        require(len(__import__('sys').argv) == 1)
        run(Files(), Runtime())
    except FileExistsError:
        raise SystemExit('pre-login refused: existing_reservation') from None
    except Exception:
        raise SystemExit('pre-login hook refused') from None
