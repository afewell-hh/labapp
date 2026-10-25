"""Offline same-code tests: only owned temp files and injected guest transports."""
import os
import signal
import socket
import threading
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from . import hook as h, receipt

LEASE = '11111111-1111-4111-8111-111111111111'
BOOT = '22222222-2222-4222-8222-222222222222'


def request():
    return {'schema': 'labapp-baseline-v1', 'lease': LEASE, 'epoch': 1,
            'run': 123, 'attempt': 1, 'nonce': 'a'*64, 'profile_sha256': 'b'*64,
            'deadline': 1000, 'source_name': 'ubuntu-2404-test', 'source_id': '123',
            'username': 'tester', 'uid': 1001, 'gid': 1001, 'home': '/home/tester'}


class Guest(h.Runtime):
    def __init__(self):
        super().__init__()
        self.input = h.canonical(request())
        self.puts = {}
        self.commands = []
        self.fail = None
        self.cycle = False
        self.missing = False
        self.cloud = 'done'

    def request(self, method, key, body=None):
        self.check()
        if method == 'GET':
            return {'instance/attributes/labapp-stage': b'base-prelogin-v1',
                    'instance/attributes/labapp-baseline-v1': self.input,
                    'instance/id': b'12345', 'instance/name': b'labapp-build-r123-a1'}[key]
        if key.endswith(self.fail or 'impossible'):
            raise h.Refused('injected lost response')
        self.puts[key.rsplit('/', 1)[1]] = body
        return b''

    def command(self, argv, timeout, limit=65536):
        self.commands.append((argv, timeout, limit))
        if self.fail == 'command':
            raise h.Refused('injected timeout')
        if argv[0] == '/usr/bin/systemctl':
            return ('Id=google-startup-scripts.service\nAfter=network.target\nBefore=' +
                    ('cloud-final.service' if self.cycle else '') + '\nActiveState=active\n\n'
                    'Id=cloud-final.service\nAfter=cloud-config.service\nBefore=\nActiveState=inactive\n').encode()
        if argv[0] == '/usr/bin/cloud-init':
            return h.canonical({'status': self.cloud})
        if argv[1] == '-S':
            return ('cloud-init: ' + argv[2] + '\n').encode()
        if self.missing:
            raise h.Missing('missing package')
        return b'installed\t1.0-test\tamd64'


class HookTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for p in ('run', 'var/lib', 'home', 'proc/sys/kernel/random', 'etc/cloud/clean.d',
                  'usr/lib/systemd/system', 'etc/default', 'etc/pam.d'):
            (self.root / p).mkdir(parents=True, exist_ok=True)
        self.write('proc/sys/kernel/random/boot_id', BOOT + '\n')
        self.write('etc/passwd', 'root:x:0:0:root:/root:/bin/bash\n')
        self.write('etc/group', 'root:x:0:\n')
        for path in h.PATHS.values():
            if path != '/etc/cloud/clean.d':
                self.write(path[1:], 'synthetic fixture only\n')
        for directory in self.root.rglob('*'):
            if directory.is_dir():
                directory.chmod(0o755)
        self.files = h.Files(str(self.root))
        self.files.uid = os.getuid()
        self.guest = Guest()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        target.chmod(0o644)

    def run_hook(self, **kwargs):
        return h.run(self.files, self.guest, hook_bytes=b'synthetic hook', now=900, **kwargs)

    def parse(self, result, **kwargs):
        key = 'result' if result['result'] == 'ready' else 'inventory'
        return receipt.parse(self.guest.puts[key], [self.guest.puts['inventory-' + str(i)] for i in range(4)],
                             {k: result[k] for k in h.BIND}, **kwargs)

    def test_inventory_and_exclusive_root_snapshot(self):
        result = self.run_hook()
        self.assertEqual(result['result'], 'inventory-only')
        self.assertEqual(self.parse(result), result)
        self.assertEqual(len(self.guest.puts), 5)
        self.assertTrue(all(len(v) <= 4096 for v in self.guest.puts.values()))
        path = self.root / 'run' / ('labapp-prelogin-' + LEASE)
        self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        self.assertEqual((path/'evidence.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(h.digest((path/'evidence.json').read_bytes()), result['baseline_sha256'])
        before = (path/'evidence.json').read_bytes()
        self.guest.puts.clear()
        with self.assertRaises(FileExistsError):
            self.run_hook()
        self.assertFalse(self.guest.puts)
        self.assertEqual((path/'evidence.json').read_bytes(), before)

    def test_synthetic_manifest_ready_and_import_barrier_contract(self):
        # Discover synthetic digest in one owned tree, then a separate fresh run.
        inventory = self.run_hook()
        self.assertRaises(h.Refused, self.parse, inventory, ready=True,
                          reviewed_layouts=(inventory['layout_sha256'],))
        self.tearDown()
        self.setUp()
        # Inodes are part of exact installed facts, so compute digest through real
        # collection in this tree using a manifest map that records its lookup.
        class Reviewed(dict):
            def get(inner, key):
                inner['layout'] = key
                return {'reviewed': True}
        manifest = Reviewed()
        result = self.run_hook(manifests=manifest, mode='baseline')
        self.assertEqual(result['result'], 'ready')
        self.parse(result, ready=True, reviewed_layouts=(manifest['layout'],))
        self.assertRaises(h.Refused, self.parse, result, ready=True)

    def test_collision_never_ready(self):
        self.write('etc/passwd', 'tester:x:1001:1001:User:/home/tester:/bin/sh\n')
        class All(dict):
            def get(self, _):
                return {'reviewed': True}
        result = self.run_hook(manifests=All(), mode='baseline')
        self.assertTrue(result['collisions']['passwd'])
        self.assertEqual(result['result'], 'inventory-only')

    def test_cycle_cloud_failure_timeout_and_loss(self):
        for failure in ('cycle', 'cloud', 'command', 'inventory-2', 'inventory'):
            with self.subTest(failure=failure):
                self.tearDown()
                self.setUp()
                self.guest.cycle = failure == 'cycle'
                self.guest.cloud = 'error' if failure == 'cloud' else 'done'
                self.guest.fail = failure
                with self.assertRaises(h.Refused):
                    self.run_hook()
                self.assertNotIn('result', self.guest.puts)
                self.assertNotIn('inventory', self.guest.puts)
                self.assertTrue((self.root/'run'/('labapp-prelogin-'+LEASE)).exists())

    def test_missing_package_inventory_only(self):
        self.guest.missing = True
        result = self.run_hook()
        self.assertEqual(result['inventory_status'], 'missing-packages')
        self.parse(result)

    def test_no_follow_hardlink_and_mount_checks(self):
        for kind in ('symlink', 'hardlink', 'mount'):
            with self.subTest(kind=kind):
                self.tearDown()
                self.setUp()
                target = self.root/'etc/nsswitch.conf'
                if kind == 'symlink':
                    target.unlink()
                    target.symlink_to(self.root/'etc/passwd')
                elif kind == 'hardlink':
                    os.link(target, self.root/'etc/another')
                if kind == 'mount':
                    real = os.stat
                    def mounted(path, *args, **kwargs):
                        s = real(path, *args, **kwargs)
                        if path == 'nsswitch.conf':
                            values = list(s)
                            values[2] += 1
                            return os.stat_result(values)
                        return s
                    with patch.object(h.os, 'stat', mounted):
                        result = self.run_hook()
                else:
                    result = self.run_hook()
                self.assertEqual(result['inventory_status'], 'incomplete')
                self.assertEqual(result['result'], 'inventory-only')
                self.parse(result)

    def test_interrupted_snapshot_rerun_refuses(self):
        with patch.object(h.os, 'write', return_value=0), self.assertRaises(h.Refused):
            self.run_hook()
        self.assertFalse(self.guest.puts)
        self.assertRaises(FileExistsError, self.run_hook)

    def test_reboot_after_parts_suppresses_summary(self):
        original = self.guest.request
        def reboot(method, key, body=None):
            result = original(method, key, body)
            if key.endswith('inventory-3'):
                self.write('proc/sys/kernel/random/boot_id', LEASE+'\n')
            return result
        self.guest.request = reboot
        self.assertRaises(h.Refused, self.run_hook)
        self.assertNotIn('inventory', self.guest.puts)

    def test_strict_parts_and_binding(self):
        result = self.run_hook()
        raw = self.guest.puts['inventory']
        parts = [self.guest.puts['inventory-'+str(i)] for i in range(4)]
        expected = {k: result[k] for k in h.BIND}
        for key in ('nonce', 'lease', 'boot_id', 'vm_id', 'epoch'):
            changed = dict(expected)
            changed[key] = {'epoch': 2, 'vm_id': '999'}.get(key, LEASE if key == 'boot_id' else BOOT if key == 'lease' else 'c'*64)
            self.assertRaises(h.Refused, receipt.parse, raw, parts, changed)
        for bad in (parts[:3], parts+[parts[0]], [parts[1], parts[0], *parts[2:]], [b' '*4097, *parts[1:]]):
            self.assertRaises(h.Refused, receipt.parse, raw, bad, expected)
        duplicate = raw[:-1] + b',"result":"inventory-only"}'
        for bad in (duplicate, b' '*4097, raw.replace(b'"epoch":1', b'"epoch":true')):
            self.assertRaises(h.Refused, receipt.parse, bad, parts, expected)
        self.assertRaises(h.Refused, receipt.attribute, b'[]', 'inventory')
        attr = h.canonical([{'namespace': 'labapp-prelogin', 'key': 'inventory', 'value': raw.decode()}])
        self.assertEqual(receipt.attribute(attr, 'inventory'), raw)

    def test_fixed_argv_and_command_transport_bounds(self):
        self.run_hook()
        self.assertIn((['/usr/bin/cloud-init', 'status', '--wait', '--format=json'], 180, 8192), self.guest.commands)
        self.assertTrue(all(c[0][0] in ('/usr/bin/dpkg-query', '/usr/bin/systemctl', '/usr/bin/cloud-init') for c in self.guest.commands))
        runtime = h.Runtime()
        for argv, timeout, limit in ((['/usr/bin/python3', '-B', '-c', 'print("x"*100)'], 2, 10),
                                     (['/usr/bin/python3', '-B', '-c', 'raise SystemExit(2)'], 2, 10),
                                     (['/usr/bin/python3', '-B', '-c', 'import time;time.sleep(1)'], .01, 10)):
            self.assertRaises(h.Refused, runtime.command, argv, timeout, limit)
        self.assertEqual(runtime.command(['/usr/bin/python3', '-B', '-c', 'print(1)'], 2, 10), b'1\n')

    def test_reboot_rerun_and_existing_reservation_symlink(self):
        self.run_hook()
        import shutil
        shutil.rmtree(self.root/'run'/('labapp-prelogin-'+LEASE))
        self.write('proc/sys/kernel/random/boot_id', LEASE+'\n')
        self.guest.puts.clear()
        self.assertRaises(FileExistsError, self.run_hook)
        self.assertFalse(self.guest.puts)

    def test_hook_limit_and_file_limit_are_typed(self):
        for kind in ('hooks', 'file', 'part'):
            with self.subTest(kind=kind):
                self.tearDown()
                self.setUp()
                if kind == 'hooks':
                    for i in range(33):
                        self.write('etc/cloud/clean.d/hook-'+str(i), 'never executed')
                elif kind == 'file':
                    self.write('etc/nsswitch.conf', 'x'*65537)
                else:
                    for i in range(20):
                        self.write('etc/cloud/clean.d/hook-'+str(i), 'never executed')
                result = self.run_hook()
                self.assertEqual(result['inventory_status'], 'limit')
                self.assertEqual(result['result'], 'inventory-only')
                self.parse(result)

    def test_collision_home_and_group_and_hook_symlink(self):
        self.write('etc/group', 'other:x:1001:\n')
        (self.root/'home/tester').symlink_to(self.root/'etc')
        self.assertRaises(h.Refused, self.run_hook)
        self.assertFalse(self.guest.puts)

    def test_source_bound_and_no_real_manifest(self):
        self.assertLessEqual(Path(h.__file__).stat().st_size, 32*1024)
        self.assertEqual(h.SUPPORTED_MANIFESTS, {})
        self.assertEqual(h.MODE, 'inventory-only')

    def test_fixed_http_transport_and_failure_bounds(self):
        calls = []
        class Response:
            status = 200
            payload = b'123'
            flavor = 'Google'
            def read(self, bound):
                calls.append(('read', bound))
                return self.payload
            def getheader(self, key):
                return self.flavor
            def close(self):
                calls.append('response closed')
        class Connection:
            response = Response()
            def __init__(self, host, timeout):
                calls.append((host, timeout))
            def request(self, method, path, body, headers):
                calls.append((method, path, body, headers))
            def getresponse(self):
                return self.response
            def close(self):
                calls.append('closed')
        runtime = h.Runtime()
        with patch.object(h.http.client, 'HTTPConnection', Connection), patch.object(h.time, 'sleep'):
            self.assertEqual(runtime.request('GET', 'instance/id'), b'123')
            self.assertIn(('GET', '/computeMetadata/v1/instance/id', None,
                           {'Metadata-Flavor': 'Google'}), calls)
            for key in ('http://example.com', 'instance/service-accounts/default/token',
                        'instance/attributes/startup-script-url'):
                self.assertRaises(h.Refused, runtime.request, 'GET', key)
            self.assertRaises(h.Refused, runtime.request, 'PUT', 'instance/id', b'x')
            for status, payload, flavor in ((302, b'', 'Google'), (200, b'x'*4097, 'Google'),
                                            (200, b'', None)):
                Connection.response.status = status
                Connection.response.payload = payload
                Connection.response.flavor = flavor
                self.assertRaises(h.Refused, runtime.request, 'GET', 'instance/id')
            runtime.end = time.monotonic() - 1
            self.assertRaises(h.Refused, runtime.request, 'GET', 'instance/id')
        self.assertEqual(calls.count('closed'), 4)

    def test_actual_default_runner_source_without_hook_bytes_injection(self):
        source = Path(h.__file__).read_bytes()
        path = '/tmp/metadata-scripts1234567890/startup-script'
        self.write(path[1:], source.decode())
        (self.root/'tmp').chmod(0o1777)
        (self.root/'tmp/metadata-scripts1234567890').chmod(0o700)
        (self.root/path[1:]).chmod(0o755)
        with patch.object(h, '__file__', path):
            result = h.run(self.files, self.guest, now=900)
        self.assertEqual(result['hook_sha256'], h.digest(source))
        self.assertEqual(result['result'], 'inventory-only')
        self.parse(result)
        # This special source read never broadens ordinary data path access.
        self.assertRaises(h.Refused, self.files.read, path, 32768)

    def test_runner_source_paths_and_ownership_fail_closed(self):
        path = '/tmp/metadata-scripts123/startup-script'
        for variant in ('unsafe-tmp', 'unsafe-directory', 'directory-link',
                        'file-link', 'hardlink', 'writable-file', 'wrong-owner', 'wrong-name'):
            with self.subTest(variant=variant):
                self.tearDown()
                self.setUp()
                self.write(path[1:], 'synthetic source')
                temporary = self.root/'tmp'
                directory = temporary/'metadata-scripts123'
                source = directory/'startup-script'
                temporary.chmod(0o1777)
                directory.chmod(0o700)
                if variant == 'unsafe-tmp':
                    temporary.chmod(0o777)
                elif variant == 'unsafe-directory':
                    directory.chmod(0o755)
                elif variant == 'directory-link':
                    directory.rename(temporary/'other')
                    directory.symlink_to(temporary/'other', target_is_directory=True)
                elif variant == 'file-link':
                    source.unlink()
                    source.symlink_to(self.root/'etc/passwd')
                elif variant == 'hardlink':
                    os.link(source, directory/'other')
                elif variant == 'writable-file':
                    source.chmod(0o666)
                elif variant == 'wrong-owner':
                    self.files.uid = os.getuid()+1
                with patch.object(h, '__file__', path if variant != 'wrong-name' else '/tmp/other/startup-script'):
                    with self.assertRaises((h.Refused, OSError)):
                        h.run(self.files, self.guest, now=900)
                self.assertFalse(self.guest.puts)

    def test_absolute_http_deadline_interrupts_trickled_headers_and_body(self):
        for phase in ('connect', 'headers', 'body'):
            with self.subTest(phase=phase):
                client, server = socket.socketpair()
                stopped = threading.Event()
                sent = []
                class LocalConnection(h.http.client.HTTPConnection):
                    def connect(inner):
                        if phase == 'connect':
                            time.sleep(.3)
                        inner.sock = client
                header = b'HTTP/1.1 200 OK\r\nMetadata-Flavor: Google\r\nContent-Length: 40\r\n\r\n'
                def serve():
                    try:
                        server.recv(8192)
                        if phase == 'body':
                            server.sendall(header)
                            payload = b'x'*40
                        else:
                            payload = header
                        for byte in payload:
                            if stopped.wait(.02):
                                break
                            server.sendall(bytes((byte,)))
                            sent.append(byte)
                    except OSError:
                        pass
                    finally:
                        server.close()
                worker = threading.Thread(target=serve)
                worker.start()
                runtime = h.Runtime()
                runtime.end = time.monotonic()+.06
                previous = signal.getsignal(signal.SIGALRM)
                before = time.monotonic()
                try:
                    with patch.object(h.http.client, 'HTTPConnection', LocalConnection):
                        self.assertRaises(h.Refused, runtime.request, 'GET', 'instance/id')
                    self.assertLess(time.monotonic()-before, .16)
                    self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
                    self.assertIs(signal.getsignal(signal.SIGALRM), previous)
                    if phase != 'connect':
                        self.assertEqual(client.fileno(), -1)
                finally:
                    stopped.set()
                    client.close()
                    worker.join(timeout=1)
                    self.assertFalse(worker.is_alive())
                # A request never survives failure in a worker/background task.
                self.assertEqual(client.fileno(), -1)

    def test_trickled_part_response_never_attempts_summary(self):
        client, server = socket.socketpair()
        stopped = threading.Event()
        attempted = []
        class LocalConnection(h.http.client.HTTPConnection):
            def connect(inner):
                inner.sock = client
        def serve():
            try:
                server.recv(16384)
                server.sendall(b'HTTP/1.1 200 OK\r\nMetadata-Flavor: Google\r\nContent-Length: 40\r\n\r\n')
                for _ in range(40):
                    if stopped.wait(.02):
                        break
                    server.sendall(b'x')
            except OSError:
                pass
            finally:
                server.close()
        worker = threading.Thread(target=serve)
        worker.start()
        original = self.guest.request
        def request(method, key, body=None):
            if method == 'PUT':
                attempted.append(key)
                self.guest.end = time.monotonic()+.06
                return h.Runtime.request(self.guest, method, key, body)
            return original(method, key, body)
        self.guest.request = request
        try:
            with patch.object(h.http.client, 'HTTPConnection', LocalConnection):
                self.assertRaises(h.Refused, self.run_hook)
            self.assertEqual(attempted, ['instance/guest-attributes/labapp-prelogin/inventory-0'])
            self.assertFalse(self.guest.puts)
            self.assertEqual(client.fileno(), -1)
        finally:
            stopped.set()
            client.close()
            worker.join(timeout=1)
            self.assertFalse(worker.is_alive())

    def test_existing_alarm_refuses_before_connection(self):
        runtime = h.Runtime()
        try:
            signal.setitimer(signal.ITIMER_REAL, 1)
            with patch.object(h.http.client, 'HTTPConnection') as connection:
                self.assertRaises(h.Refused, runtime.request, 'GET', 'instance/id')
                connection.assert_not_called()
                self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 0)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

    def test_metadata_deadline_type_and_unknown_fields(self):
        for change in ({'deadline': 899}, {'uid': True}, {'home': '/root'}, {'nonce': 'x'}, {'extra': 'x'}):
            obj = request()
            obj.update(change)
            self.assertRaises(h.Refused, h.metadata, h.canonical(obj), 900)


if __name__ == '__main__':
    unittest.main()
