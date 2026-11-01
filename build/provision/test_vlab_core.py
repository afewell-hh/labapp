"""Actual entrypoint tests with public ephemeral files and a fail-closed command spy.

No real hhfab/kubectl/systemd/network/package/sysctl/sudo execution. Only the
bounded executor tests create inspected Python stdlib children (no network).
Fakes prove source sequencing/refusal, not systemd namespaces/cgroups or VLAB.
"""
import base64
from contextlib import ExitStack, contextmanager
import copy
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import yaml
import vlab_core as core
VERIFY_PREREQUISITES = core.verify_prerequisites
DIAGNOSTIC_RUN = core.diagnostic_run
EXECUTE = core.execute
SENTINEL = 'PRIVATE-SENTINEL-' + 'z' * 8


class ExecWitness(BaseException):
    pass


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(yaml.safe_dump(value, sort_keys=False).encode())
    path.chmod(0o600)


def public_fab():
    control = {'managementSubnet': '172.30.0.0/21', 'controlVIP': '172.30.0.1/32',
               'kubeClusterSubnet': '172.28.0.0/16', 'kubeServiceSubnet': '172.29.0.0/16',
               'kubeClusterDNS': '172.29.0.10', 'dummySubnet': '172.30.90.0/24',
               'joinToken': 'PUBLIC-SYNTHETIC-NONDEPLOYABLE-TOKEN-000000',
               'defaultUser': {'password': '$5$synthetic$NOT_A_REAL_PASSWORD',
                               'authorizedKeys': ['ssh-ed25519 PUBLIC_SYNTHETIC_KEY']}}
    fabric = {'mode': 'spine-leaf', 'managementDHCPStart': '172.30.4.0',
              'managementDHCPEnd': '172.30.7.254', 'spineASN': 65100,
              'leafASNStart': 65101, 'leafASNEnd': 65533, 'protocolSubnet': '172.30.8.0/22',
              'vtepSubnet': '172.30.12.0/22', 'fabricSubnet': '172.30.128.0/17',
              'mclagSessionSubnet': '172.30.95.0/31', 'vpcWorkaroundSubnet': '172.30.96.0/19',
              'defaultSwitchUsers': {'admin': {'role': 'admin', **copy.deepcopy(control['defaultUser'])}}}
    return [{'apiVersion': 'fabricator.githedgehog.com/v1beta1', 'kind': 'Fabricator',
             'metadata': {'name': 'default', 'namespace': 'fab'}, 'spec': {'config': {
                 'control': control, 'fabric': fabric, 'registry': {'mode': 'airgap'},
                 'observability': {'defaults': ''}}}},
            {'apiVersion': 'fabricator.githedgehog.com/v1beta1', 'kind': 'ControlNode',
             'metadata': {'name': 'control-1', 'namespace': 'fab'}, 'spec': {
                 'bootstrap': {'disk': '/dev/sda'}, 'external': {'interface': 'enp2s0', 'ip': 'dhcp'},
                 'management': {'interface': 'enp2s1'}}}]


class GuestEnvironment:
    """All fixed production paths are patched to one owned ephemeral fixture."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='labapp-vlab-core-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.patch('ROOT', self.base / 'state')
        self.patch('WORK', self.base / 'work')
        self.patch('CACHE', self.base / 'cache')
        self.patch('LIB', self.base / 'lib')
        self.patch('UNITS', self.base / 'units')
        self.patch('JOURNAL', self.base / 'journald@labapp-vlab.conf')
        self.patch('JOURNAL_DROPINS', (self.base / 'journal.d',))
        self.patch('MOUNTINFO', self.base / 'mountinfo')
        self.patch('CGROUP', self.base / 'cgroup')
        self.patch('ROOT_UID', os.getuid())
        self.user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir='/home/ubuntu')
        self.stack.enter_context(patch.object(core, 'ubuntu', return_value=self.user))
        self.stack.enter_context(patch.object(core, 'verify_prerequisites', return_value={'synthetic': 'tools'}))
        self.stack.enter_context(patch.object(core, 'verify_netfilter'))
        self.stack.enter_context(patch.object(core.os, 'chown'))
        self.stack.enter_context(patch.object(core.os, 'geteuid', return_value=0))
        self.stack.enter_context(patch.object(core, 'execute', side_effect=self.command))
        # No native systemctl/journalctl: the first-failure queries are fakes in every test.
        self.diagnostics = []
        self.diag = None
        self.stack.enter_context(patch.object(core, 'diagnostic_run', side_effect=self.diagnostic))
        self.stack.enter_context(patch.dict(os.environ, {'INVOCATION_ID': 'a' * 32, 'SERVICE_RESULT': 'success'}))
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.stack.enter_context(patch('sys.stdout', self.stdout))
        self.stack.enter_context(patch('sys.stderr', self.stderr))
        self.calls = []
        self.execs = []
        self.phase = {'fresh': 'inactive', 'resume': 'inactive'}
        self.invocation = {'fresh': '', 'resume': ''}
        self.failure = None
        self.activation = True
        self.cluster_uid = 'public-cluster-uid'
        self.api_mutation = None
        self.up_error = None
        self.stop_result = 'success'
        self.tools = {'synthetic': 'tools'}
        self.fab = public_fab()
        self.fab_path = self.base / 'private-fab.yaml'
        self.fab_path.write_bytes(yaml.safe_dump_all(self.fab, sort_keys=False).encode())
        self.fab_path.chmod(0o600)
        self.wiring = Path(__file__).resolve().parents[2] / 'wiringd.yaml'
        self.receipt = self.base / 'packages.json'
        self.receipt.write_text('{"public":"synthetic-only"}')
        self.receipt.chmod(0o600)
        self.input = self.base / 'input.json'
        self.contract = {'schema': 1, 'dedicated_guest': True, 'nonce': 'b' * 32,
                         'fab': str(self.fab_path), 'fab_sha256': core.digest(self.fab_path.read_bytes()),
                         'wiring': str(self.wiring), 'wiring_sha256': core.WIRING_SHA,
                         'package_receipt': str(self.receipt),
                         'package_receipt_sha256': core.digest(self.receipt.read_bytes()),
                         'candidate_policy': {'bridge': '172.30.0.2/21', 'netfilter': 'all-three-off',
                             'forwarded_ports': '0.0.0.0-isolated-by-route', 'build': 'iso',
                             'controls_restricted': True, 'servers_restricted': True}}
        self.write_contract()

    def patch(self, name, value):
        self.stack.enter_context(patch.object(core, name, value))

    def write_contract(self):
        self.input.write_text(json.dumps(self.contract))
        self.input.chmod(0o600)

    def call(self, *args):
        return core.main(list(args))

    def prepared(self):
        self.assertEqual(self.call('prepare', '--input', str(self.input)), 0, self.stderr.getvalue())
        return core.state()

    def fresh(self):
        self.prepared()
        self.assertEqual(self.call('start-fresh'), 0, self.stderr.getvalue())
        return core.state()

    def resumable(self):
        self.fresh()
        self.assertEqual(self.call('activate-resume'), 0, self.stderr.getvalue())
        return core.state()

    def runtime_files(self):
        work = core.WORK
        nics = core.canonical_nics()
        dump(work / 'vlab/config.yaml', {'sizes': core.SIZES,
             'vms': {name: {'type': kind, 'nics': nics[name]} for name, kind in core.VMS.items()},
             'externals': {'nics': {}, 'vrfs': {}}})
        for filename in ('sshkey', 'sshkey.pub'):
            target = work / 'vlab' / filename
            target.write_bytes(b'PUBLIC_SYNTHETIC_KEY')
            target.chmod(0o600)
        for name, kind in core.VMS.items():
            directory = work / 'vlab/vms' / name
            directory.mkdir(parents=True, mode=0o700)
            files = ['os.img', 'efi_code.fd', 'efi_vars.fd']
            files += ['usb.iso'] if kind == 'control' else []
            files += ['ignition.json', 'butane.yaml'] if kind == 'server' else []
            for filename in files:
                target = directory / filename
                target.write_bytes(('public-' + filename).encode())
                target.chmod(0o600)
        result = work / 'result'
        installer = result / core.RESULT
        installer.mkdir(mode=0o700)
        target = result / (core.RESULT + '.inhash')
        target.write_bytes(b'A' * 43 + b'=')
        target.chmod(0o600)
        target = result / (core.RESULT + '-usb.iso')
        target.write_bytes(b'PUBLIC_ISO')
        target.chmod(0o600)
        target = installer / 'hhfab-recipe'
        target.write_bytes(b'PUBLIC_NOT_EXECUTABLE')
        target.chmod(0o600)
        (installer / 'fab.yaml').write_bytes(self.fab_path.read_bytes())
        (installer / 'fab.yaml').chmod(0o600)
        (installer / 'include.yaml').write_bytes(self.wiring.read_bytes())
        (installer / 'include.yaml').chmod(0o600)
        b64 = lambda raw: base64.b64encode(raw).decode()
        dump(work / 'vlab/kubeconfig', {'apiVersion': 'v1', 'kind': 'Config',
             'clusters': [{'name': 'default', 'cluster': {'server': 'https://127.0.0.1:6443',
                 'certificate-authority-data': b64(b'-----BEGIN CERTIFICATE-----PUBLIC_SYNTHETIC')}}],
             'contexts': [{'name': 'default', 'context': {'cluster': 'default', 'user': 'default'}}],
             'current-context': 'default', 'users': [{'name': 'default', 'user': {
                 'client-certificate-data': b64(b'PUBLIC_CERT'), 'client-key-data': b64(b'PUBLIC_KEY')}}]})
        core.MOUNTINFO.write_text('\n'.join(
            f'{i} 0 0:1 / {p} ro - ext4 /dev/public rw'
            for i, p in enumerate(core.readonly_paths(), 1)))

    def diagnostic(self, argv, end, keep):
        self.diagnostics.append((list(argv), end, keep))
        if self.diag is not None:
            return self.diag(argv)
        if argv[0] == core.SYSTEMCTL:
            invocation = core.state().get('invocation', '')
            return 'ok', ('ActiveState=failed\nInvocationID=' + invocation + '\n').encode(), False, 'confirmed'
        return 'ok', b'JOURNAL-TAIL ' + SENTINEL.encode(), False, 'confirmed'

    def command(self, argv, deadline, cap=30, user=False, *, retain=True):
        self.calls.append((list(argv), deadline, cap, user))
        core.remaining(deadline)
        if self.failure and self.failure(argv):
            raise core.Failure('synthetic command failure', 17)
        if argv[0] == core.SYSTEMCTL:
            action = argv[1]
            if action == 'daemon-reload' or action == 'enable':
                return b''
            mode = next(k for k, v in core.UNIT.items() if v == argv[2])
            if action == 'show':
                active = self.phase[mode]
                fields = {'Id': core.UNIT[mode], 'LoadState': 'loaded', 'ActiveState': active,
                          'SubState': 'running' if active == 'active' else 'dead',
                          'InvocationID': self.invocation[mode],
                          'MainPID': str(os.getpid()) if active in ('active', 'activating') else '0',
                          'ControlGroup': '/system.slice/' + core.UNIT[mode],
                          'FragmentPath': str(core.UNITS / core.UNIT[mode]),
                          'DropInPaths': '', 'NeedDaemonReload': 'no'}
                return '\n'.join(k + '=' + v for k, v in fields.items()).encode()
            if action == 'start':
                # Actual shared flock must be free across the synchronous manager call.
                with core.locked():
                    self.assertEqual(core.state()['phase'], 'starting')
                if not self.activation:
                    raise core.Failure('synthetic activation timeout', 124)
                self.phase[mode] = 'activating'
                self.invocation[mode] = os.environ['INVOCATION_ID']
                try:
                    core.unit_gate(mode)
                    with patch.object(core.os, 'initgroups') as groups, \
                         patch.object(core.os, 'setgid') as gid, patch.object(core.os, 'setuid') as uid, \
                         patch.object(core.os, 'getuid', return_value=self.user.pw_uid), \
                         patch.object(core.os, 'geteuid', return_value=self.user.pw_uid), \
                         patch.object(core.os, 'chdir'), \
                         patch.object(core.os, 'execve', side_effect=self.up_error or ExecWitness) as replace:
                        with self.assertRaises(ExecWitness):
                            core.unit_run(mode)
                        groups.assert_called_once_with('ubuntu', self.user.pw_gid)
                        gid.assert_called_once_with(self.user.pw_gid)
                        uid.assert_called_once_with(self.user.pw_uid)
                        replace.assert_called_once_with(core.HHFAB, core.up_argv(), core.SAFE_ENV)
                        self.execs.append(core.up_argv())
                    if mode == 'fresh':
                        self.runtime_files()
                    core.unit_ready(mode)
                    self.phase[mode] = 'active'
                except BaseException:
                    self.phase[mode] = 'failed'
                    core.unit_finished(mode)
                    raise
                return b''
            if action == 'stop':
                self.phase[mode] = 'inactive'
                if core.state().get('invocation'):
                    with patch.dict(os.environ, {'SERVICE_RESULT': self.stop_result}):
                        core.unit_finished(mode)
                return b''
        if argv[:2] == [core.HHFAB, 'init']:
            source = Path(argv[argv.index('--config') + 1])
            wiring = Path(argv[argv.index('--wiring') + 1])
            (core.WORK / 'fab.yaml').write_bytes(source.read_bytes())
            (core.WORK / 'fab.yaml').chmod(0o600)
            dump(core.WORK / '.registry.yaml', {'repo': 'ghcr.io', 'prefix': 'githedgehog'})
            (core.WORK / 'include').mkdir(mode=0o700)
            (core.WORK / 'include/wiring-input.yaml').write_bytes(wiring.read_bytes())
            (core.WORK / 'include/wiring-input.yaml').chmod(0o600)
            (core.WORK / 'result').mkdir(mode=0o700)
            return b''
        if argv[:2] == [core.HHFAB, 'validate'] or argv[:2] == [core.HHFAB, 'vlab']:
            return b''
        if argv[0] == core.KUBECTL:
            if '--raw=/readyz' in argv:
                return b'ok'
            resource = argv[argv.index('get') + 1]
            if resource == 'namespace':
                return json.dumps({'metadata': {'uid': self.cluster_uid}}).encode()
            if resource == 'nodes':
                items = [{'metadata': {'name': 'control-1'}, 'status': {
                    'conditions': [{'type': 'Ready', 'status': 'True'}]}}]
            else:
                kinds = {'fabricators': 'Fabricator', 'controlnodes': 'ControlNode', 'fabnodes': 'FabNode',
                         'switches': 'Switch', 'servers': 'Server', 'connections': 'Connection',
                         'switchgroups': 'SwitchGroup', 'vlannamespaces': 'VLANNamespace',
                         'ipv4namespaces': 'IPv4Namespace'}
                all_docs = self.fab + core.yaml_documents(self.wiring.read_bytes())
                items = copy.deepcopy([d for d in all_docs if d['kind'] == kinds[resource.split('.')[0]]])
                if self.api_mutation:
                    self.api_mutation(items)
            return json.dumps({'items': items}).encode()
        if argv[0] == core.PYTHON and argv[1] == str(core.BRIDGE):
            return b''
        if argv[:2] == ['/usr/sbin/ip', '-j']:
            return json.dumps([{'ifname': 'hhbr', 'ifindex': 42,
                'linkinfo': {'info_kind': 'bridge', 'info_data': {
                    'nf_call_iptables': 0, 'nf_call_ip6tables': 0, 'nf_call_arptables': 0}}}]).encode()
        if argv[0] in ('/usr/sbin/modprobe', '/usr/sbin/sysctl'):
            return b''
        raise AssertionError('UNINSPECTED CHILD PATH ' + repr(argv))


class GuestFixture(GuestEnvironment, unittest.TestCase):
    def test_actual_entrypoint_full_fresh_stop_activate_resume_twice(self):
        initial = self.resumable()
        self.assertEqual(initial['phase'], 'resumable')
        for _ in range(2):
            self.assertEqual(self.call('start-resume'), 0, self.stderr.getvalue())
            self.assertEqual(core.state()['cluster'], initial['cluster'])
            self.assertEqual(core.state()['critical'], initial['critical'])
            self.assertEqual(self.call('stop'), 0, self.stderr.getvalue())
            self.assertEqual(core.state()['phase'], 'resumable')
        init_calls = [c for c in self.calls if c[0][:2] == [core.HHFAB, 'init']]
        self.assertEqual(len(init_calls), 1)
        inspections = [c for c in self.calls if c[0][:3] == [core.HHFAB, 'vlab', 'inspect-switches']]
        self.assertEqual(len(inspections), 3)
        self.assertTrue(all('--wait-applied-for' in c[0] and c[0][-1] == '30' for c in inspections))
        self.assertTrue(all(c[3] for c in self.calls if c[0][0] in (core.HHFAB, core.KUBECTL)))
        self.assertNotIn('PUBLIC_SYNTHETIC', self.stdout.getvalue() + self.stderr.getvalue())

    def test_existing_work_is_never_adopted(self):
        core.WORK.mkdir(mode=0o700)
        self.assertEqual(self.call('prepare', '--input', str(self.input)), 1)
        self.assertFalse(core.ROOT.exists())
        self.assertFalse(self.calls)

    def test_fresh_refuses_existing_vlab_or_populated_result_before_up(self):
        self.prepared()
        for directory in (core.WORK / 'vlab', core.WORK / 'result'):
            created = not directory.exists()
            if created:
                directory.mkdir(mode=0o700)
            target = directory / 'foreign'
            target.write_bytes(b'preserve foreign data')
            self.assertEqual(self.call('start-fresh'), 1)
            self.assertFalse(self.execs)
            self.assertEqual(target.read_bytes(), b'preserve foreign data')
            target.unlink()
            if created:
                directory.rmdir()
        self.assertEqual(core.state()['phase'], 'prepared')

    def test_fresh_refuses_replaced_empty_result_directory(self):
        self.prepared()
        (core.WORK / 'result').rename(self.base / 'retained-result')
        (core.WORK / 'result').mkdir(mode=0o700)
        self.assertEqual(self.call('start-fresh'), 1)
        self.assertFalse(self.execs)
        self.assertTrue((self.base / 'retained-result').is_dir())

    def test_prepared_source_pins_include_deployed_owned_process_sibling(self):
        self.prepared()
        self.assertIn('owned_process.py', core.state()['source'])
        self.assertEqual((core.LIB / 'owned_process.py').read_bytes(),
                         (Path(core.__file__).parent / 'owned_process.py').read_bytes())
        (core.LIB / 'owned_process.py').write_bytes(b'public changed component')
        self.assertEqual(self.call('start-fresh'), 1)
        self.assertFalse(self.execs)

    def test_fresh_gate_and_run_recheck_before_exec_without_adoption(self):
        self.prepared()
        actual_run = core.unit_run
        def altered_run(mode):
            target = core.WORK / 'result/foreign'
            target.write_bytes(b'preserve foreign data')
            return actual_run(mode)
        with patch.object(core, 'unit_run', side_effect=altered_run):
            self.assertEqual(self.call('start-fresh'), 1)
        self.assertFalse(self.execs)
        self.assertEqual((core.WORK / 'result/foreign').read_bytes(), b'preserve foreign data')

    def start_with_ready_publication(self, mode, timing='between', mutate=None, live=None,
                                     initial_live=None, contention=False, expire_drop=False,
                                     snapshot_mutation=None):
        """Interleave actual unit_ready at its mocked bridge boundary, without children.

        The readiness writer runs its real snapshot/lock/check_live/save code;
        bridge work cannot complete before hhfab exec, so pause at that boundary.
        """
        class ReadyPaused(BaseException):
            pass
        actual_run = core.unit_run
        actual_contract = core.verify_contract
        actual_snapshot = core.startup_snapshot
        window = []
        live_identity = {}
        clock = [100.0]
        lock_calls = []
        actual_flock = core.fcntl.flock
        def identity(fields):
            return {'invocation': fields['InvocationID'], 'group': fields['ControlGroup'],
                    'pid': int(fields['MainPID']), 'start': '12345', **live_identity}
        def publish():
            with patch.object(core, 'bridge_ready', side_effect=ReadyPaused):
                with self.assertRaises(ReadyPaused):
                    core.unit_ready(mode)
            self.assertIn('service', core.state())
            self.assertTrue(any(c[0] == ['/usr/sbin/ip', '-j', '-d', 'link', 'show', 'dev', 'hhbr']
                                for c in self.calls))
        def change():
            if mutate:
                current = core.state()
                mutate(current)
                core.save(current)
            if live:
                live_identity.update(live)
        def in_run(run_mode):
            if initial_live:
                live_identity.update(initial_live)
            if timing == 'before':
                publish()
            window.append(True)
            def flock(fd, flags):
                lock_calls.append(True)
                if contention and len(lock_calls) <= 2:
                    raise BlockingIOError()
                return actual_flock(fd, flags)
            def sleep(seconds):
                clock[0] += seconds
            actual_groups = core.os.initgroups
            def groups(*args):
                # The final gate must exclude state writers through privilege drop.
                with self.assertRaisesRegex(core.Failure, 'another operation owns the lock'):
                    with core.locked():
                        self.fail('final startup lock was released before privilege drop')
                actual_groups(*args)
                if expire_drop:
                    clock[0] = core.state()['deadline']
            try:
                with patch.object(core.fcntl, 'flock', side_effect=flock), \
                     patch.object(core.time, 'sleep', side_effect=sleep), \
                     patch.object(core.os, 'initgroups', side_effect=groups):
                    return actual_run(run_mode)
            finally:
                window.pop()
        def snapshot(run_mode):
            value, deadline = actual_snapshot(run_mode)
            if window and snapshot_mutation:
                current = core.state()
                snapshot_mutation(current)
                core.save(current)
            return value, deadline
        def validate(value, deadline):
            result = actual_contract(value, deadline)
            if window:
                if timing == 'between':
                    publish()
                change()
            return result
        with patch.object(core, 'service_identity', side_effect=identity), \
             patch.object(core, 'boot', return_value='12345678-1234-1234-1234-123456789abc'), \
             patch.object(core.time, 'monotonic', side_effect=lambda: clock[0]):
            self.prepared() if mode == 'fresh' else self.resumable()
            before = len(self.execs)
            with patch.object(core, 'unit_run', side_effect=in_run), \
                 patch.object(core, 'startup_snapshot', side_effect=snapshot), \
                 patch.object(core, 'verify_contract', side_effect=validate):
                result = self.call('start-fresh' if mode == 'fresh' else 'start-resume')
            if contention:
                self.assertGreaterEqual(len(lock_calls), 4)
                self.assertAlmostEqual(clock[0], 100.02)
            return result, len(self.execs) - before

    def test_fresh_actual_run_waits_for_sibling_lock_then_execs(self):
        result, delta = self.start_with_ready_publication('fresh', 'before', contention=True)
        self.assertEqual(result, 0, self.stderr.getvalue())
        self.assertEqual(delta, 1)

    def test_resume_actual_run_waits_for_sibling_lock_then_execs(self):
        result, delta = self.start_with_ready_publication('resume', 'before', contention=True)
        self.assertEqual(result, 0, self.stderr.getvalue())
        self.assertEqual(delta, 1)

    def test_fresh_refuses_initial_live_other_pid_same_invocation(self):
        result, delta = self.start_with_ready_publication('fresh', 'none', initial_live={'pid': 999999})
        self.assertEqual(result, 1)
        self.assertEqual(delta, 0)

    def test_resume_refuses_initial_live_other_pid_same_invocation(self):
        result, delta = self.start_with_ready_publication('resume', 'before', initial_live={'pid': 999999})
        self.assertEqual(result, 1)
        self.assertEqual(delta, 0)

    def test_fresh_refuses_deadline_expired_during_privilege_drop(self):
        result, delta = self.start_with_ready_publication('fresh', 'none', expire_drop=True)
        self.assertEqual(result, 124)
        self.assertEqual(delta, 0)

    def test_resume_refuses_deadline_expired_during_privilege_drop(self):
        result, delta = self.start_with_ready_publication('resume', 'before', expire_drop=True)
        self.assertEqual(result, 124)
        self.assertEqual(delta, 0)

    def readiness_refuses_changed_snapshot(self, mode, mutation):
        def identity(fields):
            return {'invocation': fields['InvocationID'], 'group': fields['ControlGroup'],
                    'pid': int(fields['MainPID']), 'start': '12345'}
        with patch.object(core, 'service_identity', side_effect=identity), \
             patch.object(core, 'boot', return_value='12345678-1234-1234-1234-123456789abc'):
            self.prepared() if mode == 'fresh' else self.resumable()
            core.reserve(mode)
            self.phase[mode] = 'activating'
            self.invocation[mode] = os.environ['INVOCATION_ID']
            core.unit_gate(mode)
            if mode == 'fresh':
                self.runtime_files()
            original = core.critical_snapshot
            def substituted(deadline):
                critical = original(deadline)
                current = core.state()
                mutation(current)
                core.save(current)
                return critical
            before = len(self.execs)
            with patch.object(core, 'critical_snapshot', side_effect=substituted):
                with self.assertRaises(core.Failure):
                    core.unit_ready(mode)
            self.assertEqual(len(self.execs), before)
            self.assertNotEqual(core.state()['phase'], 'ready')

    def lock_fixture(self, wait, deadline, attempts, expected=None):
        """Actual locked loop; deterministic flock contention and virtual time only."""
        with patch.object(core, 'boot', return_value='12345678-1234-1234-1234-123456789abc'):
            self.prepared()
        now, sleeps, calls, entered = [100.0], [], [], []
        def sleep(seconds):
            sleeps.append(seconds)
            now[0] += seconds
        def flock(fd, flags):
            self.assertEqual(flags, core.fcntl.LOCK_EX | core.fcntl.LOCK_NB)
            self.assertFalse(os.get_inheritable(fd))
            calls.append(now[0])
            if attempts == 'late':
                now[0] = deadline
                return
            if len(calls) <= attempts:
                raise BlockingIOError()
        with patch.object(core.time, 'monotonic', side_effect=lambda: now[0]), \
             patch.object(core.time, 'sleep', side_effect=sleep), \
             patch.object(core.fcntl, 'flock', side_effect=flock):
            if expected:
                with self.assertRaises(core.Failure):
                    with core.locked(wait, deadline=deadline):
                        entered.append(True)
            else:
                with core.locked(wait, deadline=deadline):
                    entered.append(True)
        self.assertEqual(bool(entered), not bool(expected))
        self.assertLessEqual(now[0], min(100 + wait, deadline) if wait else deadline)
        return calls, sleeps

    def test_sibling_lock_contended_then_acquired_within_original_deadline(self):
        calls, sleeps = self.lock_fixture(10, 101, 2)
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(sleeps), 2)

    def test_sibling_lock_contention_cannot_renew_short_original_deadline(self):
        calls, sleeps = self.lock_fixture(10, 100.025, 100, expected=True)
        self.assertEqual(len(calls), 4)
        self.assertAlmostEqual(sum(sleeps), 0.025)

    def test_sibling_lock_contention_still_has_ten_second_cap(self):
        _, sleeps = self.lock_fixture(10, 200, 10000, expected=True)
        self.assertAlmostEqual(sum(sleeps), 10)

    def test_sibling_lock_acquisition_at_original_deadline_cannot_enter(self):
        calls, sleeps = self.lock_fixture(10, 101, 'late', expected=True)
        self.assertEqual(len(calls), 1)
        self.assertFalse(sleeps)

    def test_other_operation_lock_remains_immediate_refusal(self):
        calls, sleeps = self.lock_fixture(0, 101, 1, expected=True)
        self.assertEqual(len(calls), 1)
        self.assertFalse(sleeps)

    def test_fresh_gate_refuses_state_created_after_reservation(self):
        self.prepared()
        actual = self.command
        def altered_gate(argv, *args, **kwargs):
            if argv[:3] == [core.SYSTEMCTL, 'start', core.UNIT['fresh']]:
                (core.WORK / 'vlab').mkdir(mode=0o700)
            return actual(argv, *args, **kwargs)
        with patch.object(core, 'execute', side_effect=altered_gate):
            self.assertEqual(self.call('start-fresh'), 1)
        self.assertFalse(self.execs)
        self.assertTrue((core.WORK / 'vlab').is_dir())

    def test_cache_preexisting_symlink_nondirectory_and_writable_directory_refused(self):
        foreign = self.base / 'foreign-cache'
        foreign.mkdir()
        core.CACHE.symlink_to(foreign)
        self.assertEqual(self.call('prepare', '--input', str(self.input)), 1)
        core.CACHE.unlink()
        core.CACHE.write_text('foreign')
        self.assertEqual(self.call('prepare', '--input', str(self.input)), 1)
        core.CACHE.unlink()
        core.CACHE.mkdir(mode=0o700)
        core.CACHE.chmod(0o777)
        self.assertEqual(self.call('prepare', '--input', str(self.input)), 1)
        self.assertFalse(core.ROOT.exists())

    def test_cache_symlink_ancestor_and_wrong_owner_refused(self):
        foreign = self.base / 'foreign-cache'
        foreign.mkdir()
        ancestor = self.base / 'cache-link'
        ancestor.symlink_to(foreign)
        with patch.object(core, 'CACHE', ancestor / 'cache'):
            self.assertEqual(self.call('prepare', '--input', str(self.input)), 1)
        core.CACHE.mkdir(mode=0o700)
        original = Path.lstat
        def different_owner(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            if path == core.CACHE:
                fields = list(value)
                fields[4] = self.user.pw_uid + 1
                return os.stat_result(fields)
            return value
        with patch.object(Path, 'lstat', autospec=True, side_effect=different_owner):
            self.assertEqual(self.call('prepare', '--input', str(self.input)), 1)
        self.assertFalse(core.ROOT.exists())

    def test_failed_import_is_terminal_and_retained(self):
        self.failure = lambda args: args[:2] == [core.HHFAB, 'init']
        self.assertEqual(self.call('prepare', '--input', str(self.input)), 17)
        self.assertEqual(core.state()['phase'], 'failed')
        self.assertEqual(core.state()['stage'], 'import')
        self.assertTrue(core.WORK.exists())
        self.assertEqual(self.call('start-fresh'), 1)

    def test_failed_validate_is_terminal(self):
        self.failure = lambda args: args[:2] == [core.HHFAB, 'validate']
        self.assertEqual(self.call('prepare', '--input', str(self.input)), 17)
        self.assertEqual(core.state()['phase'], 'failed')
        self.assertEqual(core.state()['stage'], 'validate')

    def test_prepare_failure_recording_cannot_replace_primary(self):
        actual_save = core.save
        def fail_record(value):
            if value['phase'] == 'failed':
                raise core.Failure('synthetic secondary recording failure', 29)
            return actual_save(value)
        self.failure = lambda args: args[:2] == [core.HHFAB, 'init']
        with patch.object(core, 'save', side_effect=fail_record):
            self.assertEqual(self.call('prepare', '--input', str(self.input)), 17)
        self.assertIn('failure recording unverified', self.stderr.getvalue())

    def test_import_mutation_refused(self):
        real = self.command
        def changed(args, *a, **kw):
            out = real(args, *a, **kw)
            if args[:2] == [core.HHFAB, 'validate']:
                with (core.WORK / 'fab.yaml').open('ab') as stream:
                    stream.write(b'\n# changed')
            return out
        with patch.object(core, 'execute', side_effect=changed):
            self.assertEqual(self.call('prepare', '--input', str(self.input)), 1)
        self.assertEqual(core.state()['phase'], 'failed')

    def test_competing_start_refuses_without_stop(self):
        self.fresh()
        before = len(self.calls)
        self.assertEqual(self.call('start-fresh'), 1)
        self.assertEqual(self.phase['fresh'], 'active')
        self.assertFalse(any(c[0][1] == 'stop' for c in self.calls[before:] if c[0][0] == core.SYSTEMCTL))

    def test_conflicting_active_resume_refuses_without_auto_stop(self):
        self.prepared()
        self.phase['resume'] = 'active'
        before = len(self.calls)
        self.assertEqual(self.call('start-fresh'), 1)
        self.assertEqual(self.phase['resume'], 'active')
        self.assertFalse(any(c[0][1] in ('start', 'stop') for c in self.calls[before:] if c[0][0] == core.SYSTEMCTL))

    def test_gate_failure_marks_direct_partial_start_failed(self):
        self.prepared()
        self.failure = lambda args: args[0] == '/usr/sbin/modprobe'
        self.assertEqual(self.call('start-fresh'), 17)
        self.assertEqual(core.state()['phase'], 'failed')
        self.assertEqual(self.phase['fresh'], 'failed')

    def test_unexpected_runtime_unit_failure_is_not_resumable(self):
        self.fresh()
        with patch.dict(os.environ, {'SERVICE_RESULT': 'exit-code'}):
            self.assertEqual(self.call('unit-finished', '--mode', 'fresh'), 0)
        self.assertEqual(core.state()['phase'], 'failed')
        self.assertEqual(self.call('activate-resume'), 1)

    def test_explicit_owned_stop_accepts_nonzero_cancellation_then_resumes(self):
        self.fresh()
        self.stop_result = 'exit-code'
        self.assertEqual(self.call('activate-resume'), 0, self.stderr.getvalue())
        self.assertEqual(core.state()['phase'], 'resumable')
        self.assertEqual(core.state()['service_result'], 'owned-stop-process-termination')
        self.assertEqual(self.call('start-resume'), 0, self.stderr.getvalue())
        self.assertNotIn('stopping', core.state())
        self.assertEqual(self.call('stop'), 0)
        self.assertEqual(core.state()['phase'], 'resumable')

    def test_new_start_cannot_reserve_before_stop_containment_is_verified(self):
        self.resumable()
        self.assertEqual(self.call('start-resume'), 0)
        actual = self.command
        observed = []
        def during_stop(argv, *args, **kwargs):
            raw = actual(argv, *args, **kwargs)
            if argv[:3] == [core.SYSTEMCTL, 'stop', core.UNIT['resume']]:
                observed.append(core.state()['phase'])
                with self.assertRaises(core.Failure):
                    core.reserve('resume')
            return raw
        with patch.object(core, 'execute', side_effect=during_stop):
            self.assertEqual(self.call('stop'), 0)
        self.assertEqual(observed, ['stop-observed'])
        self.assertEqual(core.state()['phase'], 'resumable')

    def test_overlapping_and_delayed_stop_cannot_kill_new_invocation(self):
        self.resumable()
        self.assertEqual(self.call('start-resume'), 0)
        old = core.state()
        actual = self.command
        actual_stop = core._stop_owned_locked
        refusals = []
        def competing():
            refusals.extend([self.call('stop'), self.call('start-resume')])
            with self.assertRaises(core.Failure):
                core.unit_gate('resume')
        def during_manager(argv, *args, **kwargs):
            if argv[:3] == [core.SYSTEMCTL, 'stop', core.UNIT['resume']]:
                # The manager can acquire state, but a second controller cannot
                # issue a unit-name stop, even before the first returns.
                with core.locked():
                    self.assertEqual(core.state()['operation'], old['operation'])
                competing()
            return actual(argv, *args, **kwargs)
        def after_commit(*args, **kwargs):
            result = actual_stop(*args, **kwargs)
            self.assertEqual(core.state()['phase'], 'resumable')
            competing()  # Still excluded after resumable is committed.
            return result
        with patch.object(core, 'execute', side_effect=during_manager), \
             patch.object(core, '_stop_owned_locked', side_effect=after_commit):
            self.assertEqual(self.call('stop'), 0, self.stderr.getvalue())
        self.assertEqual(refusals, [1, 1, 1, 1])
        stops = [c for c in self.calls if c[0][:2] == [core.SYSTEMCTL, 'stop']]
        with patch.dict(os.environ, {'INVOCATION_ID': 'c' * 32}):
            self.assertEqual(self.call('start-resume'), 0, self.stderr.getvalue())
        newer = core.state()
        self.assertNotEqual(newer['operation'], old['operation'])
        with self.assertRaises(core.Failure):
            core.stop_owned(old, core.time.monotonic() + 35)
        self.assertEqual(stops, [c for c in self.calls if c[0][:2] == [core.SYSTEMCTL, 'stop']])
        self.assertEqual(core.state(), newer)
        self.assertEqual(self.phase['resume'], 'active')

    def test_stop_controller_path_refuses_symlink_and_hardlink(self):
        self.fresh()
        target = core.ROOT / 'stop-controller.lock'
        target.unlink()
        other = core.ROOT / 'other'
        other.write_bytes(b'')
        other.chmod(0o600)
        before = len(self.calls)
        target.symlink_to(other)
        self.assertEqual(self.call('stop'), 1)
        target.unlink()
        os.link(other, target)
        self.assertEqual(self.call('stop'), 1)
        self.assertFalse(any(c[0][:2] == [core.SYSTEMCTL, 'stop'] for c in self.calls[before:]))

    def test_stale_stop_intent_does_not_approve_unexpected_exit(self):
        self.fresh()
        value = core.state()
        value['stopping'] = {'operation': 'd' * 32, 'invocation': value['invocation']}
        core.save(value)
        with patch.dict(os.environ, {'SERVICE_RESULT': 'exit-code'}):
            self.assertEqual(self.call('unit-finished', '--mode', 'fresh'), 0)
        self.assertEqual(core.state()['phase'], 'failed')

    def test_readiness_failure_stops_owned_invocation(self):
        self.prepared()
        self.failure = lambda args: args[:3] == [core.HHFAB, 'vlab', 'inspect-switches']
        self.assertEqual(self.call('start-fresh'), 17)
        self.assertEqual(core.state()['phase'], 'failed')
        self.assertNotEqual(self.phase['fresh'], 'active')
        self.assertNotIn('critical', core.state())

    def test_foreground_build_failure_never_seals_or_retries(self):
        self.prepared()
        self.up_error = core.Failure('synthetic foreground build failure', 17)
        self.assertEqual(self.call('start-fresh'), 17)
        self.assertEqual(core.state()['phase'], 'failed')
        self.assertNotIn('critical', core.state())
        self.assertEqual(self.call('start-fresh'), 1)
        self.assertEqual(len([c for c in self.calls if c[0][:2] == [core.SYSTEMCTL, 'start']]), 1)

    def test_activation_timeout_cancels_queued_owned_job(self):
        self.prepared()
        self.activation = False
        self.assertEqual(self.call('start-fresh'), 124)
        self.assertEqual(core.state()['containment'], 'verified')
        self.assertTrue(any(c[0][:2] == [core.SYSTEMCTL, 'stop'] for c in self.calls))
        stopped = next(i for i, c in enumerate(self.calls) if c[0][:2] == [core.SYSTEMCTL, 'stop'])
        post = [c for c in self.calls[stopped + 1:] if c[0][:2] == [core.SYSTEMCTL, 'show']]
        self.assertTrue(post, 'positive post-stop observation required')
        self.assertTrue(all(c[1] == self.calls[stopped][1] for c in post), 'cleanup deadline renewed')

    def test_pregate_timeout_populated_cgroup_is_not_verified(self):
        self.prepared()
        self.activation = False
        group = core.CGROUP / 'system.slice' / core.UNIT['fresh']
        group.mkdir(parents=True)
        (group / 'cgroup.events').write_text('populated 1\nfrozen 0\n')
        self.assertEqual(self.call('start-fresh'), 124)
        self.assertNotEqual(core.state().get('containment'), 'verified')
        self.assertIn('containment unverified', self.stderr.getvalue())
        self.assertTrue((group / 'cgroup.events').exists())

    def test_pregate_timeout_gate_race_binds_only_same_operation(self):
        self.prepared()
        self.activation = False
        actual = self.command
        def raced_gate(argv, *args, **kwargs):
            if argv[:3] == [core.SYSTEMCTL, 'start', core.UNIT['fresh']]:
                self.phase['fresh'] = 'activating'
                self.invocation['fresh'] = 'a' * 32
                core.unit_gate('fresh')
                raise core.Failure('synthetic activation timeout after gate', 124)
            return actual(argv, *args, **kwargs)
        with patch.object(core, 'execute', side_effect=raced_gate):
            self.assertEqual(self.call('start-fresh'), 124)
        self.assertEqual(core.state()['invocation'], 'a' * 32)
        self.assertEqual(core.state()['phase'], 'failed')
        self.assertEqual(core.state()['containment'], 'verified')

    def test_pregate_cleanup_excludes_competing_controllers_and_gate(self):
        self.prepared()
        self.activation = False
        actual = self.command
        observed = []
        def during_stop(argv, *args, **kwargs):
            if argv[:3] == [core.SYSTEMCTL, 'stop', core.UNIT['fresh']]:
                observed.extend([self.call('stop'), self.call('start-fresh')])
                with self.assertRaises(core.Failure):
                    core.unit_gate('fresh')
            return actual(argv, *args, **kwargs)
        with patch.object(core, 'execute', side_effect=during_stop):
            self.assertEqual(self.call('start-fresh'), 124)
        self.assertEqual(observed, [1, 1])
        self.assertEqual(core.state()['phase'], 'failed')
        self.assertEqual(core.state()['containment'], 'verified')

    def test_pregate_timeout_foreign_operation_is_never_adopted(self):
        self.prepared()
        self.activation = False
        actual = self.command
        def different_operation(argv, *args, **kwargs):
            raw = actual(argv, *args, **kwargs)
            if argv[:3] == [core.SYSTEMCTL, 'stop', core.UNIT['fresh']]:
                value = core.state()
                value['operation'] = 'f' * 32
                core.save(value)
            return raw
        with patch.object(core, 'execute', side_effect=different_operation):
            self.assertEqual(self.call('start-fresh'), 124)
        self.assertEqual(core.state()['operation'], 'f' * 32)
        self.assertNotEqual(core.state().get('containment'), 'verified')
        self.assertIn('containment unverified', self.stderr.getvalue())

    def test_pregate_timeout_post_stop_still_active_is_uncertain(self):
        self.prepared()
        self.activation = False
        actual = self.command
        def still_active(argv, *args, **kwargs):
            raw = actual(argv, *args, **kwargs)
            if argv[:3] == [core.SYSTEMCTL, 'stop', core.UNIT['fresh']]:
                self.phase['fresh'] = 'active'
            return raw
        with patch.object(core, 'execute', side_effect=still_active):
            self.assertEqual(self.call('start-fresh'), 124)
        self.assertNotEqual(core.state().get('containment'), 'verified')
        self.assertIn('containment unverified', self.stderr.getvalue())

    def test_stale_ready_without_stoppost_cannot_activate_resume(self):
        self.fresh()
        self.phase['fresh'] = 'failed'  # manager completion without ExecStopPost
        self.assertEqual(self.call('activate-resume'), 1)
        self.assertEqual(core.state()['phase'], 'failed')
        self.assertNotIn('stop_verified', core.state())
        self.assertEqual(self.call('start-resume'), 1)

    def test_stale_ready_without_stoppost_cannot_be_promoted_by_public_stop(self):
        self.fresh()
        self.phase['fresh'] = 'inactive'
        self.assertEqual(self.call('stop'), 1)
        self.assertEqual(core.state()['phase'], 'failed')
        self.assertNotIn('stop_verified', core.state())

    def test_foreground_exit_during_critical_hash_cannot_seal_ready(self):
        self.prepared()
        actual = core.critical_snapshot
        def failed_while_hashing(deadline):
            snapshot = actual(deadline)
            self.phase['fresh'] = 'failed'
            return snapshot
        with patch.object(core, 'critical_snapshot', side_effect=failed_while_hashing):
            self.assertEqual(self.call('start-fresh'), 1)
        self.assertEqual(core.state()['phase'], 'failed')
        self.assertNotIn('critical', core.state())

    def test_primary_timeout_survives_cleanup_failure(self):
        self.prepared()
        self.activation = False
        self.failure = lambda args: args[:2] == [core.SYSTEMCTL, 'stop']
        self.assertEqual(self.call('start-fresh'), 124)
        self.assertIn('containment unverified', self.stderr.getvalue())

    # -- #368 first-failure bundle: offline orchestration fakes only. They do not show
    #    native systemd scheduling, real journald namespace retention or VLAB readiness.
    def bundle(self):
        return json.loads((core.ROOT / core.FIRST_FAILURE).read_bytes())

    def raw_section(self, name):
        return base64.b64decode(self.bundle()[name]['output'], validate=True)

    def ready_failure(self):
        return patch.object(core, 'unit_ready', side_effect=core.Failure('synthetic ready failure', 17))

    def journal_argv(self, invocation):
        unit = core.UNIT['fresh']
        return [core.JOURNALCTL, '--no-pager', '--namespace=labapp-vlab', '--lines=64',
                '--output=short-monotonic', '_BOOT_ID=' + core.boot().replace('-', ''),
                '_SYSTEMD_INVOCATION_ID=' + invocation, '_SYSTEMD_UNIT=' + unit]

    def test_unit_failure_binds_original_invocation_with_exact_fixed_queries(self):
        self.prepared()
        before = time.monotonic()
        with self.ready_failure():
            self.assertEqual(self.call('start-fresh'), 17)  # primary outer status unchanged
        value, bundle = core.state(), self.bundle()
        self.assertEqual((bundle['stage'], bundle['mode'], bundle['nonce'], bundle['operation'],
                          bundle['invocation'], bundle['boot'], bundle['query_cleanup']),
                         ('unit', 'fresh', 'b' * 32, value['operation'], 'a' * 32, core.boot(), 'confirmed'))
        self.assertEqual(bundle['primary'], {'message': 'synthetic ready failure', 'code': 17,
                                             'status': 'unavailable', 'output': ''})
        self.assertEqual([d[0] for d in self.diagnostics], [
            [core.SYSTEMCTL, 'show', core.UNIT['fresh'], '--no-pager', '--property=' + core.MANAGER_PROPERTIES],
            self.journal_argv('a' * 32)])
        self.assertEqual([d[2] for d in self.diagnostics], [2048, 8192])
        self.assertTrue(all(d[1] <= before + core.SNAPSHOT_SECONDS + 1 for d in self.diagnostics))
        self.assertEqual((bundle['manager']['status'], bundle['journal']['status']), ('ok', 'ok'))
        self.assertIn(SENTINEL.encode(), self.raw_section('journal'))
        self.assertEqual(stat.S_IMODE((core.ROOT / core.FIRST_FAILURE).stat().st_mode), 0o600)
        self.assertEqual(core.state()['containment'], 'verified')
        self.assertNotIn(SENTINEL, self.stdout.getvalue() + self.stderr.getvalue())

    def test_bundle_precedes_cleanup_and_survives_overwrite_or_cleanup_failure(self):
        self.prepared()
        actual, seen = core.cleanup_start, []
        def spy(value, deadline):
            seen.append((core.ROOT / core.FIRST_FAILURE).read_bytes())
            core.retain_failure_output(b'CLEANUP-OVERWRITE')  # what a later command failure would do
            raise core.Failure('synthetic cleanup failure', 29)
        with self.ready_failure(), patch.object(core, 'cleanup_start', side_effect=spy):
            self.assertEqual(self.call('start-fresh'), 17)
        self.assertEqual(len(seen), 1)
        self.assertEqual((core.ROOT / core.FIRST_FAILURE).read_bytes(), seen[0])
        self.assertEqual((core.ROOT / 'last-command-output').read_bytes(), b'CLEANUP-OVERWRITE')
        self.assertIn('containment unverified', self.stderr.getvalue())

    def test_manager_wrapper_preserves_observed_inner_context_then_cleanup_cannot_overwrite_bundle(self):
        self.prepared()
        actual = self.command
        inner = ('OBSERVED-INNER-' + SENTINEL).encode()
        wrapper = b'generic manager failed'
        class Selector:
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def register(self, *_): pass
            def select(self, *_): return [True]
        child = SimpleNamespace(pid=4242, stdout=SimpleNamespace(fileno=lambda: 123, close=lambda: None),
                                wait=lambda **_: 1, poll=lambda: 1)
        def command(argv, deadline, cap=30, user=False, *, retain=True):
            if argv[:2] == [core.SYSTEMCTL, 'start']:
                self.assertFalse(retain)  # actual start consumer disables only wrapper retention
                core.retain_failure_output(inner)
                with patch.object(core.subprocess, 'Popen', return_value=child), \
                     patch.object(core.selectors, 'DefaultSelector', Selector), \
                     patch.object(core.os, 'read', side_effect=[wrapper, b'']), \
                     patch.object(core.os, 'killpg', side_effect=ProcessLookupError):
                    return EXECUTE(argv, deadline, cap, user, retain=retain)
            return actual(argv, deadline, cap, user, retain=retain)
        def cleanup(*_):
            self.assertEqual(self.raw_section('command_context'), inner)
            core.retain_failure_output(b'CLEANUP-OVERWRITE')
            raise core.Failure('synthetic cleanup failure', 29)
        with patch.object(core, 'execute', side_effect=command), \
             patch.object(core, 'cleanup_start', side_effect=cleanup):
            self.assertEqual(self.call('start-fresh'), 1)
        self.assertEqual(self.raw_section('primary'), wrapper)
        self.assertEqual(self.raw_section('command_context'), inner)
        self.assertEqual(self.bundle()['command_context']['label'], core.FAILURE_CONTEXT)
        self.assertEqual((core.ROOT / 'last-command-output').read_bytes(), b'CLEANUP-OVERWRITE')
        self.assertNotIn(SENTINEL, self.stdout.getvalue() + self.stderr.getvalue())

    def test_command_context_fixed_reader_refuses_missing_foreign_links_and_replacement(self):
        self.prepared()
        self.assertEqual(core.last_failure_context(), ('unavailable', b''))
        path = core.ROOT / 'last-command-output'
        core.retain_failure_output(b'x' * 4096 + b'TAIL')
        status, raw = core.last_failure_context()
        self.assertEqual((status, len(raw), raw[-4:]), ('truncated', 2048, b'TAIL'))
        path.chmod(0o640)
        self.assertEqual(core.last_failure_context(), ('unavailable', b''))
        path.chmod(0o600)
        alias = self.base / 'alias'
        os.link(path, alias)
        self.assertEqual(core.last_failure_context(), ('unavailable', b''))
        alias.unlink()
        with patch.object(core, 'stable_stat', side_effect=[1, 2]):
            self.assertEqual(core.last_failure_context(), ('unavailable', b''))
        path.unlink()
        path.symlink_to(self.fab_path)
        self.assertEqual(core.last_failure_context(), ('unavailable', b''))

    def test_manager_primary_output_survives_without_adopting_stale_unbound_manager_evidence(self):
        self.prepared()
        actual = self.command
        self.diag = lambda argv: ('ok', b'InvocationID=' + b'e' * 32 +
                                  b'\nExecMainStatus=29\nResult=' + SENTINEL.encode(), False, 'confirmed')
        def wrapped(argv, *args, **kwargs):
            if argv[:2] == [core.SYSTEMCTL, 'start']:
                raise core.Failure('child command failed', 1, b'Job for unit failed\n' + SENTINEL.encode())
            return actual(argv, *args, **kwargs)
        with patch.object(core, 'execute', side_effect=wrapped):
            self.assertEqual(self.call('start-fresh'), 1)
        bundle = self.bundle()
        self.assertIsNotNone(bundle['operation'])  # reservation committed, but no proven invocation
        self.assertEqual((bundle['stage'], bundle['invocation'], bundle['journal']['status'],
                          bundle['primary']['status']), ('manager', None, 'unavailable', 'ok'))
        self.assertEqual(self.raw_section('primary'), b'Job for unit failed\n' + SENTINEL.encode())
        self.assertEqual(bundle['manager'], {'status': 'unavailable', 'output': ''})
        self.assertEqual(self.diagnostics, [])  # neither stale manager nor journal history is queried
        self.assertNotIn(SENTINEL, self.stdout.getvalue() + self.stderr.getvalue())

    def test_reservation_refusal_cannot_capture_an_older_operation(self):
        self.prepared()
        stale = core.state()
        stale.update(phase='failed', mode='fresh', operation='c' * 32, invocation='d' * 32)
        core.save(stale)
        self.assertEqual(self.call('start-fresh'), 1)
        self.assertFalse((core.ROOT / core.FIRST_FAILURE).exists())
        self.assertEqual(self.diagnostics, [])
        self.assertEqual(core.state(), stale)
        self.assertFalse(any(c[0][:2] in ([core.SYSTEMCTL, 'start'], [core.SYSTEMCTL, 'stop']) for c in self.calls))

    def test_manager_identity_mismatch_or_gc_never_selects_other_history(self):
        for reported, status in (('e' * 32, 'invalid'), ('', 'unavailable')):
            with self.subTest(reported=reported):
                self.setUp()
                self.prepared()
                self.diag = lambda argv, r=reported: (
                    ('ok', ('InvocationID=' + r + '\nResult=' + SENTINEL + '\n').encode(), False, 'confirmed')
                    if argv[0] == core.SYSTEMCTL else ('ok', b'ORIGINAL-INVOCATION-LINES', False, 'confirmed'))
                with self.ready_failure():
                    self.assertEqual(self.call('start-fresh'), 17)
                bundle = self.bundle()
                self.assertEqual((bundle['manager']['status'], bundle['manager']['output']), (status, ''))
                # Journal still keyed only by the frozen original boot + invocation + unit.
                self.assertEqual(self.diagnostics[1][0], self.journal_argv('a' * 32))
                self.assertEqual(bundle['journal']['status'], 'ok')

    def test_capture_failure_or_query_uncertainty_never_changes_primary_or_skips_cleanup(self):
        for name in ('query raises', 'write fails', 'uncertain'):
            with self.subTest(name):
                self.setUp()
                self.prepared()
                patches = []
                if name == 'query raises':
                    self.diag = lambda argv: (_ for _ in ()).throw(RuntimeError(SENTINEL))
                elif name == 'write fails':
                    patches.append(patch.object(core, 'write_first_failure', side_effect=OSError(SENTINEL)))
                else:
                    self.diag = lambda argv: ('unavailable', b'', False, 'uncertain')
                with ExitStack() as local:
                    for item in patches:
                        local.enter_context(item)
                    local.enter_context(self.ready_failure())
                    self.assertEqual(self.call('start-fresh'), 17)
                self.assertEqual((core.state()['phase'], core.state()['containment']), ('failed', 'verified'))
                if name == 'uncertain':
                    self.assertEqual(self.bundle()['query_cleanup'], 'uncertain')
                else:
                    self.assertFalse((core.ROOT / core.FIRST_FAILURE).exists())
                    self.assertIn('first-failure capture unverified', self.stderr.getvalue())
                self.assertNotIn(SENTINEL, self.stdout.getvalue() + self.stderr.getvalue())

    def test_first_failure_wins_and_later_reservation_refusal_cannot_overwrite_it(self):
        self.prepared()
        with self.ready_failure():
            self.assertEqual(self.call('start-fresh'), 17)
        first = (core.ROOT / core.FIRST_FAILURE).read_bytes()
        self.assertEqual(self.call('start-fresh'), 1)  # later reservation refusal
        self.assertEqual((core.ROOT / core.FIRST_FAILURE).read_bytes(), first)
        self.assertFalse((core.ROOT / (core.FIRST_FAILURE + '.new')).exists())

    def test_preplaced_first_failure_symlink_is_not_followed_or_overwritten(self):
        self.prepared()
        # A pre-placed symlink (replacement) is neither followed nor overwritten.
        foreign = self.base / 'foreign'
        foreign.write_bytes(b'FOREIGN')
        (core.ROOT / core.FIRST_FAILURE).symlink_to(foreign)
        self.diagnostics.clear()
        with self.ready_failure():
            self.assertEqual(self.call('start-fresh'), 17)
        self.assertEqual(foreign.read_bytes(), b'FOREIGN')
        self.assertTrue((core.ROOT / core.FIRST_FAILURE).is_symlink())
        self.assertEqual(self.diagnostics, [])

    def test_serialized_bundle_is_bounded_for_hostile_bytes_and_escapes(self):
        self.prepared()
        actual = self.command
        def wrapped(argv, *args, **kwargs):
            if argv[:2] == [core.SYSTEMCTL, 'start']:
                raise core.Failure('child command failed "\\ \\u0000"', 1, b'\xff"\\\x00' * (1 << 18))
            return actual(argv, *args, **kwargs)
        self.diag = lambda argv: ('ok', b'\xff"\\\x00' * 50000, False, 'confirmed')
        with patch.object(core, 'execute', side_effect=wrapped):
            self.assertEqual(self.call('start-fresh'), 1)
        raw = (core.ROOT / core.FIRST_FAILURE).read_bytes()
        self.assertLessEqual(len(raw), core.FIRST_FAILURE_LIMIT)
        bundle = json.loads(raw)
        self.assertEqual((bundle['primary']['status'], bundle['manager']['status']), ('truncated', 'unavailable'))
        for name, cap in core.FAILURE_CAPS.items():
            self.assertLessEqual(len(base64.b64decode(bundle[name]['output'], validate=True)), cap)

    @contextmanager
    def diagnostic_fixture(self, *, late=None, code=0, ownership='owned', persistent=False,
                           hold_pipe=False, signal_error=None, wait_timeout=False, spawn_error=False):
        """Actual runner + actual OwnedGroup, entirely mocked kernel/process/clock/I/O."""
        late = late or {}
        now, events, chunks = [0.0], [], [b'a' * 1000 + b'TAIL', b'']
        proc = SimpleNamespace(pid=4242, returncode=None, reaped=False)
        def tick():
            now[0] += .001
            return now[0]
        def advance(point):
            now[0] += late.get(point, 0)
        def waitid(kind, pid, options):
            self.assertEqual((kind, pid, options), (os.P_PID, 4242, os.WEXITED | os.WNOHANG | os.WNOWAIT))
            self.assertFalse(proc.reaped)
            events.append(('observe',))
            if ownership == 'lost':
                raise ChildProcessError
            return SimpleNamespace(si_pid=4243 if ownership == 'foreign' else 4242,
                                   si_code=os.CLD_EXITED, si_status=code)
        def killpg(pid, number):
            self.assertEqual(pid, 4242)
            self.assertTrue(number == 0 or not proc.reaped, 'destructive signal after reap')
            events.append(('signal', number))
            advance('probe' if number == 0 else 'signal')
            if number == 0:
                if not persistent:
                    raise ProcessLookupError
            elif signal_error is not None:
                raise signal_error
        def wait(timeout):
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 8 - now[0])
            self.assertFalse(proc.reaped)
            events.append(('reap',))
            advance('reap')
            if wait_timeout:
                raise subprocess.TimeoutExpired('fixed fixture', timeout)
            proc.reaped, proc.returncode = True, code
            return code
        def close():
            events.append(('pipe-close',))
            advance('pipe-close')
        proc.stdout = SimpleNamespace(fileno=lambda: 123, close=close)
        proc.wait = wait
        def popen(argv, **kwargs):
            self.assertEqual(argv, [core.JOURNALCTL, '--fixed-fixture'])
            self.assertEqual(kwargs, dict(cwd='/', env=core.SAFE_ENV, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True))
            events.append(('spawn',))
            advance('spawn')
            if spawn_error:
                raise OSError
            return proc
        class Selector:
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def register(self, stream, event):
                self_test.assertIs(stream, proc.stdout)
                self_test.assertEqual(event, core.selectors.EVENT_READ)
            def select(self, timeout):
                self_test.assertGreater(timeout, 0)
                if hold_pipe:
                    now[0] += timeout
                    return []
                advance('select')
                return [True]
        self_test = self
        with ExitStack() as stack:
            for target, name, value in ((core.subprocess, 'Popen', popen),
                                        (core.selectors, 'DefaultSelector', Selector),
                                        (core.os, 'read', lambda *_: chunks.pop(0)),
                                        (core.os, 'waitid', waitid), (core.os, 'killpg', killpg),
                                        (core.time, 'monotonic', tick),
                                        (core.time, 'sleep', lambda seconds: now.__setitem__(0, now[0] + seconds)),
                                        (core.owned_process, 'monotonic', tick),
                                        (core.owned_process, 'sleep', lambda seconds: now.__setitem__(0, now[0] + seconds))):
                stack.enter_context(patch.object(target, name, value))
            yield events, lambda end=8: DIAGNOSTIC_RUN([core.JOURNALCTL, '--fixed-fixture'], end, 100)

    def test_diagnostic_runner_anchors_leader_until_kill_then_sole_reap_and_esrch(self):
        with self.diagnostic_fixture() as (events, run):
            status, raw, truncated, cleanup = run()
        self.assertEqual((status, truncated, cleanup, len(raw)), ('truncated', True, 'confirmed', 100))
        self.assertTrue(raw.endswith(b'TAIL'))
        reap = events.index(('reap',))
        self.assertIn(('signal', signal.SIGKILL), events[:reap])
        self.assertEqual(events[reap + 1:], [('signal', 0), ('pipe-close',)])
        self.assertEqual(events.count(('reap',)), 1)

    def test_diagnostic_runner_requires_positive_reap_and_group_absence(self):
        for changes, expected in ((dict(code=3), ('unavailable', 'confirmed')),
                                  (dict(hold_pipe=True), ('unavailable', 'confirmed')),
                                  (dict(persistent=True), ('truncated', 'uncertain')),
                                  (dict(wait_timeout=True), ('truncated', 'uncertain')),
                                  (dict(signal_error=ProcessLookupError()), ('truncated', 'uncertain')),
                                  (dict(signal_error=PermissionError()), ('truncated', 'uncertain'))):
            with self.subTest(changes=changes), self.diagnostic_fixture(**changes) as (_, run):
                result = run()
                self.assertEqual((result[0], result[3]), expected)

    def test_diagnostic_runner_refuses_signals_after_ownership_loss(self):
        for ownership in ('lost', 'foreign'):
            with self.subTest(ownership=ownership), self.diagnostic_fixture(ownership=ownership) as (events, run):
                self.assertEqual(run()[3], 'uncertain')
                self.assertFalse(any(event[0] == 'signal' for event in events))

    def test_diagnostic_runner_never_renews_budget_and_late_steps_are_uncertain(self):
        for point in ('spawn', 'select', 'signal', 'reap', 'probe', 'pipe-close'):
            with self.subTest(point=point), self.diagnostic_fixture(late={point: 9}) as (events, run):
                self.assertEqual(run(), ('unavailable', b'', point not in ('spawn', 'select'), 'uncertain'))
                if point == 'spawn':
                    self.assertEqual(events, [('spawn',), ('pipe-close',)])
                if point == 'signal':
                    self.assertNotIn(('reap',), events)
        with self.diagnostic_fixture(spawn_error=True, late={'spawn': 9}) as (_, run):
            self.assertEqual(run()[3], 'uncertain')
        with self.diagnostic_fixture() as (events, run):
            self.assertEqual(run(end=.5), ('unavailable', b'', False, 'confirmed'))
            self.assertEqual(events, [])

    def test_capture_fully_skips_after_original_work_deadline(self):
        self.prepared()
        with patch.object(core, 'state', side_effect=AssertionError('no read after cutoff')), \
             patch.object(core, 'write_first_failure', side_effect=AssertionError('no write after cutoff')):
            core.capture_first_failure('fresh', None, core.Failure(), time.monotonic() - 1)
        self.assertEqual(self.diagnostics, [])

    def test_public_start_preserves_int_and_term_over_cleanup_failure(self):
        self.prepared()
        prepared = core.state()
        actual = self.command
        for error, code in ((KeyboardInterrupt(), 130), (core.Failure('terminated', 143), 143)):
            core.save(copy.deepcopy(prepared))
            def interrupted(argv, *args, **kwargs):
                if argv[:2] == [core.SYSTEMCTL, 'start']:
                    raise error
                if argv[:2] == [core.SYSTEMCTL, 'stop']:
                    raise core.Failure('synthetic secondary stop failure', 29)
                return actual(argv, *args, **kwargs)
            with self.subTest(code=code), patch.object(core, 'execute', side_effect=interrupted):
                self.assertEqual(self.call('start-fresh'), code)
            self.assertIn('containment unverified', self.stderr.getvalue())
        self.assertNotIn('PUBLIC_SYNTHETIC', self.stdout.getvalue() + self.stderr.getvalue())

    def test_failed_start_retains_controller_through_final_failure_commit(self):
        self.resumable()
        actual = self.command
        actual_stop = core._stop_owned_locked
        blocked = []
        def interleave(argv, *args, **kwargs):
            raw = actual(argv, *args, **kwargs)
            if argv[:3] == [core.SYSTEMCTL, 'start', core.UNIT['resume']]:
                raise core.Failure('synthetic late client failure', 17)
            return raw
        def after_verified_stop(*args, **kwargs):
            result = actual_stop(*args, **kwargs)
            with self.assertRaises(core.Failure):
                core.reserve('resume')
            blocked.append(True)
            return result
        with patch.object(core, 'execute', side_effect=interleave), \
             patch.object(core, '_stop_owned_locked', side_effect=after_verified_stop):
            self.assertEqual(self.call('start-resume'), 17)
        self.assertEqual(blocked, [True])
        self.assertEqual(core.state()['phase'], 'failed')
        self.assertEqual(core.state()['containment'], 'verified')

    def test_missing_each_critical_artifact_prevents_resume_up(self):
        saved = self.resumable()
        paths = [name for name, rec in saved['critical'].items() if stat.S_ISREG(rec['mode'])]
        for name in paths:
            with self.subTest(path=name):
                target = core.WORK / name
                moved = target.with_name(target.name + '.held')
                target.rename(moved)
                before = len(self.calls)
                self.assertNotEqual(self.call('start-resume'), 0)
                self.assertFalse(any(c[0][:2] == [core.SYSTEMCTL, 'start'] for c in self.calls[before:]))
                moved.rename(target)
        self.assertEqual(core.state()['phase'], 'resumable')

    def test_replaced_disk_identity_refused_but_disk_writes_allowed(self):
        self.resumable()
        disk = core.WORK / 'vlab/vms/server-01/os.img'
        with disk.open('ab') as stream:
            stream.write(b'ordinary guest write')
        self.assertEqual(self.call('start-resume'), 0, self.stderr.getvalue())
        self.assertEqual(self.call('stop'), 0)
        held = disk.with_name('old-disk')
        disk.rename(held)
        disk.write_bytes(held.read_bytes())
        disk.chmod(0o600)
        self.assertEqual(self.call('start-resume'), 1)
        self.assertEqual(core.state()['phase'], 'resumable')

    def test_symlinked_critical_file_refused(self):
        self.resumable()
        key = core.WORK / 'vlab/sshkey'
        key.rename(key.with_name('saved-key'))
        key.symlink_to(key.with_name('saved-key'))
        self.assertEqual(self.call('start-resume'), 1)

    def test_optional_mutable_and_generated_symlinks_refused_before_up(self):
        self.resumable()
        foreign = self.base / 'foreign-output'
        foreign.write_bytes(b'foreign data')
        for relative in ('vlab/vms/server-01/serial.log', 'vlab/vms/server-01/serial.sock',
                         'vlab/vms/server-01/mon.sock', 'vlab/vms/server-01/qmp.sock',
                         'vlab/kubeconfig', 'vlab/sshkey.pub'):
            target = core.WORK / relative
            retained = self.base / 'retained-output'
            existed = target.exists()
            if existed:
                target.rename(retained)
            target.symlink_to(foreign)
            before = len(self.execs)
            self.assertEqual(self.call('start-resume'), 1)
            self.assertEqual(len(self.execs), before)
            self.assertEqual(foreign.read_bytes(), b'foreign data')
            target.unlink()
            if existed:
                retained.rename(target)

    def test_optional_log_and_mutable_disk_hardlinks_refused_before_up(self):
        self.resumable()
        foreign = self.base / 'foreign-log'
        foreign.write_bytes(b'preserve external data')
        log = core.WORK / 'vlab/vms/server-01/serial.log'
        os.link(foreign, log)
        before = len(self.execs)
        self.assertEqual(self.call('start-resume'), 1)
        self.assertEqual(len(self.execs), before)
        self.assertEqual(foreign.read_bytes(), b'preserve external data')
        log.unlink()
        os.link(core.WORK / 'vlab/vms/server-01/os.img', self.base / 'external-disk-alias')
        self.assertEqual(self.call('start-resume'), 1)
        self.assertEqual(len(self.execs), before)

    def test_optional_runtime_wrong_type_owner_and_write_permissions_refused(self):
        self.resumable()
        log = core.WORK / 'vlab/vms/server-01/serial.log'
        log.mkdir()
        self.assertEqual(self.call('start-resume'), 1)
        log.rmdir()
        log.write_text('mutable public log')
        log.chmod(0o666)
        self.assertEqual(self.call('start-resume'), 1)
        log.chmod(0o600)
        original = Path.lstat
        def different_owner(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            if path == log:
                fields = list(value)
                fields[4] = self.user.pw_uid + 1
                return os.stat_result(fields)
            return value
        with patch.object(Path, 'lstat', autospec=True, side_effect=different_owner):
            self.assertEqual(self.call('start-resume'), 1)
        log.unlink()
        socket_path = core.WORK / 'vlab/vms/server-01/mon.sock'
        socket_path.write_bytes(b'not a socket')
        socket_path.chmod(0o600)
        self.assertEqual(self.call('start-resume'), 1)

    def test_optional_owned_log_and_recreated_socket_observations_are_allowed(self):
        self.resumable()
        log = core.WORK / 'vlab/vms/server-01/serial.log'
        log.write_text('public mutable log')
        log.chmod(0o600)
        socket_path = core.WORK / 'vlab/vms/server-01/mon.sock'
        socket_path.write_bytes(b'public synthetic socket observation')
        socket_path.chmod(0o600)
        original = Path.lstat
        def socket_observation(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            if path == socket_path:
                fields = list(value)
                fields[0] = stat.S_IFSOCK | 0o700
                return os.stat_result(fields)
            return value
        with patch.object(Path, 'lstat', autospec=True, side_effect=socket_observation):
            core.optional_runtime_paths()
        socket_path.unlink()
        self.assertEqual(self.call('start-resume'), 0, self.stderr.getvalue())

    def test_generated_kubeconfig_private_permissions_and_unit_modes_are_checked(self):
        self.resumable()
        (core.WORK / 'vlab/kubeconfig').chmod(0o644)
        self.assertEqual(self.call('start-resume'), 1)
        (core.WORK / 'vlab/kubeconfig').chmod(0o600)
        (core.UNITS / core.UNIT['resume']).chmod(0o666)
        self.assertEqual(self.call('start-resume'), 1)
        (core.UNITS / core.UNIT['resume']).chmod(0o644)
        core.JOURNAL.chmod(0o666)
        self.assertEqual(self.call('start-resume'), 1)

    def test_changed_cached_input_hash_refused(self):
        self.resumable()
        target = core.WORK / ('result/' + core.RESULT + '.inhash')
        target.write_bytes(b'B' * 43 + b'=')
        self.assertEqual(self.call('start-resume'), 1)

    def test_unknown_result_entry_is_preserved_and_refused(self):
        self.resumable()
        target = core.WORK / 'result/foreign'
        target.write_text('foreign')
        self.assertEqual(self.call('start-resume'), 1)
        self.assertEqual(target.read_text(), 'foreign')

    def test_bad_canonical_nic_reciprocity_refused(self):
        self.resumable()
        cfg = core.yaml_documents((core.WORK / 'vlab/config.yaml').read_bytes())[0]
        cfg['vms']['server-01']['nics']['enp2s1'] = 'direct:leaf-03/E1/1'
        dump(core.WORK / 'vlab/config.yaml', cfg)
        with self.assertRaises(core.Failure):
            core.vm_config()
        self.assertEqual(self.call('start-resume'), 1)

    def test_changed_cluster_uid_refuses_resume_readiness(self):
        self.resumable()
        self.cluster_uid = 'different-cluster'
        self.assertEqual(self.call('start-resume'), 1)
        self.assertEqual(core.state()['phase'], 'failed')

    def test_resume_pending_api_transport_then_healthy_keeps_original_deadline(self):
        self.resumable()
        actual = self.command
        attempts = []
        pending = [2]
        def discovering(argv, deadline, *args, **kwargs):
            if argv[0] == core.KUBECTL and '--raw=/readyz' in argv:
                attempts.append(deadline)
                if pending[0]:
                    pending[0] -= 1
                    raise core.Failure('child command failed', 1,
                        b'The connection to the server 127.0.0.1:6443 was refused - '
                        b'did you specify the right host or port?\n')
            return actual(argv, deadline, *args, **kwargs)
        with patch.object(core, 'execute', side_effect=discovering), \
             patch.object(core.time, 'sleep') as pause:
            self.assertEqual(self.call('start-resume'), 0, self.stderr.getvalue())
        self.assertEqual(pause.call_count, 2)
        self.assertEqual(len(set(attempts)), 1)
        self.assertEqual(attempts[0], core.state()['deadline'])
        self.assertEqual(core.state()['deadline'] - core.state()['started'], 900)

    def test_api_permanent_auth_tls_and_unknown_error_are_terminal(self):
        self.resumable()
        initial = core.state()
        actual = self.command
        for output in (b'error: You must be logged in to the server (Unauthorized)\n',
                       b'Unable to connect to the server: tls: failed to verify certificate: x509\n',
                       b'Error from server (Forbidden): public synthetic denial\n',
                       b'unknown failure\n'):
            core.save(copy.deepcopy(initial))
            def denied(argv, *args, **kwargs):
                if argv[0] == core.KUBECTL:
                    raise core.Failure('child command failed', 1, output)
                return actual(argv, *args, **kwargs)
            with self.subTest(output=output), patch.object(core, 'execute', side_effect=denied), \
                 patch.object(core.time, 'sleep') as pause:
                self.assertEqual(self.call('start-resume'), 1)
                pause.assert_not_called()
            self.assertEqual(core.state()['phase'], 'failed')
        self.assertNotIn('synthetic denial', self.stdout.getvalue() + self.stderr.getvalue())

    def test_changed_ca_refuses_resume_readiness(self):
        self.resumable()
        path = core.WORK / 'vlab/kubeconfig'
        cfg = core.yaml_documents(path.read_bytes())[0]
        cfg['clusters'][0]['cluster']['certificate-authority-data'] = base64.b64encode(
            b'-----BEGIN CERTIFICATE-----DIFFERENT_PUBLIC_CA').decode()
        dump(path, cfg)
        self.assertEqual(self.call('start-resume'), 1)

    def test_api_canonical_count_and_spec_refusal(self):
        self.fresh()
        for mutation in (lambda items: items.pop() if items else None,
                         lambda items: items[0].setdefault('spec', {}).update({'foreign': True}) if items else None):
            with self.subTest(mutation=mutation):
                self.api_mutation = mutation
                with self.assertRaises(core.Failure):
                    core.api_ready(core.time.monotonic() + 10)

    def test_kubeconfig_executable_or_insecure_fields_refused(self):
        self.fresh()
        original = core.yaml_documents((core.WORK / 'vlab/kubeconfig').read_bytes())[0]
        for key, value in (('exec', {'command': '/bad'}), ('auth-provider', {}), ('token', 'public')):
            cfg = copy.deepcopy(original)
            cfg['users'][0]['user'][key] = value
            dump(core.WORK / 'vlab/kubeconfig', cfg)
            with self.assertRaises(core.Failure):
                core.kubeconfig()
        cfg = copy.deepcopy(original)
        cfg['clusters'][0]['cluster']['insecure-skip-tls-verify'] = True
        dump(core.WORK / 'vlab/kubeconfig', cfg)
        with self.assertRaises(core.Failure):
            core.kubeconfig()

    def test_resume_readonly_mount_is_checked_before_exec(self):
        self.resumable()
        core.MOUNTINFO.write_text('1 0 0:1 / / rw - ext4 /dev/public rw\n')
        self.assertEqual(self.call('start-resume'), 1)
        self.assertEqual(core.state()['phase'], 'failed')

    def test_unit_source_change_or_journal_override_refused(self):
        self.prepared()
        (core.UNITS / core.UNIT['fresh']).write_text('[Service]\nExecStart=/bad\n')
        self.assertEqual(self.call('start-fresh'), 1)
        (core.UNITS / core.UNIT['fresh']).write_bytes((core.LIB / core.UNIT['fresh']).read_bytes())
        core.JOURNAL_DROPINS[0].mkdir()
        (core.JOURNAL_DROPINS[0] / 'foreign.conf').write_text('[Journal]\nForwardToConsole=yes\n')
        self.assertEqual(self.call('start-fresh'), 1)

    def test_loaded_dropin_or_stale_manager_refused(self):
        self.prepared()
        real = self.command
        for replacement in (b'DropInPaths=/foreign.conf', b'NeedDaemonReload=yes'):
            def altered(argv, *a, **kw):
                raw = real(argv, *a, **kw)
                if argv[:2] == [core.SYSTEMCTL, 'show']:
                    raw = raw.replace(b'DropInPaths=', replacement) if replacement.startswith(b'DropIn') else raw.replace(b'NeedDaemonReload=no', replacement)
                return raw
            with patch.object(core, 'execute', side_effect=altered):
                self.assertEqual(self.call('start-fresh'), 1)

    def test_fixed_deadline_never_renews(self):
        self.prepared()
        value = core.reserve('fresh')
        self.assertEqual(value['deadline'] - value['started'], 2700)
        value['deadline'] = core.time.monotonic() - 1
        value['started'] = value['deadline'] - 2700
        core.save(value)
        with self.assertRaises(core.Failure) as raised:
            core.unit_gate('fresh')
        self.assertEqual(raised.exception.code, 124)

    def test_private_input_hash_unknown_keys_and_permissions(self):
        for mutation in (lambda c: c.update(extra='unexpected'),
                         lambda c: c.update(fab_sha256='0' * 64),
                         lambda c: c.update(dedicated_guest=False)):
            original = copy.deepcopy(self.contract)
            mutation(self.contract)
            self.write_contract()
            self.assertEqual(self.call('prepare', '--input', str(self.input)), 1)
            self.assertFalse(core.ROOT.exists())
            self.contract = original
        self.write_contract()
        self.input.chmod(0o644)
        self.assertEqual(self.call('prepare', '--input', str(self.input)), 1)

    def test_original_development_credentials_and_wrong_candidates_refused(self):
        for mutate in (lambda docs: docs[0]['spec']['config']['control'].update(joinToken=''),
                       lambda docs: docs[0]['spec']['config']['control']['defaultUser'].update(password=core.DEV_PASSWORD),
                       lambda docs: docs[0]['spec']['config']['registry'].update(mode='upstream'),
                       lambda docs: docs[0]['spec']['config']['control'].update(controlVIP='10.0.0.1/32')):
            docs = copy.deepcopy(self.fab)
            mutate(docs)
            with self.assertRaises(core.Failure):
                core.validate_fab(yaml.safe_dump_all(docs).encode())

    def test_conflicting_invocation_not_stopped(self):
        self.fresh()
        self.invocation['fresh'] = 'c' * 32
        before = len(self.calls)
        self.assertEqual(self.call('stop'), 1)
        self.assertFalse(any(c[0][:2] == [core.SYSTEMCTL, 'stop'] for c in self.calls[before:]))

    def test_populated_exact_cgroup_is_uncertain(self):
        self.fresh()
        group = core.CGROUP / 'system.slice' / core.UNIT['fresh']
        group.mkdir(parents=True)
        (group / 'cgroup.events').write_text('populated 1\nfrozen 0\n')
        self.assertEqual(self.call('stop'), 1)
        self.assertTrue((group / 'cgroup.events').exists())

    def test_direct_boot_resume_only_uses_sealed_resumable_state(self):
        self.resumable()
        self.phase['resume'] = 'activating'
        self.invocation['resume'] = 'a' * 32
        self.assertEqual(self.call('unit-gate', '--mode', 'resume'), 0)
        value = core.state()
        self.assertEqual(value['phase'], 'starting')
        self.assertEqual(value['mode'], 'resume')
        self.assertEqual(value['deadline'] - value['started'], 900)
        self.assertEqual(self.call('unit-gate', '--mode', 'resume'), 1)

    def test_direct_boot_resume_preserves_deadline_at_clock_precision_boundary(self):
        self.resumable()
        self.phase['resume'] = 'activating'
        self.invocation['resume'] = 'a' * 32
        now = float.fromhex('0x1.0000000000003p+7')
        end = now + 900
        self.assertNotEqual(end - now, 900)
        with patch.object(core.time, 'monotonic', return_value=now):
            self.assertEqual(self.call('unit-gate', '--mode', 'resume'), 0,
                             self.stderr.getvalue())
            value = core.state()
            self.assertEqual(value['phase'], 'starting')
            self.assertEqual(value['mode'], 'resume')
            self.assertEqual(value['deadline'], end)
            self.assertEqual(value['started'], end - 900)
            self.assertEqual(value['deadline'] - value['started'], 900)
            self.assertEqual(self.call('unit-gate', '--mode', 'resume'), 1)
            self.assertEqual(core.state(), value)


ABSENT = b'Device "hhbr" does not exist.\n'
OLD_DIAGNOSTIC = b'OLD-DIAGNOSTIC-' + SENTINEL.encode()


def bridge_json(index=42, **link):
    value = {'ifname': 'hhbr', 'ifindex': index, 'linkinfo': {'info_kind': 'bridge'}}
    value.update(link)
    return json.dumps([value]).encode()


def absent():
    return core.Failure('child command failed', 1, ABSENT)


class BridgePrerequisiteMixin(GuestEnvironment):
    """Actual unit_ready and bridge poll; only external commands, identity, clock and sleep are fake.

    The pending probe is distinguished by retain=False. No real child, native command or sleep.
    """
    mode = None

    class Stop(BaseException):
        pass

    def bridge_run(self, answers, changes=(), start_offset=None, *, complete=False,
                   final_failure=None, final_link=None):
        """answers: per-probe bytes (stdout) or Failure; the last answer repeats.
        changes: (probe number, callable) applied while that probe is answered."""
        self.live = {}
        self.show_edit = {}
        self.boot_id = ['12345678-1234-1234-1234-123456789abc']
        self.probes = 0
        self.sleeps = []
        self.helper_count = 0
        mode = self.mode
        def identity(fields):
            core.require(fields['MainPID'] != '0', 'main process absent')
            return {'invocation': fields['InvocationID'], 'group': fields['ControlGroup'],
                    'pid': int(fields['MainPID']), 'start': '12345', **self.live}
        def wrapper(argv, deadline, cap=30, user=False, *, retain=True):
            if argv[:5] == ['/usr/sbin/ip', '-j', '-d', 'link', 'show'] and retain is False:
                self.probes += 1
                for number, change in changes:
                    if number == self.probes:
                        change()
                answer = answers[min(self.probes, len(answers)) - 1]
                self.calls.append((list(argv), deadline, cap, user))
                core.remaining(deadline)
                self.assertEqual(cap, 3)
                if isinstance(answer, Exception):
                    raise answer
                return answer
            if argv[:2] == [core.PYTHON, str(core.BRIDGE)]:
                self.helper_count += 1
                if self.helper_count == 2 and final_failure is not None:
                    self.calls.append((list(argv), deadline, cap, user))
                    raise final_failure
            if (final_link is not None and self.helper_count == 2
                    and argv[:5] == ['/usr/sbin/ip', '-j', '-d', 'link', 'show']):
                self.calls.append((list(argv), deadline, cap, user))
                return final_link
            output = self.command(argv, deadline, cap, user, retain=retain)
            if argv[0] == core.SYSTEMCTL and argv[1] == 'show' and self.show_edit:
                fields = dict(line.split('=', 1) for line in output.decode().splitlines())
                fields.update(self.show_edit)
                output = '\n'.join(k + '=' + v for k, v in fields.items()).encode()
            return output
        with patch.object(core, 'service_identity', side_effect=identity), \
             patch.object(core, 'boot', side_effect=lambda: self.boot_id[0]):
            # Fault injection belongs to unit_ready under test, after preparation.
            operation_failure = self.failure
            self.failure = None
            prepared = self.prepared() if mode == 'fresh' else self.resumable()
            self.assertEqual(prepared['phase'], 'prepared' if mode == 'fresh' else 'resumable')
            core.reserve(mode)
            self.phase[mode] = 'activating'
            self.invocation[mode] = os.environ['INVOCATION_ID']
            core.unit_gate(mode)
            if mode == 'fresh':
                self.runtime_files()
            # Preserve setup evidence while excluding it from operation assertions.
            self.preparation_calls = tuple(self.calls)
            self.operation_start = len(self.calls)
            self.assertEqual(sum(c[0][:2] == [core.PYTHON, str(core.BRIDGE)]
                                 for c in self.preparation_calls), 0 if mode == 'fresh' else 2)
            self.failure = operation_failure
            core.retain_failure_output(OLD_DIAGNOSTIC)
            deadline = core.state()['deadline']
            # Full original budget unless the case selects a shorter remaining time.
            now = [deadline - (core.START_SECONDS[mode] if start_offset is None else start_offset)]
            def sleep(seconds):
                self.sleeps.append(seconds)
                now[0] += seconds
            self.now = now
            self.deadline = deadline
            self.initial = core.state()
            actual_save = core.save
            self.commits = []
            def save(value):
                if value['phase'] == 'ready':
                    # Prove the actual final save retains the operation lock.
                    with self.assertRaisesRegex(core.Failure, 'another operation owns the lock'):
                        with core.locked():
                            self.fail('ready commit released the state lock')
                    self.commits.append(copy.deepcopy(value))
                actual_save(value)
            with patch.object(core.time, 'monotonic', side_effect=lambda: now[0]), \
                 patch.object(core.time, 'sleep', side_effect=sleep), \
                 patch.object(core, 'execute', side_effect=wrapper), \
                 patch.object(core, 'api_ready', side_effect=core.api_ready if complete else self.Stop) as api, \
                 patch.object(core, 'save', side_effect=save), \
                 patch.object(core, 'bridge_ready', wraps=core.bridge_ready) as ready:
                self.ready = ready
                self.api = api
                try:
                    core.unit_ready(mode)
                    self.assertTrue(complete)
                    return None
                except self.Stop:
                    return None
                except core.Failure as exc:
                    return exc
        self.fail('unit_ready returned without stopping at the API boundary')

    def operation_calls(self):
        return self.calls[self.operation_start:]

    def helper_calls(self):
        return [c for c in self.operation_calls() if c[0][:2] == [core.PYTHON, str(core.BRIDGE)]]

    def diagnostic_bytes(self):
        return (core.ROOT / 'last-command-output').read_bytes()

    def assertFailedClosed(self, exc, probes, code=None):
        self.assertIsInstance(exc, core.Failure)
        if code is not None:
            self.assertEqual(exc.code, code)
        self.assertEqual(self.probes, probes)
        self.assertFalse(self.helper_calls())
        self.assertNotEqual(core.state()['phase'], 'ready')

    def test_absent_beyond_61_seconds_then_valid_creation(self):
        self.assertIsNone(self.bridge_run([absent()] * 40 + [bridge_json(42)]))
        self.assertEqual(self.probes, 41)
        self.assertGreater(sum(self.sleeps), 61)
        self.assertLess(self.now[0], self.deadline)
        self.assertEqual(len(self.helper_calls()), 1)
        self.ready.assert_called_once_with(self.deadline, 42)
        self.assertEqual(self.diagnostic_bytes(), OLD_DIAGNOSTIC)
        self.assertNotEqual(core.state()['phase'], 'ready')

    def test_immediately_present_needs_no_sleep(self):
        self.assertIsNone(self.bridge_run([bridge_json(42)]))
        self.assertEqual((self.probes, self.sleeps), (1, []))

    def test_cold_absence_then_actual_locked_ready_commit(self):
        self.assertIsNone(self.bridge_run([absent()] * 40 + [bridge_json()], complete=True))
        self.assertGreater(sum(self.sleeps), 61)
        self.assertLess(self.now[0], self.deadline)
        self.assertEqual(self.probes, 41)
        self.assertEqual(len(self.helper_calls()), 2)
        self.assertEqual(self.api.call_count, 2)
        self.assertEqual(self.ready.call_args_list[0].args, (self.deadline, 42))
        self.assertEqual(self.ready.call_args_list[1].args, (self.deadline,))
        value = core.state()
        self.assertEqual(self.commits, [value])
        self.assertEqual(value['phase'], 'ready')
        self.assertEqual(value['deadline'], self.initial['deadline'])
        self.assertEqual(value['started'], self.initial['started'])
        self.assertEqual(value['deadline'] - value['started'], core.START_SECONDS[self.mode])
        self.assertEqual(value['operation'], self.initial['operation'])
        for action in ('wait-switches', 'inspect-switches'):
            self.assertTrue(any(c[0][:3] == [core.HHFAB, 'vlab', action]
                                and c[1] == self.deadline for c in self.operation_calls()))
        self.assertEqual(self.diagnostic_bytes(), OLD_DIAGNOSTIC)

    def test_final_recheck_is_hard_failure_without_prerequisite_wait(self):
        failure = absent()
        exc = self.bridge_run([bridge_json()], complete=True, final_failure=failure)
        self.assertIs(exc, failure)
        self.assertEqual((exc.code, exc.private_output), (1, ABSENT))
        self.assertEqual((self.probes, self.sleeps, self.helper_count), (1, [], 2))
        self.assertEqual(self.ready.call_args_list[-1].args, (self.deadline,))
        self.assertEqual(self.commits, [])
        self.assertNotEqual(core.state()['phase'], 'ready')

    def test_final_recheck_rejects_nonmapping_bridge_data(self):
        for field in ('linkinfo', 'info_data'):
            for malformed in (None, [], 1, 'foreign'):
                with self.subTest(field=field, malformed=malformed):
                    self.setUp()
                    info = malformed if field == 'linkinfo' else {'info_kind': 'bridge', 'info_data': malformed}
                    exc = self.bridge_run([bridge_json()], complete=True,
                                          final_link=bridge_json(linkinfo=info))
                    self.assertIsInstance(exc, core.Failure)
                    self.assertEqual((self.probes, self.sleeps, self.helper_count), (1, [], 2))
                    self.assertEqual(self.commits, [])

    def test_absence_through_original_deadline_fails_124_without_helper(self):
        exc = self.bridge_run([absent()], start_offset=10)
        self.assertFailedClosed(exc, self.probes, 124)
        self.assertGreater(self.probes, 1)
        self.assertLessEqual(self.now[0], self.deadline + 1e-6)
        self.assertEqual(self.diagnostic_bytes(), OLD_DIAGNOSTIC)

    def test_sleep_is_capped_at_original_deadline(self):
        exc = self.bridge_run([absent()], start_offset=0.5)
        self.assertFailedClosed(exc, 1, 124)
        self.assertAlmostEqual(sum(self.sleeps), 0.5)
        self.assertLessEqual(self.now[0], self.deadline + 1e-6)

    def test_expired_clock_refuses_before_any_probe(self):
        exc = self.bridge_run([bridge_json(42)], start_offset=-1)
        self.assertFailedClosed(exc, 0, 124)

    def live_changes(self):
        def state_edit(edit):
            def apply():
                current = core.state()
                edit(current)
                core.save(current)
            return apply
        def show(**fields):
            return lambda: self.show_edit.update(fields)
        return {
            'mainpid-zero-while-activating': show(MainPID='0'),
            'inactive': show(ActiveState='inactive', MainPID='0'),
            'failed': show(ActiveState='failed', MainPID='0'),
            'replaced-pid': show(MainPID='999999'),
            'replaced-start': lambda: self.live.update(start='999'),
            'replaced-invocation': show(InvocationID='c' * 32),
            'replaced-cgroup': show(ControlGroup='/system.slice/other.service'),
            'replaced-unit': show(Id='other.service'),
            'dropin': show(DropInPaths='/run/systemd/system/x.d/y.conf'),
            'daemon-reload': show(NeedDaemonReload='yes'),
            'state-phase': state_edit(lambda s: s.update(phase='failed')),
            'state-extra-field': state_edit(lambda s: s.update(extra=1)),
            'state-service-removed': state_edit(lambda s: s.pop('service')),
            'state-boot': state_edit(lambda s: s.update(boot='f' * 8 + '-' + 'f' * 4 + '-' + 'f' * 4 + '-' + 'f' * 4 + '-' + 'f' * 12)),
            'state-deadline': state_edit(lambda s: s.update(deadline=s['deadline'] + 1)),
            'reboot': lambda: self.boot_id.__setitem__(0, 'abcdef12-1234-1234-1234-123456789abc'),
        }

    def test_live_changes_fail_closed_while_absent_and_right_after_presence(self):
        for name, change in self.live_changes().items():
            with self.subTest(name + ' while absent'):
                self.setUp()  # fresh fixture; earlier cleanups unwind LIFO at test end
                exc = self.bridge_run([absent(), absent(), bridge_json(42)],
                                      [(1, self.live_changes()[name])])
                self.assertFailedClosed(exc, 1)
            with self.subTest(name + ' immediately after presence'):
                self.setUp()
                exc = self.bridge_run([absent(), bridge_json(42)], [(2, self.live_changes()[name])])
                self.assertFailedClosed(exc, 2)

    def genuine_failures(self):
        return {
            'extra-newline': (absent_with(b'Device "hhbr" does not exist.\n\n'), True),
            'altered-name': (absent_with(b'Device "hhbx" does not exist.\n'), True),
            'missing-newline': (absent_with(b'Device "hhbr" does not exist.'), True),
            'exit-2': (core.Failure('child command failed', 2, ABSENT), True),
            'permission': (absent_with(b'RTNETLINK answers: Operation not permitted\n'), True),
            'timeout': (core.Failure('child deadline exceeded', 124), False),
            'overflow': (core.Failure('private child output overflow'), False),
            'empty-output': (b'', False),
            'malformed-json': (b'{', False),
            'empty-list': (b'[]', False),
            'two-links': (json.dumps([json.loads(bridge_json())[0]] * 2).encode(), False),
            'duplicate-key': (b'[{"ifname":"hhbr","ifname":"hhbr","ifindex":42,"linkinfo":{"info_kind":"bridge"}}]', False),
            'non-list': (b'{"ifname":"hhbr"}', False),
            'non-object': (b'[1]', False),
            'foreign-name': (bridge_json(ifname='foreign0'), False),
            'foreign-kind': (bridge_json(linkinfo={'info_kind': 'dummy'}), False),
            'index-zero': (bridge_json(0), False),
            'bool-index': (bridge_json(True), False),
            **{'linkinfo-' + str(i): (bridge_json(linkinfo=value), False)
               for i, value in enumerate((None, [], 1, 'foreign'))},
            **{'info-data-' + str(i): (bridge_json(linkinfo={'info_kind': 'bridge', 'info_data': value}), False)
               for i, value in enumerate((None, [], 1, 'foreign'))},
        }

    def test_genuine_probe_failures_fail_closed_without_retry_and_keep_evidence(self):
        for name, (answer, has_bytes) in self.genuine_failures().items():
            with self.subTest(name):
                self.setUp()
                exc = self.bridge_run([answer])
                self.assertFailedClosed(exc, 1)
                if isinstance(answer, core.Failure):
                    self.assertIs(exc, answer)
                    self.assertEqual((exc.code, str(exc)), (answer.code, str(answer)))
                if isinstance(answer, core.Failure):
                    expected = answer.private_output if has_bytes else OLD_DIAGNOSTIC
                else:
                    expected = answer or OLD_DIAGNOSTIC
                self.assertEqual(self.diagnostic_bytes(), expected)

    def test_ifindex_replacement_between_probe_and_helper_fails(self):
        exc = self.bridge_run([bridge_json(41)])
        self.assertIsInstance(exc, core.Failure)
        self.assertEqual(str(exc), 'bridge identity changed')
        self.assertEqual(len(self.helper_calls()), 1)
        self.assertNotEqual(core.state()['phase'], 'ready')

    def test_helper_hard_failure_is_not_retried_and_keeps_code(self):
        self.failure = lambda argv: argv[0] == core.PYTHON
        exc = self.bridge_run([bridge_json(42)])
        self.assertIsInstance(exc, core.Failure)
        self.assertEqual(exc.code, 17)
        self.assertEqual((self.probes, len(self.helper_calls())), (1, 1))


def absent_with(raw):
    return core.Failure('child command failed', 1, raw)


class BridgePrerequisiteFresh(BridgePrerequisiteMixin, unittest.TestCase):
    mode = 'fresh'


class BridgePrerequisiteResume(BridgePrerequisiteMixin, unittest.TestCase):
    mode = 'resume'


class FormatAndSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='labapp-vlab-executor-')
        self.addCleanup(self.temp.cleanup)
        self.root_patch = patch.object(core, 'ROOT', Path(self.temp.name) / 'state')
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_probe_parser_failure_preserves_object_code_and_returned_bytes(self):
        raw = b'{"public":"malformed bridge observation"}'
        failure = core.Failure('bridge query refused', 37)
        with patch.object(core, 'execute', return_value=raw), \
             patch.object(core, 'bridge_link', side_effect=failure), \
             patch.object(core, 'retain_failure_output') as retain:
            with self.assertRaises(core.Failure) as raised:
                core.bridge_probe(101.0)
        self.assertIs(raised.exception, failure)
        self.assertEqual(raised.exception.code, 37)
        retain.assert_called_once_with(raw)

    def test_actual_executor_absence_cannot_hide_uncertain_cleanup(self):
        # Actual execute control flow, with every child/selector/OS observation mocked.
        # No children, signals, reads or real sleeps are performed by this fixture.
        for cleanup in ('confirmed', 'kill-unverified', 'reap-unverified'):
            with self.subTest(cleanup=cleanup):
                child = MagicMock()
                child.pid = 123456
                child.stdout.fileno.return_value = 123
                child.wait.side_effect = [1, subprocess.TimeoutExpired('public-query', 2)
                                          if cleanup == 'reap-unverified' else 1]
                selector = MagicMock()
                selector.__enter__.return_value = selector
                selector.select.return_value = [object()]
                failures = []
                def query(*args, **kwargs):
                    try:
                        return EXECUTE(*args, **kwargs)
                    except core.Failure as exc:
                        failures.append(exc)
                        raise
                with patch.object(core, 'execute', side_effect=query), \
                     patch.object(core.subprocess, 'Popen', return_value=child), \
                     patch.object(core.selectors, 'DefaultSelector', return_value=selector), \
                     patch.object(core.os, 'read', side_effect=[ABSENT, b'']), \
                     patch.object(core.os, 'killpg', side_effect=OSError('public uncertainty')
                                  if cleanup == 'kill-unverified' else None) as kill, \
                     patch.object(core.time, 'monotonic', return_value=100.0), \
                     patch.object(core, 'retain_failure_output') as retain, \
                     patch('sys.stderr', new_callable=io.StringIO) as errors:
                    if cleanup == 'confirmed':
                        self.assertIsNone(core.bridge_probe(101.0))
                        retain.assert_not_called()
                        self.assertEqual(errors.getvalue(), '')
                    else:
                        with self.assertRaises(core.Failure) as raised:
                            core.bridge_probe(101.0)
                        self.assertIs(raised.exception, failures[0])
                        self.assertTrue(raised.exception.cleanup_uncertain)
                        retain.assert_called_once_with(ABSENT)
                        self.assertIn('child group containment unverified', errors.getvalue())
                        self.assertNotIn(ABSENT.decode(), errors.getvalue())
                self.assertEqual(len(failures), 1)
                self.assertEqual((failures[0].code, str(failures[0]), failures[0].private_output),
                                 (1, 'child command failed', ABSENT))
                kill.assert_called_once_with(child.pid, signal.SIGKILL)
                child.stdout.close.assert_called_once_with()
                self.assertEqual(child.wait.call_args_list[0].kwargs, {'timeout': 1.0})
                if cleanup != 'kill-unverified':
                    self.assertEqual(child.wait.call_args_list[1].kwargs, {'timeout': 2})

    def test_executor_retains_one_bounded_private_failure_output(self):
        core.ROOT.mkdir(mode=0o700)
        with patch.object(core, 'ROOT_UID', os.getuid()), self.assertRaises(core.Failure) as raised:
            core.execute([sys.executable, '-I', '-B', '-c',
                          'import sys; print("PUBLIC_SYNTHETIC_DIAGNOSTIC"); sys.exit(19)'],
                         core.time.monotonic() + 3)
        self.assertEqual(raised.exception.code, 19)
        self.assertEqual(raised.exception.private_output, b'PUBLIC_SYNTHETIC_DIAGNOSTIC\n')
        path = core.ROOT / 'last-command-output'
        self.assertEqual(path.read_bytes(), raised.exception.private_output)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_unknown_private_diagnostic_path_is_retained_without_replacing_primary(self):
        core.ROOT.mkdir(mode=0o700)
        foreign = Path(self.temp.name) / 'foreign'
        foreign.write_bytes(b'public foreign data')
        (core.ROOT / 'last-command-output').symlink_to(foreign)
        with patch.object(core, 'ROOT_UID', os.getuid()), patch('sys.stderr', new_callable=io.StringIO) as errors:
            with self.assertRaises(core.Failure) as raised:
                core.execute([sys.executable, '-I', '-B', '-c', 'raise SystemExit(19)'],
                             core.time.monotonic() + 3)
        self.assertEqual(raised.exception.code, 19)
        self.assertIn('private diagnostics unverified', errors.getvalue())
        self.assertEqual(foreign.read_bytes(), b'public foreign data')
        self.assertTrue((core.ROOT / 'last-command-output').is_symlink())

    def test_private_diagnostic_hardlink_cannot_redirect_a_truncate(self):
        core.ROOT.mkdir(mode=0o700)
        foreign = Path(self.temp.name) / 'foreign'
        foreign.write_bytes(b'preserve foreign data')
        foreign.chmod(0o600)
        os.link(foreign, core.ROOT / 'last-command-output')
        with patch.object(core, 'ROOT_UID', os.getuid()), patch('sys.stderr', new_callable=io.StringIO):
            with self.assertRaises(core.Failure) as raised:
                core.execute([sys.executable, '-I', '-B', '-c', 'raise SystemExit(19)'],
                             core.time.monotonic() + 3)
        self.assertEqual(raised.exception.code, 19)
        self.assertEqual(foreign.read_bytes(), b'preserve foreign data')

    def test_read_and_hash_allow_access_time_updates(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'public'
            target.write_bytes(b'public data')
            os.utime(target, (1, 1))
            self.assertEqual(core.read(target), b'public data')
            self.assertEqual(core.identity(target, True)['sha256'], core.digest(b'public data'))

    def test_strict_json_and_yaml_reject_duplicates_aliases_deep_and_unsafe(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(core.Failure):
                core.json_data(raw)
        for raw in (b'a: 1\na: 2\n', b'a: &a []\nb: *a\n', b'a: !!python/object:os.system {}',
                    b'a: ' + b'[' * 34 + b'0' + b']' * 34):
            with self.assertRaises(core.Failure):
                core.yaml_documents(raw)
        self.assertEqual(core.yaml_documents(b'ip:\tdhcp\n'), [{'ip': 'dhcp'}])

    def test_units_actual_namespace_privilege_logging_stop_and_no_conflicts(self):
        root = Path(__file__).parent
        for mode, name in core.UNIT.items():
            raw = (root / name).read_text()
            self.assertIn('ExecStart=!/usr/bin/python3 ', raw)
            self.assertNotIn('ExecStart=+', raw)
            self.assertNotIn('Conflicts=', raw)
            self.assertIn('KillMode=control-group', raw)
            self.assertIn('TimeoutStopSec=20', raw)
            self.assertIn('Restart=no', raw)
            self.assertIn('ExecStopPost=+', raw)
            self.assertIn('LogNamespace=labapp-vlab', raw)
            self.assertIn('StandardOutput=journal', raw)
            self.assertIn('TimeoutStartSec=' + str(core.START_SECONDS[mode]), raw)
            if mode == 'resume':
                for path in ('result', 'fab.yaml', '.registry.yaml', 'include', 'vlab/config.yaml', 'vlab/sshkey'):
                    self.assertIn('/home/ubuntu/hhfab/' + path, raw)
        journal = (root / 'journald@labapp-vlab.conf').read_text()
        for name in ('Syslog', 'KMsg', 'Console', 'Wall'):
            self.assertIn('ForwardTo' + name + '=no', journal)
        self.assertIn('SystemMaxUse=32M', journal)
        self.assertIn('RuntimeMaxUse=16M', journal)

    def test_fixed_up_has_no_destructive_fallback_flags(self):
        argv = core.up_argv()
        self.assertEqual(argv[:3], [core.HHFAB, 'vlab', 'up'])
        for flag in ('--force', '--recreate', '--dev', '--no-create', '--attempts'):
            self.assertNotIn(flag, argv)
        self.assertIn('--kill-stale=false', argv)
        self.assertIn('--auto-upgrade=false', argv)
        self.assertEqual(core.PACKAGE_PINS['qemu-system-x86'], '1:8.2.2+ds-0ubuntu1.11')

    def test_bounded_executor_real_inspected_children(self):
        # No fake installed binaries and no network. Both children are stdlib only.
        for code, cap, expected in [('import time; time.sleep(10)', .03, 124),
                                    ('import os; os.write(1,b"x"*1100000)', 2, 1),
                                    ('raise SystemExit(19)', 2, 19)]:
            with self.subTest(code=code), self.assertRaises(core.Failure) as raised:
                core.execute([sys.executable, '-I', '-B', '-c', code], core.time.monotonic() + 3, cap)
            self.assertEqual(raised.exception.code, expected)

    def test_executor_cleanup_uncertainty_keeps_primary_and_fixed_diagnostic(self):
        original_popen = core.subprocess.Popen
        for failure in ('kill', 'reap'):
            def create(*args, **kwargs):
                child = original_popen(*args, **kwargs)
                actual_wait = child.wait
                calls = [0]
                def wait(*args, **kwargs):
                    calls[0] += 1
                    if failure == 'reap' and calls[0] > 1:
                        raise subprocess.TimeoutExpired('SYNTHETIC_PRIVATE_DETAIL', 2)
                    return actual_wait(*args, **kwargs)
                child.wait = wait
                return child
            with self.subTest(failure=failure), ExitStack() as stack:
                stack.enter_context(patch.object(core.subprocess, 'Popen', side_effect=create))
                if failure == 'kill':
                    stack.enter_context(patch.object(core.os, 'killpg', side_effect=OSError('SYNTHETIC_PRIVATE_DETAIL')))
                errors = stack.enter_context(patch('sys.stderr', new_callable=io.StringIO))
                with self.assertRaises(core.Failure) as raised:
                    core.execute([sys.executable, '-I', '-B', '-c', 'raise SystemExit(19)'],
                                 core.time.monotonic() + 3)
                self.assertEqual(raised.exception.code, 19)
                self.assertIn('child group containment unverified', errors.getvalue())
                self.assertNotIn('SYNTHETIC_PRIVATE_DETAIL', errors.getvalue())

    def test_bounded_executor_sanitizes_environment(self):
        with patch.dict(os.environ, {'HHFAB_JOIN_TOKEN': 'DO_NOT_FORWARD', 'KUBECONFIG': '/bad'}):
            raw = core.execute([sys.executable, '-I', '-B', '-c',
                                'import json,os; print(json.dumps(dict(os.environ)))'],
                               core.time.monotonic() + 3)
        self.assertEqual(json.loads(raw), core.SAFE_ENV)

    def test_actual_kubectl_classifier_preserves_deadline_and_only_known_transients(self):
        known = b'Error from server (ServiceUnavailable): the server is currently unable to handle the request\n'
        with patch.object(core, 'execute', side_effect=core.Failure('child command failed', 1, known)):
            with self.assertRaises(core.Pending):
                core.kubectl(['get', '--raw=/readyz'], core.time.monotonic() + 5)
        for code in (124, 130, 143):
            with self.subTest(code=code), patch.object(core, 'execute',
                    side_effect=core.Failure('child command failed', code, known)):
                with self.assertRaises(core.Failure) as raised:
                    core.kubectl(['get', '--raw=/readyz'], core.time.monotonic() + 5)
                self.assertNotIsInstance(raised.exception, core.Pending)
                self.assertEqual(raised.exception.code, code)

    def test_parent_signal_preserves_primary_and_reaps_known_child(self):
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / 'pid'
            program = ('import os,signal,time; from pathlib import Path; '
                       'Path(' + repr(str(pidfile)) + ').write_text(str(os.getpid())); '
                       'os.kill(os.getppid(),signal.SIGINT); time.sleep(10)')
            with self.assertRaises(KeyboardInterrupt):
                core.execute([sys.executable, '-I', '-B', '-c', program], core.time.monotonic() + 3)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pidfile.read_text()), 0)

    def test_exited_direct_child_does_not_leave_pipe_holding_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / 'descendant'
            descendant = 'import time; time.sleep(10)'
            program = ('import subprocess,sys; from pathlib import Path; '
                       'p=subprocess.Popen([sys.executable,"-I","-B","-c",' + repr(descendant) + ']); '
                       'Path(' + repr(str(pidfile)) + ').write_text(str(p.pid))')
            with self.assertRaises(core.Failure) as raised:
                core.execute([sys.executable, '-I', '-B', '-c', program], core.time.monotonic() + .2)
            self.assertEqual(raised.exception.code, 124)
            pid = int(pidfile.read_text())
            end = core.time.monotonic() + 2
            while True:
                try:
                    state = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
                except FileNotFoundError:
                    break
                # Nonchild zombie reaping belongs to its parent/subreaper. Only
                # termination is asserted here; no daemon/process census claim.
                if state == 'Z':
                    break
                self.assertLess(core.time.monotonic(), end, 'owned descendant remains running')
                core.time.sleep(.01)


class PrerequisiteContractTests(unittest.TestCase):
    """Unmocked prerequisite verifier, injected filesystem/package observations.

    No actual package query or binary access. Exact fixed command/pin maps stay
    in place; only their OS observations are synthetic.
    """
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.packages = {**{name: '1.0' for name in core.AUX.values()}, **core.PACKAGE_PINS}
        self.packages['systemd'] = '255.4-1ubuntu8.99-synthetic'
        self.records = {}
        for name in set(core.AUX) | set(core.TOOL_PINS):
            size, sha = core.TOOL_PINS.get(name, (4, 'f' * 64))
            self.records[name] = {'dev': 1, 'ino': len(self.records) + 1,
                'uid': 0, 'gid': 0, 'mode': stat.S_IFREG | (0o4755 if name == '/usr/bin/sudo' else 0o755),
                'size': size, 'sha256': sha}
        self.receipt = {'schema': 1, 'source_sha256': 'c' * 64, 'packages': self.packages,
                        'commands': {name: {'resolved': name, 'sha256': record['sha256']}
                                     for name, record in self.records.items()}}
        self.os_release = b'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n'
        self.arch = 'amd64'
        self.status = 'installed'
        self.installed = copy.deepcopy(self.packages)
        self.machine = 'x86_64'
        self.calls = []
        self.stack.enter_context(patch.object(core, 'read', side_effect=self.read))
        self.stack.enter_context(patch.object(core, 'identity', side_effect=self.identity))
        self.stack.enter_context(patch.object(core, 'execute', side_effect=self.execute))
        self.stack.enter_context(patch.object(core.os, 'uname', side_effect=lambda: SimpleNamespace(machine=self.machine)))
        self.stack.enter_context(patch.object(Path, 'resolve', autospec=True, side_effect=lambda path, **_: path))

    def read(self, path, *args, **kwargs):
        self.assertEqual(path, Path('/usr/lib/os-release'))
        return self.os_release

    def identity(self, path, *args, **kwargs):
        self.assertIn(str(path), self.records)
        return copy.deepcopy(self.records[str(path)])

    def execute(self, argv, *args, **kwargs):
        self.assertEqual(argv[:3], [core.DPKG, '-W', '-f=${db:Status-Status}\t${Architecture}\t${Version}\n'])
        self.assertIn(argv[3], self.packages)
        self.calls.append(argv[3])
        return f'{self.status}\t{self.arch}\t{self.installed[argv[3]]}\n'.encode()

    def verify(self):
        return VERIFY_PREREQUISITES(self.receipt, core.time.monotonic() + 5)

    def test_exact_actual_fixed_pins_and_selected_auxiliary_receipt_pass(self):
        records = self.verify()
        self.assertEqual(set(records), set(core.AUX) | set(core.TOOL_PINS))
        self.assertEqual(set(self.calls), set(self.packages))
        self.assertEqual(records['/usr/bin/sudo']['mode'], stat.S_IFREG | 0o4755)

    def test_test_qemu_point18_refused_before_package_command(self):
        self.packages['qemu-system-x86'] = '1:8.2.2+ds-0ubuntu1.18'
        with self.assertRaisesRegex(core.Failure, 'baseline package pin'):
            self.verify()
        self.assertFalse(self.calls)

    def test_unresearched_systemd_major_is_refused_without_selecting_upgrade(self):
        self.packages['systemd'] = '256.1-1-synthetic'
        with self.assertRaisesRegex(core.Failure, 'systemd compatibility family'):
            self.verify()
        self.assertFalse(self.calls)

    def test_installed_version_architecture_and_state_must_match(self):
        for field, value in (('arch', 'arm64'), ('status', 'config-files')):
            original = getattr(self, field)
            setattr(self, field, value)
            with self.subTest(field=field), self.assertRaisesRegex(core.Failure, 'installed package differs'):
                self.verify()
            setattr(self, field, original)
        self.installed['qemu-utils'] = 'different'
        with self.assertRaisesRegex(core.Failure, 'installed package differs'):
            self.verify()

    def test_receipt_cannot_select_different_pinned_tool(self):
        self.records[core.HHFAB]['sha256'] = 'e' * 64
        self.receipt['commands'][core.HHFAB]['sha256'] = 'e' * 64
        with self.assertRaisesRegex(core.Failure, 'tool pin'):
            self.verify()

    def test_command_owner_mode_hash_and_resolved_path_are_bound(self):
        for field, value in (('uid', 1000), ('mode', stat.S_IFREG | 0o777), ('sha256', 'e' * 64)):
            original = self.records[core.KUBECTL][field]
            self.records[core.KUBECTL][field] = value
            with self.subTest(field=field), self.assertRaises(core.Failure):
                self.verify()
            self.records[core.KUBECTL][field] = original
        self.receipt['commands'][core.KUBECTL]['resolved'] = '/foreign'
        with self.assertRaisesRegex(core.Failure, 'command receipt mismatch'):
            self.verify()

    def test_unknown_package_or_command_refused(self):
        self.packages['unexpected'] = '1'
        with self.assertRaisesRegex(core.Failure, 'package set'):
            self.verify()
        del self.packages['unexpected']
        self.receipt['commands']['/bad'] = {'resolved': '/bad', 'sha256': 'f' * 64}
        with self.assertRaisesRegex(core.Failure, 'command receipt set'):
            self.verify()

    def test_os_release_architecture_and_source_receipt_are_explicit(self):
        self.machine = 'aarch64'
        with self.assertRaisesRegex(core.Failure, 'guest architecture'):
            self.verify()
        self.machine = 'x86_64'
        self.os_release = self.os_release.replace(b'24.04', b'22.04')
        with self.assertRaisesRegex(core.Failure, 'Ubuntu baseline'):
            self.verify()
        self.receipt['source_sha256'] = 'unbound'
        with self.assertRaisesRegex(core.Failure, 'provisioning receipt'):
            self.verify()


def startup_race_case(mode, timing, mutation=None, live=None):
    def test(self):
        result, delta = self.start_with_ready_publication(mode, timing, mutation, live)
        expected = 1 if mutation or live else 0
        self.assertEqual(result, expected, self.stderr.getvalue())
        self.assertEqual(delta, 0 if expected else 1)
        if not expected:
            self.assertEqual(core.state()['phase'], 'ready')
    return test


def replace_start_field(field):
    def mutate(value):
        if field == 'service_null':
            value['service'] = None
        elif field == 'service_absent':
            value.pop('service')
        elif field.startswith('service_'):
            key = field.removeprefix('service_')
            value['service'][key] = {'pid': 999999, 'start': '67890',
                'invocation': 'f' * 32, 'group': '/system.slice/other.service'}[key]
        elif field in ('source', 'static', 'tools', 'critical', 'contract'):
            value[field] = {'foreign': True}
        elif field in ('stopping', 'stop_verified'):
            value[field] = {'operation': 'f' * 32, 'invocation': 'f' * 32}
        elif field in ('deadline', 'started'):
            value[field] += 1
        else:
            value[field] = {'phase': 'failed', 'mode': 'foreign', 'boot': 'foreign'}.get(field, 'f' * 32)
    return mutate


def startup_initial_snapshot_case(mode, field):
    def test(self):
        result, delta = self.start_with_ready_publication(
            mode, 'none', snapshot_mutation=replace_start_field(field))
        self.assertEqual(result, 1, self.stderr.getvalue())
        self.assertEqual(delta, 0)
    return test


def readiness_race_case(mode, field):
    def test(self):
        self.readiness_refuses_changed_snapshot(mode, replace_start_field(field))
    return test


for _mode in ('fresh', 'resume'):
    for _field in ('operation', 'invocation', 'phase', 'nonce', 'boot', 'deadline', 'stopping'):
        setattr(GuestFixture, 'test_startup_initial_reread_refuses_' + _mode + '_' + _field,
                startup_initial_snapshot_case(_mode, _field))
    for _field in ('operation', 'invocation', 'phase', 'mode', 'nonce', 'boot', 'deadline',
                   'started', 'source', 'static', 'tools', 'critical', 'contract', 'stopping',
                   'stop_verified', 'service_null', 'service_pid', 'service_start', 'service_group'):
        setattr(GuestFixture, 'test_readiness_commit_refuses_' + _mode + '_' + _field,
                readiness_race_case(_mode, _field))
    for _timing in ('before', 'between', 'none'):
        setattr(GuestFixture, 'test_startup_publication_' + _mode + '_' + _timing,
                startup_race_case(_mode, _timing))
        for _field in ('service_null', 'service_pid', 'service_start', 'service_invocation',
                       'service_group', 'operation', 'invocation', 'phase', 'mode', 'nonce',
                       'boot', 'deadline', 'started', 'source', 'static', 'tools', 'critical',
                       'contract', 'stopping', 'stop_verified'):
            if _timing == 'none' and _field.startswith('service_') and _field != 'service_null':
                continue
            setattr(GuestFixture, 'test_startup_refuses_' + _mode + '_' + _timing + '_' + _field,
                    startup_race_case(_mode, _timing, replace_start_field(_field)))
        if _timing == 'before':
            setattr(GuestFixture, 'test_startup_refuses_removed_service_' + _mode,
                    startup_race_case(_mode, _timing, replace_start_field('service_absent')))
        for _name, _live in (('other_pid_same_invocation', {'pid': 999999}),
                             ('reused_pid_start', {'start': '67890'}),
                             ('other_cgroup', {'group': '/system.slice/other.service'})):
            setattr(GuestFixture, 'test_startup_live_change_' + _mode + '_' + _timing + '_' + _name,
                    startup_race_case(_mode, _timing, live=_live))


if __name__ == '__main__':
    unittest.main()
