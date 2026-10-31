"""Owner entrypoints use only fake API/processes and public temporary files."""
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from build.gcp import vlab_trial as host
from build.provision import vlab_trial as guest


def snapshot():
    start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=1)
    value = {'profile': 'ubuntu-vlab-core-v1', 'request_id': '11111111-1111-4111-8111-111111111111',
            'epoch': 1, 'run_id': 123, 'attempt': 1, 'body_hash': 'b'*64, 'ids': {'instance': '1234', 'boot': '5678'},
            'boot_image': host.spec.COMPONENT_IMAGE, 'boot_image_id': host.spec.COMPONENT_IMAGE_ID,
            'reserved_at': start.strftime('%Y-%m-%dT%H:%M:%SZ'), 'deadline': (start+timedelta(minutes=120)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'operation': 'op-fixed', 'source_sha': 'a'*40, 'self_user': 'users/12345'}
    value['preflight'] = {'lease': value['request_id'], 'vm_id': '1234', 'source_sha': 'a'*40,
                          'checked_at': start.strftime('%Y-%m-%dT%H:%M:%SZ'),
                          **{key: 'c'*64 for key in ('quota_sha256', 'network_sha256', 'images_sha256', 'access_sha256', 'egress_sha256')}}
    return value


def run_record(value):
    return {'id': value['run_id'], 'run_attempt': value['attempt'], 'path': host.CREATOR_PATH,
            'event': 'workflow_dispatch', 'head_branch': 'main', 'head_sha': value['source_sha'],
            'repository': {'full_name': host.REPOSITORY}, 'status': 'in_progress'}


class OwnerTrial(unittest.TestCase):
    def setUp(self):
        original_umask = os.umask(0o077)
        os.umask(original_umask)
        self.addCleanup(os.umask, original_umask)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(host.subprocess, 'Popen', side_effect=AssertionError('no native child')))
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory(prefix='labapp-owner-offline-'))
        self.directory = Path(self.temp)
        self.directory.chmod(0o700)

    def test_snapshot_refuses_run_retry_missing_evidence_and_stale_preflight(self):
        host.expected_snapshot(snapshot())
        for change in ('retry', 'stale', 'missing'):
            value = snapshot()
            if change == 'retry': value['attempt'] = 2
            if change == 'stale': value['preflight']['checked_at'] = '2020-01-01T00:00:00Z'
            if change == 'missing': value['preflight'].pop('egress_sha256')
            with self.assertRaises(guest.Failure): host.expected_snapshot(value)

    def test_source_main_binding_only_at_initial_capture(self):
        value = snapshot()
        record = run_record(value)
        with patch.object(host, 'github', side_effect=[record, {'object': {'sha': value['source_sha']}}]) as get:
            host.trusted_source(value, initial=True)
            self.assertEqual(get.call_count, 2)
        with patch.object(host, 'github', return_value=record) as get:
            host.trusted_source(value)
            self.assertEqual(get.call_count, 1)
        record['status'] = 'completed'
        with patch.object(host, 'github', return_value=record):
            with self.assertRaises(guest.Failure): host.trusted_source(value)

    def test_owner_read_surface_has_no_creator_capture_delete(self):
        cloud = Mock()
        reads = host.ReadCloud(cloud)
        reads.call('instances', 'get', name='fixed')
        for resource, verb in (('instances', 'insert'), ('instances', 'delete'), ('images', 'insert'), ('images', 'delete')):
            with self.assertRaises(host.ForbiddenOperation): reads.call(resource, verb)
        self.assertEqual(cloud.call.call_count, 1)

    def test_nondevelopment_candidate_is_private_fixed_structure(self):
        raw = host.candidate_fab('ssh-ed25519 UEVCTElDX0ZJWFRVUkU=', '$5$publicfixture$' + 'a'*43, 'f'*64)
        self.assertNotIn(b'--dev', raw)
        self.assertNotIn(b'Qi4/gnM0yPtGv9kjpMh', raw)
        import yaml
        docs = list(yaml.safe_load_all(raw))
        self.assertEqual([v['kind'] for v in docs], ['Fabricator', 'ControlNode'])
        self.assertEqual(docs[0]['spec']['config']['registry'], {'mode': 'airgap'})
        self.assertEqual(docs[1]['spec']['external'], {'interface': 'enp2s0', 'ip': 'dhcp'})
        self.assertEqual(docs[0]['spec']['config']['fabric']['leafASNStart'], 65101)

    def test_common_ssh_options_work_for_sftp_and_disable_ambient_auth(self):
        options = host.ssh_options(self.directory, '1234', 'owner')
        self.assertNotIn('-S', options)  # sftp -S selects a program!
        for required in ('ControlPath=' + str(self.directory / 'master.sock'), 'IdentityAgent=none',
                         'ForwardAgent=no', 'ForwardX11=no', 'IdentitiesOnly=yes', 'StrictHostKeyChecking=yes'):
            self.assertIn(required, options)

    def master(self):
        value = snapshot()
        clock = Mock()
        clock.remaining.return_value = 30
        clock.cleanup_remaining.return_value = 15
        master = host.Master(self.directory, value, 'owner', clock, threading.Event())
        master.check = Mock()
        return master

    def test_master_channels_have_failing_fallback_and_no_second_auth(self):
        master = self.master()
        with patch.object(host, 'command', return_value=b'public') as run:
            master.remote(['/usr/bin/true'], 'stage')
        argv = run.call_args.args[0]
        self.assertIn('ProxyCommand=/usr/bin/false', argv)
        self.assertIn('ControlMaster=no', argv)
        self.assertNotIn('gcloud', str(argv))
        self.assertEqual(master.check.call_count, 2)

    def test_marker_and_full_transfer_do_not_reuse_stale_batch(self):
        master = self.master()
        with patch.object(host, 'command') as run:
            master.transfer('/tmp/labapp-vlab-'+'a'*32, ['marker'], 'access')
            self.assertFalse((self.directory / 'sftp.batch').exists())
            master.transfer('/tmp/labapp-vlab-'+'a'*32, ['manifest.json'])
        self.assertEqual(run.call_count, 2)
        self.assertTrue(all('ProxyCommand=/usr/bin/false' in c.args[0] for c in run.call_args_list))

    def test_master_cannot_restart_after_first_attempt(self):
        master = self.master()
        master.started = True
        with self.assertRaisesRegex(guest.Failure, 'replacement'): master.start()

    def test_cleanup_cancels_only_captured_run_no_manual_dispatch(self):
        value = snapshot()
        with patch.object(host, 'github', return_value=run_record(value)), patch.object(host, 'command') as run:
            host.cleanup_dispatch(value)
        self.assertEqual(run.call_args.args[0][-1], 'repos/afewell-hh/labapp/actions/runs/123/cancel')
        self.assertNotIn('workflow', run.call_args.args[0])
        changed = run_record(value)
        changed['run_attempt'] = 2
        with patch.object(host, 'github', return_value=changed), patch.object(host, 'command') as run:
            with self.assertRaises(guest.Failure): host.cleanup_dispatch(value)
            run.assert_not_called()

    def test_early_source_failure_still_attempts_correlated_cleanup(self):
        value = snapshot()
        registration = Mock()
        with patch.object(host, 'trusted_source', side_effect=guest.Failure('denied', 17)), \
             patch.object(host, 'cleanup_dispatch') as cleanup, patch('builtins.print') as output:
            result = host.trial(value, self.directory, self.directory,
                                registration=registration, records=Mock(), login=Mock())
        self.assertEqual(result, 17)
        registration.current.assert_not_called()
        cleanup.assert_called_once_with(value)
        receipt = json.loads(output.call_args.args[0])
        self.assertFalse(receipt['own_key_absent'])
        self.assertTrue(receipt['local_files_absent'])

    def test_actual_main_help_retains_zero_exit_without_cloud(self):
        with patch.object(sys, 'argv', ['vlab_trial', '--help']), \
             patch.object(host.signal, 'signal'), \
             patch.object(sys, 'stdout', io.StringIO()):
            with self.assertRaises(SystemExit) as status:
                runpy.run_module('build.gcp.vlab_trial', run_name='__main__')
        self.assertEqual(status.exception.code, 0)

    def test_actual_owner_registration_checks_cloud_shape_before_narrow_cas(self):
        from build.gcp.lifecycle.test_vlab_trial_profile import world
        w = world()
        rec = w.started(run=123)
        value = {k: rec[k] for k in host.SNAPSHOT_FIELDS}
        value.update(source_sha='a'*40, self_user='users/12345')
        value['preflight'] = dict(snapshot()['preflight'], lease=rec['request_id'],
                                  vm_id=rec['ids']['instance'], checked_at=rec['reserved_at'])
        body = host.spec.build_body(boot_image=host.spec.COMPONENT_IMAGE, request_id=rec['request_id'],
                  run_id=123, attempt=1, deadline=w.clock.now()+timedelta(minutes=120), profile=host.spec.UBUNTU_VLAB_CORE)
        inst = w.raw.instances[rec['names']['instance']]
        inst.update({k: body[k] for k in ('metadata', 'advancedMachineFeatures', 'minCpuPlatform', 'canIpForward', 'deletionProtection')})
        inst['machineType'] = 'projects/' + host.spec.PROJECT + '/' + body['machineType']
        inst['networkInterfaces'] = [{'subnetwork': 'projects/' + host.spec.PROJECT + '/' + body['networkInterfaces'][0]['subnetwork']}]
        boot = w.raw.disks[rec['names']['boot']]
        boot.update(sizeGb='500', type='projects/' + host.spec.PROJECT + '/zones/' + host.spec.ZONE + '/diskTypes/pd-balanced')
        records = Mock()
        records.read.return_value = (None, 0)
        with patch.object(host.time, 'time', return_value=w.clock.now().timestamp()+1):
            registration = host.OwnerRegistration(w.store, w.cloud, records, value)
            registration._OwnerRegistration__controller.cfg.now = w.clock.now
            self.assertEqual(registration.current()['ids'], rec['ids'])
            boot['sizeGb'] = '800'
            with self.assertRaises(guest.Failure): registration.register('public fixture')
            self.assertNotIn('access', w.record())
            boot['sizeGb'] = '500'
            from build.gcp.lifecycle.test_access import key
            context = registration.register(key())
            self.assertEqual(context.binding['run_id'], 123)
            self.assertEqual(context.binding['vm_id'], rec['ids']['instance'])
            self.assertEqual(w.record()['access']['phase'], 'registered')

    def test_lost_master_cleanup_withholds_removed_receipt_and_preserves_primary(self):
        value = snapshot()
        rec = dict(value, names=host.spec.names(123, 1, host.spec.UBUNTU_VLAB_CORE))
        registration = Mock()
        registration.current.return_value = rec
        registration.register.return_value = Mock()
        importer = Mock()
        importer.prepare.return_value = ({'posix': {'username': 'owner'}}, 1)
        master = Mock()
        master.start.side_effect = guest.Failure('original master lost', 124)
        master.close.side_effect = RuntimeError('synthetic cleanup failure')
        login = Mock(user=value['self_user'])
        def command(args, *unused, **kwargs):
            if args[:3] == ['gcloud', 'auth', 'list']: return (host.OWNER+'\n').encode()
            if args[:3] == ['gcloud', 'config', 'get-value']: return b'(unset)\n'
            if args[:4] == ['gcloud', 'compute', 'os-login', 'describe-profile']:
                return guest.encoded({'name': value['self_user']})
            if args[:2] == ['gcloud', 'version']: return b'{"Google Cloud SDK":"575.0.0"}'
            if args[0] == '/usr/bin/ssh-keygen' and '-f' in args and '-q' in args:
                target = Path(args[-1])
                target.write_text('PUBLIC_SYNTHETIC_PRIVATE_KEY_PLACEHOLDER')
                Path(str(target)+'.pub').write_text('ssh-ed25519 UEVCTElDX0ZJWFRVUkU=')
            return b'[]'
        with patch.object(host, 'command', side_effect=command), patch.object(host, 'trusted_source'), \
             patch.object(host, 'OwnKeyImport', return_value=importer), patch.object(host, 'Master', return_value=master), \
             patch.object(host, 'extract_ed25519', return_value='ssh-ed25519 UEVCTElDX0ZJWFRVUkU=\n'), \
             patch.object(host, 'cleanup_own_key') as remove, patch.object(host, 'cleanup_dispatch') as cancel, \
             patch('builtins.print') as printed:
            code = host.trial(value, self.directory, self.directory,
                              registration=registration, records=Mock(), login=login)
        self.assertEqual(code, 124)
        remove.assert_not_called()
        cancel.assert_called_once_with(value)
        receipt = json.loads(printed.call_args.args[0])
        self.assertFalse(receipt['process_absent'])
        self.assertFalse(receipt['local_files_absent'])
        self.assertFalse(receipt['own_key_absent'])

    def test_actual_owner_pipeline_stages_fixed_inputs_then_closes_before_key_receipt(self):
        value = snapshot()
        rec = dict(value, names=host.spec.names(123, 1, host.spec.UBUNTU_VLAB_CORE))
        registration, records = Mock(), Mock()
        registration.current.return_value = rec
        registration.register.return_value = Mock()
        login = Mock(user=value['self_user'])
        importer = Mock()
        importer.prepare.return_value = ({'posix': {'username': 'owner'}}, 1)
        trace, pulse = [], threading.Event()
        nonce = 'd'*32
        boot = '22222222-2222-4222-8222-222222222222'
        payload_dir = self.directory / 'inputs'
        payload_dir.mkdir()
        output = self.directory / 'output'
        output.mkdir(mode=0o700)
        pins = {}
        for name in guest.PAYLOADS:
            raw = ('PUBLIC-'+name).encode()
            (payload_dir / name).write_bytes(raw)
            pins[name] = (len(raw), guest.sha(raw))
        def command(args, *unused, **kwargs):
            if args[:3] == ['gcloud', 'auth', 'list']: return (host.OWNER+'\n').encode()
            if args[:3] == ['gcloud', 'config', 'get-value']: return b'(unset)\n'
            if args[:4] == ['gcloud', 'compute', 'os-login', 'describe-profile']:
                return guest.encoded({'name': value['self_user']})
            if args[:2] == ['gcloud', 'version']: return b'{"Google Cloud SDK":"575.0.0"}'
            if args[0] == '/usr/bin/ssh-keygen' and '-q' in args:
                target = Path(args[-1])
                target.write_text('PUBLIC_SYNTHETIC_KEY_PLACEHOLDER')
                Path(str(target)+'.pub').write_text('ssh-ed25519 UEVCTElDX0ZJWFRVUkU=')
            if args[0] == '/usr/bin/openssl': return ('$5$publicfixture$'+'a'*43+'\n').encode()
            return b'[]'
        def sources(snap, directory):
            table = {}
            for name in guest.SOURCES:
                raw = ('PUBLIC-SOURCE-'+name).encode()
                guest.exclusive(directory / name, raw)
                table[name] = {'bytes': len(raw), 'sha256': guest.sha(raw)}
            return table
        class Session:
            def start(self): trace.append('master-start')
            def transfer(self, incoming, names, phase='stage'):
                trace.append(('transfer', tuple(names), phase))
                if 'manifest.json' in names:
                    table = guest.manifest(guest.data((output / 'manifest.json').read_bytes()))
                    self_test.assertEqual(set(table['files']), guest.FILES)
            def remote(self, args, phase, cap=30, cleanup=False):
                trace.append(('remote', tuple(args), phase))
                if args[:2] == ['/usr/bin/cat', '/proc/sys/kernel/random/boot_id']: return boot.encode()
                if args[0] == '/usr/bin/cat': return nonce.encode()
                if 'heartbeat' in args:
                    pulse.set()
                    return b''
                if '-I' in args and '-c' in args and args[-1].startswith('from pathlib import Path; p='):
                    self_test.assertTrue(pulse.wait(2), 'separate heartbeat never started')
                    return guest.encoded({'schema': 1, 'code': 0, 'contained': True, 'nonce': nonce})
                return b''
            def close(self):
                trace.append('master-close')
                return True
        self_test = self
        def removed(*args, **kwargs):
            self.assertEqual(trace[-1], 'master-close')
            self.assertFalse(any(output.iterdir()), 'private files remain before final own-key receipt')
            trace.append('removed')
        def cancel(snap):
            self.assertEqual(trace[-1], 'removed')
            trace.append('captured-cancel')
        with patch.object(host, 'command', side_effect=command), patch.object(host, 'trusted_source') as trust, \
             patch.object(host, 'OwnKeyImport', return_value=importer), patch.object(host, 'Master', return_value=Session()), \
             patch.object(host, 'source_files', side_effect=sources), patch.object(guest, 'PAYLOADS', pins), \
             patch.object(host, 'extract_ed25519', return_value='ssh-ed25519 UEVCTElDX0ZJWFRVUkU=\n'), \
             patch.object(host.secrets, 'token_hex', side_effect=lambda n: 'd'*(n*2)), \
             patch.object(host.secrets, 'token_urlsafe', return_value='PUBLIC-NONDEPLOYABLE-PASSWORD'), \
             patch.object(host, 'cleanup_own_key', side_effect=removed), patch.object(host, 'cleanup_dispatch', side_effect=cancel), \
             patch('builtins.print') as printed:
            code = host.trial(value, payload_dir, output, registration=registration, records=records, login=login)
        self.assertEqual(code, 0)
        self.assertTrue(trust.call_args_list[0].kwargs['initial'])
        self.assertFalse(any(c.kwargs.get('initial',False) for c in trust.call_args_list[1:]))
        importer.import_once.assert_called_once()
        self.assertEqual(trace[-3:], ['master-close','removed','captured-cancel'])
        receipt = json.loads(printed.call_args.args[0])
        self.assertTrue(all(receipt[k] for k in ('contained','process_absent','own_key_absent','local_files_absent','independent_cleanup_dispatched')))
