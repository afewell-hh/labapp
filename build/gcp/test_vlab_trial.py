"""Owner entrypoints use only fake API/processes and public temporary files."""
from contextlib import ExitStack, nullcontext
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
            'operation': 'op-fixed', 'source_sha': 'a'*40, 'self_user': 'users/110405050082684214272'}
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

    def test_transfer_cleanup_failure_preserves_primary(self):
        master = self.master()
        with patch.object(host, 'command', side_effect=guest.Failure('terminated', 143)), \
             patch.object(Path, 'unlink', side_effect=OSError('fixture cleanup failure')):
            with self.assertRaises(guest.Failure) as caught:
                master.transfer('/tmp/labapp-vlab-'+'a'*32, ['marker'])
        self.assertEqual(caught.exception.code, 143)
        self.assertTrue(caught.exception.cleanup_uncertain)

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
        self.assertEqual((receipt['phase'], receipt['failure_category']), ('guest-access', 'guest'))

    def test_access_failure_phase_category_survives_cleanup_without_error_text(self):
        for stage, error, category in (
                ('prepare', host.AccessError('PRIVATE-PREPARE'), 'access'),
                ('import_once', host.AccessError('PRIVATE-IMPORT'), 'access'),
                ('import_once', RuntimeError('PRIVATE-UNKNOWN'), 'unknown'),
                ('import_once', KeyboardInterrupt('PRIVATE-INTERRUPT'), 'interrupted')):
            with self.subTest(stage=stage, category=category):
                value = snapshot()
                registration = Mock()
                registration.current.return_value = dict(value)
                importer = Mock()
                importer.prepare.return_value = ({'posix': {'username': 'owner'}}, 1)
                getattr(importer, stage).side_effect = error
                def command(args, *unused, **kwargs):
                    if args[:3] == ['gcloud', 'auth', 'list']: return host.OWNER.encode()
                    if args[:3] == ['gcloud', 'config', 'get-value']: return b'(unset)'
                    if args[:4] == ['gcloud', 'compute', 'os-login', 'describe-profile']:
                        return guest.encoded({'name': value['self_user']})
                    if args[:2] == ['gcloud', 'version']: return b'{"Google Cloud SDK":"575.0.0"}'
                    return b''
                with patch.object(host, 'command', side_effect=command), patch.object(host, 'trusted_source'), \
                     patch.object(guest, 'regular', return_value=b'PUBLIC-SYNTHETIC-KEY'), \
                     patch.object(host, 'OwnKeyImport', return_value=importer), \
                     patch.object(host, 'Master') as master, \
                     patch.object(host, 'cleanup_own_key', side_effect=RuntimeError('PRIVATE-CLEANUP')), \
                     patch.object(host, 'cleanup_dispatch', side_effect=RuntimeError('PRIVATE-DISPATCH')), \
                     patch('builtins.print') as printed:
                    code = host.trial(value, self.directory, self.directory, registration=registration,
                                      records=Mock(), login=Mock(user=value['self_user']))
                self.assertEqual(code, 130 if category == 'interrupted' else 1)
                master.assert_not_called()
                receipt = json.loads(printed.call_args.args[0])
                self.assertEqual(receipt['phase'], 'access-prepare' if stage == 'prepare' else 'access-import')
                self.assertEqual(receipt['failure_category'], category)
                self.assertNotIn('PRIVATE', printed.call_args.args[0])
                self.assertFalse(receipt['own_key_absent'])

    def test_owner_profile_mismatch_or_malformed_refuses_before_key_generation(self):
        for raw in ('54321', 'users/54321', '0', '012345', '１２３４５', None, True, 12345):
            with self.subTest(raw=raw):
                value = snapshot()
                registration = Mock()
                registration.current.return_value = dict(value, names=host.spec.names(123, 1, host.spec.UBUNTU_VLAB_CORE))
                calls = []
                def command(args, *unused, **kwargs):
                    calls.append(args)
                    if args[:3] == ['gcloud', 'auth', 'list']: return (host.OWNER+'\n').encode()
                    if args[:3] == ['gcloud', 'config', 'get-value']: return b'(unset)\n'
                    if args[:4] == ['gcloud', 'compute', 'os-login', 'describe-profile']:
                        return guest.encoded({'name': raw})
                    raise AssertionError('unexpected command after invalid profile')
                with patch.object(host, 'command', side_effect=command), patch.object(host, 'trusted_source'), \
                     patch.object(host, 'OwnKeyImport') as importer, patch.object(host, 'cleanup_dispatch') as cancel, \
                     patch('builtins.print'):
                    code = host.trial(value, self.directory, self.directory,
                                      registration=registration, records=Mock(), login=Mock(user=value['self_user']))
                self.assertNotEqual(code, 0)
                self.assertFalse(any(args[0] == '/usr/bin/ssh-keygen' for args in calls))
                registration.register.assert_not_called()
                importer.assert_not_called()
                cancel.assert_called_once_with(value)

    def test_actual_main_selects_closed_owner_login_adapter(self):
        value = snapshot()
        login, registration, records = Mock(), Mock(), Mock()
        with patch.object(guest, 'regular', return_value=guest.encoded(value)), \
             patch.object(host, 'private_directory', return_value=self.directory), \
             patch.object(host, 'GcsAccessRecords', return_value=records), \
             patch.object(host, 'OwnerRegistration', return_value=registration), \
             patch.object(host.SelfLogin, 'for_owner', return_value=login) as owner, \
             patch.object(host, 'trial', return_value=0) as trial:
            self.assertEqual(host.main(['--snapshot', 'public-fixture', '--payloads', 'inputs', '--output', 'output']), 0)
        owner.assert_called_once_with(value['self_user'], token_provider=host.gcloud_token)
        self.assertIs(trial.call_args.kwargs['login'], login)

    def owner_pipeline(self, *, heartbeat_alive=None, containment_error=None, start_error=None,
                       observed_code=0, observed_contained=True):
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
                return guest.encoded({'name': value['self_user'].removeprefix('users/')})
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
            def start(self):
                trace.append('master-start')
                if start_error is not None:
                    raise start_error
            def transfer(self, incoming, names, phase='stage'):
                trace.append(('transfer', tuple(names), phase))
                if 'manifest.json' in names:
                    table = guest.manifest(guest.data((output / 'manifest.json').read_bytes()))
                    self_test.assertEqual(set(table['files']), guest.FILES)
            def remote(self, args, phase, cap=30, cleanup=False, until=None):
                trace.append(('remote', tuple(args), phase))
                if cleanup and containment_error is not None:
                    raise containment_error
                if args[:2] == ['/usr/bin/cat', '/proc/sys/kernel/random/boot_id']: return boot.encode()
                if args[0] == '/usr/bin/cat': return nonce.encode()
                if 'heartbeat' in args:
                    pulse.set()
                    return b''
                if '-I' in args and '-c' in args and args[-1].startswith('from pathlib import Path; p='):
                    self_test.assertTrue(pulse.wait(2), 'separate heartbeat never started')
                    return guest.encoded({'schema': 1, 'code': observed_code, 'contained': observed_contained, 'nonce': nonce})
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
            trace.append('captured-cancel')
        heartbeat = Mock()
        heartbeat.start.side_effect = pulse.set
        heartbeat.is_alive.return_value = heartbeat_alive
        with patch.object(host, 'command', side_effect=command), patch.object(host, 'trusted_source') as trust, \
             patch.object(host, 'OwnKeyImport', return_value=importer), patch.object(host, 'Master', return_value=Session()), \
             patch.object(host, 'source_files', side_effect=sources), patch.object(guest, 'PAYLOADS', pins), \
             patch.object(host, 'extract_ed25519', return_value='ssh-ed25519 UEVCTElDX0ZJWFRVUkU=\n'), \
             patch.object(host.secrets, 'token_hex', side_effect=lambda n: 'd'*(n*2)), \
             patch.object(host.secrets, 'token_urlsafe', return_value='PUBLIC-NONDEPLOYABLE-PASSWORD'), \
             patch.object(host, 'cleanup_own_key', side_effect=removed), patch.object(host, 'cleanup_dispatch', side_effect=cancel), \
             (patch.object(host.threading, 'Thread', return_value=heartbeat) if heartbeat_alive is not None else nullcontext()), \
             patch('builtins.print') as printed:
            code = host.trial(value, payload_dir, output, registration=registration, records=records, login=login)
        return code, json.loads(printed.call_args.args[0]), trace, importer, trust, heartbeat, output

    def test_actual_owner_pipeline_stages_fixed_inputs_then_closes_before_key_receipt(self):
        code, receipt, trace, importer, trust, _, _ = self.owner_pipeline()
        self.assertEqual(code, 0)
        self.assertTrue(trust.call_args_list[0].kwargs['initial'])
        self.assertFalse(any(c.kwargs.get('initial',False) for c in trust.call_args_list[1:]))
        importer.import_once.assert_called_once()
        self.assertEqual(trace[-3:], ['master-close','removed','captured-cancel'])
        self.assertTrue(all(receipt[k] for k in ('contained','process_absent','own_key_absent','local_files_absent','independent_cleanup_dispatched')))
        self.assertEqual((receipt['phase'], receipt['failure_category']), ('guest-result', 'none'))

    def test_live_heartbeat_withholds_containment_channel_files_and_key_receipt(self):
        code, receipt, trace, _, _, heartbeat, output = self.owner_pipeline(
            heartbeat_alive=True, observed_code=7, observed_contained=False)
        self.assertEqual(code, 7)
        heartbeat.join.assert_called_once_with(timeout=25)
        self.assertFalse(any(e[0] == 'remote' and '/usr/bin/systemctl' in e[1] for e in trace if isinstance(e, tuple)))
        self.assertIn('master-close', trace)
        self.assertNotIn('removed', trace)
        self.assertTrue(any(output.iterdir()))
        self.assertFalse(any(receipt[k] for k in ('contained', 'process_absent', 'own_key_absent', 'local_files_absent')))

    def test_joined_heartbeat_permits_one_containment_attempt(self):
        code, receipt, trace, _, _, heartbeat, _ = self.owner_pipeline(
            heartbeat_alive=False, observed_code=7, observed_contained=False)
        self.assertEqual(code, 7)
        heartbeat.join.assert_called_once_with(timeout=25)
        self.assertEqual(sum(e[0] == 'remote' and '/usr/bin/systemctl' in e[1] for e in trace if isinstance(e, tuple)), 1)
        self.assertTrue(receipt['process_absent'])
        self.assertFalse(receipt['contained'])


# --- Issue #365: owned original process-group closure (fake kernel, no native child) ---
import socket
import subprocess

from build.gcp import owned_process as owned


class ProcessFixtureFakes(unittest.TestCase):
    """Fixture lifecycle source exercised without starting threads or native children."""
    def test_echild_before_adoption_never_counts_as_reaping(self):
        from build.gcp import process_group_fixture as fixture
        reaper = fixture.Reaper()
        reaper.register(4243, SimpleNamespace(pid=4242))
        observations = []
        def wait(_):
            observations.append(reaper.complete())
            if len(observations) == 3:
                reaper.stop.set()
        with patch.object(fixture.os, 'waitpid', side_effect=[ChildProcessError(), ChildProcessError(), (4243, 9)]) as waits, \
             patch.object(reaper.stop, 'wait', side_effect=wait):
            reaper.run()  # synchronous: no thread start
        self.assertEqual(observations, [False, False, True])
        self.assertEqual(reaper.reaped, {4243: 9})
        self.assertEqual([c.args for c in waits.call_args_list], [(4243, os.WNOHANG)] * 3)

    def test_reaper_error_is_not_a_completed_registry(self):
        from build.gcp import process_group_fixture as fixture
        reaper = fixture.Reaper()
        reaper.register(4243, SimpleNamespace(pid=4242))
        with patch.object(fixture.os, 'waitpid', side_effect=OSError('fixture wait error')):
            reaper.run()
        self.assertFalse(reaper.complete())
        self.assertEqual(reaper.reaped, {})
        self.assertEqual(reaper.errors, ['OSError'])

    def test_fixture_partial_setup_and_failed_closure_never_claim_clean(self):
        from build.gcp import process_group_fixture as fixture
        for kind in ('no-proc', 'no-wrapper', 'false', 'throw'):
            with self.subTest(kind=kind):
                harness = fixture.Fixture(Path('/unused'), Path('/trusted/python'), float('inf'))
                proc = SimpleNamespace(pid=4242, returncode=None, stdin=io.BytesIO(), stdout=io.BytesIO())
                group = Mock()
                group.close.return_value = False
                if kind == 'throw':
                    group.close.side_effect = RuntimeError('fixture helper failure')
                entry = {'name': 'sentinel', 'proc': None if kind == 'no-proc' else proc,
                         'group': None if kind in ('no-proc', 'no-wrapper') else group, 'clean': False}
                harness.entries.append(entry)
                with patch.object(harness, 'killpg') as signals:
                    self.assertFalse(harness.close(entry))
                self.assertFalse(entry['clean'])
                signals.assert_not_called()
                if entry['proc'] is not None:
                    self.assertTrue(proc.stdin.closed and proc.stdout.closed)


class FakeClock:
    def __init__(self, step=.001):
        self.now, self.step = 0.0, step

    def monotonic(self):
        self.now += self.step
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Kernel:
    """Records signal/reap order; refuses foreign groups and any destructive signal after reap."""
    def __init__(self, clock, *, pgid=4242, leader_exit=0.0, child_term_delay=0.0, persistent=False,
                 code=0, si_code=None, echild=False, errors=None, esrch=(), wait_timeout=False):
        self.clock, self.pgid, self.events = clock, pgid, []
        self.leader_exit, self.child_term_delay, self.persistent = leader_exit, child_term_delay, persistent
        self.code, self.si_code, self.echild = code, os.CLD_EXITED if si_code is None else si_code, echild
        self.errors, self.esrch, self.wait_timeout = errors or {}, set(esrch), wait_timeout
        self.term_at = self.kill_at = None
        self.reaped = False

    def alive(self):
        if not self.reaped or self.persistent:
            return True
        if self.kill_at is not None:
            return False
        return not (self.term_at is not None and self.child_term_delay is not None
                    and self.clock.now >= self.term_at + self.child_term_delay)

    def killpg(self, pgid, number):
        self.events.append(('kill', pgid, int(number)))
        if pgid != self.pgid:
            raise AssertionError('signal outside captured group')
        if number in self.errors:
            raise self.errors[number]
        if number == 0:
            if not self.alive():
                raise ProcessLookupError
            return
        if self.reaped:
            raise AssertionError('destructive signal after reap')
        if number in self.esrch:
            raise ProcessLookupError
        if number == owned.signal.SIGTERM:
            self.term_at = self.clock.now
        elif number == owned.signal.SIGKILL:
            self.kill_at = self.clock.now
        else:
            raise AssertionError('unexpected signal')

    def waitid(self, idtype, pid, options):
        assert idtype == os.P_PID and pid == self.pgid
        assert options == os.WEXITED | os.WNOHANG | os.WNOWAIT, 'observation must not reap'
        if self.echild or self.reaped:
            raise ChildProcessError
        if self.clock.now < self.leader_exit:
            return None
        return SimpleNamespace(si_pid=self.pgid, si_code=self.si_code, si_status=self.code)

    def order(self):
        return [('reap',) if e[0] == 'reap' else (e[0], e[2]) for e in self.events]


class FakeProc:
    def __init__(self, kernel, data=b'', hold_open=False, stdin=None):
        self.kernel, self.pid, self.returncode, self.stdin = kernel, kernel.pgid, None, stdin
        read, write = os.pipe()
        os.write(write, data)
        if hold_open:
            self.writer = write
        else:
            os.close(write)
            self.writer = None
        self.stdout = os.fdopen(read, 'rb')

    def wait(self, timeout=None):
        self.kernel.events.append(('reap', timeout))
        if self.kernel.wait_timeout:
            raise subprocess.TimeoutExpired('fixture', timeout)
        self.kernel.reaped = True
        self.returncode = self.kernel.code
        return self.returncode

    def release(self):
        if self.writer is not None:
            os.close(self.writer)
            self.writer = None
        self.stdout.close()

    def poll(self): raise AssertionError('implicit poll may reap')
    def send_signal(self, *_): raise AssertionError('implicit signal path polls')
    terminate = kill = send_signal


class WriteFails:
    closed = False
    def fileno(self): raise OSError('fixture input setup failure')
    def close(self): self.closed = True


class OwnedProcessGroup(unittest.TestCase):
    def setUp(self):
        original_umask = os.umask(0o077)
        os.umask(original_umask)
        self.addCleanup(os.umask, original_umask)
        os.umask(0o077)
        self.stack = ExitStack()
        self.addCleanup(lambda: self.stack.close())
        self.clock = FakeClock()
        directory = tempfile.TemporaryDirectory(prefix='labapp-owned-offline-')
        self.addCleanup(directory.cleanup)
        self.temp = Path(directory.name)
        self.temp.chmod(0o700)

    def reset(self):
        self.stack.close()
        self.stack = ExitStack()

    def kernel(self, clock=None, **kwargs):
        self.clock = clock or self.clock
        kernel = Kernel(self.clock, **kwargs)
        self.stack.enter_context(patch.object(owned.os, 'killpg', kernel.killpg))
        self.stack.enter_context(patch.object(owned.os, 'waitid', kernel.waitid))
        self.stack.enter_context(patch.object(owned, 'monotonic', self.clock.monotonic))
        self.stack.enter_context(patch.object(owned, 'sleep', self.clock.sleep))
        return kernel

    def popen(self, kernel, **kwargs):
        proc = FakeProc(kernel, **kwargs)
        self.addCleanup(proc.release)
        self.stack.enter_context(patch.object(host.subprocess, 'Popen', return_value=proc))
        return proc

    def assertSignalsBeforeReapOnly(self, kernel, *, kill=True):
        order = kernel.order()
        reap = order.index(('reap',))
        if kill:
            self.assertIn(('kill', 9), order[:reap])
        after = order[reap + 1:]
        self.assertTrue(all(item == ('kill', 0) for item in after), after)
        self.assertEqual(order.count(('reap',)), 1)
        self.assertTrue(all(e[1] == kernel.pgid for e in kernel.events if e[0] == 'kill'))

    # command(): every caller shares the primitive.
    def test_command_success_kills_group_while_leader_unreaped_then_requires_esrch(self):
        kernel = self.kernel()
        self.popen(kernel, data=b'public')
        self.assertEqual(host.command(['/usr/bin/true'], 10), b'public')
        self.assertSignalsBeforeReapOnly(kernel)
        self.assertNotIn(('kill', 15), kernel.order())
        self.assertEqual(kernel.order()[-1], ('kill', 0))

    def test_command_nonzero_and_signal_exit_keep_primary_code(self):
        for code, si_code, expected in ((3, None, 3), (9, os.CLD_KILLED, 137)):
            with self.subTest(code=code):
                kernel = self.kernel(code=code, si_code=si_code)
                self.popen(kernel)
                with self.assertRaises(guest.Failure) as caught:
                    host.command(['/usr/bin/false'], 10)
                self.assertEqual(caught.exception.code, expected)
                self.assertFalse(getattr(caught.exception, 'cleanup_uncertain', False))
                self.assertSignalsBeforeReapOnly(kernel)
                self.reset()

    def test_command_timeout_and_overflow_cleanup_group_inside_total_cap(self):
        kernel = self.kernel(FakeClock(step=.1), leader_exit=1e9)
        proc = self.popen(kernel, data=b'x', hold_open=True)
        with self.assertRaises(guest.Failure) as caught:
            host.command(['/usr/bin/sleep'], 10)
        self.assertEqual(caught.exception.code, 124)
        self.assertSignalsBeforeReapOnly(kernel)
        self.assertTrue(proc.stdout.closed)
        # Final wait is only the reserved cleanup budget, never a renewed cap.
        reap = next(e for e in kernel.events if e[0] == 'reap')
        self.assertLessEqual(reap[1], owned.CLEANUP_SECONDS)
        self.reset()
        kernel = self.kernel(FakeClock())
        proc = self.popen(kernel, data=b'123456')
        with self.assertRaisesRegex(guest.Failure, 'output bound'):
            host.command(['/usr/bin/yes'], 10, limit=4)
        self.assertSignalsBeforeReapOnly(kernel)
        self.assertTrue(proc.stdout.closed)

    def test_command_input_write_failure_closes_pipes_and_cleans_group(self):
        kernel = self.kernel()
        stdin = WriteFails()
        proc = self.popen(kernel, stdin=stdin)
        with self.assertRaises(OSError):
            host.command(['/usr/bin/openssl'], 10, input_bytes=b'public\n')
        self.assertTrue(stdin.closed)
        self.assertTrue(proc.stdout.closed)
        self.assertSignalsBeforeReapOnly(kernel)

    def test_nonblocking_partial_input_failure_and_wouldblock_preserve_cleanup(self):
        for fails in (False, True):
            with self.subTest(fails=fails):
                kernel = self.kernel()
                read_fd, write_fd = os.pipe()
                self.addCleanup(os.close, read_fd)
                stdin = os.fdopen(write_fd, 'wb', buffering=0)
                self.addCleanup(stdin.close)
                proc = self.popen(kernel, stdin=stdin)
                write, attempts = os.write, []
                def partial(fd, raw):
                    attempts.append(bytes(raw))
                    if len(attempts) == 1:
                        return write(fd, raw[:1])
                    if fails:
                        raise OSError('partial input failure')
                    if len(attempts) == 2:
                        raise BlockingIOError()
                    return write(fd, raw)
                with patch.object(host.os, 'write', side_effect=partial):
                    if fails:
                        with self.assertRaises(OSError):
                            host.command(['/usr/bin/openssl'], 10, input_bytes=b'abc')
                    else:
                        self.assertEqual(host.command(['/usr/bin/openssl'], 10, input_bytes=b'abc'), b'')
                self.assertEqual(attempts[:2], [b'abc', b'bc'])
                self.assertTrue(stdin.closed and proc.stdout.closed)
                self.assertSignalsBeforeReapOnly(kernel)
                self.reset()

    def test_command_cleanup_failure_marks_primary_uncertain_without_replacing_it(self):
        kernel = self.kernel(code=3, errors={9: PermissionError()})
        self.popen(kernel)
        with self.assertRaises(guest.Failure) as caught:
            host.command(['/usr/bin/false'], 10)
        self.assertEqual(caught.exception.code, 3)
        self.assertTrue(caught.exception.cleanup_uncertain)
        self.assertSignalsBeforeReapOnly(kernel, kill=False)

    def test_command_success_with_persistent_group_is_uncertain(self):
        kernel = self.kernel(persistent=True)
        self.popen(kernel, data=b'public')
        with self.assertRaises(guest.Failure) as caught:
            host.command(['/usr/bin/true'], 10)
        self.assertTrue(caught.exception.cleanup_uncertain)
        self.assertSignalsBeforeReapOnly(kernel)

    def test_command_lost_child_ownership_sends_no_signal(self):
        kernel = self.kernel(echild=True)
        self.popen(kernel)
        with self.assertRaises(owned.OwnershipUncertain) as caught:
            host.command(['/usr/bin/true'], 10)
        self.assertTrue(caught.exception.cleanup_uncertain)
        self.assertEqual([e for e in kernel.events if e[0] == 'kill'], [])

    # Master.close(): TERM, grace, KILL to the SAME anchored group, then one reap.
    def closing(self, **kwargs):
        kernel = self.kernel(**kwargs)
        proc = FakeProc(kernel)
        self.addCleanup(proc.release)
        master = host.Master(self.temp, snapshot(), 'owner', Mock(), threading.Event())
        master.group = owned.OwnedGroup(proc)
        master.proc = proc
        master.clock.cleanup_remaining.return_value = 15
        return kernel, master

    def test_close_escalates_to_kill_after_leader_first_exit_and_delayed_proxy(self):
        kernel, master = self.closing(leader_exit=0.0, child_term_delay=2.0)
        started = self.clock.now
        self.assertTrue(master.close())
        self.assertEqual(kernel.order()[:3], [('kill', 15), ('kill', 9), ('reap',)])
        self.assertSignalsBeforeReapOnly(kernel)
        self.assertGreaterEqual(self.clock.now - started, owned.TERM_GRACE_SECONDS)
        self.assertLessEqual(self.clock.now - started, owned.TERM_GRACE_SECONDS + owned.CLEANUP_SECONDS + .5)

    def test_close_kills_term_resistant_child_and_handles_zero_children(self):
        for name, delay in (('term-resistant', None), ('plain-leader', 0.0)):
            with self.subTest(name):
                kernel, master = self.closing(leader_exit=1e9, child_term_delay=delay)
                self.assertTrue(master.close())
                self.assertEqual(kernel.order()[:3], [('kill', 15), ('kill', 9), ('reap',)])
                self.assertSignalsBeforeReapOnly(kernel)
                self.reset()

    def test_close_is_idempotent_and_never_signals_after_reap(self):
        kernel, master = self.closing()
        self.assertTrue(master.close())
        events = list(kernel.events)
        self.assertTrue(master.close())
        self.assertFalse(master.live())  # settled group is not live and never signalled
        self.assertEqual(kernel.events, events)

    def test_close_esrch_before_reap_is_ownership_anomaly_not_absence(self):
        for number in (15, 9):
            with self.subTest(signal=number):
                kernel, master = self.closing(esrch={number})
                self.assertFalse(master.close())
                self.assertSignalsBeforeReapOnly(kernel, kill=False)
                events = list(kernel.events)
                self.assertFalse(master.close())
                self.assertEqual(kernel.events, events)
                self.reset()

    def test_close_eperm_unexpected_error_and_probe_error_are_uncertain(self):
        for errors in ({15: PermissionError()}, {9: PermissionError()}, {0: PermissionError()}, {0: OSError(5, 'io')}):
            with self.subTest(errors=errors):
                kernel, master = self.closing(errors=errors)
                self.assertFalse(master.close())
                self.assertSignalsBeforeReapOnly(kernel, kill=False)
                self.reset()

    def test_close_reused_or_persistent_group_after_reap_waits_only_and_is_bounded(self):
        kernel, master = self.closing(persistent=True)
        started = self.clock.now
        self.assertFalse(master.close())
        self.assertSignalsBeforeReapOnly(kernel)
        self.assertLessEqual(self.clock.now - started, owned.TERM_GRACE_SECONDS + owned.CLEANUP_SECONDS + .5)
        self.assertGreater(kernel.order().count(('kill', 0)), 1)

    def test_close_reap_timeout_or_lost_ownership_is_false_without_more_signals(self):
        kernel, master = self.closing(wait_timeout=True)
        self.assertFalse(master.close())
        self.assertEqual(kernel.order().count(('kill', 0)), 0)
        self.reset()
        kernel, master = self.closing(echild=True)
        self.assertFalse(master.close())
        self.assertEqual([e for e in kernel.events if e[0] == 'kill'], [])

    def test_close_without_started_master_and_concurrent_close_refuse_new_signals(self):
        master = host.Master(self.temp, snapshot(), 'owner', Mock(), threading.Event())
        self.assertTrue(master.close())
        kernel, master = self.closing()
        self.assertTrue(master.group._lock.acquire(blocking=False))
        try:
            self.assertFalse(master.close())
        finally:
            master.group._lock.release()
        self.assertEqual(kernel.events, [])

    # Master.start/check: nonreaping observation only.
    def started(self, **kwargs):
        kernel = self.kernel(**kwargs)
        proc = self.popen(kernel)
        session = Mock()
        session.remaining.return_value = 30
        session.cleanup_remaining.return_value = 15
        master = host.Master(self.temp, snapshot(), 'owner', session, threading.Event())
        return kernel, proc, master

    def test_start_and_check_never_poll_and_lost_master_sends_no_signal(self):
        kernel, proc, master = self.started(leader_exit=1e9)
        listener = socket.socket(socket.AF_UNIX)
        self.addCleanup(listener.close)
        listener.bind(str(self.temp / 'master.sock'))
        with patch.object(host, 'command') as run:
            master.start()
            master.check()
        self.assertEqual(run.call_count, 2)
        kernel.leader_exit = 0.0
        with self.assertRaisesRegex(guest.Failure, 'original master lost'):
            master.check()
        self.assertEqual([e for e in kernel.events if e[0] == 'kill'], [])
        self.assertIsNone(proc.returncode)

    def test_startup_failure_before_socket_is_closed_with_signals_before_reap(self):
        kernel, proc, master = self.started(leader_exit=0.0, code=255)
        with self.assertRaisesRegex(guest.Failure, 'original master exited'):
            master.start()
        self.assertTrue(master.close())
        self.assertSignalsBeforeReapOnly(kernel)

    # Actual production command/helper paths, not a stub that promises caps.
    def test_budget_inequality_and_single_end_to_end_heartbeat_deadline(self):
        self.assertLessEqual(5 + 8 + 5, host.HEARTBEAT_BUDGET_SECONDS)
        self.assertLessEqual(host.HEARTBEAT_BUDGET_SECONDS + 3, host.HEARTBEAT_JOIN_SECONDS)
        self.assertEqual(owned.TERM_GRACE_SECONDS + owned.CLEANUP_SECONDS, 8.0)
        clock = FakeClock(step=0)
        self.stack.enter_context(patch.object(owned, 'monotonic', clock.monotonic))
        marker = self.temp / 'master.sock'
        marker.write_bytes(b'')
        info = marker.lstat()
        session = Mock()
        session.remaining.return_value = 30
        master = host.Master(self.temp, snapshot(), 'owner', session, threading.Event())
        master.group = Mock()
        master.group.status.return_value = None
        master.socket_identity = (info.st_dev, info.st_ino)
        kernels, procs, ends = {}, [], []
        def spawn(*args, **kwargs):
            # Spend .5s in spawn and .5s in final reap for EACH real command.
            clock.now += .5
            kernel = Kernel(clock, pgid=4242 + len(procs))
            kernels[kernel.pgid] = kernel
            proc = FakeProc(kernel)
            original = proc.wait
            def wait(timeout=None):
                ends.append((clock.now, timeout))
                clock.now += .5
                return original(timeout)
            proc.wait = wait
            procs.append(proc)
            self.addCleanup(proc.release)
            return proc
        with patch.object(host.subprocess, 'Popen', side_effect=spawn), \
             patch.object(owned.os, 'waitid', side_effect=lambda kind, pid, opts: kernels[pid].waitid(kind, pid, opts)), \
             patch.object(owned.os, 'killpg', side_effect=lambda pid, sig: kernels[pid].killpg(pid, sig)):
            master.remote(['/usr/bin/true'], 'persistence', cap=8, until=22)
            self.assertEqual(len(procs), 3)
            self.assertEqual(clock.now, 3)
            for kernel in kernels.values():
                self.assertSignalsBeforeReapOnly(kernel)
            # Only .75 seconds left: spawn consumes .5; cleanup cannot renew it.
            finish = clock.now + .75
            with self.assertRaises(guest.Failure) as caught:
                master.remote(['/usr/bin/true'], 'persistence', cap=8, until=finish)
            self.assertEqual(caught.exception.code, 124)
            self.assertTrue(caught.exception.cleanup_uncertain)
            self.assertEqual(len(procs), 4)  # no renewed transport/check after failed first check
            self.assertLessEqual(ends[-1][1], .25)
            self.assertTrue(all(p.stdout.closed for p in procs))

    def test_spawn_handoff_failure_marks_primary_and_never_signals_unproven_pid(self):
        for error in (RuntimeError('wrapper failed'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                kernel = self.kernel()
                proc = self.popen(kernel)
                with patch.object(owned, 'OwnedGroup', side_effect=error):
                    with self.assertRaises(type(error)) as caught:
                        host.command(['/usr/bin/true'], 5)
                self.assertIs(caught.exception, error)
                self.assertTrue(error.cleanup_uncertain)
                self.assertTrue(proc.stdout.closed)
                self.assertEqual(kernel.events, [])
                self.reset()

    def test_master_spawn_handoff_failure_can_never_close_clean(self):
        kernel, proc, master = self.started()
        error = KeyboardInterrupt()
        with patch.object(owned, 'OwnedGroup', side_effect=error):
            with self.assertRaises(KeyboardInterrupt) as caught:
                master.start()
        self.assertIs(caught.exception, error)
        self.assertTrue(error.cleanup_uncertain)
        self.assertIs(master.proc, proc)
        self.assertIsNone(master.group)
        self.assertFalse(master.close())
        self.assertFalse(master.close())
        self.assertEqual(kernel.events, [])
        self.reset()
        self.directory = self.temp
        code, receipt, trace, _, _, _, _ = OwnerTrial.owner_pipeline(self, start_error=error)
        self.assertEqual(code, 130)
        self.assertFalse(receipt['process_absent'])
        self.assertFalse(receipt['local_files_absent'])
        self.assertFalse(receipt['own_key_absent'])
        self.assertNotIn('removed', trace)

    def test_master_close_original_cleanup_cutoff_cannot_renew_final_reserve(self):
        kernel, master = self.closing()
        master.clock.cleanup_remaining.return_value = 2
        self.assertFalse(master.close())
        self.assertEqual([e[2] for e in kernel.events if e[0] == 'kill'], [15])
        self.assertNotIn(('reap',), kernel.order())
        events = list(kernel.events)
        master.clock.cleanup_remaining.side_effect = AssertionError('closed result must be stored')
        self.assertFalse(master.close())
        self.assertEqual(events, kernel.events)

    def test_cleanup_helper_throw_preserves_primary_and_closes_every_pipe(self):
        kernel = self.kernel(code=7)
        proc = self.popen(kernel)
        with patch.object(owned.OwnedGroup, 'close', side_effect=KeyboardInterrupt()):
            with self.assertRaises(guest.Failure) as caught:
                host.command(['/usr/bin/false'], 5)
        self.assertEqual(caught.exception.code, 7)
        self.assertTrue(caught.exception.cleanup_uncertain)
        self.assertTrue(proc.stdout.closed)

    def test_annotated_keyboard_interrupt_reaches_coordinator_sticky_gate(self):
        kernel = self.kernel()
        self.popen(kernel)
        error = KeyboardInterrupt()
        with patch.object(owned.OwnedGroup, 'status', side_effect=error):
            with self.assertRaises(KeyboardInterrupt) as caught:
                host.command(['/usr/bin/true'], 5)
        self.assertIs(caught.exception, error)
        self.assertTrue(error.cleanup_uncertain)
        self.reset()
        self.directory = self.temp
        code, receipt, trace, _, _, _, output = OwnerTrial.owner_pipeline(self, start_error=error)
        self.assertEqual(code, 130)
        self.assertFalse(receipt['process_absent'])
        self.assertFalse(receipt['local_files_absent'])
        self.assertFalse(receipt['own_key_absent'])
        self.assertNotIn('removed', trace)
        self.assertTrue(any(output.iterdir()))

    def test_actual_containment_command_uncertainty_preserves_guest_result_and_gates(self):
        kernel = self.kernel(code=7, errors={9: PermissionError()})
        self.popen(kernel)
        with self.assertRaises(guest.Failure) as caught:
            host.command(['/usr/bin/ssh'], 5)
        self.assertTrue(caught.exception.cleanup_uncertain)
        self.reset()
        self.directory = self.temp
        code, receipt, trace, _, _, _, output = OwnerTrial.owner_pipeline(
            self, heartbeat_alive=False, containment_error=caught.exception,
            observed_code=9, observed_contained=False)
        self.assertEqual(code, 9)
        self.assertFalse(receipt['contained'])
        self.assertFalse(receipt['process_absent'])
        self.assertFalse(receipt['local_files_absent'])
        self.assertFalse(receipt['own_key_absent'])
        self.assertNotIn('removed', trace)
        self.assertTrue(any(output.iterdir()))

    def test_reentrant_close_cannot_restart_signal_sequence(self):
        kernel, master = self.closing()
        original, nested = kernel.killpg, []
        def signal(pid, number):
            if number == 15:
                nested.append(master.close())
            return original(pid, number)
        with patch.object(owned.os, 'killpg', side_effect=signal):
            self.assertTrue(master.close())
        self.assertEqual(nested, [False])
        self.assertSignalsBeforeReapOnly(kernel)

    def test_original_deadline_counts_spawn_signal_reap_probe_and_pipe_delay(self):
        for stage in ('spawn', 'signal', 'reap', 'probe', 'pipe'):
            with self.subTest(stage=stage):
                clock = FakeClock(step=0)
                kernel = self.kernel(clock)
                proc = self.popen(kernel)
                original_wait, original_signal, original_close = proc.wait, kernel.killpg, proc.stdout.close
                def spend(): clock.now += 6
                if stage == 'spawn':
                    def spawn(*args, **kwargs):
                        spend()
                        return proc
                    self.stack.enter_context(patch.object(host.subprocess, 'Popen', side_effect=spawn))
                elif stage == 'reap':
                    def wait(timeout=None):
                        spend()
                        return original_wait(timeout)
                    proc.wait = wait
                elif stage in ('signal', 'probe'):
                    def signal(pid, number):
                        if (number == 9 and stage == 'signal') or (number == 0 and stage == 'probe'):
                            spend()
                        return original_signal(pid, number)
                    self.stack.enter_context(patch.object(owned.os, 'killpg', side_effect=signal))
                else:
                    def close():
                        spend()
                        original_close()
                    self.stack.enter_context(patch.object(proc.stdout, 'close', side_effect=close))
                with self.assertRaises(guest.Failure) as caught:
                    host.command(['/usr/bin/true'], 5)
                self.assertTrue(caught.exception.cleanup_uncertain)
                self.assertTrue(proc.stdout.closed)
                if stage in ('spawn', 'signal'):
                    self.assertNotIn(('reap',), kernel.order())
                if stage == 'reap':
                    self.assertNotIn(('kill', 0), kernel.order())
                self.reset()

    def test_unexpected_wait_status_and_error_never_authorize_destructive_retry(self):
        for observed in (SimpleNamespace(si_pid=99, si_code=os.CLD_EXITED, si_status=0),
                         SimpleNamespace(si_pid=4242, si_code=999, si_status=0),
                         OSError('unexpected wait failure')):
            kernel, master = self.closing()
            with patch.object(owned.os, 'waitid', side_effect=observed if isinstance(observed, Exception) else None,
                              return_value=None if isinstance(observed, Exception) else observed):
                self.assertFalse(master.close())
            self.assertEqual([e for e in kernel.events if e[0] == 'kill'], [])
            self.reset()

    # Coordinator: prior uncertain child cleanup is sticky even when Master closes cleanly.
    def test_uncertain_command_cleanup_withholds_removed_receipt_even_if_master_closes(self):
        value = snapshot()
        rec = dict(value, names=host.spec.names(123, 1, host.spec.UBUNTU_VLAB_CORE))
        registration = Mock()
        registration.current.return_value = rec
        importer = Mock()
        importer.prepare.return_value = ({'posix': {'username': 'owner'}}, 1)
        master = Mock()
        error = guest.Failure('child cleanup uncertain', 124)
        error.cleanup_uncertain = True
        master.start.side_effect = error
        master.close.return_value = True
        def command(args, *unused, **kwargs):
            if args[:3] == ['gcloud', 'auth', 'list']: return (host.OWNER + '\n').encode()
            if args[:3] == ['gcloud', 'config', 'get-value']: return b'(unset)\n'
            if args[:4] == ['gcloud', 'compute', 'os-login', 'describe-profile']:
                return guest.encoded({'name': value['self_user']})
            if args[:2] == ['gcloud', 'version']: return b'{"Google Cloud SDK":"575.0.0"}'
            if args[0] == '/usr/bin/ssh-keygen' and '-q' in args:
                Path(args[-1]).write_text('PUBLIC_SYNTHETIC_KEY')
                Path(args[-1] + '.pub').write_text('ssh-ed25519 UEVCTElDX0ZJWFRVUkU=')
            return b'[]'
        with patch.object(host, 'command', side_effect=command), patch.object(host, 'trusted_source'), \
             patch.object(host, 'OwnKeyImport', return_value=importer), patch.object(host, 'Master', return_value=master), \
             patch.object(host, 'extract_ed25519', return_value='ssh-ed25519 UEVCTElDX0ZJWFRVUkU=\n'), \
             patch.object(host, 'cleanup_own_key') as remove, patch.object(host, 'cleanup_dispatch'), \
             patch('builtins.print') as printed:
            code = host.trial(value, self.temp, self.temp, registration=registration, records=Mock(),
                              login=Mock(user=value['self_user']))
        self.assertEqual(code, 124)
        remove.assert_not_called()
        receipt = json.loads(printed.call_args.args[0])
        self.assertFalse(receipt['process_absent'])
        self.assertFalse(receipt['own_key_absent'])
