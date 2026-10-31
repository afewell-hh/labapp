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
            'operation': 'op-fixed', 'source_sha': 'a'*40, 'self_user': 'users/110405050082684214272'}
    value['preflight'] = {'lease': value['request_id'], 'vm_id': '1234', 'source_sha': 'a'*40,
                          'checked_at': start.strftime('%Y-%m-%dT%H:%M:%SZ'),
                          **{key: 'c'*64 for key in ('quota_sha256', 'network_sha256', 'images_sha256', 'access_sha256', 'egress_sha256')}}
    return value


def worker_detail(category='child-exit', status=17, phase='stage', operation='install-docker'):
    return {'origin': 'worker', 'phase': phase, 'operation': operation,
            'category': category, 'child_status': status}


def result_value(nonce, code, contained, detail=None):
    detail = dict(guest.SUCCESS) if detail is None and code == 0 else detail or worker_detail()
    return {'schema': 2, 'code': code, 'contained': contained, 'nonce': nonce, 'diagnostic': detail}


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
            def start(self): trace.append('master-start')
            def transfer(self, incoming, names, phase='stage'):
                trace.append(('transfer', tuple(names), phase))
                if 'manifest.json' in names:
                    table = guest.manifest(guest.data((output / 'manifest.json').read_bytes()))
                    self_test.assertEqual(set(table['files']), guest.FILES)
            def remote(self, args, phase, cap=30, cleanup=False, limit=65536):
                trace.append(('remote', tuple(args), phase))
                if args[:2] == ['/usr/bin/cat', '/proc/sys/kernel/random/boot_id']: return boot.encode()
                if args[0] == '/usr/bin/cat': return nonce.encode()
                if 'heartbeat' in args:
                    pulse.set()
                    return b''
                if args == host.RESULT_COMMAND:
                    self_test.assertTrue(pulse.wait(2), 'separate heartbeat never started')
                    self_test.assertLessEqual(limit, 4096 + 128)
                    return guest.encoded(result_value(nonce, 0, True))
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
        self.assertEqual((receipt['phase'], receipt['failure_category']), ('guest-result', 'none'))
        self.assertEqual((receipt['guest_diagnostic_status'], receipt['guest_diagnostic']),
                         ('valid', dict(guest.SUCCESS)))
        self.assertIsNone(receipt['guest_service'])


SENTINEL = 'PRIVATE-SENTINEL-kubeconfig-token-password'


class GuestDiagnostics(unittest.TestCase):
    """Bounded fixed reader, strict schema-2 consumer and pre-stop original-master observation."""
    nonce = 'd' * 32

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(host.subprocess, 'Popen', side_effect=AssertionError('no native child')))
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='labapp-diagnostic-')))
        self.directory.chmod(0o700)

    # -- the fixed reader source, executed in-process against a public fixture ----
    def read(self, directory):
        source = host.READ_RESULT
        for old, new, count in (("'/var/lib/labapp-vlab-trial'", repr(str(directory)), 1),
                                ("('/var','/var/lib',d)", '(d,)', 1), ('st_uid!=0', 'st_uid!=os.geteuid()', 2)):
            self.assertEqual(source.count(old), count)  # only fixture location/owner are adapted
            source = source.replace(old, new)
        buffer = io.BytesIO()
        with patch.object(sys, 'stdout', SimpleNamespace(buffer=buffer)):
            with self.assertRaises(SystemExit):
                exec(compile(source, 'fixed-reader', 'exec'), {})
        return buffer.getvalue()

    def test_reader_has_no_selector_and_imports_no_guest_module(self):
        self.assertTrue(host.READ_RESULT.startswith('import os,stat,sys\n'))
        self.assertEqual(host.READ_RESULT.count('import '), 1)
        self.assertEqual(host.READ_RESULT.count('labapp-vlab-trial'), 1)
        self.assertNotIn('argv', host.READ_RESULT)
        self.assertEqual(host.RESULT_COMMAND[:5], ['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-c'])

    def test_reader_returns_only_bounded_private_regular_file_or_fixed_token(self):
        root = self.directory / 'guest'
        self.assertEqual(self.read(root), b'absent')
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        self.assertEqual(self.read(root), b'absent')
        target = root / 'result.json'
        target.write_bytes(b'{"public":1}')
        target.chmod(0o600)
        self.assertEqual(self.read(root), b'{"public":1}')
        target.chmod(0o644)
        self.assertEqual(self.read(root), b'invalid')
        target.chmod(0o600)
        os.link(target, self.directory / 'second-link')
        self.assertEqual(self.read(root), b'invalid')
        (self.directory / 'second-link').unlink()
        target.write_bytes(b'x' * 4097)
        self.assertEqual(self.read(root), b'invalid')
        target.write_bytes(b'x' * 4096)
        self.assertEqual(self.read(root), b'x' * 4096)
        target.unlink()
        other = self.directory / 'other'
        other.write_bytes(b'PRIVATE')
        other.chmod(0o600)
        target.symlink_to(other)
        self.assertEqual(self.read(root), b'invalid')
        target.unlink()
        root.chmod(0o755)
        target.write_bytes(b'{}')
        target.chmod(0o600)
        self.assertEqual(self.read(root), b'invalid')

    def test_reader_refuses_linked_guest_directory(self):
        real = self.directory / 'real'
        real.mkdir(mode=0o700)
        (real / 'result.json').write_bytes(b'{}')
        (real / 'result.json').chmod(0o600)
        link = self.directory / 'linked'
        link.symlink_to(real)
        self.assertEqual(self.read(link), b'invalid')

    # -- strict closed consumer ------------------------------------------------
    def encoded(self, value):
        return guest.encoded(value)

    def test_valid_failure_and_success_records_are_accepted_and_copied_closed(self):
        state, record = host.guest_result(self.encoded(result_value(self.nonce, 17, False)), self.nonce)
        self.assertEqual((state, record['code'], record['diagnostic']), ('valid', 17, worker_detail()))
        state, record = host.guest_result(self.encoded(result_value(self.nonce, 0, True)), self.nonce)
        self.assertEqual((state, record['diagnostic']), ('valid', dict(guest.SUCCESS)))
        self.assertEqual(host.guest_result(b'absent', self.nonce), ('absent', None))
        self.assertEqual(host.guest_result(b'invalid', self.nonce), ('invalid', None))
        self.assertEqual(host.guest_result(b'', self.nonce), ('invalid', None))

    def test_consumer_refuses_every_malformed_or_contradictory_record(self):
        good = result_value(self.nonce, 17, False)
        def changed(**updates):
            return dict(good, **updates)
        def detail(**updates):
            return dict(good, diagnostic=dict(good['diagnostic'], **updates))
        cases = {
            'schema1': {k: good[k] for k in ('code', 'contained', 'nonce')} | {'schema': 1},
            'extra field': changed(extra=1),
            'missing field': {k: v for k, v in good.items() if k != 'diagnostic'},
            'bool schema': changed(schema=True), 'bool code': changed(code=True),
            'string code': changed(code='17'), 'big code': changed(code=256), 'negative code': changed(code=-1),
            'int contained': changed(contained=1), 'wrong nonce': changed(nonce='e' * 32),
            'unknown origin': detail(origin='attacker'), 'unknown category': detail(category='oom-kill'),
            'unknown phase': detail(phase='access'), 'illegal pair': detail(operation='nonce-create'),
            'guardian-only op from worker': detail(operation='worker-supervision'),
            'path label': detail(operation='/root/private'), 'bool status': detail(child_status=True),
            'big status': detail(child_status=256), 'signal positive': detail(category='child-signal', child_status=9),
            'exit negative': detail(child_status=-9), 'timeout with status': detail(category='child-timeout', child_status=124),
            'success code 0 with failure': changed(code=0), 'failure code with none': changed(diagnostic=dict(guest.SUCCESS)),
            'none with exit': changed(code=0, diagnostic=dict(guest.SUCCESS, child_status=0)),
            'diagnostic list': changed(diagnostic=[]), 'diagnostic extra': detail(text=SENTINEL),
            'sentinel operation': detail(operation=SENTINEL), 'sentinel category': detail(category=SENTINEL),
            'unknown only status-invalid': detail(origin='unknown', category='child-exit'),
        }
        for name, value in cases.items():
            with self.subTest(name):
                state, record = host.guest_result(guest.encoded(value), self.nonce)
                self.assertEqual((state, record), ('invalid', None))
        for name, raw in (('duplicate key', b'{"schema":2,"schema":2}'), ('nan', b'{"schema":2,"code":NaN}'),
                          ('infinity', b'{"code":Infinity}'), ('not json', b'PRIVATE ' + SENTINEL.encode()),
                          ('oversize', b' ' * 4097), ('non-utf8', b'\xff\xfe')):
            with self.subTest(name):
                self.assertEqual(host.guest_result(raw, self.nonce), ('invalid', None))

    def test_guest_validator_is_the_same_gate_for_status_and_unknown_origin(self):
        unknown = {'origin': 'unknown', 'phase': 'stage', 'operation': 'install-docker',
                   'category': 'status-invalid', 'child_status': 137}
        self.assertEqual(guest.result_record(result_value(self.nonce, 137, False, unknown), self.nonce)['diagnostic'], unknown)
        guardian = {'origin': 'guardian', 'phase': 'stage', 'operation': 'worker-supervision',
                    'category': 'child-signal', 'child_status': -9}
        self.assertEqual(guest.result_record(result_value(self.nonce, 137, False, guardian), self.nonce)['code'], 137)
        with self.assertRaises(guest.Failure):  # a direct worker signal never claims an inner operation
            guest.diagnostic(dict(guardian, origin='worker'))

    def test_service_observation_is_closed_and_diagnostic_only(self):
        good = b'ActiveState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=1\n'
        self.assertEqual(host.service_observation(good), {'active_state': 'failed', 'result': 'exit-code',
                                                          'exec_code': 1, 'exec_status': 1})
        # signal 9 is reported as the manager reported it, never as an OOM attribution
        killed = b'ActiveState=failed\nResult=signal\nExecMainCode=2\nExecMainStatus=9\n'
        self.assertEqual(host.service_observation(killed)['result'], 'signal')
        for raw in (good + b'MainPID=1\n', good + b'Result=success\n', b'ActiveState=failed\n',
                    good.replace(b'failed', SENTINEL.encode()), good.replace(b'exit-code', b'oom-kill-ish'),
                    good.replace(b'ExecMainStatus=1', b'ExecMainStatus=256'), good.replace(b'ExecMainCode=1', b'ExecMainCode=9'),
                    good.replace(b'ExecMainCode=1', b'ExecMainCode=\xd9\xa3'), b'x' * 513, 'text', None,
                    b'ActiveState=failed\nResult=exit-code\nExecMainCode=-1\nExecMainStatus=1\n'):
            self.assertIsNone(host.service_observation(raw))

    # -- actual trial orchestration: fake master/process only ---------------------
    def drive(self, replies, *, fail_bootstrap=False, service=b'', observation_down=False):
        value = snapshot()
        rec = dict(value, names=host.spec.names(123, 1, host.spec.UBUNTU_VLAB_CORE))
        registration, records = Mock(), Mock()
        registration.current.return_value = rec
        registration.register.return_value = Mock()
        login = Mock(user=value['self_user'])
        importer = Mock()
        importer.prepare.return_value = ({'posix': {'username': 'owner'}}, 1)
        trace, pulse, pending = [], threading.Event(), list(replies)
        nonce, boot = self.nonce, '22222222-2222-4222-8222-222222222222'
        payload_dir, output = self.directory / 'inputs', self.directory / 'output'
        payload_dir.mkdir()
        output.mkdir(mode=0o700)
        pins = {}
        for name in guest.PAYLOADS:
            raw = ('PUBLIC-' + name).encode()
            (payload_dir / name).write_bytes(raw)
            pins[name] = (len(raw), guest.sha(raw))
        def command(args, *unused, **kwargs):
            if args[:3] == ['gcloud', 'auth', 'list']: return (host.OWNER + '\n').encode()
            if args[:3] == ['gcloud', 'config', 'get-value']: return b'(unset)\n'
            if args[:4] == ['gcloud', 'compute', 'os-login', 'describe-profile']:
                return guest.encoded({'name': value['self_user'].removeprefix('users/')})
            if args[:2] == ['gcloud', 'version']: return b'{"Google Cloud SDK":"575.0.0"}'
            if args[0] == '/usr/bin/ssh-keygen' and '-q' in args:
                target = Path(args[-1])
                target.write_text('PUBLIC_SYNTHETIC_KEY_PLACEHOLDER')
                Path(str(target) + '.pub').write_text('ssh-ed25519 UEVCTElDX0ZJWFRVUkU=')
            if args[0] == '/usr/bin/openssl': return ('$5$publicfixture$' + 'a' * 43 + '\n').encode()
            return b'[]'
        def sources(snap, directory):
            table = {}
            for name in guest.SOURCES:
                raw = ('PUBLIC-SOURCE-' + name).encode()
                guest.exclusive(directory / name, raw)
                table[name] = {'bytes': len(raw), 'sha256': guest.sha(raw)}
            return table
        test = self
        class Session:
            def start(self): trace.append('master-start')
            def transfer(self, incoming, names, phase='stage'): trace.append(('transfer', tuple(names)))
            def remote(self, args, phase, cap=30, cleanup=False, limit=65536):
                if args == host.RESULT_COMMAND:
                    trace.append('read-result')
                    if observation_down: raise guest.Failure('original master lost', 124)
                    if not fail_bootstrap: test.assertTrue(pulse.wait(2), 'heartbeat never started')
                    return pending.pop(0) if len(pending) > 1 else pending[0]
                if args == host.SERVICE_COMMAND:
                    trace.append('read-service')
                    if observation_down: raise guest.Failure('original master lost', 124)
                    return service
                trace.append(('remote', tuple(args)))
                if args[:2] == ['/usr/bin/cat', '/proc/sys/kernel/random/boot_id']: return boot.encode()
                if args[0] == '/usr/bin/cat': return nonce.encode()
                if 'heartbeat' in args:
                    pulse.set()
                    return b''
                if host.BOOTSTRAP in args and fail_bootstrap:
                    raise guest.Failure('bootstrap refused', 17)
                if args[:4] == ['/usr/bin/sudo', '-n', '/usr/bin/systemctl', 'stop']:
                    trace.append('stop')
                    if observation_down: raise guest.Failure('original master lost', 124)
                return b''
            def close(self):
                trace.append('master-close')
                return True
        with patch.object(host, 'command', side_effect=command), patch.object(host, 'trusted_source'), \
             patch.object(host, 'OwnKeyImport', return_value=importer), patch.object(host, 'Master', return_value=Session()), \
             patch.object(host, 'source_files', side_effect=sources), patch.object(guest, 'PAYLOADS', pins), \
             patch.object(host, 'extract_ed25519', return_value='ssh-ed25519 UEVCTElDX0ZJWFRVUkU=\n'), \
             patch.object(host.secrets, 'token_hex', side_effect=lambda n: 'd' * (n * 2)), \
             patch.object(host.secrets, 'token_urlsafe', return_value='PUBLIC-NONDEPLOYABLE-PASSWORD'), \
             patch.object(host, 'cleanup_own_key'), patch.object(host, 'cleanup_dispatch'), \
             patch('builtins.print') as printed:
            code = host.trial(value, payload_dir, output, registration=registration, records=records, login=login)
        return code, json.loads(printed.call_args.args[0]), trace, printed.call_args.args[0]

    def test_failed_guest_result_surfaces_closed_diagnostic_and_primary_code(self):
        code, receipt, trace, _ = self.drive([self.encoded(result_value(self.nonce, 17, True))])
        self.assertEqual(code, 17)
        self.assertEqual((receipt['guest_diagnostic_status'], receipt['guest_diagnostic']), ('valid', worker_detail()))
        self.assertEqual((receipt['phase'], receipt['failure_category'], receipt['code']), ('guest-result', 'guest', 17))
        self.assertNotIn('read-service', trace)  # a genuine result needs no manager observation

    def test_success_code_with_uncontained_result_is_still_operational_failure(self):
        code, receipt, _, _ = self.drive([self.encoded(result_value(self.nonce, 0, False))])
        self.assertEqual(code, 1)
        self.assertEqual(receipt['guest_diagnostic'], dict(guest.SUCCESS))
        self.assertFalse(receipt['contained'])

    def test_unsupported_or_contradictory_result_fails_closed_without_echo(self):
        for name, value in (('schema1', {'schema': 1, 'code': 0, 'contained': True, 'nonce': self.nonce}),
                            ('contradiction', dict(result_value(self.nonce, 0, True), code=1)),
                            ('sentinel', dict(result_value(self.nonce, 17, True), extra=SENTINEL))):
            with self.subTest(name):
                self.setUp()
                code, receipt, trace, text = self.drive([self.encoded(value)])
                self.assertEqual(code, 1)
                self.assertEqual((receipt['guest_diagnostic_status'], receipt['guest_diagnostic']), ('invalid', None))
                self.assertFalse(receipt['contained'])
                self.assertNotIn(SENTINEL, text)
                self.assertIn('stop', trace)

    def test_bootstrap_failure_reads_same_master_before_stop_and_keeps_primary(self):
        service = b'ActiveState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=1\n'
        code, receipt, trace, _ = self.drive([self.encoded(result_value(self.nonce, 17, False))],
                                             fail_bootstrap=True, service=service)
        self.assertEqual(code, 17)
        self.assertEqual((receipt['phase'], receipt['failure_category']), ('guest-work', 'guest'))
        self.assertEqual((receipt['guest_diagnostic_status'], receipt['guest_diagnostic']), ('valid', worker_detail()))
        self.assertEqual(receipt['guest_service'], {'active_state': 'failed', 'result': 'exit-code',
                                                    'exec_code': 1, 'exec_status': 1})
        self.assertFalse(receipt['contained'])  # a supplemental read never grants containment
        self.assertLess(trace.index('read-result'), trace.index('read-service'))
        self.assertLess(trace.index('read-service'), trace.index('stop'))
        self.assertEqual(trace.count('master-start'), 1)  # same original master; no reconnect

    def test_terminal_service_without_result_is_pending_not_success(self):
        service = b'ActiveState=inactive\nResult=signal\nExecMainCode=2\nExecMainStatus=9\n'
        code, receipt, _, _ = self.drive([b'absent'], fail_bootstrap=True, service=service)
        self.assertEqual(code, 17)
        self.assertEqual((receipt['guest_diagnostic_status'], receipt['guest_diagnostic']), ('pending', None))
        self.assertEqual(receipt['guest_service']['result'], 'signal')
        self.assertFalse(receipt['contained'])

    def test_unavailable_master_or_hostile_manager_output_stays_unavailable_and_still_stops(self):
        code, receipt, trace, _ = self.drive([b'absent'], fail_bootstrap=True, observation_down=True)
        self.assertEqual(code, 17)
        self.assertEqual((receipt['guest_diagnostic_status'], receipt['guest_diagnostic'], receipt['guest_service']),
                         ('unavailable', None, None))
        self.assertIn('stop', trace)
        self.setUp()
        hostile = ('ActiveState=failed\nResult=' + SENTINEL + '\nExecMainCode=1\nExecMainStatus=1\n').encode()
        code, receipt, _, text = self.drive([b'x' * 5000], fail_bootstrap=True, service=hostile)
        self.assertEqual(code, 17)
        self.assertEqual((receipt['guest_diagnostic_status'], receipt['guest_service']), ('invalid', None))
        self.assertNotIn(SENTINEL, text)

    def test_pre_guest_failure_reports_unavailable(self):
        value = snapshot()
        with patch.object(host, 'trusted_source', side_effect=guest.Failure('denied', 17)), \
             patch.object(host, 'cleanup_dispatch'), patch('builtins.print') as output:
            code = host.trial(value, self.directory, self.directory, registration=Mock(), records=Mock(), login=Mock())
        self.assertEqual(code, 17)
        receipt = json.loads(output.call_args.args[0])
        self.assertEqual((receipt['guest_diagnostic_status'], receipt['guest_diagnostic'], receipt['guest_service']),
                         ('unavailable', None, None))
