"""Owner entrypoints use only fake API/processes and public temporary files."""
from contextlib import ExitStack, nullcontext
import base64
from datetime import datetime, timedelta, timezone
import io
import json
import os
import re
import errno
from pathlib import Path
import runpy
import stat
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from build.gcp import vlab_trial as host
from build.provision import vlab_trial as guest
REAL_HARDEN = guest.harden_secret_process


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


def worker_detail(category='child-exit', status=17, phase='stage', operation='install-hhfab'):
    # Default is NOT install-docker: a Docker-installer child exit/signal selects the #439
    # file-only installer export mode; the core first-failure fixtures below use another stage.
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
        self.stack.enter_context(patch.object(guest, 'harden_secret_process'))
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
        self.assertEqual((receipt['phase'], receipt['host_operation'], receipt['failure_category']),
                         ('preflight', 'source-check', 'guest'))
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
        self.owner_registration_checks(1)

    def test_schema2_owner_registration_preserves_schema_and_checks_history_before_cloud(self):
        self.owner_registration_checks(2)

    def owner_registration_checks(self, schema):
        from build.gcp.lifecycle.test_vlab_trial_profile import world
        w = world()
        if schema == 2:
            from build.gcp.lifecycle.inline_history import plan_migration
            free = dict(schema=1, slot=w.cfg.key, state='FREE', epoch=0, quarantine=[])
            generation = w.store.write(w.cfg.key, free, if_generation_match=0)
            plan = plan_migration(free, generation)
            w.store.write(w.cfg.key, plan['replacement'], if_generation_match=generation)
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
            if schema == 2:
                corrupt, generation = w.store.read(w.cfg.key)
                corrupt['legacy_history'] = dict(count=0, sha256='f'*64)
                generation = w.store.write(w.cfg.key, corrupt, if_generation_match=generation)
                calls = len(w.raw.calls)
                with self.assertRaises(host.Refused): registration.current()
                self.assertEqual(len(w.raw.calls), calls)
                w.store.write(w.cfg.key, rec, if_generation_match=generation)
            boot['sizeGb'] = '800'
            with self.assertRaises(guest.Failure): registration.register('public fixture')
            self.assertNotIn('access', w.record())
            boot['sizeGb'] = '500'
            from build.gcp.lifecycle.test_access import key
            context = registration.register(key())
            self.assertEqual(context.binding['run_id'], 123)
            self.assertEqual(context.binding['vm_id'], rec['ids']['instance'])
            self.assertEqual(w.record()['access']['phase'], 'registered')
            self.assertEqual(w.record()['schema'], schema)
            if schema == 2:
                self.assertEqual(w.record()['legacy_history'], rec['legacy_history'])

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
                self.assertEqual(receipt['host_operation'], receipt['phase'])
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
                       observed_code=0, observed_contained=True, ghcr=None):
        self.remote_inputs = []
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
            def remote(self, args, phase, cap=30, cleanup=False, until=None, limit=65536, input_bytes=None):
                trace.append(('remote', tuple(args), phase))
                self_test.remote_inputs.append((tuple(args), input_bytes))
                if cleanup and containment_error is not None:
                    raise containment_error
                if args[:2] == ['/usr/bin/cat', '/proc/sys/kernel/random/boot_id']: return boot.encode()
                if args[0] == '/usr/bin/cat': return nonce.encode()
                if 'heartbeat' in args:
                    pulse.set()
                    return b''
                if args == host.RESULT_COMMAND:
                    self_test.assertTrue(pulse.wait(2), 'separate heartbeat never started')
                    self_test.assertLessEqual(limit, 4096 + 128)
                    return guest.encoded(result_value(nonce, observed_code, observed_contained,
                                                      worker_detail(status=observed_code) if observed_code else None))
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
            code = host.trial(value, payload_dir, output, registration=registration, records=records, login=login,
                              **({} if ghcr is None else {'ghcr': ghcr}))
        self.printed_text = printed.call_args.args[0]
        return code, json.loads(printed.call_args.args[0]), trace, importer, trust, heartbeat, output

    GHCR = {'schema': 1, 'registry': 'ghcr.io', 'username': 'canary-user', 'token': 'ghp_SYNTHETIC_CANARY_0123456789'}

    def test_default_bootstrap_command_and_stdin_are_unchanged_without_credentials(self):
        code, receipt, trace, _, _, _, _ = self.owner_pipeline()
        self.assertEqual(code, 0)
        boots = [(args, data) for args, data in self.remote_inputs if host.BOOTSTRAP in args]
        self.assertEqual(len(boots), 1)
        args, data = boots[0]
        self.assertIsNone(data)
        self.assertEqual(len(args), 9)
        self.assertNotIn('ghcr-auth', args)

    def test_ghcr_record_travels_only_as_bootstrap_stdin_and_never_in_argv_receipt_or_files(self):
        record = guest.encoded(self.GHCR)
        code, receipt, trace, _, _, _, output = self.owner_pipeline(ghcr=record)
        self.assertEqual(code, 0)
        carriers = [(args, data) for args, data in self.remote_inputs if data is not None]
        self.assertEqual(len(carriers), 1)
        args, data = carriers[0]
        self.assertIn(host.BOOTSTRAP, args)
        self.assertEqual((args[-1], data), ('ghcr-auth', record))
        canary = self.GHCR['token']
        self.assertNotIn(canary, repr(trace))
        self.assertNotIn(canary, self.printed_text)
        self.assertNotIn(canary, json.dumps(receipt))
        self.assertFalse(any(output.iterdir()))
        self.assertEqual([args for args, data in self.remote_inputs if data is not None and args != carriers[0][0]], [])

    def test_actual_master_remote_forwards_stdin_only_when_given(self):
        master = self.master()
        with patch.object(host, 'command', return_value=b'public') as run:
            master.remote(['/usr/bin/true'], 'stage')
            self.assertNotIn('input_bytes', run.call_args.kwargs)
            master.remote(['/usr/bin/true'], 'stage', input_bytes=b'PUBLIC-FIXTURE')
            self.assertEqual(run.call_args.kwargs['input_bytes'], b'PUBLIC-FIXTURE')
        self.assertNotIn('PUBLIC-FIXTURE', ' '.join(run.call_args.args[0]))

    def test_actual_command_refuses_oversize_stdin_without_spawning(self):
        with patch.object(host.subprocess, 'Popen', side_effect=AssertionError('must not spawn')):
            with self.assertRaises(guest.Failure):
                host.command(['/usr/bin/true'], 5, input_bytes=b'x' * 4097)

    def credential_file(self, raw, mode=0o600, name='ghcr.json'):
        path = self.directory / 'creds' / name
        path.parent.mkdir(mode=0o700, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def test_protected_ghcr_input_is_canonicalized_from_an_explicit_owner_private_file(self):
        output = self.directory / 'out'
        output.mkdir(mode=0o700)
        spaced = json.dumps(self.GHCR, indent=2).encode() + b'\n'
        self.assertEqual(host.ghcr_credentials(self.credential_file(spaced), output), guest.encoded(self.GHCR))

    def test_owner_hardens_before_first_secret_read_and_refuses_without_read_on_failure(self):
        import resource
        events = []
        path = self.credential_file(guest.encoded(self.GHCR))
        libc = Mock()
        libc.prctl.side_effect = lambda *args: events.append('dumpability') or 0
        real_read = guest.regular
        with patch.object(guest, 'harden_secret_process', side_effect=REAL_HARDEN), \
             patch.object(resource, 'setrlimit', side_effect=lambda *a: events.append('core-limit')), \
             patch.object(resource, 'getrlimit', return_value=(0, 0)), \
             patch('ctypes.CDLL', return_value=libc), \
             patch.object(guest, 'regular', side_effect=lambda *a, **k: events.append('read') or real_read(*a, **k)):
            self.assertEqual(host.ghcr_credentials(path, self.directory / 'out'), guest.encoded(self.GHCR))
        self.assertEqual(events, ['core-limit', 'dumpability', 'read'])
        with patch.object(guest, 'harden_secret_process', side_effect=OSError('PRIVATE')), \
             patch.object(guest, 'regular') as read, self.assertRaises(guest.Failure) as raised:
            host.ghcr_credentials(path, self.directory / 'out')
        read.assert_not_called()
        self.assertEqual(str(raised.exception), 'GHCR credential input refused')

    def test_protected_ghcr_input_refuses_every_unsafe_or_malformed_source_with_fixed_text(self):
        output = self.directory / 'out'
        output.mkdir(mode=0o700)
        good = guest.encoded(self.GHCR)
        canary = self.GHCR['token']
        cases = {
            'group readable': (self.credential_file(good, 0o640, 'a'), None),
            'world readable': (self.credential_file(good, 0o644, 'b'), None),
            'extra field': (self.credential_file(guest.encoded(dict(self.GHCR, helper='x')), name='c'), None),
            'other registry': (self.credential_file(guest.encoded(dict(self.GHCR, registry='docker.io')), name='d'), None),
            'oversize': (self.credential_file(good + b' ' * 2000, name='e'), None),
            'dotenv style': (self.credential_file(('GITHUB_USERNAME=u\nGITHUB_TOKEN=' + canary + '\n').encode(), name='f'), None),
            'missing': (self.directory / 'creds' / 'absent', None),
            'directory': (self.directory / 'creds', None)}
        link = self.directory / 'creds' / 'link'
        link.symlink_to(self.credential_file(good, name='target'))
        cases['symlink'] = (link, None)
        inside = output / 'ghcr.json'
        inside.write_bytes(good)
        inside.chmod(0o600)
        cases['inside output'] = (inside, None)
        for name, (path, _) in cases.items():
            with self.subTest(name), self.assertRaises(guest.Failure) as failure:
                host.ghcr_credentials(path, output)
            self.assertEqual(str(failure.exception), 'GHCR credential input refused')
            self.assertNotIn(canary, repr(failure.exception))
            self.assertIsNone(failure.exception.__cause__)
        with patch.object(host.os, 'geteuid', return_value=os.geteuid() + 1), self.assertRaises(guest.Failure):
            host.ghcr_credentials(self.credential_file(good, name='g'), output)  # foreign owner
        loose = self.directory / 'loose'
        loose.mkdir()
        loose.chmod(0o777)
        shared = loose / 'ghcr.json'
        shared.write_bytes(good)
        shared.chmod(0o600)
        with self.assertRaises(guest.Failure):  # group/world-writable parent could replace the file
            host.ghcr_credentials(shared, output)

    def test_main_reads_protected_input_before_cloud_work_and_passes_it_only_to_trial(self):
        value = snapshot()
        output = self.directory / 'out'
        output.mkdir(mode=0o700)
        good = guest.encoded(self.GHCR)
        path = self.credential_file(good)
        bad = self.credential_file(guest.encoded(dict(self.GHCR, helper='x')), name='bad')
        served = {path: good, bad: guest.encoded(dict(self.GHCR, helper='x'))}
        with patch.object(guest, 'regular', side_effect=lambda p, n, uid=None, mode=None: (
                served.get(Path(p), guest.encoded(value)))), \
             patch.object(host, 'private_directory', return_value=output), \
             patch.object(host, 'GcsAccessRecords'), patch.object(host, 'GcsSlotStore'), \
             patch.object(host, 'OwnerRegistration'), patch.object(host, 'PolicyCloud'), \
             patch.object(host, 'ComputeRestTransport'), patch.object(host.SelfLogin, 'for_owner'), \
             patch.object(host, 'trial', return_value=0) as run:
            self.assertEqual(host.main(['--snapshot', 'public-fixture', '--payloads', 'inputs', '--output', str(output),
                                        '--ghcr-credentials', str(path)]), 0)
            self.assertEqual(run.call_args.kwargs['ghcr'], good)
            self.assertEqual(host.main(['--snapshot', 'public-fixture', '--payloads', 'inputs', '--output', str(output)]), 0)
            self.assertIsNone(run.call_args.kwargs['ghcr'])
            with self.assertRaises(guest.Failure):
                host.main(['--snapshot', 'public-fixture', '--payloads', 'inputs', '--output', str(output),
                           '--ghcr-credentials', str(bad)])
        self.assertEqual(run.call_count, 2)

    def test_owner_source_never_discovers_or_sources_ambient_credentials(self):
        source = Path(host.__file__).read_text()
        for forbidden in ('local.env', 'GITHUB_TOKEN', 'GITHUB_USERNAME', 'os.environ.get(\'GH', 'dotenv', '.docker/config'):
            self.assertNotIn(forbidden, source)

    def test_actual_owner_pipeline_stages_fixed_inputs_then_closes_before_key_receipt(self):
        code, receipt, trace, importer, trust, _, _ = self.owner_pipeline()
        self.assertEqual(code, 0)
        self.assertTrue(trust.call_args_list[0].kwargs['initial'])
        self.assertFalse(any(c.kwargs.get('initial',False) for c in trust.call_args_list[1:]))
        importer.import_once.assert_called_once()
        self.assertEqual(trace[-3:], ['master-close','removed','captured-cancel'])
        self.assertTrue(all(receipt[k] for k in ('contained','process_absent','own_key_absent','local_files_absent','independent_cleanup_dispatched')))
        self.assertEqual((receipt['phase'], receipt['failure_category']), ('guest-result', 'none'))
        self.assertEqual(receipt['host_operation'], 'result-validate')
        self.assertEqual((receipt['guest_diagnostic_status'], receipt['guest_diagnostic']),
                         ('valid', dict(guest.SUCCESS)))
        self.assertIsNone(receipt['guest_service'])

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

    def test_actual_input_write_errors_reach_closed_owner_receipt_and_keep_cleanup_uncertainty(self):
        for error in (OSError(SENTINEL), BrokenPipeError(SENTINEL)):
            with self.subTest(error=type(error).__name__):
                diagnostic = GuestDiagnostics()
                diagnostic.setUp()
                try:
                    clock = FakeClock()
                    kernel = Kernel(clock, errors={9: PermissionError(SENTINEL)})
                    read_fd, write_fd = os.pipe()
                    stdin = os.fdopen(write_fd, 'wb', buffering=0)
                    proc = FakeProc(kernel, stdin=stdin)
                    actual_command = host.command
                    try:
                        with patch.object(host.subprocess, 'Popen', return_value=proc), \
                             patch.object(owned.os, 'killpg', side_effect=kernel.killpg), \
                             patch.object(owned.os, 'waitid', side_effect=kernel.waitid), \
                             patch.object(owned, 'monotonic', side_effect=clock.monotonic), \
                             patch.object(owned, 'sleep', side_effect=clock.sleep), \
                             patch.object(host.os, 'write', side_effect=error) as write:
                            code, receipt, trace, text = diagnostic.drive([b'absent'], candidate_command=actual_command)
                        write.assert_called_once()
                        self.assertIn(b'PUBLIC-NONDEPLOYABLE-PASSWORD', bytes(write.call_args.args[1]))
                        self.assertEqual((code, receipt['code'], receipt['phase'], receipt['failure_category'],
                                          receipt['host_operation']), (1, 1, 'guest-work', 'unknown', 'candidate-generation'))
                        self.assertFalse(receipt['process_absent'] or receipt['local_files_absent'] or receipt['own_key_absent'])
                        self.assertIn('dispatch-cleanup', trace)
                        self.assertNotIn(SENTINEL, text)
                        self.assertNotIn('PUBLIC-NONDEPLOYABLE-PASSWORD', text)
                        self.assertTrue(stdin.closed and proc.stdout.closed)
                        self.assertLessEqual(clock.now, 10)
                        self.assertSignalsBeforeReapOnly(kernel, kill=False)
                    finally:
                        stdin.close()
                        os.close(read_fd)
                        proc.release()
                finally:
                    diagnostic.doCleanups()

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
        self.exports = []

    # -- the fixed reader source, executed in-process against a public fixture ----
    def read(self, directory, *, fstat=None):
        source = host.READ_RESULT
        for old, new, count in (("'/var/lib/labapp-vlab-trial'", repr(str(directory)), 1),
                                ("('/var','/var/lib',d)", '(d,)', 1), ('st_uid!=0', 'st_uid!=os.geteuid()', 2)):
            self.assertEqual(source.count(old), count)  # only fixture location/owner are adapted
            source = source.replace(old, new)
        buffer = io.BytesIO()
        with ExitStack() as local:
            local.enter_context(patch.object(sys, 'stdout', SimpleNamespace(buffer=buffer)))
            if fstat is not None:
                local.enter_context(patch.object(os, 'fstat', side_effect=fstat))
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

    def test_reader_refuses_wrong_owner_nonregular_and_changed_descriptor(self):
        root = self.directory / 'guest'
        root.mkdir(mode=0o700)
        target = root / 'result.json'
        target.mkdir(mode=0o700)  # openable with NONBLOCK, but not a regular file
        self.assertEqual(self.read(root), b'invalid')
        target.rmdir()
        target.write_bytes(b'{}')
        target.chmod(0o600)
        original = os.fstat
        for field, change in (('st_uid', 1), ('st_ino', 1), ('st_size', 1),
                              ('st_mtime_ns', 1), ('st_ctime_ns', 1)):
            calls = []
            def changed(fd):
                info = original(fd)
                calls.append(fd)
                values = {name: getattr(info, name) for name in
                          ('st_mode', 'st_nlink', 'st_uid', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
                if field == 'st_uid' or len(calls) == 2:
                    values[field] += change
                return SimpleNamespace(**values)
            with self.subTest(field=field):
                self.assertEqual(self.read(root, fstat=changed), b'invalid')
                self.assertEqual(len(calls), 1 if field == 'st_uid' else 2)

    def test_literal_production_reader_uses_only_fixed_path_and_root_owner(self):
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        file = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1,
                               st_size=2, st_ino=42, st_mtime_ns=1, st_ctime_ns=1)
        buffer = io.BytesIO()
        with patch.object(os, 'lstat', return_value=directory) as lookup, \
             patch.object(os, 'open', return_value=91) as opened, \
             patch.object(os, 'fstat', return_value=file), patch.object(os, 'read', return_value=b'{}') as read, \
             patch.object(os, 'close') as closed, \
             patch.object(sys, 'stdout', SimpleNamespace(buffer=buffer)):
            with self.assertRaises(SystemExit):
                exec(compile(host.READ_RESULT, 'fixed-reader', 'exec'), {})
        self.assertEqual([c.args[0] for c in lookup.call_args_list],
                         ['/var', '/var/lib', '/var/lib/labapp-vlab-trial'])
        opened.assert_called_once_with('/var/lib/labapp-vlab-trial/result.json',
                                       os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        read.assert_called_once_with(91, 4097)
        closed.assert_called_once_with(91)
        self.assertEqual(buffer.getvalue(), b'{}')

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

    def test_host_consumes_guardian_policy_supervision_records_and_refuses_mislabels(self):
        # Shape of the final record the actual guardian publishes for a policy refusal
        # during supervision (#418); the guest-side tests produce it with the real guardian.
        policy = {'origin': 'guardian', 'phase': 'fresh', 'operation': 'worker-supervision',
                  'category': 'policy', 'child_status': None}
        for contained in (True, False):
            with self.subTest(contained=contained):
                state, record = host.guest_result(self.encoded(result_value(self.nonce, 1, contained, policy)), self.nonce)
                self.assertEqual((state, record['code'], record['contained'], record['diagnostic']),
                                 ('valid', 1, contained, policy))
        for name, detail in (('worker origin may not claim supervision', dict(policy, origin='worker')),
                             ('policy never carries a child status', dict(policy, child_status=1)),
                             ('unknown origin is status-invalid only', dict(policy, origin='unknown')),
                             ('startup phase label stays closed', dict(policy, phase='bogus')),
                             ('policy cannot be success', dict(policy, category='none'))):
            with self.subTest(name):
                self.assertEqual(host.guest_result(self.encoded(result_value(self.nonce, 1, True, detail)), self.nonce),
                                 ('invalid', None))
        with self.subTest('code 0 cannot carry a policy diagnostic'):
            self.assertEqual(host.guest_result(self.encoded(result_value(self.nonce, 0, True, policy)), self.nonce),
                             ('invalid', None))

    def test_guest_validator_is_the_same_gate_for_status_and_unknown_origin(self):
        unknown = {'origin': 'unknown', 'phase': 'stage', 'operation': 'install-docker',
                   'category': 'status-invalid', 'child_status': 137}
        self.assertEqual(guest.result_record(result_value(self.nonce, 137, False, unknown), self.nonce)['diagnostic'], unknown)
        # Unknown-origin status is context, so no child normalization is inferred.
        context = dict(unknown, child_status=17)
        self.assertEqual(guest.result_record(result_value(self.nonce, 137, False, context), self.nonce)['diagnostic'], context)
        unobserved = worker_detail(status=None)
        self.assertEqual(guest.result_record(result_value(self.nonce, 17, False, unobserved), self.nonce)['diagnostic'], unobserved)
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
    def drive(self, replies, *, fail_bootstrap=False, service=b'', observation_down=False,
              observation_error=None, stop_error=None, private=None, export=b'absent', close=True,
              fault=None, primary_error=None, candidate_command=None, close_error=None, cleanup_error=None):
        value = snapshot()
        rec = dict(value, names=host.spec.names(123, 1, host.spec.UBUNTU_VLAB_CORE))
        registration, records = Mock(), Mock()
        registration.current.return_value = rec
        registration.register.return_value = Mock()
        login = Mock(user=value['self_user'])
        importer = Mock()
        importer.prepare.return_value = ({'posix': {'username': 'owner'}}, 1)
        trace, pulse, pending = [], threading.Event(), list(replies)
        bootstrapped = threading.Event()
        def inject(boundary):
            if fault == boundary:
                trace.append(('fault', boundary))
                raise primary_error if primary_error is not None else RuntimeError(SENTINEL)
        def current():
            if bootstrapped.is_set():
                self.assertIn('bootstrap-complete', trace)
                inject('registration')
            return rec
        registration.current.side_effect = current
        real_trust = host.trusted_source
        def trust(snap, *, initial=False):
            if bootstrapped.is_set() and fault == 'github':
                self.assertIn('bootstrap-complete', trace)
                # Exercise the real github() parser with a successful malformed response.
                real_trust(snap, initial=initial)
        services = list(service) if isinstance(service, list) else [service]
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
            if args[:2] == ['gh', 'api']:
                trace.append('github-success-malformed')
                return ('{"unclosed":"' + SENTINEL).encode()
            if args[:3] == ['gcloud', 'auth', 'list']: return (host.OWNER + '\n').encode()
            if args[:3] == ['gcloud', 'config', 'get-value']: return b'(unset)\n'
            if args[:4] == ['gcloud', 'compute', 'os-login', 'describe-profile']:
                return guest.encoded({'name': value['self_user'].removeprefix('users/')})
            if args[:2] == ['gcloud', 'version']: return b'{"Google Cloud SDK":"575.0.0"}'
            if args[0] == '/usr/bin/ssh-keygen' and '-q' in args:
                target = Path(args[-1])
                target.write_text('PUBLIC_SYNTHETIC_KEY_PLACEHOLDER')
                Path(str(target) + '.pub').write_text('ssh-ed25519 UEVCTElDX0ZJWFRVUkU=')
            if args[0] == '/usr/bin/openssl':
                if candidate_command is not None:
                    return candidate_command(args, *unused, **kwargs)
                inject('candidate')
                return ('$5$publicfixture$' + 'a' * 43 + '\n').encode()
            return b'[]'
        def sources(snap, directory):
            inject('source-stage')
            table = {}
            for name in guest.SOURCES:
                raw = ('PUBLIC-SOURCE-' + name).encode()
                guest.exclusive(directory / name, raw)
                table[name] = {'bytes': len(raw), 'sha256': guest.sha(raw)}
            return table
        test = self
        class Session:
            def start(self): trace.append('master-start')
            def transfer(self, incoming, names, phase='stage'):
                trace.append(('transfer', tuple(names)))
                if 'manifest.json' in names:
                    inject('transfer')
            def remote(self, args, phase, cap=30, cleanup=False, until=None, limit=65536):
                if args == host.RESULT_COMMAND:
                    trace.append('read-result')
                    inject('result')
                    if observation_error is not None and observation_error[0] == 'reader':
                        raise observation_error[1]
                    if observation_down: raise guest.Failure('original master lost', 124)
                    if bootstrapped.is_set(): test.assertTrue(pulse.wait(2), 'heartbeat never started')
                    reply = pending.pop(0) if len(pending) > 1 else pending[0]
                    if isinstance(reply, BaseException): raise reply
                    return reply
                if args == host.SERVICE_COMMAND:
                    trace.append('read-service')
                    inject('service')
                    if observation_error is not None and observation_error[0] == 'manager':
                        raise observation_error[1]
                    if observation_down: raise guest.Failure('original master lost', 124)
                    return services.pop(0) if len(services) > 1 else services[0]
                if 'export-failure' in args:
                    trace.append('export')
                    test.exports.append({'args': list(args), 'cap': cap, 'until': until, 'cleanup': cleanup,
                                         'limit': limit, 'phase': phase})
                    if isinstance(export, BaseException): raise export
                    return export
                trace.append(('remote', tuple(args)))
                if args[:2] == ['/usr/bin/cat', '/proc/sys/kernel/random/boot_id']: return boot.encode()
                if args[0] == '/usr/bin/cat': return nonce.encode()
                if 'heartbeat' in args:
                    pulse.set()
                    return b''
                if host.BOOTSTRAP in args and fail_bootstrap:
                    raise guest.Failure('bootstrap refused', 17)
                if host.BOOTSTRAP in args:
                    inject('bootstrap')
                    trace.append('bootstrap-complete')
                    bootstrapped.set()
                if args[:4] == ['/usr/bin/sudo', '-n', '/usr/bin/systemctl', 'stop']:
                    trace.append('stop')
                    if stop_error is not None: raise stop_error
                    if observation_down: raise guest.Failure('original master lost', 124)
                return b''
            def close(self):
                trace.append('master-close')
                if close_error is not None: raise close_error
                return close
        def cleanup(name):
            trace.append(name)
            if cleanup_error is not None: raise cleanup_error
        with patch.object(host, 'command', side_effect=command), patch.object(host, 'trusted_source', side_effect=trust), \
             patch.object(host, 'OwnKeyImport', return_value=importer), patch.object(host, 'Master', return_value=Session()), \
             patch.object(host, 'source_files', side_effect=sources), patch.object(guest, 'PAYLOADS', pins), \
             patch.object(host, 'extract_ed25519', return_value='ssh-ed25519 UEVCTElDX0ZJWFRVUkU=\n'), \
             patch.object(host.secrets, 'token_hex', side_effect=lambda n: 'd' * (n * 2)), \
             patch.object(host.secrets, 'token_urlsafe', return_value='PUBLIC-NONDEPLOYABLE-PASSWORD'), \
             patch.object(host, 'cleanup_own_key', side_effect=lambda *a, **k: cleanup('remove-key')), \
             patch.object(host, 'cleanup_dispatch', side_effect=lambda *a: cleanup('dispatch-cleanup')), \
             patch('builtins.print') as printed:
            code = host.trial(value, payload_dir, output, registration=registration, records=records, login=login,
                              private=private)
        text = '\n'.join(str(arg) for call in printed.call_args_list for arg in call.args)
        return code, json.loads(printed.call_args.args[0]), trace, text

    def test_host_operations_identify_existing_boundaries_without_exception_data(self):
        cases = {'source-stage': 'source-stage', 'candidate': 'candidate-generation',
                 'transfer': 'source-transfer', 'bootstrap': 'bootstrap',
                 'registration': 'registration-check', 'github': 'source-check',
                 'result': 'result-read', 'service': 'service-read'}
        for fault, operation in cases.items():
            with self.subTest(fault=fault):
                code, receipt, trace, text = self.drive([b'absent'], fault=fault)
                self.assertEqual((code, receipt['code'], receipt['phase'], receipt['failure_category'],
                                  receipt['host_operation']), (1, 1, 'guest-work', 'unknown', operation))
                self.assertIn(receipt['host_operation'], host.HOST_OPERATIONS)
                if fault in ('registration', 'github', 'result', 'service'):
                    self.assertIn('bootstrap-complete', trace)
                if fault == 'github':
                    self.assertLess(trace.index('bootstrap-complete'), trace.index('github-success-malformed'))
                self.assertNotIn(SENTINEL, text)
                self.assertNotIn('RuntimeError', text)
                self.assertNotIn(str(self.directory), text)
                self.assertLess(trace.index('stop'), trace.index('master-close'))
                self.assertLess(trace.index('master-close'), trace.index('remove-key'))
                self.assertLess(trace.index('remove-key'), trace.index('dispatch-cleanup'))
                self.assertTrue(receipt['process_absent'] and receipt['local_files_absent'] and receipt['own_key_absent'])
            self.setUp()

    def test_primary_operation_category_and_code_survive_each_cleanup_failure(self):
        for primary, code, category in ((RuntimeError(SENTINEL), 1, 'unknown'),
                                         (guest.Failure(SENTINEL, 17), 17, 'guest'),
                                         (KeyboardInterrupt(SENTINEL), 130, 'interrupted')):
            for cleanup in ('stop', 'export', 'close', 'key-and-dispatch'):
                with self.subTest(category=category, cleanup=cleanup):
                    kwargs = {'stop': {'stop_error': OSError(SENTINEL)},
                              'export': {'export': OSError(SENTINEL)},
                              'close': {'close_error': OSError(SENTINEL)},
                              'key-and-dispatch': {'cleanup_error': OSError(SENTINEL)}}[cleanup]
                    private = self.directory / 'private'
                    private.mkdir(mode=0o700)
                    result, receipt, trace, text = self.drive(
                        [b'absent'], fault='registration', primary_error=primary, private=private, **kwargs)
                    self.assertEqual((result, receipt['code'], receipt['failure_category'], receipt['host_operation']),
                                     (code, code, category, 'registration-check'))
                    self.assertIn('bootstrap-complete', trace)
                    self.assertIn('dispatch-cleanup', trace)
                    self.assertFalse(receipt['contained'])
                    self.assertNotIn(SENTINEL, text)
                self.setUp()

    def test_host_failure_still_captures_concurrent_guest_bundle_once_with_original_bounds(self):
        private, (code, receipt, trace, text) = self.private_drive(self.export_bytes(), fault='registration')
        self.assertEqual((code, receipt['failure_category'], receipt['host_operation'], receipt['private_diagnostic']),
                         (1, 'unknown', 'registration-check', 'captured'))
        self.assertIn('bootstrap-complete', trace)
        self.assertEqual(len(self.exports), 1)
        self.assertEqual(trace.count('master-start'), 1)
        self.assertLess(trace.index('stop'), trace.index('export'))
        self.assertLess(trace.index('export'), trace.index('master-close'))
        self.assertEqual(self.exports[0]['cap'], host.EXPORT_CAP_SECONDS)
        self.assertLessEqual(self.exports[0]['until'] - host.owned_process.monotonic(), host.EXPORT_CAP_SECONDS)
        self.assertEqual(next(private.iterdir()).read_bytes(), self.export_bytes())
        self.assertNotIn(SENTINEL, text)

    # -- #368 owner-private first-failure extraction (fake original master only) ------
    boot_uuid = '22222222-2222-4222-8222-222222222222'

    def failure_bundle(self, **changes):
        def section(status='unavailable', raw=b''):
            return {'status': status, 'output': base64.b64encode(raw).decode()}
        bundle = {'schema': 3, 'source': 'vlab_core', 'nonce': self.nonce, 'mode': 'fresh', 'operation': 'e' * 32,
                  'invocation': 'f' * 32, 'boot': self.boot_uuid, 'stage': 'unit', 'query_cleanup': 'confirmed',
                  'state': {'status': 'ok', 'phase': 'failed', 'containment': 'verified', 'service_result': None},
                  'primary': {**section(), 'message': 'synthetic ready failure', 'code': 17},
                  'unit_ready': {'status': 'ok', 'message': 'synthetic readiness refusal', 'code': 17,
                                 'route': 'api-final-switches'},
                  'command_context': {**section(), 'label': guest.FAILURE_CONTEXT},
                  'manager': section('ok', b'InvocationID=' + b'f' * 32 + b'\n'),
                  'journal': section('ok', b'native detail ' + SENTINEL.encode())}
        bundle.update(changes)
        return guest.encoded(bundle)

    def export_bytes(self, bundle=None, **envelope):
        fields = {'schema': 1, 'source_sha': 'a' * 40, 'nonce': self.nonce, 'mode': 'fresh',
                  'operation': 'e' * 32, 'invocation': 'f' * 32, 'boot': self.boot_uuid, **envelope}
        return guest.encoded(fields) + b'\n' + (bundle if bundle is not None else self.failure_bundle())

    def private_drive(self, export, **kwargs):
        self.exports = []
        private = self.directory / 'private'
        private.mkdir(mode=0o700, exist_ok=True)
        return private, self.drive([self.encoded(result_value(self.nonce, 17, True))], private=private,
                                   export=export, **kwargs)

    def test_failed_trial_captures_exactly_once_between_stop_and_original_master_close(self):
        private, (code, receipt, trace, text) = self.private_drive(self.export_bytes(), fail_bootstrap=True)
        self.assertEqual((code, receipt['private_diagnostic']), (17, 'captured'))
        self.assertEqual(len(self.exports), 1)
        self.assertLess(trace.index('stop'), trace.index('export'))
        self.assertLess(trace.index('export'), trace.index('master-close'))
        self.assertEqual(trace.count('master-start'), 1)  # no reconnect or reauthentication
        call = self.exports[0]
        self.assertEqual((call['args'][:4], call['args'][-3:-1], call['cleanup'], call['phase']),
                         (['/usr/bin/sudo', '-n', '/usr/bin/python3', str(guest.ROOT / 'vlab_trial.py')],
                          ['export-failure', '--nonce'], True, 'persistence'))
        self.assertLessEqual(call['until'] - host.owned_process.monotonic(), host.EXPORT_CAP_SECONDS)
        files = list(private.iterdir())
        self.assertEqual([f.name for f in files], ['first-failure-' + snapshot()['request_id'] + '.bin'])
        self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
        self.assertEqual(files[0].read_bytes(), self.export_bytes())
        self.assertEqual(list((self.directory / 'output').iterdir()), [])  # output stays empty
        self.assertTrue(receipt['local_files_absent'] and receipt['process_absent'])
        for forbidden in (SENTINEL, str(private), 'native detail'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(receipt['guest_diagnostic'], worker_detail())  # public semantics unchanged

    def test_success_and_missing_private_directory_never_extract(self):
        self.exports = []
        code, receipt, trace, _ = self.drive([self.encoded(result_value(self.nonce, 0, True))],
                                             private=self.directory, export=self.export_bytes())
        self.assertEqual((receipt['private_diagnostic'], self.exports), ('skipped', []))  # success: no capture
        self.setUp()
        self.exports = []
        code, receipt, trace, _ = self.drive([self.encoded(result_value(self.nonce, 17, True))], export=self.export_bytes())
        self.assertEqual((receipt['private_diagnostic'], self.exports), ('skipped', []))  # no retention directory

    def test_every_binding_mismatch_or_hostile_export_is_invalid_and_retains_nothing(self):
        good = self.failure_bundle()
        other = 'b' * 32
        missing = {'status': 'unavailable', 'message': None, 'code': None, 'route': None}
        def ready(status, message=None, code=None, route=None, **extra):
            return {'status': status, 'message': message, 'code': code, 'route': route, **extra}
        cases = {
            'foreign source': self.export_bytes(source_sha='b' * 40), 'foreign nonce': self.export_bytes(nonce=other),
            'resume mode': self.export_bytes(mode='resume'), 'other boot': self.export_bytes(boot='3' * 8 + self.boot_uuid[8:]),
            'envelope operation differs': self.export_bytes(operation='9' * 32),
            'envelope invocation differs': self.export_bytes(invocation='9' * 32),
            'null bundle invocation conflicts': self.export_bytes(self.failure_bundle(invocation=None)),
            'null envelope invocation conflicts': self.export_bytes(invocation=None),
            'stale manager with matching null invocation': self.export_bytes(
                self.failure_bundle(invocation=None, stage='manager', unit_ready=missing,
                                    journal={'status': 'unavailable', 'output': ''}), invocation=None),
            'legacy schema 1': self.export_bytes(self.failure_bundle(schema=1)),
            'legacy schema 2': self.export_bytes(self.failure_bundle(schema=2)),
            'bool schema': self.export_bytes(self.failure_bundle(schema=True)),
            'missing unit_ready': self.export_bytes(self.failure_bundle(unit_ready=None)),
            'unit_ready legacy three keys': self.export_bytes(self.failure_bundle(
                unit_ready={'status': 'ok', 'message': 'x', 'code': 1})),
            'unit_ready ok with null text': self.export_bytes(self.failure_bundle(unit_ready=ready('ok'))),
            'unit_ready ok bool code': self.export_bytes(
                self.failure_bundle(unit_ready=ready('ok', 'x', True))),
            'unit_ready ok bad code': self.export_bytes(
                self.failure_bundle(unit_ready=ready('ok', 'x', 256))),
            'unit_ready ok control text': self.export_bytes(
                self.failure_bundle(unit_ready=ready('ok', 'x\ny', 1))),
            'unit_ready unavailable with text': self.export_bytes(
                self.failure_bundle(unit_ready=ready('unavailable', 'x', 1))),
            'unit_ready invalid with code': self.export_bytes(
                self.failure_bundle(unit_ready=ready('invalid', None, 0))),
            'unit_ready extra field': self.export_bytes(
                self.failure_bundle(unit_ready=ready('unavailable', x=1))),
            'unit_ready bad status': self.export_bytes(
                self.failure_bundle(unit_ready=ready('captured'))),
            'route unknown': self.export_bytes(
                self.failure_bundle(unit_ready=ready('ok', 'x', 1, 'api-final-pods'))),
            'route generic': self.export_bytes(
                self.failure_bundle(unit_ready=ready('ok', 'x', 1, 'kubectl-list'))),
            'route wrong type': self.export_bytes(
                self.failure_bundle(unit_ready=ready('ok', 'x', 1, 7))),
            'route free text': self.export_bytes(
                self.failure_bundle(unit_ready=ready('ok', 'x', 1, '/usr/local/bin/hhfab vlab wait-switches'))),
            'route list': self.export_bytes(
                self.failure_bundle(unit_ready=ready('ok', 'x', 1, ['svc-entry']))),
            'route on unavailable': self.export_bytes(
                self.failure_bundle(unit_ready=ready('unavailable', route='svc-entry'))),
            'route on invalid': self.export_bytes(
                self.failure_bundle(unit_ready=ready('invalid', route='api-initial-nodes'))),
            'unit_ready ok without invocation': self.export_bytes(
                self.failure_bundle(invocation=None, stage='manager',
                                    journal={'status': 'unavailable', 'output': ''}), invocation=None),
            'bundle nonce': self.export_bytes(self.failure_bundle(nonce=other)),
            'bundle boot': self.export_bytes(self.failure_bundle(boot='3' * 8 + self.boot_uuid[8:])),
            'bundle mode': self.export_bytes(self.failure_bundle(mode='resume')),
            'bundle extra field': self.export_bytes(self.failure_bundle(extra=SENTINEL)),
            'no envelope': good, 'envelope only': guest.encoded({}) , 'token invalid': b'invalid', 'empty': b'',
            'oversize': b'x' * (host.EXPORT_READ_LIMIT + 1), 'not bytes': 'text',
            'extra envelope field': guest.encoded({'schema': 1, 'x': 1}) + b'\n' + good,
        }
        for name, raw in cases.items():
            with self.subTest(name):
                self.setUp()
                private, (code, receipt, trace, text) = self.private_drive(raw)
                self.assertEqual((code, receipt['private_diagnostic']), (17, 'invalid'))
                self.assertEqual(list(private.iterdir()), [])
                self.assertNotIn(SENTINEL, text)

    def test_schema3_unit_ready_section_is_typed_and_diagnostic_only(self):
        # Observed refusal, never the initiating cause: every typed state keeps the trial result.
        sections = [{'status': 'ok', 'message': 'synthetic readiness refusal', 'code': 0, 'route': None},
                    {'status': 'unavailable', 'message': None, 'code': None, 'route': None},
                    {'status': 'invalid', 'message': None, 'code': None, 'route': None}]
        sections += [{'status': 'ok', 'message': 'child deadline exceeded', 'code': 124, 'route': route}
                     for route in guest.FAILURE_ROUTES]
        for section in sections:
            with self.subTest(section['status'], route=section['route']):
                self.setUp()
                bundle = self.failure_bundle(unit_ready=section)
                private, (code, receipt, _, _) = self.private_drive(self.export_bytes(bundle))
                self.assertEqual((code, receipt['private_diagnostic']), (17, 'captured'))
                self.assertEqual(next(private.iterdir()).read_bytes(), self.export_bytes(bundle))

    def test_reservation_style_null_bundle_and_absent_are_accepted_or_explicit(self):
        null = self.failure_bundle(stage='reserve', operation=None, invocation=None,
                                   unit_ready={'status': 'unavailable', 'message': None, 'code': None,
                                               'route': None},
                                   manager={'status': 'unavailable', 'output': ''},
                                   journal={'status': 'unavailable', 'output': ''})
        private, (code, receipt, _, _) = self.private_drive(self.export_bytes(null, operation=None, invocation=None))
        self.assertEqual(receipt['private_diagnostic'], 'captured')
        self.setUp()
        private, (code, receipt, _, _) = self.private_drive(self.export_bytes(null))
        self.assertEqual(receipt['private_diagnostic'], 'invalid')  # old live operation cannot vouch for null
        self.setUp()
        private, (code, receipt, _, _) = self.private_drive(b'absent')
        self.assertEqual((receipt['private_diagnostic'], list(private.iterdir())), ('absent', []))

    # -- #412 terminal-result-bound resume export (host side) ---------------------
    RESUME = {'phase': 'resume', 'operation': 'core-start-resume'}

    def resume_drive(self, export, detail=None, result_code=17, **kwargs):
        """Like private_drive but the primary validated guest result is a chosen worker diagnostic."""
        self.exports = []
        private = self.directory / 'private'
        private.mkdir(mode=0o700, exist_ok=True)
        detail = worker_detail(**{'status': result_code, **(detail or self.RESUME)})
        return private, self.drive([self.encoded(result_value(self.nonce, result_code, True, detail))],
                                   private=private, export=export, **kwargs)

    def test_accept_failure_expected_mode_is_host_held_and_never_taken_from_guest_bytes(self):
        resume = self.export_bytes(self.failure_bundle(mode='resume'), mode='resume')
        fresh = self.export_bytes()
        args = ('a' * 40, self.nonce, self.boot_uuid)
        self.assertEqual(host.accept_failure(resume, *args, 'resume'), ('captured', resume))
        self.assertEqual(host.accept_failure(fresh, *args), ('captured', fresh))
        self.assertEqual(host.accept_failure(fresh, *args, 'fresh'), ('captured', fresh))
        self.assertEqual(host.accept_failure(resume, *args), ('invalid', None))  # default stays fresh-only
        for name, raw, mode in (('resume bytes, fresh expected', resume, 'fresh'),
                                ('fresh bytes, resume expected', fresh, 'resume'),
                                ('resume envelope, fresh bundle',
                                 self.export_bytes(self.failure_bundle(), mode='resume'), 'resume'),
                                ('fresh envelope, resume bundle',
                                 self.export_bytes(self.failure_bundle(mode='resume')), 'resume'),
                                ('unknown mode', resume, 'other')):
            with self.subTest(name):
                self.assertEqual(host.accept_failure(raw, *args, mode), ('invalid', None))

    def test_validated_resume_terminal_result_retains_resume_export(self):
        resume = self.export_bytes(self.failure_bundle(mode='resume'), mode='resume')
        private, (code, receipt, trace, text) = self.resume_drive(resume)
        self.assertEqual((code, receipt['private_diagnostic'], receipt['contained']), (17, 'captured', True))
        self.assertEqual(next(private.iterdir()).read_bytes(), resume)
        self.assertEqual(receipt['guest_diagnostic'], worker_detail(**self.RESUME))
        self.assertEqual(len(self.exports), 1)
        self.assertEqual(self.exports[0]['args'][-3:-1], ['export-failure', '--nonce'])  # remote command fixed
        self.assertNotIn(SENTINEL, text)

    def test_resume_export_is_refused_unless_primary_terminal_result_is_resume_core_start(self):
        resume = self.export_bytes(self.failure_bundle(mode='resume'), mode='resume')
        fresh = self.export_bytes()
        for name, detail, raw, expected in (
                ('fresh stage failure, resume bytes', None, resume, 'invalid'),
                ('other resume operation, resume bytes', {'phase': 'resume', 'operation': 'core-stop'}, resume, 'invalid'),
                ('fresh phase operation name, resume bytes',
                 {'phase': 'fresh', 'operation': 'core-start-fresh'}, resume, 'invalid'),
                ('resume terminal, fresh bytes', self.RESUME, fresh, 'invalid'),
                ('resume terminal, mixed envelope', self.RESUME,
                 self.export_bytes(self.failure_bundle(), mode='resume'), 'invalid'),
                ('fresh terminal, fresh bytes', {'phase': 'stage', 'operation': 'install-hhfab'}, fresh, 'captured')):
            with self.subTest(name):
                self.setUp()
                private, (code, receipt, _, _) = self.resume_drive(raw, detail or {'phase': 'stage', 'operation': 'install-hhfab'})
                self.assertEqual((code, receipt['private_diagnostic']), (17, expected))
                self.assertEqual(len(list(private.iterdir())), 1 if expected == 'captured' else 0)

    def test_resume_mode_is_frozen_before_supplemental_observation_and_never_from_unvalidated_result(self):
        resume = self.export_bytes(self.failure_bundle(mode='resume'), mode='resume')
        supplemental = self.encoded(result_value(self.nonce, 17, True, worker_detail(**self.RESUME)))
        private = self.private_dir()
        # Bootstrap fails before any primary result is consumed. The real observer
        # then obtains a VALID resume result, which must remain diagnostic only.
        code, receipt, trace, _ = self.drive([supplemental], fail_bootstrap=True,
                                            private=private, export=resume)
        self.assertEqual((code, receipt['private_diagnostic'], receipt['contained']),
                         (17, 'invalid', False))
        self.assertEqual(receipt['guest_diagnostic'], worker_detail(**self.RESUME))
        self.assertEqual(receipt['guest_diagnostic_status'], 'valid')
        self.assertLess(trace.index('read-result'), trace.index('stop'))
        self.assertEqual(list(private.iterdir()), [])
        for primary in (b'absent', b'invalid'):
            with self.subTest(primary=primary):
                self.setUp()
                private = self.private_dir()
                # An invalid primary record is consumed before failure; observe_guest does
                # not replace invalid status, and it cannot authorize resume either.
                code, receipt, _, _ = self.drive([primary], fail_bootstrap=(primary == b'absent'),
                                                private=private, export=resume)
                self.assertEqual(receipt['private_diagnostic'], 'invalid')
                self.assertEqual(list(private.iterdir()), [])

    def test_resume_query_cleanup_uncertainty_retains_bytes_and_primary_result(self):
        resume = self.export_bytes(self.failure_bundle(mode='resume', query_cleanup='uncertain'), mode='resume')
        private, (code, receipt, trace, _) = self.resume_drive(resume)
        self.assertEqual((code, receipt['private_diagnostic'], receipt['contained']), (17, 'invalid', True))
        self.assertEqual(next(private.iterdir()).read_bytes(), resume)
        self.assertTrue(all(receipt[k] for k in ('process_absent', 'local_files_absent', 'own_key_absent')))
        self.assertIn('master-close', trace)
        self.assertIn('dispatch-cleanup', trace)

    def test_resume_export_interruption_preserves_primary_and_cleanup(self):
        class ExportAbort(BaseException):
            cleanup_uncertain = True
        for error in (KeyboardInterrupt(SENTINEL), SystemExit(143), ExportAbort(SENTINEL)):
            with self.subTest(error=type(error).__name__):
                self.setUp()
                private, (code, receipt, trace, text) = self.resume_drive(error)
                self.assertEqual((code, receipt['code'], receipt['private_diagnostic'], receipt['contained']),
                                 (17, 17, 'unavailable', True))
                self.assertEqual(receipt['guest_diagnostic'], worker_detail(**self.RESUME))
                self.assertIn('master-close', trace)
                self.assertIn('dispatch-cleanup', trace)
                uncertain = getattr(error, 'cleanup_uncertain', False)
                self.assertEqual(receipt['process_absent'], not uncertain)
                self.assertEqual(receipt['local_files_absent'], not uncertain)
                self.assertEqual(receipt['own_key_absent'], not uncertain)
                self.assertEqual('remove-key' in trace, not uncertain)
                self.assertEqual(list(private.iterdir()), [])
                self.assertNotIn(SENTINEL, text)

    def private_dir(self):
        private = self.directory / 'private'
        private.mkdir(mode=0o700, exist_ok=True)
        self.exports = []
        return private

    def test_capture_acceptance_requires_host_initial_boot(self):
        for boot in (None, '', host.ZERO_BOOT):
            with self.subTest(boot=boot):
                self.assertEqual(host.accept_failure(self.export_bytes(), 'a' * 40, self.nonce, boot),
                                 ('invalid', None))

    def test_guest_query_uncertainty_is_not_reported_as_clean_capture(self):
        bundle = self.failure_bundle(query_cleanup='uncertain')
        private, (code, receipt, _, _) = self.private_drive(self.export_bytes(bundle))
        self.assertEqual((code, receipt['private_diagnostic']), (17, 'invalid'))
        self.assertEqual(len(list(private.iterdir())), 1)  # retained, but never labelled captured
        self.assertTrue(receipt['process_absent'])  # guest namespace is not host process absence

    def test_extraction_failure_timeout_or_budget_never_changes_primary_or_containment(self):
        for name, export in (('master lost', guest.Failure('original master lost', 124)),
                             ('timeout', guest.Failure('bounded host child timeout', 124)),
                             ('generic', RuntimeError(SENTINEL))):
            with self.subTest(name):
                self.setUp()
                private, (code, receipt, trace, text) = self.private_drive(export, fail_bootstrap=True)
                self.assertEqual((code, receipt['private_diagnostic'], receipt['contained']), (17, 'unavailable', False))
                self.assertTrue(receipt['process_absent'] and receipt['own_key_absent'])
                self.assertIn('stop', trace)
                self.assertEqual(list(private.iterdir()), [])
                self.assertNotIn(SENTINEL, text)
        self.setUp()
        with patch.object(guest.Clock, 'cleanup_remaining', return_value=host.EXPORT_TEARDOWN_RESERVE + 1):
            private, (code, receipt, trace, _) = self.private_drive(self.export_bytes())
        self.assertEqual((receipt['private_diagnostic'], self.exports), ('skipped', []))
        self.assertIn('master-close', trace)

    def test_existing_private_file_is_never_overwritten(self):
        self.exports = []
        private = self.directory / 'private'
        private.mkdir(mode=0o700)
        existing = private / ('first-failure-' + snapshot()['request_id'] + '.bin')
        existing.write_bytes(b'EARLIER')
        _, (code, receipt, _, _) = self.private_drive(self.export_bytes())
        self.assertEqual((receipt['private_diagnostic'], existing.read_bytes()), ('unavailable', b'EARLIER'))

    # -- #439 private bounded installer failure evidence --------------------------------
    # The ACTUAL guest writer + guest exporter produce the bytes; the host side is the real
    # accepter/extractor/retention driven through a fake ORIGINAL master. No Docker/APT/VM.
    INSTALLER = {'phase': 'stage', 'operation': 'install-docker'}
    AUX = {'phase': 'stage', 'operation': 'aux-update'}

    def aux_update_failure(self, contract, code, out):
        """Drive the ACTUAL guest auxiliary orchestration to its failing `update` (no APT/network).

        Only the bounded child, the package inventory and the fixed APT tree helper are faked;
        the real apt_run -> hook -> capture_installer_failure -> private writer chain runs.
        """
        def setup(directory, snapshot_name):
            for name in ('lists', 'lists/partial', 'archives', 'archives/partial', 'parts', 'preferences'):
                (directory / name).mkdir(parents=True, exist_ok=True)
            for name in ('fixed.conf', 'sources.list'):
                (directory / name).write_bytes(b'')
            return ['/usr/bin/apt-get'], str(directory / 'fixed.conf')
        apt_tmp = Path(tempfile.mkdtemp(dir=self.directory, prefix='apt-tmp-'))
        with ExitStack() as local:
            local.enter_context(patch.dict(sys.modules, {'qemu_offline': SimpleNamespace(setup=setup)}))
            local.enter_context(patch.object(guest, 'APT_TMP', apt_tmp))
            local.enter_context(patch.object(guest, 'installed', return_value={}))
            local.enter_context(patch.object(guest, 'run', return_value=b''))
            local.enter_context(patch.object(guest, 'call_bounded', side_effect=(
                lambda args, seconds, env=None: (code, out) if 'update' in args else (0, b''))))
            local.enter_context(patch.object(os, 'geteuid', return_value=os.getuid()))
            with self.assertRaises(guest.Failure) as raised:
                guest.provision_aux(guest.Clock(contract), contract)
        self.assertEqual((raised.exception.code, raised.exception.category, raised.exception.child_status),
                         (code, 'child-exit', code))

    def installer_export(self, out=b'native installer output \xff\x00', code=17, snap=None,
                         operation='install-docker'):
        """-> (raw export, snapshot, terminal diagnostic). Real writer, real exporter."""
        snap = snap or snapshot()
        contract = {'schema': 1, 'nonce': self.nonce, 'lease': snap['request_id'], 'epoch': 1, 'run_id': 1,
                    'attempt': 1, 'body_sha256': 'b' * 64, 'vm_id': '1234', 'boot_id': '5678',
                    'image_id': '4575951068918267275', 'admitted_at': snap['reserved_at'],
                    'deadline': snap['deadline'], 'boot_uuid': self.boot_uuid, 'source_sha': snap['source_sha']}
        terminal = worker_detail('child-exit' if code > 0 else 'child-signal', code, phase='stage',
                                 operation=operation)
        root = Path(tempfile.mkdtemp(dir=self.directory, prefix='guest-root-'))
        reader = guest.regular
        with ExitStack() as local:
            local.enter_context(patch.object(guest, 'ROOT', root))
            local.enter_context(patch.object(guest, 'kernel_boot', return_value=self.boot_uuid))
            local.enter_context(patch.object(guest, 'regular', side_effect=(
                lambda p, n, uid=None, mode=None: reader(p, n, None if uid == 0 else uid, mode))))
            local.enter_context(patch.object(guest, 'load_sibling', side_effect=AssertionError('no core load')))
            (root / 'contract.json').write_bytes(guest.encoded(contract))
            (root / 'result.json').write_bytes(guest.encoded(
                {'schema': 2, 'code': code if code > 0 else 128 - code, 'contained': True,
                 'nonce': self.nonce, 'diagnostic': terminal}))
            (root / 'result.json').chmod(0o600)
            if operation == 'aux-update':
                self.aux_update_failure(contract, code, out)
            else:
                guest.capture_installer_failure(contract, guest.Clock(contract), code, out)
            raw = guest.export_failure(self.nonce)
        return raw, snap, terminal

    def installer_args(self, snap, terminal):
        return (('a' * 40, self.nonce, self.boot_uuid, 'installer'),
                {'lease': snap['request_id'], 'admitted_at': snap['reserved_at'], 'detail': terminal})

    def remade(self, raw, envelope=lambda e: e, body=lambda b: b):
        first, _, rest = raw.partition(b'\n')
        return guest.encoded(envelope(json.loads(first))) + b'\n' + guest.encoded(body(json.loads(rest)))

    def test_installer_actual_writer_guest_export_host_accept_extract_and_retention(self):
        for out, code in ((b'', 1), (b'x', 255), (bytes(range(256)) * 80, 17), (b'\x00\xffA' * 2000, 1)):
            with self.subTest(size=len(out), code=code):
                self.setUp()
                raw, snap, terminal = self.installer_export(out, code)
                envelope = json.loads(raw.partition(b'\n')[0])
                self.assertEqual(envelope, {
                    'schema': 2, 'kind': 'installer', 'source_sha': 'a' * 40, 'nonce': self.nonce,
                    'lease': snap['request_id'], 'boot': self.boot_uuid, 'phase': 'stage',
                    'operation': 'install-docker', 'outcome': 'exit', 'status': code})
                args, installer = self.installer_args(snap, terminal)
                self.assertEqual(host.accept_failure(raw, *args, installer), ('captured', raw))
                private = self.directory / 'private'
                private.mkdir(mode=0o700)
                calls = []
                class Master:
                    def remote(self, argv, phase, cap=30, cleanup=False, until=None, limit=65536):
                        calls.append((list(argv), phase, cap, cleanup, limit))
                        return raw
                uncertain = threading.Event()
                clock = guest.Clock({'admitted_at': snap['reserved_at'], 'deadline': snap['deadline']})
                with patch.object(guest, 'first_failure_bundle', side_effect=AssertionError('no core bundle')):
                    status = host.extract_failure(Master(), clock, self.nonce, snap, self.boot_uuid, private,
                                                  snap['request_id'], uncertain, 'installer', installer)
                self.assertEqual(status, 'captured')
                self.assertFalse(uncertain.is_set())
                self.assertEqual(len(calls), 1)  # exactly one fixed original-master command
                self.assertEqual(calls[0][0], host.export_command(self.nonce))
                self.assertEqual((calls[0][1:4], calls[0][4]), (('persistence', host.EXPORT_CAP_SECONDS, True),
                                                                 host.EXPORT_READ_LIMIT))
                kept = list(private.iterdir())
                self.assertEqual([p.name for p in kept], ['installer-failure-' + snap['request_id'] + '.bin'])
                self.assertEqual((kept[0].read_bytes(), stat.S_IMODE(kept[0].stat().st_mode)), (raw, 0o600))
                self.assertLessEqual(len(raw), host.EXPORT_READ_LIMIT)

    def test_installer_signal_status_and_truncated_shape_survive_the_whole_chain(self):
        raw, snap, terminal = self.installer_export(b'S' * (guest.INSTALLER_WHOLE + 1), -9)
        body = json.loads(raw.partition(b'\n')[2])
        self.assertEqual((body['outcome'], body['status'], body['output_status'], body['omitted'],
                          body['kept_head'], body['kept_tail']), ('signal', -9, 'truncated', 1, 1024, 12288))
        args, installer = self.installer_args(snap, terminal)
        self.assertEqual(host.accept_failure(raw, *args, installer)[0], 'captured')
        private = self.directory / 'private'
        private.mkdir(mode=0o700)
        calls = []
        class Master:
            def remote(self, argv, phase, cap=30, cleanup=False, until=None, limit=65536):
                calls.append((list(argv), phase, cap, cleanup, until, limit))
                return raw
        uncertain = threading.Event()
        clock = guest.Clock({'admitted_at': snap['reserved_at'], 'deadline': snap['deadline']})
        with patch.object(guest, 'first_failure_bundle', side_effect=AssertionError('no core bundle')), \
             patch.object(host.owned_process, 'monotonic', return_value=100), \
             patch.object(clock, 'cleanup_remaining', return_value=100):
            status = host.extract_failure(Master(), clock, self.nonce, snap, self.boot_uuid, private,
                                          snap['request_id'], uncertain, 'installer', installer)
        self.assertEqual(status, 'captured')
        self.assertFalse(uncertain.is_set())
        self.assertEqual(calls, [(host.export_command(self.nonce), 'persistence', host.EXPORT_CAP_SECONDS,
                                 True, 100 + host.EXPORT_CAP_SECONDS, host.EXPORT_READ_LIMIT)])
        kept = list(private.iterdir())
        self.assertEqual([p.name for p in kept], ['installer-failure-' + snap['request_id'] + '.bin'])
        self.assertEqual((kept[0].read_bytes(), stat.S_IMODE(kept[0].stat().st_mode), kept[0].stat().st_nlink,
                          kept[0].stat().st_uid), (raw, 0o600, 1, os.geteuid()))
        self.assertEqual(terminal, worker_detail('child-signal', -9, **self.INSTALLER))

    def test_installer_acceptance_rejects_every_host_binding_and_shape_mismatch(self):
        raw, snap, terminal = self.installer_export()
        args, installer = self.installer_args(snap, terminal)
        put = lambda **kw: (lambda d: {**d, **kw})
        drop = lambda key: (lambda d: {k: v for k, v in d.items() if k != key})
        admitted = guest.stamp(snap['reserved_at'])
        stamp = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        both = lambda **kw: dict(envelope=put(**kw), body=put(**kw))
        cases = {
            'foreign source': self.remade(raw, **both(source_sha='b' * 40)),
            'foreign nonce': self.remade(raw, **both(nonce='9' * 32)),
            'foreign lease': self.remade(raw, **both(lease='22222222-2222-4222-8222-222222222222')),
            'foreign boot': self.remade(raw, **both(boot='33333333-3333-4333-8333-333333333333')),
            'other operation': self.remade(raw, **both(operation='install-hhfab')),
            'other phase': self.remade(raw, **both(phase='fresh')),
            'outcome vs terminal': self.remade(raw, **both(outcome='signal', status=-9)),
            'status vs terminal': self.remade(raw, **both(status=18)),
            'envelope only differs': self.remade(raw, envelope=put(lease='22222222-2222-4222-8222-222222222222')),
            'body only differs': self.remade(raw, body=put(nonce='9' * 32)),
            'body status only differs': self.remade(raw, body=put(status=18)),
            'captured before admission': self.remade(raw, body=put(captured_at=int(admitted - 5))),
            'captured at stage cutoff': self.remade(raw, body=put(captured_at=int(admitted + 35 * 60))),
            'captured long after': self.remade(raw, body=put(captured_at=int(admitted + 3600))),
            'captured bool': self.remade(raw, body=put(captured_at=True)),
            'captured float': self.remade(raw, body=put(captured_at=admitted)),
            'captured UTC': self.remade(raw, body=put(captured_at=snap['reserved_at'])),
            'legacy public outcome': self.remade(raw, **both(outcome='child-exit')),
            'captured malformed': self.remade(raw, body=put(captured_at='2026-01-01 00:00:00')),
            'envelope schema 1': self.remade(raw, envelope=put(schema=1)),
            'envelope bool schema': self.remade(raw, envelope=put(schema=True)),
            'envelope bool status': self.remade(raw, envelope=put(status=True)),
            'envelope extra': self.remade(raw, envelope=put(extra=1)),
            'envelope missing': self.remade(raw, envelope=drop('lease')),
            'envelope cross kind': self.remade(raw, envelope=put(kind='first-failure')),
            'body bool schema': self.remade(raw, body=put(schema=True)),
            'body bool count': self.remade(raw, body=put(omitted=False)),
            'body extra': self.remade(raw, body=put(extra='x')),
            'body missing': self.remade(raw, body=drop('tail')),
            'body count lie': self.remade(raw, body=put(observed=99999)),
            'body status lie': self.remade(raw, body=put(output_status='truncated')),
            'body noncanonical base64': self.remade(raw, body=put(head='\n' + json.loads(raw.partition(b'\n')[2])['head'])),
            'body noncanonical json': raw.partition(b'\n')[0] + b'\n ' + raw.partition(b'\n')[2],
            'duplicate key': raw.replace(b'"tail":', b'"nonce":"' + self.nonce.encode() + b'","tail":', 1),
            'no separator': raw.replace(b'\n', b'', 1),
            'trailing bytes': raw + b'\n',
            'oversize': raw + b' ' * guest.INSTALLER_LIMIT,
            'invalid token': b'invalid',
            'legacy first-failure bytes': self.export_bytes(),
        }
        for name, bad in cases.items():
            with self.subTest(name):
                self.assertEqual(host.accept_failure(bad, *args, installer), ('invalid', None))
        for name, change in (('source', ('b' * 40, self.nonce, self.boot_uuid)), ('nonce', ('a' * 40, '9' * 32, self.boot_uuid)),
                             ('boot', ('a' * 40, self.nonce, '3' * 8 + self.boot_uuid[8:])),
                             ('zero boot', ('a' * 40, self.nonce, host.ZERO_BOOT))):
            with self.subTest('host expected ' + name):
                self.assertEqual(host.accept_failure(raw, *change, 'installer', installer), ('invalid', None))
        for name, bad in (('lease', dict(installer, lease='22222222-2222-4222-8222-222222222222')),
                          ('admitted later', dict(installer, admitted_at=stamp(admitted + 3600))),
                          ('signal terminal', dict(installer, detail=worker_detail('child-signal', -9, **self.INSTALLER))),
                          ('other operation terminal', dict(installer, detail=worker_detail(operation='install-hhfab'))),
                          ('timeout terminal', dict(installer, detail=worker_detail('child-timeout', None, **self.INSTALLER))),
                          ('no terminal', dict(installer, detail=None))):
            with self.subTest('host terminal ' + name):
                self.assertEqual(host.accept_failure(raw, *args, bad), ('invalid', None))
        for mode in ('fresh', 'resume', 'other'):
            with self.subTest('mode ' + mode):
                self.assertEqual(host.accept_failure(raw, 'a' * 40, self.nonce, self.boot_uuid, mode),
                                 ('invalid', None))
        self.assertEqual(host.accept_failure(b'absent', *args, installer), ('absent', None))
        self.assertEqual(host.accept_failure(raw, *args, None), ('invalid', None))

    def test_installer_trial_drive_retains_private_file_and_leaves_public_receipt_and_cleanup_unchanged(self):
        raw, snap, terminal = self.installer_export()
        private, (code, receipt, trace, text) = self.resume_drive(raw, self.INSTALLER)
        self.assertEqual((code, receipt['code'], receipt['private_diagnostic'], receipt['contained']),
                         (17, 17, 'captured', True))
        self.assertEqual(receipt['guest_diagnostic'], worker_detail(operation='install-docker'))
        self.assertEqual(len(self.exports), 1)
        self.assertEqual([f.name for f in private.iterdir()], ['installer-failure-' + snapshot()['request_id'] + '.bin'])
        self.assertLess(trace.index('export'), trace.index('master-close'))
        self.assertLess(trace.index('master-close'), trace.index('remove-key'))
        self.assertIn('dispatch-cleanup', trace)
        self.assertTrue(receipt['process_absent'] and receipt['local_files_absent'] and receipt['own_key_absent'])
        self.assertEqual(set(receipt), {'schema', 'code', 'contained', 'process_absent', 'phase', 'failure_category',
                                        'host_operation', 'own_key_absent', 'local_files_absent',
                                        'independent_cleanup_dispatched', 'lease', 'guest_diagnostic_status',
                                        'guest_diagnostic', 'guest_service', 'private_diagnostic'})
        for forbidden in ('native installer output', str(private)):
            self.assertNotIn(forbidden, text)

    # -- aux-update uses the SAME private export; operation is bound three ways ------------
    def test_aux_update_actual_orchestration_writer_guest_export_host_accept_extract_and_retention(self):
        for out, code in ((b'E: Failed to fetch \xff\x00\n', 100), (b'', 100), (b'U' * (guest.INSTALLER_WHOLE + 7), 100)):
            with self.subTest(size=len(out)):
                self.setUp()
                raw, snap, terminal = self.installer_export(out, code, operation='aux-update')
                envelope = json.loads(raw.partition(b'\n')[0])
                self.assertEqual(envelope, {
                    'schema': 2, 'kind': 'installer', 'source_sha': 'a' * 40, 'nonce': self.nonce,
                    'lease': snap['request_id'], 'boot': self.boot_uuid, 'phase': 'stage',
                    'operation': 'aux-update', 'outcome': 'exit', 'status': 100})
                body = json.loads(raw.partition(b'\n')[2])
                self.assertEqual((body['operation'], body['status'], body['observed']), ('aux-update', 100, len(out)))
                if len(out) <= guest.INSTALLER_WHOLE:
                    self.assertEqual(base64.b64decode(body['head']), out)
                args, installer = self.installer_args(snap, terminal)
                self.assertEqual(host.accept_failure(raw, *args, installer), ('captured', raw))
                private = self.directory / 'private'
                private.mkdir(mode=0o700)
                calls = []
                class Master:
                    def remote(self, argv, phase, cap=30, cleanup=False, until=None, limit=65536):
                        calls.append((list(argv), phase, cap, cleanup))
                        return raw
                uncertain = threading.Event()
                clock = guest.Clock({'admitted_at': snap['reserved_at'], 'deadline': snap['deadline']})
                with patch.object(guest, 'first_failure_bundle', side_effect=AssertionError('no core bundle')):
                    status = host.extract_failure(Master(), clock, self.nonce, snap, self.boot_uuid, private,
                                                  snap['request_id'], uncertain, 'installer', installer)
                self.assertEqual(status, 'captured')
                self.assertFalse(uncertain.is_set())
                self.assertEqual(calls, [(host.export_command(self.nonce), 'persistence', host.EXPORT_CAP_SECONDS, True)])
                kept = list(private.iterdir())
                self.assertEqual([p.name for p in kept], ['installer-failure-' + snap['request_id'] + '.bin'])
                self.assertEqual((kept[0].read_bytes(), stat.S_IMODE(kept[0].stat().st_mode)), (raw, 0o600))

    def test_aux_update_trial_drive_leaves_public_receipt_cleanup_order_and_no_core_query_unchanged(self):
        raw, snap, terminal = self.installer_export(b'E: Failed to fetch\n', 100, operation='aux-update')
        with patch.object(guest, 'first_failure_bundle', side_effect=AssertionError('no core bundle')):
            private, (code, receipt, trace, text) = self.resume_drive(raw, self.AUX, result_code=100)
        self.assertEqual((code, receipt['code'], receipt['private_diagnostic'], receipt['contained']),
                         (100, 100, 'captured', True))
        self.assertEqual(receipt['guest_diagnostic'], worker_detail(status=100, operation='aux-update'))
        self.assertEqual(len(self.exports), 1)
        self.assertEqual([f.name for f in private.iterdir()], ['installer-failure-' + snapshot()['request_id'] + '.bin'])
        self.assertLess(trace.index('export'), trace.index('master-close'))
        self.assertLess(trace.index('master-close'), trace.index('remove-key'))
        self.assertIn('dispatch-cleanup', trace)
        self.assertTrue(receipt['process_absent'] and receipt['local_files_absent'] and receipt['own_key_absent'])
        self.assertNotIn('Failed to fetch', text)
        self.assertNotIn(str(private), text)

    def test_aux_update_and_docker_operations_cannot_be_substituted_in_either_direction(self):
        docker, snap, docker_terminal = self.installer_export()
        aux, _, aux_terminal = self.installer_export(b'E: x', 100, snap, 'aux-update')
        put = lambda **kw: (lambda d: {**d, **kw})
        same = lambda raw, op: self.remade(raw, envelope=put(operation=op), body=put(operation=op))
        for name, raw, terminal in (
                ('docker bytes, aux terminal', docker, aux_terminal),
                ('aux bytes, docker terminal', aux, docker_terminal),
                ('docker bytes relabelled aux, docker terminal', same(docker, 'aux-update'), docker_terminal),
                ('aux bytes relabelled docker, aux terminal', same(aux, 'install-docker'), aux_terminal),
                ('docker bytes relabelled aux, aux terminal (status/outcome differ)', same(docker, 'aux-update'), aux_terminal),
                ('aux bytes relabelled docker, docker terminal (status differs)', same(aux, 'install-docker'), docker_terminal),
                ('envelope only swapped', self.remade(aux, envelope=put(operation='install-docker')), aux_terminal),
                ('body only swapped', self.remade(aux, body=put(operation='install-docker')), aux_terminal),
                ('other stage operation', same(aux, 'aux-check'), aux_terminal)):
            with self.subTest(name):
                args, installer = self.installer_args(snap, terminal)
                self.assertEqual(host.accept_failure(raw, *args, installer), ('invalid', None))
        for name, raw, terminal in (('docker', docker, docker_terminal), ('aux', aux, aux_terminal)):
            with self.subTest('control ' + name):
                args, installer = self.installer_args(snap, terminal)
                self.assertEqual(host.accept_failure(raw, *args, installer)[0], 'captured')
        # a non-installer stage operation never selects the installer mode
        for operation in ('aux-check', 'aux-install', 'aux-download'):
            self.assertFalse(guest.installer_terminal(worker_detail(operation=operation, phase='stage')))
        self.assertTrue(guest.installer_terminal(worker_detail(operation='aux-update', phase='stage')))
        self.assertFalse(guest.installer_terminal(worker_detail(operation='aux-update', phase='fresh')))

    def test_installer_mode_is_frozen_from_validated_terminal_never_from_payload_or_other_terminals(self):
        raw, _, _ = self.installer_export()
        fresh = self.export_bytes()
        for name, export, detail, expected in (
                ('installer terminal, core bytes', fresh, self.INSTALLER, 'invalid'),
                ('hhfab terminal, installer bytes', raw, {'phase': 'stage', 'operation': 'install-hhfab'}, 'invalid'),
                ('resume terminal, installer bytes', raw, self.RESUME, 'invalid'),
                ('installer terminal, installer bytes', raw, self.INSTALLER, 'captured')):
            with self.subTest(name):
                self.setUp()
                private, (code, receipt, _, _) = self.resume_drive(export, detail)
                self.assertEqual((code, receipt['private_diagnostic']), (17, expected))
                self.assertEqual(len(list(private.iterdir())), 1 if expected == 'captured' else 0)

    def test_installer_extraction_failures_budget_collision_and_stickiness_preserve_primary(self):
        raw, snap, terminal = self.installer_export()
        args, installer = self.installer_args(snap, terminal)
        class Abort(BaseException):
            cleanup_uncertain = True
        for name, export, expected in (('master lost', guest.Failure('original master lost', 124), 'unavailable'),
                                       ('generic', RuntimeError(SENTINEL), 'unavailable'),
                                       ('invalid reply', b'invalid', 'invalid'), ('absent', b'absent', 'absent')):
            with self.subTest(name):
                self.setUp()
                private, (code, receipt, trace, text) = self.resume_drive(export, self.INSTALLER)
                self.assertEqual((code, receipt['private_diagnostic'], receipt['contained']), (17, expected, True))
                self.assertEqual(list(private.iterdir()), [])
                self.assertIn('master-close', trace)
                self.assertNotIn(SENTINEL, text)
        self.setUp()
        private, (code, receipt, trace, _) = self.resume_drive(Abort(SENTINEL), self.INSTALLER)
        self.assertEqual((code, receipt['private_diagnostic'], receipt['process_absent'],
                          receipt['own_key_absent']), (17, 'unavailable', False, False))  # sticky uncertainty
        self.setUp()
        with patch.object(guest.Clock, 'cleanup_remaining', return_value=host.EXPORT_TEARDOWN_RESERVE + 1):
            private, (code, receipt, trace, _) = self.resume_drive(raw, self.INSTALLER)
        self.assertEqual((receipt['private_diagnostic'], self.exports), ('skipped', []))
        self.setUp()
        private = self.directory / 'private'
        private.mkdir(mode=0o700)
        existing = private / ('installer-failure-' + snapshot()['request_id'] + '.bin')
        existing.write_bytes(b'EARLIER')
        _, (code, receipt, _, _) = self.resume_drive(raw, self.INSTALLER)
        self.assertEqual((code, receipt['private_diagnostic'], existing.read_bytes()), (17, 'unavailable', b'EARLIER'))

    def test_retention_kind_is_a_closed_source_choice(self):
        lease = snapshot()['request_id']
        private = self.directory / 'private'
        private.mkdir(mode=0o700)
        for kind in ('../escape', 'other', '', None):
            with self.subTest(kind=kind), self.assertRaises(guest.Failure):
                host.retain_private(private, lease, b'x', kind)
        self.assertEqual(list(private.iterdir()), [])
        host.retain_private(private, lease, b'x', 'installer-failure')
        with self.assertRaises(FileExistsError):
            host.retain_private(private, lease, b'y', 'installer-failure')
        self.assertEqual((private / ('installer-failure-' + lease + '.bin')).read_bytes(), b'x')

    def test_export_process_uncertainty_stays_sticky_through_successful_close(self):
        class ExportAbort(BaseException):
            cleanup_uncertain = True
        private, (code, receipt, trace, text) = self.private_drive(ExportAbort(SENTINEL), fail_bootstrap=True)
        self.assertEqual((code, receipt['private_diagnostic']), (17, 'unavailable'))
        self.assertIn('master-close', trace)
        self.assertIn('dispatch-cleanup', trace)
        self.assertNotIn('remove-key', trace)
        self.assertTrue(all(not receipt[k] for k in ('process_absent', 'local_files_absent', 'own_key_absent')))
        self.assertTrue(any((self.directory / 'output').iterdir()))
        self.assertNotIn(SENTINEL, text)

    def test_private_directory_argument_must_be_owner_private_and_outside_output(self):
        output = self.directory / 'out'
        output.mkdir(mode=0o700)
        wide = self.directory / 'wide'
        wide.mkdir()
        wide.chmod(0o755)
        good = self.directory / 'private-good'
        good.mkdir(mode=0o700)
        def main(target):
            with patch.object(host.guest, 'regular', return_value=guest.encoded(snapshot())), \
                 patch.object(host, 'expected_snapshot'), patch.object(host, 'GcsAccessRecords'), \
                 patch.object(host, 'GcsSlotStore'), patch.object(host, 'OwnerRegistration'), \
                 patch.object(host, 'PolicyCloud'), patch.object(host, 'ComputeRestTransport'), \
                 patch.object(host.SelfLogin, 'for_owner'), patch.object(host, 'trial', return_value=0) as run:
                try:
                    return host.main(['--snapshot', str(self.directory / 's'), '--payloads', str(self.directory),
                                      '--output', str(output), '--private-diagnostics', str(target)]), run
                except guest.Failure:
                    return 'refused', run
        for target in (wide, output, self.directory, self.directory / 'absent-dir'):
            with self.subTest(target=target.name):
                outcome = main(target) if target.exists() else None
                if outcome is None:
                    with self.assertRaises(OSError):
                        main(target)
                    continue
                self.assertEqual(outcome[0], 'refused')
                outcome[1].assert_not_called()
        result, run = main(good)
        self.assertEqual(result, 0)
        self.assertEqual(run.call_args.kwargs['private'], good)

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
                            ('contradictory exit', result_value(self.nonce, 17, True, worker_detail(status=18))),
                            ('contradictory signal', result_value(self.nonce, 17, True, worker_detail('child-signal', -9))),
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

    def test_bootstrap_failure_with_terminal_service_keeps_primary(self):
        service = b'ActiveState=inactive\nResult=signal\nExecMainCode=2\nExecMainStatus=9\n'
        code, receipt, _, _ = self.drive([b'absent'], fail_bootstrap=True, service=service)
        self.assertEqual(code, 17)
        self.assertEqual((receipt['guest_diagnostic_status'], receipt['guest_diagnostic']), ('pending', None))
        self.assertEqual(receipt['guest_service']['result'], 'signal')
        self.assertFalse(receipt['contained'])

    def test_missing_result_polling_stops_promptly_for_terminal_service_after_one_recheck(self):
        for state in ('inactive', 'failed'):
            with self.subTest(state=state):
                self.setUp()
                service = ('ActiveState=' + state + '\nResult=signal\nExecMainCode=2\nExecMainStatus=9\n').encode()
                code, receipt, trace, text = self.drive([b'absent'], service=service)
                self.assertEqual(code, 1)
                self.assertEqual((receipt['guest_diagnostic_status'], receipt['guest_diagnostic']), ('missing', None))
                self.assertEqual(receipt['guest_service']['active_state'], state)
                self.assertEqual(trace.count('read-result'), 2)
                self.assertEqual(trace.count('read-service'), 1)
                self.assertLess(trace.index('read-service'), trace.index('read-result', trace.index('read-service')))
                self.assertIn('stop', trace)
                self.assertIn('dispatch-cleanup', trace)
                self.assertFalse(receipt['contained'])
                self.assertNotIn(SENTINEL, text)

    def test_terminal_recheck_accepts_only_genuine_result_and_pending_states_remain_bounded(self):
        terminal = b'ActiveState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=1\n'
        code, receipt, trace, _ = self.drive([b'absent', self.encoded(result_value(self.nonce, 17, True))], service=terminal)
        self.assertEqual((code, receipt['contained'], receipt['guest_diagnostic_status']), (17, True, 'valid'))
        self.assertNotIn('stop', trace)
        for service in (b'ActiveState=active\nResult=success\nExecMainCode=0\nExecMainStatus=0\n', b'PRIVATE-' + SENTINEL.encode()):
            self.setUp()
            cutoff = guest.Failure('cutoff', 124, 'phase-cutoff')
            code, receipt, trace, text = self.drive([b'absent', cutoff], service=service)
            self.assertEqual(code, 124)
            self.assertFalse(receipt['contained'])
            self.assertIn('stop', trace)
            self.assertIn('dispatch-cleanup', trace)
            self.assertNotIn(SENTINEL, text)

    def test_each_supplemental_baseexception_preserves_uncertainty_through_successful_close(self):
        class ObservationAbort(BaseException):
            cleanup_uncertain = True
        for source in ('reader', 'manager', 'stop'):
            with self.subTest(source=source):
                self.setUp()
                error = ObservationAbort(SENTINEL)
                kwargs = {'stop_error': error} if source == 'stop' else {'observation_error': (source, error)}
                code, receipt, trace, text = self.drive([b'absent'], fail_bootstrap=True, **kwargs)
                self.assertEqual(code, 17)
                self.assertIn('master-close', trace)
                self.assertIn('dispatch-cleanup', trace)
                self.assertNotIn('remove-key', trace)
                self.assertTrue(all(not receipt[k] for k in ('process_absent', 'local_files_absent', 'own_key_absent')))
                self.assertTrue(any((self.directory / 'output').iterdir()))
                self.assertNotIn(SENTINEL, text)

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


# ---- Fixed source-inactive management caller (#506): synthetic only --------------------------------
# The caller reuses the unchanged Master/OwnerRegistration/trusted_source/cleanup of vlab_trial. These tests use
# fake masters and in-memory registrations: no ssh, gcloud, GitHub, cloud, Docker or native tool is started.
import time


def load_caller():
    from build.gcp import management_trial
    return management_trial


VIEWER_PASSWORD = 'Viewer_pw_0123456789'


def handoff_bytes(nonce):
    return guest.encoded({'schema': 1, 'nonce': nonce, 'login': 'labapp-viewer-abc123', 'password': VIEWER_PASSWORD,
                          'path': '/d/chartpanel?viewPanel=7', 'port': 3000})


class FakeManagementMaster:
    """Records every original-master call; models only the fixed guest command grammar."""
    def __init__(self, program):
        self.program = program
        self.calls, self.transfers, self.checks, self.closed = [], [], 0, 0
        self.options, self.target = ['-o', 'ControlPath=/fake/master.sock'], 'labapp-trial-1234'
        self.failing_step, self.fail_heartbeat, self.lost_after = None, False, None
        self.heartbeat_failed = threading.Event()
        self.ran, self.torn, self.on_bootstrap = [], False, None
        self.marker_matches = True
        self.sample_mono, self.sample_skew, self.sample_delay = 1000.0, 0, 0

    def check(self, until=None):
        self.checks += 1
        if self.lost_after is not None and self.checks > self.lost_after:
            raise guest.Failure('original master lost', 31)

    def close(self):
        self.closed += 1
        return True

    def transfer(self, incoming, names, phase='stage'):
        self.transfers.append((incoming, list(names), phase))

    def typed(self, nonce):
        p = self.program
        record = p.public_record(p.initial_state(nonce))
        for name in self.ran:
            record['steps'][name] = 'ok'
        if self.failing_step:
            status = getattr(self, 'failure_status', 17)
            if self.torn and getattr(self, 'late_status', None) is not None:
                status = self.late_status  # the receipt read AFTER cancel differs from the primary seen earlier
            record['steps'][self.failing_step] = 'failed'
            record['failure'] = {'step': self.failing_step, 'category': getattr(self, 'failure_category', 'child-exit'),
                                 'child_status': status}
        elif len(self.ran) == len(p.STEP_NAMES):
            record['observed'] = {k: True for k in p.OBSERVED}
        final = getattr(self, 'final_terminal', None)
        if self.torn and final is not None:  # #510: the later status lives ONLY in the separate typed terminal
            record['terminal'] = {'status': final[1], 'origin': final[0], 'group': 'uncertain'}
        record['teardown'] = 'complete' if self.torn else 'pending'
        return guest.encoded(record)

    def remote(self, args, phase, cap=30, cleanup=False, until=None, limit=65536, input_bytes=None):
        args = list(args)
        self.calls.append((args, phase, cleanup))
        if args[0] == '/usr/bin/cat' and args[1].endswith('/marker'):
            return Path(args[1]).parent.name.removeprefix('labapp-vlab-').encode() if self.marker_matches else b'wrong'
        if 'heartbeat' in args:
            if self.fail_heartbeat:
                self.heartbeat_failed.set()
                raise guest.Failure('heartbeat transport', 9)
            return b''
        if args[:3] == ['/usr/bin/python3', '-I', '-c']:  # the fixed guest clock sample (#508)
            self.sample_requests = getattr(self, 'sample_requests', 0) + 1
            time.sleep(self.sample_delay)
            return json.dumps({'boot': '22222222-2222-4222-8222-222222222222', 'nonce': args[4],
                               'wall': time.time() + self.sample_skew, 'mono': self.sample_mono}).encode()
        if args[0] == '/usr/bin/sudo' and '-I' in args and '-c' in args and self.on_bootstrap:
            self.on_bootstrap()
        nonce = args[args.index('--nonce') + 1] if '--nonce' in args else None
        if 'export-viewer' in args:
            return handoff_bytes(nonce)
        if 'cancel' in args:
            self.torn = True
            return b''
        if 'result' in args:
            if not self.torn:  # the guest's ONE worker progresses by itself; the host never executes a step
                if self.fail_heartbeat:
                    self.heartbeat_failed.wait(2)
                    time.sleep(.1)  # let the heartbeat thread publish its failure to the host loop
                elif self.failing_step:
                    self.ran = list(self.program.STEP_NAMES[:self.program.STEP_NAMES.index(self.failing_step)])
                else:
                    self.ran = list(self.program.STEP_NAMES)
            return self.typed(nonce)
        return b''


class ManagementCaller(unittest.TestCase):
    def setUp(self):
        self.caller = load_caller()
        self.program = self.caller.program
        original = os.umask(0o077)
        os.umask(original)
        self.addCleanup(os.umask, original)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(host.subprocess, 'Popen', side_effect=AssertionError('no native child')))
        self.stack.enter_context(patch.object(self.caller, 'PROGRESS_INTERVAL', 0))
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='labapp-mgmt-out-')))
        self.private = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='labapp-mgmt-priv-')))
        self.directory.chmod(0o700)
        self.private.chmod(0o700)

    def sequence(self, master, *, private=None, value=None, registration=None, browser=('verified', True),
                 trusted=None, clock=None):
        caller, program = self.caller, self.program
        value = value or snapshot()
        registration = registration or Mock()
        source = {'vlab_trial.py': {'bytes': 1, 'sha256': 'a' * 64},
              'owned_process.py': {'bytes': 1, 'sha256': 'c' * 64},
              'management_trial.py': {'bytes': 1, 'sha256': 'b' * 64}}

        def fake_enroll(snap, output, reg, records, login, rec, clk, failed, initial, held):
            held.master, held.context, held.operation = master, object(), 'guest-probe'
            initial['boot_uuid'] = '22222222-2222-4222-8222-222222222222'
            return rec
        with ExitStack() as stack:
            stack.enter_context(patch.object(caller, 'enroll', side_effect=fake_enroll))
            stage = stack.enter_context(patch.object(caller, 'stage_program', return_value=(source, {'files': {}})))
            stack.enter_context(patch.object(host, 'trusted_source', side_effect=trusted))
            dispatch = stack.enter_context(patch.object(host, 'cleanup_dispatch'))
            stack.enter_context(patch.object(caller, 'cleanup_own_key'))
            session = stack.enter_context(patch.object(caller, 'browser_session', return_value=browser))
            if clock is not None:
                stack.enter_context(patch.object(program, 'ManagementClock', clock))
            printed = stack.enter_context(patch('builtins.print'))
            code = caller.sequence(value, self.directory, self.directory, registration=registration,
                                   records=Mock(), login=Mock(), private=private)
        return code, json.loads(printed.call_args.args[0]), SimpleNamespace(
            registration=registration, stage=stage, dispatch=dispatch, session=session)

    # -- inactive surface and fixed grammar --------------------------------------------------------
    def test_activation_is_held_before_any_file_or_cloud_object(self):
        caller = self.caller
        with patch.object(host, 'GcsAccessRecords', side_effect=AssertionError('no cloud')), \
             patch.object(host, 'PolicyCloud', side_effect=AssertionError('no cloud')), \
             patch.object(host, 'gcloud_token', side_effect=AssertionError('no token')):
            for call in (lambda: caller.trial(), lambda: caller.trial(snapshot(), self.directory, self.directory),
                         lambda: caller.main(['--snapshot', '/nonexistent', '--payloads', '/x', '--output', '/y']),
                         lambda: caller.main(['--snapshot', '/nonexistent', '--payloads', '/x', '--output', '/y',
                                              '--activate'])):
                with self.assertRaises(guest.Failure) as raised:
                    call()
                self.assertEqual(str(raised.exception), 'management activation held')
        with patch.object(sys, 'argv', ['management_trial']), patch.object(caller.signal, 'signal'), \
             patch.object(sys, 'stderr', io.StringIO()):
            with self.assertRaises(SystemExit) as status:
                runpy.run_module('build.gcp.management_trial', run_name='__main__')
        self.assertEqual(status.exception.code, 1)
        import inspect
        self.assertNotIn('activate', inspect.signature(caller.sequence).parameters)

    def test_vlab_entrypoint_and_tables_are_unchanged_by_the_management_caller(self):
        self.assertEqual(set(guest.PAYLOADS), {'hhfab.tar.gz', 'kubectl'})
        self.assertFalse(any('management' in name for name in guest.SOURCES))
        self.assertEqual(guest.PHASES['persistence'], 105)
        import inspect
        self.assertEqual(list(inspect.signature(host.main).parameters), ['argv'])
        self.assertEqual(list(inspect.signature(host.trial).parameters),
                         ['snapshot', 'payloads', 'output', 'registration', 'records', 'login', 'private', 'ghcr'])

    def test_commands_are_a_closed_grammar_with_no_selector(self):
        caller, program = self.caller, self.program
        nonce = 'a' * 32
        # #508: the host has no per-step or teardown command at all; only the four closed host actions.
        self.assertFalse(hasattr(caller, 'step_command') or hasattr(caller, 'STEP_CAPS'))
        self.assertEqual(program.HOST_ACTIONS, ('heartbeat', 'export-viewer', 'result', 'cancel'))
        for action in program.HOST_ACTIONS:
            self.assertEqual(caller.fixed_command(action, nonce)[:5], ['/usr/bin/sudo', '-n', '/usr/bin/python3',
                             str(program.MROOT / 'management_trial.py'), action])
        for action in ('bootstrap', 'step', 'sh', 'worker', 'guardian', 'poststop', 'expire', 'teardown'):
            with self.assertRaises(guest.Failure):
                caller.fixed_command(action, nonce)
        with self.assertRaises(guest.Failure):
            caller.fixed_command('result', 'not-a-nonce')
        self.assertEqual(caller.fixed_command('heartbeat', nonce, 3)[-2:], ['--sequence', '3'])

    def test_stub_authenticates_each_module_before_executing_it(self):
        stub = self.caller.STUB
        self.assertLess(stub.index('hexdigest()==expected'), stub.index('exec('))
        self.assertEqual(stub.count('exec('), 1)
        self.assertIn("load('vlab_trial.py',sys.argv[2],'vlab_trial')", stub)
        self.assertIn("load('owned_process.py',sys.argv[3],'owned_process')", stub)
        self.assertIn("load('management_trial.py',sys.argv[4],'management_trial')", stub)
        incoming = '/tmp/labapp-vlab-' + 'a' * 32
        command = self.caller.bootstrap_command(incoming,
                                                {'vlab_trial.py': {'sha256': 'b' * 64},
                                                 'owned_process.py': {'sha256': 'd' * 64},
                                                 'management_trial.py': {'sha256': 'c' * 64}},
                                                {'files': {}})
        self.assertEqual(command[:5], ['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-c'])
        self.assertEqual(command[5], stub)
        self.assertEqual(command[6:], [incoming, 'b' * 64, 'd' * 64, 'c' * 64, guest.sha(host.canonical({'files': {}}))])

    # -- source staging -------------------------------------------------------------------------------
    def staging(self):
        program = self.program
        payloads = {'kubectl': b'k' * 10, 'helm.tar.gz': b'h' * 11, 'chart.tgz': b'c' * 12}
        pins = {n: (len(b), guest.sha(b)) for n, b in payloads.items()}
        (self.private / 'payloads').mkdir(mode=0o700)
        for name, raw in payloads.items():
            (self.private / 'payloads' / name).write_bytes(raw)
        patches = (patch.object(program, 'PAYLOADS', pins), patch.object(program, 'FILES', {*program.SOURCES, *pins, 'contract.json'}))
        for item in patches:
            self.stack.enter_context(item)
        return self.private / 'payloads', pins

    def github(self, sha, **change):
        def fake(path, limit=0):
            self.assertTrue(path.endswith('?ref=' + sha))
            repo_path = path[len('contents/'):path.index('?ref=')]
            raw = ('synthetic source of ' + repo_path).encode()
            value = {'type': 'file', 'path': repo_path, 'encoding': 'base64', 'size': len(raw),
                     'content': base64.b64encode(raw).decode()}
            value.update(change)
            return value
        return fake

    def test_stage_program_binds_fixed_tables_to_the_trusted_source_sha_and_pinned_payloads(self):
        caller, program = self.caller, self.program
        payloads, pins = self.staging()
        value = snapshot()
        requested = []
        fake = self.github(value['source_sha'])
        with patch.object(host, 'github', side_effect=lambda p, limit=0: requested.append(p) or fake(p, limit)):
            source, table = caller.stage_program(value, payloads, self.directory, {'schema': 1, 'nonce': 'a' * 32})
        self.assertEqual(sorted(requested), sorted('contents/' + p + '?ref=' + value['source_sha'] for p in program.SOURCES.values()))
        self.assertEqual(set(table['files']), set(program.FILES))
        self.assertEqual(table['source_sha'], value['source_sha'])
        for name, item in table['files'].items():
            raw = (self.directory / name).read_bytes()
            self.assertEqual((item['bytes'], item['sha256']), (len(raw), guest.sha(raw)))
            self.assertEqual(stat.S_IMODE((self.directory / name).stat().st_mode), 0o600)
        self.assertTrue((self.directory / 'manifest.json').is_file())

    def test_stage_program_refuses_untrusted_source_and_wrong_payload_bytes(self):
        caller = self.caller
        for change in ({'path': 'build/provision/other.py'}, {'encoding': 'none'}, {'type': 'symlink'},
                       {'size': guest.MAX_SOURCE + 1}, {'size': 3}):
            payloads, _ = self.staging() if not (self.private / 'payloads').exists() else (self.private / 'payloads', None)
            value = snapshot()
            with patch.object(host, 'github', side_effect=self.github(value['source_sha'], **change)):
                with self.assertRaises(guest.Failure):
                    caller.stage_program(value, payloads, self.directory, {'schema': 1})
            for child in self.directory.iterdir():
                child.unlink()
        payloads = self.private / 'payloads'
        (payloads / 'kubectl').write_bytes(b'x' * 10)  # same size, wrong digest
        value = snapshot()
        with patch.object(host, 'github', side_effect=self.github(value['source_sha'])):
            with self.assertRaises(guest.Failure):
                caller.stage_program(value, payloads, self.directory, {'schema': 1})

    def test_management_result_accepts_only_the_closed_validated_record(self):
        caller, program = self.caller, self.program
        nonce = 'a' * 32
        record = program.public_record(program.initial_state(nonce))
        raw = guest.encoded(record)
        self.assertEqual(caller.management_result(raw, nonce), ('valid', record))
        self.assertEqual(caller.management_result(b'absent', nonce), ('absent', None))
        for bad in (b'invalid', b'', b'{', raw + b'x', guest.encoded(dict(record, nonce='b' * 32)),
                    guest.encoded(dict(record, extra=1)), b'x' * 5000):
            self.assertEqual(caller.management_result(bad, nonce), ('invalid', None))

    # -- #508 clock capsule at the caller ------------------------------------------------------------------
    def initial_contract(self):
        rec = snapshot()
        return {'schema': 1, 'nonce': 'a' * 32, 'lease': rec['request_id'], 'epoch': rec['epoch'], 'run_id': rec['run_id'],
                'attempt': rec['attempt'], 'body_sha256': rec['body_hash'], 'vm_id': rec['ids']['instance'],
                'boot_id': rec['ids']['boot'], 'image_id': rec['boot_image_id'], 'admitted_at': rec['reserved_at'],
                'deadline': rec['deadline'], 'boot_uuid': '22222222-2222-4222-8222-222222222222', 'source_sha': 'a' * 40}

    def test_guest_clock_capsule_is_one_fixed_sample_mapped_conservatively_from_the_response_clock(self):
        caller, program = self.caller, self.program
        initial = self.initial_contract()
        ticks = [0.0]
        wall0, mono0 = time.time(), time.monotonic()
        clock = program.ManagementClock(initial, wall=lambda: wall0 + ticks[0], mono=lambda: mono0 + ticks[0])
        master = FakeManagementMaster(program)
        original = master.remote

        def slow(args, phase, **kw):
            ticks[0] += 3.0  # round trip as measured by the caller's ONCE-retained original clock
            return original(args, phase, **kw)
        master.remote = slow
        capsule = caller.guest_clock_capsule(master, clock, initial)
        self.assertEqual(master.sample_requests, 1)
        call = master.calls[0]
        self.assertEqual((call[0][:4], call[1]), (['/usr/bin/python3', '-I', '-c', program.SAMPLE_STUB], 'access'))
        self.assertEqual(capsule['caller']['roundtrip'], 3.0)
        at_response = clock.left_at(program.MGMT_PHASES['access'], wall0 + 3.0, mono0 + 3.0)
        self.assertAlmostEqual(capsule['cutoffs']['access'], master.sample_mono + at_response - program.CLOCK_SAFETY_SECONDS)
        # the round trip is never added back: the cutoff is earlier than the (unknowable) sample-instant mapping
        self.assertLess(capsule['cutoffs']['access'], master.sample_mono + clock.left_at(15, wall0, mono0))
        self.assertIs(program.validate_capsule(capsule, initial), capsule)

    def test_guest_clock_capsule_refuses_slow_skewed_or_foreign_samples_fail_closed(self):
        caller, program = self.caller, self.program
        initial = self.initial_contract()
        for name, advance, skew in (('round trip over 10s', 11.0, 0), ('guest ahead beyond bracket', 0.0, 30),
                                    ('guest behind beyond bracket', 0.0, -30)):
            with self.subTest(name):
                ticks = [0.0]
                wall0, mono0 = time.time(), time.monotonic()
                clock = program.ManagementClock(initial, wall=lambda: wall0 + ticks[0], mono=lambda: mono0 + ticks[0])
                master = FakeManagementMaster(program)
                master.sample_skew = skew
                original = master.remote
                master.remote = lambda args, phase, _o=original, _t=ticks, _a=advance, **kw: (
                    _t.__setitem__(0, _t[0] + _a), _o(args, phase, **kw))[1]
                with self.assertRaises(guest.Failure):
                    caller.guest_clock_capsule(master, clock, initial)
        clock = program.ManagementClock(initial)
        for mutate in (lambda s: s.update(boot='33333333-3333-4333-8333-333333333333'), lambda s: s.update(nonce='f' * 32),
                       lambda s: s.update(extra=1), lambda s: s.update(mono=-1.0), lambda s: s.update(wall=float('nan'))):
            sample = {'boot': initial['boot_uuid'], 'nonce': 'e' * 32, 'wall': time.time(), 'mono': 1000.0}
            mutate(sample)
            with self.assertRaises((guest.Failure, ValueError)):
                program.build_capsule(initial, clock, sample, 'e' * 32, (time.time(), time.monotonic()),
                                      (time.time(), time.monotonic()))

    def test_stage_program_requires_and_binds_the_capsule(self):
        caller, program = self.caller, self.program
        with patch.object(host, 'github', side_effect=AssertionError('no source fetch before the capsule is present')):
            with self.assertRaises(guest.Failure):
                caller.stage_program(snapshot(), self.private, self.directory, self.initial_contract())
        self.assertEqual(list(self.directory.iterdir()), [])
        self.assertIn('capsule.json', program.FILES)
        foreign = self.initial_contract()
        foreign['nonce'] = 'b' * 32
        sample = {'boot': foreign['boot_uuid'], 'nonce': 'e' * 32, 'wall': time.time(), 'mono': 1000.0}
        capsule = program.build_capsule(foreign, program.ManagementClock(foreign), sample, 'e' * 32,
                                        (time.time(), time.monotonic()), (time.time(), time.monotonic()))
        payloads, _ = self.staging()
        value = snapshot()
        with patch.object(host, 'github', side_effect=self.github(value['source_sha'])):
            with self.assertRaises(guest.Failure):  # a capsule for another contract is never staged
                caller.stage_program(value, payloads, self.directory, self.initial_contract(), capsule)

    def test_sequence_samples_once_before_staging_and_never_resamples_after_a_bootstrap_failure(self):
        program = self.program
        master = FakeManagementMaster(program)

        def lost_reply():
            raise guest.Failure('ambiguous bootstrap reply', 77)
        master.on_bootstrap = lost_reply
        code, receipt, spy = self.sequence(master, private=self.private)
        self.assertEqual(code, 77)
        self.assertEqual(master.sample_requests, 1)  # no reissue/resample after the ambiguous effect
        self.assertEqual(len([c for c in master.calls if '-I' in c[0] and c[0][0] == '/usr/bin/sudo']), 1)
        capsule = spy.stage.call_args.args[4]
        self.assertEqual(capsule['nonce'], spy.stage.call_args.args[3]['nonce'])
        order = [c[0][0] for c in master.calls]
        self.assertLess(order.index('/usr/bin/python3'), order.index('/usr/bin/sudo'))

    # -- fixed sequence: success, failure, heartbeat, expiry, stale registration -------------------------
    def allowed(self, args):
        program = self.program
        if args[:2] == ['/usr/bin/mkdir', '-m']:
            return True
        if args[0] in ('/usr/bin/cat', '/usr/bin/rm'):
            return bool(re.fullmatch('/tmp/labapp-vlab-[a-f0-9]{32}/marker', args[-1])) and (
                len(args) == 2 if args[0] == '/usr/bin/cat' else args[1:-1] == ['--'])
        if args[:3] == ['/usr/bin/python3', '-I', '-c']:  # the single fixed clock sample
            return args[3] == program.SAMPLE_STUB and len(args) == 5 and re.fullmatch('[a-f0-9]{32}', args[4]) is not None
        if '-I' in args and '-c' in args:
            return args[:3] == ['/usr/bin/sudo', '-n', '/usr/bin/python3']
        if args[:3] != ['/usr/bin/sudo', '-n', '/usr/bin/python3'] or args[3] != str(program.MROOT / 'management_trial.py'):
            return False
        return args[4] in program.HOST_ACTIONS

    def test_owner_attested_or_unobserved_browser_never_yields_whole_trial_success(self):
        for browser in (('owner-attested', True), ('failed', True), ('skipped', True), ('timeout', True),
                        ('complete', True)):
            with self.subTest(browser=browser[0]):
                code, receipt, _ = self.sequence(FakeManagementMaster(self.program), private=self.private, browser=browser)
                self.assertEqual(code, 1)
                self.assertFalse(receipt['browser_verified'])
        self.assertFalse(hasattr(self.caller, 'verify_browser'))  # no verifier exists in this source

    def test_valid_sequence_preserves_order_clock_and_original_master_for_every_call(self):
        program = self.program
        master = FakeManagementMaster(program)
        code, receipt, spy = self.sequence(master, private=self.private)
        self.assertEqual(code, 0)
        # 'verified' is injected here ONLY to exercise the success predicate: this source cannot produce it.
        self.assertEqual((receipt['management_status'], receipt['browser'], receipt['forward_absent']), ('valid', 'verified', True))
        self.assertTrue(receipt['browser_verified'])
        self.assertTrue(program.succeeded(receipt['management']))
        calls = [c for c in master.calls if 'heartbeat' not in c[0]]
        self.assertTrue(all(self.allowed(c[0]) for c in master.calls), [c[0] for c in master.calls])
        verbs = [c[0][4] if c[0][0] == '/usr/bin/sudo' and len(c[0]) > 4 and c[0][3].endswith('management_trial.py') else c[0][0]
                 for c in calls]
        self.assertNotIn('step', verbs)  # the host never executes a step: ONE guest worker runs all 18
        self.assertEqual(verbs[:5], ['/usr/bin/mkdir', '/usr/bin/cat', '/usr/bin/rm', '/usr/bin/python3', '/usr/bin/sudo'])
        self.assertEqual(verbs.count('/usr/bin/python3'), 1)  # exactly one clock sample, never resampled
        self.assertEqual(verbs[-4:], ['result', 'export-viewer', 'cancel', 'result'])
        progress = [c for c in calls if c[0][4:5] == ['result']]
        self.assertEqual((progress[0][1], progress[0][2]), ('work', False))
        cancel, final = [c for c in calls if c[0][4:5] == ['cancel']][0], progress[-1]
        self.assertTrue(cancel[2] and final[2])  # cancel and the final receipt use the cleanup reserve of the ORIGINAL clock
        self.assertEqual(master.transfers[0][1:], (['marker'], 'access'))
        self.assertEqual(master.transfers[1][1], [*sorted(program.FILES), 'manifest.json'])
        self.assertIn('capsule.json', master.transfers[1][1])
        for name in program.UNIT_NAMES:
            self.assertIn(name, master.transfers[1][1])
        self.assertEqual(master.closed, 1)
        self.assertGreaterEqual(spy.registration.current.call_count, 1)
        spy.dispatch.assert_called_once()
        self.assertNotIn(VIEWER_PASSWORD, json.dumps(receipt))
        self.assertEqual(spy.session.call_args.args[5], self.private)
        self.assertEqual(guest.data(spy.session.call_args.args[4])['login'], 'labapp-viewer-abc123')

    def test_marker_mismatch_refuses_source_staging_and_bootstrap(self):
        master = FakeManagementMaster(self.program)
        master.marker_matches = False
        code, receipt, spy = self.sequence(master)
        self.assertNotEqual(code, 0)
        spy.stage.assert_not_called()
        self.assertEqual(len(master.transfers), 1)
        self.assertEqual(master.transfers[0][1:], (['marker'], 'access'))
        self.assertFalse(any('-I' in args for args, _, _ in master.calls))
        self.assertTrue(receipt['local_files_absent'])

    def test_enrollment_refuses_unpinned_sdk_before_key_generation(self):
        caller = self.caller
        snap = snapshot()
        held = caller.Held()
        replies = [host.OWNER.encode(), b'(unset)', b'{"name":"synthetic"}', b'{"Google Cloud SDK":"574.0.0"}']
        with patch.object(host, 'trusted_source'), patch.object(host, 'command', side_effect=replies) as calls, \
             patch.object(caller, 'profile_user', return_value=snap['self_user']):
            with self.assertRaises(guest.Failure):
                caller.enroll(snap, self.directory, Mock(), Mock(), SimpleNamespace(user=snap['self_user']),
                              Mock(), Mock(), threading.Event(), {}, held)
        self.assertEqual(calls.call_count, 4)
        self.assertEqual(calls.call_args.args[0], ['gcloud', 'version', '--format=json'])
        self.assertIsNone(held.context)

    def test_native_signal_status_in_the_public_receipt_keeps_its_128_plus_signal_code(self):
        for category, status, expected in (('child-signal', -9, 137), ('child-exit', 17, 17),
                                           ('heartbeat-loss', None, 1), ('child-timeout', None, 1)):
            with self.subTest(category):
                master = FakeManagementMaster(self.program)
                master.failing_step = 'helm'
                master.failure_category, master.failure_status = category, status
                code, receipt, spy = self.sequence(master, private=self.private)
                self.assertEqual(code, expected)

    def test_f2_final_native_failure_is_reconciled_into_return_and_receipt_but_never_replaces_an_earlier_primary(self):
        # (origin, status) -> code. A closure-window negative status may be our own closure's signal, so it
        # gets the fixed code 1 rather than a claimed native 128+signal; a pre-close signal stays native.
        for origin, status, expected in (('pre-close', -15, 143), ('pre-close', 17, 17), ('closure-window', 17, 17),
                                         ('closure-window', -15, 1), ('closure-window', -9, 1)):
            with self.subTest((origin, status)):
                master = FakeManagementMaster(self.program)
                master.final_terminal = (origin, status)
                code, receipt, spy = self.sequence(master, private=self.private)
                self.assertEqual((code, receipt['code']), (expected, expected))
                self.assertEqual(receipt['failure_category'], 'guest')
                self.assertIsNone(receipt['management']['failure'])  # no step is falsified
                self.assertEqual(set(receipt['management']['steps'].values()), {'ok'})  # all 18 facts preserved
                self.assertEqual(receipt['management']['terminal']['status'], status)
                self.assertEqual(receipt['management']['terminal']['origin'], origin)
                self.assertFalse(self.program.succeeded(receipt['management']))
        master = FakeManagementMaster(self.program)  # observed exit 0 is not success either (browser unverified)
        master.final_terminal = ('pre-close', 0)
        code, receipt, spy = self.sequence(master, private=self.private, browser=('owner-attested', True))
        self.assertNotEqual(code, 0)
        self.assertFalse(receipt['browser_verified'])
        master = FakeManagementMaster(self.program)  # earlier primary (17) wins; later terminal stays visible
        master.failing_step, master.late_status, master.final_terminal = 'helm', 9, ('closure-window', 23)
        code, receipt, spy = self.sequence(master, private=self.private)
        self.assertEqual((code, receipt['code']), (17, 17))
        self.assertEqual(receipt['management']['terminal']['status'], 23)
        master = FakeManagementMaster(self.program)  # an earlier primary (17) keeps its code and category
        master.failing_step, master.late_status = 'helm', 9
        code, receipt, spy = self.sequence(master, private=self.private)
        self.assertEqual((code, receipt['code']), (17, 17))
        self.assertEqual(receipt['management']['failure']['child_status'], 9)  # the receipt shows what the guest said
        for bad in ({'status': None, 'origin': 'unobserved'}, {'status': 0, 'origin': 'closure-window'}):
            self.assertEqual(self.caller.terminal_code(dict(bad, group='uncertain')), 0)  # nothing to reconcile

    def test_first_step_failure_stops_work_but_still_tears_down_and_reads_the_typed_result(self):
        master = FakeManagementMaster(self.program)
        master.failing_step = 'helm'
        code, receipt, spy = self.sequence(master, private=self.private)
        self.assertEqual(code, 17)
        self.assertEqual(master.ran, list(self.program.STEP_NAMES[:self.program.STEP_NAMES.index('helm')]))
        verbs = [c[0][4] for c in master.calls if c[0][0] == '/usr/bin/sudo' and c[0][3].endswith('management_trial.py')]
        self.assertNotIn('export-viewer', verbs)
        self.assertIn('cancel', verbs)
        self.assertEqual(receipt['management']['failure']['step'], 'helm')
        spy.session.assert_not_called()
        self.assertTrue(all(c[2] for c in master.calls if c[0][4:5] == ['cancel'] or (c[0][4:5] == ['result'] and c[2])))
        self.assertEqual(master.closed, 1)

    def test_heartbeat_failure_stops_the_sequence_and_still_tears_down(self):
        master = FakeManagementMaster(self.program)
        master.fail_heartbeat = True
        code, receipt, spy = self.sequence(master, private=self.private)
        self.assertNotEqual(code, 0)
        self.assertLess(len(master.ran), len(self.program.STEP_NAMES))
        self.assertTrue(master.torn)
        spy.session.assert_not_called()
        self.assertFalse(receipt['process_absent'] and code == 0)

    def test_exhausted_original_deadline_refuses_work_but_cleanup_still_runs(self):
        program = self.program
        master = FakeManagementMaster(program)

        class Expiring(program.ManagementClock):
            armed = False

            def remaining(self, phase):
                if Expiring.armed and phase in ('stage', 'work'):
                    raise guest.Failure('absolute phase cutoff', 124, 'phase-cutoff')
                return super().remaining(phase)
        master.on_bootstrap = lambda: setattr(Expiring, 'armed', True)
        code, receipt, spy = self.sequence(master, private=self.private, clock=Expiring)
        self.assertEqual(code, 124)
        self.assertEqual(master.ran, [])
        self.assertTrue(master.torn)
        self.assertTrue(all(c[2] for c in master.calls if c[0][4:5] == ['cancel']))
        spy.session.assert_not_called()

    def test_stale_registration_untrusted_source_stop_before_any_guest_byte(self):
        program = self.program
        for kwargs in ({'registration': Mock(current=Mock(side_effect=guest.Failure('owner lease changed')))},
                       {'trusted': guest.Failure('creator cancelled/completed/untrusted', 23)}):
            master = FakeManagementMaster(program)
            code, receipt, spy = self.sequence(master, **kwargs)
            self.assertNotEqual(code, 0)
            self.assertEqual(master.transfers, [])
            self.assertFalse(any('-I' in c[0] for c in master.calls))
            self.assertFalse(any('teardown' in c[0] for c in master.calls))
            self.assertEqual(master.closed, 1)

    def test_old_clock_work_beyond_the_ceiling_is_unreachable(self):
        program = self.program
        value = snapshot()
        start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=58)
        value['reserved_at'] = start.strftime('%Y-%m-%dT%H:%M:%SZ')
        value['deadline'] = (start + timedelta(minutes=120)).strftime('%Y-%m-%dT%H:%M:%SZ')
        master = FakeManagementMaster(program)
        code, receipt, spy = self.sequence(master, value=value)
        self.assertNotEqual(code, 0)
        self.assertEqual(master.ran, [])  # nothing is renewed: the 'access' allowance already ended

    # -- enrollment mirror -------------------------------------------------------------------------------
    def enroll(self, account=b'art@githedgehog.com\n', impersonation=b'(unset)\n', profile=None, login_user=None):
        value = snapshot()
        calls = []

        def command(argv, seconds, **kw):
            calls.append(argv)
            if argv[:3] == ['gcloud', 'auth', 'list']:
                return account
            if argv[:3] == ['gcloud', 'config', 'get-value']:
                return impersonation
            if argv[:4] == ['gcloud', 'compute', 'os-login', 'describe-profile']:
                return json.dumps({'name': profile or value['self_user']}).encode()
            raise guest.Failure('unexpected later command', 99)
        registration = Mock()
        registration.current.return_value = dict(value, names={'instance': 'fixed'})
        held = self.caller.Held()
        with patch.object(host, 'command', side_effect=command), patch.object(host, 'trusted_source'):
            try:
                self.caller.enroll(value, self.directory, registration, Mock(), SimpleNamespace(user=login_user or value['self_user']),
                                   {}, Mock(), threading.Event(), {}, held)
            except Exception as error:
                return error, calls, registration, held
        return None, calls, registration, held

    def test_enrollment_refuses_wrong_account_impersonation_and_principal_before_key_work(self):
        for kwargs in ({'account': b'someone@example.com\n'}, {'impersonation': b'robot@x.iam.gserviceaccount.com\n'},
                       {'profile': 'users/110405050082684214273'}, {'login_user': 'users/110405050082684214274'}):
            error, calls, registration, held = self.enroll(**kwargs)
            self.assertIsNotNone(error, kwargs)
            self.assertNotEqual(str(error), 'unexpected later command')
            self.assertFalse(any('ssh-keygen' in part for c in calls for part in c))
            registration.register.assert_not_called()
            self.assertIsNone(held.master)

    # -- browser: original-master loopback forward -----------------------------------------------------
    def browser(self, *, outcome='viewer-panel-seen', mode=0o600, lost=False, listening_start=False, cancel_fails=False,
                private='default', wait=0.05, write=True, override=None, replace_handoff=False, forward_fails=False,
                post_cancel_probe=None):
        caller, program = self.caller, self.program
        master = FakeManagementMaster(program)
        master.lost_after = 1 if lost else None  # first guard passes, the next socket check finds it gone
        value = snapshot()
        clock = program.ManagementClock({'admitted_at': value['reserved_at'], 'deadline': value['deadline']})
        state, commands = {'open': listening_start, 'cancel_attempted': False}, []
        nonce, lease = 'a' * 32, value['request_id']
        if private == 'default':  # fresh owned private dir per call: the exclusive-create handoff file is never reused
            private = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='labapp-mgmt-priv-')))
            private.chmod(0o700)
        self.last_private = private

        def command(argv, seconds, **kw):
            commands.append(list(argv))
            verb = argv[argv.index('-O') + 1]
            if verb == 'cancel':
                state['cancel_attempted'] = True
            if verb == 'forward':
                handoff = private / ('viewer-handoff-' + lease + '.json')
                self.last_handoff = handoff.read_bytes(), stat.S_IMODE(handoff.stat().st_mode)
                if write:
                    done = private / ('browser-complete-' + lease + '.json')
                    attestation = {'schema': 2, 'nonce': nonce, 'lease': lease, 'attestation': 'owner-attested',
                                   'login': 'labapp-viewer-abc123', 'role': 'Viewer', 'dashboard_uid': 'chartpanel',
                                   'panel_id': 7, 'datasource_type': 'prometheus', 'ui_result': outcome}
                    attestation.update(override or {})
                    done.write_text(json.dumps(attestation))
                    done.chmod(mode)
                if forward_fails:
                    state['open'] = True
                    raise guest.Failure('forward installed before command failed', 124)
            if verb == 'cancel' and replace_handoff:
                handoff = private / ('viewer-handoff-' + lease + '.json')
                handoff.rename(private / 'displaced-handoff')
                handoff.write_bytes(b'foreign replacement')
                handoff.chmod(0o600)
            if verb == 'cancel' and cancel_fails:
                raise guest.Failure('cancel failed', 5)
            state['open'] = verb == 'forward'
            return b''
        uncertain = threading.Event()
        def probe():
            return post_cancel_probe() if state['cancel_attempted'] and post_cancel_probe else state['open']

        with patch.object(host, 'command', side_effect=command), patch.object(caller, 'listening', side_effect=probe), \
             patch.object(caller.time, 'sleep'), patch.object(caller, 'BROWSER_WAIT_SECONDS', wait):
            status = caller.browser_session(master, clock, nonce, lease, handoff_bytes(nonce), private,
                                            threading.Event(), uncertain)
        return status, master, commands, uncertain, lease

    def test_browser_attestation_must_bind_nonce_lease_viewer_dashboard_and_panel(self):
        for override in ({'nonce': 'b' * 32}, {'lease': 'other-lease'}, {'login': 'labapp-viewer-fffff0'},
                         {'role': 'Editor'}, {'dashboard_uid': 'other'}, {'panel_id': 8}, {'panel_id': '7'},
                         {'datasource_type': 'loki'}, {'attestation': 'verified'}, {'schema': 1}, {'extra': 1},
                         {'ui_result': 'seen'}):
            with self.subTest(override=override):
                status, _, commands, *_ = self.browser(override=override)
                self.assertEqual(status, ('forward-failed', True))
                self.assertEqual(commands[-1][commands[-1].index('-O') + 1], 'cancel')
        status, *_ = self.browser(override={'result': 'viewer-panel-seen'})  # old marker field is not a schema
        self.assertEqual(status, ('forward-failed', True))

    def test_browser_forward_is_original_master_loopback_only_and_complete_only_by_owner_attestation(self):
        status, master, commands, uncertain, lease = self.browser()
        self.assertEqual(status, ('owner-attested', True))  # attested by the owner, NOT verified browser evidence
        self.assertEqual([c[c.index('-O') + 1] for c in commands], ['forward', 'cancel'])
        forward = commands[0]
        self.assertEqual(forward[0], '/usr/bin/ssh')
        for required in ('ControlMaster=no', 'ProxyCommand=/usr/bin/false', 'ControlPath=/fake/master.sock'):
            self.assertTrue(any(required in part for part in forward), required)
        self.assertEqual(forward[forward.index('-L') + 1], '127.0.0.1:3000:127.0.0.1:3000')
        for forbidden in ('-M', '-N', '-D', '-R', '-W', '-J', '-o ProxyJump'):
            self.assertNotIn(forbidden, forward)
        self.assertEqual(forward[-1], 'labapp-trial-1234')
        self.assertGreater(master.checks, 1)  # original socket identity checked around and during the forward
        handoff = self.last_private / ('viewer-handoff-' + lease + '.json')
        self.assertEqual(self.last_handoff[1], 0o600)
        record = guest.data(self.last_handoff[0])
        self.assertEqual(set(record), self.program.HANDOFF_FIELDS)
        self.assertFalse(any(k in record for k in ('kubeconfig', 'admin', 'token')))
        self.assertFalse(handoff.exists())
        self.assertFalse((self.last_private / ('browser-complete-' + lease + '.json')).exists())
        self.assertFalse(uncertain.is_set())

    def test_browser_cleanup_preserves_replaced_files_and_reports_uncertainty(self):
        status, _, _, uncertain, lease = self.browser(replace_handoff=True)
        self.assertEqual(status, ('owner-attested', True))
        self.assertTrue(uncertain.is_set())
        self.assertEqual((self.last_private / ('viewer-handoff-' + lease + '.json')).read_bytes(), b'foreign replacement')

    def test_partial_handoff_write_failure_is_cleaned_before_any_forward_attempt(self):
        with patch.object(self.caller.os, 'fsync', side_effect=OSError('synthetic fsync failure')):
            status, _, commands, uncertain, _ = self.browser()
        self.assertEqual(status, ('forward-failed', True))
        self.assertEqual(commands, [])
        self.assertEqual(list(self.last_private.iterdir()), [])
        self.assertFalse(uncertain.is_set())

    def test_forward_installed_then_command_failed_is_cancelled_and_absence_checked(self):
        status, _, commands, uncertain, _ = self.browser(forward_fails=True)
        self.assertEqual(status, ('forward-failed', True))
        self.assertEqual([cmd[cmd.index('-O') + 1] for cmd in commands], ['forward', 'cancel'])
        self.assertEqual(list(self.last_private.iterdir()), [])
        self.assertFalse(uncertain.is_set())
        status, _, _, uncertain, _ = self.browser(forward_fails=True, cancel_fails=True)
        self.assertEqual(status, ('forward-failed', False))
        self.assertTrue(uncertain.is_set())

    def test_listener_probe_requires_definite_refusal_for_absence(self):
        caller = self.caller
        for error, expected in ((ConnectionRefusedError(errno.ECONNREFUSED, 'synthetic refusal'), False),
                                (TimeoutError('synthetic timeout'), None),
                                (OSError(errno.EMFILE, 'synthetic descriptor exhaustion'), None),
                                (PermissionError(errno.EACCES, 'synthetic permission failure'), None)):
            with self.subTest(error=type(error).__name__), \
                 patch.object(caller.socket, 'create_connection', side_effect=error):
                self.assertIs(caller.listening(), expected)

    def test_failed_cancel_with_indeterminate_probe_never_proves_forward_absence(self):
        caller = self.caller
        original = caller.listening
        for error in (TimeoutError('synthetic timeout'), OSError(errno.EMFILE, 'synthetic descriptor exhaustion'),
                  KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), \
                 patch.object(caller.socket, 'create_connection', side_effect=error):
                status, _, commands, uncertain, _ = self.browser(
                    forward_fails=True, cancel_fails=True, post_cancel_probe=original)
            self.assertEqual(status, ('forward-failed', False))
            self.assertEqual([cmd[cmd.index('-O') + 1] for cmd in commands], ['forward', 'cancel'])
            self.assertTrue(uncertain.is_set())
            self.assertEqual(list(self.last_private.iterdir()), [])

    def test_browser_refuses_preexisting_completion_without_removing_it(self):
        lease = snapshot()['request_id']
        done = self.private / ('browser-complete-' + lease + '.json')
        done.write_bytes(b'preexisting')
        done.chmod(0o600)
        with self.assertRaises(guest.Failure):
            self.browser(private=self.private, write=False)
        self.assertEqual(done.read_bytes(), b'preexisting')

    def test_browser_failed_timeout_lax_file_lost_master_and_skips(self):
        status, *_ = self.browser(outcome='viewer-panel-failed')
        self.assertEqual(status, ('failed', True))
        status, master, commands, *_ = self.browser(write=False)  # no owner attestation -> timeout, never inferred
        self.assertEqual(status, ('timeout', True))
        self.assertEqual([c[c.index('-O') + 1] for c in commands], ['forward', 'cancel'])
        status, master, commands, *_ = self.browser(mode=0o644)
        self.assertEqual(status, ('forward-failed', True))
        self.assertEqual(commands[-1][commands[-1].index('-O') + 1], 'cancel')
        status, master, commands, *_ = self.browser(lost=True, write=False)
        self.assertEqual(status, ('forward-failed', True))
        self.assertEqual(commands[-1][commands[-1].index('-O') + 1], 'cancel')
        status, master, commands, *_ = self.browser(listening_start=True)  # port already in use: never touched
        self.assertEqual((status, commands), (('skipped', True), []))
        status, master, commands, *_ = self.browser(private=None)
        self.assertEqual((status, commands), (('skipped', True), []))

    def test_browser_cancel_failure_with_surviving_listener_marks_cleanup_uncertain(self):
        status, master, commands, uncertain, _ = self.browser(cancel_fails=True)
        self.assertEqual(status, ('owner-attested', False))
        self.assertTrue(uncertain.is_set())


class ManagementStub(unittest.TestCase):
    """The REAL stub text run under the stdlib interpreter against synthetic modules (no native tool)."""
    def setUp(self):
        self.caller = load_caller()
        self.temp = Path(tempfile.mkdtemp(prefix='labapp-stub-'))
        self.addCleanup(lambda: __import__('shutil').rmtree(self.temp, ignore_errors=True))
        self.marker = self.temp / 'marker'
        self.vlab = ('open(%r, "a").write("v")\n' % str(self.marker)).encode()
        self.owned = ('open(%r, "a").write("o")\n' % str(self.marker)).encode()
        self.mgmt = ('def bootstrap(path, manifest):\n    open(%r, "a").write("b" + manifest)\n' % str(self.marker)).encode()
        (self.temp / 'vlab_trial.py').write_bytes(self.vlab)
        (self.temp / 'owned_process.py').write_bytes(self.owned)
        (self.temp / 'management_trial.py').write_bytes(self.mgmt)

    def run_stub(self, vlab_sha, mgmt_sha, owned_sha=None):
        return subprocess.run([sys.executable, '-I', '-c', self.caller.STUB, str(self.temp),
                               vlab_sha, guest.sha(self.owned) if owned_sha is None else owned_sha, mgmt_sha, 'M' * 4],
                              capture_output=True, timeout=30)

    def test_only_hash_matching_bytes_are_executed(self):
        sha = guest.sha
        self.assertEqual(self.run_stub(sha(self.vlab), sha(self.mgmt)).returncode, 0)
        self.assertEqual(self.marker.read_text(), 'vobMMMM')
        self.marker.unlink()
        self.assertNotEqual(self.run_stub('0' * 64, sha(self.mgmt)).returncode, 0)
        self.assertFalse(self.marker.exists())  # tampered primitives: nothing executed at all
        self.assertNotEqual(self.run_stub(sha(self.vlab), sha(self.mgmt), '0' * 64).returncode, 0)
        self.assertEqual(self.marker.read_text(), 'v')
        self.marker.unlink()
        self.assertNotEqual(self.run_stub(sha(self.vlab), '0' * 64).returncode, 0)
        self.assertEqual(self.marker.read_text(), 'vo')  # only verified dependencies ran; management never did
