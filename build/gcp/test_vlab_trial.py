"""Owner entrypoints use only fake API/processes and public temporary files."""
from contextlib import ExitStack, nullcontext
import base64
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import runpy
import signal
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


# Exact public shape of the final #526 access_inventory() report (fixture; the guest module itself is
# not in this tree, so this is a fixed copy of the shape the lead probed, not an import of the module).
ACCESS = {'status': 'unproven', 'key_files': 0, 'other_home_dirs': 1, 'symlinked_homes': 0, 'oslogin_caches': 2,
          'agent_state_paths': 0}
PARTIAL_INNER = {'owned_sealed': True, 'access': ACCESS, 'unmet': ['access-material-provenance'],
                 'removed_count': 3}


def prep_report(code=3, inner=None, **outer):
    """Wrapper record exactly as the root bootstrap prints it (canonical JSON + newline)."""
    inner = PARTIAL_INNER if inner is None else inner
    text = inner if isinstance(inner, str) else json.dumps(inner)
    return guest.encoded({'schema': 1, 'code': code, 'stdout': text + '\n', **outer}) + b'\n'


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
                       observed_code=0, observed_contained=True, ghcr=None,
                       handoff=None, remaining=None, cancel_error=None, key_error=None, leftover=None,
                       print_failure=None, print_failures=1, prepare=False, prep=None):
        prep = prep or {}
        results_read = []
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
        # Fresh private root per call so several pipeline runs in one test never collide;
        # the production fresh-directory requirement is not relaxed.
        root = Path(tempfile.mkdtemp(prefix='run-', dir=self.directory))
        root.chmod(0o700)
        payload_dir = root / 'inputs'
        payload_dir.mkdir()
        output = root / 'output'
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
        def image_sources(snap, directory):
            trace.append(('image-sources', snap['source_sha']))
            if prep.get('fetch_error') is not None:
                raise prep['fetch_error']
            table = {}
            for name in host.IMAGE_SOURCES:
                raw = ('PUBLIC-IMAGE-' + name).encode()
                guest.exclusive(directory / name, raw)  # local staging that cleanup must remove
                table[name] = {'bytes': len(raw), 'sha256': guest.sha(raw)}
            return table
        class Session:
            def start(self):
                trace.append('master-start')
                if start_error is not None:
                    raise start_error
            def transfer(self, incoming, names, phase='stage', until=None):
                trace.append(('transfer', tuple(names), phase))
                if sorted(names) == sorted(host.IMAGE_SOURCES):
                    self_test.assertTrue(all((output / n).is_file() for n in names))
                    self_test.assertIsNotNone(until)
                    if prep.get('transfer_error') is not None:
                        raise prep['transfer_error']
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
                    results_read.append(1)
                    contained = observed_contained and not (prep.get('result_changed') and len(results_read) > 1)
                    return guest.encoded(result_value(nonce, observed_code, contained,
                                                      worker_detail(status=observed_code) if observed_code else None))
                if prepare and args == host.SERVICE_COMMAND:
                    if prep.get('service_error') is not None:
                        raise prep['service_error']
                    return prep.get('service', b'ActiveState=inactive\nResult=success\nExecMainCode=1\nExecMainStatus=0\n')
                if prepare and len(args) > 6 and args[6] == host.IMAGE_BOOTSTRAP:
                    if prep.get('run_error') is not None:
                        raise prep['run_error']
                    return prep.get('report', prep_report())
                return b''
            def close(self):
                trace.append('master-close')
                if leftover is not None:
                    # Unexpected local file: the fixed owned-file sweep must treat it as uncertainty.
                    (output / leftover).write_bytes(b'x')
                return True
        self_test = self
        def removed(*args, **kwargs):
            self.assertEqual(trace[-1], 'master-close')
            self.assertFalse(any(output.iterdir()), 'private files remain before final own-key receipt')
            if key_error is not None:
                raise key_error
            trace.append('removed')
        def cancel(snap):
            trace.append('captured-cancel')
            if cancel_error is not None:
                raise cancel_error
        heartbeat = Mock()
        heartbeat.start.side_effect = pulse.set
        heartbeat.is_alive.return_value = heartbeat_alive
        with patch.object(host, 'command', side_effect=command), patch.object(host, 'trusted_source') as trust, \
             patch.object(host, 'OwnKeyImport', return_value=importer), patch.object(host, 'Master', return_value=Session()), \
             patch.object(host, 'source_files', side_effect=sources), patch.object(guest, 'PAYLOADS', pins), \
             patch.object(host, 'image_source_files', side_effect=image_sources), \
             patch.object(host, 'extract_ed25519', return_value='ssh-ed25519 UEVCTElDX0ZJWFRVUkU=\n'), \
             patch.object(host.secrets, 'token_hex', side_effect=lambda n: 'd'*(n*2)), \
             patch.object(host.secrets, 'token_urlsafe', return_value='PUBLIC-NONDEPLOYABLE-PASSWORD'), \
             patch.object(host, 'cleanup_own_key', side_effect=removed), patch.object(host, 'cleanup_dispatch', side_effect=cancel), \
             (patch.object(host.threading, 'Thread', return_value=heartbeat) if heartbeat_alive is not None else nullcontext()), \
             (patch.object(guest.Clock, 'cleanup_remaining', return_value=remaining) if remaining is not None
              else nullcontext()), \
             patch('builtins.print') as printed:
            print_calls = self.print_calls = []
            def flaky_print(*args, **kwargs):
                print_calls.append(kwargs)
                if print_failure is not None and len(print_calls) <= print_failures:
                    raise print_failure
            printed.side_effect = flaky_print
            code = host.trial(value, payload_dir, output, registration=registration, records=records, login=login,
                              **({} if ghcr is None else {'ghcr': ghcr}),
                              **({} if handoff is None else {'handoff_on_success': handoff}),
                              **({'prepare_private_image': True} if prepare else {}))
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

    # --- opt-in success handoff (#523); each pipeline run gets its own private root ---

    def test_default_and_explicit_false_keep_cancellation_and_receipt_shape(self):
        for kwargs in ({}, {'handoff': False}):
            with self.subTest(kwargs=kwargs):
                code, receipt, trace, *_ = self.owner_pipeline(**kwargs)
                self.assertEqual(code, 0)
                self.assertEqual(trace[-1], 'captured-cancel')
                self.assertNotIn('success_handoff', receipt)
                self.assertTrue(receipt['independent_cleanup_dispatched'])

    def test_default_failure_keeps_primary_code_cancellation_and_receipt_shape(self):
        code, receipt, trace, *_ = self.owner_pipeline(observed_code=7, observed_contained=False)
        self.assertEqual(code, 7)
        self.assertEqual(trace[-1], 'captured-cancel')
        self.assertNotIn('success_handoff', receipt)

    def test_cli_option_is_explicit_default_false_and_reaches_trial(self):
        for argv, expected in (([], False), (['--handoff-on-success'], True)):
            with self.subTest(argv=argv):
                value = snapshot()
                with patch.object(guest, 'regular', return_value=guest.encoded(value)), \
                     patch.object(host, 'private_directory', return_value=self.directory), \
                     patch.object(host, 'GcsAccessRecords', return_value=Mock()), \
                     patch.object(host, 'OwnerRegistration', return_value=Mock()), \
                     patch.object(host.SelfLogin, 'for_owner', return_value=Mock()), \
                     patch.object(host, 'trial', return_value=0) as run:
                    host.main(['--snapshot', 'public-fixture', '--payloads', 'inputs', '--output', 'output', *argv])
                self.assertIs(run.call_args.kwargs['handoff_on_success'], expected)

    def test_explicit_handoff_after_clean_success_withholds_only_creator_cancellation(self):
        # Real Clock: the fixture deadline leaves far more than 15 minutes.
        code, receipt, trace, _, _, _, output = self.owner_pipeline(handoff=True)
        self.assertEqual(code, 0)
        self.assertEqual(receipt['success_handoff'], 'ready')
        self.assertNotIn('captured-cancel', trace)
        self.assertEqual(trace[-2:], ['master-close', 'removed'])
        self.assertFalse(receipt['independent_cleanup_dispatched'])
        self.assertTrue(all(receipt[k] for k in ('contained', 'process_absent', 'own_key_absent', 'local_files_absent')))
        self.assertFalse(any(output.iterdir()))
        for text in ('PRIVATE', 'ssh-ed25519', 'PUBLIC-NONDEPLOYABLE-PASSWORD'):
            self.assertNotIn(text, self.printed_text)

    def test_handoff_just_under_fifteen_minutes_of_original_deadline_is_refused(self):
        code, receipt, trace, *_ = self.owner_pipeline(handoff=True, remaining=899.0)
        self.assertEqual((code, receipt['success_handoff']), (1, 'refused'))
        self.assertEqual(trace[-1], 'captured-cancel')
        self.assertEqual(receipt['code'], 0)  # primary guest outcome is preserved

    def test_handoff_at_exactly_fifteen_minutes_of_original_deadline_is_ready(self):
        code, receipt, trace, *_ = self.owner_pipeline(handoff=True, remaining=900.0)
        self.assertEqual((code, receipt['success_handoff']), (0, 'ready'))
        self.assertNotIn('captured-cancel', trace)

    def test_handoff_budget_error_from_the_clock_refuses_and_cancels(self):
        with patch.object(guest.Clock, 'cleanup_remaining', side_effect=guest.Failure('cutoff', 124, 'phase-cutoff')):
            code, receipt, trace, *_ = self.owner_pipeline(handoff=True)
        self.assertEqual((code, receipt['success_handoff']), (1, 'refused'))
        self.assertEqual(trace[-1], 'captured-cancel')

    def test_requested_handoff_refuses_and_cancels_for_failure_uncertainty_and_interrupt(self):
        cases = {
            'guest-failure': dict(observed_code=7, observed_contained=False),
            'guest-failure-contained': dict(observed_code=9, observed_contained=True),
            'uncontained-success': dict(observed_contained=False),
            'live-heartbeat': dict(heartbeat_alive=True),
            'containment-error': dict(observed_contained=False, containment_error=RuntimeError('PRIVATE-CONTAINMENT')),
            'local-file-uncertainty': dict(leftover='unexpected-private-file'),
            'own-key-cleanup-failure': dict(key_error=RuntimeError('PRIVATE-KEY')),
            'interrupted': dict(start_error=KeyboardInterrupt()),
            'access-refusal': dict(start_error=host.AccessError('PRIVATE-ACCESS')),
        }
        for name, extra in cases.items():
            with self.subTest(name):
                code, receipt, trace, *_ = self.owner_pipeline(handoff=True, **extra)
                self.assertEqual(receipt['success_handoff'], 'refused')
                if name == 'containment-error':
                    self.assertIn(('remote', ('/usr/bin/sudo', '-n', '/usr/bin/systemctl', 'stop', guest.UNIT), 'persistence'), trace)
                self.assertEqual(trace[-1], 'captured-cancel')
                self.assertNotEqual(code, 0)
                self.assertEqual(code, receipt['code'] or 1)
                self.assertNotIn('PRIVATE', self.printed_text)

    def test_ready_receipt_is_printed_flushed_and_default_print_is_unchanged(self):
        self.owner_pipeline(handoff=True)
        self.assertEqual(self.print_calls, [{'flush': True}])
        self.owner_pipeline()
        self.assertEqual(self.print_calls, [{}])
        self.owner_pipeline(handoff=True, remaining=10.0)
        self.assertEqual(self.print_calls, [{}])

    def test_late_publication_failure_after_eligibility_refuses_cancels_and_exits_nonzero(self):
        cases = {
            'broken-pipe': BrokenPipeError(),
            'flush-os-error': OSError('PRIVATE-FLUSH'),
            'late-sigint': KeyboardInterrupt(),
            'late-sigterm-as-exit': SystemExit(143),
        }
        for name, error in cases.items():
            with self.subTest(name):
                code, receipt, trace, *_ = self.owner_pipeline(handoff=True, print_failure=error)
                self.assertEqual(code, 1)
                self.assertEqual(trace[-1], 'captured-cancel')
                self.assertEqual(receipt['success_handoff'], 'refused')
                self.assertEqual(receipt['code'], 0)
                self.assertTrue(receipt['independent_cleanup_dispatched'])
                self.assertEqual(self.print_calls[0], {'flush': True})
                self.assertEqual(len(self.print_calls), 2)
                self.assertNotIn('PRIVATE', self.printed_text)

    def test_failed_ready_publication_with_failing_fallback_print_still_cancels_and_exits_nonzero(self):
        code, receipt, trace, *_ = self.owner_pipeline(handoff=True, print_failure=BrokenPipeError(), print_failures=2)
        self.assertEqual(code, 1)
        self.assertEqual(trace[-1], 'captured-cancel')
        self.assertEqual(len(self.print_calls), 2)
        self.assertEqual(receipt['success_handoff'], 'refused')

    def test_failed_ready_publication_with_cancellation_failure_never_reports_dispatch_or_success(self):
        code, receipt, trace, *_ = self.owner_pipeline(handoff=True, print_failure=BrokenPipeError(),
                                                       cancel_error=RuntimeError('PRIVATE-CANCEL'))
        self.assertEqual(code, 1)
        self.assertIn('captured-cancel', trace)
        self.assertEqual(receipt['success_handoff'], 'refused')
        self.assertFalse(receipt['independent_cleanup_dispatched'])
        self.assertNotIn('PRIVATE', self.printed_text)

    def test_interrupt_after_ready_receipt_flush_before_return_still_cancels(self):
        original_trace = sys.gettrace()
        target = host.trial.__code__
        injected = False
        def interrupt(frame, event, arg):
            nonlocal injected
            if frame.f_code is target and event == 'line':
                # Publication has completed: this independently observes the mock call,
                # then interrupts the very next production statement before return.
                if frame.f_locals.get('handoff') == 'ready' and 'receipt' in frame.f_locals:
                    # The print call is the last line before this becomes true.
                    # Observe its completed mock call rather than a source line number.
                    if getattr(self, 'print_calls', []):
                        injected = True
                        sys.settrace(None)
                        raise KeyboardInterrupt()
            return interrupt
        sys.settrace(interrupt)
        try:
            code, receipt, trace, *_ = self.owner_pipeline(handoff=True)
        finally:
            sys.settrace(original_trace)
        self.assertTrue(injected, 'interrupt must occur after receipt publication')
        self.assertEqual(code, 1)
        self.assertEqual(receipt['success_handoff'], 'refused')
        self.assertEqual(trace[-1], 'captured-cancel')

    def test_default_mode_publication_failure_still_propagates_after_cancellation(self):
        with self.assertRaises(BrokenPipeError):
            self.owner_pipeline(print_failure=BrokenPipeError())

    def test_local_file_uncertainty_withholds_key_receipt_and_never_hands_off(self):
        code, receipt, trace, _, _, _, output = self.owner_pipeline(handoff=True, leftover='unexpected-private-file')
        self.assertFalse(receipt['local_files_absent'])
        self.assertFalse(receipt['own_key_absent'])
        self.assertNotIn('removed', trace)
        self.assertEqual((code, receipt['success_handoff']), (1, 'refused'))
        self.assertEqual(trace[-1], 'captured-cancel')

    def test_refused_handoff_preserves_primary_guest_code(self):
        code, receipt, trace, *_ = self.owner_pipeline(handoff=True, observed_code=7, observed_contained=False)
        self.assertEqual((code, receipt['code']), (7, 7))
        self.assertEqual(trace[-1], 'captured-cancel')

    def test_cancellation_failure_after_refused_handoff_is_nonzero_and_never_ready(self):
        code, receipt, trace, *_ = self.owner_pipeline(handoff=True, remaining=10.0,
                                                       cancel_error=RuntimeError('PRIVATE-CANCEL'))
        self.assertEqual((code, receipt['success_handoff']), (1, 'refused'))
        self.assertIn('captured-cancel', trace)
        self.assertFalse(receipt['independent_cleanup_dispatched'])
        self.assertNotIn('PRIVATE', self.printed_text)

    def test_cancellation_failure_on_primary_failure_keeps_primary_code_and_refusal(self):
        code, receipt, trace, *_ = self.owner_pipeline(handoff=True, observed_code=7, observed_contained=False,
                                                       cancel_error=RuntimeError('PRIVATE-CANCEL'))
        self.assertEqual((code, receipt['success_handoff']), (7, 'refused'))
        self.assertFalse(receipt['independent_cleanup_dispatched'])

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

    # --- opt-in private image preparation bridge (#530); provisional guest dependency (#526) ---

    @staticmethod
    def image_remotes(trace):
        return [e for e in trace if isinstance(e, tuple) and e[0] == 'remote' and len(e[1]) > 6
                and e[1][6] == host.IMAGE_BOOTSTRAP]

    def test_default_and_handoff_only_runs_never_touch_image_preparation(self):
        for kwargs in ({}, {'handoff': True}):
            with self.subTest(kwargs=kwargs):
                code, receipt, trace, *_ = self.owner_pipeline(**kwargs)
                self.assertNotIn('image_preparation', receipt)
                self.assertFalse(self.image_remotes(trace))
                self.assertFalse([e for e in trace if isinstance(e, tuple) and e[0] == 'image-sources'])
                self.assertFalse([e for e in trace if e == ('remote', tuple(host.SERVICE_COMMAND), 'persistence')])

    def test_preparation_requires_explicit_handoff_before_any_work(self):
        value = snapshot()
        registration = Mock()
        for handoff in (False, None, 1):
            with self.subTest(handoff=handoff), patch.object(host, 'trusted_source') as trust, \
                 self.assertRaises(guest.Failure):
                kwargs = {} if handoff is None else {'handoff_on_success': handoff}
                host.trial(value, self.directory, self.directory, registration=registration, records=Mock(),
                           login=Mock(), prepare_private_image=True, **kwargs)
            trust.assert_not_called()
            registration.current.assert_not_called()

    def test_cli_preparation_option_is_explicit_default_off_and_requires_handoff(self):
        value = snapshot()
        def run(argv):
            with patch.object(guest, 'regular', return_value=guest.encoded(value)), \
                 patch.object(host, 'private_directory', return_value=self.directory), \
                 patch.object(host, 'GcsAccessRecords', return_value=Mock()), \
                 patch.object(host, 'OwnerRegistration', return_value=Mock()), \
                 patch.object(host.SelfLogin, 'for_owner', return_value=Mock()), \
                 patch.object(host, 'trial', return_value=0) as trial:
                try:
                    host.main(['--snapshot', 'public-fixture', '--payloads', 'inputs', '--output', 'output', *argv])
                except SystemExit as exit_:
                    return trial, exit_.code
            return trial, None
        trial, refused = run(['--prepare-private-image'])
        trial.assert_not_called()
        self.assertEqual(refused, 2)
        trial, refused = run(['--handoff-on-success'])
        self.assertNotIn('prepare_private_image', trial.call_args.kwargs)
        trial, refused = run([])
        self.assertNotIn('prepare_private_image', trial.call_args.kwargs)
        trial, refused = run(['--handoff-on-success', '--prepare-private-image'])
        self.assertIsNone(refused)
        self.assertIs(trial.call_args.kwargs['prepare_private_image'], True)
        self.assertIs(trial.call_args.kwargs['handoff_on_success'], True)

    def test_exact_partial_preparation_is_reported_partial_owned_and_hands_off(self):
        code, receipt, trace, _, _, _, output = self.owner_pipeline(handoff=True, prepare=True)
        self.assertEqual((code, receipt['code'], receipt['contained']), (0, 0, True))
        self.assertEqual((receipt['image_preparation'], receipt['success_handoff']), ('partial-owned', 'ready'))
        self.assertNotIn('captured-cancel', trace)
        self.assertEqual(trace[-2:], ['master-close', 'removed'])
        self.assertFalse(any(output.iterdir()), 'staged public files and all local extras must be removed')
        self.assertTrue(receipt['local_files_absent'] and receipt['own_key_absent'])
        # Public receipt carries the closed status only, never guest text or counts.
        for text in ('owned_sealed', 'access-material-provenance', 'removed_count', 'unproven', 'oslogin_caches', 'PRIVATE'):
            self.assertNotIn(text, self.printed_text)

    def test_preparation_runs_only_after_heartbeat_join_on_the_original_master_in_fixed_order(self):
        code, receipt, trace, _, _, _, _ = self.owner_pipeline(handoff=True, prepare=True)
        tuples = [e for e in trace if isinstance(e, tuple)]
        heartbeats = [i for i, e in enumerate(tuples) if e[0] == 'remote' and 'heartbeat' in e[1]]
        service = tuples.index(('remote', tuple(host.SERVICE_COMMAND), 'persistence'))
        self.assertTrue(heartbeats and max(heartbeats) < service, 'heartbeat must be stopped before preparation')
        self.assertEqual(sum(e[0] == 'image-sources' for e in tuples), 1)
        sources = [i for i, e in enumerate(tuples) if e[0] == 'image-sources']
        transfer = [i for i, e in enumerate(tuples) if e[0] == 'transfer' and e[1] == tuple(sorted(host.IMAGE_SOURCES))]
        run = [i for i, e in enumerate(tuples) if e[0] == 'remote' and len(e[1]) > 6 and e[1][6] == host.IMAGE_BOOTSTRAP]
        self.assertEqual((len(transfer), len(run)), (1, 1))
        self.assertTrue(service < sources[0] < transfer[0] < run[0])
        self.assertEqual(tuples[transfer[0]][2], 'persistence')
        self.assertEqual(tuples[run[0]][2], 'persistence')
        self.assertEqual(tuples[sources[0]][1], snapshot()['source_sha'])  # captured SHA, not moving main
        self.assertEqual(trace.count('master-start'), 1)  # no second master or reconnect
        self.assertEqual(trace.index('master-close'), len(trace) - 2)

    def test_guest_command_binds_lease_boot_source_nonce_and_exact_file_hashes_without_secrets(self):
        self.owner_pipeline(handoff=True, prepare=True)
        runs = [args for args, _ in self.remote_inputs if len(args) > 6 and args[6] == host.IMAGE_BOOTSTRAP]
        self.assertEqual(len(runs), 1)
        args = runs[0]
        tool, unit = (guest.sha(('PUBLIC-IMAGE-' + n).encode()) for n in ('vlab_image.py', 'labapp-vlab-clone.service'))
        self.assertEqual(tuple(args[:6]), ('/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-B', '-c'))  # no bytecode
        self.assertEqual(tuple(args[7:14]), ('/tmp/labapp-vlab-image-' + 'd' * 32, 'a' * 40, 'd' * 32,
                                             snapshot()['request_id'], '22222222-2222-4222-8222-222222222222', tool, unit))
        self.assertTrue(args[14].isdigit() and 10 <= int(args[14]) <= host.IMAGE_CAP_SECONDS)
        self.assertEqual(len(args), 15)
        self.assertEqual([d for a, d in self.remote_inputs if a == args], [None])  # nothing on stdin
        for text in ('ghp_', 'PUBLIC-NONDEPLOYABLE-PASSWORD', 'oslogin', 'candidate.password', 'known_hosts'):
            self.assertFalse(any(text in part for part in args))

    def test_ghcr_record_never_reaches_preparation_argv_stdin_or_receipt(self):
        record = guest.encoded(self.GHCR)
        code, receipt, trace, *_ = self.owner_pipeline(handoff=True, prepare=True, ghcr=record)
        self.assertEqual(receipt['image_preparation'], 'partial-owned')
        carriers = [(a, d) for a, d in self.remote_inputs if d is not None]
        self.assertEqual(len(carriers), 1)  # only the original bootstrap stdin carries it
        self.assertIn(host.BOOTSTRAP, carriers[0][0])
        canary = self.GHCR['token']
        self.assertNotIn(canary, repr([a for a, _ in self.remote_inputs if len(a) > 6 and a[6] == host.IMAGE_BOOTSTRAP]))
        self.assertNotIn(canary, self.printed_text)

    def test_every_non_exact_guest_report_refuses_cancels_and_preserves_core_result(self):
        inner = PARTIAL_INNER
        cases = {
            'code-0-complete': prep_report(code=0),
            'code-1': prep_report(code=1),
            'code-4': prep_report(code=4),
            'code-3-not-sealed': prep_report(inner=dict(inner, owned_sealed=False)),
            'sealed-string': prep_report(inner=dict(inner, owned_sealed='true')),
            'sealed-int': prep_report(inner=dict(inner, owned_sealed=1)),
            'unmet-empty': prep_report(inner=dict(inner, unmet=[])),
            'unmet-other': prep_report(inner=dict(inner, unmet=['other'])),
            'unmet-extra': prep_report(inner=dict(inner, unmet=['access-material-provenance', 'other'])),
            'unmet-string': prep_report(inner=dict(inner, unmet='access-material-provenance')),
            'inner-extra-field': prep_report(inner=dict(inner, note='free text')),
            'inner-missing-field': prep_report(inner={k: v for k, v in inner.items() if k != 'removed_count'}),
            'outer-extra-field': prep_report(extra=1),
            'access-negative': prep_report(inner=dict(inner, access=dict(ACCESS, key_files=-1))),
            'access-bool-count': prep_report(inner=dict(inner, access=dict(ACCESS, key_files=True))),
            'access-huge-count': prep_report(inner=dict(inner, access=dict(ACCESS, key_files=10**9))),
            'access-float-count': prep_report(inner=dict(inner, access=dict(ACCESS, key_files=1.0))),
            'access-unknown-key': prep_report(inner=dict(inner, access=dict(ACCESS, metadata=1))),
            'access-missing-key': prep_report(inner=dict(inner, access={k: v for k, v in ACCESS.items()
                                                                        if k != 'oslogin_caches'})),
            'access-missing-status': prep_report(inner=dict(inner, access={k: v for k, v in ACCESS.items()
                                                                           if k != 'status'})),
            'access-status-other': prep_report(inner=dict(inner, access=dict(ACCESS, status='proven'))),
            'access-status-bool': prep_report(inner=dict(inner, access=dict(ACCESS, status=True))),
            'access-status-int': prep_report(inner=dict(inner, access=dict(ACCESS, status=1))),
            'access-empty': prep_report(inner=dict(inner, access={})),
            'access-old-count-only-shape': prep_report(inner=dict(inner, access={'metadata': 2})),
            'access-nested': prep_report(inner=dict(inner, access=dict(ACCESS, key_files={'x': 1}))),
            'removed-bool': prep_report(inner=dict(inner, removed_count=True)),
            'removed-huge': prep_report(inner=dict(inner, removed_count=10**9)),
            'inner-not-json': prep_report(inner='PRIVATE not json'),
            'inner-duplicate-key': prep_report(inner='{"owned_sealed":true,"owned_sealed":true,"access":'
                                                      + json.dumps(ACCESS) + ',"unmet":["access-material-provenance"],'
                                                      '"removed_count":0}'),
            'inner-nan': prep_report(inner='{"owned_sealed":true,"access":' + json.dumps(ACCESS)
                                          + ',"unmet":["access-material-provenance"],"removed_count":NaN}'),
            'empty': b'',
            'garbage': b'PRIVATE Traceback (most recent call last)\n',
            'no-newline': prep_report().rstrip(b'\n'),
            'not-canonical': json.dumps({'schema': 1, 'code': 3, 'stdout': json.dumps(inner) + '\n'}).encode() + b'\n',
            'string-code': guest.encoded({'schema': 1, 'code': '3', 'stdout': json.dumps(inner)}) + b'\n',
            'bool-code': guest.encoded({'schema': 1, 'code': True, 'stdout': json.dumps(inner)}) + b'\n',
            'oversize': b'x' * (host.IMAGE_REPORT_LIMIT + 1),
        }
        for name, report in cases.items():
            with self.subTest(name):
                code, receipt, trace, _, _, _, output = self.owner_pipeline(handoff=True, prepare=True,
                                                                           prep={'report': report})
                self.assertEqual(receipt['image_preparation'], 'refused')
                self.assertEqual((receipt['success_handoff'], code), ('refused', 1))
                self.assertEqual((receipt['code'], receipt['contained']), (0, True))  # core result separate
                self.assertEqual(trace[-1], 'captured-cancel')
                self.assertTrue(receipt['independent_cleanup_dispatched'])
                if host.wrapper_record(report) is not None:
                    # A valid closed wrapper record means the bootstrap positively closed the group.
                    self.assertFalse(any(output.iterdir()))
                    self.assertTrue(receipt['process_absent'])
                else:
                    # An unparseable/extra-key wrapper record cannot establish closure: sticky uncertainty.
                    self.assertFalse(receipt['process_absent'])
                self.assertNotIn('PRIVATE', self.printed_text)
                self.assertNotIn('Traceback', self.printed_text)

    def test_preparation_precondition_and_step_failures_refuse_cancel_and_clean_up(self):
        cases = {
            'service-active': dict(service=b'ActiveState=active\nResult=success\nExecMainCode=0\nExecMainStatus=0\n'),
            'service-failed': dict(service=b'ActiveState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=1\n'),
            'service-unparsed': dict(service=b'garbage'),
            'service-read-error': dict(service_error=RuntimeError('PRIVATE-SERVICE')),
            'result-changed': dict(result_changed=True),
            'fetch-error': dict(fetch_error=RuntimeError('PRIVATE-FETCH')),
            'fetch-guest-failure': dict(fetch_error=guest.Failure('PRIVATE', 1)),
            'transfer-error': dict(transfer_error=RuntimeError('PRIVATE-COPY')),
            # Definite bootstrap refusals only: exit 2 (nothing started) and exit 3 (started, owned group
            # positively closed, no record). Every other run outcome is sticky uncertainty (next test).
            'run-bootstrap-refused-2': dict(run_error=guest.Failure('host child failed', 2)),
            'run-closed-without-record-3': dict(run_error=guest.Failure('host child failed', 3)),
        }
        for name, prep in cases.items():
            with self.subTest(name):
                code, receipt, trace, _, _, _, output = self.owner_pipeline(handoff=True, prepare=True, prep=prep)
                self.assertEqual(receipt['image_preparation'], 'refused')
                self.assertEqual((receipt['success_handoff'], code), ('refused', 1))
                self.assertEqual(receipt['code'], 0)
                self.assertEqual(trace[-1], 'captured-cancel')
                self.assertEqual(trace[-3:-1], ['master-close', 'removed'])  # normal ordered cleanup still ran
                self.assertFalse(any(output.iterdir()))
                self.assertTrue(receipt['local_files_absent'] and receipt['own_key_absent'])
                self.assertNotIn('PRIVATE', self.printed_text)

    def test_insufficient_original_budget_refuses_before_any_fetch_or_stage(self):
        for remaining in (899.0, 900.0, 1000.0, 1019.0):  # reserve 900 + least usable 120
            with self.subTest(remaining=remaining):
                code, receipt, trace, *_ = self.owner_pipeline(handoff=True, prepare=True, remaining=remaining)
                self.assertEqual(receipt['image_preparation'], 'refused')
                self.assertEqual((code, receipt['success_handoff']), (1, 'refused'))
                self.assertFalse([e for e in trace if isinstance(e, tuple) and e[0] == 'image-sources'])
                self.assertFalse(self.image_remotes(trace))
                self.assertEqual(trace[-1], 'captured-cancel')

    def test_exact_minimum_original_budget_still_prepares_and_keeps_the_reserve(self):
        code, receipt, trace, *_ = self.owner_pipeline(handoff=True, prepare=True, remaining=1020.0)
        self.assertEqual((code, receipt['image_preparation'], receipt['success_handoff']), (0, 'partial-owned', 'ready'))
        seconds = [args for args, _ in self.remote_inputs if len(args) > 6 and args[6] == host.IMAGE_BOOTSTRAP][0][14]
        self.assertLessEqual(int(seconds), 120)  # never reaches into the 15 minute handoff reserve

    def test_preparation_skipped_when_core_result_is_not_a_validated_contained_success(self):
        cases = {
            'guest-failure': dict(observed_code=7, observed_contained=False),
            'uncontained-success': dict(observed_contained=False),
            'live-heartbeat': dict(heartbeat_alive=True),
            'interrupted': dict(start_error=KeyboardInterrupt()),
            'access-refusal': dict(start_error=host.AccessError('PRIVATE-ACCESS')),
        }
        for name, extra in cases.items():
            with self.subTest(name):
                code, receipt, trace, *_ = self.owner_pipeline(handoff=True, prepare=True, **extra)
                self.assertEqual(receipt['image_preparation'], 'skipped')
                self.assertEqual(receipt['success_handoff'], 'refused')
                self.assertNotEqual(code, 0)
                self.assertFalse(self.image_remotes(trace))
                self.assertFalse([e for e in trace if isinstance(e, tuple) and e[0] == 'image-sources'])
                self.assertEqual(trace[-1], 'captured-cancel')

    def test_primary_failure_code_is_preserved_when_preparation_is_requested(self):
        code, receipt, trace, *_ = self.owner_pipeline(handoff=True, prepare=True, observed_code=7, observed_contained=False)
        self.assertEqual((code, receipt['code']), (7, 7))

    def test_cleanup_uncertainty_during_preparation_is_sticky_and_blocks_handoff_and_key_receipt(self):
        failure = guest.Failure('PRIVATE-ORPHAN')
        failure.cleanup_uncertain = True
        for where in ('run_error', 'fetch_error', 'transfer_error', 'service_error'):
            with self.subTest(where):
                code, receipt, trace, _, _, _, output = self.owner_pipeline(handoff=True, prepare=True,
                                                                           prep={where: failure})
                self.assertEqual(receipt['image_preparation'], 'refused')
                self.assertEqual((code, receipt['success_handoff']), (1, 'refused'))
                self.assertFalse(receipt['process_absent'])
                self.assertFalse(receipt['own_key_absent'])
                self.assertFalse(receipt['local_files_absent'])
                self.assertNotIn('removed', trace)
                self.assertTrue(any(output.iterdir()), 'uncertain ownership must not claim files are gone')
                self.assertEqual(trace[-1], 'captured-cancel')

    def test_image_named_local_files_are_owned_only_when_preparation_is_requested(self):
        for name in sorted(host.IMAGE_SOURCES):
            with self.subTest(name=name, prepare=False):
                # Option absent: an image-named file is foreign -> never deleted, handoff refused (original shape).
                code, receipt, trace, _, _, _, output = self.owner_pipeline(handoff=True, leftover=name)
                self.assertEqual((code, receipt['success_handoff']), (1, 'refused'))
                self.assertFalse(receipt['local_files_absent'])
                self.assertTrue((output / name).exists(), 'default run silently deleted an image-named foreign file')
                self.assertNotIn('image_preparation', receipt)
            with self.subTest(name=name, prepare=True):
                code, receipt, trace, _, _, _, output = self.owner_pipeline(handoff=True, prepare=True, leftover=name)
                self.assertEqual(receipt['image_preparation'], 'partial-owned')
                self.assertTrue(receipt['local_files_absent'])  # the two fixed staging names are owned only here
                self.assertFalse((output / name).exists())

    def test_leftover_foreign_local_file_still_refuses_a_prepared_handoff(self):
        code, receipt, trace, *_ = self.owner_pipeline(handoff=True, prepare=True, leftover='unexpected-private-file')
        self.assertEqual(receipt['image_preparation'], 'partial-owned')
        self.assertFalse(receipt['local_files_absent'])
        self.assertEqual((code, receipt['success_handoff']), (1, 'refused'))
        self.assertEqual(trace[-1], 'captured-cancel')

    def test_late_publication_failure_after_preparation_keeps_the_existing_guard(self):
        code, receipt, trace, *_ = self.owner_pipeline(handoff=True, prepare=True, print_failure=BrokenPipeError())
        self.assertEqual(code, 1)
        self.assertEqual(receipt['success_handoff'], 'refused')
        self.assertEqual(receipt['image_preparation'], 'partial-owned')  # truthful: guest state was changed
        self.assertEqual(trace[-1], 'captured-cancel')

    def test_run_outcomes_that_do_not_prove_remote_closure_are_sticky_process_uncertainty(self):
        """Timeout, transport loss, exit 4/255/odd, local interrupt, unparsed/late record: never absence."""
        cases = {
            'run-timeout': dict(run_error=guest.Failure('bounded host child timeout', 124)),
            'run-error': dict(run_error=RuntimeError('PRIVATE-RUN')),
            'run-interrupt': dict(run_error=KeyboardInterrupt()),
            'run-sigterm-failure': dict(run_error=guest.Failure('signal', 143)),
            'bootstrap-closure-unproven-4': dict(run_error=guest.Failure('host child failed', 4)),
            'ssh-transport-255': dict(run_error=guest.Failure('host child failed', 255)),
            'sudo-or-generic-1': dict(run_error=guest.Failure('host child failed', 1)),
            'garbage-report': dict(report=b'PRIVATE not a record\n'),
            'empty-report': dict(report=b''),
            'unknown-outer-key': dict(report=prep_report(extra=1)),
        }
        for name, prep in cases.items():
            with self.subTest(name):
                code, receipt, trace, _, _, _, output = self.owner_pipeline(handoff=True, prepare=True, prep=prep)
                self.assertEqual(receipt['image_preparation'], 'refused')
                self.assertEqual((receipt['success_handoff'], code), ('refused', 1))
                self.assertEqual(receipt['code'], 0)
                self.assertFalse(receipt['process_absent'])      # never asserts process absence
                self.assertFalse(receipt['own_key_absent'])
                self.assertFalse(receipt['local_files_absent'])
                self.assertNotIn('removed', trace)
                self.assertEqual(trace[-1], 'captured-cancel')   # exact captured-creator cancellation
                self.assertNotIn('PRIVATE', self.printed_text)

    def test_a_valid_wrapper_record_with_a_different_real_code_is_a_closed_refusal_not_uncertainty(self):
        for code_ in (0, 1, 4, 137):
            with self.subTest(code_):
                code, receipt, trace, _, _, _, output = self.owner_pipeline(
                    handoff=True, prepare=True, prep={'report': prep_report(code=code_)})
                self.assertEqual((receipt['image_preparation'], receipt['success_handoff'], code), ('refused', 'refused', 1))
                self.assertTrue(receipt['process_absent'] and receipt['local_files_absent'])
                self.assertEqual(trace[-1], 'captured-cancel')

    def test_accept_preparation_unit_exactness(self):
        self.assertTrue(host.accept_preparation(prep_report()))
        self.assertTrue(host.accept_preparation(prep_report(inner={
            **PARTIAL_INNER, 'access': dict.fromkeys(ACCESS, 0) | {'status': 'unproven'}, 'removed_count': 0})))
        self.assertFalse(host.accept_preparation(prep_report(inner={**PARTIAL_INNER, 'access': {}})))
        self.assertFalse(host.accept_preparation(None))
        self.assertFalse(host.accept_preparation('text'))
        self.assertFalse(host.accept_preparation(prep_report(code=0)))

    def test_access_shape_is_the_exact_closed_526_public_inventory_shape(self):
        self.assertEqual(set(ACCESS), {'status', *host.IMAGE_ACCESS_KEYS})
        self.assertEqual(host.IMAGE_ACCESS_KEYS, ('key_files', 'other_home_dirs', 'symlinked_homes',
                                                   'oslogin_caches', 'agent_state_paths'))
        for key in host.IMAGE_ACCESS_KEYS:  # each count independently bounded, non-bool
            for bad in (-1, True, False, 1.0, '1', None, host.IMAGE_COUNT_LIMIT + 1):
                with self.subTest(key=key, bad=bad):
                    self.assertFalse(host.accept_preparation(
                        prep_report(inner=dict(PARTIAL_INNER, access=dict(ACCESS, **{key: bad})))))
            self.assertTrue(host.accept_preparation(
                prep_report(inner=dict(PARTIAL_INNER, access=dict(ACCESS, **{key: host.IMAGE_COUNT_LIMIT})))))

    # --- public source acquisition: two fixed files at the captured SHA with complete verification ---

    def contents(self, path, raw, **change):
        import hashlib
        value = {'type': 'file', 'path': path, 'encoding': 'base64', 'size': len(raw),
                 'content': base64.encodebytes(raw).decode(),
                 'sha': hashlib.sha1(b'blob %d\0' % len(raw) + raw).hexdigest()}
        value.update(change)
        return value

    def test_image_sources_fetch_only_two_fixed_paths_at_the_captured_sha(self):
        value = snapshot()
        value['source_sha'] = 'f' * 40
        served = {path: ('PUBLIC-' + name).encode() for name, path in host.IMAGE_SOURCES.items()}
        paths = []
        def fake(path, limit=host.MAX_JSON):
            paths.append(path)
            name, _, ref = path.removeprefix('contents/').partition('?ref=')
            return self.contents(name, served[name])
        output = self.directory / 'image-out'
        output.mkdir(mode=0o700)
        with patch.object(host, 'github', side_effect=fake):
            table = host.image_source_files(value, output)
        self.assertEqual(sorted(paths), sorted('contents/' + p + '?ref=' + 'f' * 40 for p in host.IMAGE_SOURCES.values()))
        self.assertEqual(set(table), {'vlab_image.py', 'labapp-vlab-clone.service'})
        for name, path in host.IMAGE_SOURCES.items():
            self.assertEqual((output / name).read_bytes(), served[path])
            self.assertEqual(table[name], {'bytes': len(served[path]), 'sha256': guest.sha(served[path])})
            self.assertEqual(stat.S_IMODE((output / name).stat().st_mode), 0o600)
        self.assertNotIn('main', ''.join(paths))

    def test_image_source_refuses_wrong_path_type_encoding_size_blob_hash_and_oversize(self):
        name, path = 'vlab_image.py', host.IMAGE_SOURCES['vlab_image.py']
        raw = b'PUBLIC-MODULE'
        bad = {
            'wrong-path': self.contents('build/provision/other.py', raw),
            'directory': self.contents(path, raw, type='dir'),
            'encoding': self.contents(path, raw, encoding='utf-8'),
            'size-mismatch': self.contents(path, raw, size=len(raw) + 1),
            'zero-size': self.contents(path, b'', size=0),
            'size-bool': self.contents(path, raw, size=True),
            'oversize': self.contents(path, b'x' * (guest.MAX_SOURCE + 1)),
            'blob-hash-wrong': self.contents(path, raw, sha='0' * 40),
            'blob-hash-missing': {k: v for k, v in self.contents(path, raw).items() if k != 'sha'},
            'blob-hash-short': self.contents(path, raw, sha='abc'),
            'content-not-base64': self.contents(path, raw, content='!!!!'),
        }
        for label, value in bad.items():
            with self.subTest(label), patch.object(host, 'github', return_value=value):
                output = self.directory / ('o-' + label)
                output.mkdir(mode=0o700)
                with self.assertRaises((guest.Failure, ValueError)):
                    host.image_source_files(snapshot(), output)
                self.assertFalse((output / name).exists(), 'nothing is staged before full verification')

    def test_image_source_files_are_refused_if_a_staging_name_already_exists(self):
        output = self.directory / 'preexisting'
        output.mkdir(mode=0o700)
        (output / 'vlab_image.py').write_bytes(b'foreign')
        with patch.object(host, 'github', side_effect=lambda path, limit=0: self.contents(
                path.removeprefix('contents/').partition('?')[0], b'PUBLIC')):
            with self.assertRaises(FileExistsError):
                host.image_source_files(snapshot(), output)
        self.assertEqual((output / 'vlab_image.py').read_bytes(), b'foreign')

    def test_fixed_owned_cleanup_table_names_both_image_staging_files_and_source_fixes_the_names(self):
        self.assertEqual(set(host.IMAGE_SOURCES), {'vlab_image.py', 'labapp-vlab-clone.service'})
        self.assertEqual(set(host.IMAGE_SOURCES.values()),
                         {'build/provision/vlab_image.py', 'build/provision/labapp-vlab-clone.service'})
        self.assertFalse(set(host.IMAGE_SOURCES) & guest.FILES)  # never mixes into the core table

    def test_actual_master_transfer_keeps_default_cap_and_only_shortens_with_until(self):
        master = self.master()
        with patch.object(host, 'command') as run:
            master.transfer('/tmp/labapp-vlab-image-' + 'a' * 32, ['vlab_image.py'], 'access')
            default_seconds = run.call_args.args[1]
            self.assertLessEqual(default_seconds, 600)
            master.transfer('/tmp/labapp-vlab-image-' + 'a' * 32, ['vlab_image.py'], 'access',
                            until=host.owned_process.monotonic() + 30)
            self.assertLessEqual(run.call_args.args[1], 30)
        self.assertFalse((master.directory / 'sftp.batch').exists())


@unittest.skipIf(os.geteuid() == 0, 'fixtures model the root-owned library as owned by the unprivileged test user')
@unittest.skipUnless(os.path.exists('/usr/bin/python3'), 'bootstrap child uses the fixed /usr/bin/python3')
class ImageBootstrap(unittest.TestCase):
    """Runs the REAL guest bootstrap text against PUBLIC fake module/unit in safe temp fixtures.

    Only the environment-specific trust anchors are rebound: the fixed library path and 'root' uid
    become a temp directory and the test user; every verification step is the production code.
    """
    NONCE = 'c' * 32
    SOURCE = 'a' * 40
    LEASE = '11111111-1111-4111-8111-111111111111'
    BOOT = '22222222-2222-4222-8222-222222222222'
    MODULE = (b"import json, sys\nimport owned_process\n"
              b"print(json.dumps({'owned_sealed': True, 'access': {'status': 'unproven', 'key_files': 0,"
              b" 'other_home_dirs': 1, 'symlinked_homes': 0, 'oslogin_caches': 2, 'agent_state_paths': 0},"
              b" 'unmet': ['access-material-provenance'], 'removed_count': 2}))\nsys.exit(3)\n")
    UNIT = b'[Unit]\nDescription=PUBLIC fixture\n'
    # The ACTUAL trusted closure module (same bytes the guest installs from this tree) plus a marker, so the
    # bootstrap and the child run the real OwnedGroup; only the marker line differs from the shipped file.
    TRUSTED_SOURCE = (Path(__file__).with_name('owned_process.py').read_text() + '\nMARK = "trusted"\n')

    def setUp(self):
        import shutil
        self.base = Path(tempfile.mkdtemp(prefix='image-bootstrap-'))
        self.addCleanup(shutil.rmtree, self.base, True)
        self.base.chmod(0o755)
        self.lib = self.base / 'lib'
        self.lib.mkdir(mode=0o755)
        self.lib.chmod(0o755)
        self.trusted = self.lib / 'owned_process.py'
        self.trusted.write_text(self.TRUSTED_SOURCE)
        self.trusted.chmod(0o644)
        self.decoy = self.base / 'decoy'
        self.decoy.mkdir()
        (self.decoy / 'owned_process.py').write_text('MARK = "decoy"\n')
        self.incoming = Path('/tmp/labapp-vlab-image-' + self.NONCE)
        self.assertFalse(self.incoming.exists(), 'stale fixture directory')
        self.incoming.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.incoming, True)
        self.stage(self.MODULE)

    def stage(self, module, unit=None):
        for name, raw in (('vlab_image.py', module), ('labapp-vlab-clone.service', self.UNIT if unit is None else unit)):
            path = self.incoming / name
            if path.is_symlink() or path.exists():
                path.unlink()
            path.write_bytes(raw)
            path.chmod(0o600)

    def variant(self):
        text = host.IMAGE_BOOTSTRAP
        uid = os.geteuid()
        for old, new in (
                ("LIB='/usr/local/lib/labapp'", 'LIB=' + repr(str(self.lib))),
                ("('/','/usr','/usr/local','/usr/local/lib',LIB)", '(LIB,)'),
                ('s.st_uid==0', 's.st_uid==%d' % uid),
                ("get(LIB+'/owned_process.py',0)", "get(LIB+'/owned_process.py',%d)" % uid),
                ("get(LIB+'/'+n,0,0o644)", "get(LIB+'/'+n,%d,0o644)" % uid)):
            self.assertIn(old, text, 'bootstrap changed shape; update the fixture rebinding')
            text = text.replace(old, new)
        return text

    def run_bootstrap(self, *, tool=None, unit=None, nonce=None, incoming=None, seconds='20', code=None):
        tool = tool or hashlib_sha(self.incoming / 'vlab_image.py')
        unit = unit or hashlib_sha(self.incoming / 'labapp-vlab-clone.service')
        argv = [str(incoming or self.incoming), self.SOURCE, nonce or self.NONCE, self.LEASE, self.BOOT, tool, unit, seconds]
        import subprocess as sp
        # ``-I -B``: no user site/PYTHONPATH and no bytecode, so the exact installed inventory stays exact.
        return sp.run([sys.executable, '-I', '-B', '-c', code or self.variant(), *argv], cwd=self.decoy,
                      capture_output=True, env={'PATH': '/usr/bin:/bin', 'PYTHONPATH': str(self.decoy)}, timeout=60)

    def start(self, *, seconds='20', code=None):
        """Same bootstrap as a live child the test can signal (cooperative parent cancellation)."""
        import subprocess as sp
        argv = [str(self.incoming), self.SOURCE, self.NONCE, self.LEASE, self.BOOT,
                hashlib_sha(self.incoming / 'vlab_image.py'), hashlib_sha(self.incoming / 'labapp-vlab-clone.service'),
                seconds]
        proc = sp.Popen([sys.executable, '-I', '-B', '-c', code or self.variant(), *argv], cwd=self.decoy,
                        stdout=sp.PIPE, stderr=sp.PIPE, env={'PATH': '/usr/bin:/bin', 'PYTHONPATH': str(self.decoy)})
        self.addCleanup(self.reap, proc)
        return proc

    def reap(self, proc):
        if proc.poll() is None:
            proc.kill()
        proc.communicate()
        for pid in self.pids():
            try:
                os.kill(pid, 9)
            except OSError:
                pass

    def pids(self):
        try:
            return [int(v) for v in (self.base / 'pids').read_text().split()]
        except (OSError, ValueError):
            return []

    def wait_pids(self):
        import time as t
        end = t.monotonic() + 15
        while t.monotonic() < end:
            if len(self.pids()) == 2:
                return self.pids()
            t.sleep(.05)
        self.fail('fixture module never reported its processes')

    @staticmethod
    def gone(pid):
        """True when the process is absent or only an unreaped zombie (cannot run anything)."""
        try:
            state = Path('/proc/%d/stat' % pid).read_text().rpartition(')')[2].split()[0]
        except OSError:
            return True
        return state in 'ZX'

    def watcher(self, tail=b''):
        """Safe synthetic PUBLIC module: reports pid + a same-group descendant, then runs forever.

        ``finally`` records that a cooperative stop reached nested code as an exception, not an abrupt kill.
        """
        pids, mark = self.base / 'pids', self.base / 'closed'
        return (f"import os, subprocess, sys, time\n"
                f"child = subprocess.Popen(['/usr/bin/sleep', '300'], stdin=subprocess.DEVNULL,\n"
                f"                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
                f"open({str(pids) + '.t'!r}, 'w').write(str(os.getpid()) + ' ' + str(child.pid))\n"
                f"os.rename({str(pids) + '.t'!r}, {str(pids)!r})\n"
                f"try:\n    time.sleep(300)\nfinally:\n    open({str(mark)!r}, 'w').write('closed')\n").encode() + tail

    def reset(self):
        for name in self.installed():
            (self.lib / name).unlink()
        for name in ('pids', 'closed'):
            (self.base / name).unlink(missing_ok=True)

    def installed(self):
        return sorted(p.name for p in self.lib.iterdir() if p.name != 'owned_process.py')

    def test_success_installs_exact_root_files_runs_trusted_module_and_reports_real_code(self):
        done = self.run_bootstrap()
        self.assertEqual((done.returncode, done.stderr), (0, b''))
        outer = guest.data(done.stdout)
        self.assertEqual((outer['schema'], outer['code']), (1, 3))  # real module code, never relabelled
        self.assertEqual(done.stdout, guest.encoded(outer) + b'\n')
        self.assertEqual(self.installed(), ['labapp-vlab-clone.service', 'vlab_image.py'])
        for name, raw in (('vlab_image.py', self.MODULE), ('labapp-vlab-clone.service', self.UNIT)):
            path = self.lib / name
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            self.assertEqual(path.stat().st_nlink, 1)
        self.assertTrue(host.accept_preparation(done.stdout))

    def test_module_imports_owned_process_only_from_the_trusted_library(self):
        self.stage(b"import sys, owned_process\nprint(owned_process.MARK)\nsys.exit(3)\n")
        outer = guest.data(self.run_bootstrap().stdout)
        self.assertEqual(outer['stdout'], 'trusted\n')

    def test_arguments_reach_the_module_with_exact_binding_and_hashes(self):
        self.stage(b"import json, sys\nprint(json.dumps(sys.argv[1:]))\nsys.exit(3)\n")
        done = self.run_bootstrap()
        argv = json.loads(guest.data(done.stdout)['stdout'])
        tool, unit = hashlib_sha(self.incoming / 'vlab_image.py'), hashlib_sha(self.incoming / 'labapp-vlab-clone.service')
        self.assertEqual(argv, ['prepare', '--private-candidate', '--source-sha', self.SOURCE, '--nonce', self.NONCE,
                                '--lease', self.LEASE, '--build-boot', self.BOOT, '--tool-sha256', tool,
                                '--unit-sha256', unit])

    def test_nonzero_and_signalled_module_codes_are_reported_not_relabelled(self):
        for source, expected in ((b'import sys\nsys.exit(5)\n', 5), (b'import sys\nsys.exit(0)\n', 0),
                                 (b'import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n', 137)):
            with self.subTest(expected=expected):
                for name in self.installed():
                    (self.lib / name).unlink()
                self.stage(source)
                outer = guest.data(self.run_bootstrap().stdout)
                self.assertEqual(outer['code'], expected)
                self.assertFalse(host.accept_preparation(self.run_bootstrap_output_for(outer)))

    @staticmethod
    def run_bootstrap_output_for(outer):
        return guest.encoded(outer) + b'\n'

    def refused(self, done, ran=False):
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, b'')
        self.assertEqual(done.stderr, b'')

    def test_nothing_is_installed_or_executed_when_any_verification_fails(self):
        marker = self.base / 'executed'
        executing = ('open(%r, "w").write("x")\n' % str(marker)).encode()
        self.stage(executing)
        def mutate(label):
            if label == 'hash':
                return dict(tool='0' * 64)
            if label == 'unit-hash':
                return dict(unit='0' * 64)
            if label == 'nonce-mismatch':
                return dict(nonce='e' * 32)
            if label == 'foreign-incoming-path':
                return dict(incoming=self.base)
            if label == 'bad-seconds':
                return dict(seconds='9')
            return {}
        for label in ('hash', 'unit-hash', 'nonce-mismatch', 'foreign-incoming-path', 'bad-seconds'):
            with self.subTest(label):
                self.refused(self.run_bootstrap(**mutate(label)))
                self.assertEqual(self.installed(), [])
                self.assertFalse(marker.exists())

    def test_symlink_hardlink_extra_mode_and_type_defects_in_incoming_are_refused_before_install(self):
        marker = self.base / 'executed'
        self.stage(('open(%r, "w").write("x")\n' % str(marker)).encode())
        target = self.base / 'elsewhere'
        target.write_bytes(self.UNIT)
        def symlinked():
            (self.incoming / 'labapp-vlab-clone.service').unlink()
            (self.incoming / 'labapp-vlab-clone.service').symlink_to(target)
        def hardlinked():
            os.link(self.incoming / 'vlab_image.py', self.base / 'alias')
        def extra():
            (self.incoming / 'extra').write_bytes(b'x')
        def loose_directory():
            self.incoming.chmod(0o755)
        def directory_instead():
            (self.incoming / 'vlab_image.py').unlink()
            (self.incoming / 'vlab_image.py').mkdir()
        def oversize():
            (self.incoming / 'vlab_image.py').write_bytes(b'x' * (262144 + 1))
        for label, damage in (('symlink', symlinked), ('hardlink', hardlinked), ('extra-entry', extra),
                              ('loose-mode', loose_directory), ('directory', directory_instead), ('oversize', oversize)):
            with self.subTest(label):
                import shutil
                shutil.rmtree(self.incoming)
                self.incoming.mkdir(mode=0o700)
                (self.base / 'alias').unlink(missing_ok=True)
                self.stage(('open(%r, "w").write("x")\n' % str(marker)).encode())
                damage()
                hashes = {}
                for name in ('vlab_image.py', 'labapp-vlab-clone.service'):
                    path = self.incoming / name
                    hashes[name] = hashlib_sha(path) if path.is_file() else '0' * 64
                self.refused(self.run_bootstrap(tool=hashes['vlab_image.py'], unit=hashes['labapp-vlab-clone.service']))
                self.assertEqual(self.installed(), [])
                self.assertFalse(marker.exists())

    def test_foreign_or_preexisting_installation_and_untrusted_library_are_refused(self):
        for label in ('preexisting-module', 'preexisting-unit', 'preexisting-dangling-symlink', 'no-owned-process',
                      'group-writable-owned-process', 'owned-process-symlink', 'writable-library'):
            with self.subTest(label):
                for entry in list(self.lib.iterdir()):
                    entry.unlink()
                self.lib.chmod(0o755)
                self.trusted.write_text('MARK = "trusted"\n')
                self.trusted.chmod(0o644)
                if label == 'preexisting-module':
                    (self.lib / 'vlab_image.py').write_bytes(b'FOREIGN')
                elif label == 'preexisting-unit':
                    (self.lib / 'labapp-vlab-clone.service').write_bytes(b'FOREIGN')
                elif label == 'preexisting-dangling-symlink':
                    (self.lib / 'vlab_image.py').symlink_to(self.base / 'nowhere')
                elif label == 'no-owned-process':
                    self.trusted.unlink()
                elif label == 'group-writable-owned-process':
                    self.trusted.chmod(0o664)
                elif label == 'owned-process-symlink':
                    self.trusted.unlink()
                    self.trusted.symlink_to(self.decoy / 'owned_process.py')
                else:
                    self.lib.chmod(0o775)
                before = {p.name: p.read_bytes() if p.is_file() and not p.is_symlink() else None for p in self.lib.iterdir()}
                self.refused(self.run_bootstrap())
                after = {p.name: p.read_bytes() if p.is_file() and not p.is_symlink() else None for p in self.lib.iterdir()}
                self.assertEqual(before, after)
        self.lib.chmod(0o755)

    def closed_without_record(self, done):
        """Started, owned group positively closed, no record (bootstrap exit 3)."""
        self.assertEqual((done.returncode, done.stdout), (3, b''))

    def test_oversize_or_non_ascii_module_output_is_never_reported_and_the_group_is_closed(self):
        self.stage(b"import sys\nsys.stdout.write('x' * 5000)\nsys.stdout.flush()\nsys.exit(3)\n")
        self.closed_without_record(self.run_bootstrap())
        self.reset()
        self.stage(b"import sys\nsys.stdout.buffer.write(b'\\xff')\nsys.exit(3)\n")
        done = self.run_bootstrap()
        self.closed_without_record(done)
        self.assertNotIn(b'\xff', done.stdout)

    def test_oversize_output_from_a_still_running_module_closes_its_whole_group(self):
        self.stage(self.watcher().replace(b"try:\n    time.sleep(300)",
                                          b"sys.stdout.write('x' * 5000)\nsys.stdout.flush()\ntry:\n    time.sleep(300)"))
        done = self.run_bootstrap()
        self.closed_without_record(done)
        for pid in self.pids():
            self.assertTrue(self.gone(pid), 'descendant survived oversize closure')
        self.assertEqual((self.base / 'closed').read_text(), 'closed')  # TERM reached nested code first

    def test_normal_return_kills_a_lingering_same_group_descendant_before_reporting(self):
        self.stage(self.watcher().replace(b"try:\n    time.sleep(300)\nfinally:",
                                          b"try:\n    pass\nfinally:") + b"sys.exit(3)\n")
        done = self.run_bootstrap()
        self.assertEqual(done.returncode, 0)
        self.assertEqual(guest.data(done.stdout)['code'], 3)
        pid = self.pids()[1]
        self.assertTrue(self.gone(pid), 'record was printed while a descendant could still run')

    def test_cooperative_parent_cancellation_closes_module_and_descendants_without_a_record(self):
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            with self.subTest(signal=int(number)):
                self.reset()
                self.stage(self.watcher())
                proc = self.start()
                module, descendant = self.wait_pids()
                proc.send_signal(number)
                out, err = proc.communicate(timeout=30)
                self.assertEqual((proc.returncode, out), (3, b''))  # closed, no record; never exit 0
                self.assertEqual(err, b'')
                self.assertTrue(self.gone(module) and self.gone(descendant))
                # SIGTERM became SystemExit in the child runner, so nested ``finally`` ran (not abrupt death).
                self.assertEqual((self.base / 'closed').read_text(), 'closed')
                self.assertFalse(host.accept_preparation(out))

    def test_timeout_uses_one_budget_with_a_closure_reserve_and_closes_everything(self):
        import time as t
        self.stage(self.watcher())
        started = t.monotonic()
        proc = self.start(seconds='10')
        out, _ = proc.communicate(timeout=30)
        elapsed = t.monotonic() - started
        self.assertEqual((proc.returncode, out), (3, b''))
        self.assertLess(elapsed, 10 + 5, 'wrapper outlived its single budget by more than interpreter start-up')
        module, descendant = self.pids()
        self.assertTrue(self.gone(module) and self.gone(descendant))
        self.assertEqual((self.base / 'closed').read_text(), 'closed')

    def test_closure_not_positively_established_exits_4_and_never_prints_a_record(self):
        trusted = self.TRUSTED_SOURCE + '\nOwnedGroup.close = lambda self, *a, **k: False\n'
        self.trusted.write_text(trusted)
        done = self.run_bootstrap()
        self.assertEqual((done.returncode, done.stdout), (4, b''))
        self.assertFalse(host.accept_preparation(done.stdout))

    def test_a_bad_ownership_module_cannot_report_and_leaves_no_bytecode(self):
        self.trusted.write_text(self.TRUSTED_SOURCE + '\nraise RuntimeError("PRIVATE")\n')
        done = self.run_bootstrap()
        self.refused(done)  # failed to load the trusted closure before anything was installed or run
        self.assertEqual(self.installed(), [])
        self.assertFalse(list(self.lib.rglob('__pycache__')))

    def test_exact_installed_inventory_without_bytecode_after_success(self):
        done = self.run_bootstrap()
        self.assertEqual(done.returncode, 0)
        self.assertEqual(sorted(p.name for p in self.lib.iterdir()),
                         ['labapp-vlab-clone.service', 'owned_process.py', 'vlab_image.py'])
        self.assertFalse(list(self.base.rglob('__pycache__')))

    def test_imported_closure_module_has_the_validated_installed_file_and_matching_bytes(self):
        """Actual #526 prepare reads ``owned_process.__file__`` and hashes it against the installed core copy.

        Authored UNRUN. The fixture performs that same read+hash and records the result for the assertion.
        """
        out = self.base / 'filecheck'
        self.stage((("import hashlib, os, sys, owned_process\n"
                    "p = getattr(owned_process, '__file__', None)\n"
                    "ok = p == %r and hashlib.sha256(open(p, 'rb').read()).hexdigest() == %r\n"
                    "open(%r, 'w').write('ok' if ok else 'bad:%%r' %% (p,))\n"
                    "sys.exit(3)\n") % (str(self.trusted), hashlib_sha(self.trusted), str(out))).encode('ascii'))
        done = self.run_bootstrap()
        self.assertEqual(done.returncode, 0)
        self.assertEqual(guest.data(done.stdout)['code'], 3)
        self.assertEqual(out.read_text(), 'ok')

    def test_stop_arriving_during_closure_is_not_reported_as_an_accepted_preparation(self):
        """A cancellation that lands while the group is being closed must publish no record (exit 3)."""
        trusted = self.TRUSTED_SOURCE + (
            "\n_close = OwnedGroup.close\n"
            "def _late(self, *a, **k):\n"
            "    import os, signal\n"
            "    r = _close(self, *a, **k)\n"
            "    os.kill(os.getpid(), signal.SIGTERM)\n"
            "    return r\n"
            "OwnedGroup.close = _late\n")
        self.trusted.write_text(trusted)
        # The child runner verifies the closure hash it was given, so it sees the same patched bytes.
        done = self.run_bootstrap()
        self.assertEqual((done.returncode, done.stdout), (3, b''))
        self.assertFalse(host.accept_preparation(done.stdout))

    def test_child_runner_requires_the_exact_trusted_closure_bytes(self):
        """The child exits 2 before executing anything if owned_process differs from the hash the parent saw."""
        marker = self.base / 'executed'
        self.stage(('open(%r, "w").write("x")\n' % str(marker)).encode())
        text = self.variant().replace("RUNNER,LIB,tool,osha,", "RUNNER,LIB,tool,'0'*64,")
        self.assertNotEqual(text, self.variant())
        done = self.run_bootstrap(code=text)
        self.assertEqual(done.returncode, 0)  # the child ran (and refused); its REAL code is reported
        self.assertEqual(guest.data(done.stdout)['code'], 2)
        self.assertFalse(marker.exists())
        self.assertFalse(host.accept_preparation(done.stdout))


def hashlib_sha(path):
    import hashlib
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


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
              fault=None, primary_error=None, candidate_command=None, close_error=None, cleanup_error=None,
              reads=None):
        value = snapshot()
        script, self.registration_reads = list(reads or ()), []
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
                self.registration_reads.append('read')
                if script:
                    step = script.pop(0)
                    if step is not None:
                        raise step
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
        self.assertEqual(next(self.kept(private)).read_bytes(), self.export_bytes())
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

    @staticmethod
    def kept(private):
        # Guest-bundle files only; the host's closed failure record is a distinct, separately tested file.
        return iter([p for p in private.iterdir() if not p.name.startswith('host-failure-')])

    # -- #537 closed first HOST failure record and finite periodic READ recovery ---------------
    RECEIPT_KEYS = {'schema', 'code', 'contained', 'process_absent', 'phase', 'failure_category', 'host_operation',
                    'own_key_absent', 'local_files_absent', 'independent_cleanup_dispatched', 'lease',
                    'guest_diagnostic_status', 'guest_diagnostic', 'guest_service', 'private_diagnostic'}
    HOST_RECORD_KEYS = {'schema', 'kind', 'source_sha', 'nonce', 'lease', 'epoch', 'run_id', 'attempt', 'phase',
                        'host_operation', 'failure_category', 'code', 'exception', 'http_status', 'recheck_attempts'}

    def host_record_path(self, private):
        return private / ('host-failure-' + snapshot()['request_id'] + '.json')

    def host_drive(self, reads, *, replies=None, **kwargs):
        self.exports = []
        private = self.directory / 'private'
        private.mkdir(mode=0o700, exist_ok=True)
        with patch.object(host, 'RECHECK_PAUSES', (0.0, 0.0)):
            outcome = self.drive(replies or [b'absent'], private=private, reads=reads, **kwargs)
        return private, outcome

    def test_transient_periodic_reads_recover_with_complete_fresh_success_and_no_failure_file(self):
        success = [self.encoded(result_value(self.nonce, 0, True))]
        for reads in ([host.ReadUnavailable(503), None], [host.TransientRead(None), host.ReadUnavailable(None), None],
                      [host.ReadUnavailable(429), host.TransientRead(500), None]):
            with self.subTest(reads=len(reads)):
                private, (code, receipt, trace, text) = self.host_drive(reads, replies=success)
                self.assertEqual(self.registration_reads, ['read'] * len(reads))
                self.assertEqual((code, receipt['code'], receipt['failure_category'], receipt['phase']),
                                 (0, 0, 'none', 'guest-result'))
                self.assertEqual(list(private.iterdir()), [])  # recovered polling leaves no failure file
                self.assertEqual(set(receipt), self.RECEIPT_KEYS)
                self.assertEqual(trace.count('master-start'), 1)  # no reconnect
                self.assertEqual(trace.count('remove-key'), 1)
            self.setUp()

    def test_all_three_periodic_attempts_fail_with_closed_correlated_host_record(self):
        cases = ((host.ReadUnavailable(503), 'store-read-unavailable', 503),
                 (host.TransientRead(429), 'cloud-read-unavailable', 429),
                 (host.ReadUnavailable(None), 'store-read-unavailable', None))
        for error, name, status in cases:
            with self.subTest(exception=name, status=status):
                private, (code, receipt, trace, text) = self.host_drive([error, error, error, None])
                self.assertEqual(self.registration_reads, ['read'] * host.RECHECK_ATTEMPTS)  # never a 4th
                self.assertEqual((code, receipt['code'], receipt['phase'], receipt['failure_category'],
                                  receipt['host_operation']), (1, 1, 'guest-work', 'unknown', 'registration-check'))
                self.assertEqual(set(receipt), self.RECEIPT_KEYS)
                self.assertIn('stop', trace)
                self.assertLess(trace.index('stop'), trace.index('master-close'))
                self.assertIn('remove-key', trace)
                self.assertIn('dispatch-cleanup', trace)
                path = self.host_record_path(private)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.stat().st_nlink, 1)
                raw = path.read_bytes()
                record = json.loads(raw)
                self.assertEqual(raw, guest.encoded(record))
                self.assertEqual(set(record), self.HOST_RECORD_KEYS)
                value = snapshot()
                self.assertEqual(record, {
                    'schema': 1, 'kind': 'host-failure', 'source_sha': value['source_sha'], 'nonce': self.nonce,
                    'lease': value['request_id'], 'epoch': value['epoch'], 'run_id': value['run_id'],
                    'attempt': value['attempt'], 'phase': 'guest-work', 'host_operation': 'registration-check',
                    'failure_category': 'unknown', 'code': 1, 'exception': name, 'http_status': status,
                    'recheck_attempts': 3})
                self.assertNotIn(str(self.directory).encode(), raw)
                self.assertEqual([p.name for p in private.iterdir() if p.name.startswith('first-failure')], [])
            self.setUp()

    def test_hard_registration_failures_are_not_retried_and_record_only_closed_names(self):
        cases = ((host.StoreError(SENTINEL), 'store-error', None), (host.NotFound(SENTINEL), 'cloud-not-found', 404),
                 (host.ApiError(401, SENTINEL), 'cloud-api-error', 401), (host.ApiError(403, SENTINEL), 'cloud-api-error', 403),
                 (host.Uncertain(SENTINEL), 'cloud-uncertain', None), (host.Refused(SENTINEL), 'controller-refused', None),
                 (host.ForbiddenOperation(SENTINEL), 'cloud-forbidden', None), (host.AccessError(SENTINEL), 'access-error', None),
                 (RuntimeError(SENTINEL), 'other', None), (ValueError(SENTINEL), 'other', None),
                 (OSError(SENTINEL), 'os-error', None),
                 (guest.Failure(SENTINEL, 17), 'failure', None))
        for error, name, status in cases:
            with self.subTest(exception=name, status=status):
                private, (code, receipt, trace, text) = self.host_drive([error, None, None])
                self.assertEqual(self.registration_reads, ['read'])  # no retry
                record = json.loads(self.host_record_path(private).read_bytes())
                self.assertEqual((record['exception'], record['http_status'], record['recheck_attempts']),
                                 (name, status, None))
                self.assertEqual(record['code'], code)
                self.assertNotIn(SENTINEL, self.host_record_path(private).read_text())
                self.assertNotIn(SENTINEL, text)
                self.assertEqual(set(receipt), self.RECEIPT_KEYS)
            self.setUp()

    def test_foreign_changed_lease_identity_and_deadline_failures_stay_hard(self):
        # `current()` raises guest.Failure for every changed lease/source/ID/VM/boot/deadline/status.
        for message in ('owner lease changed', 'insert not terminal', 'fixed trial refused'):
            with self.subTest(message=message):
                private, (code, receipt, trace, text) = self.host_drive([guest.Failure(message, 1), None])
                self.assertEqual((code, self.registration_reads), (1, ['read']))
                self.assertEqual(json.loads(self.host_record_path(private).read_bytes())['exception'], 'failure')
            self.setUp()

    def test_cancellation_during_periodic_recheck_is_not_retried_and_keeps_primary(self):
        for error, code, category, name in ((guest.Failure('signal', 143), 143, 'guest', 'failure'),
                                            (KeyboardInterrupt(), 130, 'interrupted', 'interrupted')):
            with self.subTest(code=code):
                private, (result, receipt, trace, text) = self.host_drive([error, None])
                self.assertEqual((result, receipt['code'], receipt['failure_category']), (code, code, category))
                self.assertEqual(self.registration_reads, ['read'])
                self.assertEqual(json.loads(self.host_record_path(private).read_bytes())['exception'], name)
            self.setUp()

    def test_guest_reported_failure_without_host_exception_has_no_host_record(self):
        private, (code, receipt, trace, text) = self.private_drive(self.export_bytes())
        self.assertEqual(code, 17)
        self.assertEqual([p.name for p in private.iterdir()], ['first-failure-' + snapshot()['request_id'] + '.bin'])
        self.assertEqual(receipt['guest_diagnostic'], worker_detail())

    def test_host_record_is_first_only_and_never_overwrites_adopts_or_follows_links(self):
        name = 'host-failure-' + snapshot()['request_id'] + '.json'
        # Preexisting regular file: untouched, primary result and cleanup unchanged.
        private = self.directory / 'private'
        private.mkdir(mode=0o700)
        (private / name).write_bytes(b'PREEXISTING')
        private, (code, receipt, trace, text) = self.host_drive([RuntimeError(SENTINEL)])
        self.assertEqual((private / name).read_bytes(), b'PREEXISTING')
        self.assertEqual((code, receipt['failure_category']), (1, 'unknown'))
        self.assertIn('remove-key', trace)
        self.assertIn('dispatch-cleanup', trace)
        self.setUp()
        # Symlink at the target: not followed, link and victim untouched.
        private = self.directory / 'private'
        private.mkdir(mode=0o700)
        victim = self.directory / 'victim'
        victim.write_bytes(b'KEEP')
        os.symlink(victim, private / name)
        private, (code, receipt, trace, text) = self.host_drive([RuntimeError(SENTINEL)])
        self.assertEqual(victim.read_bytes(), b'KEEP')
        self.assertTrue((private / name).is_symlink())
        self.assertEqual(code, 1)
        self.assertIn('dispatch-cleanup', trace)
        self.setUp()
        # Direct second write refuses; the first record is preserved.
        private = self.directory / 'private'
        private.mkdir(mode=0o700)
        initial = {'source_sha': 'a' * 40, 'nonce': 'd' * 32, 'lease': snapshot()['request_id'], 'epoch': 1,
                   'run_id': 123, 'attempt': 1}
        first = host.host_failure_record(initial, 'guest-work', 'registration-check', 'unknown', 1, RuntimeError('x'))
        host.retain_host_failure(private, first)
        later = host.host_failure_record(initial, 'guest-work', 'poll-check', 'guest', 17, guest.Failure('y', 17))
        with self.assertRaises(FileExistsError):
            host.retain_host_failure(private, later)
        self.assertEqual(json.loads((private / name).read_bytes()), first)

    def test_host_record_write_failure_cannot_change_primary_cleanup_or_success(self):
        with patch.object(host, 'retain_host_failure', side_effect=OSError(SENTINEL)):
            private, (code, receipt, trace, text) = self.host_drive([RuntimeError(SENTINEL)])
        self.assertEqual((code, receipt['code'], receipt['failure_category'], receipt['host_operation']),
                         (1, 1, 'unknown', 'registration-check'))
        self.assertEqual(list(private.iterdir()), [])
        self.assertNotIn(SENTINEL, text)
        self.assertLess(trace.index('stop'), trace.index('master-close'))
        self.assertLess(trace.index('master-close'), trace.index('remove-key'))
        self.assertLess(trace.index('remove-key'), trace.index('dispatch-cleanup'))
        self.assertTrue(receipt['process_absent'] and receipt['local_files_absent'] and receipt['own_key_absent'])
        self.setUp()
        # Even a record that would be unbuildable (invalid state) never raises out of the trial.
        with patch.object(host, 'host_failure_record', side_effect=guest.Failure('record refused', 99)):
            private, (code, receipt, trace, text) = self.host_drive([RuntimeError(SENTINEL)])
        self.assertEqual(code, 1)
        self.assertEqual(list(private.iterdir()), [])

    def test_no_private_directory_means_no_host_record_and_unchanged_behavior(self):
        with patch.object(host, 'retain_host_failure') as retain:
            code, receipt, trace, text = self.drive([b'absent'], fault='registration')
        retain.assert_not_called()
        self.assertEqual((code, receipt['private_diagnostic']), (1, 'skipped'))

    def test_host_record_requires_closed_inputs(self):
        initial = {'source_sha': 'a' * 40, 'nonce': 'd' * 32, 'lease': snapshot()['request_id'], 'epoch': 1,
                   'run_id': 123, 'attempt': 1}
        for phase, operation, category, code in (('x', 'registration-check', 'unknown', 1),
                                                 ('guest-work', 'free text', 'unknown', 1),
                                                 ('guest-work', 'registration-check', 'other', 1),
                                                 ('guest-work', 'registration-check', 'unknown', 0),
                                                 ('guest-work', 'registration-check', 'unknown', 256),
                                                 ('guest-work', 'registration-check', 'unknown', True)):
            with self.subTest(phase=phase, operation=operation, category=category, code=code):
                with self.assertRaises(guest.Failure):
                    host.host_failure_record(initial, phase, operation, category, code, RuntimeError())
        hostile = host.ReadUnavailable(503)
        hostile.status, hostile.recheck_attempts = 99999, 99
        record = host.host_failure_record(initial, 'guest-work', 'registration-check', 'unknown', 1, hostile)
        self.assertEqual((record['http_status'], record['recheck_attempts']), (None, None))
        self.assertEqual(host.host_failure_record(initial, 'guest-work', 'registration-check', 'unknown', 1,
                                                  RuntimeError(SENTINEL))['exception'], 'other')
        for lease in ('../escape', 'x' * 36, ''):
            with self.assertRaises(guest.Failure):
                host.retain_host_failure(self.directory, dict(record, lease=lease))
        loose = self.directory / 'loose'
        loose.mkdir(mode=0o755)
        loose.chmod(0o755)
        with self.assertRaises(guest.Failure):
            host.retain_host_failure(loose, record)
        self.assertEqual(list(loose.iterdir()), [])

    def test_retry_allowance_constants_are_small_and_finite(self):
        self.assertEqual(host.RECHECK_ATTEMPTS, 3)
        self.assertEqual(host.RECHECK_ALLOWANCE_SECONDS, 30.0)
        self.assertEqual(len(host.RECHECK_PAUSES), host.RECHECK_ATTEMPTS - 1)
        self.assertLess(sum(host.RECHECK_PAUSES), host.RECHECK_ALLOWANCE_SECONDS)

    # -- recheck_registration: exact budget semantics with a fake clock ------------------------
    class Recheck:
        def __init__(self, outcomes, budget=600.0):
            self.outcomes, self.budget, self.now, self.calls, self.waits = list(outcomes), budget, 1000.0, 0, []
            self.exhaust_on_call = self.fail_on_call = self.wait_result = self.wait_error = None
            self.exhausted, self.failed = False, threading.Event()
            self.registration = SimpleNamespace(current=self.current)
            self.clock = SimpleNamespace(remaining=self.remaining)

        def mono(self):
            return self.now

        def remaining(self, phase):
            assert phase == 'persistence'
            if self.exhausted:
                raise guest.Failure('absolute phase cutoff', 124, 'phase-cutoff')
            return self.budget

        def current(self):
            self.calls += 1
            if self.calls == self.exhaust_on_call:
                self.exhausted = True
            if self.calls == self.fail_on_call:
                self.failed.set()
            cost, value = self.outcomes.pop(0)
            self.now += cost
            if isinstance(value, BaseException):
                raise value
            return value

        def wait(self, seconds):
            self.waits.append(seconds)
            if self.wait_error is not None:
                raise self.wait_error
            self.now += seconds
            return bool(self.wait_result)

        def run(self):
            return host.recheck_registration(self.registration, self.clock, self.failed,
                                             monotonic=self.mono, wait=self.wait)

    def test_recheck_first_success_and_recovery_are_fully_fresh(self):
        fixture = self.Recheck([(1, 'rec')])
        self.assertEqual(fixture.run(), 'rec')
        self.assertEqual((fixture.calls, fixture.waits), (1, []))
        fixture = self.Recheck([(1, host.ReadUnavailable(503)), (1, host.TransientRead(None)), (1, 'rec')])
        self.assertEqual(fixture.run(), 'rec')
        self.assertEqual((fixture.calls, fixture.waits), (3, [2.0, 4.0]))

    def test_recheck_exhaustion_reraises_last_typed_error_with_attempt_count(self):
        errors = [host.ReadUnavailable(503), host.TransientRead(429), host.ReadUnavailable(None)]
        fixture = self.Recheck([(1, e) for e in errors])
        with self.assertRaises(host.ReadUnavailable) as caught:
            fixture.run()
        self.assertIs(caught.exception, errors[-1])
        self.assertEqual((caught.exception.recheck_attempts, fixture.calls, fixture.waits), (3, 3, [2.0, 4.0]))

    def test_recheck_hard_failures_and_signals_are_never_retried(self):
        for error in (guest.Failure('foreign', 1), guest.Failure('signal', 143), KeyboardInterrupt(), host.StoreError('x'),
                      host.NotFound('x'), host.ApiError(401, 'x'), host.ApiError(403, 'x'), host.Uncertain('x'),
                      host.Refused('x'), RuntimeError('x'), ValueError('x')):
            with self.subTest(error=type(error).__name__):
                fixture = self.Recheck([(1, error), (1, 'rec')])
                with self.assertRaises(type(error)) as caught:
                    fixture.run()
                self.assertIs(caught.exception, error)
                self.assertEqual((fixture.calls, fixture.waits), (1, []))

    def test_recheck_cancellation_during_pause_and_heartbeat_failure_refuse(self):
        fixture = self.Recheck([(1, host.ReadUnavailable(503)), (1, 'rec')])
        fixture.wait_error = guest.Failure('signal', 143)
        with self.assertRaises(guest.Failure) as caught:
            fixture.run()
        self.assertEqual((caught.exception.code, fixture.calls), (143, 1))
        fixture = self.Recheck([(1, host.ReadUnavailable(503)), (1, 'rec')])
        fixture.wait_result = True  # heartbeat failure ends the pause
        with self.assertRaisesRegex(guest.Failure, 'heartbeat'):
            fixture.run()
        self.assertEqual(fixture.calls, 1)
        fixture = self.Recheck([(1, host.ReadUnavailable(503)), (1, 'rec')])
        fixture.fail_on_call = 2  # heartbeat failed while the retry was in flight: late success refused
        with self.assertRaises(guest.Failure) as caught:
            fixture.run()
        self.assertEqual((caught.exception.code, fixture.calls), (1, 2))

    def test_recheck_original_work_window_is_enforced_before_and_after_each_attempt(self):
        fixture = self.Recheck([(1, host.ReadUnavailable(503)), (1, 'rec')], budget=6.0)  # < pause + minimum
        with self.assertRaises(host.ReadUnavailable) as caught:
            fixture.run()
        self.assertEqual((fixture.calls, fixture.waits, caught.exception.recheck_attempts), (1, [], 1))
        fixture = self.Recheck([(1, host.ReadUnavailable(503)), (1, 'rec')])
        fixture.exhaust_on_call = 2  # window closes during the retry: the late positive read grants nothing
        with self.assertRaises(guest.Failure) as caught:
            fixture.run()
        self.assertEqual((caught.exception.code, fixture.calls), (124, 2))
        fixture = self.Recheck([(1, host.ReadUnavailable(503)), (1, 'rec')])
        fixture.exhausted = True  # already closed after the first failure
        with self.assertRaises(guest.Failure) as caught:
            fixture.run()
        self.assertEqual(caught.exception.code, 124)
        self.assertEqual((fixture.calls, fixture.waits), (0, []))

    def test_recheck_aggregate_allowance_is_one_budget_with_no_reset_per_attempt(self):
        # One allowance starts at entry: 1 failure + 2 pause + 27 read exhausts all30s.
        fixture = self.Recheck([(1, host.ReadUnavailable(503)), (27, host.ReadUnavailable(503)), (1, 'rec')])
        with self.assertRaises(guest.Failure) as caught:
            fixture.run()
        self.assertEqual((fixture.calls, caught.exception.code), (2, 124))
        # A positive read that lands after the aggregate allowance is refused, not returned.
        fixture = self.Recheck([(1, host.ReadUnavailable(503)), (40, 'rec')])
        with self.assertRaises(guest.Failure) as caught:
            fixture.run()
        self.assertEqual((caught.exception.code, fixture.calls), (124, 2))
        # Exactly inside the allowance is accepted.
        fixture = self.Recheck([(1, host.ReadUnavailable(503)), (20, 'rec')])
        self.assertEqual(fixture.run(), 'rec')

    def test_recheck_uses_only_current_no_writes_reconnects_or_renewal(self):
        registration = Mock()
        registration.current.side_effect = [host.ReadUnavailable(503), 'rec']
        fixture = self.Recheck([])
        self.assertEqual(host.recheck_registration(registration, fixture.clock, fixture.failed,
                                                   monotonic=fixture.mono, wait=fixture.wait), 'rec')
        self.assertEqual([call[0] for call in registration.mock_calls], ['current', 'current'])

    # -- typed Compute READ outcome: HTTP facts only, never messages ---------------------------
    def read_cloud(self, responder):
        from build.gcp.lifecycle.auth_http import HttpResponse
        class Http:
            def __init__(self):
                self.calls = []
            def request(self, method, url, **kwargs):
                self.calls.append((method, url))
                result = responder()
                if isinstance(result, BaseException):
                    raise result
                return HttpResponse(*result)
        http = Http()
        outcome = host.ReadOutcome(http)
        raw = host.ComputeRestTransport(outcome, token_provider=lambda: 'dummy-token')
        return host.ReadCloud(host.PolicyCloud(raw, host.spec.PROJECT, host.spec.ZONE), outcome), http

    def test_compute_reads_type_only_transport_loss_and_documented_transient_statuses(self):
        for status in (408, 429, 500, 502, 503, 504):
            with self.subTest(status=status):
                cloud, http = self.read_cloud(lambda: (status, b'SECRET-BODY'))
                with self.assertRaises(host.TransientRead) as caught:
                    cloud.call('instances', 'get', name='fixed')
                self.assertEqual(caught.exception.status, status)
                self.assertNotIn('SECRET', str(caught.exception))
                self.assertEqual([c[0] for c in http.calls], ['GET'])  # one GET, no hidden retry
        for loss in (host.NetworkUnavailable('SECRET'),):
            cloud, http = self.read_cloud(lambda: loss)
            with self.assertRaises(host.TransientRead) as caught:
                cloud.call('zoneOperations', 'get', name='op-fixed')
            self.assertIsNone(caught.exception.status)
            self.assertEqual(len(http.calls), 1)

    def test_compute_reads_keep_auth_notfound_malformed_and_token_failures_hard(self):
        for status in (400, 401, 403, 409):
            cloud, http = self.read_cloud(lambda: (status, b'{}'))
            with self.assertRaises(host.ApiError) as caught:
                cloud.call('instances', 'get', name='fixed')
            self.assertEqual(caught.exception.status, status)
            self.assertNotIsInstance(caught.exception, host.TransientRead)
        cloud, _ = self.read_cloud(lambda: (404, b'{}'))
        with self.assertRaises(host.NotFound):
            cloud.call('instances', 'get', name='fixed')
        for reply in ((200, b'not json'), (200, b'[]'), (200, b'')):
            cloud, _ = self.read_cloud(lambda: reply)
            with self.assertRaises(host.Uncertain) as caught:
                cloud.call('disks', 'get', name='fixed')
            self.assertNotIsInstance(caught.exception, host.TransientRead)
        # Credential acquisition failure never reaches HTTP, so no transient fact exists.
        from build.gcp.lifecycle.auth_http import HttpResponse
        outcome = host.ReadOutcome(Mock(request=Mock(return_value=HttpResponse(200, b'{}'))))
        def no_token():
            raise host.TransportError('credential')
        raw = host.ComputeRestTransport(outcome, token_provider=no_token)
        cloud = host.ReadCloud(host.PolicyCloud(raw, host.spec.PROJECT, host.spec.ZONE), outcome)
        with self.assertRaises(host.Uncertain) as caught:
            cloud.call('instances', 'get', name='fixed')
        self.assertNotIsInstance(caught.exception, host.TransientRead)
        outcome.http.request.assert_not_called()

    def test_stale_transient_fact_cannot_type_a_later_untyped_failure(self):
        calls = iter([(503, b''), (200, b'not json')])
        cloud, _ = self.read_cloud(lambda: next(calls))
        with self.assertRaises(host.TransientRead):
            cloud.call('instances', 'get', name='fixed')
        with self.assertRaises(host.Uncertain) as caught:
            cloud.call('instances', 'get', name='fixed')
        self.assertNotIsInstance(caught.exception, host.TransientRead)

    def test_first_attempt_obeys_original_clock_heartbeat_and_aggregate_end(self):
        for kind in ('expired', 'heartbeat', 'late', 'expires-during'):
            with self.subTest(kind=kind):
                f = self.Recheck([(31 if kind == 'late' else 1, 'rec')])
                if kind == 'expired': f.exhausted = True
                if kind == 'heartbeat': f.failed.set()
                if kind == 'expires-during': f.exhaust_on_call = 1
                with self.assertRaises(guest.Failure) as caught: f.run()
                self.assertEqual(f.calls, 0 if kind in ('expired', 'heartbeat') else 1)
                self.assertEqual(caught.exception.code, 1 if kind == 'heartbeat' else 124)

    def test_actual_owner_signals_cross_real_http_and_token_adapters_without_retry(self):
        from build.gcp.lifecycle.auth_http import HttpTransport, gcloud_token
        from build.gcp.lifecycle.gcs import GcsSlotStore
        for number, code in ((signal.SIGTERM, 143), (signal.SIGINT, 130)):
            previous = signal.signal(number, host.interrupted)
            try:
                for where in ('http', 'token'):
                    for service in ('compute', 'gcs'):
                        with self.subTest(number=number, where=where, service=service):
                            def send(*args, **kwargs):
                                os.kill(os.getpid(), number)
                                raise AssertionError('signal was swallowed')
                            def token():
                                if where == 'token':
                                    with patch('build.gcp.lifecycle.auth_http.subprocess.run', side_effect=send):
                                        return gcloud_token()
                                return 'public-test-token'
                            outcome = host.ReadOutcome(HttpTransport(opener=Mock(open=Mock(side_effect=send))))
                            cloud = host.ReadCloud(host.PolicyCloud(host.ComputeRestTransport(outcome, token_provider=token),
                                                                    host.spec.PROJECT, host.spec.ZONE), outcome)
                            store = GcsSlotStore('public-test-bucket', transport=outcome.http, token_provider=token)
                            fn = (lambda: cloud.call('instances', 'get', name='fixed')) if service == 'compute' else (lambda: store.read('slots/slot-1.json'))
                            registration = SimpleNamespace(current=Mock(side_effect=fn))
                            f = self.Recheck([])
                            with self.assertRaises(host.HostCancelled) as caught:
                                host.recheck_registration(registration, f.clock, f.failed, monotonic=f.mono, wait=f.wait)
                            self.assertEqual(caught.exception.code, code)
                            self.assertEqual(registration.current.call_count, 1)
                            self.assertEqual(f.waits, [])
            finally:
                signal.signal(number, previous)

    def test_host_cancellation_keeps_primary_closed_record_and_cleanup(self):
        for number, code in ((signal.SIGTERM, 143), (signal.SIGINT, 130)):
            with self.subTest(number=number):
                private, (actual, receipt, trace, text) = self.host_drive([host.HostCancelled(number)])
                self.assertEqual((actual, receipt['code'], receipt['failure_category']), (code, code, 'interrupted'))
                record = json.loads(self.host_record_path(private).read_bytes())
                self.assertEqual((record['exception'], record['code'], record['http_status']), ('interrupted', code, None))
                self.assertEqual(set(receipt), self.RECEIPT_KEYS)
                for step in ('stop', 'master-close', 'remove-key', 'dispatch-cleanup'):
                    self.assertIn(step, trace)
            self.setUp()

    def test_actual_main_entrypoint_keeps_cancellation_before_trial(self):
        import ast
        tree = ast.parse(Path(host.__file__).read_bytes())
        entry = next(n for n in tree.body if isinstance(n, ast.If)
                     and isinstance(n.test, ast.Compare) and isinstance(n.test.left, ast.Name)
                     and n.test.left.id == '__name__')
        for number, code in ((signal.SIGTERM, 143), (signal.SIGINT, 130)):
            previous = {n: signal.getsignal(n) for n in (signal.SIGTERM, signal.SIGINT)}
            scope = dict(vars(host))
            def before_trial():
                os.kill(os.getpid(), number)
                raise AssertionError('cancellation was swallowed')
            scope.update(__name__='__main__', main=before_trial)
            try:
                with patch.object(sys, 'stderr', io.StringIO()), self.assertRaises(SystemExit) as caught:
                    exec(compile(ast.Module(body=[entry], type_ignores=[]), host.__file__, 'exec'), scope)
                self.assertEqual(caught.exception.code, code)
            finally:
                for n, handler in previous.items(): signal.signal(n, handler)

    def test_transient_types_cannot_launder_permanent_or_invalid_statuses(self):
        for kind in (host.TransientRead, host.ReadUnavailable):
            for status in (True, False, '503', 0, 200, 401, 403, 404, 499, 600):
                with self.subTest(kind=kind.__name__, status=status):
                    with self.assertRaises(ValueError): kind(status)

    def test_closed_host_record_retains_genuine_hard_gcs_status_without_retry(self):
        private, (code, receipt, trace, text) = self.host_drive([host.StoreError('fixed client message', status=403)])
        self.assertEqual((code, receipt['failure_category']), (1, 'unknown'))
        self.assertEqual(self.registration_reads, ['read'])
        record = json.loads(self.host_record_path(private).read_bytes())
        self.assertEqual((record['exception'], record['http_status']), ('store-error', 403))

    def test_compute_unknown_http_exception_remains_hard(self):
        for error in (OSError('unknown'), RuntimeError('unknown'), host.TransportError('bounds')):
            cloud, http = self.read_cloud(lambda: error)
            with self.assertRaises(host.Uncertain) as caught:
                cloud.call('instances', 'get', name='fixed')
            self.assertNotIsInstance(caught.exception, host.TransientRead)
            self.assertEqual(len(http.calls), 1)

    def test_host_record_rejects_ancestor_link_and_changed_directory_before_write(self):
        initial = {'source_sha': 'a'*40, 'nonce': 'd'*32, 'lease': snapshot()['request_id'], 'epoch': 1, 'run_id': 123, 'attempt': 1}
        record = host.host_failure_record(initial, 'guest-work', 'registration-check', 'unknown', 1, RuntimeError())
        parent = self.directory/'real'; parent.mkdir(mode=0o700)
        private = parent/'private'; private.mkdir(mode=0o700)
        alias = self.directory/'alias'; alias.symlink_to(parent, target_is_directory=True)
        with self.assertRaises(guest.Failure): host.retain_host_failure(alias/'private', record)
        self.assertEqual(list(private.iterdir()), [])
        actual_open = os.open
        moved = parent/'moved'
        def replace_after_open(path, flags, *args, **kwargs):
            fd = actual_open(path, flags, *args, **kwargs)
            if Path(path) == private and flags & os.O_DIRECTORY:
                private.rename(moved); private.mkdir(mode=0o700)
            return fd
        with patch.object(host.os, 'open', side_effect=replace_after_open):
            with self.assertRaises(guest.Failure): host.retain_host_failure(private, record)
        self.assertEqual(list(private.iterdir()), [])
        self.assertEqual(list(moved.iterdir()), [])

    def test_partial_host_record_is_preserved_after_write_failure(self):
        initial = {'source_sha': 'a'*40, 'nonce': 'd'*32, 'lease': snapshot()['request_id'], 'epoch': 1, 'run_id': 123, 'attempt': 1}
        record = host.host_failure_record(initial, 'guest-work', 'registration-check', 'unknown', 1, RuntimeError())
        private = self.directory/'private'; private.mkdir(mode=0o700)
        real_fdopen = os.fdopen
        class Partial:
            def __init__(self, fd, *args, **kwargs): self.stream = real_fdopen(fd, *args, **kwargs)
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def write(self, raw):
                self.stream.write(raw[:17]); self.stream.flush()
                raise OSError('synthetic write failure')
        with patch.object(host.os, 'fdopen', Partial):
            with self.assertRaises(OSError): host.retain_host_failure(private, record)
        target = self.host_record_path(private)
        self.assertEqual(target.read_bytes(), guest.encoded(record)[:17])
        with self.assertRaises(FileExistsError): host.retain_host_failure(private, record)
        self.assertEqual(target.read_bytes(), guest.encoded(record)[:17])

    def test_read_surface_still_refuses_mutating_verbs_with_outcome_wrapper(self):
        cloud, http = self.read_cloud(lambda: (200, b'{}'))
        for resource, verb in (('instances', 'insert'), ('instances', 'delete'), ('images', 'insert')):
            with self.assertRaises(host.ForbiddenOperation):
                cloud.call(resource, verb)
        self.assertEqual(http.calls, [])

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
        files = list(self.kept(private))
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
                self.assertEqual(list(self.kept(private)), [])
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
                self.assertEqual(next(self.kept(private)).read_bytes(), self.export_bytes(bundle))

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
        self.assertEqual((receipt['private_diagnostic'], list(self.kept(private))), ('absent', []))

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
        self.assertEqual(next(self.kept(private)).read_bytes(), resume)
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
                self.assertEqual(len(list(self.kept(private))), 1 if expected == 'captured' else 0)

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
        self.assertEqual(list(self.kept(private)), [])
        for primary in (b'absent', b'invalid'):
            with self.subTest(primary=primary):
                self.setUp()
                private = self.private_dir()
                # An invalid primary record is consumed before failure; observe_guest does
                # not replace invalid status, and it cannot authorize resume either.
                code, receipt, _, _ = self.drive([primary], fail_bootstrap=(primary == b'absent'),
                                                private=private, export=resume)
                self.assertEqual(receipt['private_diagnostic'], 'invalid')
                self.assertEqual(list(self.kept(private)), [])

    def test_resume_query_cleanup_uncertainty_retains_bytes_and_primary_result(self):
        resume = self.export_bytes(self.failure_bundle(mode='resume', query_cleanup='uncertain'), mode='resume')
        private, (code, receipt, trace, _) = self.resume_drive(resume)
        self.assertEqual((code, receipt['private_diagnostic'], receipt['contained']), (17, 'invalid', True))
        self.assertEqual(next(self.kept(private)).read_bytes(), resume)
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
                self.assertEqual(list(self.kept(private)), [])
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
        self.assertEqual(len(list(self.kept(private))), 1)  # retained, but never labelled captured
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
                self.assertEqual(list(self.kept(private)), [])
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
                kept = list(self.kept(private))
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
        kept = list(self.kept(private))
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
        self.assertEqual([f.name for f in self.kept(private)], ['installer-failure-' + snapshot()['request_id'] + '.bin'])
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
                kept = list(self.kept(private))
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
        self.assertEqual([f.name for f in self.kept(private)], ['installer-failure-' + snapshot()['request_id'] + '.bin'])
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
                self.assertEqual(len(list(self.kept(private))), 1 if expected == 'captured' else 0)

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
                self.assertEqual(list(self.kept(private)), [])
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
        self.assertEqual(list(self.kept(private)), [])
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


# ---------------------------------------------------------------------------------------------
# Manual private-image clone caller (#546). Synthetic HTTP/clock/files/processes only: the real
# orchestration, cleaner and watchdog code run against an in-memory Compute/OS Login/guest world.
# Authored without execution in a credential-bearing job; the lead runs these in isolated Docker.
import hashlib
import shlex
import shutil
import struct
import urllib.parse
from dataclasses import replace
from uuid import uuid4

from build.gcp import private_clone as clone
from build.gcp.lifecycle.access_records import canonical as clone_canonical
from build.gcp.lifecycle.auth_http import HttpResponse, TransportError

CLONE_P = 'https://www.googleapis.com/compute/v1/projects/' + clone.PROJECT + '/'


def clone_wire(seed):
    raw = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + hashlib.sha256(seed).digest()
    return 'ssh-ed25519 ' + base64.b64encode(raw).decode()


class CloneWorld:
    """In-memory Compute v1, OS Login, guest and clock. Records every mutation attempt."""
    BUILD = '00000000-0000-4000-8000-00000000000b'
    NONCE = 'a' * 32
    SEALED = ('c' * 32, 'd' * 32)

    def __init__(self):
        self.t = 1_800_000_000.0
        self.tmp = tempfile.mkdtemp(prefix='cl', dir='/tmp')
        os.chmod(self.tmp, 0o700)
        self.proc = tempfile.mkdtemp(prefix='cp', dir='/tmp')
        self.image = {'name': clone.IMAGE_NAME, 'id': clone.IMAGE_ID, 'status': 'READY',
                      'sourceDiskId': clone.SOURCE_DISK_ID}
        self.vms, self.disks, self.ops, self.keys = {}, {}, {}, {}
        self.mutations, self.events, self.imported, self.failing = [], [], [], {}
        self.watchdog, self.sha = True, None
        self.n = self.boot_n = self.polls = self.keygen = 0
        self.mode = 'off'
        self.mutate_summary = self.on_token = self.on_hostkey = self.after_import = self.cancel_on = None
        self.close_ok, self.stop_fails, self.master_fails = True, False, False
        # independent wall / monotonic offsets (a wall rollback or mono-only delay moves only one clock)
        self.wall_offset = self.mono_offset = 0.0
        self.cgroups = tempfile.mkdtemp(prefix='cg', dir='/tmp')
        self.manifest = self.owner = self.watch = None
        self.owner_state = self.watch_state = None
        self.unit_override, self.stop_ineffective, self.after_stop = {}, False, None
        self.pin_status = self.op_hook = self.next_page = None
        self.after_mutation, self.timeline = {}, []

    # clock
    def wall(self):
        return self.t + self.wall_offset

    def mono(self):
        return self.t - 1_800_000_000.0 + self.mono_offset

    # systemd (typed property fake for the exact owner and watch services)
    RUNNING_FIELDS = {'ActiveState': 'active', 'SubState': 'running'}
    INACTIVE_FIELDS = {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0', 'ControlGroup': ''}

    def bind_units(self, manifest):
        self.manifest, self.owner, self.watch = manifest, clone.owner_unit(manifest), clone.watch_unit(manifest)
        self.owner_state = dict(self.RUNNING_FIELDS, MainPID=str(os.getpid()),
                                ControlGroup='/system.slice/' + self.owner)
        self.watch_state = dict(self.RUNNING_FIELDS, MainPID='4321', ControlGroup='/system.slice/' + self.watch)

    def exec_line(self, argv, path=None):
        return ('{ path=' + (path or argv[0]) + ' ; argv[]=' + ' '.join(argv) +
                ' ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }')

    def unit_props(self, unit):
        role = 'owner' if unit == self.owner else 'watch'
        argv = clone.unit_argv(self.manifest, self.tmp, self.sha, 'run' if role == 'owner' else 'watch')
        props = {'Id': unit, 'LoadState': 'loaded', 'Type': 'simple', 'User': 'ubuntu',
                 'WorkingDirectory': clone.PROTECTED_SOURCE, 'Restart': 'no', 'RemainAfterExit': 'no',
                 'KillMode': 'mixed' if role == 'owner' else 'control-group', 'SendSIGKILL': 'yes',
                 'TimeoutStopUSec': '30s' if role == 'owner' else '1min 30s', 'InvocationID': 'a' * 32,
                 'ExecStartPre': '', 'ExecStartPost': '', 'ExecStop': '', 'ExecStopPost': '', 'ExecReload': '',
                 'ExecStart': self.exec_line(argv)}
        props.update(self.owner_state if role == 'owner' else self.watch_state)
        props.update(self.unit_override.get(role, {}))
        return props

    def cgroup_procs(self, pids):
        path = Path(self.cgroups, 'system.slice', self.owner)
        path.mkdir(parents=True, exist_ok=True)
        (path / 'cgroup.procs').write_text(''.join(f'{p}\n' for p in pids))

    def systemctl(self, argv):
        if argv[1] == 'stop':
            assert argv[2] == self.owner, argv
            self.events.append('systemctl-stop')
            self.timeline.append('systemctl-stop')
            if not self.stop_ineffective:
                self.owner_state = dict(self.INACTIVE_FIELDS)
            if self.after_stop:
                self.after_stop()
            return b''
        assert argv[1] == 'show' and argv[2] in (self.owner, self.watch), argv
        props = self.unit_props(argv[2])
        return ''.join(f'{argv[i + 1]}={props[argv[i + 1]]}\n' for i, a in enumerate(argv) if a == '-p').encode()

    def sleep(self, seconds):
        self.t += seconds

    def token(self):
        if self.on_token:
            self.on_token()
        return 'tok'

    # fault injection: mode 'drop' (not applied, no response), 'lost' (applied, no response) or HTTP status
    def inject(self, kind, mode, skip=0):
        self.failing[kind] = (skip, mode)

    def mutate(self, kind, apply):
        self.mutations.append(kind)
        self.timeline.append(kind)
        mode = None
        if kind in self.failing:
            skip, mode = self.failing[kind]
            if skip:
                self.failing[kind], mode = (skip - 1, mode), None
            else:
                del self.failing[kind]
        if mode == 'drop':
            raise TransportError('synthetic')
        if isinstance(mode, int):
            return mode, {}
        value = apply()
        if kind in self.after_mutation:
            self.after_mutation[kind]()
        if mode == 'lost':
            raise TransportError('synthetic')
        return 200, value

    # HTTP router
    def request(self, method, url, *, headers, body=None, timeout=20, max_bytes=0):
        parts = urllib.parse.urlsplit(url)
        path = urllib.parse.unquote(parts.path)
        if parts.hostname == 'oslogin.googleapis.com':
            status, value = self.oslogin(method, path, body)
        else:
            status, value = self.compute(method, path, urllib.parse.parse_qs(parts.query), body)
        return HttpResponse(status, json.dumps(value).encode())

    def profile(self):
        return {'name': 'users/110405050082684214272',
                'posixAccounts': [{'operatingSystemType': 'LINUX', 'systemId': '', 'username': 'art_githedgehog_com',
                                   'uid': '2000', 'gid': '2000', 'homeDirectory': '/home/art_githedgehog_com'}],
                'sshPublicKeys': {fp: dict(entry) for fp, entry in self.keys.items()}}

    def add_key(self, seed, expiry='0'):
        wire = clone_wire(seed)
        fp = hashlib.sha256(wire.encode()).hexdigest()[:40]
        self.keys[fp] = {'key': wire, 'expirationTimeUsec': expiry, 'fingerprint': fp,
                         'name': 'users/110405050082684214272/sshPublicKeys/' + fp}
        return wire, fp

    def oslogin(self, method, path, body):
        base = '/v1/users/art@githedgehog.com'
        assert path.startswith(base), path
        tail = path[len(base):]
        if tail == '/loginProfile' and method == 'GET':
            return 200, self.profile()
        if tail == ':importSshPublicKey' and method == 'POST':
            return self.mutate('import', lambda: self.do_import(json.loads(body)))
        assert tail.startswith('/sshPublicKeys/') and method == 'DELETE', (method, path)
        fp = tail.rsplit('/', 1)[1]
        return self.mutate('delete-key', lambda: (self.keys.pop(fp, None), {})[1])

    def do_import(self, data):
        wire = data['key']
        fp = hashlib.sha256(wire.encode()).hexdigest()[:40]
        self.keys[fp] = {'key': wire, 'expirationTimeUsec': data['expirationTimeUsec'], 'fingerprint': fp,
                         'name': 'users/110405050082684214272/sshPublicKeys/' + fp}
        self.imported.append(wire)
        if self.after_import:
            self.after_import()
        return {'loginProfile': self.profile()}

    def compute(self, method, path, query, body):
        prefix = '/compute/v1/projects/' + clone.PROJECT + '/'
        assert path.startswith(prefix), path
        rest = path[len(prefix):].split('/')
        if rest[:2] == ['global', 'images']:
            return 200, self.image
        assert rest[:2] == ['zones', clone.ZONE], path
        kind, tail = rest[2], rest[3:]
        request = query.get('requestId', [None])[0]
        if kind == 'instances':
            if not tail:
                return self.mutate('insert', lambda: self.insert(json.loads(body), request))
            name = tail[0]
            if len(tail) == 2 and tail[1] == 'reset':
                return self.mutate('reset', lambda: self.reset(name, request))
            if method == 'DELETE':
                return self.mutate('delete-vm', lambda: self.delete_vm(name, request))
            return (200, self.vms[name]) if name in self.vms else (404, {})
        if kind == 'disks':
            name = tail[0]
            if method == 'DELETE':
                return self.mutate('delete-disk', lambda: self.delete_disk(name, request))
            return (200, self.disks[name]) if name in self.disks else (404, {})
        assert kind == 'operations', path
        if not tail:
            wanted = query['filter'][0]
            items = [dict(o, status=self.pin_status or 'DONE') for o in self.ops.values()
                     if o['clientOperationId'] in wanted]
            if not self.pin_status:
                for o in self.ops.values():
                    o['status'] = 'DONE'
            page = {'items': items} if items else {}
            if self.next_page:
                page['nextPageToken'] = 'more'
            return 200, page
        op = self.ops.get(tail[0])
        if op is None:
            return 404, {}
        snapshot = dict(op)
        if self.pin_status:
            snapshot['status'] = self.pin_status
        else:
            op['status'] = 'DONE'
        if self.op_hook:
            snapshot = self.op_hook(snapshot)
        return 200, snapshot

    def op(self, kind, collection, name, target_id, request):
        self.n += 1
        op = {'name': f'op-{self.n}', 'id': str(9000 + self.n), 'kind': 'compute#operation',
              'operationType': kind, 'clientOperationId': request,
              'user': clone.OWNER, 'targetLink': CLONE_P + f'zones/{clone.ZONE}/{collection}/{name}',
              'targetId': target_id, 'status': 'RUNNING', 'zone': CLONE_P + 'zones/' + clone.ZONE}
        self.ops[op['name']] = op
        return dict(op)

    def make_disk(self, body):
        self.n += 1
        init = body['disks'][0]['initializeParams']
        disk = {'id': str(5000 + self.n), 'name': body['name'], 'status': 'READY', 'sizeGb': '500',
                'type': CLONE_P + f'zones/{clone.ZONE}/diskTypes/pd-balanced', 'sourceImageId': clone.IMAGE_ID,
                'sourceImage': CLONE_P + 'global/images/' + clone.IMAGE_NAME, 'labels': dict(init['labels'])}
        self.disks[body['name']] = disk
        return disk

    def insert(self, body, request):
        name = body['name']
        self.n += 1
        vm = {'id': str(1000 + self.n), 'name': name, 'status': 'RUNNING', 'labels': body['labels'],
              'machineType': CLONE_P + body['machineType'], 'minCpuPlatform': body['minCpuPlatform'],
              'advancedMachineFeatures': body['advancedMachineFeatures'], 'canIpForward': False,
              'deletionProtection': False, 'scheduling': dict(body['scheduling']),
              'networkInterfaces': [{'subnetwork': CLONE_P + body['networkInterfaces'][0]['subnetwork']}],
              'metadata': {'items': body['metadata']['items']},
              'disks': [{'boot': True, 'autoDelete': True, 'mode': 'READ_WRITE',
                         'source': CLONE_P + f'zones/{clone.ZONE}/disks/{name}'}]}
        self.vms[name] = vm
        self.make_disk(body)
        self.new_boot()
        return self.op('insert', 'instances', name, vm['id'], request)

    def reset(self, name, request):
        self.events.append('reset')
        self.new_boot()
        return self.op('reset', 'instances', name, self.vms[name]['id'], request)

    def delete_vm(self, name, request):
        vm = self.vms.pop(name)
        self.disks.pop(name, None)
        return self.op('delete', 'instances', name, vm['id'], request)

    def delete_disk(self, name, request):
        disk = self.disks.pop(name)
        return self.op('delete', 'disks', name, disk['id'], request)

    # guest
    def boot_id(self, n=None):
        n = self.boot_n if n is None else n
        return '%08x-0000-4000-8000-%012x' % (0x10000000 + n, n)

    def new_boot(self):
        self.boot_n += 1
        self.polls, self.mode = 2, 'starting'

    def stop(self):
        self.mode = 'stopped'

    def summary(self):
        n, boot = self.boot_n, self.boot_id()
        op, inv = '%032x' % n, '%032x' % (n + 0x100)
        if self.mode == 'starting':
            if self.polls <= 0:
                self.mode = 'ready'
            else:
                self.polls -= 1
        unit = {'ActiveState': 'active', 'InvocationID': 'x', 'Result': 'success'}
        clone_unit, resume = dict(unit), dict(unit, InvocationID=inv)
        phase, stop_verified = 'ready', None
        checkpoint = {'boot': boot, 'operation': op, 'invocation': inv}
        if self.mode == 'starting':
            phase = 'resumable'
            clone_unit['ActiveState'], resume['ActiveState'] = 'activating', 'inactive'
            checkpoint = None if n == 1 else {'boot': self.boot_id(n - 1), 'operation': '%032x' % (n - 1),
                                              'invocation': '%032x' % (n + 0xff)}
        elif self.mode == 'stopped':
            phase, stop_verified = 'resumable', {'operation': op, 'invocation': inv}
            clone_unit['ActiveState'] = resume['ActiveState'] = 'inactive'
        out = {'boot': boot, 'checkpoint': checkpoint, 'clone': clone_unit, 'resume': resume,
               'seal': {'state': 'sealed', 'owned_sealed': True, 'nonce': self.NONCE, 'build_boot': self.BUILD,
                        'core_operation': self.SEALED[0], 'core_invocation': self.SEALED[1]},
               'core': {'nonce': self.NONCE, 'phase': phase, 'mode': 'resume', 'boot': boot, 'operation': op,
                        'invocation': inv, 'stop_verified': stop_verified, 'critical_sha256': 'e' * 64,
                        'cluster_sha256': 'f' * 64}}
        if self.mutate_summary:
            self.mutate_summary(out, self)
        return out

    # processes
    def runner(self, argv, seconds, **kwargs):
        if self.cancel_on and self.cancel_on in argv:
            raise host.HostCancelled(signal.SIGTERM)
        if argv[0] == '/usr/bin/ssh-keygen' and '-t' in argv:
            path = Path(argv[argv.index('-f') + 1])
            self.keygen += 1
            path.write_text('PRIVATE-KEY-FIXTURE')
            path.chmod(0o600)
            path.with_name(path.name + '.pub').write_text(clone_wire(b'generated%d' % self.keygen) + ' fixture\n')
            return b''
        if argv[0] == '/usr/bin/ssh-keygen':
            return b'256 SHA256:fixture\n'
        if argv[:3] == ['gcloud', 'auth', 'list']:
            return (clone.OWNER + '\n').encode()
        if argv[:3] == ['gcloud', 'config', 'get-value']:
            return b'(unset)\n'
        if 'get-guest-attributes' in argv:
            if self.on_hostkey:
                self.on_hostkey()
            value = base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + b'h' * 32).decode()
            return json.dumps([{'namespace': 'hostkeys', 'key': 'ssh-ed25519', 'value': value}]).encode()
        assert argv[0] == '/usr/bin/systemctl', argv
        if not self.watchdog:
            self.watch_state = dict(self.INACTIVE_FIELDS)
        return self.systemctl(argv)


class CloneFakeMaster:
    def __init__(self, world, directory, name, vm_id, username, deps, record=None):
        self.world, self.dir, self.record = world, Path(directory), record

    def start(self, window):
        self.world.events.append('master-start')
        if self.world.master_fails:
            raise clone.Expired('synthetic master failure')
        window.remaining()
        (self.dir / 'master.sock').write_text('socket-fixture')
        if self.record:
            self.record(999999)

    def remote(self, key, window, cap=30):
        window.remaining()
        self.world.events.append(key)
        if key == 'summary':
            return clone_canonical(self.world.summary())
        if self.world.stop_fails:
            raise guest.Failure('stop refused', 17)
        self.world.stop()
        return clone.STOP_MARKER + b'\n'

    def close(self):
        self.world.events.append('master-close')
        return self.world.close_ok


class CloneCase(unittest.TestCase):
    def setUp(self):
        self.world = CloneWorld()
        self.addCleanup(shutil.rmtree, self.world.tmp, True)
        self.addCleanup(shutil.rmtree, self.world.proc, True)
        self.addCleanup(shutil.rmtree, self.world.cgroups, True)
        world = self.world
        self.deps = clone.Deps(world, world.token, world.runner, wall=world.wall, mono=world.mono, sleep=world.sleep,
                               master_factory=lambda *a, **k: CloneFakeMaster(world, *a, **k),
                               proc_root=world.proc, cgroup_root=world.cgroups, env={})
        info = clone.arm(world.tmp, self.deps)
        self.info = info
        self.sha, self.unit, world.sha = info['manifest_sha256'], info['watchdog_unit'], info['manifest_sha256']
        self.manifest = clone.load_manifest(world.tmp, self.sha)
        world.bind_units(self.manifest)
        self.store = clone.Store(world.tmp)

    def fresh_world(self):
        """Re-arm a new world/workdir between sub-cases."""
        shutil.rmtree(self.world.tmp, True)
        shutil.rmtree(self.world.proc, True)
        shutil.rmtree(self.world.cgroups, True)
        self.setUp()

    def units(self):
        return clone.Units(self.world.tmp, self.sha, self.manifest, self.deps)

    def independent(self):
        """The cleanup/watch disposal path: owner is quiesced first."""
        return clone.Cleaner(self.store, self.manifest, self.deps, units=self.units())

    def execute(self):
        return clone.Run(self.world.tmp, self.manifest, self.sha, self.deps, self.unit).execute()

    def cleaner(self):
        return clone.Cleaner(self.store, self.manifest, self.deps)

    def count(self, kind):
        return self.world.mutations.count(kind)

    def assert_disposed(self, result):
        self.assertTrue(result['cleanup']['closed'], result)
        self.assertEqual((self.world.vms, self.world.disks), ({}, {}))
        self.assertFalse((Path(self.world.tmp) / 'b1').exists() or (Path(self.world.tmp) / 'b2').exists())


class PrivateCloneContracts(CloneCase):
    def test_arm_manifest_and_deadlines(self):
        m = self.manifest
        admitted = clone.stamp(m['admitted_at'])
        self.assertEqual(clone.stamp(m['work_deadline']) - admitted, 45 * 60)
        self.assertEqual(clone.stamp(m['termination']) - admitted, 60 * 60)
        self.assertGreaterEqual(clone.stamp(m['termination']) - clone.stamp(m['work_deadline']), 15 * 60)
        self.assertRegex(m['name'], r'labapp-clone-[0-9a-f]{12}\Z')
        self.assertEqual(self.unit, 'labapp-clone-watch-' + m['name'][-12:] + '.service')
        for field, value in (('image_id', '1'), ('source_disk_id', '2'), ('zone', 'us-east1-b'),
                             ('termination', clone.iso(clone.stamp(m['termination']) + 60)),
                             ('name', 'labapp-clone-000000000000')):
            with self.subTest(field), self.assertRaises(clone.Refused):
                clone.check_manifest(dict(m, **{field: value}))
        with self.assertRaises(clone.Refused):
            clone.load_manifest(self.world.tmp, '0' * 64)

    def test_body_is_the_closed_envelope(self):
        body = clone.build_body(self.manifest)
        self.assertEqual(body['machineType'], 'zones/us-central1-a/machineTypes/n2-standard-32')
        self.assertEqual(body['scheduling'], {'provisioningModel': 'STANDARD', 'onHostMaintenance': 'TERMINATE',
                                              'automaticRestart': False, 'terminationTime': self.manifest['termination'],
                                              'instanceTerminationAction': 'DELETE'})
        self.assertEqual((body['serviceAccounts'], body['canIpForward'], body['deletionProtection']), ([], False, False))
        self.assertEqual(body['minCpuPlatform'], 'Intel Cascade Lake')
        self.assertTrue(body['advancedMachineFeatures']['enableNestedVirtualization'])
        self.assertNotIn('accessConfigs', body['networkInterfaces'][0])
        (disk,) = body['disks']
        self.assertEqual((disk['boot'], disk['autoDelete'], disk['initializeParams']['diskSizeGb']), (True, True, '500'))
        self.assertTrue(disk['initializeParams']['diskType'].endswith('/pd-balanced'))
        self.assertEqual(disk['initializeParams']['sourceImage'],
                         'projects/teched-473722/global/images/labapp-private-r42446688327-a1')
        self.assertFalse({'labapp-lease', 'labapp-owner', 'labapp-run'} & set(body['labels']))
        self.assertNotIn('startup-script', {i['key'] for i in body['metadata']['items']})

    def test_insert_refuses_any_altered_body_before_http(self):
        cloud = clone.CloneCompute(self.world, self.world.token)
        for change in ({'serviceAccounts': [{'email': 'x'}]}, {'canIpForward': True},
                       {'machineType': 'zones/us-central1-a/machineTypes/n2-standard-64'}):
            with self.subTest(change), self.assertRaises(clone.Refused):
                cloud.insert(self.manifest, dict(clone.build_body(self.manifest), **change),
                             self.manifest['request_id'], lambda: None)
        self.assertEqual(self.world.mutations, [])

    def test_operation_identity_is_fully_checked(self):
        name, request = self.manifest['name'], self.manifest['request_id']
        good = {'name': 'op-1', 'operationType': 'insert', 'clientOperationId': request, 'user': clone.OWNER,
                'targetLink': CLONE_P + f'zones/{clone.ZONE}/instances/{name}', 'targetId': '7', 'status': 'DONE'}
        args = dict(kind='insert', collection='instances', name=name, request_id=request, target_id='7', done=True)
        self.assertIs(clone.check_operation(good, **args), good)
        for field, value in (('operationType', 'delete'), ('clientOperationId', str(uuid4())), ('user', 'x@example.com'),
                             ('targetLink', CLONE_P + f'zones/{clone.ZONE}/instances/labapp-clone-ffffffffffff'),
                             ('targetId', '8'), ('error', {'errors': [{'code': 'X'}]}), ('status', 'RUNNING')):
            with self.subTest(field), self.assertRaises(clone.Mismatch):
                clone.check_operation(dict(good, **{field: value}), **args)

    def test_summary_schema_is_closed_and_readiness_phases(self):
        world = self.world
        world.new_boot()
        raw = clone_canonical(world.summary())
        self.assertEqual(clone.readiness(clone.parse_summary(raw)), 'pending')
        for _ in range(3):
            summary = clone.parse_summary(clone_canonical(world.summary()))
        self.assertEqual(clone.readiness(summary), 'ready')
        extra = json.loads(raw)
        extra['config'] = {'secret': 'x'}
        nested = json.loads(raw)
        nested['core']['config'] = 'x'
        for hostile in (clone_canonical(extra), clone_canonical(nested),
                        raw.replace(b'"boot"', b'"boot":"x","boot"', 1), b'x' * 5000, b'[]'):
            with self.subTest(hostile[:30]), self.assertRaises(clone.Refused):
                clone.parse_summary(hostile)

    def test_master_commands_are_fixed_and_isolated(self):
        master = clone.CloneMaster(Path('/tmp/x'), 'labapp-clone-aaaaaaaaaaaa', '123', 'art_githedgehog_com', self.deps)
        for option in ('IdentityAgent=none', 'StrictHostKeyChecking=yes', 'GlobalKnownHostsFile=/dev/null',
                       'PasswordAuthentication=no', 'IdentitiesOnly=yes'):
            self.assertIn(option, master.options)
        self.assertIn('-M', master.start_argv())
        self.assertIn('start-iap-tunnel labapp-clone-aaaaaaaaaaaa 22', ' '.join(master.start_argv()))
        for argv in (master.check_argv(), master.remote_argv('summary'), master.remote_argv('stop-verified')):
            self.assertIn('ProxyCommand=/usr/bin/false', argv)
        self.assertIn('ControlMaster=no', master.remote_argv('summary'))
        self.assertIn('/usr/local/lib/labapp/vlab_image.py stop-verified', master.remote_argv('stop-verified')[-1])
        with self.assertRaises(KeyError):
            master.remote_argv('/bin/sh')

    def test_cli_arm_and_fresh_run_guard(self):
        fresh = tempfile.mkdtemp(prefix='cl', dir='/tmp')
        self.addCleanup(shutil.rmtree, fresh, True)
        os.chmod(fresh, 0o700)
        with patch('builtins.print') as output:
            self.assertEqual(clone.main(['arm', '--workdir', fresh], self.deps), 0)
        info = json.loads(output.call_args.args[0])
        self.assertEqual(info['watchdog_exec_start'][-2:], ['--manifest-sha256', info['manifest_sha256']])
        self.assertEqual(info['watchdog_exec_start'][5:7], ['watch', '--workdir'])
        self.store.create('run', {'pid': 1})
        with patch('builtins.print'), patch('signal.signal'):
            self.assertEqual(clone.main(['run', '--workdir', self.world.tmp, '--manifest-sha256', self.sha,
                                         '--owner-unit', self.world.owner, '--watchdog-unit', self.unit],
                                        self.deps), 2)
        self.assertEqual(self.world.mutations, [])


class PrivateCloneOrchestration(CloneCase):
    def test_happy_two_boot_run_and_exact_disposal(self):
        code, result = self.execute()
        self.assertEqual((code, result['status']), (0, 'passed'), result)
        self.assertEqual(self.world.mutations,
                         ['insert', 'import', 'delete-key', 'reset', 'import', 'delete-key', 'delete-vm'])
        events = self.world.events
        self.assertLess(events.index('stop-verified'), events.index('master-close'))
        self.assertLess(events.index('master-close'), events.index('reset'))
        self.assertEqual(events.count('stop-verified'), 2)
        first, second = result['boots']
        self.assertNotEqual(first['boot'], second['boot'])
        self.assertEqual((first['nonce'], first['critical']), (second['nonce'], second['critical']))
        self.assertEqual(len(set(self.world.imported)), 2)
        self.assertEqual(self.world.keys, {})
        self.assert_disposed(result)
        self.assertTrue(self.store.has('closed'))
        # A later pass finds everything absent and replays no delete.
        self.assertTrue(self.cleaner().run()['closed'])
        self.assertEqual(self.count('delete-vm'), 1)

    def test_missing_watchdog_refuses_before_any_cloud_mutation(self):
        self.world.watchdog = False
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Refused'))
        self.assertEqual(self.world.mutations, [])
        self.assertFalse(self.store.has('insert-intent'))

    def test_image_preflight_before_intent(self):
        for change in ({'sourceDiskId': '1'}, {'id': '2'}, {'status': 'PENDING'}):
            with self.subTest(change):
                self.fresh_world()
                self.world.image = dict(self.world.image, **change)
                code, result = self.execute()
                self.assertEqual((code, result['failure']), (1, 'Refused'))
                self.assertEqual((self.world.mutations, self.store.has('insert-intent')), ([], False))

    def test_unrelated_same_name_disk_is_never_deleted(self):
        foreign = self.world.make_disk(clone.build_body(self.manifest))
        foreign['labels'] = {'other': 'owner'}
        code, result = self.execute()
        self.assertEqual(code, 1)
        self.assertIn(self.manifest['name'], self.world.disks)
        self.assertEqual(self.world.mutations, [])
        # Even with an insert intent on record, an unproven same-name disk is refused.
        self.store.create('insert-intent', {'request_id': self.manifest['request_id'], 'body': {},
                                            'body_sha256': '0' * 64, 'at': clone.iso(self.world.t - 400)})
        self.store.create('insert-outcome', {'state': 'uncertain'})
        again = self.cleaner().run()
        self.assertFalse(again['closed'])
        self.assertIn(self.manifest['name'], self.world.disks)
        self.assertEqual(self.count('delete-disk'), 0)

    def test_lost_insert_response_recovers_by_read_then_deletes_once(self):
        self.world.inject('insert', 'lost')
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Uncertain'))
        self.assertEqual(self.count('insert'), 1)
        self.assertEqual(self.count('delete-vm'), 1)
        self.assert_disposed(result)
        self.assertTrue(self.store.has('bound') and not self.store.has('ids'))

    def test_dropped_insert_stays_unsettled_no_matter_how_much_time_passes(self):
        # Elapsed time (and a 404) never prove a possibly-submitted INSERT cannot arrive later.
        self.world.inject('insert', 'drop')
        code, result = self.execute()
        self.assertEqual(code, 1)
        self.assertFalse(result['cleanup']['closed'])
        self.assertEqual(result['cleanup']['vm'], 'unresolved:insert-unsettled')
        for hours in (1, 24):
            self.world.t += hours * 3600
            again = self.cleaner().run()
            self.assertFalse(again['closed'])
            self.assertEqual(again['vm'], 'unresolved:insert-unsettled')
        self.assertEqual(self.count('insert'), 1)

    def test_rejected_insert_settles_immediately(self):
        self.world.inject('insert', 403)
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Rejected'))
        self.assert_disposed(result)
        self.assertEqual(self.count('insert'), 1)

    def test_stop_failure_blocks_reset_and_removes_key(self):
        self.world.stop_fails = True
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Failure'))
        self.assertEqual(self.count('reset'), 0)
        self.assertEqual(self.world.keys, {})
        self.assert_disposed(result)

    def test_unclosed_master_blocks_reset(self):
        self.world.close_ok = False
        code, result = self.execute()
        self.assertEqual(code, 1)
        self.assertEqual(self.count('reset'), 0)
        self.assertEqual(self.world.keys, {})

    def test_reset_response_lost_is_not_replayed(self):
        self.world.inject('reset', 'lost')
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Uncertain'))
        self.assertEqual(self.count('reset'), 1)
        self.assert_disposed(result)

    def test_second_import_uncertain_removes_only_exact_generated_keys(self):
        _, unrelated = self.world.add_key(b'unrelated')
        self.world.inject('import', 'lost', skip=1)
        code, result = self.execute()
        self.assertEqual(code, 1)
        self.assertEqual(self.count('import'), 2)
        self.assertEqual(set(self.world.keys), {unrelated})
        self.assert_disposed(result)

    def test_preexisting_intended_key_is_refused_without_post(self):
        self.world.add_key(b'generated1')
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Refused'))
        self.assertEqual(self.count('import'), 0)
        self.assertEqual(len(self.world.keys), 1)
        self.assert_disposed(result)

    def test_expiry_or_deadline_crossing_during_token_sends_no_import(self):
        for jump in (1300, 2800):
            with self.subTest(jump):
                self.fresh_world()
                crossed = []

                def hook(jump=jump, crossed=crossed):
                    if os.path.exists(Path(self.world.tmp) / 'a1-intent.json') and not crossed:
                        crossed.append(True)
                        self.world.t += jump
                self.world.on_token = hook
                code, result = self.execute()
                self.assertEqual((code, result['failure']), (1, 'AccessError'))
                self.assertEqual(self.count('import'), 0)
                self.assertTrue(self.store.has('a1-intent') and not self.store.has('a1-import'))

    def test_acceptance_after_response_clock_crossing_fails_and_removes_key(self):
        self.world.after_import = lambda: setattr(self.world, 't', self.world.t + 1300)
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Refused'))
        self.assertEqual(self.count('import'), 1)
        self.assertEqual(self.world.keys, {})
        self.assertFalse(self.store.has('a1-import'))

    def test_changed_boot_disk_between_hostkey_reads_fails_and_is_not_deleted(self):
        self.world.on_hostkey = lambda: self.world.disks[self.manifest['name']].update(id='777')
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Mismatch'))
        self.assertNotIn('master-start', self.world.events)
        self.assertEqual(result['cleanup']['vm'], 'unresolved:disk-provenance')
        self.assertEqual(self.count('delete-vm'), 0)
        self.assertEqual(self.world.keys, {})

    def test_cancellation_runs_the_same_disposal(self):
        self.world.cancel_on = 'get-guest-attributes'
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (143, 'cancelled'))
        self.assert_disposed(result)
        self.assertEqual(self.world.keys, {})

    def test_boot_contract_mismatches_fail_and_dispose(self):
        def builder(out, w):
            out['boot'] = w.BUILD

        def failed(out, w):
            out['clone']['ActiveState'] = 'failed'

        def nonce(out, w):
            out['core']['nonce'] = '9' * 32

        def checkpoint(out, w):
            if out['core']['phase'] == 'ready':
                out['checkpoint']['invocation'] = '1' * 32

        def reused_pair(out, w):
            if w.boot_n == 1:
                out['core']['operation'], out['core']['invocation'] = w.SEALED
                out['checkpoint'] = {'boot': out['boot'], 'operation': w.SEALED[0], 'invocation': w.SEALED[1]}

        def critical_changes(out, w):
            if w.boot_n == 2:
                out['core']['critical_sha256'] = '9' * 64

        def same_boot(out, w):
            if w.boot_n == 2:
                old = w.boot_id(1)
                out['boot'] = out['core']['boot'] = old
                if out['checkpoint']:
                    out['checkpoint']['boot'] = old

        for hook, resets in ((builder, 0), (failed, 0), (nonce, 0), (checkpoint, 0), (reused_pair, 0),
                             (critical_changes, 1), (same_boot, 1)):
            with self.subTest(hook.__name__):
                self.fresh_world()
                self.world.mutate_summary = hook
                code, result = self.execute()
                self.assertEqual((code, result['failure']), (1, 'Mismatch'), result)
                self.assertEqual(self.count('reset'), resets)
                self.assert_disposed(result)
                self.assertEqual(self.world.keys, {})

    def test_readiness_timeout_fails_without_starting_the_unit_by_hand(self):
        def never_ready(out, w):
            if w.boot_n == 1:
                out['core']['phase'] = 'resumable'
        self.world.mutate_summary = never_ready
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Expired'))
        self.assertEqual(set(self.world.events) - {'master-start', 'master-close', 'summary'}, set())
        self.assertEqual(self.count('reset'), 0)
        self.assert_disposed(result)


class SummaryIO:
    """Synthetic guest IO driving a SUMMARY source (default: the ACTUAL clone.SUMMARY).

    schedule maps a read-tick index to the producer steps executed at that tick. Every file read (on close) and every
    systemctl call is one tick, so publications land between the reads of a single collection. second_boot=True starts
    from the first boot's published checkpoint and the first boot's core identity (the retry's real starting state).
    """
    BOOT = '10000001-0000-4000-8000-000000000001'
    OLD_BOOT = '10000001-0000-4000-8000-000000000000'
    BUILD = '00000000-0000-4000-8000-00000000000b'
    OP, INV = '1' * 32, '2' * 32
    OLD_OP, OLD_INV = '3' * 32, '4' * 32
    CLONE_OLD, CLONE_NEW = '5' * 32, '6' * 32

    def __init__(self, schedule=None, second_boot=False):
        core = {'nonce': 'a' * 32, 'phase': 'resumable', 'mode': 'resume', 'boot': self.BOOT,
                'operation': 'e' * 32, 'invocation': 'f' * 32, 'critical': {'k': 1}, 'cluster': {'k': 2}}
        self.files = {
            '/var/lib/labapp-vlab-image/seal.json': {'state': 'sealed', 'owned_sealed': True, 'nonce': 'a' * 32,
                                                      'build_boot': self.BUILD, 'core_operation': 'c' * 32,
                                                      'core_invocation': 'd' * 32},
            '/var/lib/labapp-vlab-core/state.json': core}
        if second_boot:
            core.update(boot=self.OLD_BOOT, operation=self.OLD_OP, invocation=self.OLD_INV)
            self.files['/var/lib/labapp-vlab-image/clone-start.json'] = {
                'boot': self.OLD_BOOT, 'operation': self.OLD_OP, 'invocation': self.OLD_INV}
        self.units = {'labapp-vlab-clone.service': ('activating', self.CLONE_OLD, 'success'),
                      'hhfab-vlab-resume.service': ('active', self.INV, 'success')}
        self.schedule = {k: list(v) for k, v in (schedule or {}).items()}
        self.reads, self.fds = 0, {}

    @staticmethod
    def digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def prior(self):
        """The first boot's accepted ready proof (what a real second-boot readiness compares against)."""
        return {'boot': self.OLD_BOOT, 'nonce': 'a' * 32, 'build_boot': self.BUILD, 'operation': self.OLD_OP,
                'invocation': self.OLD_INV, 'critical': self.digest({'k': 1}), 'cluster': self.digest({'k': 2})}

    def tick(self):
        for step in self.schedule.pop(self.reads, ()):
            step(self)
        self.reads += 1

    def publish_core(self):
        core = self.files['/var/lib/labapp-vlab-core/state.json']
        core.update(phase='ready', boot=self.BOOT, operation=self.OP, invocation=self.INV)

    def publish_checkpoint(self, op=None):
        self.files['/var/lib/labapp-vlab-image/clone-start.json'] = {
            'boot': self.BOOT, 'operation': op or self.OP, 'invocation': self.INV}

    def publish_clone(self):
        self.units['labapp-vlab-clone.service'] = ('active', self.CLONE_NEW, 'success')

    def producer(self):
        """The real producer contract: READY core, then atomic checkpoint, then clone unit success/active."""
        return [SummaryIO.publish_core, SummaryIO.publish_checkpoint, SummaryIO.publish_clone]

    def os_open(self, path, flags, *a):
        if path not in self.files:
            raise FileNotFoundError(path)
        fd = 100 + len(self.fds)
        self.fds[fd] = json.dumps(self.files[path]).encode()   # the content as of open, like a real read
        return fd

    def fdopen(self, fd, mode):
        io_self = self
        data = self.fds[fd]

        class Stream:
            def __enter__(s):
                return s

            def __exit__(s, *a):
                io_self.tick()

            def fileno(s):
                return fd

            def read(s, n):
                return data[:n]
        return Stream()

    def fstat(self, fd):
        return SimpleNamespace(st_uid=0, st_nlink=1, st_mode=0o100600, st_size=len(self.fds[fd]))

    def run(self, argv, **kwargs):
        active, invocation, result = self.units[argv[2]]   # state as of this call, before any later publication
        self.tick()
        return SimpleNamespace(stdout=f'ActiveState={active}\nInvocationID={invocation}\nResult={result}\n')

    def execute(self, source=None):
        real_open, out = open, io.StringIO()

        def fake_open(path, *a, **k):
            return io.StringIO(self.BOOT + '\n') if path == '/proc/sys/kernel/random/boot_id' else real_open(path, *a, **k)
        with patch('os.open', self.os_open), patch('os.fdopen', self.fdopen), patch('os.fstat', self.fstat), \
                patch('subprocess.run', self.run), patch('builtins.open', fake_open), patch('sys.stdout', out):
            exec(compile(clone.SUMMARY if source is None else source, 'summary', 'exec'), {'__name__': 'summary'})
        return out.getvalue().encode()


def former_summary_source():
    """The pre-correction SUMMARY: the clone unit was read LAST, after the checkpoint and core state."""
    source = clone.SUMMARY
    early, late = "clone=unit('labapp-vlab-clone.service')\n", "'clone':clone,"
    assert source.count(early) == 1 and source.count(late) == 1
    return source.replace(early, '').replace(late, "'clone':unit('labapp-vlab-clone.service'),")


class PrivateCloneSummaryOrdering(CloneCase):
    FIELDS = (('seal', 'state'), ('core', 'phase'), ('core', 'mode'), ('clone', 'ActiveState'),
              ('clone', 'InvocationID'), ('clone', 'Result'), ('resume', 'ActiveState'),
              ('resume', 'InvocationID'), ('resume', 'Result'))

    def observe(self, io_world, source=None):
        return clone.parse_summary(io_world.execute(source))

    def test_stable_ready_passes(self):
        stable = SummaryIO(second_boot=True)
        for step in stable.producer():
            step(stable)
        self.assertEqual(clone.readiness(self.observe(stable), stable.prior()), 'ready')

    def test_hazard_exists_on_the_former_summary_order(self):
        # Old first-boot checkpoint is read, then the legal producer publishes core, checkpoint and clone before the
        # former order reads core and the clone unit: a hard Mismatch from a LEGAL interleaving.
        world = SummaryIO({1: [SummaryIO.publish_core], 2: [SummaryIO.publish_checkpoint, SummaryIO.publish_clone]},
                          second_boot=True)
        summary = self.observe(world, former_summary_source())
        self.assertEqual(summary['checkpoint']['boot'], SummaryIO.OLD_BOOT)
        self.assertEqual((summary['core']['phase'], summary['clone']['ActiveState']), ('ready', 'active'))
        with self.assertRaises(clone.Mismatch):
            clone.readiness(summary, world.prior())

    def test_same_schedule_never_mismatches_on_the_actual_summary(self):
        world = SummaryIO({1: [SummaryIO.publish_core], 2: [SummaryIO.publish_checkpoint, SummaryIO.publish_clone]},
                          second_boot=True)
        states = [clone.readiness(self.observe(world), world.prior()) for _ in range(3)]   # a Mismatch raises
        self.assertEqual(states[0], 'pending')
        self.assertEqual(states[-1], 'ready')
        self.assertFalse(world.schedule)

    def test_every_legal_producer_interleaving_never_mismatches(self):
        steps, checked = SummaryIO().producer(), 0
        for a in range(7):
            for b in range(a, 7):
                for c in range(b, 7):
                    with self.subTest(core=a, checkpoint=b, clone=c):
                        schedule = {}
                        for tick, step in zip((a, b, c), steps):
                            schedule.setdefault(tick, []).append(step)   # same tick keeps producer order
                        world = SummaryIO(schedule, second_boot=True)
                        states = []
                        for _ in range(4):   # bounded: the synthetic producer is fully progressed by then
                            states.append(clone.readiness(self.observe(world), world.prior()))   # never swallowed
                            if states[-1] == 'ready':
                                break
                        self.assertEqual(states[-1], 'ready')
                        self.assertEqual(set(states[:-1]), set(['pending'] * (len(states) - 1)))
                        self.assertFalse(world.schedule)
                        checked += 1
        self.assertEqual(checked, 84)

    def test_stable_wrong_checkpoint_stays_mismatch(self):
        stable = SummaryIO(second_boot=True)
        stable.publish_core(), stable.publish_clone()      # checkpoint stays the first boot's, permanently
        with self.assertRaises(clone.Mismatch):
            clone.readiness(self.observe(stable), stable.prior())
        wrong = SummaryIO(second_boot=True)
        wrong.publish_core(), wrong.publish_checkpoint('9' * 32), wrong.publish_clone()
        with self.assertRaises(clone.Mismatch):
            clone.readiness(self.observe(wrong), wrong.prior())

    def test_failed_clone_unit_and_transition_without_publication(self):
        world = SummaryIO()
        world.units['labapp-vlab-clone.service'] = ('failed', SummaryIO.CLONE_OLD, 'exit-code')
        with self.assertRaises(clone.Mismatch):
            clone.readiness(self.observe(world))
        pending = SummaryIO()
        pending.publish_core(), pending.publish_checkpoint()   # clone unit still activating: not yet ready
        self.assertEqual(clone.readiness(self.observe(pending)), 'pending')

    def good_summary(self):
        world = SummaryIO(second_boot=True)
        for step in world.producer():
            step(world)
        return self.observe(world)

    def test_diagnostic_validation_is_closed_for_every_nominal_field(self):
        good = self.good_summary()
        self.assertEqual(clone.diagnostic_summary(good), good)   # a fully valid summary is retained unchanged
        for group, field in self.FIELDS:
            for bad in ('TOP-SECRET-VALUE', 'ACTIVE', ' active', 'a' * 31, '0' * 33, 7):
                with self.subTest(group=group, field=field, bad=bad):
                    summary = json.loads(json.dumps(good))
                    summary[group][field] = bad
                    self.assertIsNone(clone.diagnostic_summary(summary))
        for group, field in self.FIELDS:   # optional absent forms stay valid where the producer can omit them
            if group != 'seal':
                summary = json.loads(json.dumps(good))
                summary[group][field] = None
                self.assertIsNotNone(clone.diagnostic_summary(summary), (group, field))

    def test_hostile_text_in_each_field_is_never_persisted(self):
        run = clone.Run(self.world.tmp, self.manifest, self.sha, self.deps, self.unit)
        good = self.good_summary()
        for number, (group, field) in enumerate(self.FIELDS):
            with self.subTest(group=group, field=field):
                summary = json.loads(json.dumps(good))
                summary[group][field] = 'TOP-SECRET-VALUE'
                run.phase = 'hostile%d' % number
                run.reject('readiness', clone.Mismatch('ready state does not match the clone-boot checkpoint contract'),
                           summary)
                raw = self.store.raw('rejected-hostile%d' % number)
                self.assertNotIn(b'TOP-SECRET', raw)
                self.assertEqual(json.loads(raw), {'stage': 'readiness', 'code': 'unrecognized',
                                                   'reason': 'unrecognized', 'summary': None})

    def test_rejected_terminal_summary_is_retained_exclusively_and_bounded(self):
        def wrong(out, w):
            out['clone']['InvocationID'] = 'b' * 32
            if w.boot_n == 1 and out['core']['phase'] == 'ready':
                out['checkpoint']['operation'] = '9' * 32
        self.world.mutate_summary = wrong
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Mismatch'))
        saved = self.store.read('rejected-boot1')
        self.assertEqual((saved['stage'], saved['code']), ('readiness', 'mismatch'))
        self.assertEqual(saved['reason'], 'ready state does not match the clone-boot checkpoint contract')
        self.assertEqual(saved['summary']['checkpoint']['operation'], '9' * 32)
        self.assertEqual(set(saved), {'stage', 'code', 'reason', 'summary'})
        self.assertLessEqual(len(self.store.raw('rejected-boot1')), clone.LIMIT)
        self.assertEqual(stat.S_IMODE(os.stat(self.store.path('rejected-boot1')).st_mode), 0o600)
        with self.assertRaises(clone.Refused):
            self.store.create('rejected-boot1', {})
        self.assert_disposed(result)

    def test_failed_unit_projection_is_retained(self):
        def failed(out, w):
            if w.boot_n == 1:
                out['clone'] = {'ActiveState': 'failed', 'InvocationID': 'b' * 32, 'Result': 'exit-code'}
        self.world.mutate_summary = failed
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Mismatch'))
        saved = self.store.read('rejected-boot1')
        self.assertEqual((saved['code'], saved['reason']), ('mismatch', 'unchanged clone auto-start failed'))
        self.assertEqual(saved['summary']['clone'],
                         {'ActiveState': 'failed', 'InvocationID': 'b' * 32, 'Result': 'exit-code'})
        self.assert_disposed(result)

    def test_malformed_summary_gets_only_a_fixed_classification(self):
        def hostile(out, w):
            out['config'] = {'secret': 'TOP-SECRET-VALUE'}
        self.world.mutate_summary = hostile
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Refused'))
        raw = self.store.raw('rejected-boot1')
        self.assertEqual(json.loads(raw), {'stage': 'readiness', 'code': 'malformed', 'reason': 'malformed',
                                           'summary': None})
        self.assertNotIn(b'TOP-SECRET', raw)
        self.assert_disposed(result)

    def wrong_checkpoint(self):
        def wrong(out, w):
            if w.boot_n == 1 and out['core']['phase'] == 'ready':
                out['checkpoint']['operation'] = '9' * 32
        self.world.mutate_summary = wrong

    def test_diagnostic_write_failure_preserves_primary_failure_and_cleanup(self):
        self.wrong_checkpoint()
        original = clone.Store.create

        def failing(store, kind, value):
            if kind.startswith('rejected-'):
                raise OSError('disk full')
            return original(store, kind, value)
        with patch.object(clone.Store, 'create', failing):
            code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Mismatch'))
        self.assertFalse(self.store.has('rejected-boot1'))
        self.assert_disposed(result)

    def test_diagnostic_cancellation_preserves_primary_failure_and_cleanup(self):
        self.wrong_checkpoint()
        original = clone.Store.create

        def cancelled(store, kind, value):
            if kind.startswith('rejected-'):
                raise host.HostCancelled(signal.SIGTERM)   # BaseException, not Exception
            return original(store, kind, value)
        with patch.object(clone.Store, 'create', cancelled):
            code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Mismatch'))   # not 143/'cancelled'
        self.assertFalse(self.store.has('rejected-boot1'))
        self.assertTrue(self.store.has('failure'))
        self.assert_disposed(result)


class PrivateCloneRecovery(CloneCase):
    def intent(self, outcome, age=400):
        self.store.create('insert-intent', {'request_id': self.manifest['request_id'], 'body': {},
                                            'body_sha256': '0' * 64, 'at': clone.iso(self.world.t - age)})
        self.store.create('insert-outcome', {'state': outcome})

    def failed_insert_op(self):
        """A TERMINAL, errored INSERT operation: the definite proof that nothing more will be created."""
        op = self.world.op('insert', 'instances', self.manifest['name'], None, self.manifest['request_id'])
        self.world.ops[op['name']].update(status='DONE', error={'errors': [{'code': 'PARTIAL'}]},
                                          httpErrorStatusCode=500)

    def test_disk_only_partial_create_is_bound_and_deleted_once(self):
        self.intent('uncertain')
        self.failed_insert_op()
        self.world.make_disk(clone.build_body(self.manifest))
        first = self.cleaner().run()
        self.assertTrue(first['closed'], first)
        self.assertEqual((first['vm'], first['disk']), ('absent', 'deleted'))
        self.assertEqual(self.count('delete-disk'), 1)
        self.assertTrue(self.cleaner().run()['closed'])
        self.assertEqual(self.count('delete-disk'), 1)

    def test_young_uncertain_insert_keeps_obligation_open(self):
        self.intent('uncertain', age=5)
        result = self.cleaner().run()
        self.assertFalse(result['closed'])
        self.assertEqual(self.world.mutations, [])

    def test_uncertain_vm_delete_is_never_replayed(self):
        self.intent('accepted')
        self.world.insert(clone.build_body(self.manifest), self.manifest['request_id'])
        self.world.inject('delete-vm', 'lost')
        first = self.cleaner().run()
        self.assertFalse(first['closed'])
        self.assertEqual(self.count('delete-vm'), 1)
        second = self.cleaner().run()
        self.assertEqual(self.count('delete-vm'), 1)
        self.assertTrue(second['closed'], second)

    def test_foreign_vm_with_the_same_name_is_not_touched(self):
        self.intent('uncertain')
        self.world.insert(clone.build_body(self.manifest), self.manifest['request_id'])
        self.world.vms[self.manifest['name']]['labels'] = {'labapp-manual-clone-uuid': str(uuid4())}
        result = self.cleaner().run()
        self.assertEqual(result['vm'], 'unresolved:vm-ownership-mismatch')
        self.assertEqual(self.count('delete-vm'), 0)

    def key_fixture(self):
        expiry = str(int((self.world.t + 900) * 1_000_000))
        wire, fp = self.world.add_key(b'ours', expiry=expiry)
        _, other = self.world.add_key(b'theirs')
        self.store.create('a1-intent', {'n': 1, 'public_key': wire, 'expiration_usec': expiry})
        return fp, other

    def test_key_delete_lost_response_is_resolved_by_profile_without_replay(self):
        fp, other = self.key_fixture()
        self.world.inject('delete-key', 'lost')
        cleaner = self.cleaner()
        self.assertEqual(cleaner.remove_key(1), 'removed')
        self.assertEqual(cleaner.remove_key(1), 'absent')
        self.assertEqual(self.count('delete-key'), 1)
        self.assertEqual(set(self.world.keys), {other})

    def test_key_delete_dropped_stays_unresolved_and_is_not_replayed(self):
        fp, other = self.key_fixture()
        self.world.inject('delete-key', 'drop')
        cleaner = self.cleaner()
        self.assertEqual(cleaner.remove_key(1), 'unresolved')
        self.assertEqual(cleaner.remove_key(1), 'unresolved')
        self.assertEqual(self.count('delete-key'), 1)
        self.assertEqual(set(self.world.keys), {fp, other})

    def test_watch_cleans_immediately_when_the_run_process_is_gone(self):
        self.intent('accepted')
        self.world.insert(clone.build_body(self.manifest), self.manifest['request_id'])
        self.store.create('run', {'pid': 424242, 'start': 5, 'unit': self.unit})
        self.world.owner_state = dict(self.world.INACTIVE_FIELDS)   # the bound owner service is gone
        self.assertEqual(clone.watch(self.world.tmp, self.sha, self.deps, passes=1), 0)
        self.assertEqual((self.world.vms, self.world.disks), ({}, {}))
        self.assertEqual(self.count('delete-vm'), 1)

    def test_watch_waits_for_the_work_deadline_when_no_run_started(self):
        self.assertEqual(clone.watch(self.world.tmp, self.sha, self.deps, passes=1), 0)
        self.assertGreaterEqual(self.world.t, clone.stamp(self.manifest['work_deadline']))
        self.assertEqual(self.world.mutations, [])

    def test_watch_leaves_a_closed_run_alone(self):
        self.store.create('closed', {'at': 'x'})
        before = self.world.t
        self.assertEqual(clone.watch(self.world.tmp, self.sha, self.deps), 0)
        self.assertEqual(self.world.t, before)


# ---------------------------------------------------------------------------------------------
# #546 single correction: quiescence/containment, split original clocks, key absence, recovery
# schema, operation settlement and the trusted runtime/unit contract. Same synthetic world; the
# real Units/Cleaner/Run/watch code runs, only systemd, Compute, OS Login and the guest are fakes.
import fcntl


class PrivateCloneCorrection(CloneCase):
    def intent(self, outcome='accepted'):
        self.store.create('insert-intent', {'request_id': self.manifest['request_id'], 'body': {},
                                            'body_sha256': '0' * 64, 'at': clone.iso(self.world.t - 400)})
        self.store.create('insert-outcome', {'state': outcome})

    def vm_with_op(self, outcome='accepted'):
        """An INSERT that landed: VM + disk + the (RUNNING) operation, intent and outcome on record."""
        self.intent(outcome)
        return self.world.insert(clone.build_body(self.manifest), self.manifest['request_id'])

    def vm_id(self):
        return self.world.vms[self.manifest['name']]['id']

    def key_fixture(self):
        expiry = str(int((self.world.t + 900) * 1_000_000))
        wire, fp = self.world.add_key(b'ours', expiry=expiry)
        _, other = self.world.add_key(b'theirs')
        self.store.create('a1-intent', {'n': 1, 'public_key': wire, 'expiration_usec': expiry})
        return fp, other

    HAPPY = ['insert', 'import', 'delete-key', 'reset', 'import', 'delete-key', 'delete-vm']

    # ---- 1. quiescence / containment / serialization
    def test_independent_cleanup_stops_the_bound_owner_before_any_disposal(self):
        self.vm_with_op()
        result = self.independent().run()
        self.assertTrue(result['closed'], result)
        self.assertIs(result['quiesced'], True)
        self.assertEqual(self.world.timeline[0], 'systemctl-stop')
        self.assertIn('delete-vm', self.world.timeline)
        self.assertEqual(self.world.owner_state['ActiveState'], 'inactive')
        self.assertTrue(self.store.has('disposal') and self.store.has('closed'))

    def test_no_pid_record_and_hard_killed_owner_are_covered_by_the_unit_cgroup_alone(self):
        self.vm_with_op()
        self.assertFalse(self.store.has('run'))           # spawn-to-record gap: nothing recorded at all
        self.world.cgroup_procs([991, 992])                # stray descendants of the dead leader
        self.world.after_stop = lambda: self.world.cgroup_procs([])
        result = self.independent().run()
        self.assertTrue(result['closed'], result)
        self.assertIn('systemctl-stop', self.world.events)
        # The cross-process PID/pgid reaper no longer exists in any form.
        self.assertFalse(hasattr(clone.Cleaner, 'reap'))
        self.assertFalse(hasattr(clone, 'alive'))
        self.assertFalse(hasattr(self.deps, 'killpg') or hasattr(self.deps, 'getpgid'))

    def test_leader_gone_but_cgroup_still_nonempty_is_not_quiescent(self):
        self.vm_with_op()
        self.world.owner_state = dict(self.world.INACTIVE_FIELDS)   # leader exited / zombie, unit looks inactive
        self.world.cgroup_procs([4242, 4243])                       # IAP/ssh descendants remain
        result = self.independent().run()
        self.assertFalse(result['closed'])
        self.assertIs(result['quiesced'], False)
        self.assertEqual(self.world.mutations, [])
        self.assertFalse(self.store.has('disposal'))
        self.assertIn(self.manifest['name'], self.world.vms)
        self.world.cgroup_procs([])
        self.assertTrue(self.independent().run()['closed'])

    def test_stop_that_does_not_empty_the_owner_never_allows_disposal(self):
        def ineffective():
            self.world.stop_ineffective = True

        def descendants_remain():
            self.world.cgroup_procs([7])

        def control_group_remains():
            self.world.owner_state['ControlGroup'] = '/system.slice/' + self.world.owner

        def stop_command_fails():
            raise host.guest.Failure('systemctl stop refused', 1)
        for label, setup in (('ineffective', ineffective), ('procs', None), ('cgroup', None), ('fails', None)):
            with self.subTest(label):
                self.fresh_world()
                self.vm_with_op()
                if label == 'ineffective':
                    setup()
                elif label == 'procs':
                    self.world.after_stop = descendants_remain
                elif label == 'cgroup':
                    self.world.after_stop = control_group_remains
                else:
                    self.world.after_stop = stop_command_fails
                result = self.independent().run()
                self.assertFalse(result['closed'])
                self.assertEqual(self.world.mutations, [])
                self.assertFalse(self.store.has('disposal'))

    def test_misconfigured_owner_unit_is_never_stopped_or_trusted(self):
        self.vm_with_op()
        self.world.unit_override['owner'] = {'User': 'root'}
        result = self.independent().run()
        self.assertFalse(result['closed'])
        self.assertNotIn('systemctl-stop', self.world.events)
        self.assertEqual(self.world.mutations, [])

    def test_a_work_holder_blocks_independent_disposal_even_if_the_unit_reads_inactive(self):
        self.vm_with_op()
        self.world.owner_state = dict(self.world.INACTIVE_FIELDS)
        fd = os.open(Path(self.world.tmp) / 'work.lock', os.O_RDWR)
        self.addCleanup(lambda: os.close(fd) if fd >= 0 else None)
        fcntl.flock(fd, fcntl.LOCK_SH)
        result = self.independent().run()
        self.assertFalse(result['closed'])
        self.assertIs(result['quiesced'], True)
        self.assertEqual(self.world.mutations, [])
        self.assertFalse(self.store.has('disposal'))
        fcntl.flock(fd, fcntl.LOCK_UN)
        self.assertTrue(self.independent().run()['closed'])

    def test_no_work_mutation_can_start_after_disposal_begins(self):
        self.store.create('disposal', {'at': 'x'})
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Refused'))
        self.assertEqual(self.world.mutations, [])
        run = clone.Run(self.world.tmp, self.manifest, self.sha, self.deps, self.unit)
        with self.assertRaises(clone.Expired):
            run.gate()
        cloud = clone.CloneCompute(self.world, self.world.token)
        with self.assertRaises(clone.NotSent):
            cloud.insert(self.manifest, clone.build_body(self.manifest), self.manifest['request_id'], run.gate)
        self.assertEqual(self.world.mutations, [])

    def test_independent_cleanup_racing_an_active_run_cannot_mutate_or_close_it(self):
        attempts = []

        def race():
            if not attempts:
                attempts.append(self.independent().run())
        self.world.on_hostkey = race
        code, result = self.execute()
        self.assertEqual((code, result['status']), (0, 'passed'), result)
        (attempt,) = attempts
        self.assertFalse(attempt['closed'])
        self.assertEqual(self.world.mutations, self.HAPPY)       # the racing cleaner added no mutation at all

    def test_live_caller_cleans_in_process_without_stopping_its_own_owner(self):
        code, result = self.execute()
        self.assertEqual((code, result['cleanup']['quiesced']), (0, 'in-process'))
        self.assertNotIn('systemctl-stop', self.world.events)
        record = self.store.read('run')
        self.assertEqual((record['owner_unit'], record['watch_unit'], record['control_group']),
                         (self.world.owner, self.unit, '/system.slice/' + self.world.owner))
        self.assertRegex(record['invocation_id'], r'[0-9a-f]{32}\Z')

    # ---- 2. original dual clocks
    def test_child_window_clips_to_the_parent_original_monotonic_end_after_a_wall_rollback(self):
        world, deps = self.world, self.deps
        budget = clone.Budget(self.manifest, deps)
        parent = clone.Window(deps, budget, deps.wall() + 1200, deps.mono() + 1200)
        world.t += 900
        world.wall_offset -= 900                     # wall clock rolled back; monotonic kept advancing
        child = parent.sub(780)
        self.assertLessEqual(child.remaining(), 300)
        self.assertLessEqual(parent.remaining(), 300)
        world.t += 301
        for window in (parent, child):
            with self.assertRaises(clone.Expired):
                window.remaining()

    def test_mono_only_delay_over_twenty_minutes_in_auth_sends_no_import(self):
        fired = []

        def hook():
            if (Path(self.world.tmp) / 'a1-intent.json').exists() and not fired:
                fired.append(True)
                self.world.mono_offset += 1300       # wall clock did not move at all
        self.world.on_token = hook
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'AccessError'))
        self.assertEqual(self.count('import'), 0)
        self.assertTrue(self.store.has('a1-intent') and not self.store.has('a1-import'))

    def test_mono_only_delay_during_the_import_response_is_refused_and_not_persisted(self):
        self.world.after_import = lambda: setattr(self.world, 'mono_offset', self.world.mono_offset + 1300)
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Refused'))
        self.assertEqual(self.count('import'), 1)
        self.assertFalse(self.store.has('a1-import'))
        self.assertEqual(self.world.keys, {})
        self.assert_disposed(result)

    def test_mono_only_delay_during_canonical_confirmation_is_bounded_by_the_same_window(self):
        profile_reads = []

        def hook():
            if (Path(self.world.tmp) / 'a1-intent.json').exists() and self.world.imported:
                profile_reads.append(True)
                if len(profile_reads) == 1:
                    self.world.mono_offset += 1300   # the confirmation GET's own credential step
        self.world.on_token = hook
        code, result = self.execute()
        self.assertEqual(code, 1)
        self.assertFalse(self.store.has('a1-import'))
        self.assertEqual(self.count('import'), 1)
        self.assertEqual(self.world.keys, {})

    def test_insert_credential_crossing_is_not_sent_but_a_late_response_is_uncertain(self):
        fired = []

        def hook():
            if self.store.has('insert-intent') and not fired:
                fired.append(True)
                self.world.t += 3000
        self.world.on_token = hook
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Expired'))
        self.assertEqual((self.count('insert'), self.store.read('insert-outcome')['state']), (0, 'not-sent'))
        self.assert_disposed(result)
        self.fresh_world()
        self.world.after_mutation['insert'] = lambda: setattr(self.world, 't', self.world.t + 3000)
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Uncertain'))
        self.assertEqual((self.count('insert'), self.store.read('insert-outcome')['state']), (1, 'uncertain'))
        self.assertFalse(self.store.has('ids'))
        self.assert_disposed(result)                  # recovered by request ID; deleted exactly once
        self.assertEqual(self.count('delete-vm'), 1)

    def test_terminal_done_answer_after_the_bound_is_uncertain_and_never_persisted(self):
        def late_done(snapshot):
            self.world.t += 3000
            return dict(snapshot, status='DONE')
        self.world.op_hook = late_done
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Uncertain'))
        self.assertTrue(self.store.has('insert-op') and not self.store.has('ids'))
        self.assert_disposed(result)

    def test_reset_response_after_the_bound_is_uncertain_and_still_reconciled(self):
        self.world.after_mutation['reset'] = lambda: setattr(self.world, 't', self.world.t + 3000)
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Uncertain'))
        self.assertEqual(self.store.read('reset-outcome')['state'], 'uncertain')
        self.assertEqual(self.count('reset'), 1)
        self.assert_disposed(result)

    def test_wait_operation_pins_name_and_id_and_gates_even_a_done_answer(self):
        class Cloud:
            def __init__(self, answer):
                self.answer = answer

            def operation(self, name):
                return self.answer
        first = {'name': 'op-1', 'id': '11', 'status': 'RUNNING'}
        for answer in ({'name': 'op-1', 'id': '12', 'status': 'DONE'}, {'name': 'op-2', 'id': '11', 'status': 'DONE'}):
            with self.subTest(answer), self.assertRaises(clone.Mismatch):
                clone.wait_operation(Cloud(answer), self.deps, first, lambda o, d: None, lambda: None)

        def expired():
            raise clone.Expired('late')
        with self.assertRaises(clone.Expired):
            clone.wait_operation(Cloud(None), self.deps, dict(first, status='DONE'), lambda o, d: None, expired)

    # ---- 3. key absence
    def test_expired_but_still_listed_key_is_unresolved_never_closed(self):
        fp, other = self.key_fixture()
        self.world.t += 1000                           # past the key TTL; the key is STILL in the profile
        self.world.inject('delete-key', 'drop')
        cleaner = self.cleaner()
        self.assertEqual(cleaner.remove_key(1), 'unresolved')
        self.assertEqual(cleaner.remove_key(1), 'unresolved')
        self.assertEqual(self.count('delete-key'), 1)  # one-shot; no blind retry
        result = cleaner.run()
        self.assertFalse(result['closed'])
        self.assertEqual(result['keys']['1'], 'unresolved')
        self.assertNotIn('expired', result['keys'].values())
        self.assertEqual(set(self.world.keys), {fp, other})
        del self.world.keys[fp]                        # canonical SELF profile now proves absence
        self.assertEqual(cleaner.remove_key(1), 'removed')
        self.assertEqual(cleaner.remove_key(1), 'absent')
        self.assertEqual(set(self.world.keys), {other})

    # ---- 4. recovery schema
    def test_dropped_vm_delete_recovers_without_keyerror_replay_or_adopting_another_id(self):
        self.vm_with_op()
        self.world.inject('delete-vm', 'drop')
        first = self.cleaner().run()
        self.assertFalse(first['closed'])
        self.assertEqual(first['vm'], 'unresolved:vm-delete')
        intent = self.store.read('vm-delete-intent')
        self.assertEqual(intent['resource_id'], self.vm_id())
        second = self.cleaner().run()                  # reads the real stored schema (resource_id)
        self.assertEqual((second['closed'], second['vm']), (False, 'unresolved:vm-delete'))
        self.assertEqual(self.count('delete-vm'), 1)
        self.world.vms[self.manifest['name']]['id'] = '999'
        third = self.cleaner().run()
        self.assertEqual(third['vm'], 'unresolved:vm-ownership-mismatch')
        self.assertEqual((self.count('delete-vm'), self.store.read('vm-delete-intent')['resource_id']),
                         (1, intent['resource_id']))

    def test_known_vm_id_is_immutable_across_recovery(self):
        self.vm_with_op()
        self.store.create('ids', {'vm_id': '555', 'boot_id': self.world.disks[self.manifest['name']]['id']})
        result = self.cleaner().run()
        self.assertFalse(result['closed'])
        self.assertTrue(result['vm'].startswith('unresolved:'), result)
        self.assertEqual(self.count('delete-vm'), 0)
        self.assertEqual(self.store.read('ids')['vm_id'], '555')

    # ---- 5. mutation settlement and operation identity
    def test_pending_operation_never_settles_by_elapsed_time(self):
        self.vm_with_op()
        self.world.pin_status = 'RUNNING'
        for hours in (0, 24):
            self.world.t += hours * 3600
            result = self.cleaner().run()
            self.assertFalse(result['closed'])
            self.assertEqual(result['vm'], 'unresolved:insert-unsettled')
        self.assertEqual(self.count('delete-vm'), 0)
        self.world.pin_status = None
        self.assertTrue(self.cleaner().run()['closed'])

    def test_missing_recorded_operation_is_unresolved(self):
        self.vm_with_op()
        self.store.create('insert-op', {'name': 'op-404', 'id': '1'})
        result = self.cleaner().run()
        self.assertEqual((result['closed'], result['vm']), (False, 'unresolved:insert-unsettled'))
        self.assertEqual(self.count('delete-vm'), 0)

    def test_wrong_operation_is_never_accepted(self):
        for field, value in (('id', '5'), ('user', 'other@example.com'), ('operationType', 'reset'),
                             ('targetId', '12345'), ('kind', 'compute#other'),
                             ('targetLink', CLONE_P + f'zones/{clone.ZONE}/instances/labapp-clone-ffffffffffff'),
                             ('httpErrorStatusCode', 500)):
            with self.subTest(field):
                self.fresh_world()
                op = self.vm_with_op()
                self.store.create('insert-op', {'name': op['name'], 'id': op['id']})
                self.store.create('ids', {'vm_id': self.vm_id(), 'boot_id': self.world.disks[self.manifest['name']]['id']})
                self.world.ops[op['name']][field] = value
                result = self.cleaner().run()
                self.assertFalse(result['closed'])
                self.assertEqual(result['vm'], 'unresolved:insert-unsettled')
                self.assertEqual(self.count('delete-vm'), 0)

    def test_operation_changing_identity_while_polling_is_a_mismatch(self):
        self.vm_with_op()
        self.world.pin_status = 'RUNNING'
        self.world.op_hook = lambda snapshot: dict(snapshot, id='7777')
        result = self.cleaner().run()
        self.assertEqual((result['closed'], result['vm']), (False, 'unresolved:insert-unsettled'))
        self.assertEqual(self.count('delete-vm'), 0)

    def test_lost_reset_is_reconciled_by_operation_even_after_the_vm_is_gone(self):
        self.vm_with_op()
        request = str(uuid4())
        self.store.create('reset-intent', {'request_id': request, 'vm_id': self.vm_id(), 'boot_id': 'x',
                                           'at': clone.iso(self.world.t)})
        self.store.create('reset-outcome', {'state': 'uncertain'})
        dropped = self.cleaner().run()                   # never delivered: cannot be ruled out
        self.assertEqual((dropped['closed'], dropped['vm']), (False, 'unresolved:reset-unsettled'))
        self.assertEqual(self.count('delete-vm'), 0)
        self.world.reset(self.manifest['name'], request)  # it actually landed late; now it has an operation
        landed = self.cleaner().run()
        self.assertTrue(landed['closed'], landed)
        self.assertEqual(self.count('delete-vm'), 1)

    def test_unreconciled_reset_is_not_skipped_when_the_resources_are_already_404(self):
        self.vm_with_op()
        self.store.create('reset-intent', {'request_id': str(uuid4()), 'vm_id': self.vm_id(), 'boot_id': 'x',
                                           'at': clone.iso(self.world.t)})
        self.world.vms.clear()
        self.world.disks.clear()
        result = self.cleaner().run()
        self.assertEqual((result['closed'], result['vm']), (False, 'unresolved:reset-unsettled'))

    def test_vm_delete_without_an_operation_is_unresolved_even_when_the_vm_is_gone(self):
        self.vm_with_op()
        vm_id, request = self.vm_id(), str(uuid4())
        self.store.create('vm-delete-intent', {'request_id': request, 'resource_id': vm_id,
                                               'at': clone.iso(self.world.t)})
        self.world.vms.clear()
        self.world.disks.clear()
        result = self.cleaner().run()
        self.assertEqual((result['closed'], result['vm']), (False, 'unresolved:vm-delete'))
        self.assertEqual(self.count('delete-vm'), 0)
        self.world.op('delete', 'instances', self.manifest['name'], vm_id, request)   # the DELETE did land
        reconciled = self.cleaner().run()
        self.assertTrue(reconciled['closed'], reconciled)
        self.assertEqual(self.count('delete-vm'), 0)

    def test_disk_delete_without_an_operation_is_unresolved_even_when_the_disk_is_gone(self):
        self.vm_with_op()
        disk_id = self.world.disks[self.manifest['name']]['id']
        self.store.create('disk-delete-intent', {'request_id': str(uuid4()), 'resource_id': disk_id,
                                                 'at': clone.iso(self.world.t)})
        self.world.vms.clear()
        self.world.disks.clear()
        result = self.cleaner().run()
        self.assertEqual((result['closed'], result['disk']), (False, 'unresolved:disk-delete'))

    def test_rejected_delete_is_a_definite_outcome_and_a_404_delete_is_never_replayed(self):
        self.vm_with_op()
        self.world.inject('delete-vm', 403)
        first = self.cleaner().run()
        self.assertEqual((first['closed'], first['vm']), (False, 'unresolved:vm-delete'))
        self.assertEqual(self.store.read('vm-delete-outcome'), {'state': 'rejected'})
        second = self.cleaner().run()
        self.assertEqual((second['vm'], self.count('delete-vm')), ('unresolved:vm-still-present', 1))

    def test_paginated_operation_list_is_never_assumed_complete(self):
        self.vm_with_op()
        self.world.next_page = True
        cloud = clone.CloneCompute(self.world, self.world.token)
        with self.assertRaises(clone.Uncertain):
            cloud.operations_for(self.manifest['request_id'])
        result = self.cleaner().run()
        self.assertEqual((result['closed'], result['vm']), (False, 'unresolved:insert-unsettled'))
        self.assertEqual(self.count('delete-vm'), 0)

    def test_strict_operation_identity_requires_kind_numeric_id_and_zone(self):
        name, request = self.manifest['name'], self.manifest['request_id']
        good = {'name': 'op-1', 'id': '9001', 'kind': 'compute#operation', 'operationType': 'insert',
                'clientOperationId': request, 'user': clone.OWNER, 'zone': CLONE_P + 'zones/' + clone.ZONE,
                'targetLink': CLONE_P + f'zones/{clone.ZONE}/instances/{name}', 'targetId': '7', 'status': 'RUNNING'}
        args = dict(kind='insert', collection='instances', name=name, request_id=request, target_id='7',
                    done=False, strict=True)
        self.assertIs(clone.check_operation(good, **args), good)
        for field, value in (('kind', None), ('id', None), ('id', 'abc'), ('zone', None),
                             ('error', {'errors': [{'code': 'X'}]}), ('httpErrorStatusCode', 500)):
            with self.subTest(field), self.assertRaises(clone.Mismatch):
                clone.check_operation({k: v for k, v in dict(good, **{field: value}).items() if v is not None}, **args)
        with self.assertRaises(clone.Mismatch):
            clone.check_operation(good, **dict(args, op_id='9002'))
        with self.assertRaises(clone.Mismatch):
            clone.check_operation(good, **dict(args, op_name='op-2'))

    # ---- 6. trusted runtime and exact unit contract
    def test_unit_argv_is_the_accepted_runtime_and_protected_source_for_all_verbs(self):
        self.assertEqual(clone.RUNTIME_PYTHON, '/home/ubuntu/.local/opt/labapp-cpython-3.12.16-20261026/python/bin/python3.12')
        self.assertEqual(clone.PROTECTED_SOURCE, '/home/ubuntu/.local/share/labapp-trial-egress-349/source')
        for verb in ('run', 'watch', 'cleanup'):
            with self.subTest(verb):
                argv = clone.unit_argv(self.manifest, self.world.tmp, self.sha, verb)
                self.assertEqual(argv[:5], [clone.RUNTIME_PYTHON, '-I', '-B', '-c', clone.BOOTSTRAP])
                self.assertIn(clone.PROTECTED_SOURCE, clone.BOOTSTRAP)
                self.assertNotIn('/usr/bin/python3', ' '.join(argv))
                self.assertNotIn('-m', argv)
                self.assertFalse(any(' ' in part for part in argv))
                self.assertEqual(argv[5:9], [verb, '--workdir', self.world.tmp, '--owner-unit'])
                self.assertEqual(argv[-2:], ['--manifest-sha256', self.sha])
        self.assertEqual(self.info['owner_exec_start'], clone.unit_argv(self.manifest, self.world.tmp, self.sha, 'run'))
        self.assertEqual(self.info['watchdog_exec_start'], clone.unit_argv(self.manifest, self.world.tmp, self.sha, 'watch'))
        self.assertEqual(self.info['owner_unit'], 'labapp-clone-run-' + self.manifest['name'][-12:] + '.service')
        self.assertEqual((self.info['runtime']['python'], self.info['runtime']['source']),
                         (clone.RUNTIME_PYTHON, clone.PROTECTED_SOURCE))
        with self.assertRaises(clone.Refused):
            clone.unit_argv(self.manifest, self.world.tmp, self.sha, 'sh')

    def test_unit_verification_requires_the_exact_interpreter_source_argv_user_and_kill_policy(self):
        def argv(verb):
            return clone.unit_argv(self.manifest, self.world.tmp, self.sha, verb)
        exec_line = self.world.exec_line
        run, watch = argv('run'), argv('watch')
        cases = [
            ('owner', {'ExecStart': exec_line(['/usr/bin/python3'] + run[1:])}),            # unqualified system 3.10
            ('owner', {'ExecStart': exec_line(run + ['--extra'])}),                         # superset: a substring check passes
            ('owner', {'ExecStart': exec_line([run[0]] + run[2:])}),                        # no -I
            ('owner', {'ExecStart': exec_line(run, path='/usr/bin/python3')}),              # path != runtime
            ('owner', {'ExecStart': exec_line(run) + ' ' + exec_line(run)}),                # two ExecStart entries
            ('owner', {'ExecStart': exec_line(run[:-1] + ['0' * 64])}),                     # other manifest digest
            ('owner', {'User': 'root'}), ('owner', {'WorkingDirectory': '/tmp'}), ('owner', {'Restart': 'always'}),
            ('owner', {'KillMode': 'control-group'}), ('owner', {'KillMode': 'process'}),
            ('owner', {'SendSIGKILL': 'no'}), ('owner', {'TimeoutStopUSec': 'infinity'}),
            ('owner', {'ExecStartPre': '{ path=/bin/true ; argv[]=/bin/true ; }'}),
            ('owner', {'LoadState': 'not-found'}), ('owner', {'Id': 'other.service'}),
            ('owner', {'MainPID': '1'}), ('owner', {'ControlGroup': '/system.slice/other.service'}),
            ('owner', {'ActiveState': 'inactive'}), ('owner', {'InvocationID': ''}),
            ('watch', {'ExecStart': exec_line(['/usr/bin/python3'] + watch[1:])}),
            ('watch', {'ExecStart': exec_line(watch[:-1] + ['0' * 64])}),
            ('watch', {'ExecStart': exec_line(run)}),                                       # the owner argv is not the watch
            ('watch', {'User': 'root'}), ('watch', {'Restart': 'on-failure'}), ('watch', {'ActiveState': 'failed'}),
        ]
        for role, change in cases:
            with self.subTest(role=role, change=sorted(change)[0] + str(list(change.values()))[:40]):
                self.fresh_world()
                self.world.unit_override[role] = change
                code, result = self.execute()
                self.assertEqual((code, result['failure']), (1, 'Refused'))
                self.assertEqual(self.world.mutations, [])
                self.assertFalse(self.store.has('insert-intent'))

    def test_cli_binds_the_owner_unit_and_cleanup_quiesces_first(self):
        with patch('builtins.print'):
            self.assertEqual(clone.main(['cleanup', '--workdir', self.world.tmp, '--manifest-sha256', self.sha,
                                         '--owner-unit', 'labapp-clone-run-aaaaaaaaaaaa.service'], self.deps), 2)
        self.assertEqual(self.world.events, [])
        with patch('builtins.print') as output:
            self.assertEqual(clone.main(['cleanup', '--workdir', self.world.tmp, '--manifest-sha256', self.sha,
                                         '--owner-unit', self.world.owner], self.deps), 0)
        self.assertIs(json.loads(output.call_args.args[0])['quiesced'], True)
        self.assertIn('systemctl-stop', self.world.events)

    def test_watch_stops_the_owner_at_the_deadline_by_either_clock(self):
        self.vm_with_op()
        start, rolled, original = self.world.t, [], self.deps.sleep

        def sleep(seconds):
            original(seconds)
            if self.world.t - start > 600 and not rolled:   # the wall clock is rolled back mid-watch
                rolled.append(True)
                self.world.wall_offset -= 3 * 3600
        self.deps.sleep = sleep
        self.assertEqual(clone.watch(self.world.tmp, self.sha, self.deps, passes=1), 0)
        self.assertLess(self.world.t - start, clone.WORK_SECONDS + 600)   # the monotonic bound fired, not 3 h later
        self.assertEqual(self.world.timeline[0], 'systemctl-stop')
        self.assertEqual((self.world.vms, self.world.disks), ({}, {}))


class PrivateCloneLeadIntegration(CloneCase):
    def test_cancel_during_real_master_start_closes_original_group_and_preserves_primary(self):
        import socket
        for boundary in ('record', 'check'):
            for closes in (True, False):
                with self.subTest(boundary=boundary, closes=closes):
                    self.fresh_world()
                    run = clone.Run(self.world.tmp, self.manifest, self.sha, self.deps, self.unit)
                    run.ids = {'vm_id': '123', 'boot_id': '456'}
                    directory = Path(self.world.tmp) / 'b1'
                    directory.mkdir(mode=0o700)
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    self.addCleanup(sock.close)
                    sock.bind(str(directory / 'master.sock'))
                    group = Mock(outcome=None)
                    group.status.return_value = None
                    group.close.return_value = closes
                    self.deps.master_factory = None
                    self.deps.popen = Mock(return_value=SimpleNamespace(pid=999999))
                    cancellation = host.HostCancelled(signal.SIGTERM)
                    original = run.store.create

                    def create(kind, value):
                        if boundary == 'record' and kind.startswith('master-'):
                            raise cancellation
                        return original(kind, value)

                    check = patch.object(clone.CloneMaster, 'check', side_effect=cancellation) \
                        if boundary == 'check' else nullcontext()
                    window = clone.Window(self.deps, run.budget, self.world.wall() + 1200,
                                          self.deps.mono() + 1200)
                    with patch.object(clone.owned_process, 'OwnedGroup', return_value=group), \
                            patch.object(run.store, 'create', side_effect=create), check:
                        with self.assertRaises(host.HostCancelled) as caught:
                            run.start_master(1, directory, 'ubuntu', window)
                    self.assertIs(caught.exception, cancellation)
                    self.deps.popen.assert_called_once()
                    group.close.assert_called_once()
                    self.assertEqual(len(run.unclosed), 0 if closes else 1)
                    self.assertEqual(run.cleaner.quiet(), closes)

    def test_cancelled_start_with_unclosed_group_cannot_publish_closed_cleanup(self):
        world = self.world

        class CancelledMaster(CloneFakeMaster):
            def start(self, window):
                super().start(window)
                raise host.HostCancelled(signal.SIGTERM)

        world.close_ok = False
        self.deps.master_factory = lambda *a, **k: CancelledMaster(world, *a, **k)
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (143, 'cancelled'))
        self.assertIn('master-close', world.events)
        self.assertFalse(result['cleanup']['closed'])
        self.assertFalse(self.store.has('closed'))
        self.assertEqual(self.count('reset'), 0)

    def test_late_remote_answers_do_not_publish_checkpoint_or_stop_or_reset(self):
        for boundary in ('readiness', 'stop', 'offline'):
            with self.subTest(boundary=boundary):
                self.fresh_world()
                world, crossed = self.world, []

                class LateMaster(CloneFakeMaster):
                    def remote(self, key, window, cap=30):
                        raw = super().remote(key, window, cap)
                        hit = ((boundary == 'readiness' and key == 'summary')
                               or (boundary == 'stop' and key == 'stop-verified')
                               or (boundary == 'offline' and key == 'summary'
                                   and 'stop-verified' in world.events))
                        if hit and not crossed:
                            crossed.append(True)
                            world.wall_offset += 1201  # access expires; overall 45m still has time
                        return raw

                self.deps.master_factory = lambda *a, **k: LateMaster(world, *a, **k)
                code, result = self.execute()
                self.assertTrue(crossed)
                self.assertEqual((code, result['failure']), (1, 'Uncertain'), result)
                self.assertFalse(self.store.has('stopped-1'))
                if boundary == 'readiness':
                    self.assertFalse(self.store.has('checkpoint-1'))
                self.assertEqual(self.count('reset'), 0)
                self.assert_disposed(result)

    def test_real_remote_rechecks_original_access_window_after_command(self):
        for clock in ('wall_offset', 'mono_offset'):
            with self.subTest(clock=clock):
                self.fresh_world()
                budget = clone.Budget(self.manifest, self.deps)
                window = clone.Window(self.deps, budget, self.world.wall() + 1200,
                                      self.deps.mono() + 1200)
                master = clone.CloneMaster(self.world.tmp, self.manifest['name'], '123', 'ubuntu', self.deps)

                def remote_result(*args, **kwargs):
                    setattr(self.world, clock, getattr(self.world, clock) + 1201)
                    return b'late answer'

                self.deps.runner = remote_result
                with patch.object(master, 'check'):
                    with self.assertRaises(clone.Uncertain):
                        master.remote('summary', window)

    def test_systemctl_empty_command_omission_does_not_hide_configured_commands(self):
        commands = ('ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecReload')
        props = self.world.unit_props(self.world.owner)
        omitted = {k: v for k, v in props.items() if k not in commands}

        def show(fields):
            return '\n'.join(k + '=' + v for k, v in fields.items()).encode()

        parsed = clone.parse_unit_show(show(omitted))
        self.units().check(parsed, 'owner')
        for command in commands:
            with self.subTest(command=command):
                configured = dict(omitted, **{command: self.world.exec_line(['/usr/bin/true'])})
                parsed = clone.parse_unit_show(show(configured))
                with self.assertRaises(clone.Refused):
                    self.units().check(parsed, 'owner')
        for required in ('User', 'ExecStart', 'KillMode'):
            with self.subTest(missing=required):
                missing = dict(omitted)
                del missing[required]
                with self.assertRaises(clone.Refused):
                    clone.parse_unit_show(show(missing))

    def test_uncertain_guest_attribute_child_is_not_retried_or_reported_closed(self):
        original, attempts = self.deps.runner, []
        error = guest.Failure('synthetic child closure unresolved', 1)
        error.cleanup_uncertain = True

        def runner(argv, *args, **kwargs):
            if 'get-guest-attributes' in argv and not attempts:
                attempts.append(True)
                raise error
            return original(argv, *args, **kwargs)

        self.deps.runner = runner
        code, result = self.execute()
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['cleanup']['closed'])
        self.assertFalse(self.store.has('closed'))
        self.assertEqual(attempts, [True])
        self.assertNotIn('master-start', self.world.events)
        self.assertEqual(self.count('reset'), 0)
        # The obligation can close only through the separate owner-unit containment proof.
        self.world.owner_state = dict(self.world.INACTIVE_FIELDS)
        self.world.cgroup_procs([])
        self.assertTrue(self.independent().run()['closed'])

    def test_uncertain_startup_check_is_sticky_after_the_master_itself_closes(self):
        import socket
        directory = Path(self.world.tmp) / 'b1'
        directory.mkdir(mode=0o700)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.bind(str(directory / 'master.sock'))
        original, attempts = self.deps.runner, []
        error = guest.Failure('synthetic subordinate SSH closure unresolved', 1)
        error.cleanup_uncertain = True

        def runner(argv, *args, **kwargs):
            if argv[0] == '/usr/bin/ssh' and '-O' in argv:
                attempts.append(True)
                if len(attempts) == 1:
                    raise error
            return original(argv, *args, **kwargs)

        self.deps.runner = runner
        self.deps.master_factory = None
        self.deps.popen = Mock(return_value=SimpleNamespace(pid=999999))
        run = clone.Run(self.world.tmp, self.manifest, self.sha, self.deps, self.unit)
        run.ids = {'vm_id': '123', 'boot_id': '456'}
        group = Mock(outcome=None)
        group.status.return_value = None
        group.close.return_value = True
        window = clone.Window(self.deps, run.budget, self.world.wall() + 1200, self.deps.mono() + 1200)
        with patch.object(clone.owned_process, 'OwnedGroup', return_value=group):
            with self.assertRaises(guest.Failure) as caught:
                run.start_master(1, directory, 'ubuntu', window)
        self.assertIs(caught.exception, error)
        self.deps.popen.assert_called_once()
        group.close.assert_called_once()
        self.assertEqual(attempts, [True])
        self.assertEqual(run.unclosed, [])             # main master closure alone is insufficient
        self.assertTrue(run.command_uncertain)
        self.assertFalse(run.cleaner.quiet())
        with self.assertRaises(clone.Uncertain):
            run.gate()


# ------------------------------------------------------------------------------ student pilot (#550) ---
# AUTHOR TESTS: NOT RUN by the author. Synthetic cache/source/guest only; no cloud, SSH, kubectl or credential access.
PILOT_UID = '11111111-2222-3333-4444-555555555555'


def pilot_report(**change):
    value = {'agents': 7, 'cleanup': 'removed', 'code': 'ok', 'config': 'installed', 'packages': 'installed',
             'phase': 'done', 'plugin': 'installed', 'status': 'passed', 'vpc_uid': PILOT_UID}
    value.update(change)
    return json.dumps(value, sort_keys=True).encode() + b'\n'


class PilotFakeMaster(CloneFakeMaster):
    def remote(self, key, window, cap=30, extra=()):
        world = self.world
        if not key.startswith('pilot-'):
            if key == 'summary' and getattr(world, 'ready_delay', 0) and not getattr(world, 'ready_applied', False):
                world.ready_applied = True
                world.t += world.ready_delay      # slow first-boot startup: BOTH clocks advance
            return super().remote(key, window, cap)
        window.remaining()
        world.events.append(key)
        world.pilot_calls.append({'key': key, 'cap': cap, 'extra': tuple(extra), 'window': window,
                                  'wall': world.wall()})
        if world.pilot_raise and world.pilot_raise[0] == key:
            raise world.pilot_raise[1]
        hook = getattr(world, 'pilot_after', {}).get(key)
        if hook:
            hook()
        return {'pilot-incoming': b'', 'pilot-stage': clone.PILOT_STAGED + b'\n',
                'pilot-run': world.pilot_report}[key]

    def transfer(self, window, names, cap):
        window.remaining()
        self.world.events.append('pilot-transfer')
        self.world.pilot_calls.append({'key': 'pilot-transfer', 'cap': cap, 'names': list(names), 'window': window,
                                       'wall': self.world.wall()})
        hook = getattr(self.world, 'pilot_after', {}).get('pilot-transfer')
        if hook:
            hook()


class PilotCase(CloneCase):
    """Armed with ``--student-pilot`` over a synthetic cache and protected source."""
    NAMES = ('hhfctl.tar.gz', 'libonig5.deb', 'libjq1.deb', 'jq.deb')

    def setUp(self):
        self.cache = tempfile.mkdtemp(prefix='pcache', dir='/tmp')
        self.source = tempfile.mkdtemp(prefix='psrc', dir='/tmp')
        os.chmod(self.cache, 0o700)
        self.addCleanup(shutil.rmtree, self.cache, True)
        self.addCleanup(shutil.rmtree, self.source, True)
        self.write_cache()
        provision = Path(self.source, 'build', 'provision')
        provision.mkdir(parents=True)
        for name in clone.pilot_guest.SOURCE_NAMES:
            (provision / name).write_text('# public source ' + name + '\n')
            os.chmod(provision / name, 0o644)
        paths = dict(pilot_cache=self.cache, pilot_source=self.source)
        original = clone.arm
        patcher = patch.object(clone, 'arm', lambda directory, deps: original(directory, replace(deps, **paths), pilot=True))
        patcher.start()
        super().setUp()
        patcher.stop()
        world = self.world
        world.pilot_calls, world.pilot_raise, world.pilot_report = [], None, pilot_report()
        self.deps = replace(self.deps, master_factory=lambda *a, **k: PilotFakeMaster(world, *a, **k), **paths)

    def write_cache(self):
        pins = []
        for name in self.NAMES:
            raw = (name + '-synthetic-bytes').encode()
            Path(self.cache, name).write_bytes(raw)
            os.chmod(Path(self.cache, name), 0o600)
            pins.append((name, len(raw), hashlib.sha256(raw).hexdigest()))
        patcher = patch.object(clone.pilot_guest, 'CACHE_PINS', tuple(pins))
        patcher.start()
        self.addCleanup(patcher.stop)

    def fresh_world(self):
        """Re-arm a new world/workdir; the synthetic cache and source stay as the test left them."""
        shutil.rmtree(self.world.tmp, True)
        shutil.rmtree(self.world.proc, True)
        shutil.rmtree(self.world.cgroups, True)
        paths = dict(pilot_cache=self.cache, pilot_source=self.source)
        original = clone.arm
        with patch.object(clone, 'arm', lambda directory, deps: original(directory, replace(deps, **paths), pilot=True)):
            CloneCase.setUp(self)
        world = self.world
        world.pilot_calls, world.pilot_raise, world.pilot_report = [], None, pilot_report()
        self.deps = replace(self.deps, master_factory=lambda *a, **k: PilotFakeMaster(world, *a, **k), **paths)

    def sources(self):
        return {n: hashlib.sha256(Path(self.source, 'build', 'provision', n).read_bytes()).hexdigest()
                for n in clone.pilot_guest.SOURCE_NAMES}

    def calls(self, key):
        return [c for c in self.world.pilot_calls if c['key'] == key]


class StudentPilotHost(PilotCase):
    def test_arm_binds_the_inputs_and_keeps_every_other_bound(self):
        self.assertEqual(self.info['student_pilot']['cap_seconds'], clone.PILOT_SECONDS)
        self.assertEqual(self.manifest['student_pilot'], self.info['student_pilot'])
        self.assertEqual(self.manifest['student_pilot']['inputs_sha256'], clone.pilot_inputs(self.deps)['sha256'])
        admitted = clone.stamp(self.manifest['admitted_at'])
        self.assertEqual((clone.stamp(self.manifest['work_deadline']) - admitted,
                          clone.stamp(self.manifest['termination']) - admitted), (45 * 60, 60 * 60))
        self.assertEqual((clone.KEY_SECONDS, clone.READY_SECONDS), (20 * 60, 13 * 60))

    def test_manifest_binding_is_closed(self):
        m = self.manifest
        for change in ({'cap_seconds': clone.PILOT_SECONDS + 1}, {'cap_seconds': True}, {'inputs_sha256': 'z' * 64},
                       {'inputs_sha256': 'a' * 63}, {'schema': 2}, {'extra': 1}):
            with self.subTest(change), self.assertRaises(clone.Refused):
                clone.check_manifest(dict(m, student_pilot=dict(m['student_pilot'], **change)))
        with self.assertRaises(clone.Refused):
            clone.check_manifest(dict(m, student_pilot=None))
        with self.assertRaises(clone.Refused):
            clone.check_manifest(dict(m, other=1))
        pilotless = {k: v for k, v in m.items() if k != 'student_pilot'}
        self.assertIs(clone.check_manifest(pilotless), pilotless)       # historical manifests stay valid

    def test_happy_pilot_runs_once_after_ready_and_before_the_first_stop(self):
        code, result = self.execute()
        self.assertEqual((code, result['status']), (0, 'passed'), result)
        events = self.world.events
        order = ['pilot-incoming', 'pilot-transfer', 'pilot-stage', 'pilot-run']
        for key in order:
            self.assertEqual(events.count(key), 1, key)
        positions = [events.index(k) for k in order]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(events.index('master-start'), positions[0])
        self.assertLess(positions[-1], events.index('stop-verified'))
        self.assertLess(positions[-1], events.index('reset'))
        self.assertEqual(events.count('stop-verified'), 2)
        self.assertEqual(result['pilot'], json.loads(pilot_report()))
        self.assertTrue(self.store.has('pilot-intent'))
        self.assertEqual(self.store.read('pilot-result')['status'], 'passed')
        self.assertEqual(self.world.mutations,
                         ['insert', 'import', 'delete-key', 'reset', 'import', 'delete-key', 'delete-vm'])
        self.assert_disposed(result)

    def test_only_fixed_inputs_and_digests_cross_the_channel(self):
        self.execute()
        (transfer,) = self.calls('pilot-transfer')
        names = [n for n, _ in transfer['names']]
        self.assertEqual(names, [p[0] for p in clone.pilot_guest.CACHE_PINS] + list(clone.pilot_guest.SOURCE_NAMES))
        self.assertEqual([str(p) for _, p in transfer['names'][:4]], [str(Path(self.cache, n)) for n in names[:4]])
        self.assertEqual([str(p) for _, p in transfer['names'][4:]],
                         [str(Path(self.source, 'build', 'provision', n)) for n in names[4:]])
        (stage,) = self.calls('pilot-stage')
        self.assertEqual(stage['extra'], tuple(self.sources()[n] for n in clone.pilot_guest.SOURCE_NAMES))
        for key in ('pilot-incoming', 'pilot-run'):
            self.assertEqual(self.calls(key)[0]['extra'], ())

    def test_pilot_uses_the_original_window_and_keeps_the_stop_reserve(self):
        self.execute()
        access_end = int(self.store.read('a1-intent')['expiration_usec']) / 1_000_000
        intent = self.store.read('pilot-intent')
        self.assertLessEqual(intent['budget'], clone.PILOT_SECONDS)
        self.assertGreaterEqual(intent['budget'], clone.PILOT_MIN_SECONDS)
        for call in self.world.pilot_calls:
            self.assertLessEqual(call['window'].end_wall - call['wall'], clone.PILOT_SECONDS)
            # the ORIGINAL stop minimum (not the 360 s cap) plus teardown always remain after the pilot window
            self.assertLessEqual(call['window'].end_wall + clone.PILOT_RESERVE_SECONDS, access_end + 1)
        self.assertEqual(self.calls('pilot-run')[0]['cap'], clone.PILOT_RUN_SECONDS)

    def test_the_budget_constants_are_coherent_and_shorter_than_the_host_cap(self):
        g = pilot_guest = clone.pilot_guest
        self.assertLessEqual(clone.PILOT_SECONDS, 240)
        self.assertEqual(clone.PILOT_RESERVE_SECONDS, 120 + 30)             # original STOP_MIN_SECONDS + TEARDOWN
        self.assertEqual((clone.STOP_MIN_SECONDS, clone.TEARDOWN_SECONDS, clone.STOP_SECONDS), (120, 30, 360))
        self.assertEqual((clone.KEY_SECONDS, clone.READY_SECONDS), (20 * 60, 13 * 60))
        self.assertLess(g.TOTAL_SECONDS, clone.PILOT_RUN_SECONDS)             # guest total inside the host run cap
        self.assertLessEqual(clone.PILOT_INCOMING_SECONDS + clone.PILOT_TRANSFER_SECONDS + clone.PILOT_STAGE_SECONDS
                             + clone.PILOT_RUN_SECONDS, clone.PILOT_SECONDS)   # sequential caps fit the cap
        self.assertEqual(clone.PILOT_MIN_SECONDS, clone.PILOT_INCOMING_SECONDS + clone.PILOT_TRANSFER_SECONDS
                         + clone.PILOT_STAGE_SECONDS + clone.PILOT_RUN_SECONDS)
        self.assertLessEqual(clone.PILOT_MIN_SECONDS, clone.PILOT_SECONDS)
        # at the SLOWEST allowed readiness the 20 min key still leaves room for the minimum pilot and the reserve
        self.assertGreaterEqual(clone.KEY_SECONDS - clone.READY_SECONDS - clone.PILOT_RESERVE_SECONDS,
                                clone.PILOT_MIN_SECONDS)

    def readiness(self, delay):
        """First strict ready checkpoint ``delay`` s after the key import (both clocks); the fake's two 10 s polls
        are part of that time."""
        self.world.ready_delay = delay - 20
        return self.execute()

    def test_realistic_eleven_and_thirteen_minute_readiness_still_fit_the_capped_pilot(self):
        for minutes_seconds in (11 * 60, 12 * 60, 13 * 60 - 30):
            with self.subTest(ready_after=minutes_seconds):
                self.fresh_world()
                code, result = self.readiness(minutes_seconds)
                self.assertEqual((code, result['status']), (0, 'passed'), result)
                access_end = int(self.store.read('a1-intent')['expiration_usec']) / 1_000_000
                intent = self.store.read('pilot-intent')
                self.assertEqual(intent['budget'], clone.PILOT_SECONDS)
                for call in self.world.pilot_calls:
                    self.assertLessEqual(call['window'].end_wall + clone.PILOT_RESERVE_SECONDS, access_end + 1)
                    self.assertLessEqual(call['window'].end_wall - call['wall'], clone.PILOT_SECONDS)
                self.assertEqual(self.world.events.count('stop-verified'), 2)       # the unchanged stop gates still ran
                self.assert_disposed(result)

    def test_late_readiness_refuses_before_any_staging_or_guest_mutation(self):
        # Only extended readiness (patched here) can reach a first-ready point this late; the pilot gate must hold.
        late = clone.KEY_SECONDS - clone.PILOT_RESERVE_SECONDS - clone.PILOT_MIN_SECONDS + 5
        with patch.object(clone, 'READY_SECONDS', clone.KEY_SECONDS - 10):
            code, result = self.readiness(late)
        self.assertEqual((code, result['status'], result['phase']), (1, 'failed', 'pilot'))
        self.assertFalse([e for e in self.world.events if e.startswith('pilot-')])    # no incoming dir, no transfer
        self.assertEqual(self.world.pilot_calls, [])
        self.assertFalse(self.store.has('pilot-intent'))
        self.assertNotIn('stop-verified', self.world.events)
        self.assert_disposed(result)
        # five seconds earlier the minimum still fits and the pilot proceeds
        self.fresh_world()
        with patch.object(clone, 'READY_SECONDS', clone.KEY_SECONDS - 10):
            code, result = self.readiness(late - 60)
        self.assertEqual((code, result['status']), (0, 'passed'), result)
        self.assertGreaterEqual(self.store.read('pilot-intent')['budget'], clone.PILOT_MIN_SECONDS)

    def test_wall_or_monotonic_crossing_during_the_pilot_stops_the_next_step(self):
        for clock in ('wall_offset', 'mono_offset'):
            for after in ('pilot-incoming', 'pilot-transfer'):
                with self.subTest(clock=clock, after=after):
                    self.fresh_world()
                    world = self.world
                    world.pilot_after = {after: lambda: setattr(world, clock, getattr(world, clock) + 1300)}
                    code, result = self.execute()
                    self.assertEqual((code, result['status']), (1, 'failed'))
                    later = {'pilot-incoming': ('pilot-transfer', 'pilot-stage', 'pilot-run'),
                             'pilot-transfer': ('pilot-stage', 'pilot-run')}[after]
                    self.assertFalse([e for e in world.events if e in later], world.events)
                    self.assertNotIn('stop-verified', world.events)
                    self.assertEqual(self.store.read('pilot-result')['status'], 'failed')
                    self.assert_disposed(result)

    def test_insufficient_time_for_the_reserve_refuses_before_the_pilot_and_stop(self):
        with patch.object(clone, 'PILOT_MIN_SECONDS', 10 * 60 + 600):
            code, result = self.execute()
        self.assertEqual((code, result['status'], result['phase']), (1, 'failed', 'pilot'))
        self.assertFalse([e for e in self.world.events if e.startswith('pilot-')])
        self.assertNotIn('stop-verified', self.world.events)
        self.assert_disposed(result)

    def test_a_failed_pilot_is_a_primary_failure_with_exact_cleanup(self):
        for report in (pilot_report(status='failed', code='refused', phase='config', cleanup='not-needed'),
                       pilot_report(cleanup='preserved'), pilot_report(cleanup='uncertain'),
                       pilot_report(agents=6), pilot_report(vpc_uid=''), pilot_report(plugin='-')):
            with self.subTest(report=report):
                self.fresh_world()
                self.world.pilot_report = report
                code, result = self.execute()
                self.assertEqual((code, result['status'], result['failure'], result['phase']),
                                 (1, 'failed', 'Refused', 'pilot'))
                self.assertNotIn('stop-verified', self.world.events)
                self.assertEqual(result['pilot'], json.loads(report))
                self.assertTrue(self.store.has('pilot-result'))
                self.assert_disposed(result)

    def test_malformed_or_oversized_reports_are_refused_and_not_echoed(self):
        extra = json.loads(pilot_report())
        extra['note'] = 'x'
        for report in (b'', b'not json', b'{"event":"done"}', json.dumps(extra).encode(),
                       pilot_report(code='zzz'), pilot_report(vpc_uid='not-a-uid'), pilot_report(agents=True),
                       b'x' * (clone.PILOT_REPORT_LIMIT + 1), pilot_report().replace(b'ok', b'\xc3\xa9'),
                       b'{"status":"passed","status":"passed"}'):
            with self.subTest(report=report[:40]):
                self.fresh_world()
                self.world.pilot_report = report
                code, result = self.execute()
                self.assertEqual((code, result['status']), (1, 'failed'))
                self.assertEqual(self.store.read('pilot-result')['status'], 'failed')
                self.assertNotIn('not json', json.dumps(result))
                self.assert_disposed(result)

    def test_remote_failure_timeout_and_cancellation_preserve_the_primary_outcome(self):
        cases = (('pilot-run', guest.Failure('stop refused', 17), 'Failure', 1),
                 ('pilot-stage', clone.Expired('synthetic'), 'Expired', 1),
                 ('pilot-incoming', clone.Uncertain('synthetic'), 'Uncertain', 1),
                 ('pilot-run', host.HostCancelled(signal.SIGTERM), 'cancelled', 143))
        for key, error, failure, exit_code in cases:
            with self.subTest(key=key, failure=failure):
                self.fresh_world()
                self.world.pilot_raise = (key, error)
                code, result = self.execute()
                self.assertEqual((code, result['status'], result['failure']), (exit_code, 'failed', failure))
                self.assertNotIn('stop-verified', self.world.events)
                self.assertIn('master-close', self.world.events)
                self.assertEqual(self.store.read('pilot-result')['status'], 'failed')
                self.assert_disposed(result)

    def test_changed_inputs_after_arm_refuse_before_any_cloud_mutation(self):
        Path(self.cache, 'jq.deb').write_bytes(b'tampered')
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Refused'))
        self.assertEqual(self.world.mutations, [])
        self.assertFalse(self.store.has('insert-intent'))
        Path(self.cache, 'jq.deb').write_bytes(b'jq.deb-synthetic-bytes')
        self.fresh_world()
        Path(self.source, 'build', 'provision', 'student_vpc_pilot.py').write_text('# changed after arm\n')
        code, result = self.execute()
        self.assertEqual((code, result['failure']), (1, 'Refused'))
        self.assertEqual(self.world.mutations, [])

    def test_cache_identity_refusals(self):
        jq, other = Path(self.cache, 'jq.deb'), Path(self.cache, 'libjq1.deb')
        saved = {n: Path(self.cache, n).read_bytes() for n in self.NAMES}
        for mutate in (lambda: os.chmod(self.cache, 0o755), lambda: os.chmod(jq, 0o666),
                       lambda: (jq.unlink(), jq.symlink_to(other)), lambda: (jq.unlink(), os.link(other, jq)),
                       lambda: other.unlink()):
            with self.subTest(mutate=mutate):
                for entry in Path(self.cache).iterdir():
                    entry.unlink()
                os.chmod(self.cache, 0o700)
                for name, raw in saved.items():
                    Path(self.cache, name).write_bytes(raw)
                    os.chmod(Path(self.cache, name), 0o600)
                mutate()
                with self.assertRaises((clone.Refused, FileNotFoundError, guest.Failure)):
                    clone.pilot_inputs(self.deps)

    def test_arm_refuses_without_the_verified_cache_and_leaves_the_workdir_fresh(self):
        directory = tempfile.mkdtemp(prefix='pa', dir='/tmp')
        os.chmod(directory, 0o700)
        self.addCleanup(shutil.rmtree, directory, True)
        Path(self.cache, 'jq.deb').unlink()
        with self.assertRaises((clone.Refused, FileNotFoundError)):
            clone.arm(directory, self.deps, pilot=True)
        self.assertEqual(os.listdir(directory), [])

    def test_remote_commands_are_fixed_and_take_only_hex_digests(self):
        master = clone.CloneMaster(self.world.tmp, self.manifest['name'], '1234', 'sa_user', self.deps)
        digests = tuple('ab' * 32 for _ in clone.pilot_guest.SOURCE_NAMES)
        argv = master.remote_argv('pilot-stage', digests)
        self.assertEqual(shlex.split(argv[-1])[-3:], list(digests))
        self.assertIn('ProxyCommand=/usr/bin/false', argv)
        self.assertEqual(shlex.split(master.remote_argv('pilot-run')[-1])[-2:],
                         [str(clone.pilot_guest.PAYLOAD / 'student_vpc_pilot.py'), 'run'])
        self.assertEqual(shlex.split(master.remote_argv('pilot-incoming')[-1]),
                         ['/usr/bin/mkdir', '-m', '0700', '--', 'labapp-student-pilot-in'])
        for key, extra in (('summary', digests), ('pilot-run', digests), ('pilot-stage', digests[:2]),
                           ('pilot-stage', ('x' * 64,) * 3), ('pilot-stage', ('; id',) * 3),
                           ('pilot-stage', tuple('AB' * 32 for _ in range(3)))):
            with self.subTest(key=key, extra=extra[:1]), self.assertRaises(clone.Refused):
                master.remote_argv(key, extra)
        self.assertEqual({k for k in clone.REMOTE if k.startswith('pilot-')},
                         {'pilot-incoming', 'pilot-stage', 'pilot-run'})

    def test_transfer_is_one_sftp_batch_over_the_original_master_with_no_local_file(self):
        calls = []
        deps = replace(self.deps, runner=lambda argv, seconds, **kw: calls.append((argv, seconds, kw)) or b'')
        master = clone.CloneMaster(self.world.tmp, self.manifest['name'], '1234', 'sa_user', deps)
        master.check = Mock()
        window = clone.Window(deps, clone.Budget(self.manifest, deps), deps.wall() + 600, deps.mono() + 600)
        master.transfer(window, [('a.deb', Path('/cache/a.deb')), ('b.py', Path('/src/b.py'))], 60)
        ((argv, seconds, kw),) = calls
        self.assertEqual(argv[:3], ['/usr/bin/sftp', '-b', '-'])
        self.assertIn('ControlMaster=no', argv)
        self.assertIn('ProxyCommand=/usr/bin/false', argv)
        self.assertEqual(argv[-1], 'labapp-trial-1234')
        self.assertEqual(kw['input_bytes'], b'put /cache/a.deb labapp-student-pilot-in/a.deb\n'
                                            b'put /src/b.py labapp-student-pilot-in/b.py\n')
        self.assertLessEqual(seconds, 60)
        self.assertEqual(master.check.call_count, 2)
        self.assertFalse(list(Path(self.world.tmp).glob('*batch*')))

    def test_production_stage_script_is_built_from_the_real_pins_not_the_fixture(self):
        # The fixture patches CACHE_PINS with fake names; the shipped program keeps the import-time real pins.
        real = clone.PILOT_STAGE_PINS
        self.assertNotEqual(real, clone.pilot_guest.CACHE_PINS)
        self.assertEqual(clone.PILOT_STAGE, clone.pilot_stage_script(real, clone.pilot_guest.PAYLOAD))
        compile(clone.PILOT_STAGE, 'stage', 'exec')
        self.assertNotIn('@', clone.PILOT_STAGE)
        self.assertEqual(clone.PILOT_STAGED, b'student pilot staged')
        self.assertEqual(clone.REMOTE['pilot-stage'][-1], clone.PILOT_STAGE)

    # ---- the REAL staging program, run under synthetic bounded IO (temporary home/destination, small files)
    STAGE_PINS_CONTENT = {'pin-archive.bin': b'a' * 300, 'pin-one.deb': b'one', 'pin-two.deb': b'two',
                          'pin-three.deb': b'three'}

    def stage_world(self):
        root = Path(tempfile.mkdtemp(prefix='stg', dir='/tmp'))
        self.addCleanup(shutil.rmtree, root, True)
        uid = os.getuid() or 12345                       # the program refuses root; a root test run chowns instead
        home, dest = root / 'home', root / 'dest'
        incoming = home / clone.PILOT_INCOMING
        incoming.mkdir(parents=True)
        os.chmod(incoming, 0o700)
        pins = [(n, len(raw), hashlib.sha256(raw).hexdigest()) for n, raw in self.STAGE_PINS_CONTENT.items()]
        sources = {n: ('# source ' + n + '\n').encode() for n in clone.pilot_guest.SOURCE_NAMES}
        for name, raw in {**self.STAGE_PINS_CONTENT, **sources}.items():
            (incoming / name).write_bytes(raw)
            os.chmod(incoming / name, 0o644)
        if os.getuid() == 0:
            for path in (incoming, *incoming.iterdir()):
                os.chown(path, uid, uid)
        digests = [hashlib.sha256(sources[n]).hexdigest() for n in clone.pilot_guest.SOURCE_NAMES]
        script = clone.pilot_stage_script(pins, dest)
        return SimpleNamespace(root=root, home=home, dest=dest, incoming=incoming, pins=pins, sources=sources,
                               digests=digests, script=script, uid=uid)

    def run_stage(self, world, digests=None, uid=None):
        """-> (exit code | exception, stdout). Executes the shipped program text in-process."""
        user = SimpleNamespace(pw_uid=world.uid if uid is None else uid, pw_dir=str(world.home))
        out = io.StringIO()
        argv = ['stage', *(world.digests if digests is None else digests)]
        with patch.dict(os.environ, {'SUDO_USER': 'pilotuser'}), patch('pwd.getpwnam', lambda name: user), \
                patch.object(sys, 'argv', argv), patch('sys.stdout', out):
            try:
                exec(compile(world.script, 'stage', 'exec'), {'__name__': '__stage__'})
                return 0, out.getvalue()
            except SystemExit as error:
                return error.code, out.getvalue()
            except Exception as error:     # the program itself failed closed (e.g. a conflicting destination)
                return error, out.getvalue()

    def test_stage_program_stages_exactly_the_pinned_set_and_consumes_the_incoming_directory(self):
        world = self.stage_world()
        code, out = self.run_stage(world)
        self.assertEqual((code, out.strip().encode()), (0, clone.PILOT_STAGED))
        self.assertEqual(stat.S_IMODE(world.dest.stat().st_mode), 0o700)
        staged = {p.name: p.read_bytes() for p in world.dest.iterdir()}
        self.assertEqual(staged, {**self.STAGE_PINS_CONTENT, **world.sources})
        for path in world.dest.iterdir():
            self.assertEqual((stat.S_IMODE(path.stat().st_mode), path.stat().st_nlink), (0o600, 1))
        self.assertFalse(world.incoming.exists())                         # consumed only after full verification

    def test_stage_program_mismatch_conflict_and_failure_preserve_inputs_and_leave_no_partial_stage(self):
        def tamper_pin(w):
            (w.incoming / 'pin-one.deb').write_bytes(b'ONE')                      # same size, different hash
        def oversize_pin(w):
            (w.incoming / 'pin-archive.bin').write_bytes(b'a' * 301)
        def short_pin(w):
            (w.incoming / 'pin-archive.bin').write_bytes(b'a' * 299)
        def extra_file(w):
            (w.incoming / 'unexpected.txt').write_bytes(b'x')
        def missing_file(w):
            (w.incoming / 'pin-two.deb').unlink()
        def hardlink(w):
            os.link(w.incoming / 'pin-three.deb', w.root / 'second-link')
        cases = [('pin hash', tamper_pin), ('pin larger than pinned', oversize_pin), ('pin smaller than pinned', short_pin),
                 ('unexpected file', extra_file), ('missing file', missing_file), ('extra hard link', hardlink)]
        for label, mutate in cases:
            with self.subTest(label):
                world = self.stage_world()
                mutate(world)
                before = {p.name: p.read_bytes() for p in world.incoming.iterdir()}
                code, out = self.run_stage(world)
                self.assertEqual(code, 3, label)
                self.assertNotIn('staged', out)
                self.assertFalse(world.dest.exists(), label)                     # no partial stage
                self.assertEqual({p.name: p.read_bytes() for p in world.incoming.iterdir()}, before)  # inputs preserved
        for label, digests in (('source digest', ['0' * 64] * 3), ('digest count', ['0' * 64]),
                               ('digest shape', ['G' * 64] * 3)):
            with self.subTest(label):
                world = self.stage_world()
                digests = digests if len(digests) != 3 or label != 'source digest' else \
                    [world.digests[0], '0' * 64, world.digests[2]]
                code, _ = self.run_stage(world, digests)
                self.assertEqual(code, 3)
                self.assertFalse(world.dest.exists())
                self.assertEqual(len(list(world.incoming.iterdir())), 4 + len(world.sources))
        with self.subTest('root user'):
            world = self.stage_world()
            self.assertEqual(self.run_stage(world, uid=0)[0], 3)
            self.assertFalse(world.dest.exists())
        with self.subTest('symlinked input'):
            world = self.stage_world()
            (world.incoming / 'pin-one.deb').unlink()
            (world.incoming / 'pin-one.deb').symlink_to(world.incoming / 'pin-two.deb')
            code, _ = self.run_stage(world)
            self.assertIsInstance(code, OSError)                                # O_NOFOLLOW refuses; nothing published
            self.assertFalse(world.dest.exists())
            self.assertTrue((world.incoming / 'pin-two.deb').exists())

    def test_stage_program_refuses_an_existing_destination_without_touching_it(self):
        world = self.stage_world()
        world.dest.mkdir(mode=0o700)
        (world.dest / 'keep').write_bytes(b'prior stage')
        code, out = self.run_stage(world)
        self.assertIsInstance(code, FileExistsError)
        self.assertEqual({p.name: p.read_bytes() for p in world.dest.iterdir()}, {'keep': b'prior stage'})
        self.assertEqual(len(list(world.incoming.iterdir())), 4 + len(world.sources))   # inputs preserved
        self.assertEqual(out, '')

    @unittest.skipUnless(os.getuid() == 0, 'needs root to create a file owned by another uid')
    def test_stage_program_refuses_input_owned_by_someone_else(self):
        world = self.stage_world()
        os.chown(world.incoming / 'pin-one.deb', world.uid + 1, world.uid + 1)
        self.assertEqual(self.run_stage(world)[0], 3)
        self.assertFalse(world.dest.exists())

    def test_independent_cleanup_after_a_pilot_failure_is_unchanged(self):
        self.world.pilot_raise = ('pilot-run', clone.Expired('synthetic'))
        code, result = self.execute()
        self.assertNotEqual(result['status'], 'passed')
        again = self.independent().run()
        self.assertTrue(again['closed'], again)
        self.assertEqual(self.count('delete-vm'), 1)


class StudentPilotDefaultOff(CloneCase):
    def test_default_arm_has_no_pilot_and_the_run_never_touches_the_pilot_surface(self):
        self.assertNotIn('student_pilot', self.info)
        self.assertNotIn('student_pilot', self.manifest)
        self.assertEqual(set(self.manifest), clone.MANIFEST_FIELDS)
        with patch.object(clone, 'pilot_inputs', side_effect=AssertionError('pilot touched')):
            code, result = self.execute()
        self.assertEqual((code, result['status']), (0, 'passed'), result)
        self.assertNotIn('pilot', result)
        self.assertFalse([e for e in self.world.events if e.startswith('pilot-')])
        self.assertFalse(self.store.has('pilot-intent'))
        self.assertEqual(self.world.events.count('stop-verified'), 2)

    def test_cli_flag_is_arm_only_and_opt_in(self):
        for action in ('run', 'cleanup', 'watch'):
            with self.subTest(action), self.assertRaises(SystemExit), patch('sys.stderr', io.StringIO()):
                clone.main([action, '--workdir', '/x', '--manifest-sha256', '0' * 64, '--owner-unit', 'u',
                            '--student-pilot'], self.deps)
        directory = tempfile.mkdtemp(prefix='pd', dir='/tmp')
        os.chmod(directory, 0o700)
        self.addCleanup(shutil.rmtree, directory, True)
        out = io.StringIO()
        with patch('sys.stdout', out):
            self.assertEqual(clone.main(['arm', '--workdir', directory], self.deps), 0)
        self.assertNotIn('student_pilot', json.loads(out.getvalue()))

    def test_report_vocabulary_matches_the_guest_module(self):
        good = json.loads(pilot_report())
        self.assertEqual(clone.check_pilot_report(pilot_report()), good)
        self.assertTrue(clone.pilot_passed(good))
        self.assertEqual(set(good), set(clone.pilot_guest.RESULT_KEYS))
        self.assertTrue(clone.pilot_guest.UID_RE.fullmatch(good['vpc_uid']))
