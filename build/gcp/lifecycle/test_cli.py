"""Offline trust/composition/preflight and actual inline source-loader tests."""
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import Mock, patch

import yaml

from . import controller as controller_module

from . import cli, spec
from .auth_http import HttpResponse
from .controller import Config, Controller, Outcome, Refused
from .cloud import PolicyCloud
from .fakes import FakeClock, FakeCloud
from .store import MemoryStore

ROOT = Path(__file__).resolve().parents[3]


def event_env(kind='workflow_dispatch'):
    env = {'GITHUB_REPOSITORY': cli.REPOSITORY, 'GITHUB_REF': 'refs/heads/main',
           'GITHUB_EVENT_NAME': kind, 'GITHUB_RUN_ID': '100', 'GITHUB_RUN_ATTEMPT': '1'}
    repo = {'id': cli.REPOSITORY_ID, 'full_name': cli.REPOSITORY,
            'owner': {'id': cli.OWNER_ID}}
    event = {'repository': repo}
    if kind == 'workflow_run':
        event.update(action='completed', workflow_run={
            'id': 100, 'run_attempt': 1, 'status': 'completed', 'event': 'workflow_dispatch',
            'name': cli.CREATOR_NAME, 'path': cli.CREATOR_PATH, 'head_branch': 'main',
            'head_repository': deepcopy(repo), 'head_sha': 'a' * 40})
    return env, event


def preflight_records():
    return [
        {'name': spec.PROJECT, 'quotas': [{'metric': 'CPUS_ALL_REGIONS', 'limit': 96, 'usage': 0}]},
        {'name': spec.REGION, 'quotas': [
            {'metric': metric, 'limit': limit, 'usage': 0}
            for metric, limit in [('CPUS', 200), ('DISKS_TOTAL_GB', 4096)]]},
        *[{'id': image_id, 'name': path.rsplit('/', 1)[-1], 'status': 'READY',
           'diskSizeGb': str(minimum)} for path, image_id, minimum in cli.IMAGES]]


class CliTests(unittest.TestCase):
    def test_fixed_debian_boot_pin_preserves_source_pin(self):
        self.assertEqual(cli.IMAGES, (
            ("projects/debian-cloud/global/images/debian-13-trixie-v20261023",
             "1840322579453583118", 10),
            ("projects/teched-473722/global/images/hedgehog-vaidc-v20260114",
             "7638370619126112785", 300)))

    def test_main_constructs_fixed_thirty_minute_runtime_and_sanitizes_failures(self):
        env, event = event_env()
        with tempfile.TemporaryDirectory() as tmp:
            event_path = Path(tmp) / 'event.json'
            event_path.write_text(json.dumps(event))
            env['GITHUB_EVENT_PATH'] = str(event_path)
            with patch.dict(os.environ, env), patch.object(cli, 'Controller') as factory, \
                    patch.object(cli, 'execute', return_value={'status': 'fixture'}), \
                    patch('builtins.print'):
                self.assertEqual(cli.main(['inspect']), 0)
                cfg = factory.call_args.args[2]
                self.assertEqual(cfg.lease_minutes, 30)
                self.assertEqual(cfg.poll_attempts, 72)
                self.assertEqual(cfg.poll_seconds, 5)
                self.assertEqual(cfg.min_submit_minutes, 1)
                self.assertEqual(cfg.boot_image, cli.BOOT_IMAGE)
                self.assertEqual(cfg.baseline, {})
            with patch.dict(os.environ, env), patch.object(cli, 'Controller') as factory, \
                    patch.object(cli, 'execute', return_value={'status': 'fixture'}), \
                    patch('builtins.print'):
                self.assertEqual(cli.main(['cleanup']), 0)
                self.assertEqual(factory.call_args.args[2].poll_attempts, 30)
            with patch.dict(os.environ, env), \
                    patch.object(cli, 'execute', side_effect=Exception('secret token payload')), \
                    patch('builtins.print') as output:
                self.assertEqual(cli.main(['inspect']), 1)
                self.assertNotIn('secret', str(output.call_args_list))

    def test_duration_and_command_inputs_refused_before_adapter_construction(self):
        for inputs in ({'lease_minutes': 60}, {'duration': '30'},
                       {'command': 'true'}, {'purpose': 'source-inspection'}):
            with self.subTest(inputs=inputs), tempfile.TemporaryDirectory() as tmp:
                env, event = event_env()
                event['inputs'] = inputs
                path = Path(tmp) / 'event.json'
                path.write_text(json.dumps(event))
                env['GITHUB_EVENT_PATH'] = str(path)
                with patch.dict(os.environ, env), patch.object(cli, 'Controller') as factory, \
                        patch.object(cli, 'GcsSlotStore') as store, \
                        patch.object(cli, 'ComputeRestTransport') as compute, \
                        patch('builtins.print'):
                    self.assertEqual(cli.main(['inspect']), 1)
                factory.assert_not_called()
                store.assert_not_called()
                compute.assert_not_called()

    def test_trusted_events(self):
        for kind in ('schedule', 'workflow_dispatch', 'workflow_run'):
            env, event = event_env(kind)
            cli.trusted_event('cleanup', env, event)
        env, event = event_env()
        cli.trusted_event('inspect', env, event)

    def test_creator_trust_failure_precedes_all_cloud_calls(self):
        for change in ('ref', 'repo', 'inputs', 'event'):
            env, event = event_env()
            if change == 'ref': env['GITHUB_REF'] = 'refs/heads/evil'
            if change == 'repo': event['repository']['id'] = 1
            if change == 'inputs': event['inputs'] = {'command': 'evil'}
            if change == 'event': env['GITHUB_EVENT_NAME'] = 'pull_request'
            controller, preflight = Mock(), Mock()
            with self.assertRaises(Refused):
                cli.execute('inspect', controller, preflight, env, event)
            self.assertEqual(controller.mock_calls, [])
            self.assertEqual(preflight.mock_calls, [])

    def test_workflow_run_negative_trust_fixtures(self):
        fields = {'name': 'evil', 'path': '.github/workflows/evil.yml', 'status': 'in_progress',
                  'event': 'pull_request', 'head_branch': 'evil', 'head_sha': 'bad',
                  'id': True, 'run_attempt': 0,
                  'head_repository': {'id': 1, 'full_name': cli.REPOSITORY}}
        for key, value in fields.items():
            with self.subTest(key=key):
                env, event = event_env('workflow_run')
                event['workflow_run'][key] = value
                with self.assertRaises(Refused): cli.trusted_event('cleanup', env, event)

    def test_creator_composition_and_uncertain_no_retry(self):
        env, event = event_env()
        controller, preflight = Mock(), Mock()
        controller.admit.return_value = {'request_id': 'lease'}
        controller.submit.return_value = Outcome('accepted')
        controller.confirm_created.return_value = Outcome('created')
        with patch.object(cli, 'wait_for_absence', return_value={'status': 'vm-absent'}) as wait:
            self.assertEqual(cli.execute('inspect', controller, preflight, env, event)['status'], 'vm-absent')
            wait.assert_called_once_with(controller, 'lease')
        preflight.check.assert_called_once_with()
        controller.submit.assert_called_once_with('lease')
        controller.confirm_created.assert_called_once_with('lease', timeout_seconds=360)
        controller.reset_mock()
        controller.submit.return_value = Outcome('uncertain', 'secret')
        with self.assertRaises(Refused): cli.execute('inspect', controller, preflight, env, event)
        controller.submit.assert_called_once_with('lease')
        controller.confirm_created.assert_not_called()
        controller.reconcile.assert_not_called()

    def test_completed_creator_cleanup_pins_current_lease(self):
        env, event = event_env('workflow_run')
        controller = Mock()
        controller.store.read.return_value = ({'state': 'ACTIVE', 'run_id': 100,
                                               'attempt': 1, 'request_id': 'lease'}, 4)
        controller.reconcile.return_value = Outcome('released')
        self.assertEqual(cli.execute('cleanup', controller, Mock(), env, event), {'status': 'released'})
        controller.reconcile.assert_called_once_with('lease')
        controller.reset_mock()
        event['workflow_run']['run_attempt'] = 2
        self.assertEqual(cli.execute('cleanup', controller, Mock(), env, event), {'status': 'superseded'})
        controller.reconcile.assert_not_called()

    def test_manual_cleanup_forces_current_and_schedule_is_due_only(self):
        for kind in ('workflow_dispatch', 'schedule'):
            env, event = event_env(kind)
            controller = Mock()
            controller.store.read.return_value = ({'state': 'ACTIVE', 'request_id': 'lease'}, 1)
            controller.reconcile.return_value = Outcome('released')
            cli.execute('cleanup', controller, Mock(), env, event)
            controller.reconcile.assert_called_once_with('lease' if kind == 'workflow_dispatch' else None)

    def test_creator_wait_is_read_only_bounded_and_checks_identity(self):
        controller = Mock()
        controller.store.read.return_value = ({'request_id': 'lease', 'ids': {'instance': '123', 'boot': 'b', 'data': 'd'},
                                               'names': {'instance': 'vm', 'boot': 'boot', 'data': 'data'}, 'deadline': '2026-10-24T23:05:00Z'}, 1)
        controller.cfg.now.return_value = datetime(2026, 10, 24, 23, tzinfo=timezone.utc)
        disks = [{'id': value, 'sourceImageId': image[1]}
                 for value, image in zip(('b', 'd'), cli.IMAGES)]
        controller.cloud.call.side_effect = disks + [{'id': '123', 'scheduling': {'terminationTime': '2026-10-24T23:05:00Z'}}, cli.NotFound()]
        with patch('builtins.print'):
            self.assertIn('vm-absent', cli.wait_for_absence(controller, 'lease')['status'])
        controller.cfg.sleep.assert_called_once_with(5)
        controller.cloud.call.side_effect = lambda resource, verb, name: (
            disks[0 if name == 'boot' else 1] if resource == 'disks' else {'id': '123', 'scheduling': {'terminationTime': '2026-10-24T23:05:00Z'}})
        controller.cloud.call.reset_mock()
        with patch('builtins.print'), self.assertRaisesRegex(Refused, 'fixed wait bound'):
            cli.wait_for_absence(controller, 'lease')
        self.assertEqual(controller.cloud.call.call_count, cli.ABSENCE_POLL_ATTEMPTS + 2)
        controller.cloud.call.side_effect = lambda resource, verb, name: (
            disks[0 if name == 'boot' else 1] if resource == 'disks' else {'id': 'changed'})
        with patch('builtins.print'), self.assertRaisesRegex(Refused, 'identity changed'):
            cli.wait_for_absence(controller, 'lease')

    def test_actual_disk_provenance_mismatch_preserves_cleanup_record(self):
        for field in ('sourceImageId', 'id'):
            controller = Mock()
            record = {'ids': {'instance': 'i', 'boot': 'b', 'data': 'd'},
                      'names': {'instance': 'vm', 'boot': 'boot', 'data': 'data'}}
            original = deepcopy(record)
            disk = {'id': 'b', 'sourceImageId': cli.IMAGES[0][1]}
            disk[field] = 'replacement'
            controller.cloud.call.return_value = disk
            with self.assertRaisesRegex(Refused, 'provenance mismatch'):
                cli.verify_disk_provenance(controller, record)
            self.assertEqual(record, original)
            controller.store.write.assert_not_called()
            self.assertTrue(all(call.args[:2] == ('disks', 'get')
                                for call in controller.cloud.call.call_args_list))

    def test_provenance_failure_after_real_controller_create_retains_owned_cleanup(self):
        clock = FakeClock()
        raw = FakeCloud(clock)
        controller = Controller(MemoryStore(), PolicyCloud(raw, spec.PROJECT, spec.ZONE),
                                Config(boot_image=cli.BOOT_IMAGE, lease_minutes=5,
                                       min_submit_minutes=1, now=clock.now, sleep=clock.sleep))
        env, event = event_env()
        # FakeCloud deliberately has no sourceImageId: missing provenance must
        # fail after recording identities, and must leave cleanup operational.
        with self.assertRaisesRegex(Refused, 'provenance mismatch'):
            cli.execute('inspect', controller, Mock(), env, event)
        record, _ = controller.store.read(controller.cfg.key)
        self.assertEqual(record['state'], 'ACTIVE')
        self.assertTrue(all(record['ids'].values()))
        deadline = datetime.fromisoformat(record['deadline'].replace('Z', '+00:00'))
        reserved = datetime.fromisoformat(record['reserved_at'].replace('Z', '+00:00'))
        self.assertEqual((deadline - reserved).total_seconds(), 300)
        self.assertFalse(any(call[1] == 'delete' for call in raw.calls))
        self.assertEqual(controller.reconcile(record['request_id']).status, 'released')
        self.assertEqual(raw.instances, {})
        self.assertEqual(raw.disks, {})

    def test_incomplete_cleanup_is_failure(self):
        env, event = event_env('schedule')
        controller = Mock()
        for status in ('pending-operation', 'settling', 'blocked', 'cleanup-failed'):
            controller.reconcile.return_value = Outcome(status)
            with self.assertRaises(Refused): cli.execute('cleanup', controller, Mock(), env, event)

    def test_fixed_preflight_requests_and_quota_snapshot(self):
        http = Mock()
        http.request.side_effect = [HttpResponse(200, json.dumps(r).encode()) for r in preflight_records()]
        cli.Preflight(http, lambda: 'fake-token').check()
        self.assertNotIn('E2_CPUS', str(preflight_records()))
        urls = [call.args[1] for call in http.request.call_args_list]
        base = 'https://compute.googleapis.com/compute/v1/'
        self.assertEqual(urls, [base + f'projects/{spec.PROJECT}',
                               base + f'projects/{spec.PROJECT}/regions/{spec.REGION}',
                               *[base + p for p, _, _ in cli.IMAGES]])
        self.assertTrue(all(call.args[0] == 'GET' for call in http.request.call_args_list))

    def test_preflight_rejects_bad_identity_quota_and_http(self):
        for change in ('global_quota', 'shared_cpu_quota', 'disk_quota', 'missing', 'nan', 'duplicate', 'image', 'status', 'size', 'inherited_script'):
            records = preflight_records()
            if change == 'global_quota': records[0]['quotas'][0]['usage'] = 95
            if change == 'shared_cpu_quota': records[1]['quotas'][0]['limit'] = 1
            if change == 'disk_quota': records[1]['quotas'][1]['limit'] = 309
            if change == 'missing': records[1]['quotas'].pop()
            if change == 'nan': records[1]['quotas'][0]['usage'] = float('nan')
            if change == 'duplicate': records[1]['quotas'].append(records[1]['quotas'][0])
            if change == 'inherited_script':
                records[0]['commonInstanceMetadata'] = {'items': [{'key': 'startup-script-url', 'value': 'secret'}]}
            if change == 'image': records[2]['id'] = 'replacement'
            if change == 'status': records[3]['status'] = 'PENDING'
            if change == 'size': records[3]['diskSizeGb'] = '301'
            http = Mock()
            http.request.side_effect = [HttpResponse(200, json.dumps(r).encode()) for r in records]
            with self.subTest(change=change), self.assertRaises(Refused):
                cli.Preflight(http, lambda: 'fake-token').check()
        http = Mock()
        http.request.return_value = HttpResponse(403, b'private server diagnostics')
        with self.assertRaisesRegex(Refused, '^fixed preflight read failed$'):
            cli.Preflight(http, lambda: 'fake-token').check()


class ComponentCliTests(unittest.TestCase):
    def records(self):
        records = preflight_records()[:2]
        records[1]['quotas'] = [
            {'metric': metric, 'usage': 0, 'limit': need}
            for metric, need in [('CPUS', 2), ('N2_CPUS', 2), ('INSTANCES', 1), ('DISKS_TOTAL_GB', 20)]]
        records.append({'id': spec.COMPONENT_IMAGE_ID,
                        'name': spec.COMPONENT_IMAGE.rsplit('/', 1)[-1],
                        'status': 'READY', 'architecture': 'X86_64', 'diskSizeGb': '10'})
        return records

    def check(self, records):
        http = Mock()
        http.request.side_effect = [HttpResponse(200, json.dumps(r).encode()) for r in records]
        cli.Preflight(http, lambda: 'fake', profile=spec.UBUNTU_COMPONENT).check()
        return http

    def test_component_preflight_exact_three_reads_no_source(self):
        http = self.check(self.records())
        urls = [c.args[1] for c in http.request.call_args_list]
        self.assertEqual(urls, ['https://compute.googleapis.com/compute/v1/' + p for p in (
            'projects/' + spec.PROJECT, 'projects/' + spec.PROJECT + '/regions/' + spec.REGION,
            spec.COMPONENT_IMAGE)])
        self.assertNotIn('hedgehog', str(urls))
        self.assertTrue(all(c.args[0] == 'GET' and c.kwargs['timeout'] == 20
                            and c.kwargs['max_bytes'] == 1048576 for c in http.request.call_args_list))

    def test_component_each_quota_required_finite_unique_and_sufficient(self):
        for metric in ('CPUS', 'N2_CPUS', 'INSTANCES', 'DISKS_TOTAL_GB'):
            for failure in ('missing', 'duplicate', 'insufficient', 'nonfinite', 'negative'):
                records = self.records()
                quotas = records[1]['quotas']
                target = next(q for q in quotas if q['metric'] == metric)
                if failure == 'missing': quotas.remove(target)
                if failure == 'duplicate': quotas.append(deepcopy(target))
                if failure == 'insufficient': target['usage'] = 1
                if failure == 'nonfinite': target['limit'] = float('inf')
                if failure == 'negative': target['usage'] = -1
                with self.subTest(metric=metric, failure=failure), self.assertRaises(Refused):
                    self.check(records)

    def test_component_pin_scope_architecture_and_inherited_code_refusals(self):
        mutations = [lambda r: r[0].update(name='foreign'),
                     lambda r: r[1].update(name='foreign'),
                     lambda r: r[2].update(id='replacement'),
                     lambda r: r[2].update(name='other'),
                     lambda r: r[2].update(status='PENDING'),
                     lambda r: r[2].update(architecture='ARM64'),
                     lambda r: r[2].pop('architecture'),
                     lambda r: r[2].update(diskSizeGb='11')]
        mutations += [lambda r, key=key: r[0].update(commonInstanceMetadata={
            'items': [{'key': key, 'value': 'never print this'}]})
            for key in ('startup-script', 'startup-script-url', 'shutdown-script',
                        'shutdown-script-url', 'user-data', 'user-data-encoding')]
        for mutate in mutations:
            records = self.records()
            mutate(records)
            with self.assertRaises(Refused): self.check(records)

    def test_component_main_fixed_configuration_and_preflight(self):
        env, event = event_env()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'event'
            path.write_text(json.dumps(event))
            env['GITHUB_EVENT_PATH'] = str(path)
            with patch.dict(os.environ, env), patch.object(cli, 'Controller') as controller, \
                    patch.object(cli, 'Preflight') as preflight, \
                    patch.object(cli, 'execute', return_value={'status': 'fixture'}), patch('builtins.print'):
                self.assertEqual(cli.main(['component']), 0)
            cfg = controller.call_args.args[2]
            self.assertEqual((cfg.profile, cfg.boot_image, cfg.lease_minutes, cfg.poll_attempts),
                             (spec.UBUNTU_COMPONENT, spec.COMPONENT_IMAGE, 30, 72))
            preflight.assert_called_once_with(profile=spec.UBUNTU_COMPONENT)

    def test_component_trust_failure_before_any_cloud(self):
        for kind in ('pull_request', 'workflow_run', 'schedule'):
            env, event = event_env(kind)
            controller, preflight = Mock(), Mock()
            with self.assertRaises(Refused): cli.execute('component', controller, preflight, env, event)
            self.assertEqual(controller.mock_calls + preflight.mock_calls, [])
        env, event = event_env()
        event['inputs'] = {'profile': spec.INSPECTOR}
        with self.assertRaises(Refused): cli.trusted_event('component', env, event)

    def test_new_and_old_completion_names_all_conclusions_and_no_inputs(self):
        for name in (cli.CREATOR_NAME, cli.LEGACY_CREATOR_NAME):
            for conclusion in ('success', 'failure', 'cancelled', 'timed_out'):
                env, event = event_env('workflow_run')
                event['workflow_run'].update(name=name, conclusion=conclusion)
                self.assertEqual(cli.trusted_event('cleanup', env, event)['name'], name)
                event['inputs'] = {'command': 'forbidden'}
                with self.assertRaises(Refused): cli.trusted_event('cleanup', env, event)

    def test_component_preflight_failure_precedes_admission(self):
        env, event = event_env()
        controller, preflight = Mock(), Mock()
        preflight.check.side_effect = Refused('fixture quota exhausted')
        with self.assertRaises(Refused): cli.execute('component', controller, preflight, env, event)
        self.assertEqual(controller.mock_calls, [])

    def test_all_creator_repository_bindings_fail_before_cloud(self):
        mutations = [lambda env, event: env.update(GITHUB_REF='refs/heads/other'),
                     lambda env, event: env.update(GITHUB_REPOSITORY='foreign/repo'),
                     lambda env, event: event['repository'].update(id=1),
                     lambda env, event: event['repository'].update(full_name='foreign/repo'),
                     lambda env, event: event['repository']['owner'].update(id=1)]
        for mutate in mutations:
            env, event = event_env()
            mutate(env, event)
            controller, preflight = Mock(), Mock()
            with self.assertRaises(Refused): cli.execute('component', controller, preflight, env, event)
            self.assertEqual(controller.mock_calls + preflight.mock_calls, [])

    def test_component_wait_accepts_equivalent_absolute_time_representation(self):
        from .test_profiles import world
        w = world()
        record = w.started()
        instance = next(iter(w.raw.instances.values()))
        instance['scheduling']['terminationTime'] = record['deadline'].replace('Z', '.000+00:00')
        w.cfg.sleep = lambda _seconds: w.raw.instances.clear()
        with patch('builtins.print'):
            self.assertIn('vm-absent', cli.wait_for_absence(w.ctl, record['request_id'])['status'])
        self.assertEqual(w.record()['deadline'], record['deadline'])

    def test_component_actual_create_receipt_and_old_config_cleanup(self):
        from .test_profiles import world
        w = world()
        env, event = event_env()
        real = w.raw.call
        def read_then_absent(resource, verb, **kwargs):
            result = real(resource, verb, **kwargs)
            if resource == 'instances' and verb == 'get' and read_then_absent.done:
                raise cli.NotFound()
            return result
        read_then_absent.done = False
        def mark_receipt(line, **kwargs):
            receipt = json.loads(line)
            self.assertEqual(receipt['status'], 'created')
            self.assertEqual(receipt['profile'], spec.UBUNTU_COMPONENT)
            self.assertEqual(set(receipt['ids']), {'instance', 'boot'})
            self.assertEqual(set(receipt['names']), {'instance', 'boot'})
            self.assertEqual(receipt['deadline'], w.record()['deadline'])
            self.assertEqual(receipt['request_id'], w.record()['request_id'])
            self.assertTrue(kwargs['flush'])
            read_then_absent.done = True
        w.raw.call = read_then_absent
        with patch('builtins.print', side_effect=mark_receipt):
            self.assertIn('vm-absent', cli.execute('component', w.ctl, Mock(), env, event)['status'])
        self.assertFalse(any(c[1] == 'delete' for c in w.raw.calls))
        # Cleanup's default inspector configuration still follows persisted component intent.
        w.raw.call = real
        old = Controller(w.store, w.cloud, Config(boot_image=cli.BOOT_IMAGE,
                        now=w.clock.now, sleep=w.clock.sleep))
        env, event = event_env('workflow_run')
        self.assertEqual(cli.execute('cleanup', old, Mock(), env, event), {'status': 'released'})
        self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))

    def test_component_wait_rejects_changed_deadline_without_mutation(self):
        from .test_profiles import world
        w = world()
        record = w.started()
        instance = next(iter(w.raw.instances.values()))
        instance['scheduling']['terminationTime'] = '2099-01-01T00:00:00Z'
        with patch('builtins.print'), self.assertRaisesRegex(Refused, 'deadline changed'):
            cli.wait_for_absence(w.ctl, record['request_id'])
        self.assertFalse(any(c[1] == 'delete' for c in w.raw.calls))
        self.assertEqual(w.record()['deadline'], record['deadline'])

    def test_component_disk_inventory_and_source_binding_refused(self):
        from .test_profiles import world
        for field, replacement in (('sourceImageId', 'wrong'), ('sourceImage', spec.SOURCE_IMAGE)):
            w = world()
            record = w.started()
            next(iter(w.raw.disks.values()))[field] = replacement
            with patch('builtins.print'), self.assertRaisesRegex(Refused, 'provenance mismatch'):
                cli.wait_for_absence(w.ctl, record['request_id'])
            self.assertFalse(any(c[1] == 'delete' for c in w.raw.calls))
        w = world()
        record = w.started()
        record['ids']['data'] = 'foreign'
        with self.assertRaisesRegex(Refused, 'inventory mismatch'):
            cli.verify_disk_provenance(w.ctl, record)


class PilotBudgetTests(unittest.TestCase):
    def world(self, ready_after, latency=0):
        clock = FakeClock()
        elapsed, pauses = [0.0], []
        def advance(seconds):
            elapsed[0] += seconds
            clock.advance(seconds / 60)
        def sleep(seconds):
            pauses.append(seconds)
            advance(seconds)
        raw = FakeCloud(clock)
        controller = Controller(MemoryStore(), PolicyCloud(raw, spec.PROJECT, spec.ZONE),
                                Config(boot_image=cli.BOOT_IMAGE,
                                       lease_minutes=cli.PILOT_LEASE_MINUTES,
                                       min_submit_minutes=1, poll_attempts=cli.CONFIRM_POLL_ATTEMPTS,
                                       now=clock.now, sleep=sleep))
        request = '11111111-1111-4111-8111-111111111111'
        lease = controller.admit(100, 1, request)
        self.assertEqual(controller.submit(request).status, 'accepted')
        original_call = raw.call
        def timed_call(resource, verb, **kwargs):
            result = original_call(resource, verb, **kwargs)
            if (resource, verb) == ('zoneOperations', 'get'):
                advance(latency)
                result['status'] = 'DONE' if elapsed[0] >= ready_after else 'RUNNING'
            return result
        raw.call = timed_call
        return controller, raw, lease, elapsed, pauses, advance

    def test_observed_four_minute_provisioning_confirms_with_headroom(self):
        controller, raw, lease, elapsed, _, _ = self.world(251)
        with patch.object(controller_module.time, 'monotonic', side_effect=lambda: elapsed[0]):
            outcome = controller.confirm_created(lease['request_id'], timeout_seconds=360)
        self.assertEqual(outcome.status, 'created')
        self.assertGreater(elapsed[0], 150)
        self.assertLess(elapsed[0], 360)
        record, _ = controller.store.read(controller.cfg.key)
        self.assertTrue(all(record['ids'].values()))
        self.assertEqual(record['deadline'], lease['deadline'])
        deadline = datetime.fromisoformat(record['deadline'].replace('Z', '+00:00'))
        self.assertGreater((deadline - controller.cfg.now()).total_seconds(), 240)
        reserved = datetime.fromisoformat(record['reserved_at'].replace('Z', '+00:00'))
        self.assertEqual((deadline - reserved).total_seconds(), 1800)
        self.assertEqual(record['body_hash'], lease['body_hash'])

    def test_slow_confirmation_keeps_occupied_lease_and_original_deadline(self):
        controller, raw, lease, elapsed, _, _ = self.world(361)
        with patch.object(controller_module.time, 'monotonic', side_effect=lambda: elapsed[0]):
            outcome = controller.confirm_created(lease['request_id'], timeout_seconds=360)
        self.assertEqual(outcome.status, 'pending-operation')
        self.assertEqual(elapsed[0], 360)
        record, _ = controller.store.read(controller.cfg.key)
        self.assertEqual(record['state'], 'ACTIVE')
        self.assertEqual(record['deadline'], lease['deadline'])
        self.assertEqual(record['ids'], {'instance': None, 'boot': None, 'data': None})
        self.assertFalse(any(call[1] == 'delete' for call in raw.calls))
        self.assertEqual(sum(call[:2] == ('instances', 'insert') for call in raw.calls), 1)

    def test_request_latency_consumes_budget_and_late_done_is_not_accepted(self):
        for ready_after, latency, expected_calls, expected_pauses in ((999, 30, 11, 10), (0, 400, 1, 0)):
            controller, raw, lease, elapsed, pauses, _ = self.world(ready_after, latency)
            with patch.object(controller_module.time, 'monotonic', side_effect=lambda: elapsed[0]):
                outcome = controller.confirm_created(lease['request_id'], timeout_seconds=360)
            self.assertEqual(outcome.status, 'pending-operation')
            self.assertEqual(sum(call[:2] == ('zoneOperations', 'get') for call in raw.calls), expected_calls)
            self.assertEqual(len(pauses), expected_pauses)
            self.assertLessEqual(elapsed[0], 360 + latency)
            self.assertIsNone(controller.store.read(controller.cfg.key)[0]['ids']['instance'])

    def test_cas_conflict_does_not_restart_confirmation_budget(self):
        controller, raw, lease, elapsed, pauses, advance = self.world(251)
        def competitor(key, _record):
            current, gen = controller.store.read(key)
            controller.store.write(key, current, if_generation_match=gen)
            advance(106)
        controller.store.before_write = competitor
        with patch.object(controller_module.time, 'monotonic', side_effect=lambda: elapsed[0]):
            self.assertEqual(controller.confirm_created(lease['request_id'], timeout_seconds=360).status,
                             'pending-operation')
        self.assertEqual(elapsed[0], 361)
        self.assertIsNone(controller.store.read(controller.cfg.key)[0]['ids']['instance'])

    def test_invalid_confirmation_budget_fails_without_cloud_or_ledger_access(self):
        controller = Controller(Mock(), Mock(), Config(boot_image=cli.BOOT_IMAGE))
        for timeout in (0, -1, True, 3601, 1.5):
            with self.assertRaises(Refused):
                controller.confirm_created('request', timeout_seconds=timeout)
        self.assertEqual(controller.cloud.mock_calls, [])
        self.assertEqual(controller.store.mock_calls, [])

    def test_early_creation_observation_reaches_thirty_minute_expiry(self):
        clock = FakeClock()
        controller = Mock()
        record = {'request_id': 'lease', 'ids': {'instance': 'i', 'boot': 'b', 'data': 'd'},
                  'names': {'instance': 'vm', 'boot': 'boot', 'data': 'data'},
                  'deadline': spec.rfc3339(clock.now() + timedelta(minutes=30))}
        controller.store.read.return_value = (record, 1)
        controller.cfg.now.side_effect = clock.now
        controller.cfg.sleep.side_effect = lambda seconds: clock.advance(seconds / 60)
        start = clock.now()
        def get(resource, verb, name):
            if resource == 'disks':
                index = 0 if name == 'boot' else 1
                return {'id': ('b', 'd')[index], 'sourceImageId': cli.IMAGES[index][1]}
            if (clock.now() - start).total_seconds() >= 1800:
                raise cli.NotFound()
            return {'id': 'i', 'scheduling': {'terminationTime': record['deadline']}}
        controller.cloud.call.side_effect = get
        with patch('builtins.print'):
            self.assertIn('vm-absent', cli.wait_for_absence(controller, 'lease')['status'])
        self.assertEqual((clock.now() - start).total_seconds(), 1800)
        self.assertEqual(controller.cfg.sleep.call_count, 360)

    def test_observation_stops_at_original_deadline_grace_without_extending_lease(self):
        for stalled in (False, True):
            with self.subTest(stalled=stalled):
                clock = FakeClock()
                start = clock.now()
                controller = Mock()
                deadline = spec.rfc3339(start + timedelta(minutes=30))
                record = {'request_id': 'lease', 'ids': {'instance': 'i'},
                          'names': {'instance': 'vm'}, 'deadline': deadline}
                controller.store.read.return_value = (record, 1)
                controller.cfg.now.side_effect = clock.now
                if not stalled:
                    controller.cfg.sleep.side_effect = lambda seconds: clock.advance(seconds / 60)
                controller.cloud.call.return_value = {'id': 'i', 'scheduling': {'terminationTime': deadline}}
                with patch.object(cli, 'verify_disk_provenance'), patch('builtins.print'):
                    with self.assertRaises(Refused):
                        cli.wait_for_absence(controller, 'lease')
                self.assertEqual(record['deadline'], deadline)
                self.assertEqual(controller.store.mock_calls, [unittest.mock.call.read(controller.cfg.key)])
                if stalled:
                    self.assertEqual(controller.cfg.sleep.call_count, cli.ABSENCE_POLL_ATTEMPTS)
                    self.assertEqual(clock.now(), start)
                else:
                    self.assertEqual((clock.now() - start).total_seconds(), 1920)
                    self.assertEqual(controller.cfg.sleep.call_count, 384)


class WorkflowTests(unittest.TestCase):
    @staticmethod
    def import_fetched_cli(root):
        # -I excludes the source checkout, user site and Python environment.
        # Only the actual loader's resulting directory is added to sys.path.
        script = textwrap.dedent('''\
            import pathlib
            import sys
            from unittest.mock import patch

            root = pathlib.Path(sys.argv[1]).resolve()
            sys.path.insert(0, str(root))

            def deny_network(event, args):
                if event.startswith('socket.'):
                    raise AssertionError('isolated loader import attempted network access')

            def deny_clients(frame, event, arg):
                module = frame.f_globals.get('__name__', '')
                if event == 'call' and module.startswith('lifecycle.') and (
                        frame.f_code.co_name == '__init__' or
                        frame.f_code.co_name in ('gcloud_token', 'bearer_headers', 'main')):
                    raise AssertionError('isolated loader import attempted client/auth construction')

            sys.addaudithook(deny_network)
            sys.setprofile(deny_clients)
            with patch('subprocess.Popen', side_effect=AssertionError('no child commands')):
                import lifecycle.cli as cli
                assert pathlib.Path(cli.__file__).resolve() == root / 'lifecycle/cli.py'
                env = {'GITHUB_REPOSITORY': cli.REPOSITORY,
                       'GITHUB_REF': 'refs/heads/main',
                       'GITHUB_EVENT_NAME': 'workflow_dispatch'}
                event = {'repository': {'id': cli.REPOSITORY_ID,
                         'full_name': cli.REPOSITORY, 'owner': {'id': cli.OWNER_ID}}}
                for mode in ('component', 'cleanup'):
                    assert cli.trusted_event(mode, env, event) is None
                event['inputs'] = {'command': 'forbidden'}
                try:
                    cli.trusted_event('component', env, event)
                except cli.Refused:
                    pass
                else:
                    raise AssertionError('fetched CLI accepted command input')
                for name, module in tuple(sys.modules.items()):
                    if name == 'lifecycle' or name.startswith('lifecycle.'):
                        assert pathlib.Path(module.__file__).resolve().parent == root / 'lifecycle'
            sys.setprofile(None)
            print('isolated fetched CLI import and trust validation passed')
        ''')
        return subprocess.run([sys.executable, '-I', '-B', '-c', script, str(root)],
                              cwd=root, env={'PATH': '/usr/bin:/bin', 'HOME': str(root),
                                             'TMPDIR': str(root), 'PYTHONDONTWRITEBYTECODE': '1'},
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              timeout=20, check=False)

    def workflows(self):
        return [yaml.safe_load((ROOT / '.github/workflows' / f'labapp-lifecycle-{m}.yml').read_text())
                for m in ('inspect', 'cleanup')]

    def test_workflow_boundary(self):
        inspect, cleanup = self.workflows()
        self.assertEqual(inspect['name'], cli.CREATOR_NAME)
        self.assertEqual(inspect['on'], {'workflow_dispatch': None})
        self.assertIn('python3 -m lifecycle.cli component', inspect['jobs']['inspect']['steps'][-1]['run'])
        self.assertNotIn('lifecycle.cli inspect', inspect['jobs']['inspect']['steps'][-1]['run'])
        self.assertEqual(cleanup['on']['schedule'], [{'cron': '7,17,27,37,47,57 * * * *'}])
        self.assertEqual(cleanup['on']['workflow_run'],
                         {'workflows': [cli.CREATOR_NAME, cli.LEGACY_CREATOR_NAME], 'types': ['completed'], 'branches': ['main']})
        for workflow, mode, identity in ((inspect, 'inspect', 'creator'), (cleanup, 'cleanup', 'cleanup')):
            self.assertEqual(workflow['permissions'], {'contents': 'read', 'id-token': 'write'})
            job = workflow['jobs'][mode]
            if mode == 'inspect':
                self.assertEqual(job['timeout-minutes'], 36)
                self.assertGreaterEqual(job['timeout-minutes'] * 60,
                                        cli.PILOT_LEASE_MINUTES * 60 + cli.ABSENCE_GRACE_SECONDS + 240)
                self.assertLessEqual(cli.CONFIRM_TIMEOUT_SECONDS + 240, cli.PILOT_LEASE_MINUTES * 60)
            self.assertIn("github.ref == 'refs/heads/main'", job['if'])
            steps = job['steps']
            self.assertEqual(steps[0]['env']['TRUSTED_SHA'], '${{ github.sha }}')
            self.assertIn('mkdir -p "$GITHUB_WORKSPACE"', steps[0]['run'])
            self.assertIn(f'labapp-lc-{identity}@', steps[1]['with']['service_account'])
            self.assertEqual(steps[2]['with']['version'], '540.0.0')
            for step in steps:
                if 'uses' in step: self.assertRegex(step['uses'], r'@[0-9a-f]{40}$')
            self.assertNotIn('checkout', json.dumps(workflow))
            self.assertNotIn('artifact', json.dumps(workflow))
        for required in ('head_repository.id', 'head_repository.owner.id', 'workflow_run.path',
                         'workflow_run.event', 'workflow_run.head_branch', 'workflow_run.status'):
            self.assertIn(required, cleanup['jobs']['cleanup']['if'])

    def test_actual_inline_loader_pins_allowlist_and_preserves_auth_workspace(self):
        for workflow in self.workflows():
            job = next(iter(workflow['jobs'].values()))
            script = job['steps'][0]['run'].split("<<'PYFETCH'\n", 1)[1].rsplit('\nPYFETCH', 1)[0]
            with tempfile.TemporaryDirectory() as tmp:
                credentials = Path(tmp) / 'credentials.json'
                credentials.write_text('unchanged')
                requested = []
                def urlopen(req, timeout):
                    requested.append(req.full_url)
                    path = req.full_url.split('/contents/', 1)[1].split('?')[0]
                    content = (ROOT / path).read_bytes()
                    return io.BytesIO(json.dumps({'type': 'file', 'path': path, 'size': len(content),
                                                 'encoding': 'base64', 'content': base64.b64encode(content).decode()}).encode())
                with patch.dict(os.environ, {'TRUSTED_SHA': 'a' * 40, 'RUNNER_TEMP': tmp, 'GH_TOKEN': 'test'}), \
                        patch('urllib.request.urlopen', side_effect=urlopen):
                    exec(compile(script, '<trusted-loader>', 'exec'), {})
                files = list((Path(tmp) / 'labapp-trusted-lifecycle/lifecycle').iterdir())
                self.assertEqual({p.name for p in files}, {
                    '__init__.py', 'auth_http.py', 'cloud.py', 'compute.py',
                    'controller.py', 'gcs.py', 'spec.py', 'store.py', 'cli.py',
                    'access_records.py', 'oslogin.py'})
                self.assertTrue(all(url.endswith('?ref=' + 'a' * 40) for url in requested))
                self.assertEqual(credentials.read_text(), 'unchanged')
                self.assertEqual((Path(tmp) / 'labapp-trusted-lifecycle/lifecycle/cli.py').read_bytes(),
                                 (ROOT / 'build/gcp/lifecycle/cli.py').read_bytes())
                fetched = Path(tmp) / 'labapp-trusted-lifecycle'
                result = self.import_fetched_cli(fetched)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(),
                                 'isolated fetched CLI import and trust validation passed')
                # Demonstrate this check detects the original omission rather
                # than importing already-loaded modules from this test process.
                for missing in ('access_records.py', 'oslogin.py'):
                    path = fetched / 'lifecycle' / missing
                    content = path.read_bytes()
                    path.unlink()
                    try:
                        result = self.import_fetched_cli(fetched)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('ModuleNotFoundError', result.stderr)
                        self.assertIn('lifecycle.' + path.stem, result.stderr)
                    finally:
                        path.write_bytes(content)
                self.assertEqual(credentials.read_text(), 'unchanged')
