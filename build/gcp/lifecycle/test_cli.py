"""Offline trust/composition/preflight and actual inline source-loader tests."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml

from . import cli, spec
from .auth_http import HttpResponse
from .controller import Outcome, Refused

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
            for metric, limit in [('CPUS', 200), ('E2_CPUS', 24), ('DISKS_TOTAL_GB', 4096)]]},
        *[{'id': image_id, 'name': path.rsplit('/', 1)[-1], 'status': 'READY',
           'diskSizeGb': str(minimum)} for path, image_id, minimum in cli.IMAGES]]


class CliTests(unittest.TestCase):
    def test_main_constructs_fixed_five_minute_runtime_and_sanitizes_failures(self):
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
                self.assertEqual(cfg.lease_minutes, 5)
                self.assertEqual(cfg.min_submit_minutes, 1)
                self.assertEqual(cfg.boot_image, cli.BOOT_IMAGE)
                self.assertEqual(cfg.baseline, {})
            with patch.dict(os.environ, env), \
                    patch.object(cli, 'execute', side_effect=Exception('secret token payload')), \
                    patch('builtins.print') as output:
                self.assertEqual(cli.main(['inspect']), 1)
                self.assertNotIn('secret', str(output.call_args_list))

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
        controller.confirm_created.assert_called_once_with('lease')
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
        controller.store.read.return_value = ({'request_id': 'lease', 'ids': {'instance': '123'},
                                               'names': {'instance': 'vm'}, 'deadline': '2026-10-24T23:05:00Z'}, 1)
        controller.cfg.now.return_value = datetime(2026, 10, 24, 23, tzinfo=timezone.utc)
        controller.cloud.call.side_effect = [{'id': '123'}, cli.NotFound()]
        with patch('builtins.print'):
            self.assertIn('vm-absent', cli.wait_for_absence(controller, 'lease')['status'])
        controller.cfg.sleep.assert_called_once_with(5)
        controller.cloud.call.side_effect = None
        controller.cloud.call.return_value = {'id': '123'}
        controller.cloud.call.reset_mock()
        with patch('builtins.print'), self.assertRaisesRegex(Refused, 'fixed wait bound'):
            cli.wait_for_absence(controller, 'lease')
        self.assertEqual(controller.cloud.call.call_count, 85)
        controller.cloud.call.return_value = {'id': 'changed'}
        with patch('builtins.print'), self.assertRaisesRegex(Refused, 'identity changed'):
            cli.wait_for_absence(controller, 'lease')

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
        urls = [call.args[1] for call in http.request.call_args_list]
        base = 'https://compute.googleapis.com/compute/v1/'
        self.assertEqual(urls, [base + f'projects/{spec.PROJECT}',
                               base + f'projects/{spec.PROJECT}/regions/{spec.REGION}',
                               *[base + p for p, _, _ in cli.IMAGES]])
        self.assertTrue(all(call.args[0] == 'GET' for call in http.request.call_args_list))

    def test_preflight_rejects_bad_identity_quota_and_http(self):
        for change in ('global_quota', 'e2_quota', 'disk_quota', 'missing', 'nan', 'duplicate', 'image', 'status', 'size', 'inherited_script'):
            records = preflight_records()
            if change == 'global_quota': records[0]['quotas'][0]['usage'] = 95
            if change == 'e2_quota': records[1]['quotas'][1]['limit'] = 1
            if change == 'disk_quota': records[1]['quotas'][2]['limit'] = 309
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


class WorkflowTests(unittest.TestCase):
    def workflows(self):
        return [yaml.safe_load((ROOT / '.github/workflows' / f'labapp-lifecycle-{m}.yml').read_text())
                for m in ('inspect', 'cleanup')]

    def test_workflow_boundary(self):
        inspect, cleanup = self.workflows()
        self.assertEqual(inspect['on'], {'workflow_dispatch': None})
        self.assertEqual(cleanup['on']['workflow_run'],
                         {'workflows': [cli.CREATOR_NAME], 'types': ['completed'], 'branches': ['main']})
        for workflow, mode, identity in ((inspect, 'inspect', 'creator'), (cleanup, 'cleanup', 'cleanup')):
            self.assertEqual(workflow['permissions'], {'contents': 'read', 'id-token': 'write'})
            job = workflow['jobs'][mode]
            self.assertIn("github.ref == 'refs/heads/main'", job['if'])
            steps = job['steps']
            self.assertEqual(steps[0]['env']['TRUSTED_SHA'], '${{ github.sha }}')
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
                self.assertEqual(len(files), 9)
                self.assertTrue(all(url.endswith('?ref=' + 'a' * 40) for url in requested))
                self.assertEqual(credentials.read_text(), 'unchanged')
                self.assertEqual((Path(tmp) / 'labapp-trusted-lifecycle/lifecycle/cli.py').read_bytes(),
                                 (ROOT / 'build/gcp/lifecycle/cli.py').read_bytes())
