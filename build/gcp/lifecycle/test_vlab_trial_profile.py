"""Actual closed profile/access/cleanup entrypoints, synthetic CAS/API only."""
import copy
import json
from datetime import timedelta
import unittest
from unittest.mock import Mock, patch

from . import cli, spec
from .access_records import Context, GcsAccessRecords, ReadOnlyAccessRecords
from .auth_http import HttpResponse
from .controller import Config, Controller, FREE, Refused
from .oslogin import OwnKeyImport, SelfLogin, cleanup_own_key
from .test_access import BUCKET, GCS, OS, SELF, key
from .test_cli import event_env
from .test_lifecycle import U1, U2, World

FIELDS = ('profile', 'request_id', 'epoch', 'run_id', 'attempt', 'body_hash',
          'ids', 'boot_image', 'boot_image_id', 'reserved_at', 'deadline', 'operation')


def world():
    w = World()
    w.cfg = Config(boot_image=spec.COMPONENT_IMAGE, profile=spec.UBUNTU_VLAB_CORE,
                   now=w.clock.now, sleep=w.clock.sleep)
    w.ctl = Controller(w.store, w.cloud, w.cfg)
    return w


class TrialProfile(unittest.TestCase):
    def test_exact_shape_and_fixed_duration(self):
        w = world()
        rec = w.ctl.admit(1, 1, U1)
        body = spec.build_body(boot_image=spec.COMPONENT_IMAGE, request_id=U1, run_id=1,
                 attempt=1, deadline=w.clock.now()+timedelta(minutes=120), profile=spec.UBUNTU_VLAB_CORE)
        spec.validate_body(body)
        self.assertEqual(body['machineType'], 'zones/us-central1-a/machineTypes/n2-standard-32')
        self.assertEqual(body['disks'][0]['initializeParams']['diskSizeGb'], '500')
        self.assertEqual(body['disks'][0]['initializeParams']['diskType'], 'zones/us-central1-a/diskTypes/pd-balanced')
        self.assertTrue(body['disks'][0]['autoDelete'])
        self.assertEqual(set(rec['ids']), {'instance', 'boot'})
        self.assertEqual(rec['deadline'], '2026-10-24T22:00:00Z')
        for duration in (True, 30, 119, 121):
            with self.assertRaises(ValueError):
                Config(boot_image=spec.COMPONENT_IMAGE, profile=spec.UBUNTU_VLAB_CORE, lease_minutes=duration)

    def test_finite_table_rejects_hybrid_or_extra_shapes(self):
        w = world()
        body = spec.build_body(boot_image=spec.COMPONENT_IMAGE, request_id=U1, run_id=1,
                 attempt=1, deadline=w.clock.now()+timedelta(minutes=120), profile=spec.UBUNTU_VLAB_CORE)
        for mutate in (lambda b: b['disks'][0].update(autoDelete=False),
                       lambda b: b['disks'][0]['initializeParams'].update(diskType='zones/us-central1-a/diskTypes/pd-standard'),
                       lambda b: b.update(machineType='zones/us-central1-a/machineTypes/n2-standard-2'),
                       lambda b: b.update(serviceAccounts=[{}]),
                       lambda b: b['networkInterfaces'][0].update(accessConfigs=[]),
                       lambda b: b['metadata']['items'].append({'key': 'user-data', 'value': 'ignored'}),
                       lambda b: b['disks'].append(copy.deepcopy(b['disks'][0]))):
            changed = copy.deepcopy(body)
            mutate(changed)
            with self.assertRaises(ValueError): spec.validate_body(changed)

    def test_actual_create_dispose_protects_all_preexisting_images(self):
        w = world()
        r = w.started()
        self.assertEqual(r['boot_image_id'], spec.COMPONENT_IMAGE_ID)
        with self.assertRaises(Refused): w.ctl.prepare_capture(U1, U2)
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')
        self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))
        self.assertFalse([c for c in w.raw.calls if c[0] == 'images' and c[1] != 'get'])
        self.assertEqual(w.record()['state'], FREE)

    def test_shortened_persisted_lease_refuses_without_delete(self):
        w = world()
        r = w.started()
        changed = copy.deepcopy(r)
        changed['deadline'] = spec.rfc3339(w.clock.now()+timedelta(minutes=119))
        body = spec.build_body(boot_image=spec.COMPONENT_IMAGE, request_id=U1, run_id=1,
                              attempt=1, deadline=w.clock.now()+timedelta(minutes=119), profile=spec.UBUNTU_VLAB_CORE)
        changed['body_hash'] = spec.body_hash(body)
        w.store.write(w.cfg.key, changed, if_generation_match=w.store.read(w.cfg.key)[1])
        self.assertEqual(w.ctl.reconcile(U1).status, 'blocked')
        self.assertFalse(w.deletes())

    def test_unknown_insert_and_stopped_outer_are_not_free(self):
        w = world()
        w.raw.insert_mode = 'timeout_nothing'
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        w.clock.advance(121)
        self.assertEqual(w.ctl.reconcile().status, 'blocked')
        with self.assertRaises(Refused): w.ctl.admit(2, 1, U2)
        w = world()
        r = w.started()
        w.raw.instances[r['names']['instance']]['status'] = 'TERMINATED'
        self.assertEqual(w.ctl.reconcile().status, 'released')

    def test_stale_provenance_extra_child_and_leaked_boot_block_release(self):
        for mode in ('image', 'extra', 'boot'):
            w = world()
            r = w.started()
            if mode == 'image': w.raw.disks[r['names']['boot']]['sourceImageId'] = '7638370619126112785'
            if mode == 'extra': w.raw.instances[r['names']['instance']]['disks'].append({'source': 'foreign'})
            if mode == 'boot':
                w.raw.leak_disks = True
                w.raw.delete_fail.add(r['names']['boot'])
            self.assertEqual(w.ctl.reconcile(U1).status, 'cleanup-failed')
            self.assertNotEqual(w.record()['state'], FREE)

    def access(self):
        w = world()
        w.started()
        records = GcsAccessRecords(BUCKET, token_provider=lambda: 'fake', transport=GCS(w))
        ctl = Controller(w.store, w.cloud, w.cfg, access_records=records)
        expected = {k: w.record()[k] for k in FIELDS}
        return w, records, ctl, expected

    def test_registration_requires_exact_snapshot_terminal_insert_and_correlation(self):
        for mode in ('snapshot', 'run', 'operation'):
            w, records, ctl, expected = self.access()
            if mode == 'snapshot': expected['epoch'] += 1
            if mode == 'operation': w.raw.ops[w.record()['operation']]['status'] = 'RUNNING'
            with self.assertRaises(Refused):
                ctl.register_access(U1, producer_run_id=2 if mode == 'run' else 1,
                    producer_attempt=1, self_user=SELF, public_key_text=key(), expected_trial=expected)
            self.assertNotIn('access', w.record())

    def test_registration_cas_conflict_does_not_retry(self):
        w, records, ctl, expected = self.access()
        def lose(key_name, _record):
            r, gen = w.store.read(key_name)
            w.store.write(key_name, r, if_generation_match=gen)
        w.store.before_write = lose
        with self.assertRaisesRegex(Refused, 'lost ownership'):
            ctl.register_access(U1, producer_run_id=1, producer_attempt=1,
                                self_user=SELF, public_key_text=key(), expected_trial=expected)
        self.assertNotIn('access', w.record())

    def test_no_free_until_import_removal_and_readonly_archive(self):
        w, records, ctl, expected = self.access()
        context = ctl.register_access(U1, producer_run_id=1, producer_attempt=1,
                    self_user=SELF, public_key_text=key(), expected_trial=expected)
        self.assertEqual(context, Context.from_slot(w.record()))
        readonly = ReadOnlyAccessRecords(records)
        self.assertFalse(hasattr(readonly, 'create'))
        cleanup = Controller(w.store, w.cloud, w.cfg, access_records=readonly)
        login = SelfLogin(SELF, token_provider=lambda: 'fake', transport=OS())
        session = OwnKeyImport(records, context, login, producer_run_id=1, producer_attempt=1, now=w.clock.now)
        session.prepare(key())
        session.import_once()
        self.assertEqual(cleanup.reconcile(U1).status, 'cleanup-failed')
        self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))
        self.assertNotEqual(w.record()['state'], FREE)
        cleanup_own_key(records, context, login, now=w.clock.now)
        self.assertEqual(cleanup.reconcile(U1).status, 'released')

    def test_fixed_cli_preflight_quota_pools_and_first_attempt(self):
        records = [{'name': spec.PROJECT, 'quotas': [{'metric': 'CPUS_ALL_REGIONS', 'limit': 32, 'usage': 0}]},
            {'name': spec.REGION, 'quotas': [{'metric': n, 'limit': v, 'usage': 0}
             for n, v in [('N2_CPUS', 32), ('INSTANCES', 1), ('SSD_TOTAL_GB', 500)]]},
            {'name': spec.COMPONENT_IMAGE.rsplit('/', 1)[-1], 'id': spec.COMPONENT_IMAGE_ID,
             'diskSizeGb': '10', 'status': 'READY', 'architecture': 'X86_64'}]
        http = Mock()
        http.request.side_effect = [HttpResponse(200, json.dumps(r).encode()) for r in records]
        cli.Preflight(http, lambda: 'fake', spec.UBUNTU_VLAB_CORE).check()
        for index in (0, 1):
            bad = copy.deepcopy(records)
            bad[index]['quotas'][0]['usage'] = 1
            http.request.side_effect = [HttpResponse(200, json.dumps(r).encode()) for r in bad]
            with self.assertRaises(Refused): cli.Preflight(http, lambda: 'fake', spec.UBUNTU_VLAB_CORE).check()
        env, event = event_env()
        env['GITHUB_RUN_ATTEMPT'] = '2'
        ctl, preflight = Mock(), Mock()
        with self.assertRaisesRegex(Refused, 'first-attempt'): cli.execute('vlab-core', ctl, preflight, env, event)
        ctl.admit.assert_not_called()

    def test_cleanup_cli_composes_evidence_only_adapter(self):
        env, event = event_env('schedule')
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'event.json'
            path.write_text(json.dumps(event))
            env['GITHUB_EVENT_PATH'] = str(path)
            with patch.dict('os.environ', env), patch.object(cli, 'Controller') as factory, \
                 patch.object(cli, 'execute', return_value={}), patch('builtins.print'):
                self.assertEqual(cli.main(['cleanup']), 0)
            self.assertIsInstance(factory.call_args.kwargs['access_records'], ReadOnlyAccessRecords)
