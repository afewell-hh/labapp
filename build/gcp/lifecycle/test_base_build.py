"""Retained-boot library profile: real controller/fake API, no credentials/cloud."""
import copy
import json
import unittest
from datetime import timedelta
from unittest.mock import Mock, patch

from . import cli, spec
from .controller import Config, Controller, FREE, Refused
from .test_compute import call, response, transport
from .test_lifecycle import U1, U2, World
from . import test_profiles


def world(minutes=spec.BASE_BUILD_FIRST_LEASE_MINUTES):
    w = World()
    w.cfg = Config(boot_image=spec.COMPONENT_IMAGE, profile=spec.UBUNTU_BASE_BUILD,
                   lease_minutes=minutes, now=w.clock.now, sleep=w.clock.sleep)
    w.ctl = Controller(w.store, w.cloud, w.cfg)
    return w


class BaseBuild(unittest.TestCase):
    def test_profile_caps_and_explicit_first_fixture(self):
        self.assertEqual(world().cfg.lease_minutes, 45)
        self.assertEqual(Config(boot_image=spec.COMPONENT_IMAGE,
                               profile=spec.UBUNTU_BASE_BUILD).lease_minutes, 120)
        w = world(120)
        r = w.started()
        self.assertEqual(r['deadline'], '2026-10-24T22:00:00Z')
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')
        for kwargs in ({'lease_minutes': 121}, {'lease_minutes': True},
                       {'lease_minutes': 0}, {'boot_image': spec.SOURCE_IMAGE}):
            args = dict(boot_image=spec.COMPONENT_IMAGE, profile=spec.UBUNTU_BASE_BUILD)
            args.update(kwargs)
            with self.assertRaises(ValueError):
                Config(**args)
        for profile, cap in ((spec.INSPECTOR, 60), (spec.UBUNTU_COMPONENT, 30)):
            with self.assertRaises(ValueError):
                Config(boot_image=spec.COMPONENT_IMAGE, profile=profile, lease_minutes=cap + 1)

    def test_retained_request_matches_component_except_autodelete_and_deadline(self):
        w = world()
        r = w.ctl.admit(1, 1, U1)
        body = spec.build_body(boot_image=spec.COMPONENT_IMAGE, request_id=U1,
                               run_id=1, attempt=1, deadline=w.clock.now()+timedelta(minutes=45),
                               profile=spec.UBUNTU_BASE_BUILD)
        expected = spec.build_body(boot_image=spec.COMPONENT_IMAGE, request_id=U1,
                                   run_id=1, attempt=1, deadline=w.clock.now()+timedelta(minutes=45),
                                   profile=spec.UBUNTU_COMPONENT)
        expected['disks'][0]['autoDelete'] = False
        self.assertEqual(body, expected)
        spec.validate_body(body)
        self.assertEqual(r['profile'], spec.UBUNTU_BASE_BUILD)
        self.assertEqual(r['boot_image_id'], spec.COMPONENT_IMAGE_ID)
        self.assertEqual(set(r['names']), {'instance', 'boot'})
        self.assertEqual(r['children'], {'boot': body['disks'][0]['initializeParams']})
        self.assertEqual(r['body_hash'], spec.body_hash(body))
        adapter, http = transport(response({'name': 'op'}))
        call(adapter, 'instances', 'insert', body=body, request_id=U1)
        self.assertEqual(json.loads(http.calls[0][2]["body"]), body)
        self.assertIn('requestId=' + U1, http.calls[0][1])
        for mutate in (lambda b: b['disks'][0].update(autoDelete=0),
                       lambda b: b['disks'].append(copy.deepcopy(b['disks'][0])),
                       lambda b: b['disks'][0]['initializeParams'].update(sourceImage=spec.SOURCE_IMAGE),
                       lambda b: b['networkInterfaces'][0].update(accessConfigs=[]),
                       lambda b: b.update(serviceAccounts=[{}]),
                       lambda b: b['scheduling'].update(maxRunDuration={'seconds': '7200'})):
            changed = copy.deepcopy(body)
            mutate(changed)
            with self.assertRaises(ValueError):
                spec.validate_body(changed)

    def test_delayed_submit_keeps_admission_deadline_and_cannot_renew(self):
        w = world()
        r = w.ctl.admit(1, 1, U1)
        w.clock.advance(20)
        self.assertEqual(w.ctl.submit(U1).status, 'accepted')
        self.assertEqual(w.ctl.confirm_created(U1).status, 'created')
        vm = w.raw.instances[r['names']['instance']]
        self.assertEqual(vm['scheduling']['terminationTime'], r['deadline'])
        self.assertEqual(w.record()['deadline'], r['deadline'])
        for field in ('deadline', 'reserved_at'):
            prev = w.record()
            changed = copy.deepcopy(prev)
            changed[field] = spec.rfc3339(w.clock.now()+timedelta(minutes=120))
            with self.assertRaisesRegex(AssertionError, 'immutable'):
                w.ctl._cas(prev, changed, w.store.read(w.cfg.key)[1])
        for elapsed in (36, 45, 121):
            w = world()
            w.ctl.admit(1, 1, U1)
            w.clock.advance(elapsed)
            with self.assertRaisesRegex(Refused, 'too little lease time'):
                w.ctl.submit(U1)
            self.assertEqual(w.record()['submit_attempts'], 0)
            self.assertFalse([c for c in w.raw.calls if c[1] == 'insert'])

    def test_normal_disposal_deletes_vm_then_retained_boot_and_confirms_absence(self):
        w = world()
        r = w.started()
        boot = r['names']['boot']
        real = w.raw._disks_delete
        def delete(name, *args):
            self.assertEqual(w.raw.instances, {})
            self.assertEqual(w.raw.disks[name]['id'], r['ids']['boot'])
            self.assertNotEqual(w.record()['state'], FREE)
            return real(name, *args)
        w.raw._disks_delete = delete
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')
        self.assertEqual(w.deletes(), [('instances', 'delete', r['names']['instance']),
                                       ('disks', 'delete', boot)])
        self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))
        self.assertEqual(w.record()['last_release']['ids'], r['ids'])
        self.assertIn('404 confirmed', w.record()['last_release']['evidence'][-1])

    def test_cloud_expired_vm_leaves_exact_boot_held_until_terminal_delete_and_absence(self):
        for failure in ('pending', 'noop', 'error', 'api'):
            with self.subTest(failure=failure):
                w = world()
                r = w.started()
                boot = r['names']['boot']
                # Cloud expiry uses the same documented autoDelete behavior;
                # the cloud, rather than controller, deletes the instance.
                w.clock.advance(45)
                w.raw._instances_delete(r['names']['instance'])
                self.assertEqual(w.raw.disks[boot]['id'], r['ids']['boot'])
                self.assertNotEqual(w.record()['state'], FREE)
                start = len(w.raw.calls)
                if failure == 'pending':
                    real = w.raw._disks_delete
                    def pending(*args):
                        op = real(*args)
                        w.raw.op_stuck.add(op['name'])
                        w.raw.ops[op['name']]['status'] = 'RUNNING'
                        return op
                    w.raw._disks_delete = pending
                elif failure == 'noop':
                    w.raw.delete_noop.add(boot)
                elif failure == 'error':
                    w.raw.delete_op_error.add(boot)
                    w.raw.delete_noop.add(boot)
                else:
                    w.raw.delete_fail.add(boot)
                # Legacy/default cleanup config must follow recorded profile.
                cleanup = Controller(w.store, w.cloud, Config(boot_image=cli.BOOT_IMAGE,
                                     now=w.clock.now, sleep=w.clock.sleep))
                self.assertIn(cleanup.reconcile().status, {'pending-operation', 'cleanup-failed'})
                self.assertEqual([c for c in w.raw.calls[start:] if c[1] == 'delete'],
                                 [('disks', 'delete', boot)])
                self.assertNotEqual(w.record()['state'], FREE)
                with self.assertRaises(Refused):
                    w.ctl.admit(2, 1, U2)
                if failure == 'pending':
                    self.assertEqual(cleanup.reconcile().status, 'pending-operation')
                    for name in w.raw.op_stuck:
                        w.raw.ops[name]['status'] = 'DONE'
                    w.raw.op_stuck.clear()
                w.raw.delete_fail.clear()
                w.raw.delete_noop.clear()
                w.raw.delete_op_error.clear()
                self.assertEqual(cleanup.reconcile().status, 'released')
                self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))

    def test_expired_boot_replacement_is_never_deleted(self):
        w = world()
        r = w.started()
        w.raw._instances_delete(r['names']['instance'])
        w.clock.advance(45)
        w.raw.disks[r['names']['boot']]['id'] = 'foreign'
        self.assertEqual(w.ctl.reconcile().status, 'cleanup-failed')
        self.assertEqual(w.deletes(), [])
        self.assertNotEqual(w.record()['state'], FREE)

    def test_changed_autodelete_blocks_all_cleanup(self):
        w = world()
        r = w.started()
        w.raw.instances[r['names']['instance']]['disks'][0]['autoDelete'] = True
        self.assertEqual(w.ctl.reconcile(U1).status, 'cleanup-failed')
        self.assertEqual(w.deletes(), [])

    def test_unconfirmed_expired_boot_needs_terminal_current_insert(self):
        w = world()
        w.ctl.admit(1, 1, U1)
        w.ctl.submit(U1)
        r = w.record()
        w.raw._instances_delete(r['names']['instance'])
        w.clock.advance(45)
        insert = next(op for op in w.raw.ops.values() if op['operationType'] == 'insert')
        insert['clientOperationId'] = U2
        self.assertEqual(w.ctl.reconcile().status, 'cleanup-failed')
        self.assertEqual(w.deletes(), [])
        self.assertIsNone(w.record()['ids']['boot'])
        insert['clientOperationId'] = U1
        self.assertEqual(w.ctl.reconcile().status, 'released')
        self.assertIsNotNone(w.record()['last_release']['ids']['boot'])

    def test_cancellation_before_and_after_submit_disposes_only_current_lease(self):
        for phase in ('reserved', 'submitted', 'confirmed'):
            w = world()
            w.ctl.admit(1, 1, U1)
            if phase != 'reserved':
                w.ctl.submit(U1)
            if phase == 'confirmed':
                w.ctl.confirm_created(U1)
            self.assertEqual(w.ctl.reconcile(U2).status, 'superseded')
            self.assertEqual(w.deletes(), [])
            self.assertEqual(w.ctl.reconcile(U1).status, 'released')
            self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))

    def test_admission_collision_and_failed_project_census_never_reserve(self):
        for failure in ('foreign-disk', 'stopped-vm', 'unreachable'):
            w = world()
            if failure == 'foreign-disk':
                w.raw.add_foreign('disks', spec.names(1, 1)['boot'])
            elif failure == 'stopped-vm':
                w.raw.add_foreign('instances', 'preexisting')
                w.raw.instances['preexisting']['status'] = 'STOPPED'
            else:
                w.raw.unreachables = ['zones/other']
            with self.assertRaises(Refused):
                w.ctl.admit(1, 1, U1)
            self.assertEqual(w.record()['state'], FREE)
            self.assertFalse([c for c in w.raw.calls if c[1] in ('insert', 'delete')])

    def test_persisted_component_switch_and_overlong_deadline_are_refused(self):
        for change in ('component', 'deadline'):
            w = world()
            w.ctl.admit(1, 1, U1)
            r, generation = w.store.read(w.cfg.key)
            if change == 'component':
                r['profile'] = spec.UBUNTU_COMPONENT
            else:
                deadline = w.clock.now() + timedelta(minutes=121)
                r['deadline'] = spec.rfc3339(deadline)
                # A matching hash cannot bypass the persisted profile cap.
                r['body_hash'] = spec.body_hash(spec.build_body(
                    boot_image=r['boot_image'], request_id=U1, run_id=1, attempt=1,
                    deadline=deadline, profile=spec.UBUNTU_BASE_BUILD))
            w.store.write(w.cfg.key, r, if_generation_match=generation)
            with self.assertRaises(Refused):
                w.ctl.submit(U1)
            self.assertEqual(w.ctl.reconcile(U1).status, 'blocked')
            self.assertFalse([c for c in w.raw.calls if c[1] in ('insert', 'delete')])

    def test_fixed_preflight_only_public_image_and_small_quotas(self):
        records = [
            {'name': spec.PROJECT, 'quotas': [{'metric': 'CPUS_ALL_REGIONS', 'limit': 2, 'usage': 0}]},
            {'name': spec.REGION, 'quotas': [{'metric': k, 'limit': v, 'usage': 0}
                for k, v in [('CPUS', 2), ('N2_CPUS', 2), ('INSTANCES', 1), ('DISKS_TOTAL_GB', 20)]]},
            {'name': spec.COMPONENT_IMAGE.rsplit('/', 1)[-1], 'id': spec.COMPONENT_IMAGE_ID,
             'architecture': 'X86_64', 'status': 'READY', 'diskSizeGb': '10'}]
        def check(values):
            http = Mock()
            http.request.side_effect = [response(v) for v in values]
            cli.Preflight(http, lambda: 'fake', profile=spec.UBUNTU_BASE_BUILD).check()
            self.assertEqual([c.args[1] for c in http.request.call_args_list], [
                'https://compute.googleapis.com/compute/v1/' + path for path in (
                    'projects/' + spec.PROJECT, 'projects/' + spec.PROJECT + '/regions/' + spec.REGION,
                    spec.COMPONENT_IMAGE)])
        check(records)
        for metric in range(4):
            bad = copy.deepcopy(records)
            bad[1]['quotas'][metric]['limit'] -= 1
            with self.assertRaises(Refused):
                check(bad)
        for field, value in (('id', 'foreign'), ('architecture', 'ARM64'), ('diskSizeGb', '300')):
            bad = copy.deepcopy(records)
            bad[2][field] = value
            with self.assertRaises(Refused):
                check(bad)

    def test_public_cli_does_not_select_base_build(self):
        with patch.object(cli, 'Controller') as factory, patch('sys.stderr'):
            with self.assertRaises(SystemExit):
                cli.main(['base-build'])
            factory.assert_not_called()

    def test_existing_failure_contracts_apply_to_retained_profile(self):
        # Re-run actual fake/controller scenarios under retained-boot intent.
        cases = ('image_pin_checked_at_admission_and_again_before_submission',
                 'image_read_denial_is_not_proof',
                 'lost_insert_response_and_late_materialization_keep_slot',
                 'unknown_insert_is_not_resolved_by_expiry_or_404',
                 'stale_ids_names_foreign_attachment_and_image_binding_block_all_deletes',
                 'unconfirmed_boot_provenance_refused_before_ids_adopted',
                 'bad_persisted_profiles_and_mixed_children_block_without_cloud_mutation',
                 'foreign_pending_operation_prevents_release')
        for name in cases:
            with self.subTest(scenario=name):
                # Unknown insert expiry scenario waits 31 minutes; use the
                # same permitted 30-minute lease to preserve that assertion.
                with patch('lifecycle.test_profiles.world', lambda: world(30)):
                    getattr(test_profiles.Profiles('test_' + name), 'test_' + name)()
