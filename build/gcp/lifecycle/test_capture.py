"""Explicit capture/quarantine controller, CAS and HTTP contracts; no cloud."""
import copy
import json
import unittest
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

from . import spec
from .cloud import ApiError, ForbiddenOperation, PolicyCloud, Uncertain
from .controller import Controller, FREE, Refused
from .test_base_build import world
from .test_lifecycle import U1, U2
from .test_compute import response, transport, call

C1 = '33333333-3333-4333-8333-333333333333'
C2 = '44444444-4444-4444-8444-444444444444'


def prepared(retain=False):
    w = world()
    w.started()
    w.ctl.prepare_capture(U1, C1, retain_until=(w.clock.now() + timedelta(hours=24)) if retain else None)
    return w


def captured(retain=False):
    w = prepared(retain)
    assert w.ctl.capture(U1).status == 'capture-submitted'
    return w


class Capture(unittest.TestCase):
    def test_explicit_capture_persists_before_vm_delete_and_insert(self):
        w = prepared()
        r = w.record()
        c = r['capture']
        self.assertNotEqual(c['request_id'], r['request_id'])
        self.assertEqual(c['source_disk_id'], r['ids']['boot'])
        self.assertEqual(c['deadline'], r['deadline'])
        self.assertFalse(c['submitted'])
        insert = w.raw._images_insert
        def checked(name, body, request):
            self.assertEqual(w.raw.instances, {})
            self.assertEqual(w.record()['capture']['request_id'], C1)
            self.assertTrue(w.record()['capture']['submitted'])
            self.assertEqual(w.raw.disks[r['names']['boot']]['id'], c['source_disk_id'])
            self.assertEqual(body, spec.capture_body(c))
            self.assertEqual(request, C1)
            self.assertEqual(w.deletes(), [('instances', 'delete', r['names']['instance'])])
            return insert(name, body, request)
        w.raw._images_insert = checked
        self.assertEqual(w.ctl.capture(U1).status, 'capture-submitted')
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')
        mutations = [c for c in w.raw.calls if c[1] in ('insert', 'delete')]
        self.assertEqual([c[:2] for c in mutations], [('instances', 'insert'),
            ('instances', 'delete'), ('images', 'insert'), ('images', 'delete'), ('disks', 'delete')])
        self.assertEqual((w.raw.instances, w.raw.disks, w.raw.images), ({}, {}, {}))

    def test_default_disposal_never_captures(self):
        w = world(); w.started()
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')
        self.assertFalse([c for c in w.raw.calls if c[:2] == ('images', 'insert')])

    def test_prepare_is_not_submission_and_cancellation_does_not_start_it(self):
        w = prepared()
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')
        self.assertFalse(w.raw.images)
        self.assertFalse([c for c in w.raw.calls if c[:2] == ('images', 'insert')])
        with self.assertRaises(Refused): w.ctl.capture(U1)

    def test_capture_requires_current_build_and_distinct_nonzero_uuid(self):
        for uuid in (U1, 'bad', '00000000-0000-0000-0000-000000000000'):
            w = world(); w.started()
            with self.assertRaises((Refused, ValueError)): w.ctl.prepare_capture(U1, uuid)
            self.assertEqual(w.deletes(), [])
        w = prepared()
        with self.assertRaises(Refused): w.ctl.capture(U2)
        with self.assertRaises(Refused): w.ctl.prepare_capture(U1, C2)

    def test_retention_bound_and_absolute_budget(self):
        for hours in (0, -1, 24.001):
            w = world(); w.started()
            with self.assertRaises(Refused):
                w.ctl.prepare_capture(U1, C1, retain_until=w.clock.now()+timedelta(hours=hours))
        w = world(); w.started(); w.clock.advance(30)
        with self.assertRaisesRegex(Refused, 'budget'): w.ctl.prepare_capture(U1, C1)
        w = prepared(); w.clock.advance(30)
        with self.assertRaisesRegex(Refused, 'budget'): w.ctl.capture(U1)
        self.assertEqual(w.deletes(), [])

    def test_budget_rechecked_after_slow_vm_delete(self):
        w = prepared(); real = w.raw._instances_delete
        def slow(*a):
            result = real(*a); w.clock.advance(31); return result
        w.raw._instances_delete = slow
        with self.assertRaisesRegex(Refused, 'budget'): w.ctl.capture(U1)
        self.assertFalse(w.record()['capture']['submitted'])
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')

    def test_pending_vm_delete_prevents_capture_and_boot_disposal(self):
        w = prepared(); original = w.raw._instances_delete
        def pending(*a):
            op = original(*a); w.raw.ops[op['name']]['status'] = 'RUNNING'
            w.raw.op_stuck.add(op['name']); return op
        w.raw._instances_delete = pending
        self.assertEqual(w.ctl.capture(U1).status, 'pending-operation')
        self.assertEqual(w.ctl.reconcile(U1).status, 'pending-operation')
        self.assertTrue(w.raw.disks)
        self.assertFalse(w.raw.images)

    def test_builder_already_deleted_retained_boot_still_capturable(self):
        w = prepared(); w.raw._instances_delete(w.record()['names']['instance'])
        self.assertEqual(w.ctl.capture(U1).status, 'capture-submitted')
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')

    def test_unconfirmed_or_attached_or_wrong_source_blocks_before_capture(self):
        for change in ('id', 'source', 'users', 'extra'):
            w = prepared(); r = w.record(); disk = w.raw.disks[r['names']['boot']]
            if change == 'id': disk['id'] = '999'
            elif change == 'source': disk['sourceImageId'] = '999'
            elif change == 'users': disk['users'] = ['foreign-vm']
            else: w.raw.instances[r['names']['instance']]['disks'].append({})
            with self.assertRaises(Refused): w.ctl.capture(U1)
            self.assertFalse(w.raw.images)
            self.assertTrue(w.raw.disks)

    def test_boot_rechecked_after_insert_and_wrong_source_never_cleaned(self):
        w = prepared(); real = w.raw._images_insert
        def race(*a):
            op = real(*a)
            w.raw.disks[w.record()['names']['boot']]['id'] = '999'
            return op
        w.raw._images_insert = race
        self.assertEqual(w.ctl.capture(U1).status, 'blocked')
        self.assertEqual(w.ctl.reconcile(U1).status, 'cleanup-failed')
        self.assertTrue(w.raw.images)

    def test_lost_capture_response_recovers_exact_terminal_global_operation(self):
        w = prepared(); w.raw.capture_mode = 'lost'
        self.assertEqual(w.ctl.capture(U1).status, 'uncertain')
        self.assertIsNone(w.record()['capture']['operation'])
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')
        self.assertTrue([c for c in w.raw.calls if c[:2] == ('globalOperations', 'get')])

    def test_unknown_capture_404_and_expiry_hold_boot_and_slot(self):
        w = prepared(); w.raw.capture_mode = 'timeout_nothing'
        self.assertEqual(w.ctl.capture(U1).status, 'uncertain')
        for advance in (0, 46, 1440):
            w.clock.advance(advance)
            self.assertEqual(w.ctl.reconcile(U1).status, 'blocked')
            self.assertTrue(w.raw.disks)
            self.assertNotEqual(w.record()['state'], FREE)
            with self.assertRaises(Refused): w.ctl.admit(2, 1, U2)
        self.assertEqual(len([c for c in w.raw.calls if c[:2] == ('images', 'insert')]), 1)

    def test_pending_capture_keeps_boot_until_global_operation_terminal(self):
        w = prepared(); w.raw.capture_mode = 'pending'
        self.assertEqual(w.ctl.capture(U1).status, 'capture-submitted')
        self.assertEqual(w.ctl.reconcile(U1).status, 'blocked')
        self.assertTrue(w.raw.disks); self.assertTrue(w.raw.images)
        for op in w.raw.image_ops.values(): op['status'] = 'DONE'
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')

    def test_terminal_failed_capture_with_absence_can_dispose_boot(self):
        w = captured(); w.raw.images.clear()
        for op in w.raw.image_ops.values(): op['error'] = {'errors': [1]}; op.pop('targetId')
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')

    def test_foreign_operation_proof_never_adopts_or_deletes(self):
        for field, value in [('clientOperationId', U2), ('targetId', '999'),
                             ('targetLink', 'projects/other/global/images/foreign')]:
            w = captured(); next(iter(w.raw.image_ops.values()))[field] = value
            self.assertEqual(w.ctl.reconcile(U1).status, 'blocked')
            self.assertTrue(w.raw.images); self.assertTrue(w.raw.disks)

    def test_replaced_image_wrong_labels_or_source_never_deleted(self):
        for field, value in [('id', '999'), ('sourceDiskId', '999'), ('labels', {}),
                             ('sourceDisk', 'projects/other/zones/foreign/disks/boot'), ('family', 'promoted')]:
            w = captured(); image = next(iter(w.raw.images.values())); image[field] = value
            self.assertEqual(w.ctl.reconcile(U1).status, 'blocked')
            self.assertTrue(w.raw.disks); self.assertTrue(w.raw.images)

    def test_preexisting_images_all_preserved_and_collision_rejected(self):
        w = world(); w.started()
        saved = {f'saved-{i}': {'name': f'saved-{i}', 'id': str(9000+i)} for i in range(11)}
        w.raw.images.update(copy.deepcopy(saved))
        w.ctl.prepare_capture(U1, C1)
        self.assertEqual(w.record()['capture']['preexisting_images'], {n: v['id'] for n,v in saved.items()})
        w.ctl.capture(U1); self.assertEqual(w.ctl.reconcile(U1).status, 'released')
        self.assertEqual(w.raw.images, saved)
        w = world(); w.started()
        w.raw.images['labapp-candidate-'+C1] = {'name': 'labapp-candidate-'+C1, 'id': '999'}
        with self.assertRaises(Refused): w.ctl.prepare_capture(U1, C1)
        self.assertEqual(w.deletes(), [])

    def test_preflight_saved_id_reused_for_candidate_is_rejected(self):
        w = world(); w.started(); w.raw.images['saved'] = {'name':'saved', 'id':'999'}
        w.ctl.prepare_capture(U1,C1); w.ctl.capture(U1)
        image = next(i for n,i in w.raw.images.items() if n.startswith('labapp-candidate'))
        image['id'] = '999'; next(iter(w.raw.image_ops.values()))['targetId'] = '999'
        self.assertEqual(w.ctl.reconcile(U1).status, 'blocked')
        self.assertEqual(len(w.raw.images), 2)

    def test_candidate_delete_failure_pending_or_noop_holds_capacity(self):
        for mode in ('api', 'pending', 'noop', 'error'):
            w = captured(); name = w.record()['capture']['name']
            if mode == 'api': w.raw.delete_fail.add(name)
            elif mode == 'noop': w.raw.delete_noop.add(name)
            elif mode == 'error': w.raw.delete_op_error.add(name)
            else:
                real = w.raw._images_delete
                def pending(*a):
                    op = real(*a); w.raw.image_ops[op['name']]['status'] = 'RUNNING'; return op
                w.raw._images_delete = pending
            self.assertEqual(w.ctl.reconcile(U1).status, 'blocked')
            self.assertTrue(w.raw.disks)
            self.assertNotEqual(w.record()['state'], FREE)

    def test_lost_delete_response_requires_terminal_request_receipt(self):
        w = captured(); real = w.raw._images_delete
        def lost(*a): real(*a); raise Uncertain('lost delete')
        w.raw._images_delete = lost
        self.assertEqual(w.ctl.reconcile(U1).status, 'blocked')
        self.assertTrue(w.raw.disks)
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')

    def test_pending_foreign_global_operation_blocks_capture_and_cleanup(self):
        w = prepared(); op = w.raw._op('insert', 'foreign', 'RUNNING')
        self.assertEqual(w.ctl.capture(U1).status, 'pending-operation')
        self.assertEqual(w.ctl.reconcile(U1).status, 'blocked')
        self.assertTrue(w.raw.disks)

    def test_cancel_cas_prevents_paused_submit_from_inserting(self):
        w = prepared()
        def cancel(_key, record):
            if record.get('capture', {}).get('submitted'):
                self.assertEqual(w.ctl.reconcile(U1).status, 'released')
        # Hook fires on the submit CAS; normal instance deletion writes no CAS.
        w.store.before_write = cancel
        with self.assertRaisesRegex(Refused, 'lost ownership'): w.ctl.capture(U1)
        self.assertFalse(w.raw.images)
        self.assertEqual(w.record()['state'], FREE)

    def test_cancel_after_submit_before_post_holds_unknown_and_cannot_release(self):
        w = prepared(); real = w.raw._images_insert
        def cancel(*a):
            self.assertEqual(w.ctl.reconcile(U1).status, 'blocked')
            self.assertTrue(w.raw.disks)
            return real(*a)
        w.raw._images_insert = cancel
        self.assertEqual(w.ctl.capture(U1).status, 'uncertain')
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')

    def test_capture_intent_immutable_and_double_submission_refused(self):
        w = captured(); r, gen = w.store.read(w.cfg.key); changed = copy.deepcopy(r)
        changed['capture']['source_disk_id'] = '999'
        with self.assertRaisesRegex(AssertionError, 'immutable capture'): w.ctl._cas(r, changed, gen)
        with self.assertRaises(Refused): w.ctl.capture(U1)


class Quarantine(unittest.TestCase):
    def test_transfer_is_durable_at_release_and_survives_next_lease(self):
        w = captured(True); image = copy.deepcopy(w.raw.images)
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')
        q = copy.deepcopy(w.record()['quarantine'])
        self.assertEqual(len(q), 1); self.assertEqual(q[0]['image_id'], next(iter(image.values()))['id'])
        self.assertTrue(q[0]['insert_receipt'])
        self.assertEqual((w.raw.instances, w.raw.disks), ({}, {}))
        w.started(2, U2); self.assertEqual(w.record()['quarantine'], q)
        self.assertEqual(w.ctl.reconcile(U2).status, 'released')
        self.assertEqual(w.record()['quarantine'], q)
        self.assertEqual(w.raw.images, image)

    def test_independent_expiry_works_with_new_occupied_slot(self):
        w = captured(True); w.ctl.reconcile(U1)
        self.assertEqual(w.ctl.reconcile_quarantine().status, 'not-due')
        w.started(2,U2); ids = copy.deepcopy(w.record()['ids'])
        w.clock.advance(24*60)
        self.assertEqual(w.ctl.reconcile_quarantine().status, 'quarantine-deleted')
        self.assertEqual(w.raw.images, {}); self.assertEqual(w.record()['quarantine'], [])
        self.assertEqual(w.record()['ids'], ids); self.assertNotEqual(w.record()['state'], FREE)
        self.assertTrue(w.raw.instances); self.assertTrue(w.raw.disks)

    def test_expired_before_release_is_deleted_instead_of_quarantined(self):
        w = captured(True); w.clock.advance(24*60)
        self.assertEqual(w.ctl.reconcile().status, 'released')
        self.assertEqual(w.record()['quarantine'], []); self.assertEqual(w.raw.images,{})

    def test_replaced_quarantine_or_api_failure_holds_record(self):
        for failure in ('id', 'api', 'op'):
            w = captured(True); w.ctl.reconcile(U1); w.clock.advance(24*60)
            c = w.record()['quarantine'][0]
            if failure == 'id': w.raw.images[c['name']]['id'] = '999'
            elif failure == 'api': w.raw.delete_fail.add(c['name'])
            else: w.raw.image_ops[c['operation']]['status'] = 'RUNNING'
            self.assertEqual(w.ctl.reconcile_quarantine().status, 'blocked')
            self.assertEqual(len(w.record()['quarantine']),1)
            with self.assertRaises(Refused): w.ctl.admit(2,1,U2)

    def test_quarantine_census_still_rejects_unknown_vm_disk_image_and_operation(self):
        for kind in ('instances','disks','images','operations'):
            w = captured(True); w.ctl.reconcile(U1)
            if kind in ('instances','disks'): w.raw.add_foreign(kind,'foreign')
            elif kind == 'images': w.raw.images['foreign']={'name':'foreign','id':'999'}
            else: w.raw._op('insert','foreign','RUNNING')
            with self.assertRaises(Refused): w.ctl.admit(2,1,U2)
            self.assertEqual(w.record()['state'],FREE)

    def test_duplicate_or_malformed_quarantine_records_block_admission_and_expiry(self):
        for mutation in ('duplicate','id','receipt','deadline'):
            w = captured(True); w.ctl.reconcile(U1); r,g=w.store.read(w.cfg.key)
            if mutation == 'duplicate': r['quarantine'] *= 2
            elif mutation == 'id': r['quarantine'][0]['image_id'] = None
            elif mutation == 'receipt': r['quarantine'][0]['insert_receipt']['clientOperationId'] = U2
            else: r['quarantine'][0]['retain_until'] = 'never'
            w.store.write(w.cfg.key,r,if_generation_match=g)
            with self.assertRaises(Refused): w.ctl.admit(2,1,U2)
            self.assertEqual(w.ctl.reconcile_quarantine().status,'blocked')
            self.assertTrue(w.raw.images)

    def test_quarantine_cas_conflict_rechecks_new_lease_without_overwrite(self):
        w = captured(True); w.ctl.reconcile(U1); w.clock.advance(24*60)
        # Concurrent writer changes evidence but leaves identity untouched.
        def competitor(key,record):
            r,g=w.store.read(key); r['external_receipt']='preserved'
            w.store.write(key,r,if_generation_match=g)
        w.store.before_write=competitor
        self.assertEqual(w.ctl.reconcile_quarantine().status,'quarantine-deleted')
        self.assertEqual(w.record()['external_receipt'],'preserved')


class CaptureHTTP(unittest.TestCase):
    def test_typed_image_calls_exact_global_paths_body_uuid_no_force(self):
        w=prepared(); c=dict(w.record()['capture'], submitted=True)
        adapter,http=transport(response({'name':'op'}),response({'id':'123'}),response({'name':'op2'}),response({'status':'DONE'}))
        call(adapter,'images','insert',body=spec.capture_body(c),request_id=C1,capture=c)
        call(adapter,'images','get',name=c['name'],capture=c)
        c.update(image_id='123',delete_submitted=True)
        call(adapter,'images','delete',name=c['name'],request_id=c['delete_request_id'],capture=c)
        call(adapter,'globalOperations','get',name='operation-1',capture=c)
        self.assertEqual([x[0] for x in http.calls],['POST','GET','DELETE','GET'])
        self.assertEqual(urlsplit(http.calls[0][1]).path,f'/compute/v1/projects/{spec.PROJECT}/global/images')
        self.assertEqual(parse_qs(urlsplit(http.calls[0][1]).query),{'requestId':[C1]})
        self.assertEqual(json.loads(http.calls[0][2]['body']),spec.capture_body(c))
        self.assertEqual(parse_qs(urlsplit(http.calls[2][1]).query),{'requestId':[c['delete_request_id']]})
        self.assertTrue(http.calls[3][1].endswith('/global/operations/operation-1'))

    def test_raw_and_policy_refuse_missing_or_forged_intent_before_http(self):
        w=prepared(); c=w.record()['capture']
        for mutation in ('missing','name','disk','hash','preexisting'):
            bad=copy.deepcopy(c)
            if mutation == 'missing': bad=None
            elif mutation == 'name': bad['name']='saved-image'
            elif mutation == 'disk': bad['source_disk']='projects/foreign/zones/z/disks/d'
            elif mutation == 'hash': bad['body_hash']='bad'
            else: bad['preexisting_images'][bad['name']]='999'
            adapter,http=transport(); policy=PolicyCloud(adapter,spec.PROJECT,spec.ZONE)
            for target in (adapter,policy):
                with self.assertRaises(ForbiddenOperation):
                    if target is adapter: call(target,'images','get',name=c['name'],capture=bad)
                    else: target.call('images','get',name=c['name'],capture=bad)
            self.assertEqual(http.calls,[])

    def test_global_enumeration_endpoint_includes_all_scopes_and_pagination(self):
        adapter,http=transport(response({'items':{'global':{'operations':[{'name':'image-op'}]}}}))
        out=call(adapter,'globalOperations','aggregatedList')
        self.assertEqual(out['items']['global']['operations'][0]['name'],'image-op')
        self.assertEqual(urlsplit(http.calls[0][1]).path,f'/compute/v1/projects/{spec.PROJECT}/aggregated/operations')
        self.assertEqual(parse_qs(urlsplit(http.calls[0][1]).query)['returnPartialSuccess'],['false'])

    def test_image_census_requires_intent_and_uses_global_images(self):
        w=prepared(); c=w.record()['capture']; adapter,http=transport(response({'items':[]}))
        call(adapter,'images','list',capture=c,page_token='next')
        self.assertIn('/global/images?',http.calls[0][1]); self.assertIn('pageToken=next',http.calls[0][1])
        with self.assertRaises(ForbiddenOperation): call(adapter,'images','list')

    def test_image_insert_errors_do_not_retry_or_reclassify_absence(self):
        w=prepared(); c=dict(w.record()['capture'],submitted=True)
        for reply in (response({},status=409),response({},status=500),TimeoutError()):
            adapter,http=transport(reply)
            with self.assertRaises((ApiError,Uncertain)):
                call(adapter,'images','insert',body=spec.capture_body(c),request_id=C1,capture=c)
            self.assertEqual(len(http.calls),1)


class DurableCapture(unittest.TestCase):
    def test_used_output_names_never_reused_after_deletion(self):
        w = captured(); w.ctl.reconcile(U1); w.started(2, U2)
        with self.assertRaisesRegex(Refused, 'unused name'):
            w.ctl.prepare_capture(U2, C1)
        self.assertEqual(w.record()['used_capture_ids'], [C1])
        self.assertFalse(w.raw.images)

    def test_gcs_wire_round_trip_capture_quarantine_and_expiry(self):
        from .gcs import GcsSlotStore
        from .test_gcs import BUCKET, ObjectServer
        w = world()
        w.store = GcsSlotStore(BUCKET, transport=ObjectServer(), token_provider=lambda: 'dummy')
        w.ctl = Controller(w.store, w.cloud, w.cfg)
        w.started(); w.ctl.prepare_capture(U1,C1,retain_until=w.clock.now()+timedelta(hours=24))
        self.assertEqual(w.record()['capture']['request_id'],C1)
        self.assertEqual(w.ctl.capture(U1).status,'capture-submitted')
        self.assertEqual(w.ctl.reconcile(U1).status,'released')
        self.assertEqual(w.record()['quarantine'][0]['source_disk_id'],w.record()['last_release']['ids']['boot'])
        w.clock.advance(24*60)
        self.assertEqual(w.ctl.reconcile_quarantine().status,'quarantine-deleted')
        self.assertEqual(w.record()['quarantine'],[])
        self.assertEqual(w.record()['used_capture_ids'],[C1])


class TerminalReceipts(unittest.TestCase):
    def test_quarantine_insert_receipt_survives_operation_retention(self):
        w = captured(True); w.ctl.reconcile(U1)
        w.raw.image_ops.clear()
        w.clock.advance(24*60)
        self.assertEqual(w.ctl.reconcile_quarantine().status, 'quarantine-deleted')
        self.assertFalse(w.raw.images)

    def test_candidate_delete_receipt_survives_later_boot_cleanup_failure(self):
        w = captured(); boot = w.record()['names']['boot']
        w.raw.delete_fail.add(boot)
        self.assertEqual(w.ctl.reconcile(U1).status, 'cleanup-failed')
        self.assertTrue(w.record()['capture']['delete_receipt'])
        w.raw.image_ops.clear(); w.raw.delete_fail.clear()
        self.assertEqual(w.ctl.reconcile(U1).status, 'released')
