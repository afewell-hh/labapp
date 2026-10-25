"""Required fixed access HTTP/key/controller tests: entirely offline fakes."""
import base64
import copy
import json
import struct
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from datetime import timedelta
from urllib.parse import parse_qs, unquote, urlsplit

from . import spec
from .access_records import (AccessError, Context, GcsAccessRecords, KINDS, LIMIT,
                             canonical, digest, public_key, validate_record)
from .auth_http import HttpResponse
from .controller import Controller, FREE, Refused
from .oslogin import OwnKeyImport, SelfLogin, cleanup_own_key
from .test_base_build import world
from .test_lifecycle import U1, U2
from .test_capture import C1

BUCKET = 'test-ledger-bucket'
SELF = 'users/123456789'


def key(byte=1):
    raw = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes([byte])*32
    return 'ssh-ed25519 ' + base64.b64encode(raw).decode()


def response(value, status=200):
    return HttpResponse(status, canonical(value))


class GCS:
    """REST fake with durable objects, generations and delayed single uploads."""
    def __init__(self, w):
        self.w = w
        self.objects = {}
        self.calls = []
        self.seq = 2000
        self.upload_mode = 'ok'
        self.pending = []
        self.get_mode = 'ok'
        self.after_metadata = None
        self.explicit_upload_error = None

    def put(self, name, value):
        self.seq += 1
        self.objects[name] = (copy.deepcopy(value), self.seq)
        return self.seq

    def finish(self):
        for name, value in self.pending:
            if name not in self.objects:
                self.put(name, value)
        self.pending.clear()

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)
        if method == 'POST':
            if self.explicit_upload_error:
                return response({}, self.explicit_upload_error)
            assert parsed.path == '/upload/storage/v1/b/' + BUCKET + '/o'
            assert query['ifGenerationMatch'] == ['0']
            name = query['name'][0]
            value = json.loads(kwargs['body'])
            if name in self.objects:
                return response({}, 412)
            mode, self.upload_mode = self.upload_mode, 'ok'
            if mode == 'pending':
                self.pending.append((name, value))
                raise TimeoutError('must-not-leak')
            gen = self.put(name, value)
            if mode == 'lost':
                raise TimeoutError('must-not-leak')
            return response({'bucket': BUCKET, 'name': name, 'generation': str(gen),
                             'size': str(len(canonical(value)))}, 201)
        assert method == 'GET'
        name = unquote(parsed.path.split('/o/', 1)[1])
        if name == 'slots/slot-1.json':
            value, gen = self.w.store.read(name)
        elif name in self.objects:
            value, gen = self.objects[name]
        else:
            return response({}, 404)
        if self.get_mode == 'error':
            return response({}, 403)
        if self.get_mode == 'network':
            raise TimeoutError('private HTTP diagnostic')
        if self.get_mode == 'badmeta' and query.get('alt') != ['media']:
            return response({'bucket': 'foreign', 'name': name, 'generation': '1', 'size': '1'})
        if query.get('alt') == ['media']:
            assert query['generation'] == [str(gen)]
            if self.get_mode == 'disappear':
                return response({}, 404)
            if self.get_mode == 'duplicate':
                return HttpResponse(200, b'{"schema":1,"schema":1}'.ljust(len(canonical(value)), b' '))
            return response(value)
        if self.after_metadata:
            hook, self.after_metadata = self.after_metadata, None
            hook(name)
        return response({'bucket': BUCKET, 'name': name, 'generation': str(gen),
                         'size': str(len(canonical(value)))})


class OS:
    """Canonical SELF server fake; timeout can commit or delay the mutation."""
    def __init__(self):
        self.profile = {'name': SELF, 'posixAccounts': [
            {'username': 'sa_test', 'uid': '1234', 'gid': '1234', 'homeDirectory': '/home/sa_test',
             'operatingSystemType': 'LINUX'}], 'sshPublicKeys': {}}
        self.calls = []
        self.import_mode = 'ok'
        self.delete_mode = 'ok'
        self.pending = []
        self.on_import = None
        self.profile_mode = 'ok'

    def add(self, text, expiry='0', fingerprint='server_opaque-01'):
        entry = {'key': text, 'expirationTimeUsec': expiry, 'fingerprint': fingerprint,
                 'name': SELF + '/sshPublicKeys/' + fingerprint}
        self.profile['sshPublicKeys'][fingerprint] = entry
        return entry

    def finish(self):
        for text, expiry in self.pending:
            self.add(text, expiry)
        self.pending.clear()

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        p = urlsplit(url)
        assert p.hostname == 'oslogin.googleapis.com'
        assert p.path.startswith('/v1/' + SELF)
        assert kwargs['timeout'] == 20
        assert kwargs['max_bytes'] == 65536
        if method == 'GET':
            assert parse_qs(p.query) == {'projectId': [spec.PROJECT]}
            if self.profile_mode == 'error':
                return response({}, 403)
            if self.profile_mode == 'oversize':
                return HttpResponse(200, b' '*65537)
            return response(self.profile)
        if method == 'POST':
            assert p.path == '/v1/' + SELF + ':importSshPublicKey'
            assert parse_qs(p.query) == {'projectId': [spec.PROJECT]}
            value = json.loads(kwargs['body'])
            assert set(value) == {'key', 'expirationTimeUsec'}
            if self.on_import:
                self.on_import()
            mode = self.import_mode
            if mode == 'pending':
                self.pending.append((value['key'], value['expirationTimeUsec']))
                raise TimeoutError('private diagnostics')
            self.add(value['key'], value['expirationTimeUsec'])
            if mode == 'lost':
                raise TimeoutError('private diagnostics')
            if mode == 'badttl':
                self.profile['sshPublicKeys']['server_opaque-01']['expirationTimeUsec'] = '1'
            if mode == 'badprofile':
                return response({'loginProfile': {'name': 'users/foreign'}})
            return response({'loginProfile': self.profile})
        assert method == 'DELETE'
        assert kwargs['body'] is None
        fp = unquote(p.path.split('/sshPublicKeys/', 1)[1])
        if self.delete_mode != 'pending':
            self.profile['sshPublicKeys'].pop(fp, None)
        if self.delete_mode in ('lost', 'pending'):
            raise TimeoutError('private deletion diagnostics')
        return response({})


class Fixture:
    def __init__(self):
        self.w = world()
        self.w.started()
        self.gcs = GCS(self.w)
        self.records = GcsAccessRecords(BUCKET, token_provider=lambda: 'fake-token', transport=self.gcs)
        self.w.ctl = Controller(self.w.store, self.w.cloud, self.w.cfg, access_records=self.records)
        self.os = OS()
        self.login = SelfLogin(SELF, token_provider=lambda: 'fake-token', transport=self.os)
        self.context = self.register()

    def register(self, request=U1, text=None):
        return self.w.ctl.register_access(request, producer_run_id=91, producer_attempt=1,
                                          self_user=SELF, public_key_text=text or key())

    def session(self):
        return OwnKeyImport(self.records, self.context, self.login, producer_run_id=91,
                            producer_attempt=1, now=self.w.clock.now)

    def imported(self):
        s = self.session()
        s.prepare(key())
        s.import_once()
        return s

    def clean(self):
        return cleanup_own_key(self.records, self.context, self.login, now=self.w.clock.now)

    def posts(self):
        return [c for c in self.os.calls if c[0] == 'POST']

    def stored(self, kind):
        return self.gcs.objects[self.context.path(kind)][0]


class AccessSchema(unittest.TestCase):
    def test_four_paths_derived_from_validated_current_lease_only(self):
        f = Fixture()
        self.assertEqual([f.context.path(k) for k in KINDS],
                         ['access/slot-1/' + U1 + '/' + k + '.json' for k in KINDS])
        for bad in ('../../key', 'intent.json', 'other', ''):
            with self.assertRaises(AccessError): f.context.path(bad)
        for mutate in (lambda r: r.update(state='FREE'), lambda r: r.update(request_id=U2),
                       lambda r: r['ids'].update(instance='9'), lambda r: r['access']['binding'].update(epoch=True),
                       lambda r: r['access']['binding'].update(extra=1)):
            r = copy.deepcopy(f.w.record()); mutate(r)
            with self.assertRaises(AccessError): Context.from_slot(r)

    def test_unknown_fields_private_material_duplicate_json_and_bounds_refused(self):
        f = Fixture(); value, _ = f.session().prepare(key())
        for change in ({'private_key': 'NEVER'}, {'schema': 2}, {'schema': True}, {'kind': 'removed'},
                       {'public_key': key() + ' comment'}, {'expiration_usec': '0'},
                       {'producer_nonce': 'bad'}, {'baseline_sha256': 'x'*64}):
            bad = dict(value, **change)
            with self.assertRaises(AccessError): validate_record(bad, f.context, 'intent')
        f.gcs.get_mode = 'duplicate'
        with self.assertRaises(AccessError): f.records.read(f.context, 'intent')
        f.gcs.get_mode = 'ok'
        bad = copy.deepcopy(value); bad['posix']['username'] = 'x'*LIMIT
        with self.assertRaises(AccessError): validate_record(bad, f.context, 'intent')

    def test_public_wire_canonicalization_rejects_private_wrong_type_and_bad_lengths(self):
        text, sha = public_key(key() + ' a-comment')
        self.assertEqual(text, key()); self.assertEqual(len(sha), 64)
        for bad in ('-----BEGIN OPENSSH PRIVATE KEY-----', 'ssh-rsa YQ==', 'ssh-ed25519 YQ==',
                    key() + '\n', '', None, key().replace('AAA', '!!!', 1)):
            with self.assertRaises(AccessError): public_key(bad)

    def test_record_bindings_and_intent_ref_are_strict(self):
        f = Fixture(); f.imported()
        imported = f.stored('import')
        for mutate in (lambda r: r['binding'].update(lease=U2), lambda r: r.update(intent_generation=0),
                       lambda r: r.update(server_name=SELF+'/sshPublicKeys/foreign'),
                       lambda r: r.update(fingerprint='../../foreign')):
            r = copy.deepcopy(imported); mutate(r)
            with self.assertRaises(AccessError): validate_record(r, f.context, 'import')


class AccessGCS(unittest.TestCase):
    def test_generation_pinned_reads_create_once_exact_paths_and_no_mutation_surface(self):
        f = Fixture(); f.session().prepare(key())
        for method, url, args in f.gcs.calls:
            self.assertIn('storage.googleapis.com/', url)
            if method == 'POST':
                self.assertEqual(parse_qs(urlsplit(url).query)['ifGenerationMatch'], ['0'])
                self.assertEqual(parse_qs(urlsplit(url).query)['name'], [f.context.path('intent')])
        media = [c for c in f.gcs.calls if parse_qs(urlsplit(c[1]).query).get('alt') == ['media']]
        self.assertTrue(media)
        self.assertTrue(all('generation' in parse_qs(urlsplit(c[1]).query) for c in media))
        for name in ('write', 'delete', 'list', 'overwrite'):
            self.assertFalse(hasattr(f.records, name))

    def test_lost_upload_is_equal_readback_never_blind_retry(self):
        f = Fixture(); f.gcs.upload_mode = 'lost'
        s = f.session(); s.prepare(key()); s.import_once()
        self.assertEqual(len(f.posts()), 1)
        uploads = [c for c in f.gcs.calls if c[0] == 'POST' and parse_qs(urlsplit(c[1]).query)['name'] == [f.context.path('intent')]]
        self.assertEqual(len(uploads), 1)

    def test_explicit_upload_denial_or_error_blocks_even_existing_equal_content(self):
        f = Fixture(); value, _ = f.session().prepare(key())
        for status in (403, 500):
            f.gcs.explicit_upload_error = status
            with self.assertRaises(AccessError): f.records.create(f.context, 'intent', value)
        self.assertFalse(f.posts())

    def test_existing_equal_intent_does_not_grant_original_winner(self):
        f = Fixture(); value, gen = f.session().prepare(key())
        self.assertEqual(f.records.create(f.context, 'intent', value), (gen, False))
        with self.assertRaises(AccessError): f.session().prepare(key())
        self.assertFalse(f.posts())

    def test_pending_upload_absence_is_uncertain_and_delayed_old_object_isolated(self):
        f = Fixture(); f.gcs.upload_mode = 'pending'
        s = f.session()
        with self.assertRaises(AccessError): s.prepare(key())
        with self.assertRaises(AccessError): s.import_once()
        self.assertEqual(f.w.ctl.reconcile(U1).status, 'blocked')
        self.assertNotEqual(f.w.record()['state'], FREE)
        f.gcs.finish()
        with self.assertRaises(AccessError): f.session().prepare(key())
        self.assertFalse(f.posts())

    def test_metadata_observation_followed_by_404_never_becomes_absence(self):
        f = Fixture(); f.session().prepare(key()); f.gcs.get_mode = 'disappear'
        with self.assertRaises(AccessError): f.records.read(f.context, 'intent')

    def test_permission_and_oversized_reads_fail_closed(self):
        f = Fixture(); f.session().prepare(key())
        f.gcs.get_mode = 'error'
        with self.assertRaises(AccessError): f.records.read(f.context, 'intent')
        f.gcs.get_mode = 'ok'
        value, gen = f.gcs.objects[f.context.path('intent')]
        f.gcs.objects[f.context.path('intent')] = (dict(value, extra='x'*LIMIT), gen)
        with self.assertRaises(AccessError): f.records.read(f.context, 'intent')


class OwnKeyTests(unittest.TestCase):
    def test_intent_durable_before_sole_import_exact_http_and_server_identity(self):
        f = Fixture()
        f.os.on_import = lambda: self.assertIn(f.context.path('intent'), f.gcs.objects)
        s = f.imported()
        self.assertEqual(len(f.posts()), 1)
        self.assertEqual(f.stored('import')['fingerprint'], 'server_opaque-01')
        self.assertNotEqual(f.stored('import')['fingerprint'], f.context.binding['key_sha256'])
        self.assertEqual(f.stored('import')['intent_sha256'], digest(f.stored('intent')))
        for _ in range(2):
            with self.assertRaises(AccessError): s.import_once()
            with self.assertRaises(AccessError): s.prepare(key())
            with self.assertRaises(AccessError): f.session().prepare(key())
        self.assertEqual(len(f.posts()), 1)

    def test_concurrent_and_copied_invocation_consumes_shared_capability_once(self):
        f = Fixture(); s = f.session(); s.prepare(key())
        copied = copy.copy(s)
        def attempt(session):
            try:
                session.import_once()
                return 'ok'
            except AccessError:
                return 'refused'
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(attempt, (s, copied, s, copied)))
        self.assertEqual(results.count('ok'), 1)
        self.assertEqual(len(f.posts()), 1)

    def test_forked_process_cannot_consume_original_process_capability(self):
        f = Fixture(); s = f.session(); s.prepare(key())
        with patch('lifecycle.oslogin.os.getpid', return_value=-1):
            with self.assertRaises(AccessError): s.import_once()
        self.assertFalse(f.posts())
        s.import_once()
        self.assertEqual(len(f.posts()), 1)

    def test_wrong_producer_run_attempt_or_identity_refused(self):
        f = Fixture()
        for run, attempt in ((92, 1), (91, 2), (True, 1)):
            with self.assertRaises(AccessError):
                OwnKeyImport(f.records, f.context, f.login, producer_run_id=run,
                             producer_attempt=attempt, now=f.w.clock.now)
        wrong = SelfLogin('users/foreign', token_provider=lambda: 'fake-token', transport=f.os)
        with self.assertRaises(AccessError): cleanup_own_key(f.records, f.context, wrong, now=f.w.clock.now)
        self.assertFalse(f.posts())

    def test_cleanup_recovery_returns_immutable_receipt_without_overwrite(self):
        f = Fixture(); f.imported(); old = f.clean()
        f.w.clock.advance(1)
        self.assertEqual(f.clean(), old)
        self.assertEqual(len([c for c in f.os.calls if c[0] == 'DELETE']), 1)
        self.assertEqual(len([c for c in f.gcs.calls if c[0] == 'POST' and
                              parse_qs(urlsplit(c[1]).query)['name'] == [f.context.path('removed')]]), 1)

    def test_process_restart_before_import_cannot_reconstruct_capability(self):
        f = Fixture(); f.session().prepare(key())
        restarted = f.session()
        with self.assertRaises(AccessError): restarted.import_once()
        with self.assertRaises(AccessError): restarted.prepare(key())
        self.assertFalse(f.posts())
        self.assertEqual(f.w.ctl.reconcile(U1).status, 'blocked')

    def test_preexisting_key_comments_are_canonical_collision_not_adopted(self):
        f = Fixture(); f.os.add(key()+' old-comment')
        with self.assertRaisesRegex(AccessError, 'preexists'): f.session().prepare(key())
        self.assertFalse(f.posts()); self.assertFalse(f.gcs.objects)

    def test_expired_intent_is_consumed_without_post_even_before_work_deadline(self):
        f = Fixture(); s = f.session(); s.prepare(key())
        f.w.clock.advance(21)
        with self.assertRaisesRegex(AccessError, 'expiration'): s.import_once()
        with self.assertRaises(AccessError): s.import_once()
        self.assertFalse(f.posts())
        self.assertEqual(f.w.ctl.reconcile(U1).status, 'blocked')

    def test_slow_intent_read_crossing_ttl_or_work_deadline_never_submits(self):
        for offset in (0, 25):
            f = Fixture(); f.w.clock.advance(offset)
            s = f.session(); s.prepare(key())
            f.w.clock.advance((20 if offset == 0 else 5) - 0.01)
            read = f.records.read
            def slow_read(context, kind):
                result = read(context, kind)
                if kind == 'intent':
                    f.w.clock.t += timedelta(seconds=2)
                return result
            f.records.read = slow_read
            with self.assertRaises(AccessError): s.import_once()
            with self.assertRaises(AccessError): s.import_once()
            self.assertFalse(f.posts())

    def test_token_acquisition_crossing_expiration_never_submits(self):
        f = Fixture(); s = f.session(); s.prepare(key())
        f.w.clock.advance(19.99)
        def delayed_token():
            f.w.clock.t += timedelta(seconds=2)
            return 'fake-token'
        f.login.token_provider = delayed_token
        with self.assertRaises(AccessError): s.import_once()
        with self.assertRaises(AccessError): s.import_once()
        self.assertFalse(f.posts())

    def test_finite_ttl_and_work_deadline_no_refresh(self):
        f = Fixture(); f.w.clock.advance(25)
        s = f.session(); intent, _ = s.prepare(key())
        self.assertEqual(int(intent['expiration_usec']), int((f.w.clock.now()+timedelta(minutes=5)).timestamp()*1_000_000))
        f.w.clock.advance(6)
        with self.assertRaises(AccessError): s.import_once()
        with self.assertRaises(AccessError): s.import_once()
        self.assertFalse(f.posts())

    def test_wrong_self_root_posix_ambiguous_posix_and_profile_errors_refused(self):
        for change in ('self', 'root', 'duplicate', 'error', 'oversize'):
            f = Fixture()
            if change == 'self': f.os.profile['name'] = 'users/foreign'
            if change == 'root': f.os.profile['posixAccounts'][0]['uid'] = '0'
            if change == 'duplicate': f.os.profile['posixAccounts'] *= 2
            if change in ('error', 'oversize'): f.os.profile_mode = change
            with self.assertRaises(AccessError): f.session().prepare(key())
            self.assertFalse(f.posts())

    def test_missing_foreign_and_conflicting_server_keys_refused(self):
        for mode in ('badttl', 'badprofile'):
            f = Fixture(); f.os.import_mode = mode
            s = f.session(); s.prepare(key())
            with self.assertRaises(AccessError): s.import_once()
            self.assertNotIn(f.context.path('import'), f.gcs.objects)
            self.assertEqual(f.w.ctl.reconcile(U1).status, 'blocked')

    def test_lost_import_profile_presence_cleanup_or_expiry_cannot_settle(self):
        for mode in ('lost', 'pending'):
            f = Fixture(); f.os.import_mode = mode
            s = f.session(); s.prepare(key())
            with self.assertRaises(AccessError) as caught: s.import_once()
            self.assertNotIn('private diagnostics', str(caught.exception))
            with self.assertRaises(AccessError): s.import_once()
            f.w.clock.advance(60)
            with self.assertRaises(AccessError): f.clean()
            self.assertEqual(f.w.ctl.reconcile(U1).status, 'blocked')
            self.assertNotEqual(f.w.record()['state'], FREE)
            f.os.finish()
            # A late key does not make a missing terminal import receipt valid.
            with self.assertRaises(AccessError): f.clean()
            with self.assertRaises(AccessError): f.session().prepare(key())
            self.assertEqual(len(f.posts()), 1)

    def test_exact_own_key_cleanup_preserves_unrelated_and_uses_server_name(self):
        f = Fixture(); other = copy.deepcopy(f.os.add(key(2), fingerprint='unrelated'))
        f.imported(); receipt = f.clean()
        self.assertEqual(receipt['outcome'], 'removed')
        self.assertEqual(f.os.profile['sshPublicKeys'], {'unrelated': other})
        deletes = [c for c in f.os.calls if c[0] == 'DELETE']
        self.assertEqual(len(deletes), 1)
        self.assertTrue(deletes[0][1].endswith('/'+SELF+'/sshPublicKeys/server_opaque-01'))
        self.assertEqual(len(f.posts()), 1)

    def test_uncertain_delete_requires_authenticated_absence_and_accurate_label(self):
        f = Fixture(); f.imported(); f.os.delete_mode = 'lost'
        self.assertEqual(f.clean()['outcome'], 'absence-verified-after-uncertain-delete')
        self.assertEqual(f.w.ctl.reconcile(U1).status, 'released')
        f = Fixture(); f.imported(); f.os.delete_mode = 'pending'
        with self.assertRaises(AccessError): f.clean()
        self.assertNotIn(f.context.path('removed'), f.gcs.objects)
        self.assertEqual(f.w.ctl.reconcile(U1).status, 'blocked')
        f.os.profile['sshPublicKeys'].clear()  # exact delayed DELETE completes
        self.assertEqual(f.clean()['outcome'], 'absent')
        self.assertEqual(f.w.ctl.reconcile(U1).status, 'released')

    def test_expired_absence_distinct_from_delete(self):
        f = Fixture(); f.imported(); f.w.clock.advance(21)
        f.os.profile['sshPublicKeys'].clear()
        self.assertEqual(f.clean()['outcome'], 'expired-absent')
        self.assertFalse([c for c in f.os.calls if c[0] == 'DELETE'])

    def test_profile_error_duplicate_keys_or_identity_drift_never_removes_others(self):
        for mode in ('error', 'duplicate', 'drift'):
            f = Fixture(); f.imported()
            if mode == 'error': f.os.profile_mode = 'error'
            if mode == 'duplicate': f.os.add(key(), fingerprint='duplicate')
            if mode == 'drift': f.os.profile['sshPublicKeys']['server_opaque-01']['expirationTimeUsec'] = '1'
            with self.assertRaises(AccessError): f.clean()
            self.assertFalse([c for c in f.os.calls if c[0] == 'DELETE'])


class AccessController(unittest.TestCase):
    def test_success_archive_occupied_before_free_records_retained_separately(self):
        f = Fixture(); f.imported(); f.clean()
        observed = []
        real = f.w.ctl._cas
        def cas(prev, rec, gen):
            if 'access' in rec:
                observed.append((rec['state'], rec['access']['phase']))
            return real(prev, rec, gen)
        f.w.ctl._cas = cas
        self.assertEqual(f.w.ctl.reconcile(U1).status, 'released')
        self.assertIn(('CLEANUP_FAILED', 'finalizing'), observed)
        self.assertIn(('CLEANUP_FAILED', 'archived'), observed)
        history = f.w.record()['access_history']
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['binding'], f.context.binding)
        for kind in ('intent', 'import', 'removed'):
            value, gen = f.gcs.objects[f.context.path(kind)]
            self.assertEqual(history[0]['archive'][kind], {'path': f.context.path(kind), 'generation': gen, 'sha256': digest(value)})
        self.assertEqual(history[0]['archive']['seal']['generation'], 0)
        self.assertEqual(len(f.gcs.objects), 3)
        self.assertFalse([c for c in f.gcs.calls if c[0] == 'DELETE'])
        self.assertEqual((f.w.raw.instances, f.w.raw.disks), ({}, {}))

    def test_missing_partial_wrong_digest_or_stale_receipts_hold_after_vm404(self):
        for mode in ('missing-import', 'missing-removed', 'digest', 'epoch'):
            f = Fixture(); f.imported(); f.clean()
            if mode.startswith('missing'): del f.gcs.objects[f.context.path(mode.split('-', 1)[1])]
            else:
                r, g = f.gcs.objects[f.context.path('removed')]
                if mode == 'digest': r['intent_sha256'] = '0'*64
                if mode == 'epoch': r['binding']['epoch'] += 1
            self.assertEqual(f.w.ctl.reconcile(U1).status, 'blocked')
            self.assertNotEqual(f.w.record()['state'], FREE)
            self.assertEqual((f.w.raw.instances, f.w.raw.disks), ({}, {}))
            self.assertEqual(f.w.record()['access']['phase'], 'finalizing')
            with self.assertRaises(Refused): f.w.ctl.admit(2, 1, U2)

    def test_access_http_metadata_and_duplicate_json_errors_return_blocked(self):
        for mode in ('error', 'network', 'badmeta', 'duplicate'):
            f = Fixture(); f.imported(); f.clean(); f.gcs.get_mode = mode
            outcome = f.w.ctl.reconcile(U1)
            self.assertEqual(outcome.status, 'blocked')
            self.assertNotEqual(f.w.record()['state'], FREE)
            self.assertNotIn('private HTTP diagnostic', outcome.detail)
            self.assertEqual(f.w.record()['access']['phase'], 'finalizing')
            self.assertEqual(len(f.posts()), 1)

    def test_cas_conflict_rechecks_without_reimport_or_duplicate_archive(self):
        f = Fixture(); f.imported(); f.clean()
        def race(name, record):
            actual, gen = f.w.store.read(name)
            f.w.store.write(name, actual, if_generation_match=gen)
        f.w.store.before_write = race
        self.assertEqual(f.w.ctl.reconcile(U1).status, 'released')
        self.assertEqual(len(f.posts()), 1)
        self.assertEqual(len(f.w.record()['access_history']), 1)

    def test_capture_missing_seal_and_fabricated_hashes_cannot_bypass_provenance(self):
        f = Fixture(); f.imported(); f.clean()
        with self.assertRaises(Refused): f.w.ctl.prepare_capture(U1, C1)
        intent, gen = f.records.read(f.context, 'intent')
        seal = {'schema': 1, 'kind': 'seal', 'binding': f.context.binding,
                'intent_generation': gen, 'intent_sha256': digest(intent),
                'provenance_sha256': '1'*64, 'manifest_sha256': '2'*64,
                'postcondition_sha256': '3'*64, 'nonce': '4'*64, 'result': 'sealed'}
        f.records.create(f.context, 'seal', seal)
        with self.assertRaisesRegex(Refused, 'ownership/sealing'): f.w.ctl.prepare_capture(U1, C1)
        self.assertFalse([c for c in f.w.raw.calls if c[:2] == ('images', 'insert')])

    def test_delayed_old_uuid_upload_cannot_authorize_or_occupy_new_lease(self):
        f = Fixture(); f.imported(); f.clean()
        intent, gen = f.records.read(f.context, 'intent')
        old_seal = {'schema': 1, 'kind': 'seal', 'binding': f.context.binding,
                    'intent_generation': gen, 'intent_sha256': digest(intent),
                    'provenance_sha256': '1'*64, 'manifest_sha256': '2'*64,
                    'postcondition_sha256': '3'*64, 'nonce': '4'*64, 'result': 'sealed'}
        f.gcs.upload_mode = 'pending'
        with self.assertRaises(AccessError): f.records.create(f.context, 'seal', old_seal)
        self.assertEqual(f.w.ctl.reconcile(U1).status, 'released')
        f.w.ctl.admit(2, 1, U2); f.w.ctl.submit(U2); f.w.ctl.confirm_created(U2)
        newer = f.register(U2, key(3))
        f.gcs.finish()
        self.assertIn(f.context.path('seal'), f.gcs.objects)
        self.assertEqual(f.records.read(newer, 'seal'), (None, 0))
        self.assertEqual(f.w.record()['request_id'], U2)
        with self.assertRaises(AccessError): f.records.create(f.context, 'seal', old_seal)
        self.assertEqual(f.w.ctl.reconcile(U1).status, 'superseded')
        self.assertEqual(f.w.ctl.reconcile(U2).status, 'blocked')

    def test_never_reuse_key_or_lease_even_same_producer_attempt(self):
        f = Fixture(); f.imported(); f.clean()
        self.assertEqual(f.w.ctl.reconcile(U1).status, 'released')
        f.w.ctl.admit(2, 1, U2); f.w.ctl.submit(U2); f.w.ctl.confirm_created(U2)
        with self.assertRaisesRegex(Refused, 'never be reused'): f.register(U2, key())
        self.assertNotIn('access', f.w.record())
        newer = f.register(U2, key(4))
        self.assertNotEqual(newer.path('intent'), f.context.path('intent'))

    def test_no_adapter_or_accounting_limit_cannot_optimistically_release(self):
        f = Fixture(); f.imported(); f.clean()
        f.w.ctl.access_records = None
        self.assertEqual(f.w.ctl.reconcile(U1).status, 'blocked')
        f = Fixture(); f.imported(); f.clean(); f.w.ctl.reconcile(U1)
        r, gen = f.w.store.read(f.w.cfg.key)
        r['access_history'] *= 16
        f.w.store.write(f.w.cfg.key, r, if_generation_match=gen)
        f.w.ctl.admit(2, 1, U2); f.w.ctl.submit(U2); f.w.ctl.confirm_created(U2)
        with self.assertRaisesRegex(Refused, 'accounting limit'): f.register(U2, key(4))

    def test_binding_and_archival_cannot_regress(self):
        f = Fixture(); prev = f.w.record()
        for mode in ('remove', 'binding'):
            changed = copy.deepcopy(prev)
            if mode == 'remove': del changed['access']
            else: changed['access']['binding']['attempt'] += 1
            with self.assertRaises(AssertionError): f.w.ctl._cas(prev, changed, f.w.store.read(f.w.cfg.key)[1])


if __name__ == '__main__':
    unittest.main()
