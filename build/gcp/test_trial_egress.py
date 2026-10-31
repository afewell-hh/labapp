"""Zero-cloud synthetic tests; process/network production adapters are mocked."""
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timezone
import io
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import Mock, patch

from build.gcp import trial_egress as e


def pending():
    return {'schema': 1, 'nonce': 'a' * 64, 'request_id': '11111111-1111-4111-8111-111111111111',
            'started_at': 1700000000, 'cleanup_at': 1700008400, 'hard_at': 1700009000,
            'owner': e.OWNER, 'router_404': True, 'sources': e.source_hashes()}


def router(nat=False):
    value = {'kind': 'compute#router', 'id': '123', 'name': e.ROUTER.rsplit('/', 1)[1],
             'creationTimestamp': datetime.fromtimestamp(1700000001, timezone.utc).isoformat(),
             'description': e.DESCRIPTION + 'a' * 64, 'region': e.REGION,
             'network': e.ROOT + '/global/networks/default', 'selfLink': e.ROUTER}
    if nat:
        value['nats'] = [{'name': e.NAT, 'type': 'PUBLIC', 'autoNetworkTier': 'PREMIUM',
                         'natIpAllocateOption': 'AUTO_ONLY', 'sourceSubnetworkIpRangesToNat': 'LIST_OF_SUBNETWORKS',
                         'subnetworks': [{'name': e.SUBNET, 'sourceIpRangesToNat': ['PRIMARY_IP_RANGE']}]}]
    return value


def op(kind='insert', status='DONE'):
    return {'name': 'operation-' + kind, 'targetLink': e.ROUTER, 'targetId': '123',
            'operationType': kind, 'region': e.REGION, 'user': e.OWNER, 'status': status}


def address():
    return {'name': 'auto-address', 'id': '456', 'address': '203.0.113.10',
            'selfLink': e.REGION + '/addresses/auto-address', 'region': e.REGION,
            'purpose': 'NAT_AUTO', 'addressType': 'EXTERNAL', 'networkTier': 'PREMIUM'}


class FakeAPI:
    def __init__(self, nat=True):
        self.value = router(nat)
        self.allocated = nat
        self.calls = []
        self.ops = {'operation-insert': op()}

    def check(self):
        pass

    def router(self):
        self.calls.append('router')
        return deepcopy(self.value)

    def ips(self):
        self.calls.append('ips')
        return {'result': [{'natName': e.NAT, 'natIpInfoMappings': [
            {'natIp': '203.0.113.10', 'usage': 'IN_USE', 'mode': 'AUTO'}]}]} if self.allocated else {}

    def addresses(self):
        return [address()] if self.allocated else []

    def address(self, _captured):
        self.calls.append('address')
        return address() if self.allocated else None

    def operation(self, key):
        return deepcopy(self.ops[key])

    def remove_nat(self, _request_id):
        self.calls.append('PATCH')
        self.value.pop('nats')
        self.allocated = False
        self.ops['operation-patch'] = op('patch')
        return op('patch')

    def remove_router(self, _request_id):
        self.calls.append('DELETE')
        self.value = None
        self.ops['operation-delete'] = op('delete')
        return op('delete')


class Egress(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(e, 'command', side_effect=AssertionError('unexpected native command')))
        self.stack.enter_context(patch.object(e.time, 'sleep', side_effect=AssertionError('unexpected wait')))
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='egress-offline-')))
        self.directory.chmod(0o700)
        self.state = self.stack.enter_context(e.State(self.directory))

    def owned(self):
        self.state.write('intent.json', pending())
        self.state.write('router.json', router())
        self.state.write('create-operation.json', op())

    def test_normal_cleanup_terminal_mutations_and_actual_address404(self):
        self.owned()
        api = FakeAPI()
        self.assertTrue(e.cleanup(self.state, api)['allocations_absent'])
        self.assertEqual([c for c in api.calls if c in ('PATCH', 'DELETE')], ['PATCH', 'DELETE'])
        self.assertIn('address', api.calls)
        self.assertIsNotNone(self.state.read('nat-attempt.json'))

    def test_router_only_partial_setup_does_not_patch(self):
        self.owned()
        api = FakeAPI(False)
        e.cleanup(self.state, api)
        self.assertNotIn('PATCH', api.calls)
        self.assertIn('DELETE', api.calls)

    def test_pending_lost_capture_never_adopts_even_when_router404(self):
        self.state.write('intent.json', pending())
        for value in (router(), None):
            api = FakeAPI()
            api.value = value
            with self.assertRaises(e.Failure):
                e.cleanup(self.state, api)
            self.assertNotIn('DELETE', api.calls)

    def test_changed_identity_config_and_extra_nat_refuse_before_mutation(self):
        self.owned()
        changes = ({'id': '999'}, {'description': 'foreign'}, {'interfaces': [{'name': 'foreign'}]},
                   {'bgpPeers': [{'name': 'peer'}]}, {'newField': True},
                   {'nats': router(True)['nats'] * 2}, {'network': 'foreign'})
        for change in changes:
            api = FakeAPI()
            api.value.update(change)
            with self.assertRaises(e.Failure):
                e.cleanup(self.state, api)
            self.assertNotIn('PATCH', api.calls)

    def test_wrong_nat_subnet_type_or_all_ranges_refused(self):
        for key, value in (('type', 'PRIVATE'), ('autoNetworkTier', 'STANDARD'),
                           ('natIpAllocateOption', 'MANUAL_ONLY'), ('sourceSubnetworkIpRangesToNat', 'ALL_SUBNETWORKS_ALL_IP_RANGES')):
            config = router(True)['nats']
            config[0][key] = value
            with self.assertRaises(e.Failure): e.valid_nat(config)

    def test_capture_requires_own_terminal_insert_before_nat(self):
        self.state.write('intent.json', pending())
        self.state.write('create-operation.json', op())
        with self.assertRaises(e.Failure): e.capture(self.state, FakeAPI())
        e.capture(self.state, FakeAPI(False))
        self.assertEqual(self.state.read('router.json')['id'], '123')

    def test_capture_nat_and_refresh_address_identity(self):
        self.owned()
        api = FakeAPI()
        e.capture_nat(self.state, api)
        self.assertEqual(self.state.read('initial-allocations.json')[0]['id'], '456')
        e.cleanup(self.state, api)

    def test_changed_captured_nat_refuses(self):
        self.owned()
        api = FakeAPI()
        e.capture_nat(self.state, api)
        api.value['nats'][0]['minPortsPerVm'] = 64
        with self.assertRaises(e.Failure): e.cleanup(self.state, api)
        self.assertNotIn('PATCH', api.calls)

    def test_initial_and_later_auto_allocations_both_require_absence(self):
        self.owned()
        previous = {k: address()[k] for k in ('name', 'id', 'address', 'selfLink', 'purpose')}
        previous.update(name='old-auto-address', id='455', address='203.0.113.11',
                        selfLink=e.REGION + '/addresses/old-auto-address')
        self.state.write('initial-allocations.json', [previous])
        api = FakeAPI()
        e.cleanup(self.state, api)
        records = self.state.read('allocations.json')
        self.assertEqual({r['id'] for r in records}, {'455', '456'})
        self.assertGreaterEqual(api.calls.count('address'), 3)

    def test_foreign_or_malformed_evidence_refuses_before_cloud(self):
        self.owned()
        self.state.write('foreign.json', {'unknown': True})
        api = FakeAPI()
        with self.assertRaises(e.Failure): e.cleanup(self.state, api)
        self.assertEqual(api.calls, [])

    def test_nat_terminal_failure_never_deletes_router(self):
        self.owned()
        api = FakeAPI()
        remove = api.remove_nat
        def rejected(request_id):
            return {**remove(request_id), 'error': {'errors': [{}]}}
        api.remove_nat = rejected
        with self.assertRaises(e.Failure): e.cleanup(self.state, api)
        self.assertNotIn('DELETE', api.calls)

    def test_unknown_or_inconsistent_allocation_refuses(self):
        self.owned()
        for bad in ([], [{**address(), 'purpose': 'GCE_ENDPOINT'}]):
            api = FakeAPI()
            api.addresses = lambda: bad
            with self.assertRaises(e.Failure): e.cleanup(self.state, api)
            self.assertNotIn('PATCH', api.calls)

    def test_configuration_change_immediately_before_patch_refuses(self):
        self.owned()
        api = FakeAPI()
        first = api.router()
        api.router = Mock(side_effect=[first, {**first, 'id': '999'}])
        with self.assertRaises(e.Failure): e.cleanup(self.state, api)
        self.assertNotIn('PATCH', api.calls)

    def test_prepatch_retry_same_ip_new_address_identity_proves_both404(self):
        self.owned()
        first = FakeAPI()
        before = first.router()
        first.router = Mock(side_effect=[before, {**before, 'id': '999'}])
        with self.assertRaises(e.Failure): e.cleanup(self.state, first)
        self.assertIsNotNone(self.state.read('allocations.json'))
        self.assertIsNone(self.state.read('nat-attempt.json', optional=True))
        api = FakeAPI()
        replacement = {**address(), 'name': 'later-auto-address', 'id': '457',
                       'selfLink': e.REGION + '/addresses/later-auto-address'}
        api.addresses = lambda: [replacement]
        observed = []
        def get(captured):
            observed.append((captured['name'], captured['id'], api.allocated))
            return deepcopy(replacement) if api.allocated else None
        api.address = get
        e.cleanup(self.state, api)
        records = self.state.read('final-allocations.json')
        self.assertEqual({record['id'] for record in records}, {'456', '457'})
        self.assertIn(('auto-address', '456', False), observed)
        self.assertIn(('later-auto-address', '457', False), observed)
        self.assertEqual(api.calls.count('PATCH'), 1)

    def test_pending_recorded_patch_resumes_before_nat_reread_without_resubmit(self):
        self.owned()
        api = FakeAPI()
        submit = api.remove_nat
        def pending_patch(request_id):
            submit(request_id)
            api.value = router(True)  # Submission accepted; NAT is still present.
            api.allocated = True
            return op('patch', 'RUNNING')
        api.remove_nat = pending_patch
        with patch.object(api, 'check', side_effect=e.Failure('interrupted', 143)):
            with self.assertRaises(e.Failure): e.cleanup(self.state, api)
        self.assertEqual(self.state.read('nat-operation.json')['status'], 'RUNNING')
        self.assertTrue(api.value['nats'])
        def finished(operation_name):
            self.assertEqual(operation_name, 'operation-patch')
            api.value.pop('nats', None)
            api.allocated = False
            return op('patch')
        api.operation = finished
        with patch.object(e.time, 'sleep', return_value=None):
            e.cleanup(self.state, api)
        self.assertEqual(api.calls.count('PATCH'), 1)
        self.assertEqual(api.calls.count('DELETE'), 1)

    def test_lost_mutation_response_leaves_attempt_and_never_retries(self):
        self.owned()
        api = FakeAPI()
        api.remove_nat = Mock(side_effect=e.Failure('ambiguous', 124))
        with self.assertRaises(e.Failure) as caught: e.cleanup(self.state, api)
        self.assertEqual(caught.exception.code, 124)
        self.assertIsNotNone(self.state.read('nat-attempt.json'))
        with self.assertRaises(e.Failure): e.cleanup(self.state, api)
        self.assertEqual(api.remove_nat.call_count, 1)

    def test_operation_error_or_changed_target_is_not_terminal_success(self):
        for change in ({'targetId': '999'}, {'error': {'errors': [{}]}}, {'status': 'UNKNOWN'}, {'user': 'other'}):
            with self.assertRaises(e.Failure): e.operation({**op(), **change}, '123', 'insert')

    def test_router404_without_terminal_delete_is_not_success(self):
        self.owned()
        api = FakeAPI()
        api.value = None
        with self.assertRaises(e.Failure): e.cleanup(self.state, api)

    def test_terminal_delete_successor_withholds_success(self):
        self.owned()
        api = FakeAPI(False)
        def replacement(_request_id):
            api.value = {**router(), 'id': '999'}
            return op('delete')
        api.remove_router = replacement
        with self.assertRaises(e.Failure): e.cleanup(self.state, api)

    def test_address_successor_withholds_success_without_delete(self):
        self.owned()
        api = FakeAPI()
        original = api.address
        api.address = lambda r: original(r) if api.allocated else {**address(), 'id': '999'}
        with self.assertRaises(e.Failure): e.cleanup(self.state, api)

    def test_two_cleanup_or_capture_controllers_cannot_overlap(self):
        for _operation in ('cleanup', 'capture', 'arm'):
            with self.assertRaises(BlockingIOError):
                with e.State(self.directory): self.fail('overlapping controller entered')
        self.state.write('still-owned.json', {'ok': True})
        self.assertTrue(self.state.read('still-owned.json')['ok'])

    def test_private_files_links_foreign_owner_and_duplicate_json_refuse(self):
        self.state.write('target.json', {'ok': True})
        os.link(self.directory / 'target.json', self.directory / 'hard.json')
        with self.assertRaises(e.guest.Failure): self.state.read('hard.json')
        (self.directory / 'soft.json').symlink_to(self.directory / 'target.json')
        with self.assertRaises((e.guest.Failure, OSError)): self.state.read('soft.json')
        (self.directory / 'bad.json').write_bytes(b'{"x":1,"x":2}')
        (self.directory / 'bad.json').chmod(0o600)
        with self.assertRaises(e.guest.Failure): self.state.read('bad.json')
        with patch.object(e.os, 'geteuid', return_value=os.geteuid() + 1):
            with self.assertRaises(e.guest.Failure): self.state.read('target.json')

    def test_intent_deadlines_cannot_renew_and_source_cannot_change(self):
        for change in ({'cleanup_at': 1700008401}, {'hard_at': 1700009001}, {'sources': {}}, {'schema': True}):
            with self.assertRaises(e.Failure): e.intent({**pending(), **change})

    def test_arm_requires_observed404_and_preserves_intent_on_rerun(self):
        api = FakeAPI(False)
        with self.assertRaises(e.Failure): e.arm(self.state, api, now=lambda: 1700000000)
        api.value = None
        e.arm(self.state, api, now=lambda: 1700000000)
        before = self.state.read('intent.json')
        with self.assertRaises(e.Failure): e.arm(self.state, api)
        self.assertEqual(self.state.read('intent.json'), before)

    def test_expiry_waits_without_auth_then_cleans_at_fixed_deadline(self):
        self.owned()
        api = FakeAPI(False)
        with patch.object(e.signal, 'signal'), \
             patch.object(e.time, 'time', return_value=1700008399), patch.object(e, 'API') as constructor:
            # Supply a context wrapper so the already-held state lock stays held.
            context = Mock()
            context.__enter__ = Mock(return_value=self.state)
            context.__exit__ = Mock(return_value=False)
            with patch.object(e, 'State', return_value=context):
                self.assertEqual(e.main(['expire']), 0)
                constructor.assert_not_called()
                with patch.object(e.time, 'time', return_value=1700008400):
                    constructor.return_value = api
                    with patch('sys.stdout', new=io.StringIO()): self.assertEqual(e.main(['expire']), 0)

    def test_main_preserves_cancellation_status_and_reports_unresolved(self):
        context = Mock()
        context.__enter__ = Mock(side_effect=e.Failure('cancelled', 143))
        context.__exit__ = Mock(return_value=False)
        with patch.object(e, 'State', return_value=context), patch.object(e.signal, 'signal'), \
             patch('sys.stderr', new=io.StringIO()) as output:
            self.assertEqual(e.main(['cleanup']), 143)
            self.assertIn('unresolved', output.getvalue())


class Transport(unittest.TestCase):
    def api(self, status=200, body=b'{}'):
        response = Mock(code=status)
        response.read.return_value = body
        opener = Mock()
        opener.open.return_value = response
        return e.API(opener=opener), response, opener

    def request(self, api, function):
        with patch.object(e, 'command', return_value=b'public-fixture-token'), \
             patch.object(e, 'alarm'):
            return function()

    def test_observed404_only_and_denials_never_absence(self):
        for status in (200, 404, 401, 403, 409, 429, 500):
            api, _, _ = self.api(status)
            if status in (200, 404):
                self.assertEqual(self.request(api, api.router), {} if status == 200 else None)
            else:
                with self.assertRaises(e.Failure): self.request(api, api.router)

    def test_mutation_surface_exact_fixed_urls_bodies_and_no_address_delete(self):
        api, _, opener = self.api()
        request_id = pending()['request_id']
        for function, method in ((lambda: api.remove_nat(request_id), 'PATCH'),
                                 (lambda: api.remove_router(request_id), 'DELETE')):
            self.request(api, function)
            request = opener.open.call_args.args[0]
            self.assertEqual(request.method, method)
            self.assertEqual(request.full_url, e.ROUTER + '?requestId=' + request_id)
            self.assertEqual(request.data, b'{"nats":[]}' if method == 'PATCH' else None)
        self.assertFalse(hasattr(api, 'delete_address'))

    def test_response_bound_malformed_and_unknown_list_refuse(self):
        for body in (b'x' * (e.LIMIT + 1), b'not-json', b'{"x":1,"x":2}'):
            api, _, _ = self.api(body=body)
            with self.assertRaises((e.Failure, ValueError)): self.request(api, api.router)
        api, _, _ = self.api(body=b'{"nextPageToken":"more"}')
        with self.assertRaises(e.Failure): self.request(api, api.addresses)

    def test_transport_timeout_and_close_failure_preserve_primary_code(self):
        api, response, _ = self.api()
        response.read.side_effect = e.Failure('timeout', 124)
        response.close.side_effect = OSError('close failure')
        with self.assertRaises(e.Failure) as caught: self.request(api, api.router)
        self.assertEqual(caught.exception.code, 124)
        self.assertTrue(caught.exception.cleanup_uncertain)

    def test_total_deadline_refuses_before_token_or_network(self):
        api = e.API(now=lambda: 0, opener=Mock())
        api.now = lambda: 481
        with patch.object(e, 'command') as child:
            with self.assertRaises(e.Failure): api.router()
            child.assert_not_called()

    def test_alarm_restores_handler_on_cancellation_and_refuses_active_timer(self):
        with patch.object(e.signal, 'getitimer', return_value=(0.0, 0.0)), \
             patch.object(e.signal, 'getsignal', return_value=signal.SIG_DFL), \
             patch.object(e.signal, 'signal') as handler, patch.object(e.signal, 'setitimer') as timer:
            with self.assertRaises(e.Failure):
                with e.alarm(1): raise e.Failure('cancelled', 143)
            self.assertEqual(handler.call_args.args, (signal.SIGALRM, signal.SIG_DFL))
            self.assertEqual(timer.call_args.args, (signal.ITIMER_REAL, 0))
        with patch.object(e.signal, 'getitimer', return_value=(1.0, 0.0)):
            with self.assertRaises(e.Failure):
                with e.alarm(1): self.fail('active timer accepted')

    def test_terminal_poll_preserves_deadline_error(self):
        api = Mock()
        api.check.side_effect = e.Failure('total timeout', 124)
        with self.assertRaises(e.Failure) as caught: e.terminal(api, op(status='RUNNING'), '123', 'insert')
        self.assertEqual(caught.exception.code, 124)

    def test_mode_enum_and_unexpected_nat_ip_information_refuse(self):
        self.assertEqual(e.ip_set({}), set())
        for value in ({'result': [{'natName': 'foreign', 'natIpInfoMappings': []}]}, {'unknown': []}):
            with self.assertRaises(e.Failure): e.ip_set(value)


if __name__ == '__main__':
    unittest.main()
