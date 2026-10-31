"""Owner-only cleanup for the single issue349 temporary router/NAT.

Python 3.12 stdlib, fixed owner host paths; no creation or network repair.
An exclusive owner namespace is required: Compute routers has no fingerprint
or immutable-ID mutation precondition. Offline tests are not live API proof.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import threading
import time
import uuid
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from .lifecycle.auth_http import _NoRedirect, bearer_headers
from .prelogin.hook import Files
from .vlab_trial import command
from build.provision import vlab_trial as guest

ROOT = 'https://compute.googleapis.com/compute/v1/projects/teched-473722'
REGION = ROOT + '/regions/us-central1'
ROUTER = REGION + '/routers/labapp-349-trial-router-20261031'
NAT = 'labapp-349-trial-nat-20261031'
SUBNET = REGION + '/subnetworks/default'
OWNER = 'art@githedgehog.com'
STATE = Path('/home/ubuntu/.local/state/labapp-trial-egress-349')
SOURCE = Path(__file__).resolve().parents[2]
DESCRIPTION = 'Disposable issue349 canonical trial; owner nonce='
LIMIT = 262144
require = guest.require
Failure = guest.Failure
encode = guest.encoded
decode = guest.data
SOURCE_FILES = ('build/gcp/trial_egress.py', 'build/gcp/vlab_trial.py',
                'build/gcp/prelogin/hook.py', 'build/gcp/lifecycle/auth_http.py',
                'build/provision/vlab_trial.py')
STATE_FILES = {'intent.json', 'create-operation.json', 'router.json', 'nat.json',
               'initial-allocations.json', 'allocations.json', 'final-allocations.json', 'nat-attempt.json',
               'nat-operation.json', 'delete-attempt.json', 'delete-operation.json'}


def stamp(value):
    require(type(value) is str and len(value) <= 40)
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.tzinfo is not None)
    return parsed.timestamp()


def identifier(value):
    require(type(value) is str and re.fullmatch('[1-9][0-9]{0,19}', value))
    return value


def name(value):
    require(type(value) is str and re.fullmatch('[a-z][a-z0-9-]{0,199}', value))
    return value


def cloud_value(value):
    """Accept the two documented Compute self-link host spellings only."""
    if type(value) is str:
        return value.replace('https://www.googleapis.com/compute/v1/',
                             'https://compute.googleapis.com/compute/v1/', 1) if value.startswith(
                                 'https://www.googleapis.com/compute/v1/') else value
    if type(value) is list:
        return [cloud_value(v) for v in value]
    if type(value) is dict:
        return {k: cloud_value(v) for k, v in value.items()}
    return value


@contextmanager
def alarm(seconds):
    """Absolute main-thread bound, restoring handler even after cancellation."""
    require(threading.current_thread() is threading.main_thread()
            and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0) and seconds > 0)
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_signum, _frame):
        raise Failure('egress API deadline exceeded', 124)
    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        primary = sys.exc_info()[1]
        restored = True
        for restore in (lambda: signal.setitimer(signal.ITIMER_REAL, 0),
                        lambda: signal.signal(signal.SIGALRM, previous)):
            try:
                restore()
            except BaseException:
                restored = False
        if not restored:
            if primary is None:
                raise Failure('egress alarm restoration unresolved') from None
            primary.cleanup_uncertain = True


class State:
    """Private pinned directory, immutable single-link files and nonblocking lock."""
    def __init__(self, path=STATE):
        self.path = Path(path)

    def __enter__(self):
        require(self.path.is_absolute() and len(self.path.parts) > 1 and '..' not in self.path.parts)
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in self.path.parts[1:]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
                info = os.fstat(fd)
                require(info.st_uid in (0, os.geteuid()) and
                        (not info.st_mode & 0o022 or
                         info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o1777))
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.fd = fd
            return self
        except BaseException:
            os.close(fd)
            raise

    def __exit__(self, *_args):
        try:
            os.close(self.fd)
        except BaseException:
            if _args[1] is None:
                raise Failure('egress state lock close unresolved') from None
            _args[1].cleanup_uncertain = True

    def check(self):
        require(set(os.listdir(self.fd)) <= STATE_FILES, 'foreign state files refused')
        for filename in os.listdir(self.fd):
            self.read(filename)

    def read(self, filename, optional=False):
        try:
            info = os.stat(filename, dir_fd=self.fd, follow_symlinks=False)
            require(stat.S_IMODE(info.st_mode) == 0o600)
            reader = Files()
            reader.uid = os.geteuid()
            return cloud_value(decode(reader.read_file(self.fd, filename, LIMIT)))
        except FileNotFoundError:
            require(optional, 'required egress evidence missing')
            return None

    def write(self, filename, value):
        raw = encode(value)
        require(len(raw) <= LIMIT)
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(self.fd)


def source_hashes():
    return {p: hashlib.sha256(guest.regular(SOURCE / p, 262144, os.geteuid())).hexdigest()
            for p in SOURCE_FILES}


def intent(value):
    require(type(value) is dict and set(value) == {'schema', 'nonce', 'request_id',
            'started_at', 'cleanup_at', 'hard_at', 'owner', 'router_404', 'sources'})
    require(type(value['schema']) is int and value['schema'] == 1 and value['owner'] == OWNER
            and value['router_404'] is True and re.fullmatch('[a-f0-9]{64}', value['nonce']))
    require(str(uuid.UUID(value['request_id'])) == value['request_id']
            and uuid.UUID(value['request_id']).int != 0)
    require(all(type(value[k]) is int for k in ('started_at', 'cleanup_at', 'hard_at')))
    require(value['cleanup_at'] == value['started_at'] + 140 * 60
            and value['hard_at'] == value['started_at'] + 150 * 60
            and value['sources'] == source_hashes())
    return value


def router_base(router, pending):
    require(type(router) is dict and set(router) <= {'kind', 'id', 'creationTimestamp',
            'name', 'description', 'region', 'network', 'selfLink', 'interfaces', 'bgpPeers', 'bgp', 'nats',
            'encryptedInterconnectRouter'})
    require('encryptedInterconnectRouter' not in router or router['encryptedInterconnectRouter'] is False)
    identifier(router['id'])
    require(router.get('kind') == 'compute#router' and router.get('selfLink') == ROUTER
            and router.get('name') == ROUTER.rsplit('/', 1)[1]
            and router.get('description') == DESCRIPTION + pending['nonce']
            and router.get('region') == REGION and router.get('network') == ROOT + '/global/networks/default'
            and not router.get('interfaces') and not router.get('bgpPeers'))
    bgp = router.get('bgp', {})
    require(type(bgp) is dict and set(bgp) <= {'asn', 'advertiseMode', 'keepaliveInterval'}
            and all(type(v) is type({'asn': 64514, 'advertiseMode': 'DEFAULT', 'keepaliveInterval': 20}[k])
                    and v == {'asn': 64514, 'advertiseMode': 'DEFAULT', 'keepaliveInterval': 20}[k]
                    for k, v in bgp.items()))
    created = stamp(router['creationTimestamp'])
    require(pending['started_at'] <= created <= pending['hard_at']
            and pending['hard_at'] <= created + 150 * 60)
    return {k: v for k, v in router.items() if k != 'nats'}


def valid_nat(nats):
    require(type(nats) is list and len(nats) <= 1)
    if not nats:
        return
    fixed = {'name': NAT, 'type': 'PUBLIC', 'autoNetworkTier': 'PREMIUM',
             'natIpAllocateOption': 'AUTO_ONLY', 'sourceSubnetworkIpRangesToNat': 'LIST_OF_SUBNETWORKS',
             'subnetworks': [{'name': SUBNET, 'sourceIpRangesToNat': ['PRIMARY_IP_RANGE']}]}
    defaults = {'enableDynamicPortAllocation': False, 'enableEndpointIndependentMapping': False,
                'minPortsPerVm': 64, 'udpIdleTimeoutSec': 30, 'icmpIdleTimeoutSec': 30,
                'tcpEstablishedIdleTimeoutSec': 1200, 'tcpTransitoryIdleTimeoutSec': 30,
                'tcpTimeWaitTimeoutSec': 120, 'effectiveTcpTimeWaitTimeoutSec': 120,
                'logConfig': {'enable': False, 'filter': 'ALL'}, 'endpointTypes': ['ENDPOINT_TYPE_VM'],
                'natIps': [], 'drainNatIps': [], 'rules': []}
    value = nats[0]
    require(type(value) is dict and set(fixed) <= set(value) <= set(fixed) | set(defaults)
            and all(value[k] == v and type(value[k]) is type(v) for k, v in fixed.items())
            and all(value[k] == defaults[k] and type(value[k]) is type(defaults[k])
                    for k in set(value) - set(fixed)))


class API:
    """Closed REST surface. No public URL, project, method or body selector."""
    def __init__(self, *, now=time.monotonic, opener=None):
        self.now = now
        self.end = now() + 480
        self.opener = opener or build_opener(ProxyHandler({}), _NoRedirect())

    def check(self):
        require(self.now() < self.end, 'total egress cleanup deadline exceeded')

    def _request(self, method, url, body=None):
        self.check()
        token = command(['/usr/bin/gcloud', 'auth', 'print-access-token', '--quiet',
                         '--account=' + OWNER], min(20, self.end - self.now()), limit=8192,
                        env={'HOME': '/home/ubuntu', 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                             'CLOUDSDK_CORE_DISABLE_PROMPTS': '1'}).decode('ascii').strip()
        headers = bearer_headers(lambda: token)
        headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
        response = None
        try:
            with alarm(min(20, self.end - self.now())):
                try:
                    response = self.opener.open(Request(url, data=body, headers=headers, method=method), timeout=20)
                except HTTPError as error:
                    response = error
                raw = response.read(LIMIT + 1)
                require(len(raw) <= LIMIT)
                self.check()
                if response.code == 404:
                    return None  # Only an actually received HTTP404 means absence.
                require(response.code == 200, 'egress API rejected or ambiguous')
                value = decode(raw)
                require(type(value) is dict)
                return cloud_value(value)
        finally:
            if response is not None:
                primary = sys.exc_info()[1]
                try:
                    response.close()
                except BaseException:
                    if primary is None:
                        raise Failure('egress HTTP close unresolved') from None
                    primary.cleanup_uncertain = True

    def router(self):
        return self._request('GET', ROUTER)

    def ips(self):
        return self._request('GET', ROUTER + '/getNatIpInfo')

    def operation(self, operation_name):
        return self._request('GET', REGION + '/operations/' + name(operation_name))

    def addresses(self):
        value = self._request('GET', REGION + '/addresses?maxResults=500')
        require(value is not None and not value.get('nextPageToken') and not value.get('warning'))
        items = value.get('items', [])
        require(type(items) is list and len(items) <= 500 and all(type(v) is dict for v in items))
        return items

    def address(self, captured):
        return self._request('GET', REGION + '/addresses/' + name(captured['name']))

    def remove_nat(self, request_id):
        return self._request('PATCH', ROUTER + '?requestId=' + str(uuid.UUID(request_id)), b'{"nats":[]}')

    def remove_router(self, request_id):
        return self._request('DELETE', ROUTER + '?requestId=' + str(uuid.UUID(request_id)))


def attempt(state, filename):
    value = state.read(filename, optional=True)
    if value is None:
        return None
    require(type(value) is dict and set(value) == {'request_id'})
    request_id = value['request_id']
    require(type(request_id) is str and str(uuid.UUID(request_id)) == request_id
            and uuid.UUID(request_id).int != 0)
    return request_id


def operation(value, router_id, kind, request_id=None):
    require(type(value) is dict and value.get('targetLink') == ROUTER
            and value.get('targetId') == router_id
            and value.get('region') == REGION and value.get('user') == OWNER
            and value.get('status') in ('PENDING', 'RUNNING', 'DONE') and not value.get('error')
            and not value.get('httpErrorStatusCode'))
    label = value.get('operationType')
    require(type(label) is str and re.fullmatch('[a-zA-Z][a-zA-Z0-9_.-]{0,127}', label))
    if kind == 'insert':
        require(label == 'insert' and request_id is None)
    else:
        require(kind in ('patch', 'delete') and request_id is not None
                and value.get('clientOperationId') == request_id)
        if kind == 'delete':
            require(label == 'delete')
    name(value['name'])
    return value['status'] == 'DONE'


def terminal(api, value, router_id, kind, request_id=None):
    captured_name = value['name']
    while not operation(value, router_id, kind, request_id):
        api.check()
        time.sleep(1)
        value = api.operation(captured_name)
        require(value is not None and value.get('name') == captured_name)
    return value


def ip_set(value):
    require(type(value) is dict and set(value) <= {'result'})
    rows = value.get('result', [])
    require(type(rows) is list and len(rows) <= 1)
    found = set()
    for row in rows:
        require(type(row) is dict and {'natName'} <= set(row) <= {'natName', 'natIpInfoMappings'}
                and row['natName'] == NAT)
        mappings = row.get('natIpInfoMappings', [])
        require(type(mappings) is list and len(mappings) <= 64)
        for item in mappings:
            require(set(item) == {'natIp', 'usage', 'mode'} and item['mode'] == 'AUTO'
                    and item['usage'] in ('IN_USE', 'UNUSED'))
            ip = str(ipaddress.IPv4Address(item['natIp']))
            require(ip not in found)
            found.add(ip)
    return found


def allocation(value, ips):
    require(type(value) is dict and value.get('purpose') == 'NAT_AUTO'
            and value.get('address') in ips and value.get('region') == REGION
            and value.get('selfLink') == REGION + '/addresses/' + name(value['name'])
            and value.get('addressType') == 'EXTERNAL' and value.get('networkTier') == 'PREMIUM')
    identifier(value['id'])
    return {k: value[k] for k in ('name', 'id', 'address', 'selfLink', 'purpose')}


def allocations(api, ips):
    records = [allocation(v, ips) for v in api.addresses() if v.get('address') in ips]
    require(len(records) == len(ips) and {v['address'] for v in records} == ips,
            'exact NAT_AUTO allocation identity unavailable')
    for record in records:
        require(allocation(api.address(record), ips) == record, 'allocation list/get mismatch')
    return records


def stored_allocation(record):
    require(type(record) is dict and set(record) == {'name', 'id', 'address', 'selfLink', 'purpose'}
            and record['purpose'] == 'NAT_AUTO'
            and record['selfLink'] == REGION + '/addresses/' + name(record['name']))
    identifier(record['id'])
    require(str(ipaddress.IPv4Address(record['address'])) == record['address'])


def arm(state, api, now=time.time):
    require(not os.listdir(state.fd), 'egress intent requires empty directory')
    require(api.router() is None, 'refuse preexisting router')
    started = int(now())
    value = {'schema': 1, 'nonce': os.urandom(32).hex(), 'request_id': str(uuid.uuid4()),
             'started_at': started, 'cleanup_at': started + 8400, 'hard_at': started + 9000,
             'owner': OWNER, 'router_404': True, 'sources': source_hashes()}
    state.write('intent.json', intent(value))


def capture(state, api):
    state.check()
    pending = intent(state.read('intent.json'))
    router = api.router()
    base = router_base(router, pending)
    require(not router.get('nats'), 'capture owned router BEFORE creating NAT')
    receipt = state.read('create-operation.json')
    require(operation(receipt, base['id'], 'insert'), 'terminal own create receipt required')
    actual = api.operation(receipt['name'])
    require(actual == receipt, 'creation receipt changed')
    state.write('router.json', base)


def capture_nat(state, api):
    state.check()
    pending = intent(state.read('intent.json'))
    captured = state.read('router.json')
    router = api.router()
    require(router_base(router, pending) == captured)
    valid_nat(router.get('nats', []))
    require(bool(router.get('nats')), 'NAT setup not complete')
    records = allocations(api, ip_set(api.ips()))
    require(api.router() == router, 'router changed during NAT capture')
    state.write('initial-allocations.json', records)
    state.write('nat.json', router['nats'])


def cleanup(state, api):
    state.check()
    pending = intent(state.read('intent.json'))
    captured = state.read('router.json', optional=True)
    router = api.router()
    if captured is None:
        raise Failure('lost create identity; manual owner recovery required')
    require(router_base(captured, pending) == captured)
    creation = state.read('create-operation.json')
    require(operation(creation, captured['id'], 'insert'))
    records = state.read('allocations.json', optional=True)
    nat_config = state.read('nat.json', optional=True)
    nat_op = state.read('nat-operation.json', optional=True)
    delete_op = state.read('delete-operation.json', optional=True)
    nat_request = attempt(state, 'nat-attempt.json')
    delete_request = attempt(state, 'delete-attempt.json')
    require(all(v != pending['request_id'] for v in (nat_request, delete_request) if v is not None)
            and (nat_request is None or nat_request != delete_request), 'mutation UUIDs must be distinct')
    final_records = state.read('final-allocations.json', optional=True)
    if final_records is not None:
        require(type(final_records) is list and len(final_records) <= 64)
        for record in final_records:
            stored_allocation(record)
        records = final_records
    if nat_op is not None:
        require(final_records is not None, 'captured PATCH allocation evidence unavailable')
        nat_op = terminal(api, nat_op, captured['id'], 'patch', nat_request)
        router = api.router()  # A pending captured PATCH may remove NAT during polling.
    if router is not None:
        require(router_base(router, pending) == captured, 'router identity/config changed')
        valid_nat(router.get('nats', []))
        if nat_config is not None and router.get('nats'):
            require(router['nats'] == nat_config, 'captured NAT configuration changed')
        if not router.get('nats'):
            require((nat_config is None and state.read('nat-attempt.json', optional=True) is None)
                    or nat_op is not None, 'NAT vanished without terminal owned operation')
        ips = ip_set(api.ips()) if router.get('nats') else set()
        if records is None:
            records = allocations(api, ips)
            initial = state.read('initial-allocations.json', optional=True) or []
            require(type(initial) is list and len(initial) <= 64)
            for previous in initial:
                stored_allocation(previous)
                if previous not in records:
                    records.append(previous)
            require(len(records) <= 64)
            state.write('allocations.json', records)
        require(type(records) is list and len(records) <= 64)
        for record in records:
            stored_allocation(record)
        if router.get('nats'):
            require(nat_op is None and delete_op is None, 'mutation already attempted')
            require(state.read('nat-attempt.json', optional=True) is None, 'NAT attempt outcome unresolved')
            current_records = allocations(api, ips)  # Refresh exact identities on EVERY pre-PATCH entry.
            if final_records is not None:
                require(all(record in final_records for record in current_records),
                        'final allocation capture changed; owner recovery required')
            else:
                for record in current_records:
                    if record not in records:
                        records.append(record)
                require(len(records) <= 64)
            again = api.router()
            require(again == router and ip_set(api.ips()) == ips, 'configuration/allocation changed')
            if final_records is None:
                state.write('final-allocations.json', records)
            # This is deliberately NOT an atomic ID/fingerprint precondition.
            request_id = str(uuid.uuid4())
            require(request_id not in (pending['request_id'], delete_request))
            state.write('nat-attempt.json', {'request_id': request_id})
            nat_request = request_id
            value = api.remove_nat(request_id)
            require(value is not None, 'NAT delete did not return operation')
            state.write('nat-operation.json', value)
            nat_op = terminal(api, value, captured['id'], 'patch', nat_request)
        if nat_op is not None:
            terminal(api, nat_op, captured['id'], 'patch', nat_request)
        empty = api.router()
        require(empty is not None and router_base(empty, pending) == captured, 'router identity/config changed')
        valid_nat(empty.get('nats', []))
        require(not empty.get('nats'), 'NAT absence not confirmed')
        if delete_op is None:
            require(state.read('delete-attempt.json', optional=True) is None, 'router attempt outcome unresolved')
            require(api.router() == empty, 'router changed before delete')
            request_id = str(uuid.uuid4())
            require(request_id not in (pending['request_id'], nat_request))
            state.write('delete-attempt.json', {'request_id': request_id})
            delete_request = request_id
            value = api.remove_router(request_id)
            require(value is not None, 'router delete did not return operation')
            state.write('delete-operation.json', value)
            delete_op = value
    require(records is not None and delete_op is not None, 'cleanup terminal evidence unavailable')
    require(type(records) is list and len(records) <= 64)
    if nat_op is not None:
        terminal(api, nat_op, captured['id'], 'patch', nat_request)
    terminal(api, delete_op, captured['id'], 'delete', delete_request)
    require(api.router() is None, 'router404 not observed; successor or incomplete delete')
    for record in records:
        stored_allocation(record)
        while True:
            current = api.address(record)
            if current is None:
                break
            require(current.get('id') == record['id'], 'address successor prevents cleanup success')
            allocation(current, {record['address']})
            api.check()
            time.sleep(1)
    require(api.router() is None, 'later router successor prevents cleanup success')
    return {'router_absent': True, 'allocations_absent': True, 'no_captured_router': False}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    require(len(argv) == 1 and argv[0] in ('arm', 'capture', 'capture-nat', 'cleanup', 'expire'))
    os.umask(0o077)
    def interrupted(signum, _frame):
        raise Failure('egress cleanup interrupted', 143 if signum == signal.SIGTERM else 130)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    result = 0
    try:
        with State() as state:
            if argv[0] == 'expire':
                pending = intent(state.read('intent.json'))
                if time.time() < pending['cleanup_at']:
                    return 0
            api = API()
            if argv[0] == 'arm':
                arm(state, api)
            elif argv[0] == 'capture':
                capture(state, api)
            elif argv[0] == 'capture-nat':
                capture_nat(state, api)
            else:
                print(json.dumps(cleanup(state, api), sort_keys=True))
    except BaseException as error:
        result = error.code if isinstance(error, Failure) else 1
        print('Egress cleanup unresolved; preserve private evidence and obtain owner recovery.', file=sys.stderr)
    return result


if __name__ == '__main__':
    sys.exit(main())
