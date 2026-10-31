"""Fixed, immutable per-lease access records; no launcher or IAM integration.

Only the configured ledger bucket, slot-1 read and four UUID-derived objects
are exposed. No list, overwrite, delete or slot mutation is available to A.
Records are retained: removing them needs a separately reviewed policy.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlencode

from . import spec
from .gcs import GcsSlotStore, StoreError, _decode

LIMIT = 16_384
KINDS = ('intent', 'import', 'seal', 'removed')
SLOT = 'slots/slot-1.json'
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
_USER = re.compile(r'users/[A-Za-z0-9][A-Za-z0-9@._-]{0,127}\Z')


class AccessError(Exception):
    """Invalid, missing or uncertain access evidence; keep the lease occupied."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def timestamp(value):
    if not isinstance(value, str):
        raise AccessError('invalid access timestamp')
    try:
        result = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        if spec.rfc3339(result) != value:
            raise ValueError()
        return result
    except ValueError:
        raise AccessError('invalid access timestamp') from None


def public_key(value):
    """Return canonical ED25519 SSH text and SHA256 of its RFC4253 wire blob.

    Comments/whitespace may appear in server profiles; none are persisted.
    No private-key parser, subprocess or key generation is performed here.
    """
    try:
        if not isinstance(value, str) or len(value) > 4096 or '\n' in value or '\r' in value:
            raise ValueError()
        parts = value.split()
        if len(parts) < 2 or parts[0] != 'ssh-ed25519':
            raise ValueError()
        raw = base64.b64decode(parts[1], validate=True)
        expected = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32)
        if len(raw) != 51 or raw[:19] != expected:
            raise ValueError()
        text = 'ssh-ed25519 ' + base64.b64encode(raw).decode()
        return text, hashlib.sha256(raw).hexdigest()
    except Exception:
        raise AccessError('invalid ED25519 public key') from None


def _exact(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise AccessError('invalid access record fields')


def _sha(value):
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise AccessError('invalid access digest')


def _positive(value):
    if type(value) is not int or not 0 < value <= 2**63 - 1:
        raise AccessError('invalid access integer')


def self_user(value):
    if not isinstance(value, str) or not _USER.fullmatch(value):
        raise AccessError('invalid canonical SELF name')
    return value


BINDING_FIELDS = ('lease', 'epoch', 'run_id', 'attempt', 'vm_id', 'boot_id',
                  'source_image_id', 'deadline', 'work_deadline', 'self_user', 'key_sha256')


def validate_binding(value):
    _exact(value, BINDING_FIELDS)
    if (not isinstance(value['lease'], str) or not _UUID.fullmatch(value['lease']) or
            value['lease'] == '00000000-0000-0000-0000-000000000000'):
        raise AccessError('invalid access lease UUID')
    for k in ('epoch', 'run_id', 'attempt'):
        _positive(value[k])
    for k in ('vm_id', 'boot_id', 'source_image_id'):
        if not isinstance(value[k], str) or not re.fullmatch(r'[1-9][0-9]{0,19}', value[k]) or int(value[k]) > 2**64-1:
            raise AccessError('invalid access resource ID')
    if (value['source_image_id'] != spec.COMPONENT_IMAGE_ID or
            timestamp(value['work_deadline']) >= timestamp(value['deadline'])):
        raise AccessError('invalid access deadline/image')
    self_user(value['self_user'])
    _sha(value['key_sha256'])


@dataclass(frozen=True)
class Context:
    """Capture the validated current occupied slot, never an arbitrary path."""
    _encoded: bytes

    @classmethod
    def from_slot(cls, slot):
        try:
            if (type(slot['schema']) is not int or slot['schema'] != 1 or slot['slot'] != SLOT or
                    slot['state'] not in ('ACTIVE', 'CLEANUP_FAILED') or
                    slot['profile'] not in (spec.UBUNTU_BASE_BUILD, spec.UBUNTU_VLAB_CORE) or
                    slot['boot_image_id'] != spec.COMPONENT_IMAGE_ID):
                raise AccessError('access requires occupied confirmed base build')
            a = slot['access']
            _exact(a, ('binding', 'phase', 'archive'))
            b = a['binding']
            validate_binding(b)
            if slot['profile'] == spec.UBUNTU_VLAB_CORE and (
                    (b['run_id'], b['attempt']) != (slot['run_id'], slot['attempt']) or
                    timestamp(b['deadline']) - timestamp(b['work_deadline']) != timedelta(minutes=15)):
                raise AccessError('trial access correlation/reserve differs')
            if (b['lease'] != slot['request_id'] or b['epoch'] != slot['epoch'] or
                    b['vm_id'] != slot['ids']['instance'] or b['boot_id'] != slot['ids']['boot'] or
                    b['deadline'] != slot['deadline'] or a['phase'] not in
                    ('registered', 'finalizing', 'archived') or not isinstance(a['archive'], dict)):
                raise AccessError('access binding differs from current slot')
            return cls(canonical(b))
        except (KeyError, TypeError, ValueError):
            raise AccessError('missing/invalid access lease') from None

    @property
    def binding(self):
        value = json.loads(self._encoded)
        validate_binding(value)
        return value

    def path(self, kind):
        if kind not in KINDS:
            raise AccessError('unknown fixed access record')
        return 'access/slot-1/' + self.binding['lease'] + '/' + kind + '.json'

    def current(self, slot):
        if Context.from_slot(slot) != self:
            raise AccessError('stale access producer')
        return slot


def validate_record(record, context, kind):
    base = {'schema', 'kind', 'binding'}
    ref = {'intent_generation', 'intent_sha256'}
    extra = {
        'intent': {'public_key', 'producer_nonce', 'expiration_usec', 'created_at',
                   'posix', 'baseline_sha256'},
        'import': ref | {'server_name', 'fingerprint', 'expiration_usec', 'response_sha256'},
        'seal': ref | {'provenance_sha256', 'manifest_sha256', 'postcondition_sha256',
                       'nonce', 'result'},
        'removed': ref | {'outcome', 'checked_at', 'server_name', 'fingerprint'},
    }
    if kind not in KINDS:
        raise AccessError('unknown fixed access record')
    _exact(record, base | extra[kind])
    if type(record['schema']) is not int or record['schema'] != 1 or record['kind'] != kind:
        raise AccessError('invalid access schema/kind')
    validate_binding(record['binding'])
    if record['binding'] != context.binding:
        raise AccessError('access record belongs to another lease')
    if kind != 'intent':
        _positive(record['intent_generation'])
        _sha(record['intent_sha256'])
    if kind == 'intent':
        key, sha = public_key(record['public_key'])
        if key != record['public_key'] or sha != context.binding['key_sha256']:
            raise AccessError('intent public key mismatch')
        _sha(record['producer_nonce'])
        _sha(record['baseline_sha256'])
        created = timestamp(record['created_at'])
        expiry = record['expiration_usec']
        if (not isinstance(expiry, str) or not re.fullmatch(r'[1-9][0-9]{0,18}', expiry) or
                not int(created.timestamp()*1_000_000) < int(expiry) <=
                min(int(created.timestamp()*1_000_000)+1_200_000_000,
                    int(timestamp(context.binding['work_deadline']).timestamp()*1_000_000))):
            raise AccessError('invalid finite key expiration')
        p = record['posix']
        _exact(p, ('username', 'uid', 'gid', 'home'))
        if (not isinstance(p['username'], str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,63}', p['username']) or
                p['username'] == 'root' or p['home'] != '/home/' + p['username']):
            raise AccessError('invalid POSIX identity')
        for k in ('uid', 'gid'):
            if not isinstance(p[k], str) or not re.fullmatch(r'[1-9][0-9]{0,9}', p[k]) or int(p[k]) > 2**32-2:
                raise AccessError('invalid nonroot POSIX ID')
    if kind in ('import', 'removed'):
        fp = record['fingerprint']
        if not isinstance(fp, str) or not re.fullmatch(r'[A-Za-z0-9_+=.-]{1,256}', fp):
            raise AccessError('invalid server fingerprint')
        if record['server_name'] != context.binding['self_user'] + '/sshPublicKeys/' + fp:
            raise AccessError('server key name mismatch')
    if kind == 'import':
        _sha(record['response_sha256'])
        if not isinstance(record['expiration_usec'], str) or not re.fullmatch(r'[1-9][0-9]{0,18}', record['expiration_usec']):
            raise AccessError('invalid key expiration')
    if kind == 'removed':
        if record['outcome'] not in ('removed', 'absent', 'expired-absent', 'absence-verified-after-uncertain-delete'):
            raise AccessError('invalid key-removal outcome')
        timestamp(record['checked_at'])
    if kind == 'seal':
        for k in ('provenance_sha256', 'manifest_sha256', 'postcondition_sha256', 'nonce'):
            _sha(record[k])
        if record['result'] != 'sealed':
            raise AccessError('missing seal result')
    if len(canonical(record)) > LIMIT:
        raise AccessError('access record exceeds bound')


class ReadOnlyAccessRecords:
    """Cleanup composition exposes evidence reads only, never producer writes.

    No SELF client is constructed by cleanup. Key removal belongs to the owner.
    """
    def __init__(self, records):
        self.__records = records

    def read(self, context, kind):
        return self.__records.read(context, kind)


class GcsAccessRecords:
    """Minimal A surface: exact slot read, four derived get/create operations.

    Token acquisition must be explicitly injected for the SAME A identity as
    OS Login. This class supplies no credentials, identity switching or IAM.
    """
    def __init__(self, bucket, *, token_provider, transport=None):
        self._gcs = GcsSlotStore(bucket, token_provider=token_provider, transport=transport)
        self.bucket = bucket

    def slot(self):
        try:
            return self._gcs.read(SLOT)[0]
        except StoreError:
            raise AccessError('slot read failed; keep access lease occupied') from None

    def _url(self, context, kind):
        return f'https://storage.googleapis.com/storage/v1/b/{self.bucket}/o/' + quote(context.path(kind), safe='')

    def read(self, context, kind):
        try:
            return self._read(context, kind)
        except StoreError:
            raise AccessError('access record read failed; keep lease occupied') from None

    def _read(self, context, kind):
        path = context.path(kind)
        seen = False
        for _ in range(3):
            m = self._gcs._request('GET', self._url(context, kind) + '?' + urlencode({'fields': 'bucket,name,generation,size'}))
            if m.status == 404:
                if not seen:
                    return None, 0
                continue
            if m.status != 200:
                raise AccessError('access metadata read failed')
            seen = True
            gen, size = self._gcs._metadata(m, path)
            if size > LIMIT:
                raise AccessError('access object exceeds bound')
            r = self._gcs._request('GET', self._url(context, kind) + '?' + urlencode({'alt': 'media', 'generation': str(gen)}), limit=LIMIT)
            if r.status in (404, 412):
                continue
            if r.status != 200 or len(r.body) != size:
                raise AccessError('access generation read failed')
            value = _decode(r.body, LIMIT)
            validate_record(value, context, kind)
            return value, gen
        raise AccessError('access object changed during bounded read')

    def create(self, context, kind, value):
        """Return (generation, original_request_won).

        A 412 exact match is readable evidence, never a new import capability.
        Lost upload replies are reconciled once by complete canonical equality;
        absent/mismatched/error reads remain uncertain and are never retried.
        """
        try:
            return self._create(context, kind, value)
        except StoreError:
            raise AccessError('access upload evidence failed; outcome may be uncertain') from None

    def _create(self, context, kind, value):
        validate_record(value, context, kind)
        context.current(self.slot())
        path = context.path(kind)
        payload = canonical(value)
        url = f'https://storage.googleapis.com/upload/storage/v1/b/{self.bucket}/o?' + urlencode({
            'uploadType': 'media', 'name': path, 'ifGenerationMatch': '0',
            'fields': 'bucket,name,generation,size'})
        uncertain = False
        try:
            response = self._gcs._request('POST', url, body=payload)
        except StoreError:
            uncertain = True
            response = None
        if response is not None and response.status in (200, 201):
            gen, size = self._gcs._metadata(response, path)
            if size != len(payload):
                raise AccessError('access upload acknowledgment mismatch')
            # Read back the durable generation; no capability from an ACK alone.
            found, actual = self.read(context, kind)
            if actual != gen or canonical(found) != payload:
                raise AccessError('access upload read-back mismatch')
            return gen, True
        if response is not None and response.status != 412:
            raise AccessError('access upload denied or failed; outcome not accepted')
        found, gen = self.read(context, kind)
        if found is None or canonical(found) != payload:
            raise AccessError('access upload outcome unproven')
        return gen, uncertain
