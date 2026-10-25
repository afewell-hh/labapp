"""Typed own-SELF key lifecycle, explicitly injected A credentials only.

No SSH, private keys, identity impersonation, key generation or launcher.
Sources (2026-10-25, OS Login v1): users.getLoginProfile,
users.importSshPublicKey, users.sshPublicKeys.delete and Shared.Types/SshPublicKey
at https://docs.cloud.google.com/compute/docs/oslogin/rest/ .
"""
from __future__ import annotations

import base64
import os
import threading
import re
import secrets
from urllib.parse import quote, urlencode

from . import spec
from .access_records import (AccessError, Context, canonical, digest, public_key,
                             self_user, timestamp, validate_record)
from .auth_http import HttpTransport, bearer_headers
from .gcs import _decode

PROFILE_LIMIT = 65_536


def _wire(value):
    try:
        if not isinstance(value, str) or len(value) > 4096 or '\n' in value or '\r' in value:
            raise ValueError()
        parts = value.split()
        raw = base64.b64decode(parts[1], validate=True)
        size = int.from_bytes(raw[:4], 'big')
        if (len(parts) < 2 or not 1 <= size <= 64 or len(raw) <= 4 + size or
                raw[4:4+size].decode('ascii') != parts[0]):
            raise ValueError()
        return parts[0] + ' ' + base64.b64encode(raw).decode()
    except Exception:
        raise AccessError('invalid canonical profile public key') from None


class SelfLogin:
    """Only the configured canonical authenticated SELF can be addressed.

    The trusted caller must supply A's verified canonical user ID and token
    provider. Matching profile.name prevents adopting another returned profile;
    this is not token introspection or evidence of live WIF/IAM configuration.
    """
    def __init__(self, user, *, token_provider, transport=None):
        self.user = self_user(user)
        self.token_provider = token_provider
        self.http = transport if transport is not None else HttpTransport()

    def _request(self, method, suffix, payload=None, *, import_clock=None, work_deadline=None):
        url = 'https://oslogin.googleapis.com/v1/' + quote(self.user, safe='/') + suffix
        try:
            headers = bearer_headers(self.token_provider)
            headers['Accept-Encoding'] = 'identity'
            if payload is not None:
                headers['Content-Type'] = 'application/json; charset=utf-8'
            # Token acquisition can block. Import deadlines are checked after
            # credentials are ready and immediately before transport submission.
            if method == 'POST':
                current = import_clock()
                if (current >= work_deadline or
                        int(current.timestamp()*1_000_000) >= int(payload['expirationTimeUsec'])):
                    raise ValueError('expired import')
            r = self.http.request(method, url, headers=headers,
                                  body=canonical(payload) if payload is not None else None,
                                  timeout=20, max_bytes=PROFILE_LIMIT)
            if type(r.status) is not int or not isinstance(r.body, bytes) or len(r.body) > PROFILE_LIMIT:
                raise ValueError()
            if r.status != 200:
                raise ValueError()
            return _decode(r.body, PROFILE_LIMIT)
        except Exception:
            raise AccessError('SELF request failed; mutation outcome may be uncertain') from None

    def _profile(self, value):
        if (not isinstance(value, dict) or set(value) - {'name', 'posixAccounts', 'sshPublicKeys'} or
                value.get('name') != self.user):
            raise AccessError('SELF profile identity/schema mismatch')
        keys = value.get('sshPublicKeys', {})
        accounts = value.get('posixAccounts', [])
        if not isinstance(keys, dict) or len(keys) > 128 or not isinstance(accounts, list) or len(accounts) > 8:
            raise AccessError('SELF profile exceeds bounds')
        seen = set()
        for fp, key in keys.items():
            if (not isinstance(fp, str) or not re.fullmatch(r'[A-Za-z0-9_+=.-]{1,256}', fp) or
                    not isinstance(key, dict) or set(key) - {'key', 'expirationTimeUsec', 'fingerprint', 'name'} or
                    key.get('fingerprint') != fp or key.get('name') != self.user + '/sshPublicKeys/' + fp):
                raise AccessError('SELF server key identity mismatch')
            wire = _wire(key.get('key'))
            if wire in seen:
                raise AccessError('duplicate canonical SELF key')
            seen.add(wire)
            expiry = key.get('expirationTimeUsec', '0')
            if not isinstance(expiry, str) or not re.fullmatch(r'0|[1-9][0-9]{0,18}', expiry) or int(expiry) > 2**63-1:
                raise AccessError('invalid SELF key expiration')
        return value

    def profile(self):
        return self._profile(self._request('GET', '/loginProfile?' + urlencode({'projectId': spec.PROJECT})))

    def _import_once(self, key, expiry, *, now, work_deadline):
        result = self._request('POST', ':importSshPublicKey?' + urlencode({'projectId': spec.PROJECT}),
                               {'key': key, 'expirationTimeUsec': expiry},
                               import_clock=now, work_deadline=work_deadline)
        if not isinstance(result, dict) or set(result) - {'loginProfile', 'details'}:
            raise AccessError('invalid import response')
        profile = self._profile(result.get('loginProfile'))
        return profile, digest(result)

    def _delete_exact(self, entry):
        if (entry.get('name') != self.user + '/sshPublicKeys/' + entry.get('fingerprint', '') or
                not re.fullmatch(r'[A-Za-z0-9_+=.-]{1,256}', entry.get('fingerprint', ''))):
            raise AccessError('invalid exact SELF deletion target')
        result = self._request('DELETE', '/sshPublicKeys/' + quote(entry['fingerprint'], safe=''))
        if result != {}:
            raise AccessError('invalid delete response')


def _match(profile, intended):
    matches = [key for key in profile.get('sshPublicKeys', {}).values()
               if _wire(key['key']) == intended]
    if len(matches) > 1:
        raise AccessError('ambiguous intended key')
    return matches[0] if matches else None


def _identity(profile):
    accounts = [p for p in profile.get('posixAccounts', []) if isinstance(p, dict) and
                p.get('operatingSystemType') == 'LINUX' and p.get('systemId', '') in ('', spec.PROJECT)]
    if len(accounts) != 1:
        raise AccessError('project POSIX account missing or ambiguous')
    p = accounts[0]
    return {'username': p.get('username'), 'uid': p.get('uid'), 'gid': p.get('gid'),
            'home': p.get('homeDirectory')}


def _bound_ref(intent, generation):
    return {'intent_generation': generation, 'intent_sha256': digest(intent)}


def read_intent(records, context):
    value, gen = records.read(context, 'intent')
    if value is None:
        raise AccessError('durable intent missing')
    validate_record(value, context, 'intent')
    return value, gen


def check_receipt(value, context, kind, intent, intent_gen):
    validate_record(value, context, kind)
    if any(value[k] != v for k, v in _bound_ref(intent, intent_gen).items()):
        raise AccessError('receipt intent generation/digest mismatch')
    if kind == 'import' and value['expiration_usec'] != intent['expiration_usec']:
        raise AccessError('import expiration differs from intent')


class _ImportCapability:
    """Shared, process-bound consumption survives concurrent/copied callers."""
    def __init__(self, intent, generation):
        self._value = (intent, generation)
        self._pid = os.getpid()
        self._lock = threading.Lock()

    def take(self):
        with self._lock:
            if os.getpid() != self._pid or self._value is None:
                raise AccessError('one-shot import capability unavailable')
            value, self._value = self._value, None
            return value


class OwnKeyImport:
    """One intent-create winner, one in-process capability, at most one POST.

    Fresh internal random nonce makes a restarted invocation conflict with the
    retained intent even for the same run/attempt/key. Existing intent equality
    never reconstructs this capability. Consume before every possible failure.
    """
    def __init__(self, records, context, login, *, producer_run_id, producer_attempt, now):
        if (type(producer_run_id) is not int or type(producer_attempt) is not int or
                producer_run_id != context.binding["run_id"] or
                producer_attempt != context.binding["attempt"]):
            raise AccessError("producer run/attempt differs from admitted identity")
        if login.user != context.binding['self_user']:
            raise AccessError('own-key identity mismatch')
        self.records, self.context, self.login, self.now = records, context, login, now
        self._started = False
        self._start_lock = threading.Lock()
        self._permit = None

    def prepare(self, key):
        with self._start_lock:
            if self._started:
                raise AccessError('import producer already started')
            self._started = True
        self.context.current(self.records.slot())
        canonical_key, sha = public_key(key)
        if sha != self.context.binding['key_sha256']:
            raise AccessError('public key differs from registered lease')
        profile = self.login.profile()
        if _match(profile, canonical_key) is not None:
            raise AccessError('intended key preexists; cannot import or adopt')
        now = self.now().replace(microsecond=0)
        expiry = min(int(now.timestamp()*1_000_000) + 1_200_000_000,
                     int(timestamp(self.context.binding['work_deadline']).timestamp()*1_000_000))
        value = {'schema': 1, 'kind': 'intent', 'binding': self.context.binding,
                 'public_key': canonical_key, 'producer_nonce': secrets.token_hex(32),
                 'expiration_usec': str(expiry), 'created_at': spec.rfc3339(now),
                 'posix': _identity(profile),
                 'baseline_sha256': digest(sorted(_wire(k['key']) for k in profile.get('sshPublicKeys', {}).values()))}
        validate_record(value, self.context, 'intent')
        gen, won = self.records.create(self.context, 'intent', value)
        if not won:
            raise AccessError('existing intent cannot authorize a second import')
        self._permit = _ImportCapability(value, gen)
        return value, gen

    def import_once(self):
        if self._permit is None:
            raise AccessError('one-shot import capability unavailable')
        intent, gen = self._permit.take()
        self.context.current(self.records.slot())
        actual, current_gen = read_intent(self.records, self.context)
        if actual != intent or current_gen != gen:
            raise AccessError('durable intent changed')
        now = self.now()
        if (now >= timestamp(self.context.binding['work_deadline']) or
                int(now.timestamp()*1_000_000) >= int(intent['expiration_usec'])):
            raise AccessError('access intent expiration/work deadline reached')
        # No retries, including after HTTP errors, malformed response or receipt
        # persistence failure. Re-observing a key cannot synthesize this receipt.
        profile, response_sha = self.login._import_once(
            intent['public_key'], intent['expiration_usec'], now=self.now,
            work_deadline=timestamp(self.context.binding['work_deadline']))
        entry = _match(profile, intent['public_key'])
        if entry is None or entry.get('expirationTimeUsec') != intent['expiration_usec']:
            raise AccessError('import response does not prove exact intended key/TTL')
        receipt = {'schema': 1, 'kind': 'import', 'binding': self.context.binding,
                   **_bound_ref(intent, gen), 'server_name': entry['name'],
                   'fingerprint': entry['fingerprint'], 'expiration_usec': intent['expiration_usec'],
                   'response_sha256': response_sha}
        self.records.create(self.context, 'import', receipt)
        return receipt


def cleanup_own_key(records, context, login, *, now):
    """Independent A cleanup; never imports, refreshes or replaces a key.

    An unambiguous import receipt is required for a final removal receipt.
    Exact deletion after ambiguous import may reduce exposure but never settles
    that import: this library refuses final cleanup in that case.
    """
    if login.user != context.binding['self_user']:
        raise AccessError('own-key cleanup identity mismatch')
    context.current(records.slot())
    intent, gen = read_intent(records, context)
    imported, _ = records.read(context, 'import')
    if imported is None:
        raise AccessError('sole import outcome unresolved; keep lease occupied')
    check_receipt(imported, context, 'import', intent, gen)
    profile = login.profile()
    found = _match(profile, intent['public_key'])
    previous, _ = records.read(context, 'removed')
    if previous is not None:
        check_receipt(previous, context, 'removed', intent, gen)
        if (found is not None or previous['server_name'] != imported['server_name'] or
                previous['fingerprint'] != imported['fingerprint']):
            raise AccessError('previous removal receipt no longer matches exact absence')
        return previous
    outcome = 'expired-absent' if int(now().timestamp()*1_000_000) >= int(intent['expiration_usec']) else 'absent'
    if found is not None:
        if (found['name'] != imported['server_name'] or found['fingerprint'] != imported['fingerprint'] or
                found.get('expirationTimeUsec') != intent['expiration_usec']):
            raise AccessError('intended key server identity/TTL changed')
        outcome = 'removed'
        try:
            login._delete_exact(found)
        except AccessError:
            # A delayed DELETE can only remove the exact old never-reused key,
            # not recreate it. Authenticated complete profile absence resolves
            # safe cleanup, not the HTTP response itself. Import stays one-shot.
            outcome = 'absence-verified-after-uncertain-delete'
        if _match(login.profile(), intent['public_key']) is not None:
            raise AccessError('exact key absence not proven')
    receipt = {'schema': 1, 'kind': 'removed', 'binding': context.binding,
               **_bound_ref(intent, gen), 'outcome': outcome, 'checked_at': spec.rfc3339(now()),
               'server_name': imported['server_name'], 'fingerprint': imported['fingerprint']}
    records.create(context, 'removed', receipt)
    return receipt
