"""Explicit trusted-lead FAILED/UNKNOWN disposal, separate from normal cleanup.

No CLI, producer receipt, resource mutation or automatic expiry release. The
collector and approve callback are trusted owner composition, not data-driven
credentials. Local process/file evidence is externally reviewed, not inferred
from JSON. Object paths do not provide IAM isolation.
"""
from __future__ import annotations

import copy
import re
from urllib.parse import quote, urlencode

from . import spec
from .access_records import (AccessError, Context, KINDS, SLOT, canonical, digest,
                             timestamp, validate_binding, validate_record)
from .cloud import ForbiddenOperation, NotFound
from .controller import Config, Controller, Outcome
from .gcs import GcsSlotStore, MAX_RECORD_BYTES, StoreError, _decode, _record
from .oslogin import _identity, _match, _wire
from .store import PreconditionFailed

POLICY = 'failed-disposed-unknown-import-v1'
LIMIT = MAX_RECORD_BYTES
OWNER_SELF = 'users/110405050082684214272'


def require(condition, message='failed-disposal evidence refused'):
    if not condition:
        raise AccessError(message)


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields))


def sha(value):
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value))


def source(value):
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{40}', value))


def generation(value):
    require(type(value) is int and 0 < value <= 2**64 - 1)


def bounded(value):
    # Use the same JSON depth/type policy as the ledger, before serialization.
    _record(dict(schema=1, slot=SLOT, state='FREE', epoch=0, payload=value), SLOT)
    require(len(canonical(value)) <= LIMIT, 'failed-disposal proof exceeds bound')


def path(context):
    return 'failed-disposals/slot-1/' + context.binding['lease'] + '/proof.json'


def validate_decision(value):
    exact(value, ('reference', 'trial_source_sha', 'policy_source_sha', 'local_evidence_sha256'))
    require(isinstance(value['reference'], str) and re.fullmatch(
        r'https://github.com/afewell-hh/labapp/issues/[1-9][0-9]*#issuecomment-[1-9][0-9]*',
        value['reference']) is not None,
        'explicit lead decision reference required')
    for field in ('trial_source_sha', 'policy_source_sha'):
        source(value[field])
    sha(value['local_evidence_sha256'])


def validate_local(value, slot, decision, now):
    exact(value, ('lease', 'source_sha', 'coordinator_sha256', 'registration_sha256', 'evidence_sha256',
                  'terminated_at', 'checked_at', 'result'))
    require(value['lease'] == slot['request_id'] and
            value['source_sha'] == decision['trial_source_sha'] and
            value['evidence_sha256'] == decision['local_evidence_sha256'] and
            value['result'] == 'coordinator-children-terminated-private-files-absent')
    sha(value['coordinator_sha256'])
    sha(value['registration_sha256'])
    sha(value['evidence_sha256'])
    require(timestamp(value['terminated_at']) <= timestamp(value['checked_at']) <= now)
    require(0 <= (now - timestamp(value['checked_at'])).total_seconds() <= 60,
            'lead-reviewed local cleanup evidence stale')


def validate_proof(value):
    bounded(value)
    exact(value, ('schema', 'policy', 'trial', 'import', 'disposition', 'slot',
                  'slot_generation', 'slot_sha256', 'observations', 'decision', 'evidence_sha256'))
    require(type(value['schema']) is int and value['schema'] == 1 and value['policy'] == POLICY and
            (value['trial'], value['import'], value['disposition']) == ('FAILED', 'UNKNOWN', 'FAILED_DISPOSED'))
    generation(value['slot_generation'])
    require(digest(value['slot']) == value['slot_sha256'])
    validate_decision(value['decision'])
    Context.from_slot(value['slot'])
    require(value['evidence_sha256'] == digest({k: v for k, v in value.items()
            if k not in ('decision', 'evidence_sha256')}))
    exact(value['observations'], ('checked_at', 'receipts', 'creator', 'local', 'profile', 'compute'))
    timestamp(value['observations']['checked_at'])


class GcsFailedDisposals:
    """One fixed create-only proof per captured lease; no generic record API."""
    def __init__(self, bucket, *, token_provider, transport=None):
        self.__gcs = GcsSlotStore(bucket, token_provider=token_provider, transport=transport)
        self.bucket = bucket

    def read(self, context):
        name = path(context)
        url = f'https://storage.googleapis.com/storage/v1/b/{self.bucket}/o/' + quote(name, safe='')
        seen = False
        for _ in range(3):
            meta = self.__gcs._request('GET', url + '?' + urlencode({'fields': 'bucket,name,generation,size'}))
            if meta.status == 404:
                if not seen:
                    return None, 0
                continue
            require(meta.status == 200, 'failed-disposal metadata read failed')
            seen = True
            gen, size = self.__gcs._metadata(meta, name)
            raw = self.__gcs._request('GET', url + '?' + urlencode({'alt': 'media', 'generation': str(gen)}), limit=LIMIT)
            if raw.status in (404, 412):
                continue
            require(raw.status == 200 and len(raw.body) == size)
            value = _decode(raw.body, LIMIT)
            validate_proof(value)
            require(Context.from_slot(value['slot']) == context)
            return value, gen
        raise AccessError('failed-disposal proof changed during read')

    def create(self, context, value):
        validate_proof(value)
        require(Context.from_slot(value['slot']) == context)
        payload = canonical(value)
        existing, gen = self.read(context)
        if existing is not None:
            require(canonical(existing) == payload, 'immutable failed-disposal proof differs')
            return {'path': path(context), 'generation': gen, 'sha256': digest(value)}
        url = f'https://storage.googleapis.com/upload/storage/v1/b/{self.bucket}/o?' + urlencode({
            'uploadType': 'media', 'name': path(context), 'ifGenerationMatch': '0',
            'fields': 'bucket,name,generation,size'})
        try:
            response = self.__gcs._request('POST', url, body=payload)
        except StoreError:
            response = None  # one exact read-only reconciliation; never replay
        if response is not None:
            require(response.status in (200, 201, 412), 'failed-disposal upload failed')
            if response.status != 412:
                acknowledged, size = self.__gcs._metadata(response, path(context))
                require(size == len(payload))
            else:
                acknowledged = None
        else:
            acknowledged = None
        found, gen = self.read(context)
        require(found is not None and canonical(found) == payload and
                (acknowledged is None or gen == acknowledged), 'failed-disposal upload unproven')
        return {'path': path(context), 'generation': gen, 'sha256': digest(value)}


class ReadCloud:
    """Recovery cannot call any Compute mutation, even through its controller."""
    def __init__(self, cloud):
        self.__cloud = cloud

    def call(self, resource, verb, **kwargs):
        if (resource, verb) not in {
                ('instances', 'get'), ('disks', 'get'), ('zoneOperations', 'get'),
                ('zoneOperations', 'list'), ('instances', 'aggregatedList'),
                ('disks', 'aggregatedList'), ('globalOperations', 'aggregatedList'),
                ('images', 'list')}:
            raise ForbiddenOperation('failed disposal permits fixed reads only')
        return self.__cloud.call(resource, verb, **kwargs)


class FailedAccessRecovery:
    """Library operation reachable only from explicitly composed trusted owner.

    collect(slot, decision) verifies owner/source and terminal creator, and
    obtains lead-reviewed private local evidence. approve(full_proof_digest,
    decision) must return that exact digest under separately assessed lead
    authority. Neither callback is selected or supplied by persisted JSON.
    """
    def __init__(self, store, cloud, records, proofs, login, *, collect, approve, now):
        self.__store, self.__records, self.__proofs, self.__login = store, records, proofs, login
        self.__collect, self.__approve, self.__now = collect, approve, now
        self.__controller = Controller(store, ReadCloud(cloud), Config(
            boot_image=spec.COMPONENT_IMAGE, profile=spec.UBUNTU_VLAB_CORE, now=now))

    def __slot(self, expected):
        slot, gen = expected
        generation(gen)
        _record(slot, SLOT)
        require(slot['state'] == 'CLEANUP_FAILED' and slot.get('profile') == spec.UBUNTU_VLAB_CORE and
                not slot.get('capture') and slot.get('access', {}).get('phase') == 'finalizing' and
                slot['access']['archive'] == {})
        context = Context.from_slot(slot)
        require(context.binding['self_user'] == self.__login.user == OWNER_SELF)
        self.__controller._lease_kinds(slot)
        history = slot.get('access_history', [])
        require(type(history) is list and len(history) < 16, 'retained access accounting exhausted')
        leases, keys = set(), set()
        for item in history:
            validate_binding(item['binding'])
            require(item['binding']['lease'] != context.binding['lease'] and
                    item['binding']['key_sha256'] != context.binding['key_sha256'] and
                    item['binding']['lease'] not in leases and item['binding']['key_sha256'] not in keys and
                    item.get('phase') in ('archived', 'failed-disposed') and
                    type(item.get('archive')) is dict and set(item['archive']) == set(KINDS))
            leases.add(item['binding']['lease'])
            keys.add(item['binding']['key_sha256'])
        require(all(slot['ids'].values()) and slot.get('operation'))
        return context

    def __current(self, expected):
        current, gen = self.__store.read(SLOT)
        require(gen == expected[1] and current == expected[0], 'captured slot generation changed')

    def __observe(self, expected, decision):
        slot, _ = expected
        context = self.__slot(expected)
        validate_decision(decision)
        self.__current(expected)
        owner = self.__collect(copy.deepcopy(slot), copy.deepcopy(decision))
        now = self.__now()
        exact(owner, ('creator', 'local'))
        exact(owner['creator'], ('run_id', 'attempt', 'source_sha', 'sha256', 'conclusion'))
        creator = owner['creator']
        require(creator['run_id'] == slot['run_id'] and creator['attempt'] == slot['attempt'] and
                creator['source_sha'] == decision['trial_source_sha'] and
                creator['conclusion'] in ('cancelled', 'failure', 'timed_out'))
        sha(creator['sha256'])
        validate_local(owner['local'], slot, decision, now)
        receipts, intent = {}, None
        for kind in KINDS:
            value, gen = self.__records.read(context, kind)
            if kind == 'intent':
                validate_record(value, context, kind)
                generation(gen)
                intent = value
            else:
                require(value is None and gen == 0, 'unexpected original access receipt')
            receipts[kind] = {'path': context.path(kind), 'generation': gen,
                              'sha256': digest(value) if value is not None else None,
                              'observation': 'present' if value is not None else 'observed-absent'}
        require(int(now.timestamp()*1_000_000) > int(intent['expiration_usec']), 'original key TTL has not elapsed')
        ctl = self.__controller
        operations = ctl._list_all('zoneOperations')
        require(all(op.get('status') == 'DONE' for op in operations), 'pending operation')
        original = ctl.cloud.call('zoneOperations', 'get', name=slot['operation'])
        target, error = ctl._insert_target_id(slot, [original])
        target_path = 'projects/' + slot['project'] + '/zones/' + slot['zone'] + '/instances/' + slot['names']['instance']
        require(not error and not original.get('error') and target == slot['ids']['instance'] and
                original.get('name') == slot['operation'] and
                spec.resource_link(target_path, original.get('targetLink')), 'original insert unproven')
        own = [op for op in operations if op.get('operationType') == 'insert' and
               op.get('clientOperationId') == slot['request_id']]
        require(own and ctl._insert_target_id(slot, own) == (target, None), 'insert census mismatch')
        deleted = [op for op in operations if op.get('operationType') == 'delete' and
                   spec.resource_link(target_path, op.get('targetLink')) and
                   op.get('targetId') == target and not op.get('error')]
        require(len(deleted) == 1, 'exact terminal VM delete missing or ambiguous')
        terminal = ctl.cloud.call('zoneOperations', 'get', name=deleted[0]['name'])
        require(terminal == deleted[0] and terminal.get('status') == 'DONE')
        # Require the adapter's actual NotFound, not a synthesized None.
        for kind, resource in ctl._lease_kinds(slot):
            try:
                ctl.cloud.call(resource, 'get', name=slot['names'][kind])
            except NotFound:
                continue
            raise AccessError('exact intended resource is not actual 404')
        ctl._census()  # full project pagination/foreign pending/quarantine policy
        profile = self.__login.profile()
        profile = self.__login._profile(profile)  # do not trust alternate adapters
        require(_identity(profile) == intent['posix'] and _match(profile, intent['public_key']) is None,
                'SELF identity or intended key absence differs')
        baseline = digest(sorted(_wire(k['key']) for k in profile.get('sshPublicKeys', {}).values()))
        require(baseline == intent['baseline_sha256'], 'canonical baseline changed')
        checked = self.__now()
        require(0 <= (checked - now).total_seconds() <= 60 and
                timestamp(owner['local']['terminated_at']) <= now and
                int(checked.timestamp()*1_000_000) > int(intent['expiration_usec']), 'clock/freshness uncertainty')
        return dict(checked_at=spec.rfc3339(checked), receipts=receipts, **owner,
                    profile={'sha256': digest(profile), 'baseline_sha256': baseline},
                    compute={'insert_sha256': digest(original), 'delete_sha256': digest(terminal),
                             'delete_operation': terminal['name'], 'ids': slot['ids']})

    def prepare(self, expected_slot, decision):
        observations = self.__observe(expected_slot, decision)
        slot, gen = expected_slot
        proof = {'schema': 1, 'policy': POLICY, 'trial': 'FAILED',
                      'import': 'UNKNOWN', 'disposition': 'FAILED_DISPOSED',
                      'slot': copy.deepcopy(slot), 'slot_generation': gen,
                      'slot_sha256': digest(slot), 'observations': observations}
        proof['evidence_sha256'] = digest(proof)
        proof['decision'] = copy.deepcopy(decision)
        validate_proof(proof)
        return proof

    @staticmethod
    def __same_observations(old, new):
        # New timestamps attest fresh checks; semantic evidence must match.
        a, b = copy.deepcopy(old), copy.deepcopy(new)
        for value in (a, b):
            value.pop('checked_at')
            value['local'].pop('checked_at')
        require(a == b, 'current evidence differs from reviewed proof')
        require(timestamp(new['checked_at']) >= timestamp(old['checked_at']), 'clock moved backwards')

    def recover_failed_access(self, expected_slot, proof, decision):
        validate_proof(proof)
        require(proof['slot'] == expected_slot[0] and proof['slot_generation'] == expected_slot[1] and
                proof['decision'] == decision, 'proof/decision is for another snapshot')
        require(self.__approve(digest(proof), copy.deepcopy(decision)) == digest(proof),
                'trusted lead did not approve exact proof')
        context = self.__slot(expected_slot)
        self.__same_observations(proof['observations'], self.__observe(expected_slot, decision))
        ref = self.__proofs.create(context, proof)
        exact(ref, ('path', 'generation', 'sha256'))
        generation(ref['generation'])
        require(ref['path'] == path(context) and ref['sha256'] == digest(proof))
        self.__same_observations(proof['observations'], self.__observe(expected_slot, decision))
        slot, gen = expected_slot
        history = copy.deepcopy(slot.get('access_history', []))
        history.append(dict(binding=context.binding, phase='failed-disposed',
                            archive=proof['observations']['receipts'], recovery=ref,
                            trial='FAILED', import_status='UNKNOWN', disposition='FAILED_DISPOSED'))
        free = dict(schema=1, slot=SLOT, state='FREE', epoch=slot['epoch'],
                    quarantine=copy.deepcopy(slot.get('quarantine', [])), access_history=history,
                    used_capture_ids=copy.deepcopy(slot.get('used_capture_ids', [])),
                    last_release=dict(run_id=slot['run_id'], attempt=slot['attempt'],
                        request_id=slot['request_id'], ids=slot['ids'],
                        released_at=spec.rfc3339(self.__now()), evidence=slot['evidence'],
                        outcome='FAILED_DISPOSED', trial='FAILED', import_status='UNKNOWN', recovery=ref))
        bounded(free)
        self.__current(expected_slot)
        try:
            self.__store.write(SLOT, free, if_generation_match=gen)
        except PreconditionFailed:
            raise AccessError('failed disposal CAS conflict; fresh lead assessment required') from None
        except StoreError:
            current, actual = self.__store.read(SLOT)
            require(current == free and actual != gen, 'failed disposal CAS outcome uncertain')
        return Outcome('failed-disposed', 'trial FAILED; import UNKNOWN; capacity released')


class OwnerRecovery:
    """Closed existing-owner composition; no command-line/workflow selector.

    for_owner requires trusted local_review and approve capabilities supplied by
    the lead on an exclusive trusted host. local_review re-establishes absence
    of the actual original coordinator, SSH/IAP/children and private files and
    returns sanitized digest-linked evidence. This source cannot introspect a
    dead coordinator from an arbitrary status JSON file. approve accepts the
    full immutable proof digest under explicit lead authority. Keeping these
    capabilities outside persisted inputs is essential; unsigned JSON is not
    authorization and the existing WIF bucket grants are not prefix isolation.
    """
    def __init__(self, recovery):
        self.__recovery = recovery

    @classmethod
    def for_owner(cls, *, local_review, approve, now):
        from .auth_http import gcloud_token
        from .cli import BUCKET
        from .cloud import PolicyCloud
        from .compute import ComputeRestTransport
        from .oslogin import SelfLogin
        from .access_records import GcsAccessRecords
        from build.gcp.vlab_trial import command, github
        collect = cls.collector(local_review=local_review, command=command, github=github)
        return cls(FailedAccessRecovery(GcsSlotStore(BUCKET, token_provider=gcloud_token),
            PolicyCloud(ComputeRestTransport(token_provider=gcloud_token), spec.PROJECT, spec.ZONE),
            GcsAccessRecords(BUCKET, token_provider=gcloud_token),
            GcsFailedDisposals(BUCKET, token_provider=gcloud_token),
            SelfLogin.for_owner(OWNER_SELF, token_provider=gcloud_token),
            collect=collect, approve=approve, now=now))

    @staticmethod
    def collector(*, local_review, command, github):
        # Injection points are trusted composition, as for existing transports;
        # there is no selector for commands, principals, resources or endpoints.
        import os
        from .cli import CREATOR_PATH, REPOSITORY

        def collect(slot, decision):
            validate_decision(decision)
            account = command(['gcloud', 'auth', 'list', '--filter=status:ACTIVE', '--format=value(account)'], 15).decode().strip()
            require(account == 'art@githedgehog.com', 'fixed active owner required')
            impersonation = command(['gcloud', 'config', 'get-value', 'auth/impersonate_service_account', '--quiet'], 15).decode().strip()
            require(impersonation in ('', '(unset)') and
                    not os.environ.get('CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT'), 'owner impersonation refused')
            head = command(['git', 'rev-parse', 'HEAD'], 15).decode().strip()
            require(head == decision['policy_source_sha'] and not command(
                ['git', 'status', '--porcelain', '--untracked-files=normal'], 15).strip(), 'reviewed clean source required')
            require(slot['attempt'] == 1, 'creator reruns unsupported')
            run_path = 'actions/runs/' + str(slot['run_id'])
            exact_run = github(run_path + '/attempts/' + str(slot['attempt']))
            latest = github(run_path)
            for run in (exact_run, latest):
                require(run.get('id') == slot['run_id'] and run.get('run_attempt') == slot['attempt'] and
                    run.get('path') == CREATOR_PATH and run.get('event') == 'workflow_dispatch' and
                    run.get('head_branch') == 'main' and run.get('head_sha') == decision['trial_source_sha'] and
                    run.get('repository', {}).get('full_name') == REPOSITORY and
                    run.get('status') == 'completed' and run.get('conclusion') in
                    ('cancelled', 'failure', 'timed_out'), 'original creator is not terminal failed first attempt')
            require(exact_run == latest, 'creator observations differ')
            creator = {'run_id': slot['run_id'], 'attempt': slot['attempt'],
                       'source_sha': decision['trial_source_sha'], 'sha256': digest(exact_run),
                       'conclusion': exact_run['conclusion']}
            local = local_review(copy.deepcopy(slot), copy.deepcopy(decision))
            return {'creator': creator, 'local': local}
        return collect

    def prepare(self, expected_slot, decision):
        return self.__recovery.prepare(expected_slot, decision)

    def recover_failed_access(self, expected_slot, proof, decision):
        return self.__recovery.recover_failed_access(expected_slot, proof, decision)
