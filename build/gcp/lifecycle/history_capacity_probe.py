raise SystemExit('SOURCE ONLY - unconditional refusal; ROOT must review, copy and bind exact bytes before execution (#450).')
"""Inert CURRENT baseline only; synthetic observations are not cloud/approval evidence.

Future execution requires separate ROOT functional/security review, a clean read-only
18be786c22dc410088c9da1f20c210e2f5c78b6c checkout, this artifact copied outside it,
pinned CPython 3.12.16 stdlib, -I -B, credential-free env -i and fresh empty HOME.
ROOT must provide OS-level network denial and an outer 120s kill/reap boundary.
Imports/path resolution, environment reads, randomness, PID and locks remain real;
tripwires are not an OS sandbox. No owned temporary files/children are intended.
No worst-case, history17 capacity, schema2, migration or VM17 approval is measured.
"""
import copy
import importlib
import json
import os
import socket
import subprocess
import sys
import uuid
from contextlib import ExitStack
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = '18be786c22dc410088c9da1f20c210e2f5c78b6c'
M, ST = SimpleNamespace(), dict(world='setup', cycle=0, stage='environment')
REP = dict(source=SOURCE, python=sys.version.split()[0], observations=[], checks=[],
           negative_controls=[], worlds={}, stopped=[], status='UNRUN',
           limits=dict(media_bytes=65536, depth=32, tombstones512='NOT_STRESSED',
                       quarantine32='NOT_STRESSED', evidence='NOT_STRESSED',
                       boundary='EXCLUDED', future_projections='EXCLUDED'))


class Stop(Exception):
    pass


def need(condition):
    if not condition:
        raise Stop()


def depth(value, level=0):
    children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    return max([level] + [depth(child, level + 1) for child in children])


def observe(point, value):
    wrapper = isinstance(value, dict) and 'payload' in value
    receipt = isinstance(value, dict) and value.get('kind') in M.AC.KINDS
    item = dict(ST, point=point, bytes=len(M.AC.canonical(value)), depth=depth(value),
                media_limit=None if wrapper else 16384 if receipt else 65536,
                depth_limit=32, outcome='OBSERVED_NOT_VALIDATED')
    if wrapper:
        item['note'] = 'Actual _record validation wrapper; no serialized-wrapper media check'
    if isinstance(value, dict):
        item.update(history=len(value.get('access_history', [])),
                    tombstones=len(value.get('used_capture_ids', [])),
                    quarantine=len(value.get('quarantine', [])))
    REP['observations'].append(item)
    return item


def required(stage, fn, status=None, negative=False):
    ST['stage'] = stage
    outcomes = REP['negative_controls' if negative else 'checks']
    try:
        need(not REP['stopped'])
        result = fn()
        need(status is None or result.status == status)
        need(not REP['stopped'])
    except BaseException:
        outcomes.append(dict(ST, outcome='FAIL', code='REQUIRED_FAILED'))
        raise
    outcomes.append(dict(ST, outcome='EXPECTED_REFUSAL' if negative else 'PASS'))
    return result


def hook(point, original, select):
    def wrapped(*args, **kwargs):
        item = observe(point, select(*args, **kwargs))
        try:
            result = original(*args, **kwargs)
        except BaseException:
            item.update(outcome='FAIL', code='DELEGATE_REFUSED')
            REP['stopped'].append(dict(ST, point=point, code='DELEGATE_REFUSED'))
            raise
        item['outcome'] = 'PASS' if not REP['stopped'] else 'INCOMPLETE'
        return result
    return wrapped


def ledger(value):
    store = M.gcs.GcsSlotStore(M.TG.BUCKET, token_provider=lambda: 'fake',
                              transport=M.TG.ObjectServer())
    generation = store.write(M.AC.SLOT, value, if_generation_match=0)
    found, actual = store.read(M.AC.SLOT)
    need(found == value and generation == actual)
    control = dict(ST, control='stale_create_CAS', outcome='FAIL')
    REP['negative_controls'].append(control)
    try:
        store.write(M.AC.SLOT, value, if_generation_match=0)
    except M.store.PreconditionFailed:
        control['outcome'] = 'EXPECTED_REFUSAL'
        return
    raise Stop()


def validate_slot(name, value, ctl):
    observe(name, value)
    required(name + ':record', lambda: M.gcs._record(value, M.AC.SLOT))
    required(name + ':inventory', lambda: ctl._quarantines(value))
    if value['state'] != 'FREE':
        required(name + ':context', lambda: M.AC.Context.from_slot(value))
        required(name + ':lease', lambda: ctl._lease_kinds(value))
    required(name + ':ledger', lambda: ledger(value))


def failed(w, records, proofs, login, ctx, original, before):
    link = ('https://compute.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s'
            % (M.spec.PROJECT, M.spec.ZONE, original['names']['instance']))
    for name, op in w.raw.ops.items():
        if name not in before:  # Existing offline Fixture's provider fields, current cycle only.
            op['targetLink'] = link
            if op['operationType'] == 'delete':
                op['targetId'] = original['ids']['instance']
    w.clock.advance(21)
    expected = w.store.read(w.cfg.key)
    trial, policy = M.TR.TRIAL, M.TR.POLICY_SOURCE
    decision = dict(reference='https://github.com/afewell-hh/labapp/issues/361#issuecomment-123',
                    trial_source_sha=trial, policy_source_sha=policy, local_evidence_sha256='c' * 64)
    local = dict(lease=ctx.binding['lease'], source_sha=trial, coordinator_sha256='d' * 64,
                 registration_sha256='e' * 64, evidence_sha256='c' * 64,
                 terminated_at=M.spec.rfc3339(w.clock.now() - timedelta(minutes=1)),
                 checked_at=M.spec.rfc3339(w.clock.now()),
                 result='coordinator-children-terminated-private-files-absent')
    run = dict(id=original['run_id'], run_attempt=1, path='.github/workflows/labapp-lifecycle-inspect.yml',
               event='workflow_dispatch', head_branch='main', head_sha=trial,
               repository={'full_name': 'afewell-hh/labapp'}, status='completed', conclusion='cancelled')
    endpoint = 'actions/runs/%d' % run['id']
    base = 'https://api.github.com/repos/afewell-hh/labapp/' + endpoint
    exact = dict(run, jobs_url=base + '/attempts/1/jobs', logs_url=base + '/attempts/1/logs')
    latest = dict(run, jobs_url=base + '/jobs', logs_url=base + '/logs')
    choices = {('gcloud', 'auth', 'list', '--filter=status:ACTIVE', '--format=value(account)'): 'art@githedgehog.com',
               ('gcloud', 'config', 'get-value', 'auth/impersonate_service_account', '--quiet'): '(unset)',
               ('git', 'rev-parse', 'HEAD'): policy,
               ('git', 'status', '--porcelain', '--untracked-files=normal'): '',
               ('git', 'rev-parse', '--show-toplevel'): str(Path(M.AR.__file__).resolve().parents[3])}
    def github(path):
        need(path in (endpoint, endpoint + '/attempts/1'))
        return copy.deepcopy(latest if path == endpoint else exact)
    collector = M.AR.OwnerRecovery.collector(local_review=lambda s, d: copy.deepcopy(local),
        command=lambda argv, seconds: choices[tuple(argv)].encode(), github=github)
    engine = M.AR.OwnerRecovery(M.AR.FailedAccessRecovery(w.store, w.cloud, records, proofs, login,
        collect=collector, approve=lambda sha, d: sha, now=w.clock.now))
    proof = required('recovery_prepare', lambda: engine.prepare(expected, decision))
    required('recover', lambda: engine.recover_failed_access(expected, proof, decision), 'failed-disposed')
    stored, generation = required('proof_readback', lambda: proofs.read(ctx))
    ref = w.record()['access_history'][-1]['recovery']
    required('proof_reference', lambda: need(stored == proof and ref == dict(
        path=M.AR.path(ctx), generation=generation, sha256=M.AC.digest(proof))))
    return expected[0], proof


def build(kind, stack):
    ST.update(world=kind, cycle=0, stage='construct')
    w = M.TB.world() if kind == 'normal' else M.TR.world()
    transport = M.TA.GCS(w)
    records = M.AC.GcsAccessRecords(M.TA.BUCKET, token_provider=lambda: 'fake', transport=transport)
    w.ctl = M.CT.Controller(w.store, w.cloud, w.cfg, access_records=records)
    snap, write, slot = {}, w.store.write, records.slot
    def spy(key, value, *, if_generation_match):
        result = hook('slot_write', write, lambda k, v, **kw: v)(
            key, value, if_generation_match=if_generation_match)
        if value['state'] != 'FREE':
            snap['occupied'] = copy.deepcopy(value)
        return result
    def read_slot():
        observe('before_access_slot_read', w.store.read(w.cfg.key)[0])
        return slot()
    stack.enter_context(patch.object(w.store, 'write', spy))
    stack.enter_context(patch.object(records, 'slot', read_slot))
    login = (M.OS.SelfLogin(M.TA.SELF, token_provider=lambda: 'fake', transport=M.TA.OS())
             if kind == 'normal' else M.OS.SelfLogin.for_owner(
                 M.AR.OWNER_SELF, token_provider=lambda: 'fake', transport=M.TR.Profile()))
    proofs = M.AR.GcsFailedDisposals(M.TA.BUCKET, token_provider=lambda: 'fake', transport=transport)
    summary = REP['worlds'][kind] = dict(completed=0, status='INCOMPLETE')
    for i in range(16):
        ST['cycle'] = i + 1
        run, uid, text = 100 + i, str(uuid.uuid5(uuid.NAMESPACE_URL, 'labapp450/%s/%d' % (kind, i))), M.TA.key(i + 1)
        before = set(w.raw.ops)
        required('admit', lambda: w.ctl.admit(run, 1, uid))
        required('submit', lambda: w.ctl.submit(uid), 'accepted')
        required('confirm', lambda: w.ctl.confirm_created(uid), 'created')
        rec = w.record()
        ctx = required('register', lambda: w.ctl.register_access(uid, producer_run_id=run, producer_attempt=1,
            self_user=login.user, public_key_text=text,
            expected_trial={k: rec[k] for k in M.TR.FIELDS} if kind == 'failed' else None))
        producer = M.OS.OwnKeyImport(records, ctx, login, producer_run_id=run, producer_attempt=1, now=w.clock.now)
        required('intent_prepare', lambda: producer.prepare(text))
        if kind == 'normal':
            required('import', producer.import_once)
            required('key_cleanup', lambda: M.OS.cleanup_own_key(records, ctx, login, now=w.clock.now))
            required('archive_release', lambda: w.ctl.reconcile(uid), 'released')
            occupied = snap['occupied']
        else:
            original = w.record()
            required('normal_cleanup_hold', lambda: w.ctl.reconcile(uid), 'blocked', negative=True)
            occupied, proof = failed(w, records, proofs, login, ctx, original, before)
        summary['completed'] += 1
        w.clock.advance(1)
    hist = w.record()['access_history']
    counts = dict(entries=len(hist), leases=len({e['binding']['lease'] for e in hist}),
                  keys=len({e['binding']['key_sha256'] for e in hist}),
                  distinct_entries=len({M.AC.digest(e) for e in hist}))
    summary['counts'] = counts
    required('distinct16', lambda: need(all(n == 16 for n in counts.values())))
    required('history15', lambda: need(len(occupied['access_history']) == 15))
    validate_slot('occupied15', occupied, w.ctl)
    free = w.record()
    required('free16_state', lambda: need(free['state'] == 'FREE'))
    validate_slot('free16', free, w.ctl)
    if kind == 'failed':
        required('final_proof', lambda: M.AR.validate_proof(proof))
    summary['status'] = 'PASS'


def main():
    try:
        need(sys.implementation.name == 'cpython' and sys.version_info[:3] == (3, 12, 16))
        need(sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv) == 2)
        need(not any(k.startswith(('CLOUDSDK', 'GOOGLE', 'GCLOUD', 'GH_', 'GITHUB', 'ANTHROPIC')) for k in os.environ))
        def deny(*args, **kwargs):
            raise Stop()
        with ExitStack() as stack:
            for obj, attr in ((socket.socket, 'connect'), (socket.socket, 'connect_ex'),
                              (socket, 'getaddrinfo'), (socket, 'create_connection'),
                              (subprocess, 'Popen'), (os, 'system'), (os, 'popen')):
                stack.enter_context(patch.object(obj, attr, deny))
            ST['stage'] = 'imports'
            sys.path.insert(0, str(Path(sys.argv[1]).resolve() / 'build' / 'gcp'))
            for alias, name in dict(AC='access_records', AR='access_recovery', OS='oslogin',
                                   CT='controller', TA='test_access', TR='test_access_recovery',
                                   TB='test_base_build', TG='test_gcs', gcs='gcs', store='store', spec='spec').items():
                setattr(M, alias, importlib.import_module('lifecycle.' + name))
            for module, name in ((M.gcs, '_record'), (M.AR, '_record'),
                                 (M.AR, 'bounded'), (M.AR, 'validate_proof'),
                                 (M.AC, 'validate_record'), (M.AR, 'validate_record'),
                                 (M.OS, 'validate_record'), (M.OS, 'check_receipt'),
                                 (M.CT, 'check_receipt')):
                original = getattr(module, name)
                stack.enter_context(patch.object(module, name,
                    hook(module.__name__.rsplit('.', 1)[-1] + ':' + name,
                         original, lambda value, *a, **k: value)))
            for kind in ('normal', 'failed'):
                build(kind, stack)
        REP['status'] = 'PASS' if not REP['stopped'] else 'FAIL'
    except BaseException:
        REP['stopped'].append(dict(ST, code='PROBE_STOPPED'))
        REP['status'] = 'FAIL'
    print(json.dumps(REP, sort_keys=True))
    return 1 if REP['stopped'] else 0


if __name__ == '__main__':
    sys.exit(main())
