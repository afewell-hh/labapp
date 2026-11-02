"""Finite INLINE schema-2 access-history codec and pre-admission capacity gate.

Scope (issue #455): one pure, offline-testable module. It does NOT read or write
GCS, authenticate anyone, run migration, or touch cloud/VM state. It only decides
whether a ledger record's retained access history is structurally sound and
whether the *largest permitted* occupied / normal-FREE / failed-proof continuation
still fits inside the fixed object envelope BEFORE any paid side effect.

Two on-disk shapes are understood:

* schema 1 - the existing ledger. Only its ``access_history`` list is reasoned
  about here (minimum structural/ownership semantics, de-duplication, the retained
  cap of ``LEGACY_LIMIT`` entries, and the previously-missing EARLY admission
  refusal). Everything else about schema-1 records remains owned by ``gcs._record``
  and ``controller`` and is intentionally left untouched.

* schema 2 - the new INLINE continuation for the canonical VLAB profile. It keeps
  the full schema-1 history verbatim as an immutable *legacy prefix* (lossless; no
  retroactive entry caps and no unknown-field rejection inside those entries) and
  commits that prefix with ``legacy_history = {count, sha256}`` where
  ``sha256 == digest(access_history[:count])``. Entries appended after the prefix
  are new, strictly-closed schema-2 entries. No new storage objects or namespaces
  are introduced: history stays inline in the one slot object.

Grandfathering is by explicit count + canonical digest over the verbatim prefix
(issue #455 acceptance #2, "count+canonical digest"): the entries themselves are
preserved, and the digest makes the prefix immutable for later authentication.

Old readers refuse schema 2: the pre-upgrade baseline ``gcs._record`` and
``access_records.Context`` pinned ``schema == 1``, so a schema-2 record is rejected
by every old reader. The current ROOT-upgraded readers accept schema 2 structurally
while this module owns its history semantics. No constructor here downgrades a
schema-2 record back to schema 1 (see ``carry``); migration is offline-only and
never authenticates or authorises a write (see ``plan_migration``).

Byte/depth budgets are enforced, not assumed. Chosen allocations:

* ``NEW_ENTRY_BYTES = 2048``   - serialized cap for ONE new (non-legacy) entry.
* ``LIVE_BYTES = 8192``        - occupied live portion (state/access/ids/... minus
                                 the common retained projection and ``evidence``),
                                 and the residual (``state`` + new ``last_release``)
                                 of a freshly produced FREE record. The FREE residual
                                 cap is enforced by ``free_budget`` (producer side),
                                 NOT by ``validate``, so a migrated record keeps its
                                 opaque grandfathered ``last_release`` unchanged.
* ``EVIDENCE_BYTES = 4096``    - serialized cap for the occupied ``evidence`` list.
* ``PROOF_EXTRA_BYTES = 8192`` - failed-disposal proof residual (proof minus the
                                 embedded ``slot``) and the per-proof reserve added
                                 on top of the occupied upper bound.

These are a chosen ENFORCED policy, not a measured capacity result. The disjoint
allocations (new entry, live, evidence, proof-extra, plus per-reserve envelope
slack) form an analytic partition whose conservative occupied / normal-FREE /
failed-proof upper bounds each sum to <= ``RECORD_BYTES``; ``_reserve`` refuses
before any paid side effect when they would not. They differ from the draft
figures sketched in issue #455 (new-entry 1536 / fixed 7168 / proof-extra 4096);
only ROOT accepts which figures govern. A count ceiling is therefore NOT a promise
of 24 usable entries: byte/depth/count refusal happens before the side effect, so a
near-limit legacy prefix or long escaped data fails closed rather than producing an
unusable VM. No capacity PASS is claimed here.

Canonical JSON and binding/timestamp validators are reused from ``access_records``
through a lazy, function-local import so that ``access_records.Context.from_slot``
can import this module locally without a circular import at module load.
"""
from __future__ import annotations

import copy
import re
from datetime import timedelta

from . import spec

LEGACY_LIMIT = 16
HISTORY_LIMIT = 24
NEW_ENTRY_BYTES = 2048
LIVE_BYTES = 8192
EVIDENCE_BYTES = 4096
PROOF_EXTRA_BYTES = 8192
RECORD_BYTES = 65_536
MAX_DEPTH = 30          # occupied record depth, so proof (+1) and the proof
PROOF_MAX_DEPTH = 31    # validation wrapper (+1) still stay within ledger depth 32
ENVELOPE_SLACK = 32     # conservative over-count for braces/commas/quotes

SLOT = 'slots/slot-1.json'
SIGNED63 = 2 ** 63 - 1
UINT64 = 2 ** 64 - 1
ZERO_UUID = '00000000-0000-0000-0000-000000000000'

OCCUPIED_STATES = frozenset({'RESERVED', 'ACTIVE', 'CLEANUP_FAILED'})
COMMON2 = frozenset({'schema', 'slot', 'epoch', 'access_history',
                     'legacy_history', 'quarantine', 'used_capture_ids'})
COMMON1 = frozenset({'schema', 'slot', 'epoch', 'access_history',
                     'quarantine', 'used_capture_ids'})
OCCUPIED_FIELDS = frozenset({
    'state', 'project', 'zone', 'run_id', 'attempt', 'request_id', 'body_hash',
    'boot_image', 'boot_image_id', 'profile', 'children', 'names', 'reserved_at',
    'deadline', 'submit_attempts', 'max_submit_attempts', 'operation', 'ids',
    'reason', 'evidence'})

MIGRATION_ALLOWED_TOP = frozenset({
    'schema', 'slot', 'state', 'epoch', 'access_history', 'quarantine',
    'used_capture_ids', 'last_release'})
MIGRATION_REQUIRED_TOP = frozenset({'schema', 'slot', 'state', 'epoch', 'quarantine'})

# Known FREE last_release shapes produced by the normal (controller.free) and
# failed (access_recovery) constructors. plan_migration refuses a schema-1
# last_release whose field set is neither, because ordinary later transitions
# replace the known last_release and any unknown content would silently vanish
# (issue #455 acceptance #8). A matching last_release is preserved verbatim with
# no retrospective size cap; its keys only are checked, not inner value sizes.
NORMAL_RELEASE = frozenset({
    'run_id', 'attempt', 'request_id', 'ids', 'released_at', 'evidence'})
FAILED_RELEASE = NORMAL_RELEASE | {
    'outcome', 'trial', 'import_status', 'recovery'}

_SHA_RE = re.compile(r'[0-9a-f]{64}\Z')
_ID_RE = re.compile(r'[1-9][0-9]{0,19}\Z')
_UUID_RE = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
# Compute operation name grammar (clientOperationId / operation name): a non-empty
# 1..200 run of [A-Za-z0-9_-], never empty and never arbitrary ASCII.
_OP_RE = re.compile(r'[A-Za-z0-9_-]{1,200}\Z')


class HistoryError(ValueError):
    """Unsound, oversized or reused access history, or an unsafe continuation.

    A subclass of ``ValueError`` so callers that already fence domain errors keep
    failing closed. Semantic/capacity failure here never authorises a FREE release
    or a new access lease; physically-verified owned deletion stays a separate gate.
    """


# --------------------------------------------------------------------- helpers
_records = None


def _ar():
    """Lazily import ``access_records`` to avoid an import-time cycle."""
    global _records
    if _records is None:
        from . import access_records
        _records = access_records
    return _records


def _canonical(value) -> bytes:
    try:
        return _ar().canonical(value)
    except (ValueError, TypeError):
        raise HistoryError('record is not canonical finite JSON') from None


def _hex(value) -> bool:
    return isinstance(value, str) and _SHA_RE.fullmatch(value) is not None


def _uuid(value) -> bool:
    return (isinstance(value, str) and _UUID_RE.fullmatch(value) is not None
            and value != ZERO_UUID)


def _int_range(value, lo, hi, name) -> None:
    # ``type(x) is int`` rejects bool (type(True) is bool), i.e. no bool ints.
    if type(value) is not int or not lo <= value <= hi:
        raise HistoryError(f'{name} outside the permitted range')


def _binding(value) -> dict:
    ar = _ar()
    try:
        ar.validate_binding(value)
    except ar.AccessError as exc:
        raise HistoryError(f'invalid access binding: {exc}') from None
    return value


def _timestamp(value, name):
    ar = _ar()
    try:
        return ar.timestamp(value)
    except ar.AccessError:
        raise HistoryError(f'invalid {name} timestamp') from None


def _depth(value, limit, _d=0) -> None:
    if _d > limit:
        raise HistoryError('record nesting exceeds limit')
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise HistoryError('non-string JSON object key')
            _depth(nested, limit, _d + 1)
    elif isinstance(value, list):
        for nested in value:
            _depth(nested, limit, _d + 1)
    elif value is not None and type(value) not in (str, int, bool):
        # The ledger uses no floating-point fields; reject float/other outright.
        raise HistoryError('non-finite or float JSON value')


# ----------------------------------------------------------- history entries
def _ref(value, *, lease, kind, failed) -> None:
    fields = {'path', 'generation', 'sha256'} | ({'observation'} if failed else set())
    if type(value) is not dict or set(value) != fields:
        raise HistoryError('access archive reference fields')
    if value['path'] != 'access/slot-1/' + lease + '/' + kind + '.json':
        raise HistoryError('access archive reference path')
    gen, sha = value['generation'], value['sha256']
    if failed:
        obs = value['observation']
        if kind == 'intent':
            if not (type(gen) is int and 1 <= gen <= UINT64) or not _hex(sha) or obs != 'present':
                raise HistoryError('failed-disposal intent receipt invalid')
        elif not (type(gen) is int and gen == 0 and sha is None and obs == 'observed-absent'):
            raise HistoryError('failed-disposal receipt must be observed-absent')
    elif kind == 'seal' and type(gen) is int and gen == 0:
        if sha is not None:
            raise HistoryError('unsealed seal must carry a null digest')
    elif not (type(gen) is int and 1 <= gen <= UINT64 and _hex(sha)):
        # Archive/recovery generations are the uint64 storage-generation domain
        # (GCS metadata). signed-63 applies only to validate_record's
        # intent_generation and binding epoch/run/attempt, not to these refs.
        raise HistoryError('access archive receipt invalid')


def _archive_refs(archive, *, lease, failed) -> None:
    kinds = _ar().KINDS
    if type(archive) is not dict or set(archive) != set(kinds):
        raise HistoryError('access archive must map the fixed access kinds')
    for kind in kinds:
        _ref(archive[kind], lease=lease, kind=kind, failed=failed)


def _recovery(value, *, lease) -> None:
    if type(value) is not dict or set(value) != {'path', 'generation', 'sha256'}:
        raise HistoryError('failed-disposal recovery reference fields')
    if value['path'] != 'failed-disposals/slot-1/' + lease + '/proof.json':
        raise HistoryError('failed-disposal recovery reference path')
    if not (type(value['generation']) is int and 1 <= value['generation'] <= UINT64) or not _hex(value['sha256']):
        raise HistoryError('failed-disposal recovery reference invalid')


def _entry(entry, *, legacy) -> dict:
    """Validate one retained history entry; return its binding.

    For BOTH the grandfathered legacy prefix and the new schema-2 suffix the KNOWN
    receipt/status/recovery contents are validated with their real domains, so a
    matching ``legacy_history`` digest cannot smuggle a malformed ref, a bad
    generation/sha256, or a non-FAILED/UNKNOWN status past admission. ``legacy``
    entries keep the prefix lossless: unknown EXTRA entry fields are preserved (not
    rejected) and no per-entry byte cap applies. Non-legacy (new) entries are
    additionally strictly closed and byte-bounded by the caller. If the archive or
    recovery ref SHAPE is not interpretable, the entry is refused (physical cleanup
    stays an independent gate).
    """
    if type(entry) is not dict:
        raise HistoryError('history entry must be an object')
    binding = _binding(entry.get('binding'))
    phase = entry.get('phase')
    if phase == 'archived':
        failed = False
    elif phase == 'failed-disposed':
        failed = True
    else:
        raise HistoryError('retained entry phase must be archived or failed-disposed')
    lease = binding['lease']
    if 'archive' not in entry:
        raise HistoryError('retained entry must carry an archive')
    _archive_refs(entry['archive'], lease=lease, failed=failed)
    if failed:
        if 'recovery' not in entry:
            raise HistoryError('failed-disposed entry must carry a recovery reference')
        _recovery(entry['recovery'], lease=lease)
        if (entry.get('trial') != 'FAILED' or entry.get('import_status') != 'UNKNOWN' or
                entry.get('disposition') != 'FAILED_DISPOSED'):
            raise HistoryError('failed-disposed entry outcome must be FAILED/UNKNOWN/FAILED_DISPOSED')
    if legacy:
        return binding
    if not failed:
        if set(entry) != {'binding', 'phase', 'archive'}:
            raise HistoryError('new archived entry fields')
    else:
        if set(entry) != {'binding', 'phase', 'archive', 'recovery',
                          'trial', 'import_status', 'disposition'}:
            raise HistoryError('new failed-disposed entry fields')
    return binding


def _legacy_meta(record, entries) -> int:
    meta = record.get('legacy_history')
    if type(meta) is not dict or set(meta) != {'count', 'sha256'}:
        raise HistoryError('schema-2 legacy_history must be {count, sha256}')
    count = meta['count']
    if type(count) is not int or not 0 <= count <= LEGACY_LIMIT:
        raise HistoryError('legacy_history count outside 0..LEGACY_LIMIT')
    if count > len(entries):
        raise HistoryError('legacy_history count exceeds retained history')
    if not _hex(meta['sha256']):
        raise HistoryError('legacy_history digest must be lowercase sha256')
    if meta['sha256'] != _ar().digest(entries[:count]):
        raise HistoryError('legacy prefix digest mismatch')
    return count


def history(record, *, adding=False) -> list:
    """Validate and return the retained access-history list of ``record``.

    Works for both schemas. Enforces the retained cap (16 for schema 1, 24 for
    schema 2), ``validate_binding`` on every entry, no reused lease UUID or key
    digest across the FULL history (and against the current ``access`` binding if
    present), the immutable grandfathered prefix for schema 2, and the per-entry
    byte cap on new schema-2 entries. ``adding=True`` additionally requires room
    for one more entry (the previously-missing early admission refusal).
    """
    if type(record) is not dict:
        raise HistoryError('record must be an object')
    schema = record.get('schema')
    if type(schema) is not int:
        raise HistoryError('unsupported history schema')
    if schema == 1:
        entries = record.get('access_history', [])
        limit, legacy_count = LEGACY_LIMIT, None
    elif schema == 2:
        entries = record.get('access_history')
        limit = HISTORY_LIMIT
    else:
        raise HistoryError('unsupported history schema')
    if type(entries) is not list:
        raise HistoryError('access_history must be a list')
    if schema == 2:
        legacy_count = _legacy_meta(record, entries)
    if len(entries) > limit:
        raise HistoryError('access history exceeds retention limit')
    if adding and len(entries) >= limit:
        raise HistoryError('access retention/accounting limit reached')
    leases, keys = set(), set()
    for index, entry in enumerate(entries):
        legacy = legacy_count is None or index < legacy_count
        binding = _entry(entry, legacy=legacy)
        if binding['lease'] in leases or binding['key_sha256'] in keys:
            raise HistoryError('access lease/key must never be reused')
        leases.add(binding['lease'])
        keys.add(binding['key_sha256'])
        if not legacy and len(_canonical(entry)) > NEW_ENTRY_BYTES:
            raise HistoryError('new access entry exceeds byte bound')
    access = record.get('access')
    if isinstance(access, dict) and isinstance(access.get('binding'), dict):
        current = _binding(access['binding'])
        if current['lease'] in leases or current['key_sha256'] in keys:
            raise HistoryError('current access reuses a historical lease/key')
    return entries


# ------------------------------------------------------------ record validation
def _common(record) -> dict:
    keys = COMMON2 if record.get('schema') == 2 else COMMON1
    return {k: record[k] for k in keys if k in record}


def cleanup_fact(kind, name, resource_id=None) -> str:
    """The two physical observations emitted by controller._delete_owned."""
    if resource_id is None:
        return f'{kind} {name}: absent (404)'
    return f'{kind} {name} id {resource_id}: deleted, 404 confirmed'


def cleanup_evidence(evidence, facts) -> list:
    """Append only unseen facts; preserve the entire old list, even duplicates."""
    result = list(evidence)
    for fact in facts:
        if fact not in result:
            result.append(fact)
    return result


def cleanup_evidence_bound(record) -> int:
    """Actual old bytes plus every still-possible distinct physical observation.

    Schema2 has exactly instance+boot (spec.kinds), with immutable spec.names
    (15 run digits, 3 attempt digits) and at most one uint64 ID per child.
    Each child emits only absent-404 and deleted-ID-404, so there are at most
    FOUR lifetime facts, regardless of retries/reasons/operation names. For an
    unadopted ID charge a full 20-digit fact without deduplicating a placeholder:
    an old opaque string might equal the placeholder but not the eventual ID.
    """
    evidence = record['evidence']
    if type(evidence) is not list or any(not isinstance(item, str) for item in evidence):
        raise HistoryError('physical cleanup evidence must be strings')
    expected = spec.names(record['run_id'], record['attempt'], spec.UBUNTU_VLAB_CORE)
    if record['names'] != expected or set(record['ids']) != set(expected):
        raise HistoryError('physical cleanup child inventory mismatch')
    facts, unknown = [], []
    for kind, name in expected.items():
        facts.append(cleanup_fact(kind, name))
        value = record['ids'][kind]
        if value is None:
            unknown.append(cleanup_fact(kind, name, str(UINT64)))
        elif (isinstance(value, str) and _ID_RE.fullmatch(value) and int(value) <= UINT64):
            facts.append(cleanup_fact(kind, name, value))
        else:
            raise HistoryError('physical cleanup id must be a uint64 string or null')
    return (len(_canonical(cleanup_evidence(evidence, facts))) +
            sum(len(_canonical(fact)) + 1 for fact in unknown))


def cleanup_budget(record) -> None:
    """Producer gate, independent of opaque history/access semantics.

    Ordinary controller gates call this BEFORE admission/submission/registration.
    Physical CAS also calls it, never shrinking old evidence to make room.
    Readers still enforce their existing actual-byte limits; they confer no
    permission to submit a record lacking this prospective producer reserve.
    """
    if cleanup_evidence_bound(record) > EVIDENCE_BYTES:
        raise HistoryError('physical cleanup facts exceed evidence reserve')
    live = {k: v for k, v in record.items() if k not in COMMON2 and k != 'evidence'}
    live['state'] = 'CLEANUP_FAILED'
    live['ids'] = {kind: value if value is not None else str(UINT64)
                   for kind, value in record['ids'].items()}
    # Longest fixed failure code in _reconcile_once/_delete_owned; API/transport
    # text is returned to the caller, not persisted as an unbounded live reason.
    reason = 'operation-mismatch:missing-or-mismatched-insert-target'
    if len(_canonical(live.get('reason'))) < len(_canonical(reason)):
        live['reason'] = reason
    if len(_canonical(live)) > LIVE_BYTES:
        raise HistoryError('physical cleanup live fields exceed reserve')
    if len(_canonical(record)) > RECORD_BYTES:
        raise HistoryError('physical cleanup record exceeds byte bound')


def _reserve(record) -> None:
    """Refuse unless the largest permitted continuation from here still fits.

    The retained common projection (history, legacy metadata, inventory - but NOT
    the replaced ``last_release`` or occupied live fields) is measured, then the
    conservative occupied / normal-FREE (one appended entry) / failed-proof upper
    bounds are checked against ``RECORD_BYTES``. Headroom for the eventual disposal
    (normal or failed) is reserved before any paid admission.
    """
    common = _common(record)
    _depth(common, MAX_DEPTH)
    common_bytes = len(_canonical(common))
    occupied_upper = common_bytes + LIVE_BYTES + EVIDENCE_BYTES + ENVELOPE_SLACK
    free_upper = common_bytes + NEW_ENTRY_BYTES + 1 + LIVE_BYTES + ENVELOPE_SLACK
    proof_upper = occupied_upper + PROOF_EXTRA_BYTES + ENVELOPE_SLACK
    for label, value in (('occupied', occupied_upper),
                         ('normal FREE', free_upper),
                         ('failed proof', proof_upper)):
        if value > RECORD_BYTES:
            raise HistoryError(f'reserved {label} continuation exceeds byte bound')


def _access(value) -> None:
    if type(value) is not dict or set(value) != {'binding', 'phase', 'archive'}:
        raise HistoryError('occupied access fields')
    binding = _binding(value['binding'])
    if value['phase'] not in ('registered', 'finalizing', 'archived'):
        raise HistoryError('occupied access phase')
    archive = value['archive']
    if type(archive) is not dict:
        raise HistoryError('occupied access archive must be an object')
    if value['phase'] == 'archived':
        _archive_refs(archive, lease=binding['lease'], failed=False)
    elif archive != {}:
        raise HistoryError('unarchived access must carry an empty archive')


def _occupied2(record) -> None:
    present = set(record)
    required = COMMON2 | OCCUPIED_FIELDS
    if not required <= present or not present - required <= {'access'}:
        raise HistoryError('occupied schema-2 field set')
    if record['state'] not in OCCUPIED_STATES:
        raise HistoryError('occupied schema-2 state')
    if record['profile'] != spec.UBUNTU_VLAB_CORE:
        raise HistoryError('schema-2 occupied is canonical VLAB only')
    for name in ('run_id', 'attempt'):
        if type(record[name]) is not int or record[name] < 1:
            raise HistoryError('occupied run/attempt must be positive ints')
    try:
        expected_names = spec.names(record['run_id'], record['attempt'], spec.UBUNTU_VLAB_CORE)
    except ValueError:
        raise HistoryError('occupied run/attempt outside the owned naming') from None
    if record['names'] != expected_names:
        raise HistoryError('occupied names mismatch')
    ids = record['ids']
    if type(ids) is not dict or set(ids) != set(expected_names):
        raise HistoryError('occupied ids must key the owned children')
    for value in ids.values():
        if value is not None and not (isinstance(value, str) and _ID_RE.fullmatch(value)
                                      and int(value) <= UINT64):
            raise HistoryError('occupied resource id must be a uint64 string or null')
    if not _uuid(record['request_id']):
        raise HistoryError('occupied request_id must be a nonzero UUID')
    if (record['project'] != spec.PROJECT or record['zone'] != spec.ZONE or
            record['boot_image'] != spec.COMPONENT_IMAGE or
            record['boot_image_id'] != spec.COMPONENT_IMAGE_ID):
        raise HistoryError('occupied project/zone/image pin mismatch')
    if not _hex(record['body_hash']):
        raise HistoryError('occupied body_hash must be sha256')
    if type(record['children']) is not dict:
        raise HistoryError('occupied children must be an object')
    reserved_at = _timestamp(record['reserved_at'], 'reserved_at')
    deadline = _timestamp(record['deadline'], 'deadline')
    # Close the persisted intent against the one derived VLAB request so a
    # standalone Context.from_slot validation cannot accept a body_hash/children
    # that do not match the declared run/attempt/request/deadline inputs. This
    # mirrors controller._lease_kinds; the controller stays authoritative, but
    # Context uses validate() alone and must not be identity-bypassed.
    try:
        body = spec.build_body(
            boot_image=record['boot_image'], request_id=record['request_id'],
            run_id=record['run_id'], attempt=record['attempt'],
            deadline=deadline, profile=spec.UBUNTU_VLAB_CORE)
    except (ValueError, KeyError, TypeError):
        raise HistoryError('occupied intent is not a well-formed VLAB request') from None
    if spec.body_hash(body) != record['body_hash']:
        raise HistoryError('occupied body_hash does not match the derived request')
    expected_children = {k: body['disks'][i]['initializeParams']
                         for i, (k, _) in enumerate(spec.kinds(spec.UBUNTU_VLAB_CORE)[1:])}
    if record['children'] != expected_children:
        raise HistoryError('occupied children do not match the derived request')
    if (deadline - reserved_at).total_seconds() / 60 != spec.VLAB_LEASE_MINUTES:
        raise HistoryError('occupied VLAB lease must be exactly the fixed duration')
    sa, ma = record['submit_attempts'], record['max_submit_attempts']
    if (type(sa) is not int or type(ma) is not int or not 0 <= sa <= ma or
            not 0 < ma <= SIGNED63):
        raise HistoryError('occupied submit counters must be 0<=submitted<=max, max a positive signed63')
    op = record['operation']
    if op is not None and (not isinstance(op, str) or _OP_RE.fullmatch(op) is None):
        raise HistoryError('occupied operation must be a 1..200 [A-Za-z0-9_-] name or null')
    if record['reason'] is not None and not isinstance(record['reason'], str):
        raise HistoryError('occupied reason must be a string or null')
    evidence = record['evidence']
    if type(evidence) is not list or any(not isinstance(item, str) for item in evidence):
        raise HistoryError('occupied evidence must be a list of strings')
    if len(_canonical(evidence)) > EVIDENCE_BYTES:
        raise HistoryError('occupied evidence exceeds reserve')
    if 'access' in record:
        _access(record['access'])
        # Correlate the current access binding with THIS slot so a standalone
        # Context.from_slot validation cannot accept a lease bound to different
        # run/attempt/ids/image/deadline. Mirrors access_records.Context.from_slot:
        # the VLAB work deadline is exactly 15 minutes before the slot deadline.
        b = record['access']['binding']
        ids = record['ids']
        work_deadline = _timestamp(b['work_deadline'], 'work_deadline')
        if (b['lease'] != record['request_id'] or b['epoch'] != record['epoch'] or
                b['run_id'] != record['run_id'] or b['attempt'] != record['attempt'] or
                b['vm_id'] != ids['instance'] or b['boot_id'] != ids['boot'] or
                b['source_image_id'] != spec.COMPONENT_IMAGE_ID or
                b['deadline'] != record['deadline'] or
                deadline - work_deadline != timedelta(minutes=15)):
            raise HistoryError('occupied access binding does not correlate with the slot')
    live = {k: v for k, v in record.items() if k not in COMMON2 and k != 'evidence'}
    if len(_canonical(live)) > LIVE_BYTES:
        raise HistoryError('occupied live portion exceeds reserve')


def _free2(record) -> None:
    present = set(record)
    allowed = COMMON2 | {'state'}
    if not allowed <= present or not present - allowed <= {'last_release'}:
        raise HistoryError('FREE schema-2 field set')
    if record['state'] != 'FREE':
        raise HistoryError('FREE schema-2 state')
    if 'last_release' in record:
        release = record['last_release']
        if (type(release) is not dict or
                set(release) not in (NORMAL_RELEASE, FAILED_RELEASE)):
            raise HistoryError('FREE last_release must have a known release shape')
    # The FREE residual cap is deliberately NOT enforced here: a migrated schema-1
    # record carries its opaque grandfathered last_release unchanged, bounded only
    # by the global 64 KiB/depth-32 limits. A freshly produced (new) FREE record
    # has its live residual capped by the release producer via ``free_budget``.


def _schema2(record, *, adding) -> None:
    if type(record.get('schema')) is not int or record['schema'] != 2:
        raise HistoryError('schema-2 record required')
    if record.get('slot') != SLOT:
        raise HistoryError('schema-2 is slot-1 only')
    _int_range(record.get('epoch'), 0, SIGNED63, 'epoch')
    if (type(record.get('state')) is not str or
            record['state'] not in (OCCUPIED_STATES | {'FREE'})):
        raise HistoryError('invalid schema-2 state')
    if 'capture' in record:
        raise HistoryError('schema-2 forbids inline capture inventory')
    if record.get('quarantine') != []:
        raise HistoryError('schema-2 requires an explicitly empty quarantine')
    uci = record.get('used_capture_ids')
    if (type(uci) is not list or len(uci) > 512 or
            any(not _uuid(item) for item in uci) or len(set(uci)) != len(uci)):
        raise HistoryError('used_capture_ids must be <=512 unique nonzero UUIDs')
    _depth(record, MAX_DEPTH)
    if len(_canonical(record)) > RECORD_BYTES:
        raise HistoryError('record exceeds byte bound')
    history(record, adding=adding)
    if record['state'] == 'FREE':
        _free2(record)
    else:
        _occupied2(record)


def validate(record, *, reserve=False, adding=False) -> None:
    """Validate a ledger record's history (schema 1) or whole shape (schema 2).

    schema 1: only the history is checked here; the rest stays owned by
    ``gcs._record``/``controller``. schema 2: the closed typed shape, domains,
    bounded live/evidence/residual portions, byte and depth limits are enforced.
    ``reserve=True`` additionally refuses unless the largest permitted continuation
    still fits; ``adding=True`` requires room for one more retained entry.
    """
    if type(record) is not dict:
        raise HistoryError('record must be an object')
    schema = record.get('schema')
    if type(schema) is not int:
        raise HistoryError('unsupported ledger schema')
    if schema == 1:
        # Legacy behavior is preserved except for the early count/history gate;
        # schema-1 records are NOT subjected to the schema-2 capacity reserve.
        history(record, adding=adding)
    elif schema == 2:
        _schema2(record, adding=adding)
        if reserve:
            _reserve(record)
    else:
        raise HistoryError('unsupported ledger schema')


def proof_budget(proof) -> None:
    """Refuse a failed-disposal proof whose embedded continuation cannot fit.

    When the embedded ``slot`` is schema 2 it must pass the occupied reserve. The
    proof residual (proof minus ``slot``) is capped at ``PROOF_EXTRA_BYTES`` and the
    whole proof at ``RECORD_BYTES``/``PROOF_MAX_DEPTH``. The recovery flow's own
    ``validate_proof`` stays authoritative for proof semantics; this is an added
    capacity gate to invoke before upload.
    """
    if type(proof) is not dict:
        raise HistoryError('proof must be an object')
    slot = proof.get('slot')
    if isinstance(slot, dict) and slot.get('schema') == 2:
        validate(slot, reserve=True, adding=True)
    residual = {k: v for k, v in proof.items() if k != 'slot'}
    if len(_canonical(residual)) > PROOF_EXTRA_BYTES:
        raise HistoryError('proof residual exceeds reserve')
    if len(_canonical(proof)) > RECORD_BYTES:
        raise HistoryError('proof exceeds byte bound')
    _depth(proof, PROOF_MAX_DEPTH)


def free_budget(record) -> None:
    """Producer-side gate for a freshly produced FREE record before it is written.

    Validates the record WITHOUT the forward reserve and additionally caps its live
    residual (``state`` plus the new ``last_release``) at ``LIVE_BYTES``.

    ``reserve`` is deliberately NOT applied here. Admission already reserved two
    disjoint continuations from the pre-admission history: (current history + max
    occupied + max failed proof) AND (current history + one new entry + max FREE
    residual). A disposal that appends its one entry and writes FREE is the second,
    already-reserved outcome; demanding NEXT-admission occupied/proof headroom from
    the just-appended FREE record would falsely block a correctly-reserved release.
    A FREE record may validly consume all current headroom - the NEXT admission is
    the one that must refuse early, via ``validate(..., reserve=True, adding=True)``.

    ``validate`` does NOT impose the residual cap, so a migrated schema-1 record
    keeps a large opaque grandfathered ``last_release``; only newly produced
    normal/failed FREE records pass through here and are held to the typed shape and
    the reserved live budget.
    """
    if type(record) is not dict:
        raise HistoryError('record must be an object')
    if record.get('state') != 'FREE':
        raise HistoryError('free_budget applies to a FREE record')
    validate(record, reserve=False, adding=False)
    release = record.get('last_release')
    if type(release) is not dict or set(release) not in (NORMAL_RELEASE, FAILED_RELEASE):
        raise HistoryError('new FREE last_release must be a typed normal/failed release')
    for name in ('run_id', 'attempt'):
        _int_range(release[name], 1, SIGNED63, 'release ' + name)
    if not _uuid(release['request_id']):
        raise HistoryError('new FREE release request must be a nonzero UUID')
    ids = release['ids']
    if type(ids) is not dict or set(ids) != {'instance', 'boot'}:
        raise HistoryError('new FREE release ids must key the VLAB children')
    for value in ids.values():
        if value is not None and not (isinstance(value, str) and _ID_RE.fullmatch(value)
                                      and int(value) <= UINT64):
            raise HistoryError('new FREE release id must be a uint64 string or null')
    _timestamp(release['released_at'], 'released_at')
    if (type(release['evidence']) is not list or
            any(not isinstance(item, str) for item in release['evidence'])):
        raise HistoryError('new FREE release evidence must be strings')
    if set(release) == FAILED_RELEASE:
        if (release['outcome'] != 'FAILED_DISPOSED' or release['trial'] != 'FAILED' or
                release['import_status'] != 'UNKNOWN'):
            raise HistoryError('new FREE failed release must retain FAILED/UNKNOWN')
        _recovery(release['recovery'], lease=release['request_id'])
    common_keys = COMMON2 if record.get('schema') == 2 else COMMON1
    residual = {k: v for k, v in record.items() if k not in common_keys}
    if len(_canonical(residual)) > LIVE_BYTES:
        raise HistoryError('new FREE residual exceeds reserve')


def canonical(value) -> bytes:
    """Public re-export of the ledger canonical JSON encoder (``access_records``)."""
    return _ar().canonical(value)


def digest(value) -> str:
    """Public re-export of the ledger canonical SHA-256 digest (``access_records``)."""
    return _ar().digest(value)


# ------------------------------------------------------- continuation / migration
def carry(prev, new) -> dict:
    """Enforce and return the history continuation from ``prev`` to ``new``.

    The caller constructs ``new`` with its intended history already set; ``carry``
    guarantees no schema downgrade, an immutable schema-2 legacy prefix, that the
    full old history is an unchanged prefix of the new one, and that at most one
    entry is appended (old entries are never rewritten). It injects no top-level
    fields and returns ``new`` unchanged on success.
    """
    if type(prev) is not dict or type(new) is not dict:
        raise HistoryError('carry operates on two record objects')
    prev_schema, new_schema = prev.get('schema'), new.get('schema')
    if type(new_schema) is not int or new_schema not in (1, 2):
        raise HistoryError('unsupported schema continuation')
    if prev_schema == 2 and new_schema != 2:
        raise HistoryError('schema-2 cannot be downgraded')
    prev_hist = prev.get('access_history', [])
    new_hist = new.get('access_history', [])
    if type(prev_hist) is not list or type(new_hist) is not list:
        raise HistoryError('access_history must be a list on both records')
    if new_hist[:len(prev_hist)] != prev_hist:
        raise HistoryError('retained history prefix changed')
    if not 0 <= len(new_hist) - len(prev_hist) <= 1:
        raise HistoryError('at most one access entry may be appended')
    if prev_schema == 2 and prev.get('legacy_history') != new.get('legacy_history'):
        raise HistoryError('legacy_history metadata is immutable')
    return new


def plan_migration(record, generation) -> dict:
    """Return a PURE offline schema-1 -> schema-2 migration plan; no IO, no auth.

    ``record`` must be a compatible schema-1 FREE slot-1 record (exact allowed top
    fields, an explicitly empty quarantine, no ``access``/``capture``). Every entry,
    the epoch, inventory and any opaque ``last_release`` are preserved; the full
    history becomes the immutable legacy prefix committed by ``legacy_history``. The
    plan carries the expected whole-record snapshot, generation and digest for a
    SEPARATE ROOT CAS write that must itself authenticate the history and obtain
    trusted approval. This function authenticates nothing and authorises no write;
    it raises ``HistoryError`` if the record cannot be soundly migrated (including
    byte-headroom refusal).
    """
    if type(record) is not dict:
        raise HistoryError('record must be an object')
    if type(generation) is not int or not 0 < generation <= UINT64:
        raise HistoryError('migration generation must be a positive uint64')
    _depth(record, 32)
    if len(_canonical(record)) > RECORD_BYTES:
        raise HistoryError('migration source exceeds byte bound')
    present = set(record)
    if not MIGRATION_REQUIRED_TOP <= present or not present <= MIGRATION_ALLOWED_TOP:
        raise HistoryError('schema-1 FREE record has unexpected fields for migration')
    if 'access' in record or 'capture' in record:
        raise HistoryError('cannot migrate an occupied or capture-bearing record')
    if type(record.get('schema')) is not int or record['schema'] != 1:
        raise HistoryError('only a schema-1 record can be migrated')
    if record.get('slot') != SLOT or record.get('state') != 'FREE':
        raise HistoryError('only the FREE slot-1 record can be migrated')
    _int_range(record.get('epoch'), 0, SIGNED63, 'epoch')
    if record.get('quarantine') != []:
        raise HistoryError('migration requires an explicitly empty quarantine')
    entries = record.get('access_history', [])
    inventory = record.get('used_capture_ids', [])
    if type(entries) is not list or type(inventory) is not list:
        raise HistoryError('migration history/inventory must be lists')
    history(record)  # minimum schema-1 semantics, de-dup and the 16-entry cap
    ar = _ar()
    replacement = {
        'schema': 2,
        'slot': SLOT,
        'state': 'FREE',
        'epoch': record['epoch'],
        'quarantine': [],
        'used_capture_ids': copy.deepcopy(inventory),
        'access_history': copy.deepcopy(entries),
        'legacy_history': {'count': len(entries), 'sha256': ar.digest(entries)},
    }
    if 'last_release' in record:
        release = record['last_release']
        if not isinstance(release, dict):
            raise HistoryError('schema-1 last_release must be an object to migrate')
        keys = set(release)
        if keys != NORMAL_RELEASE and keys != FAILED_RELEASE:
            raise HistoryError(
                'schema-1 last_release has unknown fields; migration refuses it '
                'because a later transition would silently drop that content')
        replacement['last_release'] = copy.deepcopy(release)
    validate(replacement, reserve=True)
    return {
        'expected': copy.deepcopy(record),
        'expected_generation': generation,
        'expected_sha256': ar.digest(record),
        'replacement': replacement,
    }
