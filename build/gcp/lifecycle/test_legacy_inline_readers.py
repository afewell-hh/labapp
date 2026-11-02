"""Frozen real reader predicates from 18be786c22dc410088c9da1f20c210e2f5c78b6c.

Keep the original complete GCS envelope validator and Context.from_slot method,
not a test-written approximation of their schema predicates. This exercises the
old rejection policy offline without requiring Git history in a shallow CI clone.
"""
import json
import unittest
from datetime import timedelta

from . import spec
from .access_records import AccessError, SLOT, canonical, validate_binding
from .gcs import StoreError


OLD_RECORD = '''
def _record(record, key: str) -> None:
    # Validate the shared versioned envelope, not a second controller model.
    # Unknown versions/states and occupied records missing core fields block
    # access instead of being treated as FREE. Nested JSON is bounded below.
    if (not isinstance(record, dict) or type(record.get("schema")) is not int or
            record["schema"] != 1 or record.get("slot") != key or
            not isinstance(record.get("state"), str) or record["state"] not in _STATES or
            type(record.get("epoch")) is not int or record["epoch"] < 0):
        raise StoreError("invalid ledger record envelope")
    if record["state"] != "FREE":
        core = {"project": str, "zone": str, "run_id": int, "attempt": int,
                "request_id": str, "body_hash": str, "boot_image": str,
                "names": dict, "reserved_at": str, "deadline": str,
                "submit_attempts": int, "max_submit_attempts": int,
                "ids": dict, "evidence": list}
        if (any(type(record.get(k)) is not t for k, t in core.items()) or
                "operation" not in record or "reason" not in record):
            raise StoreError("invalid occupied ledger record")
    elif "last_release" in record and not isinstance(record["last_release"], dict):
        raise StoreError("invalid ledger release record")
    def visit(value, depth=0):
        if depth > 32:
            raise StoreError("ledger record nesting exceeds limit")
        if isinstance(value, dict):
            if any(not isinstance(k, str) for k in value):
                raise StoreError("invalid ledger JSON key")
            for v in value.values():
                visit(v, depth + 1)
        elif isinstance(value, list):
            for v in value:
                visit(v, depth + 1)
        elif value is not None and type(value) not in (str, int, bool):
            # The controller uses no floating-point fields.
            raise StoreError("invalid ledger JSON value")
    visit(record)
'''

OLD_CONTEXT = '''
class Context:
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
'''


def old_readers():
    from .access_records import _exact, timestamp
    from dataclasses import make_dataclass
    namespace = dict(StoreError=StoreError, AccessError=AccessError, spec=spec,
        SLOT=SLOT, canonical=canonical, validate_binding=validate_binding,
        _exact=_exact, timestamp=timestamp, timedelta=timedelta,
        _STATES=frozenset({'FREE', 'RESERVED', 'ACTIVE', 'CLEANUP_FAILED'}))
    exec(OLD_RECORD, namespace)
    exec(OLD_CONTEXT, namespace)
    # Preserve the frozen original method, with the original bytes constructor.
    context = make_dataclass('OldContext', [('_encoded', bytes)])
    context.from_slot = classmethod(namespace['Context'].from_slot.__func__)
    return namespace['_record'], context


class OldReaderRefusal(unittest.TestCase):
    def test_old_gcs_validator_accepts_legacy_and_refuses_schema2(self):
        old_record, _ = old_readers()
        legacy = dict(schema=1, slot=SLOT, state='FREE', epoch=0)
        old_record(legacy, SLOT)
        with self.assertRaises(StoreError):
            old_record(dict(legacy, schema=2), SLOT)

    def test_old_context_method_accepts_real_schema1_then_refuses_schema2(self):
        from .test_access import Fixture
        _, old_context = old_readers()
        f = Fixture()
        self.assertEqual(json.loads(old_context.from_slot(f.w.record())._encoded), f.context.binding)
        value = f.w.record()
        value['schema'] = 2
        with self.assertRaises(AccessError): old_context.from_slot(value)
