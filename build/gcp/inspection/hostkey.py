"""Pure parser for the fixed owner gcloud host-key query; no IO or cloud calls.

Input is bounded ``get-guest-attributes --query-path=hostkeys/ssh-ed25519
--format=json`` output: a JSON array of queryValue.items, not a REST envelope.
Caller owns authenticated capture, immutable VM/boot identity checks before and
after, private files, ssh-keygen validation and strict SSH. Guest-writable
attributes are not an attestation against an untrusted guest.
"""
import base64
import binascii
import json

MAX_RESPONSE_BYTES = 4096
_PREFIX = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate host-key JSON field")
        result[key] = value
    return result


def extract_ed25519(raw: bytes) -> str:
    """Return one canonical OpenSSH public-key line, or sanitized ValueError."""
    try:
        if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_RESPONSE_BYTES:
            raise ValueError()
        items = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object)
        if not isinstance(items, list) or len(items) != 1:
            raise ValueError()
        item = items[0]
        if (not isinstance(item, dict) or set(item) != {"namespace", "key", "value"}
                or item["namespace"] != "hostkeys" or item["key"] != "ssh-ed25519"
                or not isinstance(item["value"], str)):
            raise ValueError()
        encoded = item["value"]
        wire = base64.b64decode(encoded, validate=True)
        if (len(wire) != len(_PREFIX) + 32 or not wire.startswith(_PREFIX)
                or base64.b64encode(wire).decode("ascii") != encoded):
            raise ValueError()
        return "ssh-ed25519 " + encoded + "\n"
    except (ValueError, TypeError, UnicodeError, binascii.Error, RecursionError):
        raise ValueError("host-key guest attribute refused") from None
