"""Actual parser on synthetic public keys; no cloud or credentials."""
import base64
import json
import unittest

from .hostkey import MAX_RESPONSE_BYTES, extract_ed25519

WIRE = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
VALUE = base64.b64encode(WIRE).decode("ascii")


def response(**changes):
    return json.dumps([dict(namespace="hostkeys", key="ssh-ed25519",
                            value=VALUE, **changes)]).encode()


class HostKeyTests(unittest.TestCase):
    def test_exact_cli_shape_and_canonical_key(self):
        self.assertEqual(extract_ed25519(response()), "ssh-ed25519 " + VALUE + "\n")

    def test_missing_extra_duplicate_and_rest_envelope_refused(self):
        item = json.loads(response())[0]
        invalid = [[], [item, item], [item, dict(item, key="ssh-rsa")],
                   [dict(item, namespace="foreign")], [dict(item, key="ssh-rsa")],
                   [dict(item, extra="private")], [{"key": "ssh-ed25519", "value": VALUE}],
                   {"queryPath": "hostkeys/ssh-ed25519", "queryValue": {"items": [item]}}]
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(ValueError):
                extract_ed25519(json.dumps(data).encode())
        with self.assertRaises(ValueError):
            extract_ed25519(response().replace(b'"namespace":', b'"namespace":"x","namespace":'))

    def test_malformed_algorithm_lengths_trailing_data_and_injection_refused(self):
        invalid = ["", "!", VALUE + "\n", "ssh-ed25519 " + VALUE,
                   VALUE + " comment", base64.b64encode(WIRE + b'x').decode(),
                   base64.b64encode(WIRE[:-1]).decode(),
                   base64.b64encode(WIRE.replace(b'ssh-ed25519', b'ssh-ed25518')).decode(),
                   base64.b64encode(WIRE.replace(b'\x00\x00\x00\x20', b'\x00\x00\x00\x21')).decode(),
                   1, None]
        item = json.loads(response())[0]
        for value in invalid:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, '^host-key guest attribute refused$'):
                extract_ed25519(json.dumps([dict(item, value=value)]).encode())

    def test_bounds_invalid_json_and_error_suppression(self):
        for raw in (b'', b'private secret', b'\xff', b'x' * (MAX_RESPONSE_BYTES + 1),
                    b'[' * 1100 + b'0' + b']' * 1100, 'not bytes'):
            with self.subTest(raw=type(raw)), self.assertRaisesRegex(ValueError, '^host-key guest attribute refused$'):
                extract_ed25519(raw)


if __name__ == '__main__':
    unittest.main()
