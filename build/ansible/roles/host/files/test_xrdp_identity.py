"""Offline checks for XRDP's public certificate and file-safety boundaries."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


HELPER = Path(__file__).with_name('labapp-xrdp-identity.py')
spec = importlib.util.spec_from_file_location('labapp_xrdp_identity', HELPER)
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


class XrdpIdentityTests(unittest.TestCase):
    def test_real_certificate_pair_and_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = root / 'cert.pem'
            key = root / 'key.pem'
            other_cert = root / 'other-cert.pem'
            other_key = root / 'other-key.pem'
            for output_cert, output_key in ((cert, key), (other_cert, other_key)):
                subprocess.run(
                    ['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                     '-sha256', '-nodes', '-days', '1', '-subj', '/CN=labapp-xrdp',
                     '-keyout', str(output_key), '-out', str(output_cert)],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                    timeout=20,
                )
            with patch.object(identity, 'CERT', cert), patch.object(identity, 'KEY', key):
                identity.validate_pair()
                key.write_bytes(other_key.read_bytes())
                with self.assertRaisesRegex(RuntimeError, 'identity-pair-mismatch'):
                    identity.validate_pair()

    def test_unsafe_identity_file_types_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / 'regular'
            regular.write_text('public test data')
            self.assertTrue(identity.regular(regular, {os.getuid()}))
            link = root / 'link'
            link.symlink_to(regular)
            with self.assertRaisesRegex(RuntimeError, 'unsafe-identity-file'):
                identity.regular(link, {os.getuid()})
            hardlink = root / 'hardlink'
            os.link(regular, hardlink)
            with self.assertRaisesRegex(RuntimeError, 'unsafe-identity-file'):
                identity.regular(regular, {os.getuid()})


if __name__ == '__main__':
    unittest.main()
