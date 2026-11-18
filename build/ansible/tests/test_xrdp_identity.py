"""Unprivileged main() tests: real OpenSSL, temporary paths, synthetic keygen.

Root/xrdp ownership is modeled through fixture-scoped metadata/chown lookups;
physical file modes/types/link counts and OpenSSL operations remain real. The
native xrdp-keygen boundary uses a real executable child fixture, not a mocked
successful result. No real /etc path, private credential, or root access is used.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HELPER = Path(__file__).resolve().parents[1] / 'roles/host/files/labapp-xrdp-identity.py'
spec = importlib.util.spec_from_file_location('labapp_xrdp_identity', HELPER)
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)
REAL_RUN = subprocess.run
REAL_LSTAT = Path.lstat


class Fixture:
    """Model only privilege/path boundaries, never crypto or main() decisions."""
    def __init__(self):
        self.stack = contextlib.ExitStack()
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.parent = self.root / 'xrdp'
        self.parent.mkdir(mode=0o755)
        self.tls = self.parent / 'instance-tls'
        self.cert, self.key = self.tls / 'cert.pem', self.tls / 'key.pem'
        self.rsa = self.parent / 'rsakeys.ini'
        self.calls = self.root / 'keygen-calls.jsonl'
        self.mode = self.root / 'keygen-mode'
        self.mode.write_text('success')
        self.owners = {}
        self.chowns = []
        self.child = self.root / 'keygen.py'
        self.child.write_text(
            '#!/usr/bin/python3\nimport json,os,pathlib,sys\n'
            f'calls=pathlib.Path({str(self.calls)!r})\n'
            'with calls.open("a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\n'
            f'mode=pathlib.Path({str(self.mode)!r}).read_text()\n'
            'if mode=="failure": sys.exit(23)\n'
            f'target=pathlib.Path({str(self.rsa)!r})\n'
            'if mode=="empty": target.touch()\n'
            'elif mode=="success": target.write_bytes(b"synthetic-rdp-key-"+os.urandom(16))\n'
        )
        self.child.chmod(0o755)
        for name, value in (('TLS', self.tls), ('CERT', self.cert),
                            ('KEY', self.key), ('RSA', self.rsa)):
            self.stack.enter_context(patch.object(identity, name, value))
        self.stack.enter_context(patch.object(identity.os, 'geteuid', return_value=0))
        self.stack.enter_context(patch.object(identity.os, 'chown', side_effect=self.chown))
        self.stack.enter_context(patch.object(identity.pwd, 'getpwnam', side_effect=self.user))
        self.stack.enter_context(patch.object(identity.grp, 'getgrnam', side_effect=self.group))
        self.stack.enter_context(patch.object(identity.socket, 'gethostname', return_value='clone-test'))
        self.stack.enter_context(patch.object(Path, 'lstat', lambda path: self.metadata(path)))
        self.stack.enter_context(patch.object(identity.subprocess, 'run', side_effect=self.execute))

    def close(self):
        self.stack.close()

    def local(self, path):
        path = Path(path).absolute()
        if not path.is_relative_to(self.root):
            raise AssertionError('test attempted a path outside its temporary tree')
        return path

    def metadata(self, path):
        result = REAL_LSTAT(path)
        if Path(path).absolute().is_relative_to(self.root):
            fields = list(result)
            fields[4], fields[5] = self.owners.get(Path(path).absolute(), (0, 0))
            return os.stat_result(fields)
        return result

    def chown(self, path, uid, gid):
        path = self.local(path)
        self.chowns.append((path, uid, gid))
        self.owners[path] = (uid, gid)

    @staticmethod
    def user(name):
        if name != 'xrdp':
            raise AssertionError('unexpected account lookup')
        return SimpleNamespace(pw_uid=4242, pw_gid=4243)

    @staticmethod
    def group(name):
        if name != 'ssl-cert':
            raise AssertionError('unexpected group lookup')
        return SimpleNamespace(gr_gid=4244)

    def execute(self, args, **kwargs):
        args = list(args)
        if args[0] == '/usr/bin/xrdp-keygen':
            if args != ['/usr/bin/xrdp-keygen', 'xrdp', 'auto']:
                raise AssertionError('unexpected native keygen invocation')
            args = [sys.executable, str(self.child), *args[1:]]  # Test executable lookup; works on noexec /tmp.
        elif args[0] == '/usr/bin/openssl':
            for option in ('-in', '-keyout', '-out'):
                if option in args:
                    self.local(args[args.index(option) + 1])
        else:
            raise AssertionError('unexpected executable')
        return REAL_RUN(args, **kwargs)

    def main(self, operation):
        with patch.object(identity.sys, 'argv', ['identity', operation]), contextlib.redirect_stdout(io.StringIO()):
            identity.main()

    def keygen_calls(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def spki(self):
        pem = identity.run(['/usr/bin/openssl', 'x509', '-in', str(self.cert), '-pubkey', '-noout'])
        return identity.run(['/usr/bin/openssl', 'pkey', '-pubin', '-outform', 'DER'], pem)


class XrdpIdentityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.addCleanup(self.fixture.close)

    def test_ensure_real_certificate_identity_and_permissions(self):
        f = self.fixture
        f.main('ensure')
        identity.validate_pair()
        subject = identity.run(['/usr/bin/openssl', 'x509', '-in', str(f.cert), '-noout', '-subject', '-nameopt', 'RFC2253'])
        self.assertEqual(subject.strip(), b'subject=CN=labapp-xrdp')
        san = identity.run(['/usr/bin/openssl', 'x509', '-in', str(f.cert), '-noout', '-ext', 'subjectAltName'])
        self.assertEqual(san.splitlines()[-1].strip(), b'DNS:clone-test')
        identity.run(['/usr/bin/openssl', 'x509', '-in', str(f.cert), '-checkend', '31536000', '-noout'])
        for path, mode, owner in ((f.tls, 0o710, (0, 4244)), (f.key, 0o640, (0, 4244)),
                                  (f.cert, 0o644, (0, 0)), (f.rsa, 0o600, (4242, 4243))):
            self.assertEqual(stat.S_IMODE(REAL_LSTAT(path).st_mode), mode)
            self.assertEqual(f.owners[path], owner)
            self.assertIn((path, *owner), f.chowns)
        self.assertEqual(f.keygen_calls(), [['xrdp', 'auto']])

    def test_repeat_ensure_keeps_identity_and_does_not_call_keygen(self):
        f = self.fixture
        f.main('ensure')
        before = tuple(path.read_bytes() for path in (f.cert, f.key, f.rsa))
        spki = f.spki()
        f.mode.write_text('failure')
        f.main('ensure')
        self.assertTrue(before == tuple(path.read_bytes() for path in (f.cert, f.key, f.rsa)))
        self.assertTrue(spki == f.spki())
        self.assertEqual(len(f.keygen_calls()), 1)

    def test_seal_removes_only_owned_identity_and_is_repeatable(self):
        f = self.fixture
        sentinel = f.parent / 'unrelated'
        sentinel.write_text('unrelated public fixture')
        f.main('ensure')
        f.main('seal')
        f.main('seal')
        self.assertTrue(all(not path.exists() for path in (f.cert, f.key, f.rsa)))
        self.assertEqual(sentinel.read_text(), 'unrelated public fixture')

    def test_seal_then_ensure_changes_real_public_key(self):
        f = self.fixture
        f.main('ensure')
        first = f.spki()
        f.main('seal')
        f.main('ensure')
        self.assertFalse(first == f.spki())
        self.assertEqual(len(f.keygen_calls()), 2)
        identity.validate_pair()

    def test_incomplete_pair_refused_before_keygen(self):
        f = self.fixture
        f.tls.mkdir(mode=0o710)
        f.cert.write_text('incomplete public certificate fixture')
        with self.assertRaisesRegex(RuntimeError, 'incomplete-identity-pair'):
            f.main('ensure')
        self.assertEqual(f.keygen_calls(), [])
        self.assertTrue(f.cert.exists())
        self.assertFalse(f.key.exists())

    def test_invalid_hostname_refused_before_generation(self):
        f = self.fixture
        for name in ('', '../escape', 'bad\nname', 'a' * 254):
            with self.subTest(name_length=len(name)), patch.object(identity.socket, 'gethostname', return_value=name):
                with self.assertRaisesRegex(RuntimeError, 'invalid-instance-hostname'):
                    f.main('ensure')
        self.assertEqual(f.keygen_calls(), [])
        self.assertFalse(f.key.exists())

    def test_native_keygen_failure_is_not_success(self):
        f = self.fixture
        f.mode.write_text('failure')
        with self.assertRaisesRegex(RuntimeError, 'identity-command-failed'):
            f.main('ensure')
        self.assertEqual(f.keygen_calls(), [['xrdp', 'auto']])
        self.assertFalse(f.rsa.exists())
        identity.validate_pair()  # Valid TLS alone did not turn failure into success.

    def test_native_keygen_must_create_nonempty_file(self):
        f = self.fixture
        for mode in ('empty', 'no-output'):
            with self.subTest(mode=mode):
                f.mode.write_text(mode)
                with self.assertRaisesRegex(RuntimeError, 'invalid-rdp-security-key'):
                    f.main('ensure')
                if f.rsa.exists():
                    f.rsa.unlink()
        self.assertEqual(f.keygen_calls(), [['xrdp', 'auto'], ['xrdp', 'auto']])

    def test_unsafe_symlink_refused_without_seal_partial_deletion(self):
        f = self.fixture
        f.main('ensure')
        target = f.root / 'foreign-key'
        target.write_text('unrelated public sentinel')
        f.key.unlink()
        f.key.symlink_to(target)
        for operation in ('ensure', 'seal'):
            with self.subTest(operation=operation), self.assertRaisesRegex(RuntimeError, 'unsafe-identity-file'):
                f.main(operation)
        self.assertTrue(f.cert.exists() and f.rsa.exists() and f.key.is_symlink())
        self.assertEqual(target.read_text(), 'unrelated public sentinel')

    def test_hardlinked_rsa_refused_before_any_seal_deletion(self):
        f = self.fixture
        f.main('ensure')
        os.link(f.rsa, f.root / 'rsa-alias')
        with self.assertRaisesRegex(RuntimeError, 'unsafe-identity-file'):
            f.main('seal')
        self.assertTrue(all(path.exists() for path in (f.cert, f.key, f.rsa)))

    def test_wrong_file_owner_refused_before_deletion(self):
        f = self.fixture
        f.main('ensure')
        f.owners[f.key] = (9999, 9999)
        with self.assertRaisesRegex(RuntimeError, 'unsafe-identity-file'):
            f.main('seal')
        self.assertTrue(all(path.exists() for path in (f.cert, f.key, f.rsa)))

    def test_unsafe_parent_directory_refused(self):
        f = self.fixture
        f.parent.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError, 'unsafe-xrdp-directory'):
            f.main('ensure')
        self.assertFalse(f.tls.exists())
        self.assertEqual(f.keygen_calls(), [])

    def test_symlinked_parent_directory_refused(self):
        f = self.fixture
        f.parent.rmdir()
        elsewhere = f.root / 'elsewhere'
        elsewhere.mkdir()
        f.parent.symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'unsafe-xrdp-directory'):
            f.main('ensure')
        self.assertFalse((elsewhere / 'instance-tls').exists())

    def test_unsafe_identity_directory_refused(self):
        f = self.fixture
        f.tls.mkdir(mode=0o777)
        f.tls.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError, 'unsafe-identity-directory'):
            f.main('ensure')
        self.assertFalse(f.key.exists())

    def test_symlinked_identity_directory_refused(self):
        f = self.fixture
        elsewhere = f.root / 'elsewhere'
        elsewhere.mkdir()
        f.tls.symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'unsafe-identity-directory'):
            f.main('ensure')
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_valid_but_mismatched_certificate_refused(self):
        f = self.fixture
        f.main('ensure')
        other_cert, other_key = f.root / 'other-cert.pem', f.root / 'other-key.pem'
        identity.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                      '-days', '1', '-subj', '/CN=other', '-keyout', str(other_key), '-out', str(other_cert)])
        f.cert.write_bytes(other_cert.read_bytes())
        with self.assertRaisesRegex(RuntimeError, 'identity-pair-mismatch'):
            f.main('ensure')
        self.assertEqual(len(f.keygen_calls()), 1)

    def test_unprivileged_policy_and_invalid_operation_fail_before_writes(self):
        f = self.fixture
        with patch.object(identity.os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(RuntimeError, 'invalid-invocation'):
                f.main('ensure')
        with self.assertRaisesRegex(RuntimeError, 'invalid-invocation'):
            f.main('unexpected')
        self.assertFalse(f.tls.exists())
        self.assertEqual(f.chowns, [])


if __name__ == '__main__':
    unittest.main()
