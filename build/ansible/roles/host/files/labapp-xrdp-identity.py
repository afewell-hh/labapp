#!/usr/bin/python3
"""Manage only XRDP's dedicated clone identity; never touch shared snakeoil."""
import grp
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import tempfile

TLS = Path('/etc/xrdp/instance-tls')
CERT = TLS / 'cert.pem'
KEY = TLS / 'key.pem'
RSA = Path('/etc/xrdp/rsakeys.ini')


def regular(path, owners):
    if not path.exists() and not path.is_symlink():
        return False
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in owners:
        raise RuntimeError('unsafe-identity-file')
    return True


def run(args, data=None):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=15, check=False)
    if result.returncode:
        raise RuntimeError('identity-command-failed')
    return result.stdout


def validate_pair():
    if KEY.stat().st_size == 0 or CERT.stat().st_size == 0:
        raise RuntimeError('empty-identity')
    key_public = run(['/usr/bin/openssl', 'pkey', '-in', str(KEY), '-pubout', '-outform', 'DER'])
    cert_public = run(['/usr/bin/openssl', 'x509', '-in', str(CERT), '-pubkey', '-noout'])
    cert_public = run(['/usr/bin/openssl', 'pkey', '-pubin', '-outform', 'DER'], cert_public)
    run(['/usr/bin/openssl', 'x509', '-in', str(CERT), '-checkend', '0', '-noout'])
    if key_public != cert_public:
        raise RuntimeError('identity-pair-mismatch')


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in ('ensure', 'seal'):
        raise RuntimeError('invalid-invocation')
    uid = pwd.getpwnam('xrdp').pw_uid
    gid = grp.getgrnam('ssl-cert').gr_gid
    parent = TLS.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        raise RuntimeError('unsafe-xrdp-directory')
    if TLS.exists() or TLS.is_symlink():
        info = TLS.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('unsafe-identity-directory')
    elif sys.argv[1] == 'ensure':
        TLS.mkdir(mode=0o710)
    present = [regular(path, {0}) for path in (CERT, KEY)]
    rsa_present = regular(RSA, {0, uid})
    if sys.argv[1] == 'seal':
        # Validate every target before removing any; no following links/shared paths.
        for path, exists in ((CERT, present[0]), (KEY, present[1]), (RSA, rsa_present)):
            if exists:
                path.unlink()
        print('XRDP identity sealed')
        return
    os.chown(TLS, 0, gid)
    TLS.chmod(0o710)
    if any(present) and not all(present):
        raise RuntimeError('incomplete-identity-pair')
    if not any(present):
        name = socket.gethostname()
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', name):
            raise RuntimeError('invalid-instance-hostname')
        # Build privately, then install. Any interrupted partial installation fails closed.
        with tempfile.TemporaryDirectory(prefix='.generate-', dir=TLS) as temp:
            cert, key = Path(temp) / 'cert.pem', Path(temp) / 'key.pem'
            run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-sha256',
                 '-nodes', '-days', '365', '-subj', '/CN=' + name,
                 '-addext', 'subjectAltName=DNS:' + name,
                 '-keyout', str(key), '-out', str(cert)])
            os.chown(key, 0, gid)
            key.chmod(0o640)
            cert.chmod(0o644)
            os.replace(key, KEY)
            os.replace(cert, CERT)
    os.chown(KEY, 0, gid)
    KEY.chmod(0o640)
    os.chown(CERT, 0, 0)
    CERT.chmod(0o644)
    validate_pair()
    if not rsa_present:
        run(['/usr/bin/xrdp-keygen', 'xrdp', 'auto'])
    if not regular(RSA, {0, uid}) or RSA.stat().st_size == 0:
        raise RuntimeError('invalid-rdp-security-key')
    os.chown(RSA, uid, pwd.getpwnam('xrdp').pw_gid)
    RSA.chmod(0o600)
    print('XRDP instance identity ready')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('XRDP identity preparation failed', file=sys.stderr)
        sys.exit(1)
