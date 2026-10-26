"""Bounded Ubuntu 24.04 guest prerequisite probe (Python 3.12 stdlib).

Root only, explicit existing nonroot --owner-uid and absolute --archive. Keep the
unchanged install-hhfab.py and hhfab_release.py siblings. No cwd/env overrides,
network, package installation, user changes or cloud access. Trusted lead must
exclude concurrent changes to payload/archive and /run; never run on production.
The nonroot owner must be dedicated/idle: this is not a hostile multiuser sandbox.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import sys
import tempfile
import uuid

from hhfab_release import PINS, Refusal, bounded, digest

VERSION = "0.50.4"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMD_RUN = "/usr/bin/systemd-run"
PYTHON = "/usr/bin/python3"
# Fixed failure-phase allowlist; STAGE names the action in progress, never child output.
PHASES = ("preflight", "installer", "systemd", "kvm", "cleanup", "unknown")
STAGE = "unknown"
ACTION = "none"
EXECUTION_MOUNT = "none"
# This wrapper drops supplementary groups, then gid/uid before exec; no shell.
DROP = ("import os,sys; uid=int(sys.argv[1]); gid=int(sys.argv[2]); "
        "os.setgroups([]); os.setgid(gid); os.setuid(uid); os.chdir(sys.argv[3]); "
        "os.execve(sys.argv[4],sys.argv[4:], "
        "{'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','HOME':sys.argv[3]})")
KVM = """import os,fcntl
fds=[]
try:
 d=os.open('/dev/kvm',os.O_RDWR|os.O_CLOEXEC); fds.append(d)
 if fcntl.ioctl(d,0xAE00,0)!=12: raise RuntimeError('API')
 v=fcntl.ioctl(d,0xAE01,0); fds.append(v)
 print('root-api12-create-vm')
finally:
 for fd in reversed(fds): os.close(fd)
"""


def stage(name, action="none", execution_mount="none"):
    global STAGE, ACTION, EXECUTION_MOUNT
    previous = STAGE, ACTION, EXECUTION_MOUNT
    STAGE, ACTION, EXECUTION_MOUNT = name, action, execution_mount
    return previous


def installer_action(name):
    global ACTION, EXECUTION_MOUNT
    ACTION = name
    EXECUTION_MOUNT = "unknown" if name == "cli" else "none"


class DiagnosticRefusal(Refusal):
    """Local fixed category; never accepts command output as diagnostic text."""
    def __init__(self, category, message):
        super().__init__(message)
        self.category = category


def failure_category(error):
    if isinstance(error, PermissionError):
        return "permission"
    if isinstance(error, DiagnosticRefusal):
        return error.category
    if isinstance(error, Refusal):
        return {"command timeout": "timeout", "overall work deadline exceeded": "timeout",
                "command output overflow": "overflow",
                "installed binary verification failed": "mismatch",
                "rerun changed binary": "mismatch",
                "installed CLI version mismatch": "mismatch"}.get(str(error), "refusal")
    return "interrupted" if isinstance(error, KeyboardInterrupt) else "operational"


def run(args, seconds=15, limit=4096):
    return bounded(args, seconds, limit=limit, env=ENV)


def require(args, seconds=15, expected=None):
    code, output = run(args, seconds)
    if code:
        raise DiagnosticRefusal("nonzero", "prerequisite command failed")
    if expected is not None and output != expected:
        raise DiagnosticRefusal("mismatch", "prerequisite command output mismatch")
    return output


def preflight(uid, archive):
    if os.geteuid() != 0 or uid <= 0 or sys.version_info < (3, 10):
        raise Refusal("requires root, Python 3.10+ and explicit nonroot owner")
    owner = pwd.getpwuid(uid)
    if owner.pw_gid == 0:
        raise Refusal("owner primary group must be nonroot")
    if Path('/proc/1/comm').read_text().strip() != 'systemd':
        raise Refusal("PID1 is not systemd")
    for tool in (PYTHON, SYSTEMCTL, SYSTEMD_RUN, "/usr/bin/env"):
        if not os.access(tool, os.X_OK):
            raise Refusal("required guest tool missing")
    if not archive.is_absolute() or not stat.S_ISREG(archive.lstat().st_mode):
        raise Refusal("archive must be absolute regular non-symlink file")
    if archive.stat().st_size != PINS[VERSION][0] or digest(archive) != PINS[VERSION][1]:
        raise Refusal("official archive integrity failed")
    return owner


def as_owner(owner, directory, args):
    return [PYTHON, '-I', '-c', DROP, str(owner.pw_uid), str(owner.pw_gid),
            str(directory), *map(str, args)]


def installed_snapshot(binary, uid):
    info = binary.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o755 or info.st_size != PINS[VERSION][2]
            or digest(binary) != PINS[VERSION][3]):
        raise Refusal("installed binary verification failed")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def installer_probe(owner, workspace, archive):
    destination = workspace / 'install'
    installer_action('mkdir')
    destination.mkdir(mode=0o700)
    installer_action('chown')
    os.chown(destination, owner.pw_uid, owner.pw_gid)
    installer = Path(__file__).resolve().with_name('install-hhfab.py')
    args = [PYTHON, str(installer), '--version', VERSION,
            '--install-dir', str(destination), '--archive', str(archive)]
    installer_action('firstinstall')
    require(as_owner(owner, destination, args), 65, b'hhfab install: installed\n')
    binary = destination / 'hhfab'
    installer_action('snapshot-first')
    before = installed_snapshot(binary, owner.pw_uid)
    installer_action('rerun')
    require(as_owner(owner, destination, args), 65, b'hhfab install: unchanged\n')
    installer_action('snapshot-rerun')
    if before != installed_snapshot(binary, owner.pw_uid):
        raise Refusal("rerun changed binary")
    installer_action('cli')
    # Observation only, in this process's actual mount namespace. Failure to observe
    # must not replace or skip the original CLI action. No mount/path text is exported.
    global EXECUTION_MOUNT
    try:
        EXECUTION_MOUNT = "noexec" if os.statvfs(destination).f_flag & os.ST_NOEXEC else "exec"
    except OSError:
        pass
    output = require(as_owner(owner, destination, [str(binary), '--version']), 20)
    if not re.fullmatch(rb'hhfab version v?0\.50\.4\n?', output):
        raise Refusal("installed CLI version mismatch")
    return {'version': VERSION, 'sha256': PINS[VERSION][3], 'mode': '0755',
            'uid': owner.pw_uid, 'gid': owner.pw_gid, 'supplementary_groups': [],
            'rerun': 'unchanged', 'cli': 'passed'}


def unit_properties(unit):
    code, raw = run([SYSTEMCTL, 'show', unit, '--property=LoadState,ActiveState,SubState,Result,ExecMainStatus'])
    props = dict(line.split('=', 1) for line in raw.decode('ascii').splitlines() if '=' in line)
    if code not in (0, 1) or props.get('LoadState') not in ('loaded', 'not-found'):
        raise Refusal('unit state unavailable')
    if code and props.get('LoadState') != 'not-found':
        raise Refusal('unit state unavailable')
    return props


def cleanup_unit(unit):
    # Stop waits for the stop job; reset-failed releases a failed transient unit.
    code, _ = run([SYSTEMCTL, 'stop', unit], 15)
    if code not in (0, 5):
        raise Refusal('owned unit stop failed')
    code, _ = run([SYSTEMCTL, 'reset-failed', unit], 10)
    if code not in (0, 1, 5):
        raise Refusal('owned unit reset failed')
    if unit_properties(unit).get('LoadState') != 'not-found':
        raise Refusal('owned unit still present')


def systemd_probe(workspace):
    token = uuid.uuid4().hex
    unit = 'labapp-prereq-' + token + '.service'
    marker = workspace / 'systemd-marker'
    if unit_properties(unit).get('LoadState') != 'not-found':
        raise Refusal('unit name already exists')
    # Mark ownership before attempting start: a lost reply still requires cleanup.
    try:
        require([SYSTEMD_RUN, '--unit=' + unit, '--collect', '--quiet', '--no-ask-password',
                 '--expand-environment=no',
                 '--property=Type=oneshot', '--property=RemainAfterExit=yes',
                 '--property=TimeoutStartSec=10s', '--property=TimeoutStopSec=5s',
                 '--property=KillMode=control-group', '--property=User=0', '--property=Group=0',
                 '--property=WorkingDirectory=' + str(workspace),
                 '--property=UnsetEnvironment=HOME USER LOGNAME SSH_AUTH_SOCK',
                 '--property=Environment=PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8',
                 '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LANG=C.UTF-8', 'LC_ALL=C.UTF-8',
                 PYTHON, '-I', '-c',
                 "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text(sys.argv[2])",
                 str(marker), token], 20)
        props = unit_properties(unit)
        if any(props.get(k) != v for k, v in {
                'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'exited',
                'Result': 'success', 'ExecMainStatus': '0'}.items()):
            raise Refusal('systemd result mismatch')
        if not marker.is_file() or marker.stat().st_size != 32 or marker.read_text() != token:
            raise Refusal('systemd marker mismatch')
        return {'pid1': 'systemd', 'result': 'success', 'exec_main_status': 0,
                'marker': 'matched', 'cleanup': 'verified-absent'}
    finally:
        # Defer repeated interruption while bounded stop/reset/absence checks run.
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK,
                                          {signal.SIGTERM, signal.SIGINT, signal.SIGALRM})
        # A cleanup failure replaces the original error and is reported as cleanup;
        # a successful cleanup leaves the original failing phase untouched.
        previous = stage('cleanup')
        try:
            cleanup_unit(unit)
            stage(*previous)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


def probe(uid, archive):
    stage('preflight')
    owner = preflight(uid, archive)
    report = {'schema': 'labapp-component-prerequisites-v1', 'caller_uid': os.geteuid(),
              'python': '.'.join(map(str, sys.version_info[:3])), 'checks': {}}
    # Trusted /run parent, root-only namespace; owner gets only its install dir.
    temporary = tempfile.TemporaryDirectory(prefix='labapp-prereq-', dir='/run')
    try:
        workspace = Path(temporary.name)
        workspace.chmod(0o711)
        stage('installer')
        report['checks']['installer'] = installer_probe(owner, workspace, archive)
        stage('systemd')
        report['checks']['systemd'] = systemd_probe(workspace)
        stage('kvm')
        require([PYTHON, '-I', '-c', KVM], 10, b'root-api12-create-vm\n')
        report['checks']['kvm'] = {'uid': 0, 'api_version': 12, 'create_vm': 'passed',
                                   'scope': 'root-device-api-only', 'l2_execution': 'unproven'}
    finally:
        previous = stage('cleanup')
        temporary.cleanup()
        stage(*previous)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--owner-uid', type=int, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    args = parser.parse_args()
    def expired(*_):
        signal.alarm(0)  # Reserve bounded child cleanup after the work deadline.
        raise Refusal('overall work deadline exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(210)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        print(json.dumps(probe(args.owner_uid, args.archive), sort_keys=True))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        # Never export raw child output, exception text or paths.
        print(json.dumps({'schema': 'labapp-component-prerequisites-v1', 'outcome': 'failed',
                          'category': failure_category(error),
                          'phase': STAGE if STAGE in PHASES else 'unknown',
                          'action': ACTION if STAGE == 'installer' else 'none',
                          'execution_mount': EXECUTION_MOUNT if STAGE == 'installer' and ACTION == 'cli' else 'none'}))
        return 1
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    sys.exit(main())
