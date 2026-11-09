"""Internal guest recipe and proof: native parent-VM student CLI + VPC Provisioning Essentials (#550).

Python 3.12 stdlib, Ubuntu 24.04 amd64 guest only, self-contained (imports no sibling). Not a student
command, wrapper, service, RBAC design or image build step. The private-clone host stages this file, the
unchanged ``install-kubectl-fabric.py`` + ``hhfab_release.py``, the pinned public hhfctl archive and the three
pinned jq packages into an exclusive root-private ``/run/labapp-student-pilot`` and runs ``run`` once as root.

``run`` (root): preflight -> packages (offline dpkg of exactly the pinned jq/libjq1/libonig5) -> plugin (the
unchanged pinned installer) -> ``configure`` (child as the real ``ubuntu`` user: exposes the single real binding
of ``/home/ubuntu/hhfab/vlab/kubeconfig`` as ``~/.kube/config`` with default context ``vlab``, preserving the
cluster/user identity) -> ``accept`` (child as ``ubuntu``, normal HOME/PATH, no KUBECONFIG, no --kubeconfig: the
five Lab Steps of hh-learn 0a62674 VPC Provisioning Essentials v1.0.0 with ordinary kubectl, native
``kubectl fabric`` discovery/help/read-only query and the lesson's kubectl-JSONPath-to-jq pipe) -> bounded
test-owned VPC teardown (harness teardown, NOT a lesson step). Reruns leave equal state unchanged; a conflicting
package, plugin or student config is refused and preserved. There is no rollback after a publication.

Output is ONE closed JSON line (<= 2048 bytes): fixed phase/code vocabulary and fixed counters only; never
config/cert/key/token bytes, kubectl output or arbitrary guest strings. The lesson has no server attachment,
dataplane or GUI step; this proves control-plane reconciliation only. Importing performs no IO.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types

PAYLOAD = Path('/run/labapp-student-pilot')
USER, HOME = 'ubuntu', Path('/home/ubuntu')
SOURCE_KUBECONFIG = HOME / 'hhfab/vlab/kubeconfig'
TARGET_DIR = HOME / '.kube'
TARGET = TARGET_DIR / 'config'
KUBECTL, PLUGIN, JQ = '/usr/local/bin/kubectl', '/usr/local/bin/kubectl-fabric', '/usr/bin/jq'
PYTHON, DPKG, DPKG_QUERY = '/usr/bin/python3', '/usr/bin/dpkg', '/usr/bin/dpkg-query'
KUBECTL_PIN = (58597560, 'a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989')
API_SERVER = 'https://127.0.0.1:6443'
CONTEXT = 'vlab'

# Fixed public inputs (name, size, sha256). The hhfctl pin is the installer's; the jq pins were observed from the
# signed Ubuntu snapshot 20261024T000000Z InRelease. The host re-verifies all of them before and during staging.
ARCHIVE = ('hhfctl-linux-amd64-v0.96.2.tar.gz', 13620070,
           '379b7ae4210f766fab733024bbb3313333135bfbde04ecf1bdf1d38e735aabca')
DEBS = (('libonig5_6.9.9-1build1_amd64.deb', 172336,
         '605f42287d2bcb6c84f5a02377c7cd777090c5e857259a4030a571989f19dde2', 'libonig5', '6.9.9-1build1'),
        ('libjq1_1.7.1-3ubuntu0.24.04.2_amd64.deb', 141902,
         '078fbf38b2e7c3f24cc5dc894d1bb03b617894b887a6e13d5943e13818e724f3', 'libjq1', '1.7.1-3ubuntu0.24.04.2'),
        ('jq_1.7.1-3ubuntu0.24.04.2_amd64.deb', 65694,
         'f59183392f84fe67b407b494d8ba6185e9b0e4a106ffcb369490bd20a83fd40e', 'jq', '1.7.1-3ubuntu0.24.04.2'))
CACHE_PINS = tuple([ARCHIVE] + [d[:3] for d in DEBS])
SOURCE_NAMES = ('student_vpc_pilot.py', 'install-kubectl-fabric.py', 'hhfab_release.py')
LIBC_MINIMUM = '2.39'

# Finite assumptions, NOT measured fit. The host caps the whole pilot (transfer + staging + this run) at 240 s inside
# the original access window (#550), so this guest run is deliberately SHORTER than that cap: the host's non-run steps
# (10 + 45 + 15 s) plus ``TOTAL_SECONDS`` plus the 10 s margin of the host run cap stay under it. Work phases are
# clipped to the remaining total minus the teardown reserve; the accept child's own total (ACCEPT_SECONDS) is inside
# the root total and itself holds back TEARDOWN_SECONDS for the harness teardown.
TOTAL_SECONDS = 150
TEARDOWN_SECONDS = 20
PREFLIGHT_SECONDS, PACKAGE_SECONDS, PLUGIN_SECONDS, CONFIG_SECONDS = 10, 30, 25, 15
ACCEPT_MARGIN_SECONDS = 5      # child startup/report/closure margin inside the original root work clock
ACCEPT_SECONDS = TOTAL_SECONDS - TEARDOWN_SECONDS - ACCEPT_MARGIN_SECONDS  # maximum, never a fresh parent budget
AGENT_WAIT_SECONDS, AGENT_POLL_SECONDS = 60, 5  # declared new inner maximum; always clipped below
FINAL_WORK_SECONDS = 20       # keep lesson-end native queries out of the agent-wait allocation
CALL_SECONDS = 15
CHILD_CLOSE_SECONDS = 3.0      # owned_process final reap + group-convergence budget per child
OUTPUT_LIMIT = 2048
KUBE_LIMIT = 1 << 20     # the accepted core's known finite 1 MiB allowance; a full seven-agent query is unmeasured
SOURCE_LIMIT = 262144
AGENTS = 7
# Canonical VLAB switch agents of this repo's wiring (wiringd.yaml): exactly these seven names.
AGENT_NAMES = frozenset({'spine-01', 'spine-02', 'leaf-01', 'leaf-02', 'leaf-03', 'leaf-04', 'leaf-05'})
# Accepted immutable process-group closure (#365), already installed in the guest; reused unmodified.
OWNED_PROCESS = Path('/usr/local/lib/labapp/owned_process.py')
OWNED_PROCESS_SHA256 = '873c77d857d62280fbf9202a3544102f83e6cab39de0ddb05cd37107ca56e599'
OWNED_LIMIT = 65536
# Harness-only raw DELETE (NOT a lesson step): preconditions.uid makes the delete atomic with the observed object.
VPC_PATH = '/apis/vpc.githedgehog.com/v1beta1/namespaces/default/vpcs/' + 'webapp-prod'

PHASES = ('preflight', 'packages', 'plugin', 'config', 'accept', 'teardown', 'done')
CODES = ('ok', 'refused', 'conflict', 'timeout', 'failed', 'cancelled', 'uncertain')
PACKAGE_RESULTS = ('-', 'installed', 'unchanged')
PLUGIN_RESULTS = ('-', 'installed', 'unchanged', 'mode-repaired')
CONFIG_RESULTS = ('-', 'installed', 'unchanged')
CLEANUP_RESULTS = ('not-needed', 'removed', 'absent', 'preserved', 'uncertain')
RESULT_KEYS = ('agents', 'capacity', 'cleanup', 'code', 'config', 'packages', 'phase', 'plugin', 'status', 'step',
               'vpc_uid')
# Closed lesson substep last ENTERED by the acceptance child (the failing one on a refusal; '-' when none ran).
# Pre-apply substeps come first; 'manifest' onward are at or after the first possible mutation boundary.
STEPS = ('-', 'binary', 'context', 'contexts', 'plugin', 'fabric', 'jq', 'vpc-absent', 'ipv4-read', 'vlan-read',
         'namespaces', 'conflicts', 'manifest', 'apply', 'post-apply', 'vpc-readback', 'vpc-list',
         'agents-list', 'vpc-describe', 'vpc-yaml', 'vpc-spec', 'agent-detail', 'agents-query',
         'desired-state', 'dhcp-view', 'dhcp-jq', 'fabric-query', 'endstate', 'accept-budget', 'agent-budget')
# Observed capacity booleans only: true/false when actually computed from a parsed read, null when not observed.
CAPACITY_KEYS = ('ipv4_web', 'ipv4_worker', 'no_conflict', 'vlan_web', 'vlan_worker')
CAPACITY_SUBNETS = (('web-servers', 'ipv4_web'), ('worker-nodes', 'ipv4_worker'))

UID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:@-]{0,252}\Z')
# dpkg-query ${db:Status-Abbrev}: desired, status and error flag (any dpkg letter: ii, iU, iF, iHR, rc, un ...).
STATUS_RE = re.compile(r'([a-z ][A-Za-z ][A-Z ])\|([a-z0-9+.-]+)\|(.*)\Z')
ABSENT_RE = re.compile(r'dpkg-query: no packages found matching ([a-z0-9+.-]+)\Z')

ROOT_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'DEBIAN_FRONTEND': 'noninteractive'}
# Ordinary Ubuntu login values for the student identity: HOME, PATH and no KUBECONFIG.
STUDENT_ENV = {'HOME': '/home/ubuntu', 'USER': USER, 'LOGNAME': USER, 'SHELL': '/bin/bash',
               'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}

VPC_NAME = 'webapp-prod'
VPC_YAML = '''apiVersion: vpc.githedgehog.com/v1beta1
kind: VPC
metadata:
  name: webapp-prod
  namespace: default
spec:
  ipv4Namespace: default
  vlanNamespace: default
  subnets:
    web-servers:
      subnet: 10.10.10.0/24
      gateway: 10.10.10.1
      vlan: 1010
    worker-nodes:
      subnet: 10.10.20.0/24
      gateway: 10.10.20.1
      vlan: 1020
      dhcp:
        enable: true
        range:
          start: 10.10.20.10
          end: 10.10.20.250
'''
SUBNETS = {'web-servers': ('10.10.10.0/24', '10.10.10.1', 1010),
           'worker-nodes': ('10.10.20.0/24', '10.10.20.1', 1020)}
DHCP_RANGE = {'start': '10.10.20.10', 'end': '10.10.20.250'}
SLEEP = time.sleep
# Sticky: once a child group could not be positively closed, or a student worker was forcibly stopped, nothing
# further is mutated, torn down or passed in this process; the exact whole-VM disposal owns the rest.
STICKY = []
OWNED = []


class Refused(Exception):
    """Fixed nonsecret message only; never CLI output, config bytes or guest strings."""


class Conflict(Refused):
    pass


class Timeout(Refused):
    def __init__(self, message, *, site=None):
        super().__init__(message)
        self.site = site


class Uncertain(Refused):
    pass


class Coded(Refused):
    """A child's own closed failure code, propagated unchanged."""
    def __init__(self, code):
        super().__init__('child reported a closed failure code')
        self.code = code


class Interrupted(BaseException):
    pass


def require(ok, message='student pilot refused'):
    if not ok:
        raise Refused(message)


def digest(path):
    result = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            result.update(block)
    return result.hexdigest()


def classify(error):
    if isinstance(error, Interrupted):
        return 'cancelled'
    if isinstance(error, Coded):
        return error.code
    for kind, code in ((Conflict, 'conflict'), (Timeout, 'timeout'), (Uncertain, 'uncertain'), (Refused, 'refused')):
        if isinstance(error, kind):
            return code
    return 'failed'


def emit(value):
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')
    sys.stdout.flush()


def _interrupt(_signum, _frame):
    raise Interrupted


def shield():
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, signal.SIG_IGN)


# ------------------------------------------------------------------------------ bounded children --
def run_child(argv, seconds, *, env, limit=65536, stdin=None, account=None):
    """-> (returncode, output, state) with state 'ok'|'timeout'|'overflow'; partial output is kept.

    Own session; the accepted ``owned_process.OwnedGroup`` anchors the group with the unreaped leader, SIGKILLs it,
    reaps once and needs positive ESRCH absence. A closure that is not proven makes the process STICKY uncertain:
    every later child (so any mutation or teardown) is refused. Only this child's own session is covered; a nested
    child a worker started in ITS session is outside it, which is why a forcibly stopped worker is never followed by
    further guest work (see ``run``). ``account`` drops to that real user (uid, gid, supplementary groups) in the child."""
    require_certain()
    owned = load_owned()
    extra = {}
    if account is not None:
        extra = {'user': account.pw_uid, 'group': account.pw_gid,
                 'extra_groups': os.getgrouplist(account.pw_name, account.pw_gid)}
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, cwd='/',
                            start_new_session=True, **extra)
    try:
        group = owned.OwnedGroup(proc)
    except BaseException:
        STICKY.append('unanchored child')
        raise
    output, state = bytearray(), 'ok'
    deadline = time.monotonic() + seconds
    try:
        pending = memoryview(stdin) if stdin else None
        os.set_blocking(proc.stdout.fileno(), False)
        if proc.stdin is not None:
            os.set_blocking(proc.stdin.fileno(), False)
        exited = False
        with selectors.DefaultSelector() as select:
            select.register(proc.stdout, selectors.EVENT_READ)
            if pending:
                select.register(proc.stdin, selectors.EVENT_WRITE)
            elif proc.stdin is not None:
                proc.stdin.close()
            while select.get_map() and state == 'ok':
                if group.status() is not None:
                    # The leader (still unreaped, so it anchors the group) exited: no descendant may keep the pipe
                    # open. The group is closed below and already-written output is drained afterwards.
                    exited = True
                    break
                left = deadline - time.monotonic()
                if left <= 0:
                    state = 'timeout'
                    break
                for key, _ in select.select(min(left, .2)):
                    if key.fileobj is proc.stdin:
                        try:
                            pending = pending[os.write(proc.stdin.fileno(), pending):]
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            pending = b''
                        if not pending:
                            select.unregister(proc.stdin)
                            proc.stdin.close()
                        continue
                    try:
                        block = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not block:
                        select.unregister(key.fileobj)
                    elif len(output) + len(block) > limit:
                        output.extend(block[:max(0, limit - len(output))])
                        state = 'overflow'
                        break
                    else:
                        output.extend(block)
        while state == 'ok' and not exited:   # non-reaping completion observation; the leader stays the group anchor
            if group.status() is not None:
                break
            if time.monotonic() >= deadline:
                state = 'timeout'
            else:
                time.sleep(.01)
    except owned.OwnershipUncertain:
        raise Uncertain('child ownership could not be shown') from None
    finally:
        primary = sys.exc_info()[0] is not None
        try:
            closed = group.close(0, CHILD_CLOSE_SECONDS)   # SIGKILL while anchored, one reap, positive ESRCH absence
        except BaseException:
            closed = False
        if not closed:
            STICKY.append('child group not proven closed')
        elif state == 'ok' and not primary:
            state = drain(proc.stdout, output, limit)
        for pipe in (proc.stdin, proc.stdout):
            try:
                if pipe is not None:
                    pipe.close()
            except OSError:
                pass
        if not closed and not primary:
            raise Uncertain('child group was not proven closed')
    return proc.returncode, bytes(output), state


def drain(stream, output, limit):
    """Read what a closed group left in the pipe (writers are gone, so EOF or EAGAIN ends it)."""
    while True:
        try:
            block = os.read(stream.fileno(), 65536)
        except OSError:
            return 'ok'
        if not block:
            return 'ok'
        if len(output) + len(block) > limit:
            output.extend(block[:max(0, limit - len(output))])
            return 'overflow'
        output.extend(block)


def require_certain():
    if STICKY:
        raise Uncertain('an earlier child was not proven closed')


def load_owned():
    """The accepted immutable owned_process.py (#365): size/owner/mode checked, SHA256 pinned, executed from the
    exact bytes that were hashed. Never modified or copied; no sibling import."""
    if OWNED:
        return OWNED[0]
    info = regular(OWNED_PROCESS, owner=0, limit=OWNED_LIMIT, private=False)
    require(not info.st_mode & 0o022, 'process closure module is writable')
    raw = OWNED_PROCESS.read_bytes()
    require(len(raw) <= OWNED_LIMIT and hashlib.sha256(raw).hexdigest() == OWNED_PROCESS_SHA256,
            'process closure module does not match the pin')
    module = types.ModuleType('owned_process')
    exec(compile(raw, str(OWNED_PROCESS), 'exec'), module.__dict__)
    OWNED.append(module)
    return module


class Clock:
    """Monotonic budget; ``reserve`` is held back for the teardown that must still run."""
    def __init__(self, seconds, reserve=0, *, deadline=None, site=None):
        self.end, self.reserve = time.monotonic() + seconds, reserve
        if deadline is not None:
            self.end = min(self.end, deadline)
        self.site = site

    def left(self):
        left = self.end - time.monotonic() - self.reserve
        if left <= 0:
            raise Timeout('pilot budget exhausted', site=self.site)
        return left


def parse_json(raw):
    try:
        value = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError, RecursionError):
        raise Refused('unparseable JSON') from None
    require(isinstance(value, dict), 'JSON shape')
    return value


# ------------------------------------------------------------------------------ identity / files ----
def account():
    try:
        user = pwd.getpwnam(USER)
    except KeyError:
        raise Refused('ubuntu identity refused') from None
    require(user.pw_uid > 0 and user.pw_dir == str(HOME), 'ubuntu identity refused')
    return user


def student_identity():
    """The calling process IS the real non-root ubuntu user with ordinary HOME/PATH and no kubeconfig override."""
    user = account()
    require(os.geteuid() == user.pw_uid == os.getuid() and os.getegid() == user.pw_gid, 'not the ubuntu identity')
    require(os.environ.get('HOME') == str(HOME) and 'KUBECONFIG' not in os.environ and
            os.environ.get('PATH') == STUDENT_ENV['PATH'], 'student environment refused')
    return user


def regular(path, *, owner, limit, private=True):
    """lstat + fstat identity: single-link regular file of ``owner``, not group/world accessible, bounded."""
    try:
        before = os.lstat(path)
        require(stat.S_ISREG(before.st_mode), 'regular file required')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise Refused('file unavailable') from None
    try:
        info = os.fstat(fd)
    finally:
        os.close(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == owner
            and (info.st_dev, info.st_ino) == (before.st_dev, before.st_ino)
            and not (private and info.st_mode & 0o077) and info.st_size <= limit, 'file identity refused')
    return info


def real_directory(path, *, owner, private):
    try:
        info = os.lstat(path)
    except OSError:
        raise Refused('directory unavailable') from None
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner
            and not info.st_mode & (0o077 if private else 0o022), 'directory identity refused')


def verify_kubectl():
    info = regular(KUBECTL, owner=0, limit=KUBECTL_PIN[0], private=False)
    require(info.st_size == KUBECTL_PIN[0] and not info.st_mode & 0o022 and digest(KUBECTL) == KUBECTL_PIN[1],
            'kubectl does not match the pin')


def verify_payload():
    require(os.geteuid() == 0, 'root required')
    real_directory(PAYLOAD, owner=0, private=True)
    require(Path(__file__).parent == PAYLOAD, 'not run from the staged payload')
    names = {p[0] for p in CACHE_PINS} | set(SOURCE_NAMES)
    require({p.name for p in PAYLOAD.iterdir()} == names, 'payload set refused')
    for name, size, sha in CACHE_PINS:
        info = regular(PAYLOAD / name, owner=0, limit=size)
        require(info.st_size == size and digest(PAYLOAD / name) == sha, 'payload pin mismatch')
    for name in SOURCE_NAMES:
        regular(PAYLOAD / name, owner=0, limit=SOURCE_LIMIT)


def preflight():
    require(os.geteuid() == 0, 'root required')
    release = {}
    for line in Path('/etc/os-release').read_text(encoding='utf-8').splitlines():
        key, _, value = line.partition('=')
        release[key] = value.strip().strip('"')
    require((release.get('ID'), release.get('VERSION_ID')) == ('ubuntu', '24.04') and os.uname().machine == 'x86_64',
            'guest is not Ubuntu 24.04 amd64')
    user = account()
    verify_payload()
    verify_kubectl()
    load_owned()
    require(os.path.isfile('/usr/local/bin/hhfab'), 'hhfab absent')
    real_directory(HOME, owner=user.pw_uid, private=False)
    regular(SOURCE_KUBECONFIG, owner=user.pw_uid, limit=65536)
    return user


# ------------------------------------------------------------------------------ packages ------------
def package_state():
    """-> {package: (status, version)} for the wanted packages plus libc6, parsed COMPLETELY.

    ``status`` is the dpkg abbreviation without padding ('ii', 'iU', 'iF', 'iHR', 'rc' ...). Only DEFINITE absence is
    omitted: dpkg's exact "no packages found" line or an 'un' row without a version. Every requested package must be
    accounted for exactly once and every non-blank line must be understood, otherwise the query is refused."""
    names = [d[3] for d in DEBS] + ['libc6']
    code, out, state = run_child([DPKG_QUERY, '-W', '-f', '${db:Status-Abbrev}|${Package}|${Version}\n', *names],
                                 15, env=ROOT_ENV, limit=8192)
    require(state == 'ok' and code in (0, 1), 'package query failed')
    found, seen = {}, set()
    for line in out.decode('utf-8', 'replace').splitlines():
        if not line.strip():
            continue
        row, absent = STATUS_RE.match(line), ABSENT_RE.match(line)
        name = row.group(2) if row else absent.group(1) if absent else None
        require(name in names and name not in seen, 'package query output refused')
        seen.add(name)
        if row and not (row.group(1).rstrip() == 'un' and not row.group(3)):
            require(row.group(3), 'package query output refused')
            found[name] = (row.group(1).rstrip(), row.group(3))
    require(seen == set(names), 'package query output incomplete')
    return found


def install_packages(clock):
    found = package_state()
    libc = found.get('libc6')
    require(libc is not None and libc[0] == 'ii', 'libc6 state refused')
    code, _, state = run_child([DPKG, '--compare-versions', libc[1], 'ge', LIBC_MINIMUM], 10, env=ROOT_ENV, limit=1024)
    require(state == 'ok' and code == 0, 'libc6 too old for the pinned jq')
    missing = []
    for name, _, _, package, version in DEBS:
        have = found.get(package)
        if have is None:   # definite absence only; every partial/unknown/error state is a conflict below
            missing.append(name)
        elif have != ('ii', version):
            raise Conflict('existing package state conflicts')
    if missing:
        if any(n.startswith('jq_') for n in missing):
            require(not os.path.lexists(JQ), 'jq files exist without the package')
        argv = [DPKG, '--install', '--refuse-downgrade', *[str(PAYLOAD / n) for n in missing]]
        code, _, state = run_child(argv, min(PACKAGE_SECONDS, clock.left()), env=ROOT_ENV, limit=65536)
        if state == 'timeout':
            raise Uncertain('package installation timed out')
        require(state == 'ok' and code == 0, 'package installation failed')
        after = package_state()
        require(all(after.get(d[3]) == ('ii', d[4]) for d in DEBS), 'package state not verified after install')
        return 'installed'
    return 'unchanged'


# ------------------------------------------------------------------------------ plugin ---------------
def install_plugin(clock):
    argv = [PYTHON, '-B', str(PAYLOAD / 'install-kubectl-fabric.py'), '--version', '0.96.2',
            '--platform', 'linux/amd64', '--archive', str(PAYLOAD / ARCHIVE[0])]
    code, out, state = run_child(argv, min(PLUGIN_SECONDS, clock.left()), env=ROOT_ENV, limit=8192)
    if state == 'timeout':
        raise Uncertain('plugin installation timed out')
    require(state == 'ok', 'plugin installer output refused')
    if code != 0:
        if b'differs from the archive member' in out:
            raise Conflict('existing kubectl-fabric conflicts')
        raise Refused('plugin installation refused')
    status = None
    for line in out.decode('utf-8', 'replace').splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get('tool') == 'kubectl-fabric':
            status = value.get('status')
    require(status in ('installed', 'unchanged', 'mode-repaired'), 'plugin installer result refused')
    return status


# ------------------------------------------------------------------------------ student config -------
def view_json(path, clock):
    """Native normalized JSON of one kubeconfig file (internal only, never printed)."""
    code, out, state = run_child([KUBECTL, '--kubeconfig', str(path), 'config', 'view', '--raw', '-o', 'json'],
                                 min(10, clock.left()), env=STUDENT_ENV, limit=262144)
    require(state == 'ok' and code == 0, 'kubeconfig view failed')
    return parse_json(out)


def binding(config):
    """The single real VLAB binding of a kubeconfig document: (cluster, user) entries, strictly shaped."""
    require(set(config) <= {'apiVersion', 'kind', 'preferences', 'clusters', 'users', 'contexts', 'current-context'}
            and config.get('apiVersion') == 'v1' and config.get('kind') == 'Config', 'kubeconfig shape refused')
    parts = [config.get(k) for k in ('clusters', 'users', 'contexts')]
    require(all(isinstance(p, list) and len(p) == 1 and isinstance(p[0], dict) for p in parts), 'single binding required')
    (cluster,), (user,), (context,) = parts
    require(set(cluster) == {'name', 'cluster'} and set(user) == {'name', 'user'} and set(context) == {'name', 'context'}
            and isinstance(cluster['cluster'], dict) and isinstance(user['user'], dict)
            and isinstance(context['context'], dict), 'binding entries refused')
    require(set(cluster['cluster']) == {'server', 'certificate-authority-data'}
            and set(user['user']) == {'client-certificate-data', 'client-key-data'}
            and cluster['cluster']['server'] == API_SERVER, 'binding identity refused')
    require(all(isinstance(v, str) and v for v in (*cluster['cluster'].values(), *user['user'].values())),
            'binding credentials refused')
    require(all(isinstance(n, str) and NAME_RE.fullmatch(n) for n in (cluster['name'], user['name'], context['name']))
            and set(context['context']) <= {'cluster', 'user', 'namespace'}
            and context['context'].get('cluster') == cluster['name'] and context['context'].get('user') == user['name']
            and config.get('current-context') == context['name'], 'binding references refused')
    return cluster, user


def student_candidate(config):
    cluster, user = binding(config)
    return {'apiVersion': 'v1', 'kind': 'Config', 'preferences': {}, 'clusters': [cluster], 'users': [user],
            'contexts': [{'name': CONTEXT, 'context': {'cluster': cluster['name'], 'user': user['name']}}],
            'current-context': CONTEXT}


def configure(clock):
    """Child as ubuntu. -> 'installed' | 'unchanged'; a conflicting existing config is Conflict and untouched."""
    user = student_identity()
    verify_kubectl()
    regular(SOURCE_KUBECONFIG, owner=user.pw_uid, limit=65536)
    real_directory(HOME, owner=user.pw_uid, private=False)
    candidate = student_candidate(view_json(SOURCE_KUBECONFIG, clock))
    if os.path.lexists(TARGET_DIR):
        real_directory(TARGET_DIR, owner=user.pw_uid, private=False)
    else:
        os.mkdir(TARGET_DIR, 0o700)
    stage = Path(tempfile.mkdtemp(prefix='.student-pilot-stage-', dir=TARGET_DIR))
    try:
        staged = stage / 'config'
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(json.dumps(candidate, indent=2, sort_keys=True) + '\n')   # JSON is valid kubeconfig YAML
            stream.flush()
            os.fsync(stream.fileno())
        wanted = view_json(staged, clock)
        if os.path.lexists(TARGET):
            regular(TARGET, owner=user.pw_uid, limit=65536)
            if view_json(TARGET, clock) != wanted:
                raise Conflict('existing student kubeconfig conflicts')
            return 'unchanged'
        try:
            os.link(staged, TARGET)   # no-clobber publication; the commit point
        except FileExistsError:
            raise Conflict('student kubeconfig appeared concurrently') from None
        os.unlink(staged)   # single link before the identity check
        regular(TARGET, owner=user.pw_uid, limit=65536)
        if view_json(TARGET, clock) != wanted:
            raise Uncertain('published student kubeconfig failed verification')
        return 'installed'
    finally:
        primary = sys.exc_info()[0] is not None
        try:
            shutil.rmtree(stage)
        except OSError:
            if not primary:
                raise Uncertain('owned stage cleanup failed') from None


# ------------------------------------------------------------------------------ lesson (ubuntu) ------
def kube(args, clock, *, seconds=CALL_SECONDS, ok=(0,)):
    """Ordinary ``kubectl`` through PATH with the default context (no --kubeconfig/--context)."""
    code, out, state = run_child(['kubectl', *args], min(seconds, clock.left()), env=STUDENT_ENV, limit=KUBE_LIMIT)
    if state == 'timeout':
        raise Timeout('kubectl call timed out')
    require(state == 'ok', 'kubectl output bound')
    require(code in ok, 'kubectl call refused')
    clock.left()  # a positive response/child closure cannot outlive its original clock
    return code, out


def kube_json(args, clock):
    return parse_json(kube(args, clock)[1])


def items(document):
    value = document.get('items')
    require(isinstance(value, list) and all(isinstance(i, dict) for i in value), 'list shape')
    return value


def vpc_spec_ok(obj):
    """The exact requested default/webapp-prod spec (extra controller-defaulted fields are tolerated)."""
    spec = obj.get('spec') if isinstance(obj, dict) else None
    if not isinstance(spec, dict) or spec.get('ipv4Namespace') != 'default' or spec.get('vlanNamespace') != 'default':
        return False
    subnets = spec.get('subnets')
    if not isinstance(subnets, dict) or set(subnets) != set(SUBNETS):
        return False
    for name, (cidr, gateway, vlan) in SUBNETS.items():
        entry = subnets[name]
        if not isinstance(entry, dict) or (entry.get('subnet'), entry.get('gateway')) != (cidr, gateway) \
                or entry.get('vlan') != vlan or type(entry.get('vlan')) is not int:
            return False
    if (subnets['web-servers'].get('dhcp') or {}).get('enable'):
        return False
    dhcp = subnets['worker-nodes'].get('dhcp')
    return isinstance(dhcp, dict) and dhcp.get('enable') is True and dhcp.get('range') == DHCP_RANGE


def agents_state(document):
    """-> (agent count, all APPLIEDG == CURRENTG with Applied=True). Exactly seven agents are required."""
    agents = items(document)
    names = [(a.get('metadata') or {}).get('name') if isinstance(a.get('metadata'), dict) else None for a in agents]
    good = len(set(names)) == len(names) and set(names) == AGENT_NAMES
    for agent in agents:
        meta, status = agent.get('metadata'), agent.get('status')
        if not isinstance(meta, dict) or not isinstance(status, dict):
            return len(agents), False
        generation, applied = meta.get('generation'), status.get('lastAppliedGen')
        conditions = status.get('conditions')
        flags = [c.get('status') for c in conditions if isinstance(c, dict) and c.get('type') == 'Applied'] \
            if isinstance(conditions, list) else []
        good = good and type(generation) is int and generation == applied and flags == ['True']
    return len(agents), good and len(agents) == AGENTS


def cidr_conflict(document):
    wanted = [ipaddress.ip_network(c[0]) for c in SUBNETS.values()]
    vlans = {c[2] for c in SUBNETS.values()}
    for vpc in items(document):
        spec = vpc.get('spec') if isinstance(vpc.get('spec'), dict) else {}
        for entry in (spec.get('subnets') or {}).values():
            if not isinstance(entry, dict):
                continue
            try:
                network = ipaddress.ip_network(entry.get('subnet'))
            except (ValueError, TypeError):
                continue
            if spec.get('ipv4Namespace') == 'default' and any(network.overlaps(w) for w in wanted):
                return True
            if spec.get('vlanNamespace') == 'default' and entry.get('vlan') in vlans:
                return True
    return False


def ipv4_capacity(ipv4):
    """-> {'ipv4_web': bool, 'ipv4_worker': bool} actually computed from the parsed object, or None if malformed."""
    try:
        have = [ipaddress.ip_network(s) for s in ((ipv4.get('spec') or {}).get('subnets') or [])]
        return {key: any(ipaddress.ip_network(SUBNETS[name][0]).subnet_of(h) for h in have)
                for name, key in CAPACITY_SUBNETS}
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def vlan_capacity(vlan):
    """-> {'vlan_web': bool, 'vlan_worker': bool} actually computed from the parsed object, or None if malformed."""
    try:
        ranges = [(r['from'], r['to']) for r in ((vlan.get('spec') or {}).get('ranges') or [])]
        return {key.replace('ipv4', 'vlan'): any(lo <= SUBNETS[name][2] <= hi for lo, hi in ranges)
                for name, key in CAPACITY_SUBNETS}
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def namespaces_ok(ipv4, vlan):
    have_ipv4, have_vlan = ipv4_capacity(ipv4), vlan_capacity(vlan)
    return have_ipv4 is not None and have_vlan is not None and all(have_ipv4.values()) and all(have_vlan.values())


def capacity_valid(value):
    """Closed shape of the diagnostic booleans: exactly the five keys, each true, false or null (unobserved)."""
    return (isinstance(value, dict) and set(value) == set(CAPACITY_KEYS)
            and all(v is None or type(v) is bool for v in value.values()))


def observe(clock):
    """-> None (definitely absent) or the present object's UID (a string, possibly not a valid UID -> refused)."""
    _, out = kube(['get', 'vpc', VPC_NAME, '-o', 'json', '--ignore-not-found'], clock)
    if not out.strip():
        return None
    uid = (parse_json(out).get('metadata') or {}).get('uid')
    require(isinstance(uid, str) and UID_RE.fullmatch(uid), 'observed UID refused')
    return uid


def remove_owned(uid, clock, work):
    """HARNESS teardown (not a lesson step) of ONLY the VPC whose UID the successful create response gave.

    -> 'removed' | 'absent' | 'preserved' | 'uncertain'. With no known UID nothing is read or deleted ('uncertain').
    The delete is one native ``kubectl delete --raw`` whose DeleteOptions carry ``preconditions.uid``, so the API
    server refuses it atomically if the name was replaced after the observation; it is never a name-only delete."""
    if uid is None:
        return 'uncertain'
    try:
        seen = observe(clock)
        if seen is None:
            return 'absent'
        if seen != uid:
            return 'preserved'
        body = Path(work) / 'delete-options.json'
        fd = os.open(body, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(json.dumps({'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid}},
                                    sort_keys=True))
        accepted = True
        try:
            kube(['delete', '--raw', VPC_PATH, '-f', str(body)], clock, seconds=20)
        except Timeout:
            return 'uncertain'
        except Refused:
            accepted = False   # precondition refusal or transport failure: decided by the observation below
        while True:
            seen = observe(clock)
            if seen is None:
                return 'removed' if accepted else 'absent'   # a refused delete never claims the removal
            if seen != uid:
                return 'preserved'   # the name now belongs to something else; it was not touched
            try:
                clock.left()
            except Timeout:
                return 'uncertain'
            SLEEP(1)
    except Refused:
        return 'uncertain'


def lesson(clock, state):
    """The five Lab Steps. ``state['uid']``/``['agents']`` are published as soon as they are known."""
    # Native discovery and the source-supported read-only checks (no cluster state is changed).
    # ``state['step']``/``state['capacity']`` are fixed closed diagnostics only (no messages, CLI or config output).
    state['step'] = 'binary'
    require(shutil.which('kubectl', path=STUDENT_ENV['PATH']) == KUBECTL, 'kubectl is not the pinned native binary')
    verify_kubectl()
    state['step'] = 'context'
    require(kube(['config', 'current-context'], clock)[1].decode().strip() == CONTEXT, 'default context is not vlab')
    state['step'] = 'contexts'
    require(kube(['config', 'get-contexts', '-o', 'name'], clock)[1].decode().split() == [CONTEXT], 'single context required')
    state['step'] = 'plugin'
    require(PLUGIN in kube(['plugin', 'list'], clock)[1].decode('utf-8', 'replace').split(), 'plugin not discovered')
    state['step'] = 'fabric'
    kube(['fabric', '--help'], clock)
    require(kube(['fabric', '--version'], clock)[1].strip(), 'fabric version was empty')
    # The signed Ubuntu 1.7.1-3ubuntu0.24.04.2 package reports its binary as "jq-1.7" (confirmed native check).
    state['step'] = 'jq'
    code, out, _ = run_child(['jq', '--version'], min(10, clock.left()), env=STUDENT_ENV, limit=256)
    require(code == 0 and re.fullmatch(rb'jq-1\.7\n?', out), 'jq is not the pinned version')
    # Refuse conflicts before mutating: preexisting webapp-prod, missing namespaces, overlapping CIDR/VLAN.
    state['step'] = 'vpc-absent'
    require(not kube(['get', 'vpc', VPC_NAME, '-o', 'name', '--ignore-not-found'], clock)[1].strip(), 'webapp-prod preexists')
    capacity = state.setdefault('capacity', dict.fromkeys(CAPACITY_KEYS))
    state['step'] = 'ipv4-read'
    ipv4 = kube_json(['get', 'ipv4namespace', 'default', '-o', 'json'], clock)
    capacity.update(ipv4_capacity(ipv4) or {})
    state['step'] = 'vlan-read'
    vlan = kube_json(['get', 'vlannamespace', 'default', '-o', 'json'], clock)
    capacity.update(vlan_capacity(vlan) or {})
    state['step'] = 'namespaces'
    require(namespaces_ok(ipv4, vlan), 'default namespaces cannot hold the lesson VPC')
    state['step'] = 'conflicts'
    conflict = cidr_conflict(kube_json(['get', 'vpcs', '-o', 'json'], clock))
    capacity['no_conflict'] = not conflict
    if conflict:
        raise Conflict('lesson CIDR or VLAN already in use')
    # Step 1: write and check the manifest.
    state['step'] = 'manifest'
    work = Path(tempfile.mkdtemp(prefix='labapp-student-pilot-'))
    state['work'] = work
    manifest = work / 'webapp-prod-vpc.yaml'
    fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(VPC_YAML)
    text = manifest.read_text(encoding='utf-8')
    require(text == VPC_YAML and text.count('subnet:') == 2, 'manifest check failed')
    # Step 2: apply and confirm creation.
    # The same lesson action as ``kubectl apply -f``; ``-o json`` returns its successful mutation response.
    # Root must exclude competing writers of webapp-prod in this private-VM pilot (normal Fabric reconciliation
    # continues). Absence preflight plus this response establishes ownership only under that operational assumption:
    # apply itself is not creation proof under concurrent writers, and work.lock is not a Kubernetes writer lock.
    # An ambiguous/unproven response leaves the UID unknown; the object is never adopted or deleted.
    state['step'] = 'apply'
    state['attempted'] = True
    _, applied = kube(['apply', '-f', str(manifest), '-o', 'json'], clock)
    created = parse_json(applied)
    meta = created.get('metadata') if isinstance(created.get('metadata'), dict) else {}
    uid = meta.get('uid')
    require(created.get('kind') == 'VPC' and meta.get('name') == VPC_NAME and meta.get('namespace') == 'default'
            and isinstance(uid, str) and UID_RE.fullmatch(uid) and meta.get('generation') == 1
            and vpc_spec_ok(created), 'apply response did not prove a created VPC')
    state['uid'] = uid
    state['step'] = 'post-apply'
    emit({'event': 'uid', 'uid': uid})
    state['step'] = 'vpc-readback'
    obj = kube_json(['get', 'vpc', VPC_NAME, '-o', 'json'], clock)
    require((obj.get('metadata') or {}).get('uid') == uid, 'created VPC was replaced')
    state['step'] = 'vpc-list'
    kube(['get', 'vpcs'], clock)
    state['step'] = 'agents-list'
    kube(['get', 'agents'], clock)
    # Step 3: inspect.
    state['step'] = 'vpc-describe'
    described = kube(['describe', 'vpc', VPC_NAME], clock)[1].decode('utf-8', 'replace')
    require(all(t in described for t in (VPC_NAME, '10.10.10.0/24', '10.10.20.0/24', '1010', '1020')), 'describe refused')
    state['step'] = 'vpc-yaml'
    kube(['get', 'vpc', VPC_NAME, '-o', 'yaml'], clock)
    state['step'] = 'vpc-spec'
    require(vpc_spec_ok(kube_json(['get', 'vpc', VPC_NAME, '-o', 'json'], clock)), 'VPC spec differs from the request')
    # Step 4: reconciliation through all seven agents.
    state['step'] = 'agents-list'
    kube(['get', 'agents'], clock)
    state['step'] = 'agent-detail'
    require(b'conditions:' in kube(['get', 'agent', 'leaf-01', '-o', 'yaml'], clock)[1], 'leaf-01 conditions absent')
    wait = Clock(min(AGENT_WAIT_SECONDS, clock.left() - FINAL_WORK_SECONDS), site='agent-budget')
    # This window is clipped once and every boundary checks BOTH clocks.
    poll_clock = types.SimpleNamespace(left=lambda: min(clock.left(), wait.left()))
    streak = 0
    while True:
        poll_clock.left()
        state['step'] = 'agents-query'
        count, good = agents_state(kube_json(['get', 'agents', '-o', 'json'], poll_clock))
        poll_clock.left()
        require(count == AGENTS, 'agent count is not seven')
        state['agents'] = count
        streak = streak + 1 if good else 0
        if streak >= 2:
            poll_clock.left()
            break
        SLEEP(min(AGENT_POLL_SECONDS, poll_clock.left()))
        poll_clock.left()
    # Step 5: desired versus applied state; the lesson's kubectl JSONPath piped to jq.
    state['step'] = 'desired-state'
    kube(['get', 'vpc', VPC_NAME, '-o', 'yaml'], clock)
    state['step'] = 'dhcp-view'
    _, path = kube(['get', 'vpc', VPC_NAME, '-o', "jsonpath={.spec.subnets.worker-nodes.dhcp}"], clock)
    state['step'] = 'dhcp-jq'
    code, piped, pstate = run_child(['jq', '.'], min(10, clock.left()), env=STUDENT_ENV, limit=4096, stdin=path or b'null')
    require(pstate == 'ok' and code == 0, 'jq pipe failed')
    clock.left()
    dhcp = parse_json(piped)
    require(dhcp.get('enable') is True and dhcp.get('range') == DHCP_RANGE, 'jq DHCP view differs')
    state['step'] = 'fabric-query'
    require(kube(['fabric', 'switch', 'ip', '--name', 'leaf-01'], clock)[1].strip(), 'read-only fabric query was empty')
    # End-state checkpoint: the lesson is complete BEFORE (and separately from) the harness teardown.
    state['step'] = 'endstate'
    final = kube_json(['get', 'vpc', VPC_NAME, '-o', 'json'], clock)
    require((final.get('metadata') or {}).get('uid') == state['uid'] and vpc_spec_ok(final), 'end state refused')
    state['endstate'] = True
    clock.left()
    state['step'] = 'post-apply'  # successful final checkpoint retains the unchanged host gate


def accept(deadline=None):
    """Child as ubuntu (`-I -` stdin program). Prints uid/done events only; always tears down what it created."""
    student_identity()
    state = {'uid': None, 'attempted': False, 'agents': 0, 'work': None, 'endstate': False,
             'step': '-', 'capacity': dict.fromkeys(CAPACITY_KEYS)}
    code = 'ok'
    work = Clock(ACCEPT_SECONDS, TEARDOWN_SECONDS, deadline=deadline, site='accept-budget')
    try:
        lesson(work, state)
    except BaseException as error:
        code = classify(error)   # the primary outcome; nothing below may replace it
        if isinstance(error, Timeout) and error.site in ('accept-budget', 'agent-budget'):
            state['step'] = error.site
    shield()
    cleanup = 'not-needed'
    try:
        if state['attempted']:
            # Only the UID from the successful create response is owned; an ambiguous create stays unresolved.
            cleanup = remove_owned(state['uid'], Clock(TEARDOWN_SECONDS), state['work'])
        if state['work'] is not None:
            shutil.rmtree(state['work'], ignore_errors=True)
    except BaseException:
        cleanup = 'uncertain'
    if STICKY and code == 'ok':
        code = 'uncertain'
    # Diagnostics are closed by construction; anything unexpected degrades to the empty form, never a free string.
    step = state['step'] if state['step'] in STEPS else '-'
    capacity = state['capacity'] if capacity_valid(state['capacity']) else dict.fromkeys(CAPACITY_KEYS)
    emit({'event': 'done', 'code': code, 'cleanup': cleanup, 'agents': state['agents'],
          'step': step, 'capacity': capacity})
    return 0


def teardown_only(uid):
    student_identity()
    shield()
    verdict = 'uncertain'
    if uid != '-':
        work = Path(tempfile.mkdtemp(prefix='labapp-student-pilot-'))
        try:
            verdict = remove_owned(uid, Clock(TEARDOWN_SECONDS), work)
        except BaseException:
            verdict = 'uncertain'
        finally:
            shutil.rmtree(work, ignore_errors=True)
    emit({'event': 'done', 'code': 'ok', 'cleanup': verdict, 'agents': 0,
          'step': '-', 'capacity': dict.fromkeys(CAPACITY_KEYS)})
    return 0


def configure_main():
    status = configure(Clock(CONFIG_SECONDS))   # signals stay interrupting: a cancelled setup keeps prior state
    emit({'event': 'config', 'status': status})
    return 0


# ------------------------------------------------------------------------------ root orchestration ---
def parse_events(raw):
    """Closed events from a child's output; anything not an exact event is ignored, never echoed."""
    events = {}
    for line in raw.decode('utf-8', 'replace').splitlines():
        if len(line) > 512 or not line.startswith('{'):
            continue
        try:
            value = json.loads(line)
        except ValueError:
            continue
        kind = value.get('event') if isinstance(value, dict) else None
        if kind == 'uid' and set(value) == {'event', 'uid'} and isinstance(value['uid'], str) \
                and UID_RE.fullmatch(value['uid']):
            events['uid'] = value['uid']
        elif kind == 'config' and set(value) == {'event', 'status'} and value['status'] in CONFIG_RESULTS[1:]:
            events['config'] = value['status']
        elif kind == 'done' and set(value) == {'event', 'code', 'cleanup', 'agents', 'step', 'capacity'} \
                and value['code'] in CODES and value['cleanup'] in CLEANUP_RESULTS \
                and isinstance(value['step'], str) and value['step'] in STEPS and capacity_valid(value['capacity']) \
                and type(value['agents']) is int and 0 <= value['agents'] <= 99:
            events['done'] = value
    return events


def student_child(mode, seconds, source, extra=()):
    user = account()
    code, out, state = run_child([PYTHON, '-I', '-', mode, *extra], seconds, env=STUDENT_ENV, limit=16384,
                                 stdin=source, account=user)
    return code, parse_events(out), state


def run():
    result = {'status': 'failed', 'phase': 'preflight', 'code': 'failed', 'packages': '-', 'plugin': '-',
              'config': '-', 'vpc_uid': '', 'agents': 0, 'cleanup': 'not-needed',
              'step': '-', 'capacity': dict.fromkeys(CAPACITY_KEYS)}
    clock = Clock(TOTAL_SECONDS, TEARDOWN_SECONDS)
    source, unfinished = b'', False
    try:
        source = Path(__file__).read_bytes()
        require(len(source) <= SOURCE_LIMIT, 'source bound')
        preflight()
        result['phase'] = 'packages'
        result['packages'] = install_packages(clock)
        result['phase'] = 'plugin'
        result['plugin'] = install_plugin(clock)
        result['phase'] = 'config'
        code, events, state = student_child('configure', min(CONFIG_SECONDS, clock.left()), source)
        if state != 'ok' or code is None or code < 0:
            STICKY.append('configure worker forcibly stopped')   # its nested kubectl runs in other sessions
            raise Uncertain('configure child did not finish')
        if code != 0 or 'config' not in events:
            raise Conflict('student config refused') if code == 3 else Refused('student config failed')
        result['config'] = events['config']
        result['phase'] = 'accept'
        # Delegate an absolute end inside the ORIGINAL root work clock. Child
        # startup cannot renew it, and the root keeps its original reserve.
        allowance = min(ACCEPT_SECONDS + ACCEPT_MARGIN_SECONDS, clock.left())
        accept_end = min(time.monotonic() + ACCEPT_SECONDS,
                         clock.end - clock.reserve - ACCEPT_MARGIN_SECONDS)
        if accept_end - time.monotonic() <= TEARDOWN_SECONDS:
            result['step'] = 'accept-budget'
            raise Timeout('no acceptance work budget remains')
        unfinished = True
        code, events, state = student_child('accept', allowance, source, (format(accept_end, '.9f'),))
        result['vpc_uid'] = events.get('uid', '')
        done = events.get('done')
        if done is not None:
            result['agents'], result['cleanup'] = done['agents'], done['cleanup']
            result['step'], result['capacity'] = done['step'], done['capacity']   # closed diagnostics; primary code unchanged
        if state != 'ok' or code is None or code < 0:
            # Forcibly stopped worker: its nested kubectl children run in their OWN sessions and may outlive the
            # killed group, so its state is unprovable. Sticky uncertain: no teardown, no further guest mutation,
            # no pass; the existing exact whole-VM disposal owns the rest.
            STICKY.append('acceptance worker forcibly stopped')
            result['cleanup'], unfinished = 'uncertain', False
            raise Uncertain('acceptance child was forcibly stopped')
        if done is None or code != 0:
            raise Uncertain('acceptance child did not finish')
        unfinished = False
        if done['code'] != 'ok':
            raise Coded(done['code'])
        require(done['step'] == 'post-apply' and all(done['capacity'][key] is True for key in CAPACITY_KEYS),
                'student acceptance checks incomplete')
        result['phase'] = 'teardown'
        require(result['cleanup'] == 'removed', 'test-owned VPC was not removed')
        # Preserve the child's primary verdict and safety evidence above. Only
        # otherwise valid success is subject to this ORIGINAL root-clock guard.
        clock.left()
        result['phase'], result['status'], result['code'] = 'done', 'passed', 'ok'
    except BaseException as error:
        result['code'] = classify(error)
    if unfinished and source:
        # The acceptance worker exited by itself (so it closed its own nested children) without its teardown. Only a
        # UID it reported is owned; with none, the possibly-created object is unresolved and never touched.
        shield()
        result['cleanup'] = 'uncertain'
        if result['vpc_uid']:
            try:
                _, events, _ = student_child('teardown', TEARDOWN_SECONDS, source, (result['vpc_uid'],))
                done = events.get('done')
                result['cleanup'] = 'uncertain' if done is None else done['cleanup']
            except BaseException:
                result['cleanup'] = 'uncertain'
    if result['status'] == 'passed' and (result['cleanup'] != 'removed' or STICKY):
        result['status'], result['code'] = 'failed', 'uncertain'
    emit(result)
    return 0   # the closed report is the verdict; a nonzero exit would hide it from the host (crash only)


def main(argv):
    mode = argv[1] if len(argv) > 1 else ''
    extra = argv[2:]
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, _interrupt)
    os.umask(0o077)
    try:
        if mode == 'run' and not extra:
            return run()
        if mode == 'configure' and not extra:
            return configure_main()
        if mode == 'accept' and len(extra) <= 1:
            if not extra:
                return accept()
            if not re.fullmatch(r'[0-9]{1,12}(?:\.[0-9]{1,9})?', extra[0]):
                return 2
            deadline = float(extra[0])
            if deadline > time.monotonic() + ACCEPT_SECONDS:
                return 2
            return accept(deadline)
        if mode == 'teardown' and len(extra) == 1 and (extra[0] == '-' or UID_RE.fullmatch(extra[0])):
            return teardown_only(extra[0])
    except Conflict:
        return 3
    except BaseException:
        return 1
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
