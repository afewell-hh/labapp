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

# Finite assumptions, not measured fit. Work phases are clipped to the remaining total minus the teardown reserve.
TOTAL_SECONDS = 310
TEARDOWN_SECONDS = 25
PREFLIGHT_SECONDS, PACKAGE_SECONDS, PLUGIN_SECONDS, CONFIG_SECONDS = 15, 45, 45, 25
ACCEPT_SECONDS = 150
AGENT_WAIT_SECONDS, AGENT_POLL_SECONDS = 75, 5
CALL_SECONDS = 30
OUTPUT_LIMIT = 2048
KUBE_LIMIT = 262144
SOURCE_LIMIT = 262144
AGENTS = 7

PHASES = ('preflight', 'packages', 'plugin', 'config', 'accept', 'teardown', 'done')
CODES = ('ok', 'refused', 'conflict', 'timeout', 'failed', 'cancelled', 'uncertain')
PACKAGE_RESULTS = ('-', 'installed', 'unchanged')
PLUGIN_RESULTS = ('-', 'installed', 'unchanged', 'mode-repaired')
CONFIG_RESULTS = ('-', 'installed', 'unchanged')
CLEANUP_RESULTS = ('not-needed', 'removed', 'absent', 'preserved', 'uncertain')
RESULT_KEYS = ('agents', 'cleanup', 'code', 'config', 'packages', 'phase', 'plugin', 'status', 'vpc_uid')

UID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:@-]{0,252}\Z')
STATUS_RE = re.compile(r'([a-z]{2}) ?\|([a-z0-9+.-]+)\|(.*)\Z')

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


class Refused(Exception):
    """Fixed nonsecret message only; never CLI output, config bytes or guest strings."""


class Conflict(Refused):
    pass


class Timeout(Refused):
    pass


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

    Own session; the unreaped leader anchors the group, which is SIGKILLed before the single reap.
    ``account`` drops to that real user (uid, gid, supplementary groups) in the child."""
    extra = {}
    if account is not None:
        extra = {'user': account.pw_uid, 'group': account.pw_gid,
                 'extra_groups': os.getgrouplist(account.pw_name, account.pw_gid)}
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, cwd='/',
                            start_new_session=True, **extra)
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
                if not exited and os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
                    # The leader (still unreaped, so it anchors the group) exited: no descendant may keep the pipe
                    # open. Already-written output is still read before EOF.
                    exited = True
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
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
        while state == 'ok':   # non-reaping completion observation; the leader stays the group anchor
            info = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if info is not None:
                break
            if time.monotonic() >= deadline:
                state = 'timeout'
            else:
                time.sleep(.01)
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        reaped = True
        try:
            proc.wait(timeout=5)
        except BaseException:
            reaped = False
        for pipe in (proc.stdin, proc.stdout):
            try:
                if pipe is not None:
                    pipe.close()
            except OSError:
                pass
        if not reaped and sys.exc_info()[0] is None:
            raise Uncertain('child was not reaped')
    return proc.returncode, bytes(output), state


class Clock:
    """Monotonic budget; ``reserve`` is held back for the teardown that must still run."""
    def __init__(self, seconds, reserve=0):
        self.end, self.reserve = time.monotonic() + seconds, reserve

    def left(self):
        left = self.end - time.monotonic() - self.reserve
        if left <= 0:
            raise Timeout('pilot budget exhausted')
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
    require(os.path.isfile('/usr/local/bin/hhfab'), 'hhfab absent')
    real_directory(HOME, owner=user.pw_uid, private=False)
    regular(SOURCE_KUBECONFIG, owner=user.pw_uid, limit=65536)
    return user


# ------------------------------------------------------------------------------ packages ------------
def package_state():
    """-> {package: (status abbreviation, version)} for the wanted packages plus libc6; absent = missing key."""
    names = [d[3] for d in DEBS] + ['libc6']
    _, out, state = run_child([DPKG_QUERY, '-W', '-f', '${db:Status-Abbrev}|${Package}|${Version}\n', *names],
                              15, env=ROOT_ENV, limit=8192)
    require(state == 'ok', 'package query failed')
    found = {}
    for line in out.decode('utf-8', 'replace').splitlines():
        match = STATUS_RE.match(line)
        if match and match.group(2) in names:
            found[match.group(2)] = (match.group(1), match.group(3))
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
        if have is None or (have[0] == 'un' and not have[1]):
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
    good = True
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


def namespaces_ok(ipv4, vlan):
    wanted = [ipaddress.ip_network(c[0]) for c in SUBNETS.values()]
    try:
        have = [ipaddress.ip_network(s) for s in ((ipv4.get('spec') or {}).get('subnets') or [])]
        ranges = [(r['from'], r['to']) for r in ((vlan.get('spec') or {}).get('ranges') or [])]
    except (ValueError, TypeError, KeyError):
        return False
    return (all(any(w.subnet_of(h) for h in have) for w in wanted)
            and all(any(lo <= v[2] <= hi for lo, hi in ranges) for v in SUBNETS.values()))


def remove_owned(uid, clock):
    """Harness teardown of ONLY the test-owned VPC. -> 'removed' | 'absent' | 'preserved' | 'uncertain'."""
    try:
        _, out = kube(['get', 'vpc', VPC_NAME, '-o', 'json', '--ignore-not-found'], clock)
        if not out.strip():
            return 'absent'
        obj = parse_json(out)
        meta = obj.get('metadata') if isinstance(obj.get('metadata'), dict) else {}
        if uid is None or meta.get('uid') != uid:   # only the actual created UID proves ownership
            return 'preserved'
        kube(['delete', 'vpc', VPC_NAME, '--wait=true', '--timeout=20s'], clock, seconds=30)
        _, out = kube(['get', 'vpc', VPC_NAME, '-o', 'json', '--ignore-not-found'], clock)
        return 'removed' if not out.strip() else 'uncertain'
    except Refused:
        return 'uncertain'


def lesson(clock, state):
    """The five Lab Steps. ``state['uid']``/``['agents']`` are published as soon as they are known."""
    # Native discovery and the source-supported read-only checks (no cluster state is changed).
    require(shutil.which('kubectl', path=STUDENT_ENV['PATH']) == KUBECTL, 'kubectl is not the pinned native binary')
    verify_kubectl()
    require(kube(['config', 'current-context'], clock)[1].decode().strip() == CONTEXT, 'default context is not vlab')
    require(kube(['config', 'get-contexts', '-o', 'name'], clock)[1].decode().split() == [CONTEXT], 'single context required')
    require(PLUGIN in kube(['plugin', 'list'], clock)[1].decode('utf-8', 'replace').split(), 'plugin not discovered')
    kube(['fabric', '--help'], clock)
    code, out, _ = run_child(['jq', '--version'], 10, env=STUDENT_ENV, limit=256)
    require(code == 0 and re.fullmatch(rb'jq-1\.7\.1\n?', out), 'jq is not the pinned version')
    # Refuse conflicts before mutating: preexisting webapp-prod, missing namespaces, overlapping CIDR/VLAN.
    require(not kube(['get', 'vpc', VPC_NAME, '-o', 'name', '--ignore-not-found'], clock)[1].strip(), 'webapp-prod preexists')
    ipv4 = kube_json(['get', 'ipv4namespace', 'default', '-o', 'json'], clock)
    vlan = kube_json(['get', 'vlannamespace', 'default', '-o', 'json'], clock)
    require(namespaces_ok(ipv4, vlan), 'default namespaces cannot hold the lesson VPC')
    if cidr_conflict(kube_json(['get', 'vpcs', '-o', 'json'], clock)):
        raise Conflict('lesson CIDR or VLAN already in use')
    # Step 1: write and check the manifest.
    work = Path(tempfile.mkdtemp(prefix='labapp-student-pilot-'))
    state['work'] = work
    manifest = work / 'webapp-prod-vpc.yaml'
    fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(VPC_YAML)
    text = manifest.read_text(encoding='utf-8')
    require(text == VPC_YAML and text.count('subnet:') == 2, 'manifest check failed')
    # Step 2: apply and confirm creation.
    state['attempted'] = True
    _, applied = kube(['apply', '-f', str(manifest)], clock)
    require(applied.decode('utf-8', 'replace').strip().endswith('created'), 'apply did not create the VPC')
    obj = kube_json(['get', 'vpc', VPC_NAME, '-o', 'json'], clock)
    uid = (obj.get('metadata') or {}).get('uid')
    require(isinstance(uid, str) and UID_RE.fullmatch(uid), 'created UID refused')
    state['uid'] = uid
    emit({'event': 'uid', 'uid': uid})
    kube(['get', 'vpcs'], clock)
    kube(['get', 'agents'], clock)
    # Step 3: inspect.
    described = kube(['describe', 'vpc', VPC_NAME], clock)[1].decode('utf-8', 'replace')
    require(all(t in described for t in (VPC_NAME, '10.10.10.0/24', '10.10.20.0/24', '1010', '1020')), 'describe refused')
    kube(['get', 'vpc', VPC_NAME, '-o', 'yaml'], clock)
    require(vpc_spec_ok(kube_json(['get', 'vpc', VPC_NAME, '-o', 'json'], clock)), 'VPC spec differs from the request')
    # Step 4: reconciliation through all seven agents.
    kube(['get', 'agents'], clock)
    require(b'conditions:' in kube(['get', 'agent', 'leaf-01', '-o', 'yaml'], clock)[1], 'leaf-01 conditions absent')
    wait = Clock(min(AGENT_WAIT_SECONDS, clock.left()))
    streak = 0
    while True:
        count, good = agents_state(kube_json(['get', 'agents', '-o', 'json'], clock))
        require(count == AGENTS, 'agent count is not seven')
        state['agents'] = count
        streak = streak + 1 if good else 0
        if streak >= 2:
            break
        try:
            wait.left()
        except Timeout:
            raise Timeout('agents did not converge') from None
        SLEEP(AGENT_POLL_SECONDS)
    # Step 5: desired versus applied state; the lesson's kubectl JSONPath piped to jq.
    kube(['get', 'vpc', VPC_NAME, '-o', 'yaml'], clock)
    _, path = kube(['get', 'vpc', VPC_NAME, '-o', "jsonpath={.spec.subnets.worker-nodes.dhcp}"], clock)
    code, piped, pstate = run_child(['jq', '.'], min(10, clock.left()), env=STUDENT_ENV, limit=4096, stdin=path or b'null')
    require(pstate == 'ok' and code == 0, 'jq pipe failed')
    dhcp = parse_json(piped)
    require(dhcp.get('enable') is True and dhcp.get('range') == DHCP_RANGE, 'jq DHCP view differs')
    require(kube(['fabric', 'switch', 'ip', '--name', 'leaf-01'], clock)[1].strip(), 'read-only fabric query was empty')


def adopt(clock):
    """UID of a VPC left by an ambiguous apply. Absence was proven just before the apply, so a present object
    that carries exactly the requested spec is the test's own; anything else is never adopted."""
    try:
        _, out = kube(['get', 'vpc', VPC_NAME, '-o', 'json', '--ignore-not-found'], clock)
        obj = parse_json(out) if out.strip() else {}
        uid = (obj.get('metadata') or {}).get('uid')
        return uid if isinstance(uid, str) and UID_RE.fullmatch(uid) and vpc_spec_ok(obj) else None
    except Refused:
        return None


def accept():
    """Child as ubuntu (`-I -` stdin program). Prints uid/done events only; always tears down what it created."""
    student_identity()
    state = {'uid': None, 'attempted': False, 'agents': 0, 'work': None}
    code = 'ok'
    work = Clock(ACCEPT_SECONDS, TEARDOWN_SECONDS)
    try:
        lesson(work, state)
    except BaseException as error:
        code = classify(error)
    shield()
    cleanup = 'not-needed'
    try:
        if state['attempted']:
            owned = Clock(TEARDOWN_SECONDS)
            cleanup = remove_owned(state['uid'] or adopt(owned), owned)
        if state['work'] is not None:
            shutil.rmtree(state['work'], ignore_errors=True)
    except BaseException:
        cleanup = 'uncertain'
    emit({'event': 'done', 'code': code, 'cleanup': cleanup, 'agents': state['agents']})
    return 0


def teardown_only(uid):
    student_identity()
    shield()
    verdict = remove_owned(uid if uid != '-' else None, Clock(TEARDOWN_SECONDS))
    emit({'event': 'done', 'code': 'ok', 'cleanup': verdict, 'agents': 0})
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
        elif kind == 'done' and set(value) == {'event', 'code', 'cleanup', 'agents'} \
                and value['code'] in CODES and value['cleanup'] in CLEANUP_RESULTS \
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
              'config': '-', 'vpc_uid': '', 'agents': 0, 'cleanup': 'not-needed'}
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
        if state != 'ok':
            raise Uncertain('configure child did not finish')
        if code != 0 or 'config' not in events:
            raise Conflict('student config refused') if code == 3 else Refused('student config failed')
        result['config'] = events['config']
        result['phase'] = 'accept'
        unfinished = True
        code, events, state = student_child('accept', min(ACCEPT_SECONDS + 5, clock.left()), source)
        result['vpc_uid'] = events.get('uid', '')
        done = events.get('done')
        if done is not None:
            result['agents'], result['cleanup'] = done['agents'], done['cleanup']
        if state != 'ok' or done is None or code != 0:
            raise Uncertain('acceptance child did not finish')
        unfinished = False
        if done['code'] != 'ok':
            raise Coded(done['code'])
        result['phase'] = 'teardown'
        require(result['cleanup'] == 'removed', 'test-owned VPC was not removed')
        result['phase'], result['status'], result['code'] = 'done', 'passed', 'ok'
    except BaseException as error:
        result['code'] = classify(error)
    if unfinished and source:
        # The acceptance child may have been killed after creating the VPC but before its own teardown.
        shield()
        try:
            _, events, _ = student_child('teardown', TEARDOWN_SECONDS, source, (result['vpc_uid'] or '-',))
            done = events.get('done')
            result['cleanup'] = 'uncertain' if done is None else done['cleanup']
            if result['cleanup'] == 'absent' and not result['vpc_uid']:
                result['cleanup'] = 'not-needed'
        except BaseException:
            result['cleanup'] = 'uncertain'
    if result['status'] == 'passed' and result['cleanup'] != 'removed':
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
        if mode == 'accept' and not extra:
            return accept()
        if mode == 'teardown' and len(extra) == 1 and (extra[0] == '-' or UID_RE.fullmatch(extra[0])):
            return teardown_only(extra[0])
    except Conflict:
        return 3
    except BaseException:
        return 1
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
