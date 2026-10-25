"""Fixed QEMU native-APT data protocol; not a package resolver or policy importer.

Only trusted lead acquisition receipts are accepted. No received configuration is
executed. Limits intentionally cover one small component, not a general mirror.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from hhfab_release import Refusal, digest

BASE = 'ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac'
MAX_FILES, MAX_BYTES, MAX_FILE = 256, 256 * 1024**2, 64 * 1024**2
KEY = Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def identity():
    here = Path(__file__).parent
    return {name: digest(here / name) for name in ('install-qemu.py', 'qemu_offline.py', 'hhfab_release.py')}


def base_id(value):
    if not re.fullmatch(r'(ubuntu@sha256:[a-f0-9]{64}|gce-image:[0-9]{1,20})', value):
        raise Refusal('explicit immutable base identity required')
    return value


def regular(path, limit=MAX_FILE):
    # Incoming trees must be trusted caller-owned and quiescent. Open the final
    # file no-follow/nonblocking; reject replacement/type/size and bound reads.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise Refusal('regular file required')
        if info.st_nlink != 1:
            raise Refusal('single-link regular file required')
        if info.st_size > limit:
            raise Refusal('bounded regular file size exceeded')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(descriptor)
        if len(data) > limit or (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise Refusal('file size/change during read')
        return data
    finally:
        os.close(descriptor)


def parse(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Refusal('duplicate JSON key')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs)
    except (ValueError, RecursionError):
        raise Refusal('invalid bounded JSON') from None


def load(path, limit=16 * 1024**2):
    return parse(regular(path, limit))


def policy_files():
    # Preserve and bind distro config, while explicitly overriding ALL sources,
    # preferences, hooks, proxies, package-cache/solver options in our own APT.
    result = {}
    for path in sorted(Path('/etc/apt').rglob('*')):
        if path.name == 'auth.conf' or 'auth.conf.d' in path.parts:
            continue  # Never read/export credential files; fixed APT ignores them.
        if path.is_dir() and not path.is_symlink():
            continue
        data = regular(path, 1024**2)
        if len(result) >= 128:
            raise Refusal('APT policy inventory limit')
        result[str(path.relative_to('/etc/apt'))] = hashlib.sha256(data).hexdigest()
    return result


def capture(call, base):
    foreign = call(['/usr/bin/dpkg', '--print-foreign-architectures'])
    holds = call(['/usr/bin/apt-mark', 'showhold'])
    audit = call(['/usr/bin/dpkg', '--audit'])
    if foreign.strip() or holds.strip() or audit.strip():
        raise Refusal('foreign architecture, hold or dpkg audit unsupported')
    if call(['/usr/bin/dpkg', '--print-architecture']).strip() != b'amd64':
        raise Refusal('amd64 required')
    status = regular(Path('/var/lib/dpkg/status'), 8 * 1024**2)
    return {'format': 'labapp-qemu-state-v1', 'base': base_id(base), 'module': identity(),
            'status': base64.b64encode(status).decode(), 'architecture': 'amd64',
            'foreign': '', 'holds': '', 'audit': '',
            'selections_sha256': hashlib.sha256(call(['/usr/bin/dpkg', '--get-selections'])).hexdigest(),
            'policy': policy_files(), 'keyring': digest(KEY),
            'apt_config_sha256': hashlib.sha256(call(['/usr/bin/apt-config', 'dump'])).hexdigest(),
            'os_release_sha256': digest(Path('/etc/os-release'))}


def check_state(state, base):
    keys = {'format', 'base', 'module', 'status', 'architecture', 'foreign', 'holds', 'audit',
            'selections_sha256', 'policy', 'keyring', 'apt_config_sha256', 'os_release_sha256'}
    if (not isinstance(state, dict) or set(state) != keys or state['format'] != 'labapp-qemu-state-v1'
            or state['base'] != base_id(base) or state['module'] != identity()
            or state['architecture'] != 'amd64' or any(state[k] != '' for k in ('foreign', 'holds', 'audit'))
            or state['keyring'] != digest(KEY)):
        raise Refusal('target/base/module/trust identity mismatch')
    try:
        status = base64.b64decode(state['status'], validate=True)
    except (ValueError, TypeError):
        raise Refusal('invalid target status') from None
    if not status or len(status) > 8 * 1024**2:
        raise Refusal('target status size')
    return status


def setup(root, snapshot):
    root.chmod(0o755)
    for name in ('lists/partial', 'archives/partial', 'parts', 'preferences'):
        (root / name).mkdir(parents=True, exist_ok=True)
    (root / 'sources.list').write_text(''.join(
        'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] '
        f'https://snapshot.ubuntu.com/ubuntu/{snapshot}/ {suite} main universe\n'
        for suite in ('noble', 'noble-updates', 'noble-security')))
    # APT_CONFIG is read before ambient files; these paths prevent loading them.
    config = root / 'fixed.conf'
    config.write_text(f'Dir::Etc::main "{root}/none";\nDir::Etc::parts "{root}/parts";\n')
    settings = {
        'Dir::Etc::sourcelist': str(root / 'sources.list'), 'Dir::Etc::sourceparts': str(root / 'parts'),
        'Dir::Etc::preferences': str(root / 'preferences/none'),
        'Dir::Etc::preferencesparts': str(root / 'preferences'),
        'Dir::Etc::netrc': str(root / 'none'), 'Dir::Etc::netrcparts': str(root / 'parts'),
        'Dir::State::lists': str(root / 'lists'), 'Dir::Cache::archives': str(root / 'archives'),
        'Dir::Cache::pkgcache': '', 'Dir::Cache::srcpkgcache': '',
        'APT::Architecture': 'amd64', 'APT::Architectures::': 'amd64',
        'Acquire::Retries': '0', 'Acquire::https::Timeout': '15', 'Acquire::GzipIndexes': 'true',
        'DPkg::Lock::Timeout': '10', 'APT::Get::AllowUnauthenticated': 'false',
        'Acquire::AllowInsecureRepositories': 'false', 'Acquire::AllowWeakRepositories': 'false',
        'Acquire::AllowDowngradeToInsecureRepositories': 'false', 'Acquire::Check-Valid-Until': 'true',
        'APT::Get::allow-Downgrades': 'false', 'APT::Get::allow-Change-Held-Packages': 'false'}
    options = [item for key, value in settings.items() for item in ('-o', key + '=' + value)]
    return ['/usr/bin/apt-get', *options], str(config)


def inventory(root):
    result, total = {}, 0
    for directory in ('lists', 'archives'):
        folder = root / directory
        if folder.is_symlink() or not folder.is_dir():
            raise Refusal('bundle data directory required')
        for path in sorted(folder.iterdir()):
            if path.name in ('partial', 'auxfiles'):
                if path.is_symlink() or not path.is_dir() or any(path.iterdir()):
                    raise Refusal('nonempty or unsafe APT working directory')
                continue
            if path.name == 'lock':
                if regular(path, 0) != b'':
                    raise Refusal('invalid lock')
                continue
            valid = (re.fullmatch(r'[A-Za-z0-9_.%+~:-]{1,240}\.deb', path.name) if directory == 'archives'
                     else re.fullmatch(r'[A-Za-z0-9_.%+~:-]{1,240}_(InRelease|Packages(?:\.lz4)?|Translation-en(?:\.lz4)?|Components-[a-z0-9]+\.yml(?:\.gz)?)', path.name))
            if not valid:
                raise Refusal('unexpected bundle filename')
            data = regular(path)
            total += len(data)
            result[directory + '/' + path.name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            if len(result) > MAX_FILES or total > MAX_BYTES:
                raise Refusal('bundle byte/count limit')
    return result


def signatures(root, call):
    releases = sorted((root / 'lists').glob('*_InRelease'))
    expected = {f'snapshot.ubuntu.com_ubuntu_20261024T000000Z_dists_{suite}_InRelease'
                for suite in ('noble', 'noble-updates', 'noble-security')}
    if {p.name for p in releases} != expected:
        raise Refusal('fixed snapshot signed release set required')
    for path in releases:
        call(['/usr/bin/gpgv', '--keyring', str(KEY), str(path)])


def receive(bundle, expected, root, state_base, snapshot, pins, call):
    if bundle.is_symlink() or not bundle.is_dir():
        raise Refusal('bundle directory required')
    data = regular(bundle / 'receipt.json', 16 * 1024**2)
    if not re.fullmatch('[a-f0-9]{64}', expected) or hashlib.sha256(data).hexdigest() != expected:
        raise Refusal('trusted expected receipt mismatch')
    receipt = parse(data)
    if set(p.name for p in bundle.iterdir()) != {'receipt.json', 'lists', 'archives'} or bundle.is_symlink():
        raise Refusal('unexpected bundle entry')
    if (set(receipt) != {'format', 'snapshot', 'pins', 'state', 'files'}
            or receipt['format'] != 'labapp-qemu-bundle-v1' or receipt['snapshot'] != snapshot
            or receipt['pins'] != pins):
        raise Refusal('bundle fixed identity mismatch')
    check_state(receipt['state'], state_base)
    actual = inventory(bundle)
    if actual != receipt['files']:
        raise Refusal('bundle complete inventory mismatch')
    # Copy only verified data into the module's owned private workspace. Source
    # must be caller-owned/quiescent; rehash private result before using APT.
    for relative in actual:
        (root / relative).write_bytes(regular(bundle / relative))
    if inventory(root) != actual:
        raise Refusal('bundle changed during copy')
    signatures(root, call)
    return receipt['state']
