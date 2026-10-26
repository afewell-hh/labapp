"""Fixed hosted-job ownership/evidence hooks, not a build runner.

Python 3.10+ stdlib. Buildx executes builds in separately bounded workflow steps.
No caller commands/images/options. A query failure is always HOLD. No retries,
prune, image loading, container execution, or VM admission. See component README.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile

# Publisher release + Docker Hub tag metadata read 2026-10-26; README has URLs.
BUILDKIT_IMAGE = "moby/buildkit@sha256:99368f3e46177c6405b9740e4461d91cee004128daeecca78d4ceac50ec1da5c"
BUILDX_VERSION = "v0.38.1"
HEX = re.compile(r"sha256:[0-9a-f]{64}\Z")
CID = re.compile(r"[0-9a-f]{64}\Z")
HOST = "unix:///var/run/docker.sock"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else _hash(handle)


def _hash(handle):
    result = hashlib.sha256()
    for block in iter(lambda: handle.read(1024 * 1024), b''):
        result.update(block)
    return result.hexdigest()


def docker(args):
    # Deliberately no ambient HOME, Docker context, registry helpers, or secrets.
    result = subprocess.run(['/usr/bin/docker', '--host', HOST, '--config',
                             os.environ['DOCKER_CONFIG'], *args],
                            env={'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME']},
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=30, check=True)
    require(len(result.stdout) <= 65536, 'oversized query')
    return result.stdout.decode('utf-8').strip()


def builders(call):
    # Buildx v0.38.1 `ls` reports node errors in JSON even with exit 0.
    rows = [json.loads(line) for line in call(['buildx', 'ls', '--format=json']).splitlines()]
    require(len(rows) <= 128 and len({x['Name'] for x in rows}) == len(rows), 'ambiguous builders')
    require(all(not x.get('Err') and all(not n.get('Err') and n.get('Status') != 'error'
                for n in x['Nodes']) for x in rows), 'builder query error')
    return rows


def census(call, name):
    # Successful empty LIST responses establish absence. Inspect errors never do.
    names = [x['Name'] for x in builders(call)]
    containers = call(['container', 'ls', '-aq', '--no-trunc', '--filter',
                       f'name=^/buildx_buildkit_{name}0$']).splitlines()
    volumes = call(['volume', 'ls', '-q', '--filter', f'name=^buildx_buildkit_{name}0_state$']).splitlines()
    require(len(containers) <= 1 and len(volumes) <= 1, 'ambiguous ownership')
    return name in names, containers, volumes


def bind(call, state):
    name = state['name']
    exists, containers, volumes = census(call, name)
    if exists:
        matches = [x for x in builders(call) if x['Name'] == name]
        require(len(matches) == 1, 'builder disappeared')
        builder, = matches
        require(builder['Name'] == name and builder['Driver'] == 'docker-container', 'builder mismatch')
        nodes = builder['Nodes']
        require(len(nodes) == 1 and nodes[0]['Name'] == name + '0' and
                nodes[0]['Endpoint'] == HOST, 'builder endpoint mismatch')
        require(nodes[0].get('DriverOpts') == {'image': BUILDKIT_IMAGE, 'restart-policy': 'no',
                'provenance-add-gha': 'false'} and not nodes[0].get('Files') and
                not nodes[0].get('ProxyConfig'), 'builder configuration mismatch')
    if containers:
        require(exists and CID.fullmatch(containers[0]), 'orphan container')
        item, = json.loads(call(['container', 'inspect', containers[0]]))
        require(item['Id'] == containers[0] and item['Name'] == '/buildx_buildkit_' + name + '0', 'container mismatch')
        require(item['Config']['Image'] == BUILDKIT_IMAGE and HEX.fullmatch(item['Image']), 'builder image mismatch')
        require(item['HostConfig']['RestartPolicy']['Name'] == 'no', 'restart policy mismatch')
        mounts = [x for x in item['Mounts'] if x['Destination'] == '/var/lib/buildkit']
        require(len(mounts) == 1 and mounts[0]['Type'] == 'volume' and
                mounts[0]['Name'] == 'buildx_buildkit_' + name + '0_state', 'cache mismatch')
        require(volumes == [mounts[0]['Name']], 'cache query mismatch')
        volume, = json.loads(call(['volume', 'inspect', volumes[0]]))
        require(volume['Name'] == volumes[0] and volume['Driver'] == 'local', 'volume mismatch')
        identity = {'container': item['Id'], 'image': item['Image'], 'volume': volume}
        if 'identity' in state:
            require(state['identity'] == identity, 'owned identity changed')
        state['identity'] = identity
    else:
        # Partial create with just a volume cannot be safely attributed: HOLD.
        require(not volumes and 'identity' not in state, 'orphan or vanished resources')
    return exists


def cleanup(call, state):
    require(state['admitted'] is True, 'no admission receipt')
    exists = bind(call, state)  # resolve exact IDs and mount before ANY removal
    if exists:
        call(['buildx', 'rm', '--force', state['name']])
    require(census(call, state['name']) == (False, [], []), 'cleanup incomplete')
    state['cleanup'] = 'verified'


def read_member(archive, name, cap):
    matches = []
    for number, member in enumerate(archive):
        require(number < 4096, 'too many tar members')
        if member.name == name:
            matches.append(member)
    require(len(matches) == 1, 'missing/duplicate tar member')
    member, = matches
    require(member.isfile() and 0 < member.size <= cap, 'invalid tar member')
    return archive.extractfile(member).read(cap + 1)


def evidence(out, state):
    """Read fixed Docker-export members; never extract archive paths to disk."""
    require((out / 'image.tar').stat().st_size <= 4*1024**3, 'tar too large')
    with tarfile.open(out / 'image.tar', 'r:') as archive:
        manifest = json.loads(read_member(archive, 'manifest.json', 65536))
        require(isinstance(manifest, list) and len(manifest) == 1, 'not single-platform')
        entry, = manifest
        require(re.fullmatch(r'[A-Za-z0-9_./-]+', entry['Config']) and '..' not in entry['Config'].split('/'), 'bad config path')
        config = read_member(archive, entry['Config'], 1024 * 1024)
        image_id = 'sha256:' + hashlib.sha256(config).hexdigest()
        require((out / 'iid.txt').read_text().strip() == image_id, 'image ID mismatch')
        cfg = json.loads(config)
        diffids = cfg['rootfs']['diff_ids']
        require(diffids and all(HEX.fullmatch(x) for x in diffids), 'invalid DiffIDs')
        require(len(entry['Layers']) == len(diffids) <= 128, 'layer count mismatch')
        require(all(re.fullmatch(r'[A-Za-z0-9_./-]+', x) and '..' not in x.split('/') for x in entry['Layers']), 'bad layer path')
        # Docker exporter writes uncompressed layers. Hash every layer against
        # the config's DiffIDs, including the final layer holding APT evidence.
        for layer, expected in zip(entry['Layers'], diffids):
            member = archive.getmember(layer)
            require(member.isfile(), 'invalid layer')
            require('sha256:' + _hash(archive.extractfile(member)) == expected, 'layer hash mismatch')
        with tarfile.open(fileobj=archive.extractfile(archive.getmember(entry['Layers'][-1])), mode='r:') as layer:
            for name, cap in [('packages.txt', 4*1024*1024), ('sources.txt', 65536),
                              ('policy.txt', 1024*1024), ('apt-config.txt', 1024*1024),
                              ('apt-lists.tar', 256*1024*1024), ('keyring.gpg', 1024*1024),
                              ('inrelease.sha256', 65536), ('indexes.sha256', 1024*1024)]:
                raw = read_member(layer, 'usr/share/labapp-runtime/' + name, cap)
                (out / name).write_bytes(raw)
    state['image_id'], state['diffids'] = image_id, diffids
    require((out / 'metadata.json').is_file(), 'missing build metadata')
    require((out / 'metadata.json').stat().st_size <= 1024*1024, 'oversized metadata')
    metadata = json.loads((out / 'metadata.json').read_text())
    require(metadata['containerimage.config.digest'] == image_id, 'metadata image mismatch')
    state['tar_sha256'] = digest(out / 'image.tar')


def seal(out, state, job_status='failure', build_outcome='failure'):
    require(job_status == build_outcome == 'success', 'failed/cancelled job cannot publish')
    require(state.get('cleanup') == 'verified' and 'tar_sha256' in state,
            'publication requires evidence and verified cleanup')
    require(digest(out / 'image.tar') == state['tar_sha256'], 'tar changed')
    require(digest(out / 'Dockerfile') == state['dockerfile_sha256'], 'Dockerfile changed')
    (out / 'provenance.json').write_text(json.dumps(state, sort_keys=True) + '\n')
    files = sorted(out.iterdir())
    require(all(x.is_file() and not x.is_symlink() for x in files), 'unexpected artifact member')
    require(not (out / 'SHA256SUMS').exists(), 'already sealed')
    (out / 'SHA256SUMS').write_text(''.join(f'{digest(x)}  {x.name}\n' for x in files))


def main():
    phase, = sys.argv[1:]
    root = Path(os.environ['RUNNER_TEMP']) / 'labapp-runtime'
    path, out = root / 'state.json', root / 'out'
    if phase == 'admit':
        require(HEX.fullmatch(BUILDKIT_IMAGE.removeprefix('moby/buildkit@')), 'HOLD: builder digest unverified')
        require(os.environ['GITHUB_REF'] == 'refs/heads/main' and os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch', 'trusted main dispatch only')
        require(re.fullmatch(r'[0-9]+-[0-9]+', os.environ['RUNTIME_RUN']), 'invalid run identity')
        root.mkdir(mode=0o700)
        require(Path(os.environ['DOCKER_CONFIG']).is_dir() and
                not (Path(os.environ['DOCKER_CONFIG']) / 'config.json').exists(), 'private credential-free Docker config required')
        out.mkdir(mode=0o700)
        (out / 'Dockerfile').write_bytes((Path(__file__).parent / 'runtime' / 'Dockerfile').read_bytes())
        state = {'name': 'labapp-rt-' + os.environ['RUNTIME_RUN'], 'source_commit': os.environ['GITHUB_SHA'],
                 'dockerfile_sha256': digest(Path(__file__).parent / 'runtime' / 'Dockerfile'),
                 'buildkit': BUILDKIT_IMAGE, 'buildx': BUILDX_VERSION, 'admitted': True, 'dependency_image_retention': 'fresh hosted VM disposal; never delete preexisting images'}
        require(census(docker, state['name']) == (False, [], []), 'preexisting resources')
        require(BUILDX_VERSION in docker(['buildx', 'version']).split(), 'unsupported Buildx')
    else:
        state = json.loads(path.read_text())
        if phase == 'bind':
            require(bind(docker, state), 'builder absent')
        elif phase == 'evidence':
            evidence(out, state)
        elif phase == 'cleanup':
            cleanup(docker, state)
        elif phase == 'seal':
            seal(out, state, os.environ.get('RUNTIME_JOB_STATUS'), os.environ.get('RUNTIME_BUILD_OUTCOME'))
        else:
            raise ValueError('unknown fixed phase')
    path.write_text(json.dumps(state, sort_keys=True) + '\n')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
        print(f'HOLD: {type(exc).__name__}', file=sys.stderr)
        raise SystemExit(7)
