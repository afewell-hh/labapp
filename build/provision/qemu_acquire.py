"""Internal trusted downloader guest; fixed native APT, never host APT.

Invoked only by prepare-qemu-offline.sh from reviewed trusted code. Status is
resolver input only, never copied over the downloader or target dpkg database.
"""
import hashlib
import json
from pathlib import Path
import runpy
import signal
import sys
import time

import qemu_offline as protocol
from hhfab_release import Refusal, digest


def acquire():
    print('QEMU acquisition stage: validate-state', flush=True)
    module = runpy.run_path('/suite/install-qemu.py')
    state = protocol.load(Path('/target-state.json'))
    status = protocol.check_state(state, state['base'])
    root = Path('/work/bundle')
    root.mkdir(mode=0o755)
    apt, config = protocol.setup(root, module['SNAPSHOT'])
    module['ENV']['APT_CONFIG'] = config
    copied_status = root / 'status'
    copied_status.write_bytes(status)
    apt += ['-o', 'Dir::State::status=' + str(copied_status)]
    start = time.monotonic()
    def call(args, seconds=10):
        remaining = 210 - (time.monotonic() - start)
        if remaining <= 0:
            raise Refusal('acquisition deadline exceeded')
        return module['call'](args, min(seconds, remaining))
    print('QEMU acquisition stage: update', flush=True)
    call([*apt, '-o', 'APT::Update::Error-Mode=any', 'update'], 180)
    print('QEMU acquisition stage: dependency-check', flush=True)
    call([*apt, 'check'], 30)
    selected = [name + '=' + version for name, version in module['PINS'].items()]
    call([*apt, '--simulate', '--no-remove', '--no-install-recommends', 'install', *selected], 30)
    print('QEMU acquisition stage: download', flush=True)
    call([*apt, '--download-only', '--yes', '--no-remove', '--no-install-recommends', 'install', *selected], 180)
    print('QEMU acquisition stage: signatures-inventory', flush=True)
    protocol.signatures(root, call)
    files = protocol.inventory(root)
    # Export only data. No config/status working files are accepted in a bundle.
    for name in ('status', 'fixed.conf', 'sources.list'):
        (root / name).unlink()
    for name in ('parts', 'preferences'):
        (root / name).rmdir()
    receipt = {'format': 'labapp-qemu-bundle-v1', 'snapshot': module['SNAPSHOT'],
               'pins': module['PINS'], 'state': state, 'files': files}
    (root / 'receipt.json').write_bytes(protocol.encoded(receipt))
    # tmpfs disappears when Docker stops the container. Export only this already
    # validated bounded data tree to the owned writable layer before exit.
    exported = Path('/export-bundle')
    exported.mkdir()
    for directory in ('lists', 'archives'):
        (exported / directory).mkdir()
    for relative in files:
        with (exported / relative).open('xb') as output:
            output.write(protocol.regular(root / relative))
    (exported / 'receipt.json').write_bytes(protocol.encoded(receipt))
    if protocol.inventory(exported) != files:
        raise Refusal('export inventory mismatch')
    print(json.dumps({'receipt_sha256': digest(root / 'receipt.json'), 'files': len(files),
                      'bytes': sum(row['bytes'] for row in files.values()),
                      'state_sha256': hashlib.sha256(protocol.encoded(state)).hexdigest(),
                      'seconds': round(time.monotonic() - start, 3)}), flush=True)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Refusal('acquisition overall timeout')))
    signal.alarm(230)
    try:
        acquire()
    except Refusal as exc:
        print('QEMU acquisition refused: ' + str(exc), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError):
        print('QEMU acquisition refused: input or IO', file=sys.stderr)
        sys.exit(1)
