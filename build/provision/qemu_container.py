"""Test-only runner inside owned Docker containers; never a cloud entrypoint."""
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile

from hhfab_release import Refusal, bounded, digest
import qemu_witness


def install():
    module = runpy.run_path('/suite/install-qemu.py')
    apt_before = {str(p): digest(p) for p in Path('/etc/apt').rglob('*') if p.is_file()}
    packages_before = module['installed']()
    # Exercise actual APT authentication failure against the official signed
    # snapshot with an owned empty trust keyring, before installing anything.
    globals_ = module['install'].__globals__
    original_call = globals_['call']
    with tempfile.TemporaryDirectory(prefix='labapp-qemu-rejection-') as temporary:
        Path(temporary).chmod(0o755)
        key = Path(temporary) / 'empty.gpg'
        key.write_bytes(b'')
        def rejected_trust(args, seconds=10):
            if args[0] == '/usr/bin/apt-get' and args[-1] == 'update':
                source = Path(next(a.split('=', 1)[1] for a in args if a.startswith('Dir::Etc::sourcelist=')))
                source.write_text(source.read_text().replace('/usr/share/keyrings/ubuntu-archive-keyring.gpg', str(key)))
                code, output = bounded(args, seconds, env=module['ENV'])
                assert code != 0 and b'NO_PUBKEY' in output
                raise Refusal('actual signature refusal')
            return original_call(args, seconds)
        globals_['call'] = rejected_trust
        try:
            module['install']()
        except Refusal as exc:
            assert str(exc) == 'actual signature refusal'
        else:
            raise AssertionError('untrusted signature accepted')
        finally:
            globals_['call'] = original_call
    assert module['installed']() == packages_before
    # Unavailable explicit pin must fail at resolution, without package changes.
    original_pin = module['PINS']['qemu-system-x86']
    module['PINS']['qemu-system-x86'] = '999:0.invalid'
    try:
        module['install']()
    except Refusal:
        pass
    else:
        raise AssertionError('unavailable pin accepted')
    finally:
        module['PINS']['qemu-system-x86'] = original_pin
    assert module['installed']() == packages_before
    print(json.dumps({'actual_signature_refusal': True, 'actual_unavailable_pin_refusal': True,
                      'preinstall_failure_packages_unchanged': True}))
    for _ in range(2):
        code, output = bounded(['/usr/bin/python3', '/suite/install-qemu.py'], 240,
                               env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
        if code:
            raise Refusal('unchanged installer CLI failed')
        print(json.dumps(json.loads(output)), flush=True)
    assert {str(p): digest(p) for p in Path('/etc/apt').rglob('*') if p.is_file()} == apt_before
    # Real held-state preflight refuses before an APT transaction.
    assert bounded(['/usr/bin/apt-mark', 'hold', 'socat'], 10)[0] == 0
    try:
        module['preflight']()
    except Refusal as exc:
        assert 'held packages' in str(exc)
    else:
        raise AssertionError('held state accepted')
    finally:
        assert bounded(['/usr/bin/apt-mark', 'unhold', 'socat'], 10)[0] == 0
    print(json.dumps({'apt_configuration_unchanged': True, 'actual_hold_refusal': True}))
    # Real drift refusal occurs before APT mutation. A target version change is
    # simulated in this test process only, never by altering installed packages.
    module['PINS']['socat'] = '0.invalid'
    try:
        module['preflight']()
    except Refusal as exc:
        assert 'drift' in str(exc)
    else:
        raise AssertionError('drift accepted')


def runtime():
    assert os.getuid() == 1000
    assert {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'}
    assert not Path('/dev/kvm').exists()
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    assert int(status['CapEff'].strip(), 16) == 0 and status['NoNewPrivs'].strip() == '1'
    print(json.dumps(qemu_witness.probe(test_tcg=True)), flush=True)
    # Invoke unchanged production CLI: no KVM device means refusal, never TCG.
    code, output = bounded(['/usr/bin/python3', '/suite/qemu_witness.py'], 20, limit=4096)
    assert code == 1 and b'KVM character device absent; no fallback' in output
    # Also prove actual QEMU's KVM-only path refuses, rather than just our guard.
    code, output = bounded(['/usr/bin/qemu-system-x86_64', '-nodefaults', '-display', 'none',
                            '-accel', 'kvm', '-cpu', 'host', '-machine', 'pc-i440fx-8.2'], 5, limit=4096)
    assert code != 0 and b'failed to initialize kvm' in output and b'LABAPP-L2:' not in output
    print(json.dumps({'production_no_kvm_refusal': True, 'actual_qemu_kvm_refusal': True}))


if __name__ == '__main__':
    {'install': install, 'runtime': runtime}[sys.argv[1]]()
