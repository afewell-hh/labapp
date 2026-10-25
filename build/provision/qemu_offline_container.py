"""Test-only disconnected target acceptance, including consequential refusals."""
import hashlib
import json
from pathlib import Path
import runpy
import sys
import tempfile

import qemu_offline as protocol
from hhfab_release import bounded, digest
import qemu_witness

BASE = protocol.BASE
BUNDLE = Path('/bundle')
PREFERENCE = Path('/etc/apt/preferences.d/labapp-test-conflict')
HOOK = Path('/etc/apt/apt.conf.d/labapp-test-hook')
MARKER = Path('/tmp/labapp-test-ambient-hook-ran')
POLICY = {PREFERENCE: b'Package: qemu-system-common\nPin: version *\nPin-Priority: -1\n',
          HOOK: b'DPkg::Pre-Invoke {"touch /tmp/labapp-test-ambient-hook-ran";};\n'}


def prepare_policy():
    # A positive control on the same real lists makes candidate-none meaningful.
    def candidate():
        code, output = bounded(['/usr/bin/apt-cache', 'policy', 'qemu-system-common'], 10)
        assert code == 0
        return output.decode().split('Candidate: ', 1)[1].splitlines()[0]
    assert candidate() != '(none)', 'missing ambient package index positive control'
    for path, data in POLICY.items():
        assert not path.exists()
        path.write_bytes(data)
    assert candidate() == '(none)', 'ambient negative pin is not active'
    assert not MARKER.exists()
    print(json.dumps({'ambient_dependency_candidate_positive_control': True,
                      'ambient_conflicting_pin_active': True}), flush=True)


def unchanged_policy():
    assert not MARKER.exists(), 'ambient APT hook executed'
    for path, data in POLICY.items():
        assert path.read_bytes() == data, 'ambient policy bytes changed'


def invoke(expected, success=False, reason=None):
    code, output = bounded(['/usr/bin/python3', '/suite/install-qemu.py', '--offline', str(BUNDLE),
                            '--receipt-sha256', expected, '--base-id', BASE], 240)
    if success:
        safe = [line for line in output.decode(errors='replace').splitlines() if line.startswith('qemu install: ')]
        assert code == 0, 'actual unchanged offline CLI failed: ' + '; '.join(safe)
        return json.loads(output)
    assert code != 0, 'unsafe offline input accepted'
    if reason is not None:
        assert reason.encode() in output, 'wrong refusal category: ' + str(reason)


def main():
    assert {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'}
    receipt_file = BUNDLE / 'receipt.json'
    receipt_bytes = receipt_file.read_bytes()
    expected = hashlib.sha256(receipt_bytes).hexdigest()
    receipt = json.loads(receipt_bytes)
    before = digest(Path('/var/lib/dpkg/status'))
    module = runpy.run_path('/suite/install-qemu.py')
    with tempfile.TemporaryDirectory(prefix='labapp-qemu-baseline-', dir='/var/tmp') as directory:
        root = Path(directory)
        protocol.setup(root, module['SNAPSHOT'])
        state = protocol.receive(BUNDLE, expected, root, BASE, module['SNAPSHOT'], module['PINS'], module['call'])
        assert state == protocol.capture(module['call'], BASE)
    unchanged_policy()
    for path, data in POLICY.items():
        assert state['policy'][str(path.relative_to('/etc/apt'))] == hashlib.sha256(data).hexdigest()
    print(json.dumps({'baseline_receipt_inventory_signatures_target_state_valid': True}), flush=True)
    # A harmless change to the captured conflicting pin must refuse before APT.
    PREFERENCE.write_bytes(POLICY[PREFERENCE] + b'# changed after capture\n')
    invoke(expected, reason='target state drift before transaction')
    assert digest(Path('/var/lib/dpkg/status')) == before
    assert not MARKER.exists()
    PREFERENCE.write_bytes(POLICY[PREFERENCE])
    # Each failure must occur before any real dpkg change; no network exists.
    invoke('0' * 64, reason='trusted expected receipt mismatch')
    for kind in ('archives', 'lists'):
        relative = next(name for name in receipt['files'] if name.startswith(kind + '/'))
        file = BUNDLE / relative
        saved = file.read_bytes()
        file.unlink()
        invoke(expected, reason='bundle complete inventory mismatch')
        file.write_bytes(saved + b'corrupt')
        invoke(expected, reason='bundle complete inventory mismatch')
        file.write_bytes(saved)
    unsafe = BUNDLE / 'apt.conf'
    unsafe.write_text('DPkg::Pre-Invoke {"false";};')
    invoke(expected, reason='unexpected bundle entry')
    unsafe.unlink()
    archive = next((BUNDLE / 'archives').glob('*.deb'))
    saved = archive.read_bytes()
    archive.unlink()
    archive.symlink_to('/var/lib/dpkg/status')
    invoke(expected)
    archive.unlink()
    archive.write_bytes(saved)
    drift = Path('/etc/apt/apt.conf.d/labapp-test-state-drift')
    drift.write_text('// harmless but different captured policy\n')
    invoke(expected, reason='target state drift before transaction')
    drift.unlink()
    for field, value in [('foreign', 'arm64'), ('base', 'gce-image:1')]:
        changed = json.loads(receipt_bytes)
        changed['state'][field] = value
        receipt_file.write_bytes(protocol.encoded(changed))
        invoke(digest(receipt_file), reason='target/base/module/trust identity mismatch')
    receipt_file.write_bytes(receipt_bytes)
    # Even a trusted receipt must not bypass the independent signature check.
    release = next((BUNDLE / 'lists').glob('*_InRelease'))
    saved = release.read_bytes()
    changed_release = saved.replace(b'Origin: Ubuntu', b'Origin: Broken', 1)
    assert changed_release != saved
    release.write_bytes(changed_release)
    changed = json.loads(receipt_bytes)
    changed['files'][str(release.relative_to(BUNDLE))]['sha256'] = digest(release)
    receipt_file.write_bytes(protocol.encoded(changed))
    invoke(digest(receipt_file), reason='command failed: gpgv')
    release.write_bytes(saved)
    receipt_file.write_bytes(receipt_bytes)
    assert digest(Path('/var/lib/dpkg/status')) == before
    first = invoke(expected, True)
    assert first['changed']
    second = invoke(expected, True)
    assert not second['changed']
    assert digest(Path('/var/lib/dpkg/status')) != before
    unchanged_policy()
    print(json.dumps({'actual_offline_install': True, 'actual_offline_rerun': True,
                      'ambient_pin_isolated_hook_not_run_policy_bytes_unchanged': True,
                      'preference_hash_bound_and_drift_refused': True,
                      'pretransaction_refusals_status_unchanged': True,
                      'missing_corrupt_list_archive_receipt': True,
                      'unsafe_config_link_stale_foreign_base_signature_refusals': True,
                      'bundle_files': len(receipt['files']),
                      'archive_count': sum(name.startswith('archives/') for name in receipt['files']),
                      'bundle_bytes': sum(row['bytes'] for row in receipt['files'].values()), 'network': 'none'}), flush=True)
    print(json.dumps(qemu_witness.probe(test_tcg=True)), flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['--prepare-policy']:
        prepare_policy()
    else:
        assert not sys.argv[1:]
        main()
