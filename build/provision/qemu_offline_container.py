"""Test-only disconnected target acceptance, including consequential refusals."""
import hashlib
import argparse
import json
from pathlib import Path
import re
import runpy
import sys
import tempfile
import time

import qemu_offline as protocol
from hhfab_release import bounded, digest
import qemu_witness

BASE = protocol.BASE
BUNDLE = Path('/bundle')
# Both the unchanged installer ('labapp-qemu-') and this harness
# ('labapp-qemu-baseline-') own scratch below /var/tmp with this prefix.
SCRATCH_ROOT = Path('/var/tmp')
SCRATCH_PREFIX = 'labapp-qemu-'
MAX_PACKAGES, MAX_ARCHIVES = 1024, 256
PACKAGE = re.compile(r'[a-z0-9][a-z0-9+.:-]{0,127}')
VERSION = re.compile(r'[A-Za-z0-9.+:~_-]{1,128}')
ARCHIVE = re.compile(r'[A-Za-z0-9_.%+~:-]{1,240}\.deb')
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


def scratch():
    return sorted(p.name for p in SCRATCH_ROOT.iterdir() if p.name.startswith(SCRATCH_PREFIX))


def scratch_absent(label, before):
    # Positive evidence: the exact census was read again and nothing new remains.
    leftover = [name for name in scratch() if name not in before]
    assert not leftover, 'owned scratch remains after ' + label + ': ' + ', '.join(leftover[:8])
    print(json.dumps({'target_scratch_absent': label, 'root': str(SCRATCH_ROOT),
                      'prefix': SCRATCH_PREFIX, 'preexisting_entries': len(before)}), flush=True)


def public_report(kind, result, seconds, selected):
    """Bounded, validated public summary of the unchanged installer's own JSON."""
    policy = protocol.selection(selected)
    keys = {'snapshot', 'pins', 'resolved_installed', 'downloaded_archives', 'changed', 'seconds', 'selection'}
    packages = result.get('resolved_installed') if isinstance(result, dict) else None
    archives = result.get('downloaded_archives') if isinstance(result, dict) else None
    if (not isinstance(result, dict) or not set(result) <= keys or not keys - {'selection'} <= set(result)
            or result['snapshot'] != policy['snapshot'] or result['pins'] != policy['pins']
            or result.get('selection', selected) != selected
            or type(result['changed']) is not bool
            or type(result['seconds']) not in (int, float) or not 0 <= result['seconds'] < 1000
            or not isinstance(packages, dict) or not 0 < len(packages) <= MAX_PACKAGES
            or any(not isinstance(k, str) or not PACKAGE.fullmatch(k) or not isinstance(v, str)
                   or not VERSION.fullmatch(v) for k, v in packages.items())
            or any(packages.get(k) != v for k, v in policy['pins'].items())
            or not isinstance(archives, list) or len(archives) > MAX_ARCHIVES
            or any(not isinstance(row, dict) or set(row) != {'name', 'bytes', 'sha256'}
                   or not isinstance(row['name'], str) or not ARCHIVE.fullmatch(row['name'])
                   or type(row['bytes']) is not int or row['bytes'] < 0
                   or not protocol.sha(row['sha256']) for row in archives)):
        raise protocol.Refusal('installer report failed bounded public validation')
    return {'qemu_offline_report': kind, 'selection': selected, 'snapshot': policy['snapshot'],
            'pins': policy['pins'], 'changed': result['changed'],
            'installer_seconds': result['seconds'], 'harness_seconds': round(seconds, 3),
            'installed_package_count': len(packages), 'archives': archives}


def invoke(expected, success=False, reason=None, selected=protocol.TEST, observe=None):
    protocol.selection(selected)
    started = time.monotonic()
    code, output = bounded(['/usr/bin/python3', '/suite/install-qemu.py', '--offline', str(BUNDLE),
                            '--receipt-sha256', expected, '--base-id', BASE, '--selection', selected], 240)
    elapsed = time.monotonic() - started
    if success:
        safe = [line for line in output.decode(errors='replace').splitlines() if line.startswith('qemu install: ')]
        assert code == 0, 'actual unchanged offline CLI failed: ' + '; '.join(safe)
        result = json.loads(output)
        if observe is not None:
            observe.append((result, elapsed))
        return result
    assert code != 0, 'unsafe offline input accepted'
    if reason is not None:
        assert reason.encode() in output, 'wrong refusal category: ' + str(reason)


def emit(kind, observed, selected):
    result, seconds = observed.pop()
    print(json.dumps(public_report(kind, result, seconds, selected), sort_keys=True), flush=True)
    return result


def main(selected, expected):
    descriptor = protocol.selection(selected)
    if not protocol.sha(expected):
        raise protocol.Refusal('independent trusted acquisition receipt digest required')
    before_scratch = scratch()
    try:
        run(selected, expected, descriptor, before_scratch)
    except BaseException:
        # Best-effort evidence only; the primary failure/cancellation is re-raised.
        try:
            leftover = [name for name in scratch() if name not in before_scratch]
            print(json.dumps({'target_scratch_after_failure': 'present' if leftover else 'absent',
                              'entries': leftover[:8]}), file=sys.stderr, flush=True)
        except Exception:
            print('target scratch census unavailable after failure', file=sys.stderr, flush=True)
        raise


def run(selected, expected, descriptor, before_scratch):
    assert {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'}
    receipt_file = BUNDLE / 'receipt.json'
    receipt_bytes = receipt_file.read_bytes()
    assert hashlib.sha256(receipt_bytes).hexdigest() == expected, 'trusted acquisition digest mismatch'
    receipt = json.loads(receipt_bytes)
    before = digest(Path('/var/lib/dpkg/status'))
    module = runpy.run_path('/suite/install-qemu.py')
    with tempfile.TemporaryDirectory(prefix='labapp-qemu-baseline-', dir='/var/tmp') as directory:
        root = Path(directory)
        protocol.setup(root, descriptor['snapshot'])
        state = protocol.receive(BUNDLE, expected, root, BASE, descriptor['snapshot'], descriptor['pins'], module['call'], selected)
        assert state == protocol.capture(module['call'], BASE, selected)
    scratch_absent('harness-workspace', before_scratch)
    unchanged_policy()
    for path, data in POLICY.items():
        assert state['policy'][str(path.relative_to('/etc/apt'))] == hashlib.sha256(data).hexdigest()
    print(json.dumps({'baseline_receipt_inventory_signatures_target_state_valid': True}), flush=True)
    # A harmless change to the captured conflicting pin must refuse before APT.
    PREFERENCE.write_bytes(POLICY[PREFERENCE] + b'# changed after capture\n')
    observed = []
    def check(digest_, success=False, reason=None):
        return invoke(digest_, success, reason, selected, observed)
    check(expected, reason='target state drift before transaction')
    assert digest(Path('/var/lib/dpkg/status')) == before
    assert not MARKER.exists()
    PREFERENCE.write_bytes(POLICY[PREFERENCE])
    # Each failure must occur before any real dpkg change; no network exists.
    check('0' * 64, reason='trusted expected receipt mismatch')
    for kind in ('archives', 'lists'):
        relative = next(name for name in receipt['files'] if name.startswith(kind + '/'))
        file = BUNDLE / relative
        saved = file.read_bytes()
        file.unlink()
        check(expected, reason='bundle complete inventory mismatch')
        file.write_bytes(saved + b'corrupt')
        check(expected, reason='bundle complete inventory mismatch')
        file.write_bytes(saved)
    unsafe = BUNDLE / 'apt.conf'
    unsafe.write_text('DPkg::Pre-Invoke {"false";};')
    check(expected, reason='unexpected bundle entry')
    unsafe.unlink()
    archive = next((BUNDLE / 'archives').glob('*.deb'))
    saved = archive.read_bytes()
    archive.unlink()
    archive.symlink_to('/var/lib/dpkg/status')
    check(expected)
    archive.unlink()
    archive.write_bytes(saved)
    drift = Path('/etc/apt/apt.conf.d/labapp-test-state-drift')
    drift.write_text('// harmless but different captured policy\n')
    check(expected, reason='target state drift before transaction')
    drift.unlink()
    for field, value in [('foreign', 'arm64'), ('base', 'gce-image:1')]:
        changed = json.loads(receipt_bytes)
        changed['state'][field] = value
        receipt_file.write_bytes(protocol.encoded(changed))
        check(digest(receipt_file), reason='target/base/module/trust identity mismatch')
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
    check(digest(receipt_file), reason='command failed: gpgv')
    release.write_bytes(saved)
    receipt_file.write_bytes(receipt_bytes)
    assert digest(Path('/var/lib/dpkg/status')) == before
    first = check(expected, True)
    emit('install', observed, selected)
    scratch_absent('install', before_scratch)
    assert first['changed']
    second = check(expected, True)
    final = emit('rerun', observed, selected)
    scratch_absent('rerun', before_scratch)
    assert not second['changed']
    print(json.dumps({'final_installed_package_map': final['resolved_installed'],
                      'selection': selected}, sort_keys=True), flush=True)
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
    finish_runtime(selected)


def finish_runtime(selected):
    protocol.selection(selected)
    if selected == protocol.TEST:
        print(json.dumps(qemu_witness.probe(test_tcg=True)), flush=True)
    else:
        print(json.dumps({'selection': selected, 'partial_qemu_contract_only': True,
                          'TEST_runtime_witness_omitted': True}), flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['--prepare-policy']:
        prepare_policy()
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--selection', default=protocol.TEST)
        parser.add_argument('--receipt-sha256', required=True)
        args = parser.parse_args()
        main(args.selection, args.receipt_sha256)
