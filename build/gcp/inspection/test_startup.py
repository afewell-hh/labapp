"""Synthetic and public historical recipes only; no appliance reports."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from . import candidate, collector, startup


UNIT = '''[Unit]
Description=PRIVATE_DESCRIPTION
Documentation=https://example.invalid/PRIVATE_URL
After=hhfab-vlab-resume.service
Wants=hhfab-vlab-resume.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/hhbr-ip-setup.sh
RemainAfterExit=yes
Restart=on-failure
RestartSec=37
[Install]
WantedBy=multi-user.target
'''


class StartupTests(unittest.TestCase):
    def fixture(self, root, unit=UNIT, helper=startup.HHBR_RECIPE):
        for path, body in {
            'etc/os-release': 'PRIVATE_OS=yes\n',
            'usr/lib/os-release': 'PRIVATE_CANONICAL=yes\n',
            'var/lib/dpkg/status': '',
            'etc/systemd/system/hhbr-ip.service': unit,
            'usr/local/bin/hhbr-ip-setup.sh': helper,
            'etc/systemd/system/hhbr-ip.service.d/PRIVATE_NAME.conf':
                '[Service]\nExecStart=PRIVATE_DROPIN\n',
        }.items():
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(body)
        return collector.collect(root)

    def test_recover_reusable_unit_and_complete_public_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
        result = startup.derive(report)['persisted_startup']
        unit = result['units'][0]
        self.assertEqual(unit['gaps'], [])
        self.assertTrue(unit['literal_subset_complete'])
        self.assertEqual(unit['settings']['Service']['RestartSec'], '37')
        expected = '''[Unit]
After=hhfab-vlab-resume.service
Wants=hhfab-vlab-resume.service

[Service]
ExecStart=/usr/local/bin/hhbr-ip-setup.sh
RemainAfterExit=yes
Restart=on-failure
RestartSec=37
Type=oneshot

[Install]
WantedBy=multi-user.target

'''
        self.assertEqual(unit['reusable_unit'], expected)
        self.assertEqual(startup.unit_settings(expected), (unit['settings'], []))
        self.assertEqual(result['helpers'][0]['recipe'], 'hhbr-ip-issue131')
        self.assertEqual(result['helpers'][0]['reusable_script'], startup.HHBR_RECIPE)
        self.assertFalse(result['effective'])  # Even with a private conflicting drop-in.
        self.assertEqual(result['enabled_state'], 'unknown')
        self.assertNotIn('PRIVATE_', json.dumps(result))

    def test_mixed_secrets_unknown_values_and_directives_are_not_emitted(self):
        mixed = UNIT + '''[Service]
Environment=PRIVATE_ENV
EnvironmentFile=/PRIVATE_PATH
User=PRIVATE_USER
ExecStartPre=/bin/echo PRIVATE_ARG
PRIVATE_KEY=PRIVATE_VALUE
[PRIVATE_SECTION]
Type=PRIVATE_TYPE
'''
        with tempfile.TemporaryDirectory() as tmp:
            output = startup.derive(self.fixture(Path(tmp), mixed, '#!/bin/sh\necho PRIVATE_HELPER\n'))
        self.assertNotIn('PRIVATE_', json.dumps(output))
        unit = output['persisted_startup']['units'][0]
        self.assertEqual(unit['settings']['Service']['ExecStart'], '/usr/local/bin/hhbr-ip-setup.sh')
        self.assertFalse(unit['literal_subset_complete'])
        self.assertEqual(unit['gaps'], ['unknown_section', 'unsupported_directive',
                                       'unsupported_syntax', 'unsupported_value'])
        self.assertEqual(output['persisted_startup']['helpers'][0]['recipe'], 'unknown')

    def test_repeated_assignments_resets_and_unsupported_syntax(self):
        for extra in ('ExecStart=\n', 'ExecStart=/usr/local/bin/fix-argocd-port.sh\n',
                      'ExecStart=PRIVATE\n'):
            settings, gaps = startup.unit_settings(UNIT + '[Service]\n' + extra)
            self.assertNotIn('ExecStart', settings['Service'])
            self.assertIn('repeated_assignment', gaps)
        for value in ('%i', '$PRIVATE', '"/usr/local/bin/hhbr-ip-setup.sh"',
                      '/usr/local/bin/hhbr-ip-setup.sh PRIVATE'):
            settings, gaps = startup.unit_settings('[Service]\nExecStart=' + value)
            self.assertNotIn('ExecStart', settings.get('Service', {}))
            self.assertEqual(gaps, ['unsupported_value'])
        self.assertEqual(startup.unit_settings('[Service]\nExecStart=/bin/bash \\\n+Type=oneshot\n'), ({}, ['unsupported_syntax']))
        self.assertEqual(startup.unit_settings('[Service]\nBROKEN_PRIVATE\n')[1], ['unsupported_syntax'])
        for value in ('3601', '-1', 'infinity', '5s', 'PRIVATE', '9999999999999999999999999999'):
            settings, gaps = startup.unit_settings('[Service]\nRestartSec=' + value)
            self.assertEqual(gaps, ['unsupported_value'])
            self.assertEqual(settings, {})
        for value in ('0', '3600'):
            self.assertEqual(startup.unit_settings('[Service]\nRestartSec=' + value)[1], [])

    def test_literal_shell_recipe_and_dependency_catalog(self):
        settings, gaps = startup.unit_settings('[Service]\nExecStart=' + startup.NETFILTER + '\n')
        self.assertEqual(gaps, [])
        self.assertIn(startup.NETFILTER, startup.format_unit(settings))
        _, gaps = startup.unit_settings('[Unit]\nAfter=docker.service PRIVATE.service\n')
        self.assertEqual(gaps, ['unsupported_value'])

    def test_unicode_separators_never_invent_directives(self):
        for separator in ('\u0085', '\u2028', '\u2029', '\u00a0', '\r', '\v', '\f'):
            text = '[Service]\nDescription=PRIVATE' + separator + 'ExecStart=/usr/local/bin/hhbr-ip-setup.sh\n'
            self.assertEqual(startup.unit_settings(text), ({}, ['unsupported_syntax']))
            with tempfile.TemporaryDirectory() as tmp:
                # Collector intentionally refuses ASCII nontext first.
                output = startup.derive(self.fixture(Path(tmp), text))
            self.assertNotIn('PRIVATE', json.dumps(output))
            self.assertFalse(any(u['settings'].get('Service', {}).get('ExecStart')
                                 for u in output['persisted_startup']['units']))
        self.assertEqual(startup.unit_settings(UNIT.replace('\n', '\r\n')),
                         startup.unit_settings(UNIT))

    def test_whole_helper_matching_preserves_semantic_changes(self):
        self.assertEqual(startup.normalized_body(startup.HHBR_RECIPE.replace('\n', '\r\n')),
                         startup.normalized_body(startup.HHBR_RECIPE))
        for changed in (startup.HHBR_RECIPE.replace('#!/bin/bash', '#!/usr/bin/python3'),
                        startup.HHBR_RECIPE + 'echo PRIVATE\n',
                        startup.HHBR_RECIPE.replace('MAX_WAIT=600', 'MAX_WAIT=300'),
                        startup.HHBR_RECIPE.replace('hhbr IP setup starting...', 'PRIVATE'),
                        startup.HHBR_RECIPE + '# private extra comment\n'):
            with tempfile.TemporaryDirectory() as tmp:
                output = startup.derive(self.fixture(Path(tmp), helper=changed))
            helper = output['persisted_startup']['helpers'][0]
            self.assertEqual(helper['recipe'], 'unknown')
            self.assertNotIn('reusable_script', helper)

    def test_canonical_no_follow_and_historical_schema_compatibility(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self.fixture(root)
            (root / 'etc/os-release').unlink()
            (root / 'etc/os-release').symlink_to('/usr/lib/os-release')
            report = collector.collect(root)
            os_records = [r for r in report['records'] if r['kind'] == 'os_release']
            self.assertEqual([r['status'] for r in os_records], ['symlink_skipped', 'captured'])
            candidate.derive(report)
            startup.derive(report)
            old = deepcopy(report)
            old['records'] = [r for r in old['records'] if r['path'] != '/usr/lib/os-release']
            old_inventory = candidate.derive(old)
            self.assertNotEqual(old_inventory['counts'], candidate.derive(report)['counts'])
            # New startup derivation preserves every original inventory field.
            new = startup.derive(old)
            new.pop('persisted_startup')
            self.assertEqual(new, old_inventory)
            canonical = root / 'usr/lib/os-release'
            canonical.unlink()
            canonical.symlink_to('/etc/shadow')
            self.assertEqual(next(r for r in collector.collect(root)['records']
                                  if r['path'] == '/usr/lib/os-release')['status'], 'symlink_skipped')

    def test_private_writer_and_invalid_input_and_formatter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, output = root / 'raw.json', root / 'out.json'
            source.write_text(json.dumps(self.fixture(root / 'guest')))
            source.chmod(0o600)
            receipt = candidate.write_candidate(source, output, deriver=startup.derive)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(receipt['sha256'], hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertNotIn('PRIVATE_', json.dumps(receipt))
            with self.assertRaises(FileExistsError):
                candidate.write_candidate(source, output, deriver=startup.derive)
        with self.assertRaises(candidate.Refused):
            startup.derive({'PRIVATE': 'invalid'})
        for settings in ({'Service': {'Environment': 'PRIVATE'}}, {'PRIVATE': {'Type': 'oneshot'}},
                         {'Service': {'ExecStart': '/bin/echo PRIVATE'}}):
            with self.assertRaises(candidate.Refused):
                startup.format_unit(settings)


if __name__ == '__main__':
    unittest.main()
