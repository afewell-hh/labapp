"""Synthetic fixtures only; never open actual appliance reports."""
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from . import candidate, collector


class CandidateTests(unittest.TestCase):
    def fixture(self, root):
        def put(name, text):
            path = root / name.lstrip('/')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        put('/etc/os-release', 'PRIVATE_OS_MARKER=yes\n')
        put('/var/lib/dpkg/status', 'Package: docker-ce\nVersion: 5:28.2.2-1\nStatus: install ok installed\n\n'
            'Package: secret-company-package\nVersion: 1.2\nStatus: install ok installed\n')
        put('/etc/systemd/system/hhbr-ip.service',
            '[Service]\nExecStart=/usr/local/bin/hhbr-ip\nEnvironment=PRIVATE_UNIT_MARKER\n')
        put('/usr/local/bin/hhbr-ip', '#!/bin/sh\necho PRIVATE_HELPER_MARKER\n')
        put('/etc/systemd/system/hhbr-ip.service.d/PRIVATE_DROPIN_NAME.conf', 'PRIVATE_DROPIN_BODY\n')
        return collector.collect(root)

    def test_real_collector_schema_never_copies_private_or_dynamic_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
        output = candidate.derive(report)
        text = json.dumps(output)
        for private in ('PRIVATE_', 'secret-company-package', 'private_content', 'ExecStart', 'Environment'):
            self.assertNotIn(private, text)
        self.assertEqual(output['packages'], [{'name': 'docker-ce', 'version': '5:28.2.2-1'}])
        helper = next(r for r in output['files'] if r['path'] == '/usr/local/bin/hhbr-ip')
        self.assertEqual(helper['sha256'], hashlib.sha256(b'#!/bin/sh\necho PRIVATE_HELPER_MARKER\n').hexdigest())
        self.assertEqual(output['provenance'], 'lead-verification-required')
        self.assertTrue(output['review_required'])
        self.assertEqual(sum(c['count'] for c in output['counts']), len(report['records']))
        self.assertFalse(any(f['path'] == '/etc/os-release' for f in output['files']))

    def test_schema_keys_types_paths_statuses_and_payloads_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = self.fixture(Path(tmp))
        changes = [
            lambda r: r.update(schema_version=True), lambda r: r.update(schema_version=2),
            lambda r: r.update(extra='private'), lambda r: r.update(private_review_required=False),
            lambda r: r.update(unimplemented=[]), lambda r: r.update(records='wrong'),
            lambda r: r['records'][0].update(extra='private'),
            lambda r: r['records'][0].update(path='/etc/shadow'),
            lambda r: r['records'][0].update(path='/etc/systemd/system/hhbr-ip.service.d/../private.conf'),
            lambda r: r.update(records=r['records'] * 7),
            lambda r: r['records'][0].update(status='SECRET_STATUS'),
            lambda r: r['records'][0].update(kind='unknown'),
            lambda r: r['records'][0].update(sha256='secret'),
            lambda r: r['records'][0].update(sha256='a' * 64),
            lambda r: r['records'][0].update(private_content=123),
            lambda r: r['records'].append(deepcopy(r['records'][0])),
            lambda r: r['records'].pop(0),
            lambda r: r['records'][1]['packages'][0].update(version='1\nPRIVATE'),
            lambda r: r['records'][1]['packages'][0].update(name='PRIVATE PACKAGE'),
            lambda r: r['records'][1]['packages'][0].update(secret='PRIVATE'),
            lambda r: r['records'][1]['packages'].append({'name': 'docker-ce', 'version': '2'}),
            lambda r: r['records'][0].update(private_content='a' * (collector.FILE_LIMIT + 1)),
        ]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                report = deepcopy(good)
                change(report)
                with self.assertRaises(candidate.Refused):
                    candidate.derive(report)

    def test_failed_package_parse_digest_and_gap_have_no_payload_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
        report['records'][1] = {'path': '/var/lib/dpkg/status', 'kind': 'packages',
                                'status': 'invalid_dpkg', 'sha256': 'a' * 64}
        result = candidate.derive(report)
        self.assertEqual(result['packages'], [])
        self.assertTrue(any(c['status'] == 'invalid_dpkg' for c in result['counts']))

    def test_private_file_modes_hash_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            guest = parent / 'fixture'
            guest.mkdir()
            source, output = parent / 'raw.json', parent / 'candidate.json'
            source.write_text(json.dumps(self.fixture(guest)))
            source.chmod(0o600)
            receipt = candidate.write_candidate(source, output)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(receipt['sha256'], hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertNotIn('PRIVATE_', json.dumps(receipt))
            with self.assertRaises(FileExistsError):
                candidate.write_candidate(source, output)
            source.chmod(0o644)
            with self.assertRaises(candidate.Refused):
                candidate.write_candidate(source, parent / 'bad.json')

    def test_symlink_fifo_and_nonprivate_parent_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            target = parent / 'target'
            target.write_text('{}')
            target.chmod(0o600)
            source = parent / 'input'
            source.symlink_to(target)
            with self.assertRaises(candidate.Refused):
                candidate.write_candidate(source, parent / 'out')
            source.unlink()
            os.mkfifo(source, 0o600)
            with self.assertRaises(candidate.Refused):
                candidate.write_candidate(source, parent / 'out')
            parent.chmod(0o755)
            with self.assertRaises(candidate.Refused):
                candidate.write_candidate(target, parent / 'out')

    def test_duplicate_keys_oversize_and_sanitized_cli_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            source, output = parent / 'raw.json', parent / 'out.json'
            for text in ('{"schema_version":1,"schema_version":2}',
                         'x' * (collector.REPORT_LIMIT + 1)):
                source.write_text(text)
                source.chmod(0o600)
                with self.assertRaises(ValueError):
                    candidate.write_candidate(source, output)
                self.assertFalse(output.exists())
            err = io.StringIO()
            with patch('sys.argv', ['candidate', '--private-input', str(source), '--private-output', str(output)]), \
                    patch('sys.stderr', err), self.assertRaises(SystemExit):
                candidate.main()
            self.assertEqual(err.getvalue(), 'Candidate refused; no private content is printed.\n')


if __name__ == '__main__':
    unittest.main()
