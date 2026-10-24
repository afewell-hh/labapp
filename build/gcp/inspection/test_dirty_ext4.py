"""Offline real-harness control flow; fake tools, no loop/mount/cloud calls."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from . import dirty_ext4 as proof
from .mounted_collect import Refused

HEADER = "Filesystem state: clean\nFilesystem features: has_journal needs_recovery\nJournal start: 1\n"
JOURNAL = ("Journal starts at block 1, transaction 1\n"
           "Found expected sequence 1, type 1 (descriptor block) at block 1\n"
           "Found expected sequence 1, type 2 (commit block) at block 3\n"
           "No magic number at block 4: end of journal.\n")
ITEM = {"name": "/dev/loop99", "maj:min": "7:99", "type": "loop",
        "fstype": "ext4", "ro": True, "mountpoints": [None]}


class DirtyJournalTests(unittest.TestCase):
    def test_committed_pending_transaction_and_unchanged_guard(self):
        proof.validate_dirty_evidence(HEADER, JOURNAL)
        for header, journal in ((HEADER.replace("needs_recovery", ""), JOURNAL),
                                (HEADER.replace("Journal start: 1", "Journal start: 0"), JOURNAL),
                                (HEADER, JOURNAL.replace("type 2 (commit block)", "type 3 (revoke block)")),
                                (HEADER, JOURNAL.replace("transaction 1", "transaction 2")),
                                (HEADER, JOURNAL + JOURNAL), (HEADER, "")):
            with self.subTest(header=header, journal=journal), self.assertRaises(Refused):
                proof.validate_dirty_evidence(header, journal)
        with patch.object(proof, 'validate_clean'), self.assertRaisesRegex(Refused, 'not_refused'):
            proof.validate_dirty_evidence(HEADER, JOURNAL)

    def test_mount_children_identity_or_writable_state_refuse(self):
        proof.validate_loop_layout(json.dumps({'blockdevices': [ITEM]}), '/dev/loop99', '7:99')
        for key, value in (('name', '/dev/loop98'), ('maj:min', '7:98'), ('ro', False),
                           ('mountpoints', ['/mnt']), ('children', [{}]), ('fstype', 'xfs')):
            with self.subTest(key=key), self.assertRaises(Refused):
                proof.validate_loop_layout(json.dumps({'blockdevices': [dict(ITEM, **{key: value})]}),
                                           '/dev/loop99', '7:99')
        for entries in (None, [], ['malformed'], [ITEM, ITEM]):
            with self.subTest(entries=entries), self.assertRaises(Refused):
                proof.validate_loop_layout(json.dumps({'blockdevices': entries}), '/dev/loop99', '7:99')

    def execute(self, *, fail_probe=False, fail_detach=False):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        work = Path(self.temp.name) / 'owned'
        work.mkdir(mode=0o700)
        calls = []
        detached = False

        def command(argv):
            nonlocal detached
            calls.append(argv)
            name = Path(argv[0]).name
            if name == 'losetup':
                if '--show' in argv:
                    return '/dev/loop99\n'
                if '--detach' in argv:
                    if fail_detach:
                        raise Refused('injected_detach_failure')
                    detached = True
                return json.dumps({'loopdevices': [] if detached else [{}]})
            if name == 'blockdev':
                return '1' if '--getro' in argv else str(proof.SIZE)
            if name == 'lsblk':
                return json.dumps({'blockdevices': [ITEM]})
            if name == 'dumpe2fs':
                if fail_probe:
                    raise Refused('injected_probe_failure')
                return HEADER
            if name == 'debugfs' and '-R' in argv:
                return JOURNAL
            return ''

        with ExitStack() as stack:
            for target, value in (("os.geteuid", lambda: 0), ("os.access", lambda *a: True),
                                  ("tempfile.mkdtemp", lambda **kw: str(work)),
                                  ("validate_namespace", lambda *a: None),
                                  ("device_number", lambda *a: None),
                                  ("verify_loop", lambda *a: ('/dev/loop99', '7:99')),
                                  ("digest", lambda path: hashlib.sha256(path.read_bytes()).hexdigest()),
                                  ("command", command)):
                stack.enter_context(patch.object(proof, target, value) if '.' not in target else
                                    patch('inspection.dirty_ext4.' + target, value))
            if fail_detach:
                with self.assertRaisesRegex(Refused, 'cleanup_required'):
                    proof.run()
                self.assertTrue((work / 'owned.ext4').exists())
            elif fail_probe:
                with self.assertRaisesRegex(Refused, 'probe_failure'):
                    proof.run()
                self.assertFalse(work.exists())
            else:
                self.assertEqual(proof.run()['production_cleanliness_refusal'], 'passed')
                self.assertFalse(work.exists())
        self.assertFalse(any(Path(c[0]).name in ('mount', 'umount', 'fsck', 'e2fsck') for c in calls))
        self.assertEqual(sum('--detach' in c for c in calls), 1)
        self.assertEqual(sum('-w' in c for c in calls), 1)
        self.assertTrue(all('journal_run' not in str(c) for c in calls))

    def test_success_uses_only_owned_preparation_then_readonly_probes(self):
        self.execute()

    def test_probe_failure_still_detaches_and_cleans_owned_files(self):
        self.execute(fail_probe=True)

    def test_uncertain_detach_preserves_owned_evidence(self):
        self.execute(fail_detach=True)


if __name__ == '__main__':
    unittest.main()
