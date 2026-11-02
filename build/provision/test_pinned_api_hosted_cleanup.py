"""Synthetic offline controls for the pinned API hosted wrapper's cleanup diagnostics.

The cleanup functions are extracted verbatim from fixtures/pinned-api/run-hosted.sh
(from ``containers() {`` up to ``trap finish EXIT``) and run by bash with a fake
``docker`` shell function, so no Docker, network, cloud or credential is used. Only
the ``docker`` timeout wrapper is replaced; selectors, ID checks, scratch identity
and exit logic are the production text. A fake plan maps a call key to
``rc:N`` (exit status) or ``out:TEXT`` (stdout, ``\\n`` expands to a newline).
Keys: c-prep-N / c-runtime-N (Nth container ls), rm, i-N (Nth image ls), imgrm.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / 'fixtures' / 'pinned-api' / 'run-hosted.sh'
CID = 'a' * 64
CID2 = 'c' * 64
IMG = 'sha256:' + 'b' * 64
SECRET = 'UNLISTED_SECRET_MUST_NOT_PRINT'

HARNESS_PREFIX = r'''
set -euo pipefail
suffix=TESTSFX
label="labapp.pinned-api=$suffix"
prep="labapp-pinned-api-prep-$suffix"
runtime="labapp-pinned-api-runtime-$suffix"
tag="labapp-pinned-api:$suffix"
scratch=$SCRATCH
identity=$(stat -c %d:%i:%u:%a -- "$scratch" 2>/dev/null || echo none)
if [[ ${IDENT_MODE:-} == bad ]]; then identity=bad:0:0:0; fi
if [[ ${STAT_FAIL:-0} == 1 ]]; then : > "$COUNTDIR/armed"; fi
prep_pending=${PREP_PENDING:-0}
runtime_pending=${RUNTIME_PENDING:-0}
commit_pending=${COMMIT_PENDING:-0}
rm() {
  case ${RM_MODE:-real} in fail) return 3 ;; noop) return 0 ;; *) command rm "$@" ;; esac
}
stat() {
  if [[ ${STAT_FAIL:-0} == 1 && -f $COUNTDIR/armed ]]; then return 5; fi
  command stat "$@"
}
bump() {
  local f=$COUNTDIR/$1 n=0
  if [[ -f $f ]]; then n=$(<"$f"); fi
  n=$((n + 1)); echo "$n" > "$f"; echo "$n"
}
plan() {
  local line
  action=
  while IFS= read -r line; do
    if [[ $line == "$1="* ]]; then action=${line#*=}; return 0; fi
  done <<< "${FAKE_PLAN:-}"
}
docker() {
  local k w=prep
  case "$1 $2" in
    "container ls")
      if [[ "$*" == *"$runtime"* ]]; then w=runtime; fi
      k=c-$w-$(bump "c-$w") ;;
    "image ls") k=i-$(bump i) ;;
    "image rm") k=imgrm; echo "image rm $3" >> "$COUNTDIR/calls" ;;
    "rm -f") k=rm; echo "rm $3" >> "$COUNTDIR/calls" ;;
    *) echo "unexpected docker call" >&2; return 99 ;;
  esac
  plan "$k"
  case $action in
    rc:*) return "${action#rc:}" ;;
    out:*) printf '%b\n' "${action#out:}" ;;
  esac
}
'''


def harness():
    text = SCRIPT.read_text()
    body = text[text.index('containers() {'):text.index('trap finish EXIT')]
    return HARNESS_PREFIX + body + '\ntrap finish EXIT\nexit "$PRIMARY"\n'


class HostedCleanupDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.counts = self.root / 'counts'
        self.counts.mkdir()
        self.scratch = self.root / 'labapp-pinned-api.TESTSFX'
        self.scratch.mkdir(mode=0o700)
        (self.scratch / 'home').mkdir()
        self.script = self.root / 'harness.sh'
        self.script.write_text(harness())

    def run_cleanup(self, plan='', primary=0, recreate=True, **extra):
        # Each run starts with fresh call counters and, unless told otherwise, a fresh scratch.
        for item in self.counts.iterdir():
            item.unlink()
        if recreate and not os.path.lexists(self.scratch):
            self.scratch.mkdir(mode=0o700)
        env = {'PATH': os.environ['PATH'], 'SCRATCH': str(self.scratch), 'COUNTDIR': str(self.counts),
               'FAKE_PLAN': plan, 'PRIMARY': str(primary), 'AWS_SECRET_ACCESS_KEY': SECRET}
        env.update({k: str(v) for k, v in extra.items()})
        result = subprocess.run(['bash', str(self.script)], env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, timeout=30)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        return result

    def calls(self):
        path = self.counts / 'calls'
        return path.read_text().splitlines() if path.exists() else []

    def assert_stage(self, result, stage, status, outcome):
        line = 'Pinned API cleanup stage=%s status=%s outcome=%s' % (stage, status, outcome)
        self.assertIn(line, result.stderr.splitlines(), result.stderr)

    def assert_unverified(self, result, code=1):
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertIn('Pinned API owned cleanup unverified', result.stderr)
        self.assertNotIn('absent', result.stdout)

    def test_clean_run_reports_absence_and_removes_only_exact_scratch(self):
        result = self.run_cleanup('c-runtime-1=out:%s\nc-prep-1=out:%s\ni-1=out:%s' % (CID, CID2, IMG))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Pinned API exact containers/image/host scratch absent', result.stdout)
        self.assertEqual(self.calls(), ['rm ' + CID, 'rm ' + CID2, 'image rm ' + IMG])
        self.assertFalse(self.scratch.exists())
        for stage in ('runtime-container', 'prep-container'):
            self.assert_stage(result, stage + '-verify', 0, 'absent')
        self.assert_stage(result, 'image-verify', 0, 'absent')
        self.assert_stage(result, 'scratch-verify', 0, 'absent')

    def test_command_failure_and_timeout_are_distinct_per_stage(self):
        for status, outcome in ((1, 'command-failed'), (124, 'timeout'), (137, 'timeout'), (125, 'command-failed')):
            with self.subTest(select=status):
                result = self.run_cleanup('c-runtime-1=rc:%d' % status)
                self.assert_unverified(result)
                self.assert_stage(result, 'runtime-container-select', status, outcome)
        for status, outcome in ((1, 'command-failed'), (124, 'timeout')):
            with self.subTest(prep_verify=status):
                (self.counts / 'c-prep').unlink(missing_ok=True)
                result = self.run_cleanup('c-prep-1=out:%s\nc-prep-2=rc:%d' % (CID, status))
                self.assert_unverified(result)
                self.assert_stage(result, 'prep-container-remove', 0, 'command-ok')
                self.assert_stage(result, 'prep-container-verify', status, outcome)
            with self.subTest(image_select=status):
                result = self.run_cleanup('i-1=rc:%d' % status)
                self.assert_unverified(result)
                self.assert_stage(result, 'image-select', status, outcome)
            with self.subTest(image_verify=status):
                (self.counts / 'i').unlink(missing_ok=True)
                result = self.run_cleanup('i-2=rc:%d' % status)
                self.assert_unverified(result)
                self.assert_stage(result, 'image-verify', status, outcome)

    def test_remove_command_failure_and_timeout_are_reported_without_absence_claim(self):
        for status, outcome in ((1, 'command-failed'), (124, 'timeout')):
            with self.subTest(status=status):
                result = self.run_cleanup('c-runtime-1=out:%s\nrm=rc:%d' % (CID, status))
                self.assert_unverified(result)
                self.assert_stage(result, 'runtime-container-remove', status, outcome)
                (self.counts / 'c-runtime').unlink(missing_ok=True)
                (self.counts / 'c-prep').unlink(missing_ok=True)
                result = self.run_cleanup('i-1=out:%s\nimgrm=rc:%d' % (IMG, status))
                self.assert_unverified(result)
                self.assert_stage(result, 'image-remove', status, outcome)
                (self.counts / 'i').unlink(missing_ok=True)

    def test_malformed_and_multiple_ids_are_distinct_and_never_removed(self):
        cases = (('not-an-id', 'malformed-id'), (CID[:63], 'malformed-id'), (CID.upper(), 'malformed-id'),
                 ('%s\\n%s' % (CID, CID2), 'multiple-ids'), ('%s\\n%s' % (CID, SECRET), 'multiple-ids'),
                 (SECRET, 'malformed-id'))
        for text, outcome in cases:
            with self.subTest(text=text[:12]):
                result = self.run_cleanup('c-runtime-1=out:' + text)
                self.assert_unverified(result)
                self.assert_stage(result, 'runtime-container-select', 0, outcome)
                self.assertEqual(self.calls(), [])
        for text, outcome in ((CID, 'malformed-id'), ('%s\\n%s' % (IMG, IMG), 'multiple-ids'), ('sha256:short', 'malformed-id')):
            with self.subTest(image=text[:12]):
                result = self.run_cleanup('i-1=out:' + text)
                self.assert_unverified(result)
                self.assert_stage(result, 'image-select', 0, outcome)
                self.assertEqual(self.calls(), [])

    def test_still_present_objects_are_reported_after_removal_attempt(self):
        result = self.run_cleanup('c-runtime-1=out:%s\nc-runtime-2=out:%s' % (CID, CID))
        self.assert_unverified(result)
        self.assert_stage(result, 'runtime-container-remove', 0, 'command-ok')
        self.assert_stage(result, 'runtime-container-verify', 0, 'still-present')
        self.assertEqual(self.calls(), ['rm ' + CID])
        (self.counts / 'c-runtime').unlink(missing_ok=True)
        (self.counts / 'calls').unlink()
        result = self.run_cleanup('i-1=out:%s\ni-2=out:%s' % (IMG, IMG))
        self.assert_unverified(result)
        self.assert_stage(result, 'image-remove', 0, 'command-ok')
        self.assert_stage(result, 'image-verify', 0, 'still-present')

    def test_outstanding_create_or_commit_uncertainty_fails_without_absence_claim(self):
        for flag in ('PREP_PENDING', 'RUNTIME_PENDING', 'COMMIT_PENDING'):
            with self.subTest(flag=flag):
                result = self.run_cleanup(**{flag: 1})
                self.assert_unverified(result)
                self.assert_stage(result, 'create-commit-uncertain', 0, 'outstanding')
                self.assert_stage(result, 'scratch-verify', 0, 'absent')
                self.scratch.mkdir(mode=0o700, exist_ok=True)

    def test_scratch_identity_failures_preserve_the_directory(self):
        (self.scratch / 'keep').write_text('x')
        result = self.run_cleanup(IDENT_MODE='bad')
        self.assert_unverified(result)
        self.assert_stage(result, 'scratch-identity', 0, 'identity-mismatch')
        self.assertTrue((self.scratch / 'keep').exists())
        self.assertNotIn('scratch-remove', result.stderr)
        result = self.run_cleanup(STAT_FAIL=1)
        self.assert_unverified(result)
        self.assert_stage(result, 'scratch-identity', 5, 'stat-failed')
        self.assertTrue((self.scratch / 'keep').exists())
        target = self.root / 'target'
        target.mkdir()
        (target / 'keep').write_text('x')
        self.scratch.rename(self.root / 'moved')
        self.scratch.symlink_to(target)
        result = self.run_cleanup()
        self.assert_unverified(result)
        self.assert_stage(result, 'scratch-identity', 0, 'not-owned-directory')
        self.assertTrue((target / 'keep').exists())
        self.scratch.unlink()
        result = self.run_cleanup(recreate=False)
        self.assert_unverified(result)
        self.assert_stage(result, 'scratch-identity', 0, 'not-owned-directory')

    def test_scratch_removal_failure_and_survival_are_distinct(self):
        result = self.run_cleanup(RM_MODE='fail')
        self.assert_unverified(result)
        self.assert_stage(result, 'scratch-remove', 3, 'command-failed')
        self.assert_stage(result, 'scratch-verify', 0, 'still-present')
        result = self.run_cleanup(RM_MODE='noop')
        self.assert_unverified(result)
        self.assert_stage(result, 'scratch-remove', 0, 'command-ok')
        self.assert_stage(result, 'scratch-verify', 0, 'still-present')
        self.assertTrue(self.scratch.exists())

    def test_primary_failure_status_is_preserved_and_cleanup_failure_alone_is_one(self):
        for primary in (2, 7, 130, 143):
            with self.subTest(primary=primary, cleanup='verified'):
                result = self.run_cleanup(primary=primary)
                self.assertEqual(result.returncode, primary, result.stderr)
                self.assert_stage(result, 'primary', primary, 'recorded')
                self.scratch.mkdir(mode=0o700, exist_ok=True)
            with self.subTest(primary=primary, cleanup='unverified'):
                result = self.run_cleanup('c-runtime-1=rc:124', primary=primary)
                self.assert_unverified(result, primary)
                self.assert_stage(result, 'primary', primary, 'recorded')
                self.assert_stage(result, 'runtime-container-select', 124, 'timeout')
                (self.counts / 'c-runtime').unlink(missing_ok=True)
        result = self.run_cleanup('c-runtime-1=rc:124', primary=0)
        self.assert_unverified(result, 1)

    def test_diagnostics_contain_only_fixed_vocabulary(self):
        result = self.run_cleanup('c-runtime-1=out:%s\\n%s\ni-1=out:%s' % (SECRET, CID, SECRET), primary=3)
        self.assert_unverified(result, 3)
        allowed = re.compile(r'^Pinned API cleanup stage=[a-z-]+ status=\d+ outcome=[a-z-]+$')
        lines = [x for x in result.stderr.splitlines() if x != 'Pinned API owned cleanup unverified']
        self.assertTrue(lines)
        for line in lines:
            self.assertRegex(line, allowed)
        self.assertNotIn(CID, result.stderr)

    def test_wrapper_keeps_selectors_and_helper_deadline(self):
        text = SCRIPT.read_text()
        self.assertIn('timeout --kill-after=1s 5s docker "$@"', text)
        self.assertIn('--filter "name=^/${1}$" --filter "label=$label"', text)
        self.assertIn('--filter "reference=$tag" --filter "label=$label"', text)
        self.assertIn('=~ ^[a-f0-9]{64}$', text)
        self.assertIn('=~ ^sha256:[a-f0-9]{64}$', text)
        self.assertIn('%d:%i:%u:%a', text)
        self.assertNotIn('retry', text.lower())


if __name__ == '__main__':
    unittest.main()
