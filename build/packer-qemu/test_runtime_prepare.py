"""Synthetic only: no Docker daemon, image, build, service, network, or VM."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import tarfile

import runtime_prepare as prep


NAME = 'labapp-rt-123-1'
ID = 'a' * 64
IMAGE = 'sha256:' + 'b' * 64
VOLUME = {'Name': 'buildx_buildkit_' + NAME + '0_state', 'Driver': 'local', 'CreatedAt': 'fixed'}


class Fake:
    def __init__(self):
        self.builder = self.container = self.volume = True
        self.calls = []
        self.fail = None
        self.builder_info = {'Name': NAME, 'Driver': 'docker-container',
            'Nodes': [{'Name': NAME + '0', 'Endpoint': prep.HOST,
                       'DriverOpts': {'image': prep.BUILDKIT_IMAGE, 'restart-policy': 'no',
                                      'provenance-add-gha': 'false'}}]}
        self.item = {'Id': ID, 'Name': '/buildx_buildkit_' + NAME + '0',
                     'Image': IMAGE, 'Config': {'Image': prep.BUILDKIT_IMAGE},
                     'HostConfig': {'RestartPolicy': {'Name': 'no'}},
                     'Mounts': [{'Type': 'volume', 'Name': VOLUME['Name'], 'Destination': '/var/lib/buildkit'}]}

    def __call__(self, args):
        self.calls.append(args)
        key = tuple(args[:2])
        if key == self.fail:
            raise subprocess.CalledProcessError(1, args)
        if key == ('buildx', 'ls'):
            return json.dumps(self.builder_info) if self.builder else ''
        if key == ('container', 'ls'):
            return ID if self.container else ''
        if key == ('volume', 'ls'):
            return VOLUME['Name'] if self.volume else ''
        if key == ('container', 'inspect'):
            return json.dumps([self.item])
        if key == ('volume', 'inspect'):
            return json.dumps([VOLUME])
        if key == ('buildx', 'rm'):
            self.builder = self.container = self.volume = False
            return ''
        raise AssertionError(args)


def state():
    return {'name': NAME, 'admitted': True}


def archive_bytes(files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as archive:
        for name, raw in files:
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return out.getvalue()


def candidate(out, missing=None, duplicate=None):
    files = ['packages.txt', 'sources.txt', 'policy.txt', 'apt-config.txt',
             'apt-lists.tar', 'keyring.gpg', 'inrelease.sha256', 'indexes.sha256']
    members = [('usr/share/labapp-runtime/' + x, b'synthetic-only\n') for x in files if x != missing]
    if duplicate:
        members += [('usr/share/labapp-runtime/' + duplicate, b'duplicate')]
    layer = archive_bytes(members)
    cfg = json.dumps({'rootfs': {'diff_ids': ['sha256:' + hashlib.sha256(layer).hexdigest()]}}).encode()
    iid = 'sha256:' + hashlib.sha256(cfg).hexdigest()
    manifest = json.dumps([{'Config': 'config.json', 'Layers': ['layer.tar']}]).encode()
    (out / 'image.tar').write_bytes(archive_bytes([('manifest.json', manifest), ('config.json', cfg), ('layer.tar', layer)]))
    (out / 'iid.txt').write_text(iid)
    (out / 'metadata.json').write_text(json.dumps({'containerimage.config.digest': iid}))
    (out / 'Dockerfile').write_text('synthetic-only')


class Ownership(unittest.TestCase):
    def test_cleanup_resolves_ids_before_removal_and_checks_absence(self):
        fake, record = Fake(), state()
        prep.bind(fake, record)
        prep.cleanup(fake, record)
        self.assertEqual(record['cleanup'], 'verified')
        removal = fake.calls.index(['buildx', 'rm', '--force', NAME])
        self.assertTrue(any(x[:2] == ['container', 'inspect'] for x in fake.calls[:removal]))
        self.assertEqual(fake.calls[-1], ['container', 'ls', '-aq', '--no-trunc', '--filter', 'id=' + ID])
        self.assertEqual(record['identity']['container'], ID)

    def test_query_errors_are_never_absence(self):
        for key in [('buildx', 'ls'), ('container', 'ls'), ('volume', 'ls'),
                    ('container', 'inspect'), ('volume', 'inspect')]:
            with self.subTest(key=key):
                fake, record = Fake(), state()
                fake.fail = key
                with self.assertRaises(subprocess.CalledProcessError):
                    prep.cleanup(fake, record)
                self.assertNotIn('cleanup', record)
                self.assertFalse(any(x[:2] == ['buildx', 'rm'] for x in fake.calls))

    def test_successful_json_with_embedded_node_or_builder_error_is_hold(self):
        for node in [False, True]:
            with self.subTest(node=node):
                fake, record = Fake(), state()
                target = fake.builder_info['Nodes'][0] if node else fake.builder_info
                target['Err'] = 'synthetic daemon error'
                with self.assertRaisesRegex(ValueError, 'query error'):
                    prep.cleanup(fake, record)
                self.assertFalse(any(x[:2] == ['buildx', 'rm'] for x in fake.calls))

    def test_real_cli_schema_uses_ls_json_not_unsupported_inspect_format(self):
        fake, record = Fake(), state()
        prep.cleanup(fake, record)
        self.assertIn(['buildx', 'ls', '--format=json'], fake.calls)
        self.assertFalse(any(x[:2] == ['buildx', 'inspect'] for x in fake.calls))

    def test_failed_remove_is_hold(self):
        fake, record = Fake(), state()
        fake.fail = ('buildx', 'rm')
        with self.assertRaises(subprocess.CalledProcessError):
            prep.cleanup(fake, record)
        self.assertNotIn('cleanup', record)

    def test_unattributable_partial_create_is_hold(self):
        fake, record = Fake(), state()
        fake.container = False
        with self.assertRaisesRegex(ValueError, 'orphan'):
            prep.cleanup(fake, record)
        self.assertNotIn('cleanup', record)

    def test_config_only_partial_create_can_be_removed(self):
        fake, record = Fake(), state()
        fake.container = fake.volume = False
        prep.cleanup(fake, record)
        self.assertEqual(record['cleanup'], 'verified')

    def test_exact_identity_change_refuses_mutation(self):
        fake, record = Fake(), state()
        prep.bind(fake, record)
        fake.item['Image'] = 'sha256:' + 'c' * 64
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            prep.cleanup(fake, record)
        self.assertFalse(any(x[:2] == ['buildx', 'rm'] for x in fake.calls))

    def test_wrong_image_mount_restart_name_are_held(self):
        for field, value in [('Name', '/foreign'), ('Config', {'Image': 'moby/buildkit:latest'}),
                             ('Mounts', []), ('HostConfig', {'RestartPolicy': {'Name': 'unless-stopped'}})]:
            with self.subTest(field=field):
                fake, record = Fake(), state()
                fake.item[field] = value
                with self.assertRaises(ValueError):
                    prep.cleanup(fake, record)
                self.assertNotIn('cleanup', record)

    def test_post_remove_query_failure_cannot_publish(self):
        fake, record = Fake(), state()
        def call(args):
            result = fake(args)
            if args[:2] == ['buildx', 'rm']:
                fake.fail = ('container', 'ls')
            return result
        with self.assertRaises(subprocess.CalledProcessError):
            prep.cleanup(call, record)
        self.assertNotIn('cleanup', record)

    def test_full_id_query_failure_or_remaining_id_blocks_publication(self):
        for fault in ['failure', 'remaining']:
            with self.subTest(fault=fault):
                fake, record = Fake(), state()
                def call(args):
                    if args[-1] == 'id=' + ID:
                        if fault == 'failure':
                            raise subprocess.CalledProcessError(1, args)
                        return ID
                    return fake(args)
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    prep.cleanup(call, record)
                self.assertNotIn('cleanup', record)

    def test_cancel_or_timeout_is_not_absence(self):
        for error in [KeyboardInterrupt(), subprocess.TimeoutExpired('docker', 30)]:
            fake, record = Fake(), state()
            def call(args):
                if args[:2] == ['container', 'inspect']:
                    raise error
                return fake(args)
            with self.assertRaises(type(error)):
                prep.cleanup(call, record)
            self.assertNotIn('cleanup', record)

    def test_unverified_builder_pin_refuses_before_any_files_or_query(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.dict(prep.os.environ, {'RUNNER_TEMP': directory}, clear=True), \
             mock.patch.object(prep, 'BUILDKIT_IMAGE', ''), \
             mock.patch.object(prep.sys, 'argv', ['runtime_prepare.py', 'admit']), \
             mock.patch.object(prep, 'docker') as call:
            with self.assertRaisesRegex(ValueError, 'unverified'):
                prep.main()
            call.assert_not_called()
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_client_has_private_config_no_ambient_credentials_and_timeout(self):
        with mock.patch.dict(prep.os.environ, {'DOCKER_CONFIG': '/private/config', 'HOME': '/private/home'}, clear=True), \
             mock.patch.object(prep.subprocess, 'run') as run:
            run.return_value.stdout = b''
            prep.docker(['volume', 'ls'])
        args, kwargs = run.call_args
        self.assertEqual(args[0][:5], ['/usr/bin/docker', '--host', prep.HOST, '--config', '/private/config'])
        self.assertEqual(kwargs['timeout'], 30)
        self.assertTrue(kwargs['check'])
        self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/bin', 'HOME': '/private/home'})


class Export(unittest.TestCase):
    def test_complete_evidence_and_cleanup_are_hash_bound_before_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            out, record = Path(directory), state()
            candidate(out)
            prep.evidence(out, record)
            prep.cleanup(Fake(), record)
            record['dockerfile_sha256'] = prep.digest(out / 'Dockerfile')
            prep.seal(out, record, 'success', 'success')
            sums = (out / 'SHA256SUMS').read_text()
            self.assertIn('  provenance.json\n', sums)
            for line in sums.splitlines():
                expected, name = line.split('  ')
                self.assertEqual(prep.digest(out / name), expected)
            self.assertEqual(json.loads((out / 'provenance.json').read_text())['cleanup'], 'verified')

    def test_no_artifact_seal_for_failure_cancel_timeout_or_unverified_cleanup(self):
        for cleanup in [None, 'failed', 'cancelled', 'timeout', 'hold']:
            with self.subTest(cleanup=cleanup), tempfile.TemporaryDirectory() as directory:
                out, record = Path(directory), state()
                candidate(out)
                prep.evidence(out, record)
                record['cleanup'] = cleanup
                with self.assertRaises(ValueError):
                    prep.seal(out, record, 'success', 'success')
                self.assertFalse((out / 'SHA256SUMS').exists())

    def test_cancellation_after_verified_cleanup_still_blocks_publication(self):
        for job, build in [('cancelled', 'success'), ('failure', 'success'), ('success', 'failure'), ('success', 'cancelled')]:
            with self.subTest(job=job, build=build), tempfile.TemporaryDirectory() as directory:
                out, record = Path(directory), state()
                candidate(out)
                prep.evidence(out, record)
                prep.cleanup(Fake(), record)
                with self.assertRaisesRegex(ValueError, 'cannot publish'):
                    prep.seal(out, record, job, build)
                self.assertFalse((out / 'SHA256SUMS').exists())

    def test_missing_duplicate_provenance_members_refused(self):
        for options in [{'missing': 'packages.txt'}, {'duplicate': 'keyring.gpg'}]:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                candidate(out, **options)
                with self.assertRaises(ValueError):
                    prep.evidence(out, state())

    def test_wrong_iid_layer_hash_metadata_and_corrupt_tar_refused(self):
        for member, value in [('iid.txt', 'sha256:' + '0'*64), ('metadata.json', '{bad'), ('image.tar', 'bad')]:
            with self.subTest(member=member), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                candidate(out)
                (out / member).write_text(value)
                with self.assertRaises((ValueError, tarfile.TarError)):
                    prep.evidence(out, state())

    def test_layer_diffid_and_metadata_binding_fail_closed(self):
        for fault in ['layer', 'metadata']:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                candidate(out)
                if fault == 'layer':
                    with tarfile.open(out / 'image.tar') as archive:
                        files = [(x.name, archive.extractfile(x).read()) for x in archive]
                    files = [(name, raw + b'changed' if name == 'layer.tar' else raw) for name, raw in files]
                    (out / 'image.tar').write_bytes(archive_bytes(files))
                else:
                    (out / 'metadata.json').write_text(json.dumps({'containerimage.config.digest': 'sha256:' + 'c'*64}))
                with self.assertRaises(ValueError):
                    prep.evidence(out, state())

    def test_oversized_nonregular_and_duplicate_tar_members_refused(self):
        for fault in ['oversized', 'link', 'duplicate']:
            with self.subTest(fault=fault):
                raw = io.BytesIO()
                with tarfile.open(fileobj=raw, mode='w') as archive:
                    member = tarfile.TarInfo('fixed')
                    if fault == 'link':
                        member.type, member.linkname = tarfile.SYMTYPE, '/etc/passwd'
                        archive.addfile(member)
                    else:
                        member.size = 100
                        archive.addfile(member, io.BytesIO(b'x'*100))
                        if fault == 'duplicate':
                            archive.addfile(member, io.BytesIO(b'x'*100))
                with tarfile.open(fileobj=io.BytesIO(raw.getvalue())) as archive, self.assertRaises(ValueError):
                    prep.read_member(archive, 'fixed', 10 if fault == 'oversized' else 1000)

    def test_tar_mutation_after_evidence_refuses_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            out, record = Path(directory), state()
            candidate(out)
            prep.evidence(out, record)
            record['cleanup'] = 'verified'
            (out / 'image.tar').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'changed'):
                prep.seal(out, record, 'success', 'success')

    def test_exact_dockerfile_index_hash_command_ignores_apt_directories(self):
        dockerfile = Path(prep.__file__).with_name('runtime') / 'Dockerfile'
        line, = [x for x in dockerfile.read_text().splitlines() if '(cd /var/lib/apt/lists && find ' in x]
        command = line.split('(cd /var/lib/apt/lists && ', 1)[1].split(')', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'partial').mkdir()
            (root / 'auxfiles').mkdir()
            for name in ['test_InRelease', 'test_Packages.lz4']:
                (root / name).write_text('synthetic index')
            result = subprocess.run(['/bin/bash', '-o', 'pipefail', '-c', command], cwd=root,
                env={'PATH': '/usr/bin:/bin'}, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            rows = result.stdout.decode().splitlines()
            self.assertEqual(len(rows), 2)
            for row in rows:
                expected, name = row.split('  ')
                self.assertEqual(prep.digest(root / name), expected)

    def test_no_extraction_or_runtime_execution_in_helper(self):
        source = Path(prep.__file__).read_text()
        self.assertNotIn('.extractall(', source)
        self.assertNotIn("['run',", source)
        self.assertNotIn("['load',", source)
        script = Path(prep.__file__).with_name('runtime-prepare.sh').read_text()
        self.assertIn('type=docker,dest=', script)
        self.assertNotIn('--load', script)
        self.assertIn('provenance-add-gha=false', script)
        self.assertIn('restart-policy=no', script)


if __name__ == '__main__':
    unittest.main()
