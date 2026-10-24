"""Synthetic Docker-daemon state, including lost mutation responses; no Docker."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

RUNNER = Path(__file__).with_name("test-bridge-ipv4.sh")
FAKE_DOCKER = r'''#!/usr/bin/python3
import hashlib
import json
import os
from pathlib import Path
import sys

path = Path(os.environ['FAKE_DOCKER_STATE'])
s = json.loads(path.read_text())
a = sys.argv[1:]
mode = os.environ['FAKE_DOCKER_MODE']
s['calls'].append(a)

def save():
    path.write_text(json.dumps(s))

def option(name):
    return a[a.index(name)+1]

def filtered(objects):
    filters = [a[i+1] for i, v in enumerate(a) if v == '--filter']
    for obj in objects.values():
        match = True
        for f in filters:
            key, val = f.split('=', 1)
            if key == 'name':
                match &= val == '^/' + obj['name'] + '$'
            elif key == 'reference':
                match &= val == obj['name']
            elif key == 'label':
                match &= val == obj['label']
            else:
                raise AssertionError('unsupported filter')
        if match:
            print(obj['id'])

if a[0] == 'version':
    print('synthetic docker')
elif a[0] == 'create':
    name, label = option('--name'), option('--label')
    ident = hashlib.sha256(name.encode()).hexdigest()
    if mode == 'name_collision':
        s['containers'][ident] = {'id': ident, 'name': name, 'label': 'foreign-owner=1'}
        save()
        sys.exit(125)
    s['containers'][ident] = {'id': ident, 'name': name, 'label': label}
    # Same-label nearby names/tags must survive; label alone is insufficient.
    s['containers']['f'*64] = {'id': 'f'*64, 'name': name+'-foreign', 'label': label}
    save()
    if (mode == 'create_lost' and 'prep' in name) or (mode == 'runtime_lost' and 'runtime' in name):
        sys.exit(124)  # Daemon mutation persisted; client supplied no ID.
    print(ident)
elif a[0] == 'start':
    pass  # Never execute the guest command on the host.
elif a[0] == 'inspect':
    print('0')
elif a[0] == 'commit':
    label = option('--change').removeprefix('LABEL ')
    tag = a[-1]
    ident = 'sha256:' + hashlib.sha256(tag.encode()).hexdigest()
    s['images'][ident] = {'id': ident, 'name': tag, 'label': label}
    s['images']['sha256:'+'e'*64] = {'id': 'sha256:'+'e'*64, 'name': tag+'-foreign', 'label': label}
    save()
    if mode == 'commit_lost':
        sys.exit(124)
    print(ident)
elif a[:2] == ['container', 'ls']:
    if mode == 'daemon_down':
        save()
        sys.exit(1)
    filtered(s['containers'])
elif a[:2] == ['image', 'ls']:
    if mode == 'daemon_down':
        save()
        sys.exit(1)
    filtered(s['images'])
elif a[:2] == ['image', 'inspect']:
    print('synthetic image')
elif a[0] == 'rm':
    obj = s['containers'].pop(a[-1])
    assert not obj['name'].endswith('-foreign')
elif a[:2] == ['image', 'rm']:
    target = a[-1]
    matches = [key for key, obj in s['images'].items() if target in (key, obj['name'])]
    assert len(matches) == 1
    obj = s['images'].pop(matches[0])
    assert not obj['name'].endswith('-foreign')
else:
    raise AssertionError(a)
save()
'''


class CleanupTests(unittest.TestCase):
    def run_harness(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "docker"
            fake.write_text(FAKE_DOCKER)
            fake.chmod(0o755)
            state_path = root / "state.json"
            state_path.write_text(json.dumps({"containers": {}, "images": {}, "calls": []}))
            env = dict(os.environ, PATH=str(root)+os.pathsep+os.environ["PATH"],
                       FAKE_DOCKER_STATE=str(state_path), FAKE_DOCKER_MODE=mode)
            result = subprocess.run(["bash", str(RUNNER)], env=env, capture_output=True,
                                    text=True, timeout=10)
            return result, json.loads(state_path.read_text())

    def assert_owned_removed(self, state):
        for objects in (state["containers"], state["images"]):
            self.assertTrue(all(obj["name"].endswith("-foreign") for obj in objects.values()))
        self.assertTrue(state["containers"], "foreign object must survive")
        queries = [a for a in state["calls"] if a[:2] in (["container", "ls"], ["image", "ls"])]
        self.assertTrue(queries)
        for args in queries:
            filters = [args[i+1] for i, value in enumerate(args) if value == "--filter"]
            self.assertEqual(len(filters), 2)
            self.assertTrue(any(value.startswith("label=labapp.bridge-test.run=") for value in filters))
            self.assertTrue(any(value.startswith(("name=^/", "reference=labapp-bridge-test:"))
                                for value in filters))

    def test_success_cleans_owned_resources(self):
        result, state = self.run_harness("success")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_owned_removed(state)

    def test_lost_create_response_recovers_owned_container(self):
        result, state = self.run_harness("create_lost")
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assert_owned_removed(state)
        self.assertFalse(any(a[0] == "start" for a in state["calls"]))

    def test_lost_runtime_create_recovers_all_owned_resources(self):
        result, state = self.run_harness("runtime_lost")
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assert_owned_removed(state)
        self.assertTrue(state["images"], "foreign image must survive")

    def test_lost_commit_response_recovers_owned_image(self):
        result, state = self.run_harness("commit_lost")
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assert_owned_removed(state)
        self.assertTrue(state["images"], "foreign image must survive")

    def test_exact_name_with_foreign_label_is_never_removed(self):
        result, state = self.run_harness("name_collision")
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertEqual(len(state["containers"]), 1)
        self.assertEqual(next(iter(state["containers"].values()))["label"], "foreign-owner=1")
        self.assertFalse(any(a[0] == "rm" for a in state["calls"]))

    def test_daemon_query_failure_is_cleanup_failure_not_absence(self):
        result, state = self.run_harness("daemon_down")
        self.assertEqual(result.returncode, 1)
        self.assertIn("owned cleanup failed", result.stderr)
        self.assertTrue(any(not obj["name"].endswith("-foreign") for obj in state["containers"].values()))
        self.assertFalse(any(a[0] == "rm" or a[:2] == ["image", "rm"] for a in state["calls"]))


if __name__ == "__main__":
    unittest.main()
