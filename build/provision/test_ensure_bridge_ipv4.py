"""Public synthetic fixtures only; never inspects or mutates host networking."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "bridge_runtime", Path(__file__).with_name("ensure-bridge-ipv4.py"))
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)
ARGS = ["--bridge", "testbr0", "--cidr", "192.0.2.2/24",
        "--wait-seconds", "2", "--poll-ms", "50"]
LINK = {"ifindex": 7, "ifname": "testbr0", "linkinfo": {"info_kind": "bridge"}}
ADDRESS = {"family": "inet", "local": "192.0.2.2", "prefixlen": 24}


def row(*entries, index=7):
    link = copy.deepcopy(LINK)
    link.update(ifindex=index, addr_info=list(entries))
    return link


def reply(link):
    return 0, json.dumps([link]).encode()


class RuntimeTests(unittest.TestCase):
    def run_case(self, responses, argv=ARGS):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(helper.shutil, "which", return_value="/usr/sbin/ip"), \
                patch.object(helper, "command", side_effect=responses) as command, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = helper.main(argv)
        return result, out.getvalue(), err.getvalue(), command

    def assert_failure(self, responses, diagnostic):
        result, out, err, command = self.run_case(responses)
        self.assertEqual(result, 1)
        self.assertEqual(out, "")
        self.assertEqual(err, f"ensure-bridge-ipv4: ERROR: {diagnostic}\n")
        return command

    def test_validation_precedes_dependencies_and_commands(self):
        bad = [("--bridge", value) for value in
               ("", "-bad", "12", "all", "default", "lo:1", "a/b", "a b", "a"*16, "é")]
        bad += [("--cidr", value) for value in
                ("192.0.2.2", "192.000.2.2/24", "192.0.2.2/024", "192.0.2.2/255.255.255.0",
                 "192.0.2.2/33", "::1/128", "192.0.2.2/24\n", "x")]
        bad += [(flag, value) for flag in ("--wait-seconds", "--poll-ms")
                for value in ("0", "-1", "nan", "inf", "01", "1.5", "999999", " 50")]
        bad += [("--wait-seconds", "601"), ("--poll-ms", "49"), ("--poll-ms", "10001"),
                ("--poll-ms", "2001")]
        with patch.object(helper, "ensure") as ensure:
            for flag, value in bad:
                args = ARGS.copy()
                args[args.index(flag)+1] = value
                with self.subTest(flag=flag, value=value), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(helper.main(args), 1)
            for args in ([], ARGS[:-2], ARGS+["--bridge", "again"], ARGS+["--wat", "x"],
                         ["--brid", "x"]+ARGS[2:]):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(helper.main(args), 1)
            ensure.assert_not_called()

    def test_canonical_host_cidr_boundaries(self):
        for cidr in ("192.0.2.2/0", "192.0.2.2/31", "192.0.2.2/32"):
            args = ARGS.copy()
            args[3] = cidr
            self.assertEqual(str(helper.arguments(args)[1]), cidr)

    def test_missing_dependency(self):
        with patch.object(helper.shutil, "which", return_value=None), \
                patch.object(helper, "command") as command:
            with self.assertRaisesRegex(helper.Failure, "iproute2 is required"):
                helper.ensure(*helper.arguments(ARGS))
            command.assert_not_called()

    def test_add_and_verify_only_allowed_mutation(self):
        rc, out, err, command = self.run_case([
            reply(LINK), reply(row()), reply(LINK), (0, b""), reply(row(ADDRESS))])
        self.assertEqual((rc, out, err), (0, "ensure-bridge-ipv4: verified\n", ""))
        calls = [call.args[1] for call in command.call_args_list]
        self.assertEqual(calls[3], ["-4", "address", "add", "192.0.2.2/24", "dev", "testbr0"])
        self.assertTrue(all("show" in args for args in calls[:3]+calls[4:]))

    def test_idempotent_exact_address(self):
        rc, _, _, command = self.run_case([reply(LINK), reply(row(ADDRESS)), reply(row(ADDRESS))])
        self.assertEqual(rc, 0)
        self.assertEqual(command.call_count, 3)
        self.assertTrue(all("show" in call.args[1] for call in command.call_args_list))

    def test_valid_ipv6_is_preserved_and_ignored(self):
        other = {"family": "inet6", "local": "2001:db8::2", "prefixlen": 64}
        rc, _, _, _ = self.run_case([
            reply(LINK), reply(row(other)), reply(LINK), (0, b""), reply(row(other, ADDRESS))])
        self.assertEqual(rc, 0)

    def test_substring_is_not_exact(self):
        other = dict(ADDRESS, local="192.0.2.20")
        rc, _, _, command = self.run_case([
            reply(LINK), reply(row(other)), reply(LINK), (0, b""), reply(row(other, ADDRESS))])
        self.assertEqual(rc, 0)
        self.assertIn("add", command.call_args_list[3].args[1])

    def test_conflicting_prefix_never_mutates(self):
        for entries in ([dict(ADDRESS, prefixlen=25)], [ADDRESS, dict(ADDRESS, prefixlen=25)]):
            command = self.assert_failure([reply(LINK), reply(row(*entries))],
                                          "address has a conflicting prefix")
            self.assertEqual(command.call_count, 2)

    def test_add_failure_even_if_race_could_have_added(self):
        command = self.assert_failure([reply(LINK), reply(row()), reply(LINK), (2, b"CANARY")],
                                      "address add failed")
        self.assertEqual(command.call_count, 4)

    def test_postcondition_missing_and_conflict(self):
        self.assert_failure([reply(LINK), reply(row()), reply(LINK), (0, b""), reply(row())],
                            "address postcondition failed")
        self.assert_failure([reply(LINK), reply(row()), reply(LINK), (0, b""),
                             reply(row(dict(ADDRESS, prefixlen=25)))],
                            "address has a conflicting prefix")

    def test_identity_changes_before_and_after_mutation(self):
        self.assert_failure([reply(LINK), reply(row(index=8))], "bridge identity changed")
        self.assert_failure([reply(LINK), reply(row()), reply(dict(LINK, ifindex=8))],
                            "bridge identity changed")
        self.assert_failure([reply(LINK), reply(row()), reply(LINK), (0, b""),
                             reply(row(ADDRESS, index=8))], "bridge identity changed")

    def test_nonbridge_rejected(self):
        for kind in ("dummy", "veth", None):
            link = dict(LINK, linkinfo={"info_kind": kind})
            self.assert_failure([reply(link)], "requested interface is not a Linux bridge")

    def test_query_errors_fail_fast_and_do_not_echo(self):
        for status, raw in ((2, b"CANARY"), (1, b"Operation not permitted\n"),
                            (1, b'Device "other" does not exist.\n')):
            command = self.assert_failure([(status, raw)], "iproute2 query failed")
            self.assertEqual(command.call_count, 1)

    def test_missing_then_created(self):
        missing = (1, b'Device "testbr0" does not exist.\n')
        with patch.object(helper.time, "sleep") as sleep:
            rc, _, _, _ = self.run_case([missing, reply(LINK), reply(row(ADDRESS)), reply(row(ADDRESS))])
            self.assertEqual(rc, 0)
            sleep.assert_called_once()

    def test_missing_retries_end_at_deadline(self):
        opts, cidr = helper.arguments(ARGS)
        clock = [0.0]
        def sleep(seconds):
            clock[0] += seconds
        with patch.object(helper.shutil, "which", return_value="/usr/sbin/ip"), \
                patch.object(helper.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(helper.time, "sleep", side_effect=sleep), \
                patch.object(helper, "command", return_value=(1, b'Device "testbr0" does not exist.\n')):
            with self.assertRaisesRegex(helper.Failure, "bridge wait timed out"):
                helper.ensure(opts, cidr)
        self.assertLessEqual(clock[0], 2)

    def test_bad_json_structure(self):
        for raw in (b'[{"ifindex":7,"ifindex":7}]', b'{"bad":NaN}', b"CANARY", b"[", b"{}", b"[]", b"[{},{}]", b"[null]", b"\xff",
                    json.dumps([dict(LINK, ifindex=True)]).encode(),
                    json.dumps([dict(LINK, ifname="CANARY")]).encode(),
                    json.dumps([dict(LINK, linkinfo=[])]).encode()):
            self.assert_failure([(0, raw)], "invalid iproute2 JSON")

    def test_bad_address_json(self):
        for value in (None, {}, [None], [{}], [dict(ADDRESS, prefixlen=True)],
                      [dict(ADDRESS, prefixlen=33)], [dict(ADDRESS, local="CANARY")],
                      [dict(ADDRESS, family="inet6")]):
            self.assert_failure([reply(LINK), reply(dict(LINK, addr_info=value))],
                                "invalid iproute2 JSON")


class ChildTests(unittest.TestCase):
    def call(self, code, budget=2):
        return helper.command(sys.executable, ["-c", code], time.monotonic()+budget)

    def test_child_output_and_return(self):
        self.assertEqual(self.call("import sys; print('ok'); sys.exit(2)"), (2, b"ok\n"))

    def test_child_fixed_environment_and_cwd(self):
        status, output = self.call("import os; print(os.getcwd()); print(os.environ['LC_ALL']); "
                                   "print(os.environ['PATH'])")
        self.assertEqual(status, 0)
        self.assertEqual(output, f"/\nC\n{helper.SYSTEM_PATH}\n".encode())

    def test_child_timeout_and_reaping(self):
        start = time.monotonic()
        with self.assertRaisesRegex(helper.Failure, "iproute2 command timed out"):
            self.call("import time; time.sleep(5)", budget=0.1)
        self.assertLess(time.monotonic()-start, 1)

    def test_output_limit_including_stderr(self):
        for stream in ("1", "2"):
            with self.assertRaisesRegex(helper.Failure, "iproute2 output limit exceeded"):
                self.call(f"import os; os.write({stream}, b'x'*70000)")

    def test_execution_failure_and_expired_deadline(self):
        with self.assertRaisesRegex(helper.Failure, "cannot execute iproute2"):
            helper.command("/nonexistent/public-test-ip", [], time.monotonic()+1)
        with self.assertRaisesRegex(helper.Failure, "deadline exceeded"):
            helper.command(sys.executable, [], time.monotonic()-1)


if __name__ == "__main__":
    unittest.main()
