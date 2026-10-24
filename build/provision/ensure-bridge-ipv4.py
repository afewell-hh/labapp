#!/usr/bin/python3
"""Runtime primitive, not an installer. Invoke with python3 (Ubuntu 24.04 / 3.12).
Requires Linux, iproute2 at a fixed system path, root or CAP_NET_ADMIN in the
current network namespace. No sudo, downloads, service changes or env overrides.
Cwd independent; children get only fixed PATH and LC_ALL=C, no shell or stdin.
All four arguments are required. The monotonic wait budget covers discovery,
addition and verification (1..600s); poll is 50..10000ms, at most the budget.
Each child has <=3s and <=64KiB combined output; errors use fixed diagnostics.
Only adds the exact CIDR; never deletes/replaces/flushes or raises a link.
An add failure ALWAYS fails, even if another writer concurrently added it.
Identity is checked by name, ifindex and bridge kind before/after address work;
callers must exclude concurrent link renames/deletion/recreation during mutation
(the separate ip invocations cannot provide an atomic identity transaction).
"""

import argparse
import ipaddress
import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import time

SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
OUTPUT_LIMIT = 65536
CHILD_SECONDS = 3


class Failure(Exception):
    """Only fixed public diagnostic strings belong here."""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Failure("invalid arguments")


def arguments(argv):
    parser = Parser(description="Ensure one explicit IPv4 CIDR on an existing Linux bridge.",
                    allow_abbrev=False)
    parser.add_argument("--bridge", required=True)
    parser.add_argument("--cidr", required=True)
    parser.add_argument("--wait-seconds", required=True)
    parser.add_argument("--poll-ms", required=True)
    # Reject duplicates rather than silently letting the last value win.
    if any(argv.count(flag) != 1 for flag in
           ("--bridge", "--cidr", "--wait-seconds", "--poll-ms")):
        if argv != ["--help"]:
            raise Failure("invalid arguments")
    opts = parser.parse_args(argv)
    # Conservative Linux interface-name subset; excludes options, aliases,
    # numeric ifindex ambiguity, special all/default targets and glob syntax.
    if (not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,14}", opts.bridge)
            or opts.bridge in ("all", "default")):
        raise Failure("invalid bridge identifier")
    try:
        cidr = ipaddress.IPv4Interface(opts.cidr)
    except ValueError:
        raise Failure("invalid IPv4 CIDR") from None
    if str(cidr) != opts.cidr:
        raise Failure("invalid IPv4 CIDR")
    for field in ("wait_seconds", "poll_ms"):
        if not re.fullmatch(r"[1-9][0-9]{0,4}", getattr(opts, field)):
            raise Failure("invalid timing bounds")
        setattr(opts, field, int(getattr(opts, field)))
    if not (1 <= opts.wait_seconds <= 600
            and 50 <= opts.poll_ms <= min(10000, opts.wait_seconds * 1000)):
        raise Failure("invalid timing bounds")
    return opts, cidr


def command(ip, args, deadline):
    """Drain bounded output incrementally; communicate() alone is unbounded."""
    end = min(deadline, time.monotonic() + CHILD_SECONDS)
    if time.monotonic() >= end:
        raise Failure("deadline exceeded")
    try:
        child = subprocess.Popen([ip, *args], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 env={"PATH": SYSTEM_PATH, "LC_ALL": "C"}, cwd="/")
    except OSError:
        raise Failure("cannot execute iproute2") from None
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise Failure("iproute2 command timed out")
                if not selector.select(remaining):
                    raise Failure("iproute2 command timed out")
                chunk = os.read(child.stdout.fileno(), 8192)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > OUTPUT_LIMIT:
                    raise Failure("iproute2 output limit exceeded")
        try:
            status = child.wait(timeout=max(0, end - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise Failure("iproute2 command timed out") from None
        return status, bytes(output)
    finally:
        if child.poll() is None:
            child.kill()
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            raise Failure("cannot reap iproute2 child") from None
        finally:
            child.stdout.close()


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError
        obj[key] = value
    return obj


def reject_constant(value):
    raise ValueError


def snapshot(ip, bridge, deadline, *, addresses=False, missing_ok=False):
    args = ["-j", "-d"]
    args += ["address"] if addresses else ["link"]
    status, raw = command(ip, [*args, "show", "dev", bridge], deadline)
    if status:
        # Only this exact, locale-fixed iproute2 missing-device response retries.
        if (missing_ok and status == 1
                and raw == f'Device "{bridge}" does not exist.\n'.encode("ascii")):
            return None
        raise Failure("iproute2 query failed")
    try:
        data = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
        if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
            raise ValueError
        link = data[0]
        if (link["ifname"] != bridge or type(link["ifindex"]) is not int
                or link["ifindex"] <= 0):
            raise ValueError
        kind = link.get("linkinfo", {}).get("info_kind")
        if kind != "bridge":
            raise Failure("requested interface is not a Linux bridge")
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise Failure("invalid iproute2 JSON") from None
    return link


def same_identity(link, identity):
    if link["ifindex"] != identity:
        raise Failure("bridge identity changed")


def has_address(link, cidr):
    """Reject a conflicting prefix even if the exact address also exists."""
    try:
        entries = link["addr_info"]
        if not isinstance(entries, list):
            raise ValueError
        found = False
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError
            family = entry["family"]
            if family not in ("inet", "inet6"):
                raise ValueError
            local, prefix = entry["local"], entry["prefixlen"]
            address_type = ipaddress.IPv4Address if family == "inet" else ipaddress.IPv6Address
            if (not isinstance(local, str) or str(address_type(local)) != local
                    or type(prefix) is not int or not 0 <= prefix <= (32 if family == "inet" else 128)):
                raise ValueError
            if family == "inet" and local == str(cidr.ip):
                if prefix != cidr.network.prefixlen:
                    raise Failure("address has a conflicting prefix")
                found = True
        return found
    except (KeyError, TypeError, ValueError):
        raise Failure("invalid iproute2 JSON") from None


def ensure(opts, cidr):
    ip = shutil.which("ip", path=SYSTEM_PATH)
    if ip is None:
        raise Failure("iproute2 is required")
    deadline = time.monotonic() + opts.wait_seconds
    while True:
        if time.monotonic() >= deadline:
            raise Failure("bridge wait timed out")
        link = snapshot(ip, opts.bridge, deadline, missing_ok=True)
        if link is not None:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Failure("bridge wait timed out")
        time.sleep(min(opts.poll_ms / 1000, remaining))
    identity = link["ifindex"]
    link = snapshot(ip, opts.bridge, deadline, addresses=True)
    same_identity(link, identity)
    present = has_address(link, cidr)
    if not present:
        # Recheck identity immediately before the only mutating operation.
        same_identity(snapshot(ip, opts.bridge, deadline), identity)
        status, _ = command(ip, ["-4", "address", "add", str(cidr),
                                 "dev", opts.bridge], deadline)
        if status:
            raise Failure("address add failed")
    link = snapshot(ip, opts.bridge, deadline, addresses=True)
    same_identity(link, identity)
    if not has_address(link, cidr):
        raise Failure("address postcondition failed")
    if time.monotonic() >= deadline:
        raise Failure("deadline exceeded")


def main(argv=None):
    try:
        opts, cidr = arguments(sys.argv[1:] if argv is None else argv)
        ensure(opts, cidr)
    except Failure as exc:
        print(f"ensure-bridge-ipv4: ERROR: {exc}", file=sys.stderr)
        return 1
    except OSError:
        print("ensure-bridge-ipv4: ERROR: operating system failure", file=sys.stderr)
        return 1
    print("ensure-bridge-ipv4: verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
