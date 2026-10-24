# Provisioning modules (`build/provision/`)

Provisioning modules and standalone runtime artifacts. Provisioning modules use
the same file for development testing and, later, Packer `shell` provisioning. `install-k3d.sh` is the binary-install pilot (#148/#149);
`ensure-bridge-ipv4.py` is a separate runtime artifact (#204). `cloud-config.yaml` is unchanged and does not call these
modules yet. A complete Packer build or provisioning framework does not exist;
the broader mechanism is still provisional (see #145).

`install-k3d.sh` installs a pinned k3d release binary (v5.7.4, linux/amd64,
SHA256 verified, noninteractive).

```bash
# Install (override K3D_INSTALL_DIR to isolate; default /usr/local/bin)
K3D_INSTALL_DIR=/tmp/k3d-test bash build/provision/install-k3d.sh
# Disposable Ubuntu 24.04 container test of the real module (needs docker + network).
# Runs the suite in 2 separate fresh containers by default (pass N to change), printing
# base image id/digest, os-release, per-check PASS/FAIL and per-run timing. Containers
# mount only build/provision read-only: no Docker socket or host credentials.
bash build/provision/test-install-k3d.sh
# Optional immutable base image; CI sets this to a verified Ubuntu 24.04 digest.
K3D_TEST_IMAGE=ubuntu@sha256:YOUR_DIGEST bash build/provision/test-install-k3d.sh
```

Static checks. `bash -n` parses only its first file argument (later names
become positional arguments), so run it once per file:

```bash
for f in build/provision/*.sh; do bash -n "$f" || exit 1; done
shellcheck -x build/provision/*.sh
```

The download is bounded: 120s per attempt (K3D_DOWNLOAD_MAX_TIME), aborted
under 1 KiB/s for 30s, 3 retries, 600s hard cap overall
(K3D_DOWNLOAD_TOTAL_TIMEOUT). The test covers clean install, idempotent rerun,
repair of a preseeded non-executable (0644) matching binary, bad-digest,
unavailable-download and stalled-download failures that preserve an existing
binary, and unsupported-architecture failure. It does not verify Docker, a k3d
cluster, systemd, cloud-init, nested KVM or VLAB.

## Contract for new modules

Follow the execution contract in
[`docs/contributing/agent-workflow.md`](../../docs/contributing/agent-workflow.md#same-code-execution-contract).
Each module's header comment states its interpreter, required privileges,
environment overrides and dependencies, and its tests assert them.

## Explicit bridge IPv4 runtime helper

`ensure-bridge-ipv4.py` ensures one caller-specified IPv4 host address and prefix
on one existing Linux bridge. It is a new functional component, not a recovered
image helper or a claim of historical equivalence. It is not called by Packer,
cloud-init, a service, or the current image. Service integration and actual image
network values require separate acceptance. The example uses public synthetic
parameters, not appliance topology:

```bash
# Inside the intended network namespace, as root or with CAP_NET_ADMIN:
python3 /absolute/path/to/ensure-bridge-ipv4.py \
  --bridge testbr0 --cidr 192.0.2.2/24 --wait-seconds 10 --poll-ms 100
# Offline: synthetic inputs and child-process tests, no host networking access.
python3 -m unittest discover -s build/provision -p test_ensure_bridge_ipv4.py -v
# Docker and package-download network access needed for preparation only.
bash build/provision/test-bridge-ipv4.sh
```

All four options are required exactly once, using the displayed separate-value
form; abbreviated options and `--option=value` are rejected. Bridge names use
ASCII letters first, then letters/digits/underscore/dot/hyphen, at most 15 bytes;
`all`, `default`, numeric names, aliases, patterns and option-like names are
rejected. CIDRs must equal Python's canonical `IPv4Interface` string (explicit
numeric prefix, no leading zeros or netmask notation). Host bits are retained;
this is an interface address, not a network declaration. Prefixes 0..32 are
supported. Wait is an integer 1..600 seconds; poll is an integer 50..10000 ms
and cannot exceed the wait budget. Validation finishes before any network command.

Ubuntu 24.04, Python 3.12 stdlib and distribution `iproute2` are the runtime
dependencies. Python provides exact IPv4 parsing, JSON validation, bounded pipe
reads and a monotonic deadline without extra packages. Invoke with `python3`,
independent of executable mode or cwd. The helper has no environment overrides;
it finds `ip` only in `/usr/sbin:/usr/bin:/sbin:/bin` and passes only that PATH
and `LC_ALL=C` to children, with cwd `/`, no stdin and no shell. It requires
root or `CAP_NET_ADMIN` in the intended namespace to add an address; it never
invokes sudo or installs a dependency. A correct existing address can be verified
without mutation even when add permission is absent.

The one monotonic budget includes discovery, addition and final verification.
Each child gets at most three seconds or the remaining budget, with at most
64 KiB of combined stdout/stderr and one second for killed-child reaping. Bounds
assume the OS schedules and services process creation/termination normally;
this is not a kernel hard-real-time guarantee. Only the exact locale-fixed
missing-device response is retried during initial discovery. Malformed JSON,
output overflow, child timeout, missing dependency, permissions and other query
errors fail immediately with fixed diagnostics; tool output/exception text is
never echoed. Success prints only `ensure-bridge-ipv4: verified`.

The helper requires `linkinfo.info_kind=bridge` and retains the name and ifindex
across address checks, immediately before adding and during final verification.
It matches `local` and `prefixlen` exactly. A different prefix for the same local
address fails before mutation, even if the desired pair also exists. Correct
reruns only query. A nonzero add result always fails; concurrent-add errors are
not accepted as success. Successful adds require a fresh exact postcondition.
It never deletes, flushes or replaces addresses, routes, links or firewall state,
and does not raise links or attach ports. Normal kernel side effects of adding
an address (such as connected routes) still apply. There is no rollback on a
later verification failure: an address just added can remain present.

Separate ip invocations cannot make an atomic identity transaction. Callers must
exclude concurrent link deletion/recreation or renaming during the operation;
ifindex/name/kind checks detect observed changes, not every intervening race.
This helper proves address presence, not forwarding, carrier, topology or VLAB
readiness.

The container runner first prepares distribution packages in a bounded Ubuntu
24.04 container with no repository mount and no NET_ADMIN. Only preparation has
network access. It then executes the unchanged helper with `--network=none`,
`--cap-drop=ALL --cap-add=NET_ADMIN`, no-new-privileges, a read-only filesystem,
16 MiB `/tmp`, and only `build/provision` mounted read-only. No host sockets,
credentials or host networking are supplied. Preparation uses 512 MiB/1 CPU/128
PIDs and a 210-second internal cap (240 seconds externally); runtime uses
256 MiB/1 CPU/64 PIDs and 30 seconds internally (45 externally). The runner
records image IDs, OS/kernel/tool versions and capabilities and removes only
returned owned container/image IDs, verifying their absence on exit. Host-side
create/commit/remove commands also have deadlines. CI runs this and the required
offline suite alongside all existing checks. A denied NET_ADMIN/bridge operation
fails the check; it does not trigger privileged or host-network fallback.

Representative tests cover delayed bridge creation, actual bridge identity,
addition, exact-prefix idempotence, preserved unrelated addresses, conflicting
prefix refusal, nonbridge refusal and missing-bridge timeout. They do not test
systemd, image boot/reboot or student acceptance. The network test file refuses
execution outside the runner's explicit test environment.
