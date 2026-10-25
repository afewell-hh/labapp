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
python3 -m unittest discover -s build/provision -p test_bridge_ipv4_harness.py -v
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
records image IDs, OS/kernel/tool versions and capabilities. A fresh UUID marks
exact container names, a unique prepared-image tag and an ownership label.
Cleanup rediscovers only the conjunction of exact name/tag and that label,
validates returned IDs, removes those IDs and verifies absence. This also recovers
objects when create/commit succeeded at the daemon but the client response was
lost; no received ID is required for recovery. An unreachable daemon makes
cleanup fail, rather than implying absence. Cleanup calls each have a five-second
cap and one-second kill grace; create/commit commands also have deadlines.
Synthetic fake-Docker tests exercise lost prep/runtime create responses, lost
commit response, a foreign-label name collision and cleanup daemon failure. CI runs this and the required
offline suite alongside all existing checks. A denied NET_ADMIN/bridge operation
fails the check; it does not trigger privileged or host-network fallback.

Representative tests cover delayed bridge creation, actual bridge identity,
addition, exact-prefix idempotence, preserved unrelated addresses, conflicting
prefix refusal, nonbridge refusal and missing-bridge timeout. They do not test
systemd, image boot/reboot or student acceptance. The network test file refuses
execution outside the runner's explicit test environment.

## Offline official hhfab configuration proof

This is a test harness, **not** an installer or production configuration generator.
It tests official `hhfab init`, imported wiring, `validate --hydrate-mode
if-not-present`, and `versions` after the fixture exists and passes validation.
Every init receives a new owned empty temporary directory; validation reruns
preserve it. Two independent lanes use observed 0.43.1 and compatibility candidate
0.50.4. Neither is automatically the next image pin. Each lane performs two fresh
runs on the exact root `wiringd.yaml` (SHA256
`c522c64d80515c7484a67c27646acebf86073192f0f6ff9597497b990548806a`),
then real CLI rejection checks. No topology normalization or approximation occurs.

```bash
# Host: Docker daemon, curl, timeout and Python 3.10+ stdlib; network for preparation.
# Synthetic parser checks additionally need distribution python3-yaml.
python3 -m unittest discover -s build/provision -p test_hhfab_offline.py -v
timeout --kill-after=30s 10m bash build/provision/test-hhfab-offline.sh
```

Invoke the Bash launcher explicitly; it resolves paths independently of cwd,
uses no environment overrides, and never executes hhfab on the host. Python is
used only for bounded download/extraction, test assertions and child-process
control; this adds no provisioning framework. CI runs these actual commands in
addition to the existing five jobs.

Public inputs are official release assets at
`https://github.com/githedgehog/fabricator/releases/download/vVERSION/hhfab-linux-amd64-vVERSION.tar.gz`.
The only accepted archive member is the regular file `hhfab-linux-amd64/hhfab`;
links, extra members and size/checksum mismatches fail before execution.

| Lane | Archive bytes / SHA256 | Binary bytes / SHA256 |
| --- | --- | --- |
| 0.43.1 | 93055151 / `b1387342191a329772c2595504ec6ff129eb45980727c1c86d9901ef4d9f37a4` | 170709176 / `b5c7e0265339b9b95fa1073967bfb6c6fede6086755c85eca24cb80637b04e37` |
| 0.50.4 | 59692810 / `a8e6d1b8d0f752d7586c29201add3ff174d330c87fa25a3bdadec43f6c1376b6` | 104890530 / `b7a5c7744e3b617d7e76d9ccc9015588a8c32da62623c8ecc114cae24e1a5fcd` |

Preparation reuses Ubuntu 24.04 amd64 base digest
`ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac`
(amd64 image ID `sha256:6277ab668b2ad3c3ab851d370faa1690d324b30db29d342527f61fed28f20f36`).
It installs distribution `python3=3.12.3-0ubuntu2.1`,
`python3.12=3.12.3-1ubuntu0.17`, `python3-yaml=6.0.1-2build2`, and
`libyaml-0-2=0.2.5-1build1`, without a version fallback. Complete resolved dpkg
versions and base/prepared image IDs are printed before CLI execution; transitive
apt dependencies are recorded, not a complete snapshot lock. Apt repository
availability remains a preparation dependency. Base coreutils is 9.4-3ubuntu6.3.

Structural assertions require distribution `yaml.CSafeLoader` explicitly.
Upstream 0.43.1's public `initconfig.tmpl.yaml` contains a tab separating `ip:`
from `dhcp`: pure Python SafeLoader refuses it while libyaml accepts it. The
harness keeps generated bytes unchanged and uses the official CLI as semantic
validation authority; it never rewrites configuration to satisfy a parser.
This parser choice applies only to disposable public fixtures, not private
source-evidence derivation.

Runtime containers use uid/gid1000, network none, cap-drop ALL,
no-new-privileges, a read-only root filesystem, 1GiB RAM, two CPUs and 128 PIDs.
Only tmpfs `/work` (64MiB, includes HOME/cache) and `/var/log` (8MiB) are writable;
there are no host mounts, Docker socket, credentials, devices, KVM or namespace
sharing. Clean child environments omit ambient HHFAB_* variables. All inputs
and verified binaries are baked into a unique owned image. Preparation alone has
network, with 512MiB/one CPU/128 PIDs and a 210-second internal/240-second external
apt cap. Downloads get 120 seconds each, 1KiB/s minimum for 20 seconds and exact
size ceilings; extraction is bounded by exact pinned archive/member sizes. The
complete host download/hash/extract/copy phase gets 270 seconds plus a three-second
kill grace, including both downloads; exceeding it fails and triggers cleanup.
Each CLI command gets at most 30 seconds inside a 120-second lane, with two-second
child-group kill/reap grace. Docker attachment gets 135 seconds and a 1 MiB combined lane-report
ceiling. Each Docker mutation/query/cleanup has its own bounded deadline. The
outer 10-minute timeout also triggers cleanup. Exact nonce-bearing names/tags AND
ownership labels recover lost create/commit responses; cleanup removes only
validated immutable IDs, verifies absence, and fails if queries or deletion fail.
No broad prefix cleanup occurs.

The common init flags use spine-leaf, explicit ghcr.io/githedgehog registry,
`--dev`, `--gateway=false`, and public wiring. **All generated config contains
upstream public development credentials and is ephemeral test data only.** No raw
configuration or CLI logs are exported or uploaded. Safe bounded summaries label
each version, fresh text hashes and versions-output hashes. Native hydration is
in memory; hashes do not claim hydrated YAML persisted. Invalid YAML, unsupported
GVK, duplicate object, missing endpoint, bad port, invalid fabric mode and partial
hydration exercise the real CLI. Missing generated config is rejected before
`versions` can misleadingly report release defaults. Synthetic integrity/ownership
checks cover bad checksums, unsafe archive members, interrupted/timeout/overflow
children, lost Docker mutation responses, foreign objects and cleanup errors.

The recovered sizing map is a separate structural/range fixture in the test,
with control 6/6144/100, switch 4/5120/50, server 2/768/10, gateway 8/6144/50 and
external 4/5120/50 (CPU cores/RAM MB/disk GB). It does not request gateway/external
VMs. `hhfab validate` ignores `vlab/config.yaml`; no `vlab up` or full VLAB
configuration generation runs. These tests prove neither systemd/Docker/KVM,
image boot/reboot, a live fabric, telemetry/GitOps nor student acceptance.

Primary sources, accessed 2026-10-25: official versioned
[0.43.1 CLI](https://github.com/githedgehog/fabricator/blob/v0.43.1/cmd/hhfab/main.go),
[configuration](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/hhfab/cmdconfig.go),
[initial template](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/fab/initconfig.tmpl.yaml),
[hydration](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/hhfab/hydrate.go),
and [0.50.4 CLI](https://github.com/githedgehog/fabricator/blob/v0.50.4/cmd/hhfab/main.go).

## Pinned hhfab installer

`install-hhfab.py` installs only official Linux-amd64 0.43.1 or 0.50.4 using the
archive and member pins in the preceding table. The caller must choose a version;
0.50.4 remains a compatibility candidate, not an accepted next-image upgrade.
The installer is not yet called by cloud-init or Packer.

```bash
# Ubuntu 24.04: Python 3.12 stdlib and curl; root for /usr/local/bin.
# Keep hhfab_release.py alongside install-hhfab.py. No login environment needed.
python3 /absolute/path/build/provision/install-hhfab.py --version 0.50.4
# Offline delivery uses exactly the same installer and full integrity checks.
# Destination directory must already exist and be writable by the caller.
python3 /absolute/path/build/provision/install-hhfab.py --version 0.43.1 \
  --install-dir /absolute/owned/bin --archive /absolute/release.tar.gz
# Host synthetic failures plus actual unchanged installer in two fresh containers.
python3 -m unittest discover -s build/provision -p test_install_hhfab.py -v
timeout --kill-after=30s 10m bash build/provision/test-install-hhfab.sh
```

Python 3.10+ stdlib supports host tests; representative installation uses Ubuntu
24.04's pinned distribution Python 3.12 described above. Invocation is explicit
`python3`, noninteractive, without sudo or environment overrides. All options are
shown above; `--version` is required, `--install-dir` defaults to `/usr/local/bin`,
and omitted `--archive` downloads the exact official versioned release via curl
on PATH. The module resolves its sibling import independently of cwd; relative
archive paths use the caller's cwd. The install directory must be absolute,
caller-owned and not group/world writable; every component must be a real
(non-symlink) directory. Existing targets and local archives must be single-link
regular files. Symlink, directory, special-file and hardlink targets are refused.
Callers must trust the interpreter, PATH tools, module directory, destination
ancestors and archive input, and exclude concurrent mutations of those paths.
Observed target changes are checked before replacement; this is not an atomic
transaction against a hostile concurrent filesystem writer.

No existing or downloaded binary is executed by installation. Correct 0755
binaries return unchanged; a matching nonexecutable binary is repaired through
verified replacement. Downloads enforce HTTPS redirects only, exact archive-size
ceiling, 120 seconds, and minimum 1KiB/s over 20 seconds, without retries. The
child has a 125-second external deadline and two-second kill/reap grace. The
installer invocation has a 180-second alarm covering download, hashing,
extraction and publication (plus child reaping/cleanup; normal OS scheduling is
assumed). Exact archive size/hash is checked before parsing; only the sole regular
member `hhfab-linux-amd64/hhfab` is accepted, with its exact size/hash. Extraction
streams at most that pinned member size, never tar-extracts names or links.
Staging is private on the destination filesystem; only verified 0755 bytes are
atomically renamed to `hhfab`. Failure before publication preserves the existing
binary and removes staging. Publication is atomic visibility, not a power-loss
durability guarantee. No directory creation or package installation is implicit.

The installer test uses the existing bounded Docker ownership/cleanup runner in
an explicit separate mode. Public archives are downloaded and verified during
host preparation, then baked with the unchanged installer and shared verification
module. Each version installs, reruns, repairs mode and executes the installed
`hhfab --version` in a separate fresh network-none uid1000 container. Runtime
`/work` is a 512MiB executable tmpfs for staging/installing the larger binary;
other capability, resource, network, ownership and cleanup restrictions remain
those of the offline configuration harness. No host mounts, socket, credentials
or host binary execution occur. The optional local-archive path enables offline
production delivery too; it does not bypass a pin. Synthetic regressions exercise
integrity/member failures, download nonzero/timeout with real child processes,
unsupported platform/version, unsafe paths, prior-state preservation, exact
idempotence and mode repair. Shared harness tests continue covering lost daemon
responses and cleanup failures. CI keeps the existing six jobs and adds a separate
installer job. These tests do not prove systemd, nested KVM, VLAB startup, image
boot/reboot, or student acceptance.

Primary sources accessed 2026-10-25: official
[0.43.1 release](https://github.com/githedgehog/fabricator/releases/tag/v0.43.1),
[0.50.4 release](https://github.com/githedgehog/fabricator/releases/tag/v0.50.4),
[release API](https://api.github.com/repos/githedgehog/fabricator/releases/tags/v0.50.4),
and [upstream installer](https://i.hhdev.io/hhfab). The upstream installer defaults
to `latest` and `/usr/local/bin`; this module deliberately requires explicit
version selection. The docs overview was unavailable through the research browser;
no installation claim relies on that page.

## Offline-delivered guest prerequisite probe

`component_prerequisites.py` is a small **guest** check for an explicitly
approved disposable Ubuntu 24.04 amd64 component VM. It does not launch or
access VMs. Trusted lead delivery must place this script, the unchanged
`install-hhfab.py` and `hhfab_release.py` siblings in a root-owned directory,
and deliver the official 0.50.4 archive pinned above. No guest download, package
installation, module loading, user/group changes or network repair occurs.
Version 0.50.4 is a probe compatibility choice, not acceptance as an image pin.

Invoke as root with `/usr/bin/python3` (Ubuntu 24.04 Python 3.12 stdlib;
offline host tests also support Python 3.10+) and an explicit existing nonroot
UID with a nonroot primary group:

```bash
sudo /usr/bin/python3 /trusted/provision/component_prerequisites.py \
  --owner-uid 1000 --archive /trusted/hhfab-linux-amd64-v0.50.4.tar.gz
```

The archive and trusted script directory must be readable/traversable by that
owner. The probe does not change external file permissions. The caller excludes
concurrent changes to these inputs, their ancestors and `/run`; the selected
owner must be dedicated and idle. This is not a hostile multiuser sandbox.
The current directory is irrelevant and children receive fixed clean environments.
Required tools are fixed `/usr/bin/python3`, `/usr/bin/systemd-run`,
`/usr/bin/systemctl`, `/usr/bin/env`; PID1 must actually be systemd. Missing
prerequisites fail without fallback. Protect the root script/import directory
from writes by the selected owner.

A root-owned unique `/run/labapp-prereq-*` directory permits traversal only;
its install child belongs to the selected owner. The existing installer runs
unchanged as that UID/primary GID with supplementary groups cleared, then reruns.
The probe verifies the pinned binary hash/size, owner, mode0755 and unchanged
inode/timestamps; the actual installed `--version` smoke also runs as that
nonroot identity. It never installs into `/usr/local/bin`.

The systemd check creates only a unique `labapp-prereq-<uuid>.service` after
refusing a preexisting exact name. Its root oneshot has explicit working
directory/environment, 10-second startup and 5-second stop deadlines and
control-group kill semantics. Success requires observed Result=success,
ExecMainStatus=0, active/exited state and an exact nonce marker. Normal failure,
lost start reply and interruption attempt stop/reset of only that unit and
verify it is absent before success. The temporary directory is removed on exit.
Cleanup uncertainty is failure; SIGKILL or machine loss still requires the
external VM lifecycle owner. No global unit enumeration or journal export occurs.

The separate bounded KVM child opens `/dev/kvm`, requires API12, creates a VM
handle and immediately closes both descriptors. **This runs as root.** It proves
only root device/API/VM-handle availability, not student/nonroot KVM permissions,
L2 instruction execution, QEMU, VLAB, reboot persistence or production service
integration. No vCPU or custom hypervisor is created.

Each child has a time/output cap (4KiB); installer calls allow65s each,
CLI20s, service start20s and KVM10s. A210s work deadline leaves bounded cleanup
(stop15s, reset10s, absence15s, each process kill/reap allowance2s). Use an
external300s ceiling with cleanup grace in any future access orchestration;
that ceiling must not replace the cloud lease. Only fixed sanitized JSON is
printed; child output, paths, journal, credentials and arbitrary exceptions are
never exported. A failed check exits1 and gives no overall passing claim.

Run the offline suite (also required by existing hhfab install CI):

```bash
python3 -m unittest discover -s build/provision -p test_component_prerequisites.py -v
```

The fake-systemd/KVM tests verify failure, interruption, ownership and descriptor
cleanup; real local subprocess tests exercise time/output caps. These tests do
not execute host systemd/KVM or establish live guest evidence.
