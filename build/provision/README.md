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
VMs. `hhfab validate` ignores `vlab/config.yaml`; no `vlab up` runs.

Each lane also runs a no-switch smoke fixture: fresh `init` without `--wiring`, official `vlab generate --no-switches`
(writes `include/vlab.generated.yaml`), then `validate`, which must succeed.
Assertions: exactly `Fabricator/default` and `ControlNode/control-1` (no
`FabNode`) in `fab.yaml`, and exactly the default VLAN/IPv4 namespace identities
with ranges 1000–2999 and subnet 10.0.0.0/16, plus exactly `SwitchGroup/empty`
with empty spec; no Switch/Server/Connection/Gateway/External. Both pinned
builders create that group unconditionally. It is a marker grouping switches,
not a switch or another device; namespace-only expectations omit generated data. Native rejection fails the lane; no workaround. The report
holds kinds and file hashes only. Canonical wiring checks are unchanged.
Both fixtures share the existing 120-second lane deadline and isolation bounds.
The first native validate precedes structural inspection; it must pass, followed
by all identity/spec assertions and an unchanged successful native rerun before
the lane passes. A later assertion failure does not establish the rerun.
Synthetic tests exercise the actual bounded argv/environment bindings, negative
objects/output, native refusal propagation and rerun preservation. These tests
prove neither systemd/Docker/KVM,
image boot/reboot, a live fabric, telemetry/GitOps nor student acceptance.

Primary sources, accessed 2026-10-25: official versioned
[0.43.1 CLI](https://github.com/githedgehog/fabricator/blob/v0.43.1/cmd/hhfab/main.go),
[configuration](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/hhfab/cmdconfig.go),
[initial template](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/fab/initconfig.tmpl.yaml),
[hydration](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/hhfab/hydrate.go),
and [0.50.4 CLI](https://github.com/githedgehog/fabricator/blob/v0.50.4/cmd/hhfab/main.go).

No-switch sources, accessed 2026-10-26: exact
[0.43.1 generator](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/hhfab/cmdvlab.go),
[builder](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/hhfab/vlabbuilder.go),
and [0.50.4 builder](https://github.com/githedgehog/fabricator/blob/v0.50.4/pkg/hhfab/vlabbuilder.go).
The corresponding fabric dependency schemas
[0.96.2](https://github.com/githedgehog/fabric/blob/v0.96.2/api/wiring/v1beta1/switchgroup_types.go)
and [0.133.0](https://github.com/githedgehog/fabric/blob/v0.133.0/api/wiring/v1beta1/switchgroup_types.go)
define `SwitchGroupSpec` as an empty struct.

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

## Pinned kubectl installer

`install-kubectl.py` installs only kubectl 1.35.0 linux/amd64 from
`https://dl.k8s.io/release/v1.35.0/bin/linux/amd64/kubectl`, exactly 58,597,560 bytes,
SHA256 `a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989`
(#321). There is no stable/latest fallback, upgrade or force mode. It is not called by
cloud-init or Packer. No native download, install, rerun or runtime check has been run.

```bash
# Ubuntu 24.04: Python 3.12 stdlib and curl; root for /usr/local/bin. Keep
# hhfab_release.py alongside the module. Paths must be absolute; cwd is irrelevant.
python3 /absolute/path/build/provision/install-kubectl.py --version 1.35.0 --platform linux/amd64
# Caller-owned alternate directory and a local file (fully verified before any mutation):
python3 /absolute/path/build/provision/install-kubectl.py --version 1.35.0 --platform linux/amd64 \
  --install-dir /absolute/owned/bin --binary /absolute/kubectl
# Offline synthetic tests (no network, no kubectl execution). CI additionally refuses zero tests.
python3 -m unittest discover -s build/provision -p test_install_kubectl.py -v
```

Behavior for `DIR/kubectl`: absent installs atomically (no-clobber link from an owned
stage); exact pinned bytes with mode 0755 are unchanged; exact pinned bytes with another
mode are replaced through the stage (never chmod in place); any other existing bytes are
refused. Symlink, directory, special-file, hardlink or non-caller-owned targets, and a
destination change observed before publication, are refused. `DIR` must be absolute,
caller-owned, not group/world writable, with real (non-symlink) directory components;
ownership and mode are checked only on `DIR`, not every ancestor. Callers must trust the
interpreter, `curl`, module directory and `DIR`, and exclude concurrent mutation; this is
not a defense against a hostile concurrent writer. A failure before publication keeps the
prior target; there is no rollback after publication.

Download uses `/usr/bin/curl` or `/bin/curl` with `--disable` first, HTTPS-only initial and
redirect protocols, no retries, `--max-filesize` equal to the pin, 120s transfer, a
125s bounded child (output capped, process group killed and reaped) and a 180s whole-run
alarm. These are finite assumptions, not measured fit. The child gets only
`PATH=/usr/bin:/bin` and `LC_ALL=C`, no stdin or TTY; no proxy, curlrc or credential
variables are forwarded. After download, size and SHA256 are checked again explicitly. The
owned `.kubectl-stage-*` directory is cleaned on success, failure, timeout and SIGTERM.
Cleanup failure preserves any primary error; otherwise it refuses success after publication,
with no rollback promise. kubectl is never executed.

Python 3.10+ supports synthetic host tests; the representative native target remains
Ubuntu 24.04 Python 3.12. The child inherits cwd, but absolute paths and disabled curl
configuration keep operations independent of cwd.

On success one JSON line (at most 4096 UTF-8 bytes) binds tool, version, platform, source URL, pinned size/hash,
SHA256 of this module and of `hhfab_release.py`, the observed target path, SHA256 and
mode, and `status` (`installed`, `unchanged` or `mode-repaired`). It verifies bytes
against the repo pin only. The target is rechecked for pinned bytes, owner, mode and
observed identity stability before reporting. Escaped target paths over 1024 characters
are refused before mutation; an over-budget final report refuses after publication. The release signature/certificate, redirect chain, runtime
behavior, installation-time fit and equivalence to the baseline image's kubectl path,
owner and mode are not verified (`not_verified`; cosign is outside this slice).

### Native kubectl install and rerun proof

`kubectl_native_proof.py` runs the unchanged `install-kubectl.py` CLI twice
(`--version 1.35.0 --platform linux/amd64 --install-dir <private>/install`, network mode) against
one private, harness-created destination, for a manual-only workflow on a fresh GitHub-hosted
Ubuntu 24.04 runner (Python 3.12 stdlib and curl; no APT, container or VM). It proves only that
the unchanged CLI can acquire, byte-install and idempotently rerun in a caller-owned directory.
It does not prove root or `/usr/local/bin` installation, a pinned-container base, image/VM
integration or kubectl runtime; kubectl is never executed. Real download and timing evidence
requires a separately authorized manual dispatch.

```bash
# Cleared environment; ROOT is a caller-owned 0700 directory with empty 0700 home/ and tmp/.
env -i PATH=/usr/bin:/bin HOME=$ROOT/home TMPDIR=$ROOT/tmp LC_ALL=C PYTHONDONTWRITEBYTECODE=1 \
  python3 -B /absolute/kubectl_native_proof.py --root $ROOT --commit <40-hex> --tree <40-hex>
# Offline synthetic tests (no network, no kubectl execution). CI additionally refuses zero tests.
python3 -m unittest discover -s build/provision -p test_kubectl_native_proof.py -v
```

Up to two JSON lines are printed (`preflight` when reached, then the final report) and the exit status is
0 only if both invocations and cleanup passed. Before the first call the harness records the
commit/tree it was given, SHA256 of itself, the installer and `hhfab_release.py`, the observed OS,
Python, UID and curl version, private directory modes, and that `install/kubectl` is absent. After each call it verifies
independently of the installer: exit status, a single-line JSON result whose tool, version,
platform, URL, pin, module/helper hashes, target path, mode, status (`installed`, then
`unchanged`) and `executed: false` match; the target's bytes, size, 0755 mode, owner and link
count; that the directory holds only `kubectl`; and that no process remains in the installer's
session. The rerun must leave the target's inode, mtime and ctime unchanged. Per-call seconds are
reported (finite assumptions, not measured fit).

Limits are initial assumptions: 600s total work (alarm), a separate 60s cleanup (alarm), and
185s per call plus at most 5s graceful cancellation around the installer's own unchanged 120/125/180s limits; no renewal, widening,
retry or repair. Any failure, including timeout, stays failed and preserves the primary error;
cleanup errors are reported separately. Cleanup removes only the recorded install-directory
inode and a successfully observed, pinned `kubectl` matching its recorded inode. Unobserved
outputs, leftover stages and other unknown children (or non-empty `home`/`tmp`) are retained
and reported as cleanup failures. The installer owns its normal stage cleanup; the harness
never infers stage ownership from a name prefix or shape. A hard runner cancellation (SIGKILL) gives no cleanup
receipt, and later runner disposal is not one. Trusted: the interpreter, `/usr/bin/curl`, the
module directory, the runner and the destination; this is not a defense against a hostile
concurrent writer or an arbitrary descendant that leaves the installer's session. Cancellation
sends installer SIGTERM and waits up to 5s so its unchanged helper can kill/reap curl in its
separate session. Forced escalation leaves nested-process cleanup explicitly unverified.
The manual workflow fixes a 700s outer bound with 30s kill grace and a 13-minute job bound;
these enclose the 600s work plus 60s cleanup envelope without renewing it. Cancellation
grace consumes that same fixed envelope; cleanup receives at most 60s of its remainder.

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
concurrent changes to these inputs, their ancestors and `/var/lib` (including its ancestors); the selected
owner must be dedicated and idle. This is not a hostile multiuser sandbox.
The current directory is irrelevant and children receive fixed clean environments.
Required tools are fixed `/usr/bin/python3`, `/usr/bin/systemd-run`,
`/usr/bin/systemctl`, `/usr/bin/env`; PID1 must actually be systemd. Missing
prerequisites fail without fallback. Protect the root script/import directory
from writes by the selected owner.

Preflight requires the fixed existing `/var/lib` and each ancestor to be a real
non-symlink root-owned directory, unwritable by group/others and traversable by
the nonroot owner. `statvfs` must confirm its filesystem permits execution;
unavailable observations or `ST_NOEXEC` fail before workspace creation. There is
no parent creation, permission/ownership change, remount, `TMPDIR` lookup or fallback.
A root-owned random exclusive `/var/lib/labapp-prereq-*` directory has mode0711;
its mode0700 install child belongs to the selected owner. The existing installer runs
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

The failure JSON carries only fixed `phase`, `action`, `category` and
`execution_mount` values alongside schema/outcome. The phase names the failed stage:
`preflight`, `installer`, `systemd`, `kvm`, `cleanup` or `unknown`. Installer actions are `mkdir`, `chown`, `firstinstall`, `snapshot-first`, `rerun`,
`snapshot-rerun` and `cli`; other phases use action `none`. Actions are set before
work starts. Categories distinguish helper `timeout`/`overflow`, command `nonzero`,
expected-output or installed-state `mismatch`, actual `PermissionError` as
`permission`, other exceptions as `operational`, interruption as `interrupted`,
and other refusals as `refusal`. Arbitrary exception/refusal text is not exported.
Immediately before CLI execution, `statvfs` observes the destination's effective
`ST_NOEXEC` flag as `exec` or `noexec`; an unavailable observation is `unknown`
and still executes the CLI. Other failures use `execution_mount: none`. This
observation does not establish why a child failed or change any mount. A failing
cleanup (unit stop/reset/absence or workspace removal) replaces the original error
and is reported as `cleanup`; a successful cleanup keeps the original phase, action and mount observation. The
phase is metadata only: it never repairs or retries anything and does not change
the success output, exit codes, deadlines or child cleanup. A missing KVM device
is not assumed; only a failure while the `kvm` action runs reports `kvm`.

Run the offline suite (also required by existing hhfab install CI):

```bash
python3 -m unittest discover -s build/provision -p test_component_prerequisites.py -v
```

The fake-systemd/KVM tests verify failure, interruption, ownership and descriptor
cleanup; real local subprocess tests exercise time/output caps. These tests do
not execute host systemd/KVM or establish live guest evidence.

## Snapshot-pinned QEMU prerequisites and execution witness

`install-qemu.py` is a standalone root/noninteractive Ubuntu 24.04 amd64 Python
3.12 module (host unit tests support Python 3.10+); keep `hhfab_release.py` beside
it and `qemu_offline.py`. It requires APT/dpkg and the Ubuntu archive keyring;
networked mode also requires installed HTTPS CA certificates. Its default accepts
no arguments/environment overrides and works from any cwd. Run only in a disposable guest, with an outer deadline:

```bash
sudo timeout --kill-after=3s 240s python3 build/provision/install-qemu.py
python3 build/provision/qemu_witness.py
```

The installer uses official signed snapshot `20261024T000000Z`, Noble
main/universe plus updates/security, and explicit versions:
`qemu-system-x86`/`qemu-utils=1:8.2.2+ds-0ubuntu1.18`,
`socat=1.8.0.0-4ubuntu0.1`, `seabios=1.16.3-2`. These are component experiment
pins, not an upgraded production-image decision. Update snapshot and pins
together after review. Standard APT signed Release → package index → archive
verification remains mandatory; no current-mirror fallback or authentication
bypass. Temporary source/list/cache/preferences paths preserve `/etc/apt`.
Existing base dependencies can differ: the receipt records the full installed
package versions and downloaded archive hashes, not a universal dependency
closure or a permanently archived mirror. Ubuntu intends snapshot retention
of at least two years. No libvirt/GUI/kernel/user/group/bridge changes occur.

Preflight rejects wrong OS/architecture/nonroot, dpkg audit findings, any held
packages, and installed top-level pin drift. After authenticated index update,
isolated `apt-get check` rejects unsatisfied base dependencies before simulation
or installation can repair them. Installation refuses removals,
downgrade authorization and hold override. Network requests have 15-second
inactivity timeouts, native `Acquire::Retries=1` (one retry per item, not per
command; APT retries transient HTTP errors, not 404 or digest mismatch, and a
15-second timeout is not a total download deadline) and a 10-second dpkg-lock wait; APT work shares
a 210-second elapsed budget, each child bounded to at most 180 seconds. Smaller
pre/postflight queries each have a 10-second limit. The outer 240-second limit
provides an independent invocation ceiling; the CLI also arms a235second alarm. APT failure can leave partial dpkg
state: fail and discard that disposable guest; there is no atomic rollback or
automatic repair. A correct rerun reauthenticates the snapshot and verifies exact
versions, mandatory tool/firmware verification against dpkg md5sums, dependency consistency and dpkg audit again.
The pinned socat package provides the exact `socat -> socat1` link; its regular
`socat1` payload and that fixed link target are both verified. Minimal-image
documentation exclusions do not bypass verification of the required tools.

The explicit disconnected path uses the **same installer** and fixed selection:

```bash
# On the actual disposable target, before other package/policy changes:
sudo python3 build/provision/install-qemu.py --capture-state /tmp/qemu-state.json \
  --base-id gce-image:IMMUTABLE_IMAGE_ID
# Trusted lead copies that private data to the trusted acquisition host:
timeout --kill-after=30s 9m bash build/provision/prepare-qemu-offline.sh \
  /private/qemu-state.json /private/new-qemu-bundle
# Lead supplies the printed receipt SHA independently of the transferred bundle.
# On the same target after authenticated transfer:
sudo timeout --kill-after=3s 240s python3 build/provision/install-qemu.py \
  --offline /private/new-qemu-bundle --receipt-sha256 EXPECTED_SHA256 \
  --base-id gce-image:IMMUTABLE_IMAGE_ID
```

The immutable base identifier is **caller attested**, not a guest proof of GCE
identity. The trusted lead must verify the actual lease/instance/disk-image
binding independently before supplying it. Container tests instead use the fixed
`ubuntu@sha256:…` base identity. A state export is private package inventory, not
credentials; retain it only for the owned transfer and remove it afterwards.
The capture exclusively creates a0600 file. It binds actual status, architecture,
foreign architectures, selections, holds/audit, archive keyring, OS identity,
module files and hashes of supported `/etc/apt` policy files and effective APT
configuration. Auth credential files are never read or transferred.
It does not export source/config contents or auth/proxy credentials.

Supported policy is deliberately narrow: amd64 only, no foreign architectures,
holds or audit findings. Nonempty `/etc/apt/preferences` and `preferences.d`
files are preserved and hashed as target identity; their pin rules are deliberately
ignored for this module, as are ambient sources and hooks. No target preference
parser, provider whitelist or caller policy override is supported.
Both modes explicitly replace sources, preferences, cache/solver settings,
proxies, credential-file paths and hooks with the reviewed fixed module policy.
Native compressed-index storage (`Acquire::GzipIndexes=true`) keeps the transfer
within the fixed data bounds; no index parser is introduced. A locally generated
`APT_CONFIG` redirects main/parts **before** parsing; ambient APT hooks and
configuration are never loaded by its APT transactions. Original files remain
unchanged; hashes bind target policy drift, they do not authorize executing it.
Do not use this module where those fixed overrides violate required site policy.

`prepare-qemu-offline.sh STATE NEW_DIRECTORY` is a **trusted lead tool** run only
from reviewed code, never an arbitrary worker artifact. It launches one pinned
Ubuntu downloader with no mounts, devices, credentials, Docker socket or host
APT. Python/CA bootstrap uses the existing fixed package pins; transitive inputs
remain current-mirror inputs. Native APT authenticates signed snapshot Release
→ indexes → downloaded archives against the copied **actual target status**;
the downloader's own package state never substitutes for that target. The
resolver does not write any target status database. It exports data-only lists,
archives and a receipt binding **every** file plus target/base/module/snapshot/pins.
The independently expected receipt digest and successful authenticated native
APT acquisition must come through the trusted lead boundary. A self-asserted
receipt or signed InRelease alone does not authenticate arbitrary adjacent indexes.

Offline mode rejects receipt/inventory mismatch, unexpected config/paths, links,
special files and oversized data, copies verified data to its own workspace,
rehashes and checks the exact three InRelease signatures. Incoming directories
and ancestors must be trusted caller owned, quiescent, and inaccessible to
untrusted writers; this is not an archive upload API. All file reads are bounded
and no-follow; no transferred APT configuration executes. Limits are256 files,
256MiB total,64MiB/file and16MiB receipt/state. Downloader staging is320MiB
noexec tmpfs; limits are1GiB RAM/2CPU/128PIDs. Fixed native acquisition shares
210seconds, each child at most180seconds, with230second overall guest alarm.
The validated data tree is copied to a fixed owned writable export before exit
(tmpfs disappears when Docker stops). Bootstrap plus acquisition has420second
guest/450second client bounds; all
Docker calls have deadlines and the client caps combined output at1MiB.
Exact nonce name plus label and immutable ID checks govern cleanup; daemon
query failure is never treated as absence. Failed acquisition output is removed.

Before any new transaction, offline mode rechecks the actual target fingerprint,
including immediately after simulation. It uses the **real** local dpkg database,
skips update and forces `--no-download` for checks/simulation/installation, with
no network repair/fallback. A correct rerun verifies exact pins/artifacts,
dependency consistency and audit and performs **no install transaction**; it does
not require the now-stale preinstallation status hash. This exception cannot
authorize changes on a different state. APT failure still requires discarding the
disposable target; no rollback is promised.

`qemu_witness.py` accepts no arguments or accelerator/binary/disk/firmware
options. It requires the exact QEMU/SeaBIOS package identities and artifact
hashes in its source. Caller UID/GID/groups and actual `/dev/kvm` device facts
are recorded; no permission repair is attempted. The production CLI uses only
`-accel kvm -cpu host`, never TCG fallback. Its original annotated BIOS fixture
emits a fresh random nonce through port0xe9 and exits33 through port0xf4. It
owns a private 1MiB raw disk under `/tmp`, uses snapshot mode and checks the
backing hash afterwards. No default devices, guest networking, external disk,
monitor or serial console is enabled. The real process-group helper caps
combined output at4KiB, execution at15seconds, then kills/reaps in2seconds;
private files are removed on success/failure/interruption. The CLI adds a40second
overall alarm and converts SIGTERM to a cleanup-capable interruption. The report records
nonce equality, hashes, elapsed time and cleanup. Root success would not prove
student access, Linux boot, full VLAB, networking, reboot or image readiness.

```bash
python3 -m unittest discover -s build/provision -p test_qemu.py -v
python3 -m unittest discover -s build/provision -p test_qemu_offline.py -v
# Separately scoped lead execution only: runs the loopback apt-helper transport
# fixture (retry/404/digest/deadline; HTTP only, not TLS or signature proof)
# before any public snapshot request, then strict signature/missing-pin checks.
timeout --kill-after=30s 20m bash build/provision/test-qemu.sh
timeout --kill-after=30s 20m bash build/provision/test-qemu-offline.sh
```

Ordinary HTTP/digest refusals require a native integer nonzero exit and the
expected bounded status evidence. A supervisor timeout or output overflow is a
fixture failure; only the dedicated hang case expects the external timeout.
The shared bounded runner optionally observes the new session leader inside its
cleanup boundary. This fixture records its PID/PGID/session/start tick and checks
`/proc` for any surviving owned group or session member, including orphan APT
method children whose arguments contain no download path. It waits at most two
seconds for reaping; preparation uses Docker `--init` to reap orphan APT
method children. It fails closed on unknown census/identity, and never kills
unrelated processes. The helper source change also invalidates earlier hashed
module identities; existing captures and bundles are not rewritten.

The Docker proof installs Python/CA prerequisites in two fresh pinned Ubuntu
containers, then runs the unchanged QEMU module twice in each and checks actual
signature/unavailable-pin/hold/drift refusal and unchanged APT configuration. Base manifest digest is
`68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac`;
Python pins are `3.12.3-0ubuntu2.1`/`3.12.3-1ubuntu0.17`, CA certificates
`20240203`. Bootstrap transitive inputs come from current official mirrors and
are recorded in the full package receipt; this is not a fully locked base.
Preparation has network access,1GiB/2CPU/128PID limits and a510second internal
bound/540second attach bound. Runtime uses a committed immutable image ID,
UID/GID1000, network none, all capabilities dropped, no-new-privileges, read-only
root,64MiB owned tmpfs,768MiB/1CPU/128PID limits and45second/60second bounds.
There are no host mounts, devices, socket or credential sharing. The test-only
internal TCG lane uses `-accel tcg,thread=single -cpu qemu64` with the same fixture
and checks exact nonce/exit/unchanged disk. Separately the unchanged production
CLI and actual KVM-only QEMU must refuse the absent KVM device. **TCG success is
fixture/command proof, not KVM execution proof.** Exact nonce names/tags plus
ownership label recover ambiguous create/commit responses; cleanup removes
immutable IDs and verifies absence, and daemon query failure is never absence.
Every Docker operation has an external deadline. No cloud resource is used.

The additional proof prepares a Python-only target image, captures its actual
state after starting with network none, acquires from a separate connected
container, then invokes the unchanged offline CLI twice. Real missing/corrupt
list/archive/receipt, unexpected config, symlink, target drift, foreign/base
identity and invalid-signature inputs must fail before dpkg mutation. A real
ambient negative pin is first shown to block an available dependency candidate;
then the unchanged isolated installer succeeds while preserving pin/hook bytes,
never running the harmless pre-invoke marker, and rejecting captured-pin drift.
The same TCG fixture verifies installed payloads without KVM. This container closure does
not establish a GCE closure, KVM, VLAB, image capture or release acceptance.

Sources (accessed2026-10-25): [Debian native APT on both machines](https://www.debian.org/doc/manuals/apt-offline/ch2.en.html),
[Noble APT configuration loading order](https://manpages.ubuntu.com/manpages/noble/man5/apt.conf.5.html),
[APT2.8.3 preference selection](https://manpages.ubuntu.com/manpages/noble/man5/apt_preferences.5.html),
[Ubuntu snapshot service](https://snapshot.ubuntu.com/),
[Noble apt-get](https://manpages.ubuntu.com/manpages/noble/man8/apt-get.8.html),
[apt-secure](https://manpages.ubuntu.com/manpages/noble/man8/apt-secure.8.html),
[QEMU8.2.2 boot-sector pattern](https://github.com/qemu/qemu/blob/v8.2.2/tests/qtest/boot-sector.c),
[debug exit](https://github.com/qemu/qemu/blob/v8.2.2/hw/misc/debugexit.c),
[debug console](https://github.com/qemu/qemu/blob/v8.2.2/hw/char/debugcon.c).

## Fixed baseline Docker package component (#317, source only)

`install-docker.py` is a standalone root/noninteractive Ubuntu 24.04 noble amd64
Python 3.12 module (needs `hhfab_release.py`, apt/dpkg, curl, CA certificates and
the Ubuntu archive keyring). It installs exactly `docker-ce` and `docker-ce-cli`
`5:29.1.3-1~ubuntu.24.04~noble` and `containerd.io`
`2.2.1-1~ubuntu.24.04~noble` with `--no-install-recommends`, using a private
owned APT config/key/sources/preferences/lists/cache (Docker stable/noble/amd64
plus Ubuntu snapshot `20260114T000000Z` noble, noble-updates, noble-security).
The Docker key is fetched over HTTPS and must have SHA256
`1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570`; APT
authenticates Release, indexes and archives, and the three downloaded `.deb`
SHA256 values (#315 review) are checked before the first dpkg mutation. No global
`/etc/apt` change, `trusted=yes`, purge, removal, downgrade, upgrade or hold.

```bash
# Run only on a disposable guest, after separate lead authorization.
sudo timeout --kill-after=3s 240s python3 build/provision/install-docker.py \
  --receipt /var/tmp/labapp-docker-receipt.json
# Offline mocked tests (no APT, network, container or system change):
python3 -m unittest discover -s build/provision -p test_install_docker.py -v
```

It refuses non-root, unsupported OS/architecture, foreign architectures, holds,
dpkg audit problems, conflicting packages (`docker.io`, `containerd`, `runc`,
...), installed version drift, a partial trio, unowned payload-path collisions,
and simulations that remove, purge or upgrade unrelated packages. Downloaded
archives must cover the reviewed simulation exactly; native `dpkg-deb` reads
metadata after authentication, and a second simulation must match before install.
The 32-package plan ceiling is an initial finite bound, not a proven closure.
A rerun with the exact trio installed re-fetches the reviewed key and authenticates
fresh source indexes, checks package health and verifies payloads against dpkg
md5sums, then compares the optional receipt (module/source/key hashes, full installed
package state and payload SHA256). dpkg metadata verifies consistency; it is not
independent installed-file SHA provenance. Unsafe receipt parents/types are refused
before acquisition; an existing receipt cannot authorize first installation.
Partial dpkg failure leaves a failed disposable target;
there is no rollback or repair. Budgets (210s APT, 180s child, 235s alarm, 240s
outer) are unproved initial assumptions.

Not covered: rootless extras, buildx/compose and other recommendations (baseline
gaps, not complete Docker equivalence), user/group access, daemon readiness,
k3d, VLAB, reboot, course behavior, snapshot dependency solvability and
historical snapshot freshness/Valid-Until. These need separate integration
evidence. [Noble APT 2.8.3 sources.list](https://manpages.ubuntu.com/manpages/noble/man5/sources.list.5.html)
documents default Valid-Until enforcement and source-specific historical-repository
controls; this module retains secure defaults and refuses expired metadata.
The [snapshot service](https://snapshot.ubuntu.com/) documents historical selection
and intended retention, which do not establish this target's freshness or closure.
Sources accessed 2026-10-27. Native installation remains unrun for this source.

### Docker package container proof

`test-docker.sh` is a test-only host launcher (Docker, `timeout`; no arguments or
overrides) that creates exactly ONE fresh Ubuntu 24.04 amd64 container from the
pinned `ubuntu@sha256:68ee...33ac` base. Inside it, fixture preparation installs
`python3=3.12.3-0ubuntu2.1`, `python3.12=3.12.3-1ubuntu0.17` and
`ca-certificates=20240203` (the `test-qemu.sh` pins) plus **unpinned** `curl` and
its libraries, so the fixture is only as reproducible as the archive; the driver
`docker_container.py` records the resolved versions, the Python version, the
base image id/digest and the source SHA256 values. The driver denies service
startup (`/usr/sbin/policy-rc.d` exits 101, verified), plants a Docker-data
sentinel, then runs the unchanged `install-docker.py` twice in the same target
(install, then rerun with the same receipt path) with independent before/after
probes. It does not duplicate installer logic, retry, widen limits or repair.

```bash
# Separately scoped lead execution only: acquires the base image, Ubuntu fixture
# packages, the Docker key/indexes and the packages (needs outbound network).
timeout --kill-after=30s 11m bash build/provision/test-docker.sh
# Offline mocked lifecycle/failure tests (no APT, network, container or Docker):
python3 -m unittest discover -s build/provision -p test_docker_container.py -v
```

Success requires: the exact trio versions and declared archive SHA256 values, the
reviewed key SHA256, an archive set equal to the installed dependency closure
(recorded), clean `dpkg --audit`, no holds, no removed/changed preexisting
packages, unchanged `/etc/apt`, an intact sentinel, no Docker daemon process, a
receipt that matches dpkg state, payload and source hashes, and a rerun that
re-fetches the key, runs authenticated `update` and `check` twice, acquires and
installs nothing, and preserves package state, payload and receipt identity.
The driver invokes the normal `python3 install-docker.py --receipt PATH` CLI
unchanged in a bounded subprocess. It does not intercept calls or claim an
independently observed authentication-stage trace; authentication assertions come
from native APT success and the reviewed installer's receipt/implementation.
Each structured installer result (including archive digests/bytes and receipt
fields), prepared package inventory and source hashes is retained in the bounded
report. The aggregate JSON report is capped at 60 KiB and exported whole within
the host's 64 KiB capture tail. Oversized evidence is an explicit failure and
preserves any primary failure exit status. A preexisting trusted regular service policy is preserved at
`/usr/sbin/policy-rc.d.labapp-original` before planting the fixed denial; both are
disposable fixture data and deleted with the target.

Containment (assumptions to measure, not demonstrated fit): `--init`, 2 CPUs, 1 GiB
(swap equal), 128 PIDs, `no-new-privileges`, explicit `--network=bridge` and
`--cap-drop=CAP_NET_RAW`, no privileged mode, host socket, devices, host network or credentials.
Inspect must report exactly `bridge` and `["CAP_NET_RAW"]`; aliases, missing or
additional capability drops and other network modes are refused before start.
The docker client uses an empty private `DOCKER_CONFIG`; only a read-only copy of
the three public files is mounted. Total work, including acquisition and
preparation, is 600s (guest wrapper 570s, installer runs refused when the
remaining budget is under their 235s alarm plus margin); cleanup uses bounded
5-20s Docker calls and no renewal. The target is removed by exact nonce-bearing
name AND ownership label (also after lost create responses, failure, SIGINT/
SIGTERM and timeout) together with its processes, volume and temp files, and the
host workdir is removed. Public logs include the nonce-bearing name/ownership label,
created or recovered immutable ID, applied containment and a checked absence receipt
only after successful exact-name/label and immutable-ID queries. A cleanup failure is reported but never replaces a
primary failure code; a supervisor timeout (124/137) is labelled and is not APT
evidence. A transport failure, unresolved dependency or budget issue stays a
failure: `transport_suspected` is only a label.

Not proved: systemd or daemon readiness, `docker`/`containerd` API behavior,
user/group access, recommendations, snapshot solvability or freshness, other
CPUs/platforms, or any image. Mocked tests do not show installability. The CI
step runs the real mocked lifecycle suite.

Before either containment comparison can reject the target, the launcher emits
requested and observed values for the fixed ten applied/isolation fields only.
Values use Bash escaping with at most 128 input bytes per value and an explicit
truncation flag; validation compares the full original values, without aliases
or normalization. Inspect failures, missing records and extra record counts are
reported separately; extra values are omitted. No environment or host census is
printed. A failed inspect or mismatch prevents container start. These diagnostics
do not identify the missing field/value from the earlier failed native trial.

Launcher and workflow host cleanup print exact owned path absence receipts only
after checking both existence and symlink presence. The launcher removes only its
known regular files and empty directories; replaced types and unknown children
(including dangling links) are preserved and cause cleanup failure. The workflow
removes only its four empty private directories. Cleanup failure prevents success
and preserves a primary failure code, including 124/130/143. Offline tests execute
the actual launcher and the maintained workflow cleanup function against synthetic
Docker state and temporary paths; they do not prove native cleanup or installability.

The maintained `docker-package-proof.yml` workflow is manual-only, accepts no
inputs and runs only from this repository's `main`. Separately scoped lead
execution can dispatch it with:

```bash
gh workflow run docker-package-proof.yml --repo afewell-hh/labapp --ref main
```

It checks out the exact dispatch commit without persisted Git credentials,
records commit/tree, four public source hashes, actual host Python/UID/platform
and Docker client/server versions, then invokes `test-docker.sh` exactly once
with an empty private HOME/TMP and cleared environment. Contents read is its only
GitHub permission; no secrets, cloud credentials or environments are requested.
A fixed concurrency group serializes dispatches without cancellation. The 13-minute
job budget encloses the 11-minute command bound (600s work plus bounded cleanup;
outer termination has a 30s kill margin). No native trial runs on a push, PR or
merge. Read the actual outcome and identity/containment/cleanup receipts in the
run log; a green source/mock job alone proves no installation. A hard job or
runner cancellation may prevent exact cleanup observation: hosted-runner disposal
is the fallback, not a verified container deletion receipt. A failed trial remains
failed and needs lead disposition before any new dispatch.

## Pinned Helm installer

`install-helm.py` installs only Helm 3.19.4 linux/amd64. Ubuntu 24.04 Python 3.12
stdlib and sibling `hhfab_release.py` are required; network mode additionally
needs `/usr/bin/curl` or `/bin/curl`. Invoke explicitly, without sudo inside the
module, environment overrides, prompts or TTY:

```bash
# Root for the default existing /usr/local/bin; all supplied paths absolute.
python3 /absolute/build/provision/install-helm.py --version 3.19.4 --platform linux/amd64
python3 /absolute/build/provision/install-helm.py --version 3.19.4 --platform linux/amd64 \
  --install-dir /absolute/caller-owned/bin --archive /absolute/helm.tar.gz
```

The repo trust pins are the official
`https://get.helm.sh/helm-v3.19.4-linux-amd64.tar.gz`, 18,014,603 bytes,
SHA256 `759c656fbd9c11e6a47784ecbeac6ad1eb16a9e76d202e51163ab78504848862`,
and selected binary 60,182,712 bytes,
SHA256 `ea22096683b9b61005584501e36168a1eadc5b6883a89df299f5a55e4e2dd283`.
Trust is checksum-only against these source pins. GPG signature verification and
upstream-build provenance remain unverified. Exact layout comes from the
[bounded artifact inspection](https://github.com/afewell-hh/labapp/issues/332#issuecomment-6528657450):
ordered `linux-amd64/` (directory, 0 bytes), `linux-amd64/LICENSE` (regular,
11,373), `linux-amd64/README.md` (regular, 3,699), `linux-amd64/helm` (regular,
60,182,712). The exact accepted archive modes are 0755/0644/0644/0755; baseline installed
path, owner and mode equivalence are unknown.

The entire compressed size/hash is checked through one no-follow single-link
regular-file descriptor before physical tar parsing. The same descriptor is
rewound; input identity is checked again after parsing. A Helm-only streaming
512-byte parser checks checksums, exact names/order/types/sizes/modes, empty link and
prefix fields, GNU ustar magic, zero member padding and at least two zero end
blocks with an entirely zero block-aligned final tail. Extensions (PAX/GNU
long-name/sparse), links, special files, duplicates, extra/missing members and
traversal are refused by this exact physical contract. Expanded bytes, including
headers, padding and tail, are capped at 70 MiB (observed archive 60,211,200 bytes).
The single gzip stream must reach CRC-validated EOF without concatenation or
trailing compressed bytes. Only the selected member is streamed to disk and
size/hash verified; no extract/extractall or binary invocation occurs.

`DIR/helm` absent installs with a no-clobber link from a private stage. Exact
0755 pinned bytes return `unchanged` without consulting archive or curl. Matching
bytes with another mode use verified staged replacement (`mode-repaired`);
different bytes are refused, with no force/upgrade/latest fallback. Symlinks,
hardlinks, special files and non-caller-owned targets are refused. Every directory
component must be real; only the final directory's ownership and group/world
writability are checked. Callers must trust and keep quiescent the interpreter,
module/helper directory, curl, archive input, destination and ancestors. Observed
target identity is checked immediately before replacement; absence publication
is no-clobber. These checks do not defeat hostile concurrent writers. Failure
before publication preserves prior bytes; there is no rollback after publication
or power-loss durability promise. Directory fsync is best-effort.

Curl starts with `--disable`, HTTPS-only initial/redirect protocols, no retries,
fixed absolute paths, cwd `/`, stdin `/dev/null` and only PATH=/usr/bin:/bin and
LC_ALL=C. Transfer/child/total budgets are 120/125/180 seconds, initial finite
assumptions rather than measured fit; combined child output is capped at 1 MiB,
and child process groups are killed/reaped on failures/cancellation. The owned
stage is checked by directory identity; only its known regular archive/binary
children are removed. Unknown children and changed types are preserved and fail
cleanup. Cleanup errors preserve the primary failure; after publication they
prevent success. SIGTERM maps to a cleanup-capable interruption; SIGKILL cannot
promise cleanup.

One JSON line of at most 4096 UTF-8 bytes binds source/member pins, module/helper
hashes, observed target identity/hash/mode and status; it states unverified GPG,
provenance, redirect chain, runtime and baseline metadata equivalence. No receipt
file, config, cluster, credentials, cloud-init or Packer integration is created.
The required CI step discovers `test_install_helm.py` with a zero-test guard,
private 0700 HOME/TMP, env-i, Python -I -B and umask022, and removes only its exact
empty outer directories with checked absence while preserving any primary code.
Synthetic tests exercise actual install/parser/CLI and bounded fake children;
they do not establish native download/install/runtime or image equivalence.
