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

The0.43.1 lane also imports the exact shared trial `candidate_fab` renderer with
public synthetic ED25519/hash/token values, then reuses `config_import_smoke`
for a fresh official import and two exact-preservation validations. The renderer
is imported unchanged from the copied `vlab_trial.py`; no GCP/cloud module or
real candidate secret enters this container. The report's `trial_renderer_import`
contains only public fixture/source hashes and status. The ordinary generated
public FAB check alone does not validate this additional recipe. All existing
network-none/nonroot/no-capability/resource/owned-cleanup bounds remain active.
Native import/first-validation/rerun refusals identify the finite public fixture
(`generated-reference` or `rendered-candidate`) without printing CLI output.
The trial renderer leaves control management/dummy IPs unallocated, matching
the [v0.43.1 template](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/fab/initconfig.tmpl.yaml).
Official [if-not-present hydration](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/hhfab/hydrate.go)
requires wholly unhydrated inputs and assigns the sole control `172.30.0.5/21`
and dummy `172.30.90.0/31` in memory. Core candidate validation retains the
explicit management-address policy; import and validation retain exact bytes.

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

The 0.43.1 lane additionally imports its generated public `fab.yaml` into a
separate new empty directory using `init --config PATH`, explicit
`ghcr.io/githedgehog` registry and unchanged canonical `--wiring`. It checks
exact FAB, registry and wiring bytes plus expected output directories before
native validation, after validation and after an unchanged validation rerun.
The first fixture and pinned binary must stay unchanged throughout; unexpected,
missing or symlinked outputs fail. Each CLI or preservation refusal stops before
the next command. The existing bounded executor and launcher own cancellation
and cleanup; no extra deadline, acquisition or retry is introduced. The 0.50.4
lane is unchanged. Only hashes and a `generated-public-candidate-only` scope
appear in the report. These public development inputs do not recover original
Fabric values or prove baseline/runtime equivalence. The maintained synthetic
suite exercises this actual helper's command binding, preservation, native
refusals, source/tool mutation and occupied-destination refusal without executing
hhfab; its existing required CI invocation includes these cases.

Import source, accessed 2026-10-30: exact
[0.43.1 configuration](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/hhfab/cmdconfig.go)
reads and validates imported FAB/wiring, then writes those original bytes without
serialization; `validate` loads/hydrates in memory. The
[0.43.1 CLI](https://github.com/githedgehog/fabricator/blob/v0.43.1/cmd/hhfab/main.go)
binds `--config` to `ImportConfig`. No `--force`, regeneration or runtime command
is used for import.

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

Bounded-child refusals retain a fixed public command label; APT transaction
failures also identify `update`, `pre-check`, `simulate`, `install` or
`post-check`. Labels never copy command arguments, environment or paths.
Known timeout/output-overflow/deadline refusals retain their fixed reason;
unknown bounded-refusal text is withheld. The unchanged combined-output cap is
1 MiB; returned nonzero commands retain the existing bounded
4096-byte output tail. Interruption still unwinds cleanup and exits 130.
These diagnostics locate a new observed failure; they cannot reconstruct the
stage or cause of earlier failures or prove installation/runtime success.

#### QEMU installation output-overflow observations

Only `install-qemu.py` opts in (`bounded(..., observe=True)`); every other
`bounded()` caller keeps its exact error string, behavior and no observation.
The 1 MiB combined stdout/stderr cap stays a hard refusal: the overflowing block
is never retained, and an overflowing command is never a success, even if it
would later exit 0 or 100. An overflow refusal appends one fixed line to the
existing `[stage=S: ]command=LABEL: command output overflow` text:

```text
observation=through-cutoff-not-total cap= block= deadline_seconds= elapsed_ms=
blocks= observed_bytes= retained_bytes= long_records=
lines[get= hit= ign= err= w= e= dpkg= other=] unterminated_tail=0|1 non_ascii=0|1
```

All values are bounded integers or 0/1 flags in that fixed order. Counters cover
only output read up to the cutoff; they are not total child output, a native
exit status or a cause. `observed_bytes` includes the crossing read block and so
can exceed `cap`; `retained_bytes` never does. Records end at CR or LF and are
classified by a fixed leading-byte prefix (`Get:`, `Hit:`, `Ign:`, `Err:`, `W:`,
`E:`, common dpkg progress lines, else `other`); `long_records` counts records
over 4096 bytes. No child text, snippet, argument, environment, path, hash or
dynamic key is emitted, and a missing or invalid observation prints
`observation=unavailable`. Parsing keeps at most 24 prefix bytes and does linear
work per read block, so CR-heavy, binary or very long records stay bounded. A
failing observer (including ordinary construction failures) is dropped without
changing the refusal or the child cleanup. Observer interruption still propagates
after cleanup attempts.

On any primary failure the supervisor still attempts group `SIGKILL`, leader wait
and pipe close, and the primary failure is preserved if one of those steps also
fails, including interruption during a cleanup step; subsequent steps are still
attempted. Cleanup failure or interruption after an apparent success still fails.
Leader reap does not prove that the whole session or every descendant is gone, and a child that
leaves its process group or sits in uninterruptible sleep is not preempted.
Tests: `python3 -m unittest discover -s build/provision -p test_qemu.py -v`.
CI requires this file and the nonempty `OverflowObservationTests` class to be
discovered and rejects skipped tests.

### Explicit historical QEMU selection

The no-option default and explicit `--selection test-20261024` retain the four
TEST pins above. `--selection baseline-20260114` instead requests ONLY the two
observed `qemu-system-x86` and `qemu-utils` versions
`1:8.2.2+ds-0ubuntu1.11`, using `20260114T000000Z`. These are the only two
source-defined selections; unknown names refuse before preflight/workspace/APT.
There are no arbitrary package, mirror, date, environment or profile overrides.

Historical success verifies exact versions plus regular nonsymlink
`/usr/bin/qemu-system-x86_64` and `/usr/bin/qemu-img` against installed dpkg
md5sums. It does not require invented original socat/SeaBIOS pins or reuse the
TEST member hashes. Native signed APT authenticates acquired packages; dpkg
md5sums detect installed-payload drift. Dependency versions are target-specific
observations in the full installed map, not recovered original companion pins.
This partial QEMU contract does not certify firmware, socat, KVM, VLAB or image
equivalence. The unchanged `qemu_witness.py` still requires TEST .18 and its
firmware hashes; historical .11 must refuse before launching QEMU.

The explicit disconnected path uses the **same installer** and fixed selection:

```bash
# On the actual disposable target, before other package/policy changes:
sudo python3 build/provision/install-qemu.py --capture-state /tmp/qemu-state.json \
  --base-id gce-image:IMMUTABLE_IMAGE_ID --selection baseline-20260114
# Trusted lead copies that private data to the trusted acquisition host:
timeout --kill-after=30s 9m bash build/provision/prepare-qemu-offline.sh \
  /private/qemu-state.json /private/new-qemu-bundle
# Lead supplies the printed receipt SHA independently of the transferred bundle.
# On the same target after authenticated transfer:
sudo timeout --kill-after=3s 240s python3 build/provision/install-qemu.py \
  --offline /private/new-qemu-bundle --receipt-sha256 EXPECTED_SHA256 \
  --base-id gce-image:IMMUTABLE_IMAGE_ID --selection baseline-20260114
```

Use the same explicit selection for capture and installation. The two-argument
acquisition launcher reads the validated captured selection; it has no independent
selection override. State/bundle v2 bind exact selection/snapshot/pins, immutable
base, source (installer, protocol, bounded helper, acquisition module and launcher),
keyring, status and policy. Nested descriptors/types are checked against source;
received fields never become executable policy. Old v1 or source-mismatched
captures/bundles refuse and are never rewritten or migrated. Capture fresh state
from the actual target after source changes. No new freshness grace or expiry
bypass is introduced: date/Valid-Until checks and all existing budgets remain.

The immutable base identifier is **caller attested**, not a guest proof of GCE
identity. The trusted lead must verify the actual lease/instance/disk-image
binding independently before supplying it. Container tests instead use the fixed
`ubuntu@sha256:…` base identity. A state export is private package inventory, not
credentials; retain it only for the owned transfer and remove it afterwards.
The capture exclusively creates a0600 file. It binds actual status, architecture,
foreign architectures, selections, holds/audit, archive keyring, OS identity,
module files and hashes of supported `/etc/apt` policy files and effective APT
configuration. APT auth credential files are never read or transferred (the separate,
narrowly authorized GHCR record of the canonical trial is described under issue #378).
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
# Separate lead scope required; not activated by ordinary CI:
timeout --kill-after=30s 20m bash build/provision/test-qemu-offline.sh --selection baseline-20260114
```

The existing offline harness passes the digest printed at the trusted acquisition
boundary into the disconnected target independently of the copied bundle. The
target requires that digest and never derives its expected value from its receipt.
Explicit historical selection propagates through actual capture, receive and CLI
calls, and omits ONLY the TEST runtime witness. Default ordinary CI remains TEST
with its witness. Source/fake qualification is not an authenticated historical
acquisition or install result; the later single bounded native trial needs separate
lead scope, actual measured stage outcomes and audited cleanup. Existing shell
traps do not establish independent host-workdir absence or hard-cancellation cleanup.
Both offline launcher finish traps preserve a primary nonzero exit when cleanup
also fails, including 124/130/143; cleanup-only failure prevents success.

For either selection the target harness prints one bounded public JSON report each
for the unchanged installer's install and rerun (`qemu_offline_report`: pins, `changed`,
installer-reported and harness-measured seconds, archive names/sizes/digests), then
`final_installed_package_map` from the rerun. Resolved auxiliary package versions are
reported as found, not pinned. The host launcher prints measured acquisition seconds and
`host scratch absent: PATH` only after rechecking the exact owned workdir (a leftover
fails the run); `prepare-qemu-offline.sh` does the same for its owned output on
failure. These reports do not replace receipt, selection, ownership or package-policy
checks. They do not establish installer-internal scratch absence, global filesystem
or daemon cleanliness, or hard-cancellation cleanup.

The fixed `labapp-qemu-baseline-offline.yml` workflow is manual, main-only and has no
inputs. When separately authorized, it runs one bounded capture/acquisition/install
and rerun with `--selection baseline-20260114`, using the host acquisition result as
the independently supplied expected receipt digest. It omits the TEST runtime
witness; its results establish only the historical two-QEMU-pin package contract.
Ordinary CI continues to use the default TEST selection.

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


### Native Helm install and rerun proof

`helm_native_proof.py` runs the unchanged Helm installer CLI twice in the same
private 0700 caller-owned `ROOT/install`: first `installed`, then `unchanged`.
Its only options are `--root ABS --commit 40hex --tree 40hex` and optional
`--runner-image TEXT`. Invoke with Python 3.12 on Ubuntu 24.04 x86_64, a cleared
environment, and an existing 0700 root containing empty caller-owned 0700 `home`
and `tmp` directories. The production command always selects version 3.19.4,
platform linux/amd64 and network mode; there is no archive override or Helm execution.

The manual-only `.github/workflows/helm-native-proof.yml` has no inputs, fixes
repository/owner/main guards and read-only permissions, and checks out exact
`github.sha` without persisted credentials. A real trial needs separate lead
scope. Source qualification alone provides no native installation evidence.

The bounded stdout report records source/helper/proof and host Python identities,
public archive/member pins, actual JSON and per-call timings. Strict JSON fields
and types bind each independent lstat/hash/lstat target snapshot, including size,
owner, mode, device and inode. The complete first/rerun snapshots, including
mtime/ctime, must match. Only `helm` may remain in the install directory; this
checks remaining entries, not whether a transient stage ever existed.

Fixed initial assumptions are 600s work, 60s cleanup, 185s per installer,
700s outer timeout plus 30s kill grace and a 13-minute job. Grace consumes the
same absolute envelope; no retry or renewal occurs. Deadline124, INT130,
TERM143 and installer nonzero codes survive cleanup failures. The wrapper waits
only for its direct children. Graceful nested curl cleanup relies on the accepted
installer's own killpg/wait; no descendant census is claimed. Forced escalation
fails with nested cleanup unverified. Hard cancellation/disposal is no absence receipt.

Cleanup removes only the observed owned target and exact empty install directory.
Root/HOME/TMP/install identities are checked; unknown children, leftover stages
and replaced paths are retained and prevent success. The later host trap checks
root identity before touching children, removes only exact empty HOME/TMP/root,
and prints each positively observed absence. The wrapper leaves HOME/TMP for
that trap and reports this distinction explicitly. Trusted quiescent paths and
normal OS scheduling are required; this is not a hostile multiuser sandbox.

CI requires the actual `test_helm_native_proof.py` suite with zero-test refusal,
env-i, private0700 HOME/TMP, umask022 and Python-I-B. A parent socket audit hook
and inspected fake children bound offline qualification; the hook is not inherited
child or OS network isolation. Tests exercise the wrapper, the maintained shell
cleanup body, and an explicitly synthetic real-installer archive with recomputed
pins. They never execute Helm or real curl. Checksum-only trust does not prove
GPG/provenance, installed baseline metadata, runtime or full image/course equivalence.

## Pinned public serializer/default asymmetry fixture

`fixtures/pinned-api/main.go` (#394, extended by #400) runs three public inputs
through the pinned upstream code:

- the unchanged canonical `wiringd.yaml` (43 objects: 1 VLANNamespace, 1
  IPv4Namespace, 3 SwitchGroups, 7 Switches, 10 Servers, 21 Connections covering
  all six variants: mclagDomain 1, mclag 2, unbundled 3, bundled 3, eslag 2,
  fabric 10), read only from the fixed read-only mount `/repo/wiringd.yaml` and
  refused unless its SHA-256 equals the pinned value (no caller override);
- the four hardcoded public synthetic controls from #394 (empty VLAN list,
  group/speed ordering, stale labels, original-copy safety);
- a hardcoded public installer-shaped Fabricator and ControlNode, using the field
  shape of the production candidate renderer with only public placeholders (no
  environment, `.env` or private data), plus a separate public control with a
  non-default `spineASN`.

Wiring path: `apiutil` loader (strict decode) on preserved originals; copies are
added to the fake client; `PrintInclude`; a fresh loader reloads the printed YAML;
separate deep copies receive typed `Default()` and ordinary `encoding/json`.
Fabricator path: loader, then `fab.GetFabAndNodes` (DefaultConfig merge, `Validate`
which itself calls `Fabricator.Default`, `CalculateVersions`, control/node
listing with `AllowNotHydrated`), `apiutil.PrintFab`, reload and the same merge
again. The producer records the merge deltas (added/changed/removed config paths),
whether the printed Fabricator is a fixed point of reload+merge+print, and whether
a further typed `Default()` changes it; separate controls prove a set non-default
value survives the merge and that `Fabricator.Default` resets
`LoopbackWorkaroundDisable`. FabNode count is explicitly 0 and ControlNode 1.
`loadedBeforeMerge` and `reloadLoadedBeforeMerge` are independent strict-decoded
typed snapshots captured before each `GetFabAndNodes` call. The
`afterReloadMergeBeforeExplicitDefault` snapshot is already merged, defaulted
by validation and versioned; it precedes only the extra explicit `Default()`.
Originals and the sources of explicit-default copies are checked unchanged.
The raw public ControlNode renderer input omits `dummy`; its pinned value-struct
field survives `encoding/json`'s `omitempty` as `dummy: {}` in typed snapshots,
printed YAML and observed JSON. Tests assert that exact named serialization
delta while preserving every raw input field. Output remains exactly
`expected.yaml` (printed Fabricator, ControlNode and 43 wiring objects),
`observed.json` (`canonical` 45 defaulted objects and `synthetic` 4) and
`meta.json`, created exclusively as owned regular single-link mode-0600 files in
an owned empty mode-0700 directory, totaling at most 1 MiB. The producer prints
each file's size and the total, so whether the full vectors fit is measured, not
assumed; the 1 MiB aggregate and three-file interface are unchanged.

`test_pinned_api_fixture.py` reuses `GuestEnvironment` and calls actual
`api_ready` with the independently produced 45 public objects and actual per-kind
query counts (Fabricator 1, ControlNode 1, FabNode 0, Switch 7, Server 10,
Connection 21, SwitchGroup 3, VLANNamespace 1, IPv4Namespace 1); readiness, node,
kubeconfig and VM-config fakes come from the existing public suite. Expected
metadata is asserted from hand-written endpoint/type tables (cross-checked against
ports in the raw source): per-Connection type and switch/server endpoint labels,
per-Switch profile, group and `default` VLAN-namespace labels and the
`vlanNamespaces: [default]` delta, unchanged values and link order against the raw
canonical YAML, namespaces, and exact ControlNode namespace/spec. The raw
`object_value` asymmetry between printed and defaulted Switch (7) and Connection
(21) objects is still asserted. The independently printed expected set now
passes actual `api_ready` against the independently produced 45 observed objects
through the expected-only projection below (no monkeypatched projection or
version guard), and projection negatives start from that passing pair (missing/wrong/
extra endpoint and generated labels, unknown labels, annotations, specs, IP/ASN/
profile/port drift, link order, identities, counts, version binding, unsupported
and conflicting expected forms). Duplicate tests keep equal collapsed maps to
exercise both production uniqueness guards. Missing, extra, insecure or
oversized fixture files, or zero discovered tests, fail rather than skip.
Separately named matched synthetic controls preserve the earlier printer branch
and strict-comparison coverage; they are not independent production positives.

### Expected-only Switch/Connection projection (issue #406)

`vlab_core.project_expected` deep-copies the installer expected objects and adds
only what the pinned Fabric typed `Default()` generates; observed objects, labels,
annotations and specs are compared exactly and never normalized. Original expected
and observed identities are validated first and both collapsed-map length guards,
per-kind counts, zero FabNode, VM names, queries, caps and deadlines are unchanged.
Projection preserves identity, count and order.

- Switch: absent or empty `spec.vlanNamespaces` becomes `['default']`; labels
  `fabric.githedgehog.com/profile`, `switchgroup.fabric.githedgehog.com/<group>`
  and `vlanns.fabric.githedgehog.com/<namespace>` are derived from the expected
  spec and added when missing. A conflicting existing value is refused. Refused
  as unsupported: unsorted or duplicate `groups`/`vlanNamespaces`, a
  `redundancy.group` absent from `groups`, and `SPEED_*` port speed values (no
  speed stripping, sorting, insertion or reserialization).
- Connection: exactly one structurally valid variant among unbundled, bundled,
  mclag, eslag, mclagDomain (peerLinks and sessionLinks) and fabric (spine/leaf).
  Derives `fabric.githedgehog.com/connection-type` (`mclag-domain` for
  mclagDomain) and `switch.`/`server.fabric.githedgehog.com/<name>` endpoint labels
  from link ports. Empty device/port components, repeated full ports and
  unsupported device cardinalities refuse before label derivation, as required
  by the upstream `Endpoints` path. Endpoint field shapes are checked; hydrated
  fabric-link IP strings are preserved. No VPC label for these variants.
- Fabricator, ControlNode, Server, SwitchGroup, VLANNamespace and IPv4Namespace
  are unchanged.

Version binding: projection is allowed only when `TOOL_PINS[HHFAB]` equals the
pinned hhfab v0.43.1 size/SHA-256 (already verified by the prerequisite receipt
and `verify_contract`), the single expected Fabricator is `v1beta1`, and each
actual installer field `status.versions.fabric.api`, `.controller` and `.agent`
is exactly the string `v0.96.2`. `GetFabAndNodes` calculates these fields and
`PrintFab` retains Fabricator status in `fab.yaml`. Missing, malformed, stale or
`(devel)` affected Fabric versions refuse. Overrides must be absent, `{}`,
`{versions: {}}`, or the exact typed-empty shape `{versions: {platform: {},
fabricator: {}, fabric: {}, gateway: {}, vlab: {}}}`. Value structs retain that
last shape through Go serialization; no recursive empty pruning or nonempty
override is allowed.

The production Fabricator release identity comes from the already verified
hhfab bytes, never from Fabricator status version strings. The public oracle's
ordinary Go build honestly retains `(devel)` in its Fabricator status; that
value is unchanged and supplies no binary provenance or production bypass.
The selected affected Fabric versions plus trusted hhfab bytes bind these
rules; they do not prove deployed CRD/OCI identity. Other mutable status remains
outside the existing identity/labels/annotations/spec comparison.

Not implemented and still unknown: other Fabric versions or general printer forms,
Fabricator
hydration (management/dummy IPs), full migration-branch coverage and `hhfab`
build behavior; what live webhooks, deployed CRDs, OCI bytes or the controller
do. The actual VLAN helper fills zero `to` from `from` and sorts ranges in place;
`Default()` assigns the returned ranges only on error and discards the merged
return on success. The canonical singleton stays unchanged; no generic merging
is presumed. Execution evidence belongs in the associated PR and CI runs;
these assertions do not establish effective deployed behavior.

Source provenance, independently read as raw primary code on 2026-11-01:
[Fabricator v0.43.1](https://github.com/githedgehog/fabricator/tree/65254ebab3cb7173598985dfb9f3f358e08769ca),
commit `65254ebab3cb7173598985dfb9f3f358e08769ca`, pins Fabric v0.96.2 in
`go.mod` and `pkg/fab/versions.go`; the corresponding
[Fabric commit](https://github.com/githedgehog/fabric/tree/8b0aefa0937a95e51cc04ec3ea33fadb06782a99)
is `8b0aefa0937a95e51cc04ec3ea33fadb06782a99`.
[Installer output](https://github.com/githedgehog/fabricator/blob/65254ebab3cb7173598985dfb9f3f358e08769ca/pkg/fab/recipe/control_build.go#L180)
uses `PrintFab`/`PrintInclude`; the
[printer](https://github.com/githedgehog/fabricator/blob/65254ebab3cb7173598985dfb9f3f358e08769ca/pkg/util/apiutil/printer.go#L77)
removes generated labels and last-applied annotations. Fabric's
[label cleanup](https://github.com/githedgehog/fabric/blob/8b0aefa0937a95e51cc04ec3ea33fadb06782a99/api/wiring/v1beta1/meta.go#L99),
[Switch defaults](https://github.com/githedgehog/fabric/blob/8b0aefa0937a95e51cc04ec3ea33fadb06782a99/api/wiring/v1beta1/switch_types.go#L183)
and Connection/Server defaults define the asserted transformations. Source webhook
registration invokes those defaults; the fake client does not run admission.
The pinned [ControlNode value struct](https://github.com/githedgehog/fabricator/blob/65254ebab3cb7173598985dfb9f3f358e08769ca/api/fabricator/v1beta1/controlnode_types.go#L18)
and [Go 1.25.9 JSON omission rules](https://github.com/golang/go/blob/go1.25.9/src/encoding/json/encode.go#L113)
explain the explicit empty `dummy` serialization expectation.

The hosted wrapper compiles only this helper in a temporary command directory
inside the immutable Fabricator checkout, using its unchanged module/vendor tree
with `GOWORK=off`, `GOTOOLCHAIN=local`, `-mod=vendor` and dependency fetching
disabled. No standalone module or generated lock is needed. The exact compiler is
[Go 1.25.9 linux-amd64](https://go.dev/dl/#go1.25.9), archive SHA-256
`00859d7bd6defe8bf84d9db9e57b9a4467b2887c18cd93ae7460e713db774bc1`.

```bash
bash build/provision/fixtures/pinned-api/run-hosted.sh
```

Public source/toolchain preparation needs network access and is distinct from
the isolated fixture execution. The latter has no network, host credentials or
Docker socket, mounts provision sources and canonical wiring read-only, and
uses a bounded disposable workspace. The wrapper supplies
`LABAPP_PINNED_API_FIXTURE_DIR`, runs Python 3.12 with `-I -B` and a fixed provision
import path, and explicitly requires nonzero discovery of `test_pinned_api_fixture.py`.
The required CI job has a 25-minute limit, a 23-minute outer command bound and
a 75-second cleanup reserve. Inner limits are 420 seconds for public preparation,
600 for compilation, 30 for the producer and 90 for Python tests; the outer bound
still governs their combined runtime. Cleanup verifies the exact named disposable
containers, committed preparation image and owned host scratch are absent.

On exit the wrapper also writes one fixed-vocabulary line per cleanup stage to
stderr, `Pinned API cleanup stage=<stage> status=<exit code> outcome=<word>`
(#423), so an `owned cleanup unverified` result names the failing stage. Outcomes:
`command-failed`, `timeout-status` (observed status 124 or 137), `malformed-id`,
`multiple-ids`, `still-present`, `identity-mismatch`, `stat-failed`,
`not-owned-directory`, `outstanding` (create/commit response uncertainty), plus
non-failure `absent`, `none-found`, `command-ok`, `match`. Docker output, names,
IDs and environment are excluded from these new diagnostic lines. Status 124 or
137 can come directly from Docker; 137 may also be another kill, so the label
does not establish a timeout cause. This changes no selector, label, ID, scratch
identity, helper deadline, overall budget or exit behavior: the original primary
status is still preserved, cleanup failure alone still exits 1, and `command-ok`
lines are not an absence receipt (only the unchanged final success line is). It
cannot show what an earlier unlogged run did. The synthetic controls in
`test_pinned_api_hosted_cleanup.py` run the extracted production cleanup functions
against a fake `docker` shell function; a separate control runs the production
`docker()` dispatcher with only `env` replaced by an argv recorder.

Removal limit (#426): generic Docker calls keep the 5s limit plus 1s kill grace. Only
the exact maintained `rm -f <one 64-hex container id>` and
`image rm <one sha256:64-hex image id>` calls get 10s plus 1s kill grace. This is
removal-only tuning after one observed post-merge failure where both removals
returned 124 after about 5s; it is not a proven fix, adds no retry or new deletion
form, and does not change ownership guards. A nonzero removal status (including
124/137, which stay ambiguous with other kills) still fails cleanup even if the
object is later absent, and killing the CLI does not show the daemon rolled back or
finished. Configured-call arithmetic for the worst `finish` path (nine Docker calls):
6 selection/verification x 6s + 3 removals x 11s = 69s, leaving 6s of the existing
75s cleanup reserve for bookkeeping, scratch removal and scheduling. That is
arithmetic, not an absolute completion guarantee. The 23-minute outer bound, 75s
reserve, 25-minute job and 15s+1s preflight are unchanged. CI requires all thirteen
controls without skips before public preparation in the same job, bounded to 15
seconds plus one second kill grace within the existing job budget. Run them separately with
`python3 -m unittest discover -s build/provision -p test_pinned_api_hosted_cleanup.py -v`.

Limits: these are typed decoding/defaulting inputs, not a complete validated
admission topology. The pinned loader enables strict decoding and rejects unknown
fields; ordinary permissive typed Go decoding can discard them. Unknown-spec-field
drift is therefore injected into decoded Python JSON. The checks cover source serializer/
default asymmetry and mocked production comparison behavior; they do not establish
effective live admission, published OCI bytes, canonical11's actual differing field,
full VLAB readiness, or VM functionality. A failing fixture never authorizes
relaxing readiness.

## Dedicated guest VLAB core assembly and preserved-state resume

`vlab_core.py` is a fixed guest component, invoked with Ubuntu 24.04 Python 3.12
and distribution PyYAML 6.0.x/libyaml (`yaml.CSafeLoader`). It consumes an explicit
private Fabricator/ControlNode input and an **already provisioned** package/tool
receipt. It installs no packages or binaries. It is independent of provider
launchers and does not change the existing small builder fixtures. Source tests
prove sequencing and refusals; an actual dedicated guest trial must establish
systemd, networking, eighteen-node readiness and student-state persistence.

Run only inside a dedicated, separately authorized appliance guest. Upstream
hhfab adopts/reconfigures `hhtap*` networking and can delete excess taps; this is
unsuitable for a workstation or shared guest. The outer route must isolate
forwarded ports: hhfab's SSH/6443/31000 listeners bind `0.0.0.0`, even with
restricted controls/servers. This component creates no ingress rule. Its host
bridge policy explicitly selects `hhbr`/`172.30.0.2/21` and all three namespace
bridge netfilter hooks off, without firewall flush. Those are candidate choices;
actual Docker/k3d coexistence and traffic remain trial gates.

Stage `vlab_core.py`, its `owned_process.py` sibling, the unchanged `ensure-bridge-ipv4.py`,
`labapp-vlab-fresh.service`, `hhfab-vlab-resume.service` and
`journald@labapp-vlab.conf` together in a trusted root-controlled directory.
The first command installs exactly those maintained siblings and fixed units;
it refuses conflicting bytes and never starts or enables services during prepare.
All commands require root and clear child environments; no caller working
directory, environment override, arbitrary user/workdir/command or TTY is used.

```bash
# Separately authorized dedicated guest only. Inputs contain private credentials.
python3 /absolute/staged/vlab_core.py prepare --input /absolute/private/input.json
python3 /usr/local/lib/labapp/vlab_core.py start-fresh
python3 /usr/local/lib/labapp/vlab_core.py activate-resume
python3 /usr/local/lib/labapp/vlab_core.py start-resume
python3 /usr/local/lib/labapp/vlab_core.py stop
```

Startup action ordering: each fixed unit runs `unit-gate` (`ExecStartPre`),
`unit-run` (`ExecStart`, a Python wrapper that drops privilege and `execve`s
hhfab) and `unit-ready` (`ExecStartPost`). For `Type=exec`, systemd waits for
execution of the Python interpreter, so readiness can publish `service` while
the wrapper validates its startup snapshot. Whole-state equality at the final
run gate would then reject a legitimate same-operation publication. A run
refusal can leave readiness waiting for the bridge; a later bridge timeout
does not establish the original cause. Earlier trial causes require their own
evidence. Neither wrapper exec nor service activation establishes readiness.

Cold-start bridge ordering (#372, researched 2026-10-31). In fabricator
[v0.43.1](https://github.com/githedgehog/fabricator/tree/v0.43.1) (`pkg/hhfab/`
`cmdvlab.go`, `cmdbuild.go`, `vlabrunner.go`, `cmdhelpers.go`, `vlabconfig.go`),
`vlab up` synchronously builds the control installer (installer payload and
ISO-root downloads) before `VLABRun`; `VLABRun` then prepares taps, where `hhbr` is
created, and only afterwards prepares the ONIE/Flatcar VM images. So `hhbr`
legitimately appears only after the cold installer build, which can exceed 60
seconds; not every download precedes the bridge. `unit-ready` is an `ExecStartPost` of
a `Type=exec` unit (see
[systemd.service(5) v255 source](https://github.com/systemd/systemd/blob/v255/man/systemd.service.xml)),
so it runs while that build is still in progress. In systemd v255
[`service.c`](https://github.com/systemd/systemd/blob/v255/src/core/service.c) a
failed start-post action enters the stop path with SIGTERM to the main process,
as documented for failed `ExecStartPost` commands. The ordering explains why a
fixed bridge timeout can terminate a legitimate cold build; this is source
inference, not a native causal proof. The Ubuntu 24.04 systemd patch set was
not reviewed. Trial findings and execution evidence belong in
[#372](https://github.com/afewell-hh/labapp/issues/372).

Before the unchanged helper call, `unit-ready` runs a core-only prerequisite poll
(`bridge_prerequisite`): one bounded read-only `ip -j -d link show dev hhbr`
per iteration (`BRIDGE_POLL_SECONDS` apart). Only the exact ordinary child
failure (code 1, `child command failed`, bytes `Device "hhbr" does not exist.`
plus newline), without executor cleanup uncertainty, is pending; every other result, exit code, timeout, overflow,
malformed or duplicate JSON, foreign name/kind or non-positive index fails
closed without retry. Before each probe and again right after a positive
observation the published state must equal the snapshot exactly, the original
boot and deadline must validate, and `check_live` must pin the original main
process. Probes and sleeps are capped at the ORIGINAL operation deadline (no
renewal, restart or longer allowance). The existing executor retains its separate
two-second cleanup wait; clipping query work does not bound total cleanup by
the operation deadline. Final readiness still refuses an expired deadline.
Pending probes run with `retain=False`
so they never overwrite `last-command-output`; a genuine probe failure retains
its own non-empty private bytes, including returned malformed/foreign JSON,
without replacing the original failure or code. Timeout and
output-limit failures carry no partial bytes, so the previous diagnostic remains.
The observed ifindex must equal the one the unchanged helper (wait 60, cap 60)
then verifies. This comparison detects observed replacement; it is not an atomic
identity transaction between processes. The unchanged helper contract still
requires the caller to exclude concurrent link recreation. The final
post-inspection `bridge_ready` adds no prerequisite poll and
keeps the helper's existing hard failure; it is not a single-probe claim.

The preliminary startup snapshot binds the original boot and operation deadline
before any sibling lock wait. The locked reread preserves every field except
an absent `service` becoming exactly the live invocation/cgroup/PID/start pin;
null, removed or replaced service values refuse. `unit-run` requires the live
main PID to be its own PID initially and reobserves the original live pin at
its final gate, including when service is absent or already published. All
other state fields remain exact, including nonce, operation, mode, invocation,
phase, boot, deadline, source/static/tool/contract pins and stop ownership.
`unit-ready` alone publishes service, and its final readiness commit compares
its full published snapshot before changing phase/critical/cluster itself.

Only the sibling startup actions wait for the state lock: at most 10 seconds,
capped by the original operation deadline, with expiry checked again after
acquisition. Other callers retain immediate refusal. The final run lock stays
held through privilege drop and exec; Python's non-inheritable lock descriptor
closes on successful exec and the context closes it on failure. A final clock
check after privilege drop prevents late exec. No new operation time allowance,
reconnect or readiness retry is introduced.

Primary sources read 2026-10-31: [Ubuntu Noble systemd.service,
255.4-1ubuntu8.18](https://manpages.ubuntu.com/manpages/noble/man5/systemd.service.5.html)
and [upstream systemd 255 service manual](https://www.freedesktop.org/software/systemd/man/255/systemd.service.html)
(`Type=exec`, `ExecStartPre/Post`, main-process semantics);
[Noble execve, manpages-dev 6.7-2](https://manpages.ubuntu.com/manpages/noble/man2/execve.2.html)
(process replacement and preserved process attributes); and
[Python 3.12 os.open / descriptor inheritance](https://docs.python.org/3.12/library/os.html#fd-inheritance)
(non-inheritable descriptors close at exec on Unix). These document the
scheduling and descriptor contract, not a native appliance proof.

The mocked fixtures in `test_vlab_core.py` call actual `unit-ready` through its
publication and pause at the bridge boundary before/between run snapshots,
for fresh and resume. Separate cold-start cases keep the bridge absent beyond
61 virtual seconds, then complete actual API/inspection/final-bridge checks and
the locked ready commit under the unchanged original deadline. Final helper
absence remains a hard failure with no new prerequisite wait. Mocked executor
cases exercise cleanup uncertainty while preserving the original error and
private bytes. Separate cases specify immutable/service/live PID/start
substitutions, full readiness commit consistency, bounded flock contention and
late acquisition/privilege-drop expiry. These fixtures model source sequencing;
execution evidence is recorded in CI and issue handoffs. Native systemd scheduling,
namespace/cgroup enforcement and actual VLAB readiness cannot be proved by mocks.

The bounded input JSON is mode0600, with no symlink components, duplicate keys,
unknown fields or ambient credential lookup. Its exact fields are:

| Field | Contract |
| --- | --- |
| `schema`, `dedicated_guest`, `nonce` | `1`, `true`, 32 lowercase hex characters identifying this appliance |
| `fab`, `fab_sha256` | Absolute private FAB file and exact SHA256; mode0600; no development credentials |
| `wiring`, `wiring_sha256` | Absolute canonical `wiringd.yaml` and `c522c64d80515c7484a67c27646acebf86073192f0f6ff9597497b990548806a` |
| `package_receipt`, `package_receipt_sha256` | Absolute private receipt and its exact SHA256 |
| `candidate_policy` | Exactly `{"bridge":"172.30.0.2/21","netfilter":"all-three-off","forwarded_ports":"0.0.0.0-isolated-by-route","build":"iso","controls_restricted":true,"servers_restricted":true}` |

FAB must explicitly supply `fab/default` Fabricator plus `fab/control-1`
ControlNode with bootstrap `/dev/sda`, external `enp2s0`/DHCP and management
`enp2s1` (if hydrated, `172.30.0.5/21`). The candidate control settings are
managementSubnet `172.30.0.0/21`, controlVIP `172.30.0.1/32`, kubeClusterSubnet
`172.28.0.0/16`, kubeServiceSubnet `172.29.0.0/16`, kubeClusterDNS `172.29.0.10`,
dummySubnet `172.30.90.0/24`. Candidate Fabric values are spine-leaf,
managementDHCPStart `172.30.4.0`, managementDHCPEnd `172.30.7.254`, spineASN 65100,
leafASNStart 65101/leafASNEnd 65533, protocolSubnet `172.30.8.0/22`, vtepSubnet
`172.30.12.0/22`, fabricSubnet `172.30.128.0/17`, mclagSessionSubnet
`172.30.95.0/31` and vpcWorkaroundSubnet `172.30.96.0/19`. Registry is explicitly
`{"mode":"airgap"}`; host downloads use ghcr.io/githedgehog; no gateway is enabled;
observability defaults is the empty string. Require a stable private joinToken
and private `$5$` passwords/SSH keys for control and switch users; upstream public
development credentials are refused. Official validation remains semantic
authority. These explicit values replace unknown original settings only for a
candidate; they are not historical recovery or release acceptance.

The receipt has exactly `schema:1`, `source_sha256` (declared provisioning-source
SHA256), `packages` and `commands`. Packages include all fixed baseline Docker
trio and QEMU system-x86/utils `.11` versions listed in the baseline runbook,
plus the selected full versions of sudo, socat, openssh-client, less, iproute2,
systemd, kmod, procps and python3-minimal. Systemd must be in the researched 255
family; that is an explicit compatibility boundary, not a recovered version pin.
Installed dpkg status, amd64 and full versions must match. `commands` maps every
fixed command in `AUX` and `TOOL_PINS`
to exactly `{"resolved":"/absolute/resolved/path","sha256":"..."}`; those installed
bytes, owners and executable modes are checked. hhfab 0.43.1 and kubectl 1.35.0 use
the fixed previously documented binary sizes/digests, never receipt-selected pins.
The declared source digest is retained with this trusted private input; it does
not independently authenticate a provisioning run or package provenance. TEST
QEMU `.18` is rejected. Noninteractive sudo, KVM/TUN availability, resource fit,
package acquisition and access isolation are external prerequisites/trial gates.
This is a separate explicit component input, not the JSON output of
`install-qemu.py --selection baseline-20260114`. That historical selection
pins only the two QEMU packages; it does not produce this full selected-tool
receipt or establish auxiliary/firmware versions. Assemble the component input
from independently checked installed facts after separately scoped package
provisioning; do not infer successful installation from source support.

Prepare reserves an absent `/home/ubuntu/hhfab`, imports without `--dev`/force,
validates twice and requires exact FAB/wiring/registry preservation. Failed
preparation retains owned state for diagnosis and cannot retry/reset/adopt it.
Fresh startup is one-shot. It runs the pinned `hhfab vlab up` foreground as ubuntu
only while the sealed result directory is the same owned empty directory,
the prepared work entries match exactly and VLAB state is absent. These checks
run at reservation, gate and immediately before exec; preexisting state is never
adopted, repaired or deleted during fresh startup. It runs
with fixed ISO/restriction/sizing flags, no automatic upgrade, kill-stale, setup
VPCs or retry. Recovered sizes are control 6 CPUs/6144 MB/100 GB,
switch 4 CPUs/5120 MB/50 GB and server 2 CPUs/768 MB/10 GB, with exactly one
control, seven switches and ten servers.
Unused gateway/external size settings do not create additional VMs.

Public activation includes dependency waiting inside a fixed 2700-second fresh
or 900-second resume clock. Short private operation locks are released before
waiting on systemctl. Enabled boot resume begins its clock at the gate; its
pre-gate dependency queue remains nonready and is bounded only by the outer
trial lifecycle, since TimeoutStartSec does not bound queued dependencies.
A separate nonblocking private stop-controller lock covers every outstanding
manager stop through positive containment and the final state commit. Competing
stops and startup reservations refuse while it is held; a delayed controller
must still match its original operation, mode and invocation before stopping.
ExecStopPost takes only the short state lock, so it can finish during the stop.
The root run wrapper uses systemd `!` to retain its filesystem namespace,
reads root-private state and checks actual resume mounts,
then initializes ubuntu groups/gid/uid and execs only fixed hhfab. No `Conflicts`
auto-stop is used. Competing starts refuse without disrupting the running unit.
Root-private state is under `/var/lib/labapp-vlab-core` with 0700/0600 permissions.
Raw foreground diagnostics remain in the `labapp-vlab` journal namespace for
local administrators (`journalctl --namespace=labapp-vlab`). Its explicit config
sets 32M persistent/16M runtime storage policies and disables forwarding to syslog,
kmsg, console and wall. These rotation policies are not an exact hard byte cap;
actual ACL/forwarding/effective configuration remain dedicated-guest checks.
No raw private output, certificates, keys or FAB are exported in public receipts.
Short-command failures retain at most 1 MiB in the root-private 0600
`/var/lib/labapp-vlab-core/last-command-output`, overwriting only the observed
owned regular 0600 path; unknown/replaced/symlinked diagnostic paths are refused.
It is the last failed command's diagnostic, not a transcript or archive. Failure
to retain it never replaces the original operation result. Do not attach this
file to public issues/artifacts: it may include private configuration or keys.

Readiness requires the actual private kubeconfig, trusted embedded credentials
and loopback HTTPS API, `/readyz`, one Ready control, exact canonical Fabric,
node/wiring object sets/specs, persisted VM names/types/sizes/NICs, then bounded
`wait-switches` and `inspect-switches --strict=true --wait-applied-for 30` while
the same invocation/PID/start identity/cgroup runs. Server metadata/status fields
are explicitly excluded from spec comparison; admission/defaulting differences
must be reviewed if an actual mismatch occurs. Logs and service-active status do
not establish readiness. Child output is bounded and not echoed publicly.
Only the pinned kubectl formatter's exact localhost connection-refused message
or bounded single-line ServiceUnavailable response is discovery-pollable; opaque,
authentication, certificate and structural failures stop immediately. Timeout 124
and cancellation 130/143 are never converted to transient startup conditions.

Only after fresh readiness and a bounded owned stop may `activate-resume` seal
and enable resume. The manifest covers exact static inputs/tools/units, cached
result tree/hash/ISO, config/SSH key and all 18 OS/EFI artifacts, plus cluster UID
and CA identity. Mutable OS and EFI-vars preserve device/inode/type/owner/mode;
ordinary disk writes, sizes and timestamps may change. Missing/replaced/changed
critical files fail before up. Critical regular files must have one link.
Optional recreated logs and
sockets still require no-symlink/type/owner/write-permission checks; root-written
serial logs and private diagnostics also reject hardlinks. Generated kubeconfig
and SSH public-key paths may refresh but cannot be redirected through links.
The fixed cache and its .cache parent reject links, wrong owners and group/world
write permission; absent cache paths are allowed, without a recursive cache census.
Result/static inputs are read-only in the actual
resume run namespace; if upstream wants a rebuild, the kernel denies it. This
is not proven by fakes and excludes hostile root/remount/concurrent mutation.
Generated kubeconfig may refresh; CA and cluster identity must persist.

Stop requests only the exact recorded service invocation/cgroup: TERM for 20 seconds,
then systemd KILL and 35 seconds of public observation. It verifies inactive/failed,
PID 0 and absent/unpopulated exact cgroup. This is **process termination, not proven
guest OS shutdown**. No student-state deletion or broad stale-process cleanup
occurs. An explicit stop intent binds the current operation and service invocation;
expected nonzero upstream cancellation is allowed only through that owned stop.
ExecStopPost records stop observation first; a new resume cannot reserve until
the public stop verifies exact cgroup containment. Unexpected service exits
remain failed. No global exit-code whitelist or automatic restart is installed.
Run the public `stop` command before an outer guest shutdown/reboot. Direct
`systemctl stop` or an OS shutdown without that owned stop intent remains failed;
this component does not establish seamless reboot or cloud stop/start behavior.
Those outer transitions need separate lifecycle acceptance.
Primary nonzero/INT 130/TERM 143/deadline 124 survives cleanup uncertainty;
uncertainty is reported rather than asserting containment. Direct/boot partial
startup failures are recorded through ExecStopPost. Normal future appliance
service lifetime has no implicit cap; disposable trials separately require their
immutable outer lifecycle deadline and cleanup allocation.

Offline tests execute maintained actual entrypoints with inspected fake commands,
private public fixtures, full fresh→stop→activate→resume transitions, no-rebuild
refusals and signal/timeout containment. Required CI uses an empty private HOME/TMP,
cleared environment, Python-I-B, parent socket audit denial and zero-test refusal:

```bash
python3 -m unittest discover -s build/provision -p test_vlab_core.py -v
```

The audit hook is not an inherited child or OS network sandbox. Executor-only
tests launch inspected Python stdlib children; all guest command paths are fake.
No synthetic test establishes actual systemd namespaces/cgroups, networking,
cluster boot, disk quiescence, nonce persistence or course compatibility. Direct
service replaces historical tmux behavior; kubeconfig merging/default contexts,
desktop/EMC/GitOps/telemetry and complete course behavior remain separate gates.

## Fixed disposable trial coordinator and early guardian

`vlab_trial.py` is shared guest logic for one dedicated canonical trial. It
composes the existing unchanged QEMU, Docker, hhfab and kubectl installers with
the public VLAB core prepare/start/stop/resume interface. It is Python3.12 on
Ubuntu24.04 amd64, root-only, fixed paths/argv/environment, independent of cwd;
there is no arbitrary command, plan, plugin, source URL or user selector.
GCP lifecycle/owner access belongs in `build/gcp/vlab_trial.py`.

The authenticated owner transfers a fixed flat file table into a fresh owner0700
directory. A fixed isolated stdlib root primitive validates the exact coordinator
digest before executing it. Bootstrap validates every manifest path/size/hash,
regular/no-link/single-link file and total transfer bound before exclusive
root0700 staging. It installs only one fixed guardian unit. No package download,
installer, Docker start or core operation precedes its one-shot boot/lease
reservation and active guardian binding. Root bootstrap failures retain the
reservation and attempt exact service stop; they never retry or rebaseline.

The guardian monitors its owned worker, immutable boot, ten-second owner
heartbeats with thirty-second loss bound, and five-second cheap filesystem/
MemAvailable/OOM samples. Worker admission also verifies the original guardian
parent and unit cgroup. Public core stop contains its exact services; separately
owned package-created Docker socket/service and containerd are stopped and
observed inactive. Worker/group reaping and guardian cgroup membership are
separate positive gates. ExecStopPost supplies independent containment if the
SSH-facing process disappears; killing a client alone is insufficient. A lost
receipt or uncertain containment never becomes clean success. Primary124/130/
143/nonzero survives secondary cleanup errors.

Replaced guardian state (#422). `phase.json` and `heartbeat.json` are published by
exclusive temp file plus `os.replace`. An open descriptor remains usable after replacement,
but its old inode can lose its last link between `regular()`'s two `fstat` calls.
Only the exact observed signature (initial guards passed, byte count equals the
initial size, dev/ino/size/mtime/uid/gid/full mode unchanged, link count exactly 1 to 0,
ctime changed) is a private `Failure` subtype with the unchanged "file changed"
message/code/category. Four guardian sites (initial and post-auth heartbeat, supervision
phase and heartbeat) go through `guardian_state()`: the first such failure's bytes are
DISCARDED, the original `Clock` is checked, one more complete `regular()` runs (at most two
application-level reads of 4097 bytes, no sleep, third attempt or renewal), and the clock is
checked again. Any other change, a second failure, expiry or signal is the terminal primary.
Parsing, age, boot, resource and OOM checks apply to the consumed bytes unchanged.
Phase recovery checks the original persistence cutoff, then the consumed phase's cutoff;
heartbeat recovery uses the original stage or consumed phase cutoff. The loop checks that
same consumed phase cutoff after heartbeat parsing and freshness, before continuing.
Strict readers (`result.json`, auth/credential, contract, writer sequence,
`auth_publish_check`) never recover. This proves neither legitimate publication, ordering
nor interference-free history, and does not establish the cause of canonical13.

All cutoffs are absolute from durable admission, with wall AND monotonic bounds:

| Phase | Cutoff in minutes |
| --- | ---: |
| Identity/access | 15 |
| Stage/provision/prepare | 35 |
| Fresh readiness | 70 |
| Strict checks and nonce creation | 80 |
| Public stop/offline image audit/resume | 95 |
| Persistence/nonce removal/owned stop | 105 |
| Independent outer cleanup | 120 |

The core2700/900-second caps are maxima; each caller uses the earliest remaining
phase/work bound. No retry resets, reserve borrowing, outer reboot/stop, resize,
sealing or capture is implemented. A five-second sample can miss bursts and
does not prove immunity to disk-full or memory exhaustion.

Auxiliary provisioning reuses `qemu_offline.setup` with the fixed signed Ubuntu
snapshot20261024, preserving all installed stock versions. It resolves missing
sudo/socat/SSH/less/iproute2/systemd/kmod/procps/Python/PyYAML/CA/curl/keyring/gpgv
and the complete simulated dependency closure before mutation, rejects upgrades,
removals/downgrades/holds/repair, pins the full closure, downloads authenticated
archives and installs with no-download. Source/index/archive and before/after
dpkg/audit receipts remain root-private. These auxiliary selections are candidate
facts, not recovered original pins. In particular historical two-QEMU-pin .11
proof does not supply socat or the complete prerequisite receipt.

Existing installers run once with their real CLI interfaces: QEMU
`--selection baseline-20260114`, Docker `--receipt`, hhfab `--version 0.43.1
--archive`, kubectl `--version 1.35.0 --platform linux/amd64 --binary`. Their
separate actual receipts/source evidence are retained. The core schema1 package
map is exactly PACKAGE_PINS|AUX, with fixed resolved command paths/hashes and
verified root ownership/modes/status/amd64/tool bytes. Parser, systemd255,
dedicated ubuntu home/sudo, KVM/TUN and daemon checks precede prepare. The fixed
account adaptation adds only the verified dedicated ubuntu to the new
package-created docker group, then verifies fresh runuser credentials, daemon
executables/root identity and the root:docker0660 Unix socket. Unexpected stock
policy refuses; there is no arbitrary account or chmod repair.

Require >=250GiB free/>=96GiB MemAvailable after stage, staging/cache<=160GiB,
and runtime stops below64GiB/16GiB or on OOM. Existing input/cache allocation
observations are bounded before fresh start. Upstream v0.43.1 creates/downloads
selected images inside `vlab up` and supplies no prepare-only public command;
there is deliberately no duplicate image-preparation implementation. Complete
cold preboot eighteen-image audit is therefore **unmet**. After verified public
stop and before resume, the coordinator records all eighteen offline image
formats/virtual/physical sizes and refuses backing chains, then checks the
staging cap again. No recursive scan or qemu-img probe runs against live disks.

Strict canonical inspection plus real fixed server SSH/API operations precede
nonce VPC/attachment creation. Only default-namespace nonce names, unused
10.0.254.0/24/VLAN2998 and canonical server-01 mclag connection are selected.
The shared object name is only a locator: `l` plus the first ten hex characters
of SHA256 of the full nonce (40 bits, 11 characters, lowercase RFC1123).
Pinned primary sources, accessed 2026-10-31:
[fabricator v0.43.1 version defaults](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/fab/versions.go),
[version calculation](https://github.com/githedgehog/fabricator/blob/v0.43.1/api/fabricator/v1beta1/fabricator_types.go)
and [Fabric installation](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/fab/comp/fabric/fabric.go)
select Fabric API/controller v0.96.2 without overrides. That version's
[VPC validator](https://github.com/githedgehog/fabric/blob/v0.96.2/api/vpc/v1beta1/vpc_types.go)
limits names to 11 characters; its
[metadata validator](https://github.com/githedgehog/fabric/blob/v0.96.2/api/meta/validation.go)
requires lowercase RFC1123 subdomains and namespace `default`. The
[webhook handler](https://github.com/githedgehog/fabric/blob/v0.96.2/pkg/webhook/vpc/vpc_webhook.go)
delegates to that validator, with CREATE/UPDATE wiring in the
[source manifests](https://github.com/githedgehog/fabric/blob/v0.96.2/config/webhook/manifests.yaml).
This is source inference: published OCI chart bytes and the live effective
controller/admission behavior have not been inspected or validated here.
The locator can collide and is never ownership
authority. Ownership is the full nonce in annotation
`labapp.hedgehog.com/trial-nonce` on BOTH the VPC and the attachment, together
with the receipt UID and expected spec; all must match exactly in each create
response, persistence verification, pre-delete read and deletion poll.
Creation is create-only, refuses ANY pre-existing object of either name (even
one whose annotation matches; nothing is adopted or overwritten) and retains
returned UIDs/defaulted specs, names and full nonce after each create. Same
CA/cluster and nonce UID/spec/annotation persistence must survive public
stop/resume. Deletion removes the attachment first, then the VPC, using exact
UID-preconditioned DeleteOptions through kubectl raw DELETE, and verifies
absence within the unchanged phase cutoff. Each DELETE has its own fresh
ownership read, including the VPC after the attachment deletion wait. If a
later create response fails ownership checks, the receipt retains only the
earlier verified objects; it does not declare the two-object create complete.
Mocked admission tests model the
documented contract; they are not native validation of the live webhook.

### Transient GHCR registry authentication (issue #378)

Primary sources: [Hedgehog download prerequisite](https://docs.hedgehog.cloud/latest/getting-started/download/)
(`docker login ghcr.io` with the provided username and token),
[docker login](https://docs.docker.com/reference/cli/docker/login/) (config file;
base64 `auth` storage when no credential store is used) and
[tmpfs](https://docs.kernel.org/filesystems/tmpfs.html) (pages may be swapped; the
`noswap` option disables it). Source access on 2026-11-01: the initial worker
used summaries only; the revision worker read raw Docker CLI `login.md` and Linux
`tmpfs.rst` from their maintainer repositories, and the raw Hedgehog download
page's login section. These current documentation pages do not establish guest
runtime behavior. Fabricator v0.43.1 Docker/ORAS/containers-image behavior relies
on the lead's pinned raw review in #377.

Source contract (new synthetic tests are written but unrun; no guest proof):

* **Input.** `bootstrap` gains the single fixed option `ghcr-auth`. Only then it
  applies `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0`, refuses before creating any state unless
  `/run` is the standard `tmpfs` with no active swap area (or an explicit `noswap`
  mount), the target is absent and no fallback store exists, and later reads at most
  1 KiB from stdin (EOF required). Read and guardian gate share one original cutoff,
  fixed before guardian startup at at most 10 s and clipped to the original stage
  clock and startup heartbeat grace. Neither read nor gate appends time. The record has exactly
  `schema=1, registry=ghcr.io, username, token` (bounded character sets); no other
  registry, helper, `identitytoken`/`registrytoken`, URL, command, path or field.
  Refusals use fixed text and never echo input.
* **Arming before secret.** Root-private `auth-intent.json` (nonce, ubuntu uid/gid; no
  secret) is written before the guardian starts. The secret is read only after the
  guardian is started, bound to the lease/nonce/boot and confirmed as the active main
  process. Publication rechecks the original guardian receipt, cgroup liveness,
  complete contract, source manifest/bytes, boot and original cutoff under a bounded
  root-private lock. No lock is held across stdin. The guardian blocks at the shared ready gate: no worker or
  provisioning can run until `auth-ready.json` exists and the config verifies; gate
  expiry, lost bootstrap/channel or invalid input fail closed into containment.
  Before spawning, the guardian rechecks boot, its original clock and heartbeat.
  The worker re-verifies before any package action and again immediately before
  `start-fresh`.
* **Location and identity.** Fixed `/run/labapp-vlab-docker` (`DOCKER_CONFIG`),
  constructed root-private (`0700` directory, `0600` file) and kept root-owned for
  its entire lifetime. After writing, root grants only read/search to the actual
  `ubuntu` primary group: root:ubuntu directory `0750`, config `0640`. The primary
  group must be named `ubuntu`, have no other named members and be no other
  account's primary group. The reader receives no directory or file write access,
  so it cannot rename, replace or chmod the original objects. No ACL dependency or
  writable Docker login store is needed: this is a read-only client config.
  Paths are created without following links, `mkdir` refusing preexisting paths. The directory identity
  (device, inode, intended reader identity) is recorded in root-private `auth-bound.json` BEFORE the
  secret exists; `auth-file.json` binds the exact file device/inode before the first
  secret write, including partial writes. File inode and config size are recorded
  in `auth-ready.json`; no secret value or digest enters root records.
  Open descriptors are checked against current pathnames, exact device/inode,
  owner, mode and single link before every secret write, before the read grant and
  before readiness. Protection covers unprivileged reader mutation, not root or
  an authorized reader copying credentials elsewhere. `vlab_core.SAFE_ENV`
  (which replaces the environment) exports only `DOCKER_CONFIG`; the fresh unit sets
  `LimitCORE=0` for the hhfab readers. These are conventional process limits, not
  a no-disk guarantee: ordinary exec resets dumpability and piped system core
  collectors may ignore `RLIMIT_CORE`. No global collector/sysctl policy is changed.
  Fallback stores Docker/ORAS/containers-image can
  consult (`~/.docker/config.json`, `~/.dockercfg`, `~/.config/containers/auth.json`,
  `/run/containers/<uid>/auth.json`, `/run/user/<uid>/containers/auth.json`) must be
  absent and are never adopted or deleted. tmpfs on a path under `/run` is not a "never
  on disk" guarantee; the swap/`noswap` check is the enforced control and a later
  `swapon` is only caught by the repeated pre-`start-fresh` verification.
* **Cleanup.** Cleanup permanently closes publication before checking absence or
  waiting at most two seconds for the shared lock, clipped to the original cleanup
  cutoff. A stopped publisher cannot recreate credentials after verified clean
  removal. A publisher already holding the lock can finish an in-flight write;
  cleanup must acquire that lock and remove its output before proving absence.
  Lock timeout reports uncertainty; cleanup never waits indefinitely. `auth_remove`
  is idempotent and identity checked: it deletes only the bound
  directory's single regular, single-link, root-owned `config.json` through the
  open directory descriptor, after matching the file's exact device/inode receipt
  and freshly validating current names, then the bound directory. Cleanup accepts
  the exact private construction modes or final read-only modes. It writes exact
  nonce/device/inode unlink and directory-removal receipts only after those actions.
  A known file or directory disappearing without its matching positive receipt is
  uncertain, including an unexpectedly empty directory; absence alone never proves
  removal of a published object. Any link, extra entry, replacement,
  wrong owner/mode/link count or missing binding is NOT deleted; it raises a fixed
  `credential cleanup uncertain` failure (`cleanup_uncertain`). An interruption
  before an identity receipt becomes durable leaves an unbound object untouched
  and uncertain; cleanup never adopts a plausible partial file. The worker removes and
  verifies absence right after `start-fresh` (checkpoint `auth-remove`), before strict
  checks, stop, resume or success, and asserts absence again before `start-resume`.
  Canonical absence checks also refuse newly appeared fallback stores without
  reading or deleting them. Standalone core
  `unit-run --mode resume` refuses a present directory. `containment()` (guardian
  `finally` and `ExecStopPost`) runs the same removal after stopping readers and even if
  a stop failed; uncertainty withholds `contained` but the primary result code is
  preserved and VM disposal is independent. Bootstrap failure after arming stops the unit
  and removes the exact owned config as well.
* **Not claimed.** No guarantee the registry or Docker daemon memory never held the
  credential, no secure erase, and no proof that Fabricator 0.43.1 consults only
  `DOCKER_CONFIG` (fallback absence is enforced instead). The first live trial is
  separate lead-scoped runtime proof.

Tests: `TransientRegistryAuth` in `test_vlab_trial.py` (synthetic canaries, real
functions, temporary mount/swap/home/run stand-ins), `RegistryCredentialEnvironment` in
`test_vlab_core.py` and the owner tests in `build/gcp/test_vlab_trial.py`.

### Closed failure diagnostics (issue #364)

The guardian's only result is `result.json` schema2: exactly `schema`, `code`,
`contained`, `nonce` and `diagnostic`, where `diagnostic` has exactly `origin`,
`phase`, `operation`, `category`, `child_status`. All values come from reviewed
source literals (`OPERATIONS`, `CATEGORIES`); there is no argv, path, user,
exception text, stdout/stderr, FAB, kubeconfig, password or token in it, and
schema1 is rejected. `child_status` is the raw status of the one positively
observed child (negative is a signal, nonnegative an exit) or null; it never
infers an OOM cause. The final file is at most 4096 bytes.

* `origin`: `worker` (a fixed checkpoint failed), `guardian` (the guardian itself
  observed the failure: heartbeat, OOM counter, resource floor, boot, phase
  cutoff, spawn, or a direct worker signal) or `unknown` (a nonzero worker exit
  without a usable terminal status; phase/operation are then only the last valid
  checkpoint seen, context and not proof of cause).
* The worker takes sole ownership of root-0600 `worker-status.json` by exclusive
  create, only after its contract/lease/boot/original-guardian-pid and current
  guardian-cgroup checks, and
  commits the next fixed `(phase, operation)` BEFORE each operation. A checkpoint
  write failure stops that operation. A claim collision or earlier binding
  failure writes nothing. The guardian is the sole writer of `result.json`, and
  only after its exclusive `started.json` reservation: contract, clock, boot and
  reservation failures (including a collision) publish no result and cannot
  replace an incumbent's. Status can never set `contained` or any receipt.
* Truth table, from the ACTUAL worker termination: exit0 plus a nonce-bound
  `succeeded` terminal at `persistence/complete` is the only success; exit0
  without it is code1 `status-invalid`. A positive exit with a matching `failed`
  terminal reports that worker diagnostic; without one it is `unknown`. A
  negative returncode (direct worker signal) is code `128+N`, origin `guardian`,
  operation `worker-supervision`, `child-signal`, never an inner operation. An
  internal child exit137 (`child-exit`, 137) and an internal child signal -9
  (`child-signal`, -9) both give worker code137 but stay distinct. Helper
  timeout is `child-timeout` (null status); an ordinary child exit124 stays
  `child-exit`. Only the two fixed `hhfab_release` messages are classified.
  In-process core failures are reduced by the core's fixed message literals only;
  the core folds a signal-killed child into 1, so code1 is `core-refusal` with
  null status. Only positively proved exits2..255 retain `child-exit` and that
  exact status. Both worker-status and final-result validators enforce observed
  exit E -> code E and signal -N -> code128+N; null remains unobserved and
  `status-invalid` carries context rather than child provenance.
* The primary code and diagnostic are captured before containment. Reap,
  containment, status and result-write trouble can only clear `contained` or
  degrade the diagnostic; `code0 + contained false` stays an operational failure.
  Watchdog order is unchanged: what the guardian observed first is reported.
* Not covered: a syntax or import error of the guest module, exec failure,
  SIGKILL of the guardian, disk exhaustion or an unwritable private directory
  can leave no result; the host reports `unavailable`/`pending`, or `missing`
  after a terminal manager observation and bounded reader recheck.
  The historical failed trial's guest cause is unknown and this does not diagnose it.

#### Root-private first-failure bundle (issue #368)

The public boundary above is unchanged: a failed `start-fresh` still reports the
core's outer status (1 is ambiguous `core-refusal`) at `core-start-fresh`, with no new
labels or worker transport, and no nested manager/hhfab status is promoted into the
worker code. Detail needed to find the actual cause is kept in ONE root-private
`/var/lib/labapp-vlab-core/first-failure.json` (root 0700 directory, mode 0600,
single link, at most 32 KiB SERIALIZED including base64/JSON escaping).

* **When.** `start()` now holds `reserve()` inside the same failure path. On the first
  failure the bundle is written BEFORE `cleanup_start`, so a later
  `last-command-output` overwrite, stop or cleanup failure cannot change it. First
  failure wins (`link()` never replaces; an existing file or symlink is left alone).
  Writing is diagnostic only: any error is swallowed (`first-failure capture unverified`
  on stderr), the primary exception and exit status are untouched and `cleanup_start`
  runs with its unchanged 35 s budget.
* **Binding.** Header: state nonce (the trial nonce), `mode`, `operation`,
  `invocation`, boot id and a derived `stage` (`reserve` | `manager` | `unit` |
  `final`; a coarse locator, not a per-substep proof). A reservation refusal has no
  operation of this call, so `operation`/`invocation` are null only for matching
  `prepared` state with no mode/operation/invocation keys. Conflicting live bindings
  are refused at capture, guest export and host acceptance; no older state
  operation, manager history or journal is adopted. If the state is unreadable or
  differs from the reserved operation, the `state` section is `unavailable`/`invalid`
  and `invocation` is null.
* **Sections** (each `ok | truncated | unavailable | invalid`, raw bytes base64):
  `primary` is the in-flight `Failure.private_output` (tail, at most 2 KiB), the fixed
  Failure message literal and code; it is `unavailable` when the exception has none
  (never an exception `repr`). `command_context` is a separately labeled observation:
  "last failed command output observed before manager-wrapper overwrite/core cleanup".
  It reads only the fixed `last-command-output` file, at most a 2 KiB tail, with
  descriptor/path identity, root ownership, regular single-link 0600 and stable
  size/timestamp checks. Missing, unsafe or changed files are `unavailable`.
  The outer `systemctl start` alone uses `retain=False` so its generic output
  cannot overwrite that context; its actual bytes still belong to `primary`.
  This does not identify the first inner failure, prove hhfab executed or grant
  readiness/containment authority. `state` is a fixed token subset. Without a
  proven frozen invocation, manager execution evidence stays `unavailable` with
  empty output and no query, even if this call has a reserved operation. `manager` is one
  `systemctl show --no-pager --timestamp=us+utc` of the fixed unit for `ActiveState,
  SubState,Result,InvocationID,ExecMainCode,ExecMainStatus,ExecMainPID,
  ExecMainExitTimestamp,ExecStartPost` (at most 2 KiB, 2 s; same single query,
  the last two properties and the timestamp option were added for #387). The raw
  bytes are kept opaque: no timestamp parsing, ordering or cause label. `manager.status=ok`
  means a bounded capture with the matching frozen `InvocationID`, not that every
  requested property is present or meaningful; missing, `n/a`, zero or truncated
  values stay unknown. `ExecStartPost` code/status shows only that command's reported
  outcome, not who initiated a failure; exit timestamps are manager reaping
  observations subject to clock changes, ties, notification/reaping order and
  cancellation races. Neither proves the sender of a SIGKILL or excludes an earlier
  fault. Sources (systemd v255, read 2026-11-01): `src/systemctl/systemctl-show.c`,
  `src/systemctl/systemctl.c`, `src/basic/time-util.c`, `src/core/dbus-service.c`,
  `src/core/dbus-execute.c`. This is source reading only: there is no native runtime
  proof, and Ubuntu's patched behavior is unvalidated. Offline tests use fixture text. A different
  `InvocationID` makes it `invalid` (output dropped); a forgotten unit makes it
  `unavailable`. `journal` runs only with a frozen invocation: `journalctl --no-pager
  --namespace=labapp-vlab --lines=64 --output=short-monotonic _BOOT_ID=<boot without
  dashes> _SYSTEMD_INVOCATION_ID=<frozen> _SYSTEMD_UNIT=<fixed unit>` (at most 8 KiB,
  8 s). It remains allowed when the manager forgot the unit, and there is no unit-only
  fallback or history search. Success is never assumed from missing `ExecMain*`.
* **Bundle schema 2 and `unit_ready` (issue #390).** The bundle schema is now `2` (state,
  host envelope and public result schemas are unchanged). The shared guest/host validator
  accepts only schema 2; there is no legacy schema-1 fallback because host and source are
  pinned together. A new exactly typed private section `unit_ready` is
  `{status, message, code}`: only `status=ok` carries a validated message (printable ASCII,
  1..128) and strict integer code (0..255); `unavailable` and `invalid` require null
  message and null code. It is a diagnostic observation inside the existing 32 KiB serialized
  cap, with unchanged primary/command-context/manager/journal bounds, one manager and one
  journal query, the shared 10 s capture/reap budget and the 35 s cleanup.
  * **Record.** `unit-ready` writes one fixed root-private
    `/var/lib/labapp-vlab-core/unit-ready-failure.json` (at most 1024 bytes, root 0600, single
    link, root 0700 directory) using the same exclusive temp + `link()` first-writer pattern:
    it never overwrites, adopts, retries or deletes a stale record or stale temp file. Exactly 12 keys:
    `schema` (1, this record's own), `source` (`vlab_core`), `action` (`unit-ready`), `nonce`,
    `mode`, `operation`, `invocation`, `boot`, `started`, `deadline`, `message`, `code`. There is
    no argv, command output, raw exception or `repr`, credential, step/kind, wall-clock timestamp
    or public notice. A `Failure` originating in this source keeps its text only if it is
    printable ASCII 1..128 with a strict integer code 0..255 (the outer status is unchanged);
    any other exception, or an unsafe text/code, records only the fixed `operational failure`
    with code `1`.
  * **When.** Only at the actual `unit_ready` failure boundary, after the ORIGINAL
    `startup_snapshot` succeeded and after the readiness locks unwound. Before publishing it
    revalidates the original nonce, mode, operation, invocation, boot, started and deadline
    against the current state, the unit's `INVOCATION_ID`, the absence of any owned-stop
    intent, the original boot and the original absolute operation clock; a failure before the
    snapshot, an expired clock, a stop intent or any mismatch writes nothing, and authority
    is never rebuilt from later state. `KeyboardInterrupt`, `SystemExit` and the exact handled
    `Failure('terminated', 130|143)` are excluded; a genuine child command exiting 130 or 143 is
    recorded (it has other text) and is not judged by its code alone. No new process, systemd,
    journal or network query, wait, retry or renewal is made. Any secondary diagnostic error or
    signal is swallowed, so the same exception and exit status propagate and cleanup is
    untouched.
  * **Outer read.** The first-failure capture reads the record ONCE (no wait, no reread) with
    descriptor and path identity, no-follow/non-blocking open, regular file, root 0600, single
    link, size, duplicate-key and strict-schema checks, and compares every binding including
    the clocks to the ORIGINAL reserved operation. Unlike the writer's original
    `startup_snapshot`, the outer `reserve` snapshot deliberately has no invocation.
    Current nonce, operation, mode, boot, started and deadline must equal that reserve
    snapshot, and its boot must equal the live boot, before the current invocation
    frozen in the bundle header can authorize this section. `unit_gate` publishes that
    invocation once; the record never supplies invocation authority. Missing current
    state or a frozen invocation prevents an authoritative read; a mismatch is refused
    for this section without changing manager/journal selection. Missing (or late)
    is `unavailable`; unsafe, changed, malformed or foreign is `invalid`. A reader error
    never discards the other sections or prevents cleanup.
  * **Lifetime.** Same as the core `prepared` state and the first-failure bundle: `prepare`
    refuses an existing root, a failed fresh start cannot be resumed, a successful fresh start
    writes no failure record, and a later normal resume may record its own. A stale or
    unsupported-recovery record stays `invalid`/unknown. There is no cleanup, rotation or
    adoption machinery.
  * **Meaning and limits.** Missing is unknown. The record is the refusal this process
    observed, never the initiating cause. Independent hhfab failure or cancellation may
    precede or follow it; manager reaping order does not establish causality, and journal
    truncation may omit the refusal. Nothing here supports a 20-minute
    inference or a kubeconfig-race assumption, and no readiness, timeout or retry changed.
    Offline fixtures use fake commands, clock and files for the real `unit_ready`/`start`/
    `main`/export/host-accept paths; they are not native systemd scheduling, and filesystem
    non-preemptibility between the revalidation and the link remains a documented limit.
* **Budget.** Both queries share one absolute deadline
  `min(start end, now + 10 s)` that includes spawn, I/O, kill/reap and pipe close
  (the last second of each query is held back for containment). If the original
  start work budget is exhausted, capture is fully skipped, including file-only
  sections. No wait or signal renews the deadline; late spawn/cleanup/close is
  uncertain. `query_cleanup`
  is `confirmed` only after the direct child was reaped and its process group is
  positively gone, otherwise `uncertain`. This is the GUEST process namespace: an
  uncertain guest query is contained by the guardian and VM disposal and is never
  reported as a clean capture.
  The deployed sibling is byte-identical to `build/gcp/owned_process.py`, guarded
  by CI `cmp`. It keeps the leader unreaped through all destructive signals,
  observes with `waitid(WNOWAIT)`, uses one final positive-PID wait, then requires
  group ESRCH. Lost ownership refuses further destructive signals. Normal child
  wait semantics and no foreign reaper are prerequisites; escaped sessions are
  outside this process-group boundary. `Popen` itself is not interruptible here:
  a late return cannot be reported as within-budget cleanup.
* **Untrusted.** Raw sections may contain anything hhfab, kubectl or a unit printed
  (possibly credentials). They stay root-private and are never read by the worker,
  never staged into candidate/images/CI artifacts/GitHub.
* **Retention.** The file lives in the disposable trial VM's core state directory
  until that VM is disposed. It is not copied by any build step.
* **Export.** `vlab_trial.py export-failure --nonce N` (root, no path argument, same
  call style as `heartbeat`) prints `absent`, the fixed token `invalid`, or
  `<envelope>\n<bundle>`. The envelope is built from `contract.json`
  (`source_sha`), the LIVE core `state.json` (`operation`, `invocation`) and the live
  boot id, independently of the bundle header; the bundle must match it and the
  contract nonce/boot. Operation and invocation equality includes null values;
  null reservation requires legitimate prepared state. The strict validator (`first_failure_bundle`) is shared with
  the owner host. A root-compromised guest could forge both records; the check detects
  stale, foreign or replaced data, not a hostile root, and all bytes remain untrusted.
  Only after contract, nonce and live-boot validation, a missing core root also
  returns `absent` (no available bundle); it cannot distinguish never-created
  from moved/deleted state. Dangling or live links, wrong type/owner/mode and
  malformed or foreign bindings remain refusals. A host-origin failure still
  permits the existing one-shot export because a guest failure may be concurrent.
* **Mode binding (issue #412).** The remote command is unchanged and takes no mode.
  The expected mode is `fresh` unless the nonce-bound terminal `result.json` (read once
  through the existing `result_record` validator and 4096-byte bound) is a failed
  `worker` diagnostic with phase `resume` and operation `core-start-resume`
  (`terminal_export_mode`); then it is `resume`. A missing, unsafe, oversize, foreign or
  invalid record, a success, or any other diagnostic keeps `fresh`. The expected mode
  is never taken from the bundle, the live core mode or manager output. The bundle
  mode, the live core mode (when an operation exists) and the envelope mode must all
  equal it; source/nonce/boot/operation/invocation and null checks are unchanged.
  Limits: a refusal inside the resume reservation (before a new operation commits)
  intentionally captures nothing (`absent`), and a stale first-writer bundle from an
  earlier refused attempt is neither cleared nor rebound, so its export stays refused.
  Diagnostic export compatibility does not establish the cause of a resume failure.

The diagnostic runner fixtures (`test_vlab_core.py`) mock Popen, waitid, killpg,
selector/I/O and monotonic time while exercising the actual runner and unchanged
OwnedGroup; they start no child. Other existing executor tests remain separate.
Offline bundle fixtures (`test_vlab_core.py`, `test_vlab_trial.py`) use fake queries and
files; they do not show native systemd scheduling, real `journalctl` selection or
namespace retention, or VLAB readiness. The cause of canonical run 41242950882/1
remains unknown.

Version scope: Ubuntu 24.04's systemd 255; official version-255 documentation
read 2026-10-31: [systemd.exec](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html)
(`SERVICE_RESULT` is a service result; main-process exit variables require an
identified main process), [journalctl](https://www.freedesktop.org/software/systemd/man/255/journalctl.html)
(different field matches combine with AND; an exact namespace selects that journal),
[journal fields](https://www.freedesktop.org/software/systemd/man/255/systemd.journal-fields.html)
(trusted boot/unit/invocation fields; boot is 128-bit hex), and
[systemd D-Bus properties](https://www.freedesktop.org/software/systemd/man/255/org.freedesktop.systemd1.html)
(`ExecMain*` describe current or last main process as known). These are documented
semantics, not a native scheduling, journal-retention or readiness test.

Required offline command, in its own interpreter (CI refuses zero discovery):

```bash
python3 -B -m unittest discover -s build/provision -p test_vlab_trial.py -v
```

Fixtures patch every package/systemd/hhfab/network/privileged process path and
mutate only public owned temporary files. Persisted-checkpoint fault cases cover
each auxiliary phase, parser/prerequisites, strict inspect/SSH/API, nonce
create/verify/remove and resume start through terminal and guardian publication
and the host byte validator. Startup no-writer, wrong-cgroup, contradictory
child evidence and last-valid-then-corrupt status cases preserve fail-closed
ownership and provenance. They establish no live guest/session,
package solvability, peak fit, firmware completeness or functional/course proof.
Primary text read2026-10-31: [Docker group and fresh credentials](https://docs.docker.com/engine/install/linux-postinstall/),
[v0.43.1 image preparation](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/hhfab/vlabrunner.go),
[v0.43.1 public CLI](https://github.com/githedgehog/fabricator/blob/v0.43.1/cmd/hhfab/main.go),
[selected Fabric0.96.2 attachment schema](https://github.com/githedgehog/fabric/blob/v0.96.2/api/vpc/v1beta1/vpcattachment_types.go),
and [kubectl1.35 raw DeleteOptions path](https://github.com/kubernetes/kubectl/blob/v0.35.0/pkg/cmd/delete/delete.go).
