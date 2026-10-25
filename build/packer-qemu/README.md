# Stock Packer/QEMU portability experiment (`build/packer-qemu/`)

The **VM experiment remains disabled and unproven**. Fixed non-VM Docker `probe`
and `hcl-check` tasks are available under separately scoped lead execution. The
experiment tests stock Packer core with the stock QEMU plugin,
`communicator = "none"`, a NoCloud guest that runs the
unchanged `build/provision/` modules, and a private host-side observer. Plain
QEMU carries the same receipt, shutdown, watchdog and cleanup obligations; compare
the glue honestly and stop on a structural mismatch rather than fork the builder
or grow a framework. Status, plans and actual results live in GitHub
(#252, #253, #255, #264, #145). This is not a selected build system or image
pipeline. Offline tests use fake channels and disposable inputs; they establish
no Packer, QEMU, cloud-init
or hardware compatibility. Runtime evidence and remaining gates belong in the PR.

## Files

| File | Role |
|---|---|
| `labapp.pkr.hcl` | One `qemu` source (`communicator = "none"`) and one `shell-local` provisioner that only runs the verifier |
| `supervise.py` | Offline input staging and read-only hardware diagnostics; every execution request is rejected |
| `host_verify.py` | Sole client of the private QMP and serial sockets; bounded parser; writes the result marker |
| `guest/user-data`, `guest/guest-build.sh` | NoCloud seed; nonblocking enqueue; build service body (plan, seal, receipt, poweroff) |
| `container_runner.py`, `stage_tools.py` | Fixed Docker `probe` and `hcl-check` tasks; pinned bounded staging (see "Bounded container probe"); `sentinel` mode is gated off until a runtime identity is accepted |
| `runtime/Dockerfile`, `guest/assert-sentinel.sh` | Unbuilt sentinel runtime recipe; guest assertions run by the sentinel plan |
| `test_*.py` | Offline tests: `python3 -m unittest discover -s build/packer-qemu -p 'test_*.py' -v` |

## Pins, verification, licensing

`stage_tools.PINS` contains the full archive/base SHA256 values, sizes and selected
archive-member metadata. Authenticated provenance is recorded in the
[#261 signed-metadata receipt](https://github.com/afewell-hh/labapp/issues/261#issuecomment-6402828950),
[#262 archive receipt](https://github.com/afewell-hh/labapp/issues/262#issuecomment-6403952254)
and [#263 image receipt](https://github.com/afewell-hh/labapp/issues/263#issuecomment-6404038389).
Staging checks caller-supplied bytes against these pins; acquisition receipts do
not establish executable or VM compatibility.

| Input | Pin | Verification contract |
|---|---|---|
| Packer core | `1.16.2` (HCL `required_version = "= 1.16.2"`); uses SDK 0.6.13 | Signed checksum provenance in #261; pinned archive and selected member checked during staging. License text at the tag is BSL 1.1 |
| QEMU plugin | `github.com/hashicorp/qemu` `= 1.1.7`; built on SDK 0.6.11 | Signed checksum provenance in #261; bounded extraction and computed binary sidecar under `PACKER_PLUGIN_PATH`. No `packer init` or install command. Source headers are MPL-2.0 |
| Base image | Ubuntu 24.04 Noble 20261017 amd64 cloud image; exact size/SHA256 in `stage_tools.PINS` | Canonical signed checksum provenance in #261/#263; staging copies and hashes an owned read-only snapshot. No download path |
| Modules | `build/provision/*` bytes, unchanged | Their SHA256 are in `MANIFEST`; the receipt binds `sha256(MANIFEST)` |

The core/plugin SDK split (0.6.13 vs 0.6.11) is an integration risk to test, not
evidence of incompatibility.

## Private completion observer (source-traced, v1.1.7)

* `qmp_enable = true` makes the builder add `-qmp unix:PATH,server,nowait` and
  open a go-qemu `SocketMonitor` in `stepConfigureQMP`. It is stored as
  `qmp_monitor`, never given an `Events()` consumer in that file, and go-qemu
  discards events when nobody called `Events()`. A QEMU `server` chardev serves one
  client at a time, so a second observer cannot share it. `vnc_use_password` also
  forces `qmp_enable`.
* Therefore the builder's QMP stays **disabled** and `qemuargs` adds two sockets
  that only `host_verify.py` opens: `-qmp unix:DIR/events.sock,server=on,wait=off`
  and `-serial unix:DIR/serial.sock,server=on,wait=off`. Neither flag is a builder
  default when `qmp_enable = false`. No `-device`/`-drive` override is used (the
  docs warn that one drops Packer's defaults). `-cpu host`, `-vnc none`, `-monitor
  none` and `-S` are also set; their interaction with generated defaults requires
  VM runtime validation.
* Builder channels are explicitly off: `disable_vnc = true` (without it the pinned
  `stepTypeBootCommand` still connects to VNC and fails before `shell-local`),
  `boot_command = []` (no typing), `qmp_enable = false` (no native QMP),
  `vnc_use_password = false`, no `net_bridge`, and `vnc_bind_address = "127.0.0.1"`
  for any transient reservation. Attribute names and effects come from the pinned
  docs/source; actual HCL-check results belong in #264, separately from VM proof.
* Startup order: `-S` launches QEMU paused. The sole observer (1) attaches the
  serial receipt reader, (2) reads and validates the QMP greeting and version
  (QEMU >= 4), (3) sends `qmp_capabilities`, `query-status` (must be `prelaunch`,
  `running=false`), `query-kvm` (`present` and `enabled` both true), each with a
  fixed command id and a strict response schema, one in flight, and only then (4)
  sends `cont`. Events interleaved with responses are tolerated; a `SHUTDOWN`
  before `cont` is fully sent fails. A normal shutdown between the fully sent
  `cont` and its matching successful acknowledgment is buffered; success still
  requires that acknowledgment. Responses to queued or partially written commands
  are rejected. Writes are nonblocking and resumed after partial writes. The
  ordering relies on the guest not running before `cont`; VM proof must establish
  the builder's boot-wait and provisioner behavior with `-S`.
* Strict parsing: UTF-8 only; duplicate keys (at any depth), `NaN`/`Infinity`,
  overflowing numbers, non-object messages, a response carrying both `return` and
  `error` (or missing/unknown/duplicate/wrong `id`), a `null`/malformed greeting
  and malformed event envelopes all fail with fixed reason codes.
* A future approved runner must create `DIR` as a fresh private directory
  (0700, safe characters only) and retain ownership until cleanup is verified.
  The disabled supervisor does not create it. The verifier refuses an endpoint
  that is not a socket owned by the same user.
* Socket startup: after `stepRun`, endpoints may not exist or listen yet; the
  verifier retries (50 ms) until its deadline and then fails. The `-S` prelaunch
  protocol above attaches both channels before resuming the guest; elapsed guest
  startup time is not a protection against missed events or serial bytes.
* Success needs both: a serial line `LABAPP-RECEIPT v1 nonce=<64hex> inputs=<64hex>
  status=ok` equal to this run's values, and QMP `SHUTDOWN` with
  `data.guest == true` and `reason == "guest-shutdown"` (exactly those two keys; a
  second `SHUTDOWN` fails). Observation continues after the receipt: it alone never
  succeeds, a normal guest shutdown is still required. `status=fail`, a
  malformed, stale, wrong or duplicate receipt, a host/non-guest shutdown,
  `RESET`, `GUEST_PANICKED`/`GUEST_CRASHLOADED`, EOF before shutdown or the
  successful `cont` acknowledgment, or shutdown without a drained receipt
  (5 s) fail. QEMU exit, EOF or a vanished socket never succeed on their own.
* Bounds: QMP lines 64 KiB / 1 MiB total (violations fail); serial lines 4 KiB
  (longer lines are discarded) / 4 MiB total; one monotonic deadline. Peer bytes
  are never echoed. Deadline expiry wins over observed success and is rechecked
  before publishing the result marker. `reason` in `SHUTDOWN` needs QEMU 4.0+
  (Ubuntu 24.04 ships 8.2). Terminal event definitions follow the
  [QMP reference](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html)
  (accessed 2026-10-25); actual runtime evidence belongs in GitHub.
* Trust: neither channel authenticates the guest. The private 0700 directory and
  the owned QEMU instance define the boundary; the nonce rejects stale receipts,
  not a malicious guest. Native SSH is **not** used and its identity gap is not
  waived (SDK 0.6.11 `InsecureIgnoreHostKey`).
* `WaitForShutdown` in the plugin treats any QEMU exit as shutdown, so Packer
  success alone proves nothing. The observer writes `verified.json` only after
  both pieces of evidence (`O_EXCL`), bound to the nonce and digest. VM execution
  is disabled; no runner accepts that marker or any VM build artifact.

## Guest sequence (requires VM validation)

NoCloud (`cidata` CD from `cd_files`) stages bytes. Final-stage `runcmd` only
copies them to `/var/lib/labapp-build/in` and runs
`systemctl start --no-block labapp-build.service`. The unit is
`After=cloud-final.service` and `guest-build.sh` first requires
`cloud-init status --format json` to exit zero and say `done`, with no non-empty
`errors`/`recoverable_errors` and no nonzero exit/return code at any nesting level
(`status: done` alone is insufficient, and `After=` alone is satisfied by a failed
unit; the selected disk's JSON shape needs runtime validation). Then it checks
the staged directory with a bounded `find -print0` enumeration (no `ls | grep`; ShellCheck
SC2010 is fixed, not suppressed), then checks the staged bytes against `MANIFEST`,
runs `plan.txt` lines, seals, `sync`s, writes the receipt and calls poweroff, all
outside `cloud-final`; cloud-init is never cleaned from its own active script.
`runcmd` reaches `scripts_user` in the final stage (cloud-init 24.1.3 source);
Noble's actual version/config is a gate.

Module contract preserved: `plan.txt` lines are `<root|ubuntu> <argv...>`, e.g.
`root bash @IN@/install-k3d.sh`, run under `env -i` with fixed `PATH`, `HOME`,
`LC_ALL`, `DEBIAN_FRONTEND`, cwd `/`, stdin `/dev/null`, `ubuntu` through
`runuser`. Input hash contract: `MANIFEST` lists `sha256  name` for every staged
file except `nonce` and itself; the receipt carries `sha256(MANIFEST)`. The seal
(`cloud-init clean --logs`, empty `/etc/machine-id`, staging removal) is a
placeholder minimum; identity regeneration, sealing order and reboot behavior need
boot/reboot evidence.

## Watchdog and cleanup (`supervise.py`)

**Build execution is disabled.** `run()` always returns `("disabled", None)`;
CLI build requests return exit code 6 before input reads, staging, preflight or
process creation. There is no session-based fallback, process signaling or
artifact acceptance path. The retained `stage_inputs()` helper serves disposable
offline preparation tests only; it has no build-time deadline guarantee. It
reserves generated and builtin filenames before copying caller inputs, but is
not a secure stager: lstat/copy can race, parent directories or the plan can be
symlinks, and whole-file reads have no size bounds. Use only trusted inputs in a
disposable offline directory. `stage_tools.py` supplies bounded staging for the
fixed non-VM HCL check; this helper does not enable VM execution. The HCL and guest
files are experimental inputs, not an approved launch command.

A process session cannot contain a descendant that changes sessions, and a
PID/session scan followed by signaling has reuse races. Cleanup must not erase
ownership or remove a workspace while an owned child might remain. An exit code
or receipt cannot override cancellation, expired budgets or unverified cleanup.

Before enabling VM execution, implement and independently validate a supported
Linux containment boundary that includes preparation and all descendants before
execution begins. Use one absolute admission deadline, covering preparation,
work and cleanup with no renewal, and reject insufficient remaining work budget
before starting a builder. Preserve exact ownership on exceptions or incomplete
cleanup. Proposed experiment allocations remain `sentinel` 15 min work + 5 min
cleanup and `fixture` 30 + 15; these are not measured performance or implemented
runtime guarantees.

Primary sources read 2026-10-25 (current upstream manuals; actual runner versions
remain unverified): [systemd-run](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html)
documents transient services managed by systemd; [KillMode](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html)
with `control-group` stops unit descendants; [service timeouts](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
distinguish startup, active runtime and stop deadlines. `RuntimeMaxSec` alone
starts too late to bound admission/preparation and does not bound oneshot units.
A user transient service is a candidate, not implemented here: manager access,
unit identity, cancellation, all budget phases and verified empty cleanup still
need proof. Direct delegated [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
would require correct attach-before-exec, permissions and ownership handling;
a hand-written process supervisor is not a substitute for those guarantees.

## Bounded container probe (`container_runner.py`)

The fixed non-VM `probe` mode exercises containment; `hcl-check` runs only the
three Packer commands described below. Neither mode launches QEMU or a VM, and
neither accepts arbitrary commands. Execution requires separate lead scope.
Docker is reached only through a `Backend`: fixed `/usr/bin/docker`,
explicit `--host unix://…` and an empty `--config` dir (no caller context or
credential helpers), minimal environment, and a bounded byte collector (64 KiB
cap, deadline, process-group kill; overflow or invalid UTF-8 is an error, never
truncated). The CLI prints its plan unless `--execute` is given. Runtime evidence, tested
Docker versions and remaining acceptance gates are recorded in #255; offline
fake-process tests alone cannot establish containment.

* Inputs: only the Ubuntu digest already pinned in `build/provision`
  (`PINNED_IMAGE`; there is no image option), never pulled and never deleted
  (`--pull=never`; only the probe container is removed). `image inspect` must
  show that digest in `RepoDigests` and no `Config.Volumes` or `ONBUILD`; the
  image ID is what gets created, with `--no-healthcheck`. Workspace root and a
  separate host-only ledger dir must be owned, symlink-free and not
  group/other-writable; root callers are refused.
* Create argv (fixed): `/bin/bash` entrypoint running the entry script, then
  `exec timeout` (same PID 1, no `--init`), `--restart=no`, `--network=none`,
  `--cap-drop=ALL`, `no-new-privileges`, `--read-only`, caller UID:GID,
  256m/1 CPU/64 PIDs, `--log-driver=none`, one bind of the fresh output workspace.
  No device, socket, home, credentials, privileged or host namespaces.
* Clock and deadline: Linux `CLOCK_BOOTTIME` on the host and builtin Bash
  `read` of `/proc/uptime` at ACTUAL container start, both including suspend.
  The host rejects nonzero time-namespace offsets; the startup wrapper requires
  the same kernel boot ID and zero monotonic/boottime namespace offsets before
  running work. Only an explicit local Unix Docker endpoint is supported; remote
  contexts and forwarded endpoints are unsupported. The host passes the admission
  work deadline floored to whole seconds. The wrapper floors uptime and computes
  `timer = deadline - now - 1 (rounding) - 5 (kill-after)`; under 5 s it exits
  125. It then execs GNU timeout as the same PID 1. Budget: `probe` is 30 s work
  + 20 s cleanup; each Docker call is capped by remaining budget. Cancellation
  and deadline are checked through final publication. Host expiry is failure.
  This probe targets an awake local Linux host. GNU timeout's running timer
  behavior across host suspend/failure is unproven here; this is not a universal
  absolute watchdog or a VM runtime guarantee. No sleep controls are installed.
* Ledger (host-only, outside the container-writable workspace): use one shared
  ledger directory as the admission authority for the local endpoint. A
  nonblocking `flock` covers scan, reservation, run, cleanup and publication;
  a competing invocation returns HOLD without contacting Docker. Directory
  scans accept at most 128 entries, each record at most 4 KiB; symlinks, corrupt
  or incomplete records and unexpected entries fail closed. One fsynced,
  atomically renamed JSON record per request (name, label, image, full ID,
  workspace, deadlines, state) written BEFORE each mutation (`reserved`,
  `create_intent`, `start_intent`, `stop_rm_intent`). Any record not `released`
  (including corrupt ones) blocks a new request with `hold`/exit 7 and no Docker
  call: unresolved requests are never retried as fresh work. A ledger write
  failure before create prevents the mutation; after it, the result is `hold`.
  Host death leaves the record plus the container's own timer.
* Cleanup: queries exact name+label (rejects any extra ID or an unexplained
  vanished container), inspects the full ID and requires the exact name and
  label before `stop`/`rm`, then requires successful empty name+label and
  full-ID queries. A lost/failed stop or rm response is uncertain and stays
  `hold` even if later queries find nothing; a failed query is not absence.
  Lost create/start responses also stay `hold`. `released` is written only for
  verified container removal AND owned workspace removal with confirmed absence.
  A workspace removal failure is HOLD and blocks reuse. `hold` retains the
  host ledger; workspace retention is best effort if removal already occurred.
* Signals: SIGTERM/SIGINT mark cancellation and unwind to cleanup (a signal
  during cleanup only sets the flag); a cancelled run is never accepted.
  Finalization exceptions become `hold`, never a crash or acceptance.
* Acceptance (probe only): exit 124/137, not OOM-killed, cleanup verified, and
  startup evidence: `/out/witness` is exactly one small regular file written by the
  fixed probe (`start <boot seconds> <timer>`, `probe <setsid child pid>`,
  `term_ignored`). The detached child installs its own TERM-ignore handler and
  writes its own PID after `setsid`; the parent waits for that line. The timer
  must be consistent with the deadline, and the container
  ran about as long as that timer (an immediate 137 is rejected). Anything else
  in the workspace is untrusted and rejects. Exit codes: accepted 0, failed 1,
  usage 2, hold 7.

Pinned-source basis (read 2026-10-25): coreutils
[`timeout.c` v9.4](https://raw.githubusercontent.com/coreutils/coreutils/v9.4/src/timeout.c)
(Ubuntu 24.04's series) installs handlers for TERM/INT/QUIT/HUP/ALRM, so PID 1
can receive them; on the first signal it sends to the child then, unless
`--foreground`, to its own group (ignoring that signal itself first), and arms
`--kill-after` only then. `setpgid(0,0)` is unchecked, so failing as a session
leader is harmless. It exits 124 on timeout, or 137 if the child was KILLed.
[pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
(man-pages 6.19): PID 1 exit SIGKILLs the namespace; PID 1 only receives
signals it has handlers for, except SIGKILL/SIGSTOP from an ancestor.
[`docker stop`](https://docs.docker.com/reference/cli/docker/container/stop/):
TERM, then KILL after the grace period. [Live restore](https://docs.docker.com/engine/daemon/live-restore/):
containers keep running without the daemon, so the internal timer must stand alone.

Before extending to any VM mode, require real-Docker proof that descendants (including the
`setsid` child) die with PID 1 and that the exit codes above hold, observing
child existence and namespace cleanup directly (the witness records a pid; it
does not prove cleanup); `bash`/`timeout`/`setsid` presence in the pinned image;
exact 124-vs-137 behavior with a TERM-ignoring probe; UID mapping of the bind (rootless/userns);
`/dev/kvm` passthrough; input verification and evidence binding (core/plugin/
base/module hashes, nonce, acceleration, normal shutdown); input mounts.
Assess those gates against the current issue evidence; the fixed non-VM probe
does not enable VM execution or establish another host configuration's support.

### Fixed `hcl-check` task (pre-VM tool/HCL check)

`--mode hcl-check --core-file … --plugin-file … --base-file …` reuses the probe's
admission, ledger, deadline, cleanup and HOLD logic with different fixed data. It
is not an arbitrary-command option and starts no VM. Selected in #264 (reviews
6404228868/6404240697 control). **Live execution needs separate lead scope**; the
default prints the plan only.

* Budget: 120 s work **including all staging from admission** + 30 s cleanup,
  immutable. 1 CPU / 1 GiB / 128 PIDs (explicit bounds, not measured needs).
* Pins (`stage_tools.PINS`, from #262/#263): Packer 1.16.2 archive
  `abbfe0cf…2414` (34,038,571 B), qemu plugin 1.1.7 archive `2da85692…94f2`
  (15,249,228 B) and the Noble 20261017 disk `04e8f246…6c94` (621,284,352 B); full
  values are in code. Member name/mode/size/CRC come from the #262 listing. **Member
  SHA256 values are not archive-listing pins**: they are computed from the
  size-bounded, CRC-checked extraction and recorded.
* Staging (host stdlib, no fetched code runs): whole-archive size and SHA256, exact
  member set, then only `packer` and the plugin are streamed by actual bytes, with
  CRC, to fresh 0700 paths (`O_EXCL|O_NOFOLLOW`); `LICENSE.txt` is validated but not
  extracted. The plugin gets a `_SHA256SUM` sidecar of exactly 64 hex bytes; there is
  no `packer init`/install. The base image is copied and hashed through one stable
  descriptor into owned `in/base.img` (0400), then rehashed after the run; no external
  source pathname is bound. Every source parent is opened without following symlinks,
  and sources inside the workspace (including aliases) are refused. The repo's
  `labapp.pkr.hcl`, `host_verify.py` and guest files are copied (never mounted from
  the tree).
* Mounts: `/in` (tools, plugins, HCL, verifier, base snapshot and generated
  `validate.pkrvars.hcl`) and `/out/work/cd` read-only; only fresh `/out` is writable. No
  network, capabilities, devices, host home, socket or credentials. `inputs` hashes a
  canonical manifest of staged bytes excluding the var-file; the var-file hash is
  recorded separately.
* Steps (fixed script, empty `env -i`, `HOME=/out/home`, `TMPDIR=/out/tmp`,
  `PACKER_PLUGIN_PATH=/in/plugins`, `ulimit -f` caps each output): `packer version`,
  `validate -syntax-only`, full `validate -var-file=…`. Full validation executes the
  plugin's `describe`. Syntax-only does not load plugins; neither proves boot, KVM,
  QEMU/xorriso presence (checked only at build time) or VLAB.
* Success needs container exit 0, all three steps 0, `Packer v1.16.2`, all seven
  status/stdout/stderr files present as bounded regular files (no symlinks; empty
  stdout/stderr is valid), staged bytes unchanged after the run, no cancellation/expiry
  and verified cleanup. Any nonzero step is FAILED; an expected negative test is test evidence, never tool success.
  The probe's 124/137 rule is not reused.
* Limits: malicious same-user concurrent writers are out of scope (source descriptor
  identity and copied bytes are checked, not locked); `ulimit -f` bounds file size,
  not total `/out` bytes. Actual version-output, sidecar and HCL-check results
  belong in #264; they cannot establish VM readiness.

### Fixed `sentinel` task (offline contracts only; UNRUN, execution refused)

`--mode sentinel` reuses the same admission, single ledger, actual-start timer, bounded
backend, exact name+label+ID cleanup and HOLD semantics. There is no image, command or
runtime option. **It refuses before the lock, ledger, workspace, staging or any Docker
call unless `container_runner.SENTINEL_RUNTIME` holds an accepted `image_id` and
RootFS `diffids`; the shipped value is `None`** (no digest is invented). `supervise.py`
stays execution-disabled.

* Runtime: `runtime/Dockerfile` (that directory is the whole build context) derives from
  the full accepted Ubuntu digest, deletes ambient APT sources, writes one Deb822 source
  pair for snapshot `20261024T000000Z` (Canonical's documented Noble form; the keyring
  is the base image's own, no key download or authentication/`Valid-Until` bypass) and
  installs explicit candidate roots `qemu-system-x86`, `qemu-utils`, `seabios`
  (equal to `build/provision/install-qemu.py` PINS, which are untouched), `python3`,
  `python3.12` and `xorriso` with `--no-install-recommends`; the resolved package list
  and `InRelease` hashes are recorded inside the image. The ISO tool is one the pinned
  SDK actually searches (`xorriso`, `mkisofs`, `hdiutil`, `oscdimg`); the
  `supervise.py` diagnostic no longer accepts `genisoimage`. Versions are candidates:
  snapshot availability, closure (for example `ipxe-qemu` option ROMs), HTTP vs CA needs
  and `Valid-Until` behavior are **unverified** until the preparation job runs.
  A build-client or job timeout does not prove daemon-side work stopped.
* Argv: hcl-check's boundary plus `--device=/dev/kvm` and numeric `--group-add` of its
  GID (metadata-only `lstat` preflight: character device, nonzero group, group rw; no
  open/ioctl; missing KVM is `kvm_unavailable`, never TCG). Proposed, unmeasured caps:
  `--cpus=5`, `--memory=10g`, `--memory-swap=10g`, `--pids-limit=512` around the
  4 vCPU / 8 GiB guest. Sockets stay at the short owned `/out/work/{events,serial}.sock`.
* Budget: 900 s work including staging from admission, 300 s cleanup, no renewal.
  `verify_seconds` = work left when the var-file is written minus `SENTINEL_RESERVE`
  (120 s, unmeasured: Docker calls, Packer start, ISO, convert, rehash, reads). The
  plugin's 5 min `shutdown_timeout` is not subtracted: the observer returns only after
  guest shutdown and a later wait returns at once; it stays a secondary cap.
* Identities: the overall canonical `in/`+`cd/` digest stays runner evidence
  (`inputs`) and is rechecked after the run; the observer's `--inputs`/receipt value is
  `SHA256(cd/MANIFEST)` (`guest_receipt`), via the sentinel-specific
  `sentinel.pkrvars.hcl`. `hcl-check` staging is unchanged.
* Guest: plan runs `guest/assert-sentinel.sh` as `root` then `ubuntu` (uid, cwd `/`,
  sanitized environment); it is staged 0444 before the MANIFEST so both users can read
  the copy. No downloads or VLAB. The root run also prints the bounded
  `cloud-init status` JSON on the serial port before the seal cleans it;
  **`host_verify.py` currently ignores non-receipt lines, so capturing that evidence is
  an unmet gate.**
* Success needs container exit 0, `build 0`, a `verified.json` with exactly the observer's
  four keys matching this run's nonce, `guest_receipt` and `guest-shutdown`, a bounded
  regular artifact (hashed, then deleted), unchanged staged bytes and verified cleanup.
  Packer exit 0 or `verified.json` alone is not enough.
* Unmet before any VM (HOLD): accepted runtime identity from a reviewed preparation
  workflow with owned builder cleanup; named KVM runner and UID/GID mapping; ISO
  Rock Ridge mode check; the unrun HCL attributes above; capture of the evidence line;
  measured resource caps and reserve; failure/hang trial, then one success.

```bash
# Read-only hardware diagnostics; successful exit does not enable execution.
python3 -I /abs/build/packer-qemu/supervise.py --preflight-only
```

The required offline suites run in the `portable-builder-offline` CI job; they
exercise preparation, observer parsing and rejection of execution without
launching Packer, QEMU, systemd units or other build processes.

## Runner preflight

Hardware diagnostics read Linux x86_64, `/dev/kvm` user access, required tools,
CPU `vmx`/`svm` and the `kvm_intel`/`kvm_amd` nested parameter. They do not open
KVM or establish that acceleration works. Builder boot requires usable KVM;
the later nested VLAB proof also requires nested CPU exposure. TCG is never a
substitute. A named runner and a supported containment/manager preflight are
still required before any later execution approval. A passing diagnostic is
neither build admission nor accelerated nested-VLAB proof.

## VM and platform acceptance gates

Assess current HCL-check results in #264 separately from these VM gates: a named
KVM runner; verified runtime tools and applicable licenses; that
`cd_files` globs, `-cpu host`/`-vnc none` overrides and the shell-local/`none` path
work on the pinned pair; observer and watchdog against a real forced failure
(crash, hang, bad receipt) leaving no processes or files; unchanged modules twice;
sealed boot/reboot identity, devices, network; accelerated nested execution; full
pinned VLAB and course exercises; GCP import route and its resources/IAM (no import
adapter exists; capture uses `sourceDisk`). Required offline suites are wired into
CI; shell checks cover `guest/guest-build.sh` only statically. VM execution requires
its own supported containment and absolute admission-through-cleanup deadline
proof; fixed non-VM tasks and passing offline tests cannot authorize a build.
