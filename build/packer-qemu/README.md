# Stock Packer/QEMU portability experiment (`build/packer-qemu/`)

The **VM experiment requires separately scoped lead execution**; successful guest
compatibility remains a live acceptance gate. Fixed non-VM Docker `probe`,
`hcl-check` and `runtime-check` tasks are available under separately scoped lead execution. The
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
| `container_runner.py`, `stage_tools.py` | Fixed Docker `probe`, `hcl-check` and `runtime-check` tasks; pinned bounded staging (see "Bounded container probe"); `sentinel` mode pins its runtime identity and requires separate lead scope |
| `runtime/Dockerfile`, `guest/assert-sentinel.sh` | Separately gated runtime preparation recipe; guest assertions run by the sentinel plan |
| `guest/assert-fixture.py` | Fixed hhfab `fixture` assertions between two runs of the unchanged installer (see "Fixed `fixture` task") |
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
  both pieces of evidence (`O_EXCL`), bound to the nonce and digest. The fixed `sentinel` runner additionally validates the marker, staged inputs and
  disposable artifact before accepting a trial; separate lead scope is required.

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

### Fixed `sentinel` task (VM execution gate)

`--mode sentinel` reuses the same admission, single ledger, actual-start timer, bounded
backend, exact name+label+ID cleanup and HOLD semantics. There is no image, command or
runtime option. **It refuses before the lock, ledger, workspace, staging or any Docker
call unless `container_runner.SENTINEL_RUNTIME` holds an accepted `image_id` and
RootFS `diffids`; the fixed identity is `PREPARED_RUNTIME`**. This source gate is
not execution authorization: each actual trial needs separate lead scope and
reconciled shared-ledger admission. `supervise.py` stays execution-disabled.

* Runtime: `runtime/Dockerfile` (that directory is the whole build context) derives from
  the full accepted Ubuntu digest, deletes ambient APT sources, writes one Deb822 source
  pair for snapshot `20261024T000000Z` (Canonical's documented Noble form; the keyring
  is the base image's own, no key download or authentication/`Valid-Until` bypass) and
  installs explicit pinned roots `qemu-system-x86`, `qemu-utils`, `seabios`
  (equal to `build/provision/install-qemu.py` PINS, which are untouched), `python3`,
  `python3.12`, `xorriso` and `ca-certificates` with `--no-install-recommends`; the resolved package list
  and `InRelease` hashes are recorded inside the image. The ISO tool is one the pinned
  SDK actually searches (`xorriso`, `mkisofs`, `hdiutil`, `oscdimg`); the
  `supervise.py` diagnostic no longer accepts `genisoimage`. Snapshot availability, dependency closure (including option ROMs), transport/CA
  requirements and `Valid-Until` behavior require reviewed preparation evidence;
  firmware loading and ISO operation require separate execution evidence.
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
  the copy. No downloads or VLAB. Only root pipes `cloud-init status --format json`
  to staged `guest/sentinel-evidence.py` before the seal cleans it. The helper rejects
  output over 64 KiB (never accepts truncation), malformed/duplicate JSON, non-done
  status, nested errors/recoverable errors and nonzero status codes. It emits only
  `LABAPP-EVIDENCE v1 nonce=HEX64 inputs=HEX64 cloud-init=done errors=0 recoverable=0`;
  arbitrary status fields and error text are never retained or echoed. The identities
  are the checked staged nonce and CD MANIFEST digest.
  The record is written with a direct `os.write` loop (partial writes, EINTR; no buffered
  stdout to flush again at interpreter exit). The helper's exit status is a fixed
  classification: 0 accepted, 1 input rejected, 3 EPIPE, 4 ENOSPC, 5 EIO, 6 other errno,
  7 no write progress. `assert-sentinel.sh` captures both `PIPESTATUS` values at once,
  still fails on any nonzero one, and leaves only the fixed reason token
  `pipe-p<producer>-r<renderer>` (first reason wins) for the existing `LABAPP-DIAG` line.
  This was added after the first fixture guest failed at root step 1 with exit 120
  (interpreter cleanup error) before hhfab ran; the errno and which side failed there
  remain unobserved, so the cause is inferred, not established. The next attempt's
  `reason=` token will separate them. Offline tests: `test_sentinel_evidence.py`.
* Observer: sentinel vars set `require_sentinel_evidence = true` (HCL default false),
  adding `--require-sentinel-evidence`. The observer requires exactly one matching
  record alongside the existing receipt, prelaunch/KVM/cont and normal-shutdown gates.
  Missing, malformed, duplicate, stale, non-done or oversized evidence fails within
  the original serial byte/line/deadline bounds; ordinary overlong boot noise is still
  discarded. Successful evidence becomes the closed `cloud_init` object
  `{"status":"done","errors":0,"recoverable_errors":0}` in `verified.json`.
  Ordinary observer runs ignore evidence lines and retain their original four-key result.
* Success needs container exit 0, `build 0`, a `verified.json` with exactly the observer's
  five keys matching this run's nonce, `guest_receipt`, `guest-shutdown` and the
  exact normalized `cloud_init` summary (integer zero counts), a bounded regular
  artifact (hashed, then deleted), unchanged staged bytes and verified cleanup.
  All result-file parents and leaves are opened through anchored directory descriptors
  with no symlink following; empty output files remain valid and reads reject size or
  identity changes. External bytes cannot enter evidence through an aliased parent.
  Runner evidence retains the validated summary and the result-file size/hash, with no
  raw result-file excerpt.
  Packer exit 0 or `verified.json` alone is not enough.
* Before each VM (HOLD if unmet): verify the accepted runtime identity and
  preparation provenance, named KVM runner and UID/GID mapping, required tool/ISO
  checks, reviewed HCL, original resource/time bounds and shared-ledger admission.
  Independently accepted failure/hang cleanup and reconciliation must precede the
  separately scoped success trial. Actual guest evidence, resource/reserve fit and
  remaining compatibility gates are recorded in GitHub, never inferred from source activation.

### Fixed `sentinel-expiry` task (failure-only VM proof)

`--mode sentinel-expiry` is the deterministic failure/expiry proof that precedes any
success trial. Same admission, single ledger, restricted container, exact `/dev/kvm` plus
numeric group, exact cleanup and HOLD rules as `sentinel`; no image, command, QMP
sequence or duration option. It refuses before the lock, ledger, workspace, staging or
Docker unless `container_runner.EXPIRY_RUNTIME` holds an accepted identity (the fixed `PREPARED_RUNTIME`,
separately gated from `SENTINEL_RUNTIME`). This identity does not authorize
execution: each actual trial requires separately scoped lead authorization.

* Budget: 300 s work INCLUDING staging from admission + 120 s cleanup, no renewal;
  staging is rejected if under 150 s of work remain. After expiry, immutable input
  revalidation may consume the original cleanup allocation, retaining 60 s for exact
  cleanup; every operation remains bounded by the original 420 s total deadline. The observer and shell-local timeouts
  are fixed 300 s from their later start so the original container PID 1 deadline wins.
* Observer (`--expiry-witness FILE`, selected by `expiry_proof = true`; excludes
  success mode): after the usual serial attach, greeting, prelaunch, KVM and `cont`
  acknowledgement it requires `query-status` running, `stop`, then `query-status` paused
  (QEMU 8.2 `RunState` `paused`: "guest has been paused via the 'stop' command"). Only
  then it writes one strict `armed.json` (kind, `paused`, CLOCK_BOOTTIME `armed_at` rounded upward, boot ID,
  nonce, `guest_receipt`) only when at least 60 s of the PID1 timer remain, and stays alive. Any observer return
  revokes arming and writes a bounded failure marker before Packer cleanup. Any later receipt line, SHUTDOWN event, wrong
  response or socket EOF fails; it never writes `verified.json`.
* Accepted only if: container exit 124/137 (not OOM), no `steps` file and no
  `verified.json`, valid timer witness, exit not before the timer, and an `armed.json`
  matching this run's nonce and `guest_receipt` that leaves at least 60 s before the
  timer; staged bytes unchanged and cleanup verified. A bounded regular partial artifact is size-recorded without following aliases;
  disposal uses the existing exact owned-workspace cleanup, never individual path deletion. The result carries `proof: expected_expiry` and `build_success: false`; it
  is never a successful guest or build.
* Unproven here: that a paused guest survives to the timer under the real plugin, that
  Packer/QEMU descendants vanish with the container (an independent client-loss probe
  is a separate lead step), and every UNRUN HCL attribute above.

### Fixed `fixture` task (unchanged hhfab installer twice; source only)

`--mode fixture --archive-file ABS` is a fixed variant of `sentinel`, not a module runner.
It reuses the sentinel staging, run-bound receipt and pre-seal cloud-init evidence, observer
(`require_sentinel_evidence`), SENTINEL runtime identity, `/dev/kvm` access, ledger, deadline and exact
cleanup; there is no new HCL variable, command, module or path option. The caller supplies
a read-only archive that must be exactly the committed pin (59,692,810 bytes, SHA256
`a8e6d1b8d0f752d7586c29201add3ff174d330c87fa25a3bdadec43f6c1376b6`, hhfab 0.50.4, a compatibility
candidate and not an image pin); the runner copies it through the bounded `copy_hash` helper.
Nothing is acquired here and no archive cache is created or authorized; the caller-held file's
ownership, retention and disposition stay outside this repository until the lead records them.

* Staged on the CD and covered by the MANIFEST/receipt identity: byte-identical
  `build/provision/install-hhfab.py`, `hhfab_release.py` and `component_prerequisites.py`, the pinned archive, `guest/assert-fixture.py`.
* Fixed plan (steps are numbered for diagnostics): 1-2 the sentinel root/`ubuntu`/cloud-init assertions;
  3 `baseline` (real unwritable-by-others directory chain, no `hhfab`, no stage leftover; records unrelated entries);
  4 `/usr/bin/python3 -B install-hhfab.py --version 0.50.4 --archive ...` as root, cwd `/`, sanitized environment, default
  `/usr/local/bin`; 5 `snapshot` (exact member hash, regular/single-link/0755/owner, unrelated entries untouched, no
  `.hhfab-stage-*`, inode/size/mtime/ctime recorded); 6 the identical installer argv again; 7 `verify` (rerun left the same inode and times, so it
  answered `unchanged`, and nothing else changed); 8 `negatives`; 9 `smoke`; 10 the unchanged
  `build/provision/component_prerequisites.py` as root with `--owner-uid 1000 --archive ...` (last, so steps 1-9 keep their
  numbers). `baseline` also requires `ubuntu` to be uid 1000 with a nonzero primary group (token `owner-map`), so the probe never
  runs against root or an unintended user. The probe checks PID1/systemd transient-unit start/result/cleanup, a stripped-groups
  nonroot private install twice plus its CLI, then root `/dev/kvm` API 12 and VM-handle creation. It runs no L2 vCPU and proves
  neither nonroot KVM nor VLAB; `-cpu host` does not guarantee nested devices, and a missing guest `/dev/kvm` means that host cannot
  provide this validation, not that the image or GCP is invalid. A nonzero exit is preserved: no TCG, permission, module or retry repair.
* Staged modes: the installer pair and archive are `0444` (the probe's nonroot child reads and imports them; `user-data` makes
  `/var/lib/labapp-build` and `.../in` root-owned `0755`); the probe, `assert-fixture.py`, plan and MANIFEST are `0400`, and
  the nonce is `0600` after the copy. Fresh source-file modes are explicit even with umask `077`. The guest also normalizes
  the copied flat input files after MANIFEST verification and before the plan: only the two
  sentinel helpers and the fixture installer pair/archive become `0444`; other files are
  `0400`, with nonce `0600`. Optional fixture files may be absent in minimal sentinel mode.
  The copy is recursively made root-owned after `cp -a`; baseline verifies every real, trusted,
  traversable parent and each required single-link regular file and its exact mode/owner. A bounded
  sanitized `ubuntu` Python child actually reads the pair/archive, imports the exact sibling, verifies
  those files are unwritable and cannot read the nonce, without executing hhfab or installer/probe work.
  The same staging-only guard runs during root sentinel step 1 before ubuntu step 2, preserving
  plan numbering, and baseline repeats it before installation. Failure uses the existing fixed
  `staging-*` reason path. The probe is MANIFEST/receipt covered like the other files.
* CD metadata limitation (primary source read 2026-10-26): [QEMU plugin 1.1.7](https://github.com/hashicorp/packer-plugin-qemu/blob/v1.1.7/go.mod)
  pins [SDK 0.6.11 StepCreateCD](https://github.com/hashicorp/packer-plugin-sdk/blob/v0.6.11/multistep/commonsteps/step_create_cdrom.go).
  Its file-copy path uses `os.Create` and `io.Copy` without source-mode preservation; a public
  source file can become `0600` under umask `077` before ISO creation. Source hash/mode tests
  and direct xorriso checks therefore cannot establish the final guest copy's accessibility.
  Guest normalization and actual early nonroot read/import/privacy assertions cover that boundary.
* Probe diagnostics: step 10 failure reports only `step=10 exit=N reason=plan-step`. The unchanged probe's JSON reason is
  deliberately not exported and it exits 1 for installer, systemd and KVM failures alike, so a missing guest `/dev/kvm` cannot be told
  from an earlier probe failure without changing the probe or adding a wrapper step; neither is done here.
* `negatives` run the unchanged installer against ISOLATED owned directories under `/run`, never `/usr/local/bin`: a
  same-size corrupted copy of the archive against nonmatching prior bytes (never executed) and against an absent
  target must exit 1 with exactly the archive checksum/size refusal and leave those bytes, mode and times and the directory
  unchanged; `--version 9.9.9` must be the argparse exit 2 refusal. (An already matching installed binary returns
  `unchanged` before reading its archive, so it cannot test a corrupt archive; `test_install_hhfab.py` records that.)
* `smoke` runs `/usr/local/bin/hhfab --version` as `ubuntu` through `runuser`, `env -i`, cwd `/`, 20 s, 4 KiB output, and
  requires the anchored `hhfab version v?0.50.4` (optional final newline) used by `component_prerequisites.py`.
* Diagnostics: a failing plan step makes `guest-build.sh` send one `LABAPP-DIAG v1 ... step=N exit=N reason=token` line
  before the failure receipt; `token` is a fixed word from `/run/labapp-reason` written by `assert-fixture.py`
  (`owner-map`, `dir-state`, `target-present`, `stage-leftover`, `install-state`, `dir-preserved`, `rerun-state`, `archive-integrity`, `bad-version`,
  `neg-state`, `negative-timeout`, `state-missing`, `cli-run`, `cli-version`, `cli-timeout`, `output-bound`, `internal`) or `plan-step`. The observer validates it against the run's nonce and
  inputs and appends only those fields to its failure reason; the runner keeps that bounded text as
  `evidence.observer_failure` beyond the 2 KiB excerpt. No guest stdout/stderr is exported.
* Budget: 1800 s work INCLUDING staging from admission + 900 s cleanup, no renewal (proposed, unmeasured).
  The staged 60 MB CD file and the two extractions are unmeasured; large-ISO readback is a separate offline-checkable
  and live gate. Source activation here is not execution authorization: every actual trial needs separately scoped lead
  authorization and reconciled shared-ledger admission.
* Installer refusal checks and the CLI smoke reuse the unchanged sibling helper
  for a combined 4 KiB streaming output cap, fixed deadline and process-group cleanup;
  cwd is `/`, and diagnostics never export the child output.
* Proves, if run: the unchanged installer's offline `--archive` path installs and reruns as root in a fresh accelerated
  guest and the binary starts as `ubuntu`. Not proven: network download, APT/dpkg, services, reboot or seal, nested VLAB,
  other platforms, the release attestation (GitHub's immutable-release digest is not a verified publisher signature).

```bash
# Read-only hardware diagnostics; successful exit does not enable execution.
python3 -I /abs/build/packer-qemu/supervise.py --preflight-only
```

The required offline suites run in the `portable-builder-offline` CI job; they
exercise preparation, observer parsing and rejection of execution without
launching Packer, QEMU, systemd units or other build processes.

## Fixed non-VM runtime tool check

`container_runner.py --mode runtime-check` prints an offline plan by default;
`--execute` requires separate concrete lead authorization. This task accepts only
`PREPARED_RUNTIME` (the image ID and four DiffIDs from the reviewed preparation
artifact); no CLI/environment image, command or input override is accepted. Its
identity remains bound to the original source and Dockerfile hashes recorded in
GitHub even when recipe comments change. Preparation/import, actual tool results
and subsequent VM acceptance are separate gates; no tool check authorizes a VM trial.

This mode reuses the existing admission ledger, absolute budget, cancellation and
exact full-ID/name/label cleanup. It has 90 seconds work plus 30 seconds cleanup,
256 MiB memory, one CPU and 64 PIDs; nonroot, read-only root, no capabilities,
no-new-privileges, no network, no devices and only one owned writable workspace.
It stages no core, plugin, base disk or provisioner. The fixed empty-environment
command checks QEMU/qemu-img 8.2.2, Python 3.12.3, xorriso 1.5.6 and readable
nonempty SeaBIOS, standard VGA and virtio network firmware. It runs QEMU only
with `--version`; there is no boot or KVM open/ioctl.

The tiny ISO uses the pinned SDK's exact xorriso recipe: `-as genisoimage -rock
-joliet -volid cidata -output DEST SOURCE`. Fixed inert bytes have a long nested
filename; xorriso reads it back without mounting. The check requires successful
creation/extraction, exact bytes, unchanged source and the ISO9660 volume label.
Files are capped at 8 MiB, logs at 16 KiB, and a strict 4 KiB JSON report binds
versions, firmware paths and input/readback/ISO hashes. The host reader rejects
symlinked, oversized, missing, malformed or duplicate-key evidence. Before cleanup,
fixed tool logs and the runtime program stdout/stderr log retain bounded byte
counts, SHA256s and excerpts (at most 2 KiB each) in the result, including on
nonzero/OOM exits. Missing or invalid diagnostics are explicitly listed; arbitrary
paths and oversized files are never read as diagnostics. JSON serialization escapes
control bytes in public output. Failure evidence retains candidate identity, exit
code, OOM state and elapsed time; it cannot turn a failure into acceptance. Acceptance
also requires verified container and workspace removal before publication. These
checks prove neither firmware loading nor Packer/guest/hardware compatibility.
Offline fake-tool/daemon tests run in the existing required `test_container_runner.py`
CI suite; they do not execute a prepared image.

Primary sources read 2026-10-26: [QEMU plugin v1.1.7 SDK pin](https://github.com/hashicorp/packer-plugin-qemu/blob/v1.1.7/go.mod),
[its StepCreateCD use](https://github.com/hashicorp/packer-plugin-qemu/blob/v1.1.7/builder/qemu/builder.go),
[SDK v0.6.11 ISO argv](https://github.com/hashicorp/packer-plugin-sdk/blob/v0.6.11/multistep/commonsteps/step_create_cdrom.go),
[GNU xorriso extraction examples](https://www.gnu.org/software/xorriso/) (current manual; selected tool 1.5.6),
[plugin machine/device defaults](https://github.com/hashicorp/packer-plugin-qemu/blob/v1.1.7/builder/qemu/config.go)
and [QEMU command generation](https://github.com/hashicorp/packer-plugin-qemu/blob/v1.1.7/builder/qemu/step_run.go).

## Fixed hosted runtime preparation

`runtime-prepare.sh` and the fixed `runtime_prepare.py` hooks are the preparation
entrypoints. Preparation requires a separate concrete lead execution scope. The lead
must apply/review the fixed manual workflow separately and record execution scope.
The standard fresh GitHub-hosted Ubuntu 24.04 VM is the trust boundary: read-only
checkout authority, no cloud/registry-write/SSH credentials or secret forwarding,
private HOME and credential-free Docker config for every client call. Python
3.10+ stdlib is sufficient; no repository-shadowed `-m` execution is required.
Only a fresh directory containing a copied `runtime/Dockerfile` enters BuildKit;
checkout auth and `.git` never enter the context. The CLI and builder are fixed,
not caller options. Preparation does not change VM execution scope or admission.

The workflow uses Docker's maintained Buildx docker-container driver. Its
BuildKit container is **privileged by the driver**, independently of the later
nonroot/capability-dropped VM task. This is acceptable only in the separately
reviewed fresh managed-host scope. No extra manual privileged flag or rootless
assumption is added. Explicit `restart-policy=no` and `provenance-add-gha=false`
avoid automatic restart and implicit workflow-context provenance. The pinned
setup-buildx action uses `driver: docker`, `name: default`, `use: false`, fixed
`version: v0.38.1` and `cache-binary: false` solely to install the CLI; its source
skips builder creation for that driver. The actual owned builder is created only
after successful absence queries, in a private config, then bootstrapped explicitly.

The hooks resolve builder name/driver/node/endpoint, full container ID, pinned
BuildKit image and actual image ID, exact cache mount and inspected local volume
identity before removal through `buildx rm`. Successful list queries must prove
absence afterwards, including a successful empty full-container-ID query. Buildx `ls --format=json` is parsed using its pinned source
schema, including embedded builder/node errors that can accompany exit status 0;
`inspect --format` is unsupported and is not used. Failed queries/removal, identity changes, unexplained vanished
resources and partial creation leaving only an unattributable volume are HOLD;
no global prune or deletion of preexisting images is allowed. Pulled base/BuildKit
images are immutable dependency cache, retained until fresh-host disposal. Only
owned builder/container/state volume are mutable daemon assets. There is no
candidate image in the daemon: the Docker exporter writes `image.tar` directly;
no `load`, reader container or candidate-image deletion is necessary. Copied
source context, exported tar and evidence remain only for publication and fresh
host disposal; no persistent host-cleanliness claim includes these retained files.

Build execution remains in maintained workflow steps (17-minute work, 3-minute
`always()` cleanup, 2-minute sealing, 25-minute job timeout). Normal failure and
cancellation invoke the bounded cleanup step when GitHub permits it. Cancellation,
job timeout, runner loss or SIGKILL can interrupt cleanup; these are managed-host
bounds plus fresh-VM disposal, **not proof of universal daemon destruction**.
Missing cleanup or any uncertainty prevents sealing/publication and runtime
admission. Upload occurs only after work and cleanup succeed; cancellation fails
the GitHub `success()` condition. Failed uploads do not admit any runtime. This
workflow is not a durable local lease authority or a reusable self-hosted runner.

The base must contain compatible APT, HTTPS transport, archive keyring and gpgv;
the Dockerfile checks them before network work. The pinned Ubuntu base lacks a CA
bundle (observed in existing CI bootstrap package logs). Snapshot rewriting and
the dated HTTP endpoint lead to HTTPS, so HTTP archive entries do not solve that
bootstrap requirement. A fixed data-only `COPY` obtains the CA bundle from the
already digest-pinned BuildKit image into `/tmp/labapp-bootstrap-ca.pem`. The
v0.34.1 source selects Alpine 3.23; Alpine's `apk-tools` requires the CA bundle
package whose contents include `/etc/ssl/certs/ca-certificates.crt`. These are
source/package-metadata evidence for the path, not inspection of the exact donor
image's file bytes. A missing donor path or unusable trust corpus fails closed.

Both APT update and install explicitly use that dedicated corpus through
`Acquire::https::CAInfo`. TLS peer/host checks, Ubuntu archive signatures, package
hashes and Valid-Until stay enabled. Native dated-snapshot resolution includes
`ca-certificates=20240203`; no donor executable runs and no donor package is
installed. There is no ambient-latest APT bootstrap, key TOFU or authentication
bypass. The final RUN copies the bootstrap corpus into the final evidence layer
before deleting the temporary path, so the fixed last-layer reader can retain its
bounded bytes. Provenance records the exact donor digest/path and actual corpus
size/SHA256, and sealing rechecks the retained corpus. Exact donor file content,
TLS usability, candidate root availability, signed-snapshot dependency closure
and firmware completeness remain unverified until separately scoped preparation.
A refusal means HOLD; synthetic recipe/data tests establish no actual COPY/build.
The final image layer retains complete APT list files (including signed InRelease
and package indexes), their hashes, archive keyring, sources, APT configuration,
policy and the complete installed package/version/architecture set before cache
removal. This records APT's actual authenticated resolution, not an independent
reimplementation of its signature verification.

The fixed Docker export explicitly uses `compression=uncompressed` **and**
`force-compression=true`. BuildKit v0.34.1 defaults to gzip; choosing uncompressed
without force would affect only newly created layers and could leave inherited
Ubuntu layers compressed. Its Docker variant accepts the shared compression
attributes, and force applies conversion across the complete layer chain before
containerd copies the blob bytes into the archive. The reader therefore expects
uncompressed bytes for every config DiffID. Compressed or unexpected output
fails closed; it does not introduce host decompression or relax any size/hash
bound. Actual exporter execution remains unverified until separately scoped.

The data-only host reader never extracts archive paths or runs candidate code.
It bounds tar/member sizes/counts, rejects missing/duplicate/nonregular evidence,
checks every exported layer against the config DiffIDs and binds the exact config
image ID to `iid.txt` and build metadata. Source commit/Dockerfile hash, image ID,
DiffIDs, complete package/index provenance and exported tar hash precede sealing.
`SHA256SUMS` includes provenance and the copied Dockerfile; it is written only
after verified cleanup. Artifacts expire after 14 days; the lead must separately
accept an immutable identity and its provenance before any sentinel admission.
Same-user adversarial mutation races on the fresh trusted host are outside this
boundary. No actual signed-index resolution, image build, tool/ISO test, KVM or VM
is claimed by the synthetic suite.

Required fake-backend tests are `test_runtime_prepare.py`, alongside existing
portable-builder suites. Run them without credentials or Docker using a private
HOME, `env -i`, and `python3 -I -B`, explicitly adding this component's absolute
path to `sys.path` before unittest discovery. No suite may be silently absent.

Primary sources read 2026-10-26 (upstream current docs; no runtime execution):
[Buildx docker-container driver and defaults](https://docs.docker.com/build/builders/drivers/docker-container/),
[pinned v0.38.1 JSON listing schema](https://github.com/docker/buildx/blob/v0.38.1/commands/ls.go),
[pinned v0.38.1 driver source, including privileged bootstrap and removal](https://github.com/docker/buildx/blob/v0.38.1/driver/docker-container/driver.go),
[BuildKit v0.34.1 Docker exporter and shared options](https://github.com/moby/buildkit/blob/v0.34.1/exporter/oci/export.go),
[compression attribute parsing](https://github.com/moby/buildkit/blob/v0.34.1/util/compression/attrs.go),
[default gzip](https://github.com/moby/buildkit/blob/v0.34.1/util/compression/compression.go#L72),
[force across inherited/new layers](https://github.com/moby/buildkit/blob/v0.34.1/cache/remote.go#L33-L36),
[uncompressed conversion](https://github.com/moby/buildkit/blob/v0.34.1/util/compression/uncompressed.go),
[containerd v2.4.1 unchanged blob copy](https://github.com/containerd/containerd/blob/v2.4.1/core/images/archive/exporter.go#L429-L458),
[Docker exporter / metadata / pull behavior](https://docs.docker.com/reference/cli/docker/buildx/build/),
[pinned setup action source](https://github.com/docker/setup-buildx-action/blob/8d2750c68a42422c14e847fe6c8ac0403b4cbd6f/src/main.ts),
[BuildKit v0.34.1 release](https://github.com/moby/buildkit/releases/tag/v0.34.1),
[publisher Docker Hub digest metadata](https://hub.docker.com/v2/namespaces/moby/repositories/buildkit/tags/v0.34.1),
[BuildKit v0.34.1 Alpine donor source](https://github.com/moby/buildkit/blob/v0.34.1/Dockerfile#L221),
[Alpine 3.23 apk-tools CA dependency](https://pkgs.alpinelinux.org/package/v3.23/main/x86_64/apk-tools),
[Noble APT explicit CAInfo and default TLS verification](https://manpages.ubuntu.com/manpages/noble/man1/apt-transport-https.1.html),
[Alpine CA bundle file metadata](https://pkgs.alpinelinux.org/contents?arch=x86_64&branch=v3.23&name=ca-certificates-bundle&repo=main),
[Canonical Noble snapshots](https://ubuntu.com/server/docs/how-to/software/snapshot-service/),
[GitHub standard fresh hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[GitHub timeout / cancellation conditions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).
The builder index is `sha256:99368f3e46177c6405b9740e4461d91cee004128daeecca78d4ceac50ec1da5c`;
publisher metadata is content identity, not image-signature or compatibility proof.
The checkout/upload SHA pins are resolved from their official `v4` commit API;
setup-buildx is resolved from official `v3`. The Ubuntu base pin remains unchanged.

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
