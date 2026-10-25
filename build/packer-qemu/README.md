# Stock Packer/QEMU portability experiment (`build/packer-qemu/`)

An **unexecuted experiment**, not the selected build system and not an image
pipeline. It exists to cheaply falsify one candidate: stock Packer core with the
stock QEMU plugin, `communicator = "none"`, a NoCloud guest that runs the
unchanged `build/provision/` modules, and a private host-side observer. Plain
QEMU carries the same receipt, shutdown, watchdog and cleanup obligations; compare
the glue honestly and stop on a structural mismatch rather than fork the builder
or grow a framework. Status, plans and evidence live in GitHub (#253, #252, #145).
This is preparation-only code with execution disabled. Offline tests use
fake channels and disposable inputs; they establish no Packer, QEMU, cloud-init
or hardware compatibility. Runtime evidence and remaining gates belong in the PR.

## Files

| File | Role |
|---|---|
| `labapp.pkr.hcl` | One `qemu` source (`communicator = "none"`) and one `shell-local` provisioner that only runs the verifier |
| `supervise.py` | Offline input staging and read-only hardware diagnostics; every execution request is rejected |
| `host_verify.py` | Sole client of the private QMP and serial sockets; bounded parser; writes the result marker |
| `guest/user-data`, `guest/guest-build.sh` | NoCloud seed; nonblocking enqueue; build service body (plan, seal, receipt, poweroff) |
| `test_*.py` | Offline tests: `python3 -m unittest discover -s build/packer-qemu -p 'test_*.py' -v` |

## Pins, verification, licensing (access date 2026-10-25, documented not verified)

| Input | Pin | Verify before first use |
|---|---|---|
| Packer core | `1.16.2` (HCL `required_version = "= 1.16.2"`); uses SDK 0.6.13 | HashiCorp `SHA256SUMS` and its signature; license text at the tag (core is not MPL; check the tag's `LICENSE`) |
| QEMU plugin | `github.com/hashicorp/qemu` `= 1.1.7`; built on SDK 0.6.11 | Install from a pre-fetched, checksummed binary via `PACKER_PLUGIN_PATH`; this code never runs `packer init` (it downloads). Source headers are MPL-2.0 |
| Base image | Ubuntu 24.04 cloud image, a local file whose SHA256 is passed as `--base-sha256`; Packer checks it | Canonical `SHA256SUMS` signature; exact serial recorded. No image is pinned or downloaded here |
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
  none` and `-S` are also set; whether they override or conflict with defaults is
  **UNRUN**.
* Builder channels are explicitly off: `disable_vnc = true` (without it the pinned
  `stepTypeBootCommand` still connects to VNC and fails before `shell-local`),
  `boot_command = []` (no typing), `qmp_enable = false` (no native QMP),
  `vnc_use_password = false`, no `net_bridge`, and `vnc_bind_address = "127.0.0.1"`
  for any transient reservation. Attribute names and effects are from the pinned
  docs/source and **UNRUN** (`packer validate` has not been run).
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
  ordering relies on the guest not running before `cont`; the builder's own
  boot-wait and provisioner start are **UNRUN** against `-S`.
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
  (accessed 2026-10-25; actual pinned runtime remains unexecuted).
* Trust: neither channel authenticates the guest. The private 0700 directory and
  the owned QEMU instance define the boundary; the nonce rejects stale receipts,
  not a malicious guest. Native SSH is **not** used and its identity gap is not
  waived (SDK 0.6.11 `InsecureIgnoreHostKey`).
* `WaitForShutdown` in the plugin treats any QEMU exit as shutdown, so Packer
  success alone proves nothing. The observer writes `verified.json` only after
  both pieces of evidence (`O_EXCL`), bound to the nonce and digest. Execution is
  disabled; no supervisor currently accepts that marker or any build artifact.

## Guest sequence (UNRUN on a real Noble disk)

NoCloud (`cidata` CD from `cd_files`) stages bytes. Final-stage `runcmd` only
copies them to `/var/lib/labapp-build/in` and runs
`systemctl start --no-block labapp-build.service`. The unit is
`After=cloud-final.service` and `guest-build.sh` first requires
`cloud-init status --format json` to exit zero and say `done`, with no non-empty
`errors`/`recoverable_errors` and no nonzero exit/return code at any nesting level
(`status: done` alone is insufficient, and `After=` alone is satisfied by a failed
unit; the exact Noble JSON shape is **UNRUN**). Then it checks the staged
directory with a bounded `find -print0` enumeration (no `ls | grep`; ShellCheck
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
disposable offline directory. The execution-grade staging requirements tracked
in #255 remain unmet. The HCL and guest files are experimental inputs, not an
approved launch command.

A process session cannot contain a descendant that changes sessions, and a
PID/session scan followed by signaling has reuse races. Cleanup must not erase
ownership or remove a workspace while an owned child might remain. An exit code
or receipt cannot override cancellation, expired budgets or unverified cleanup.

Before re-enabling execution, implement and independently validate a supported
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

## Bounded container probe (`container_runner.py`, #255 initial stage, UNRUN)

One fixed non-VM `probe` mode; no Packer/QEMU/VM path, no arbitrary command
option. Docker is reached only through a `Backend`: absolute `/usr/bin/docker`,
explicit `--host unix://…` and an empty `--config` dir (no caller context or
credential helpers), minimal environment, and a bounded byte collector (64 KiB
cap, deadline, process-group kill; overflow or invalid UTF-8 is an error, never
truncated). The CLI prints its plan unless `--execute` is given; nothing here has
been run against a real Docker daemon (revision 1 is source + fake tests only).

* Inputs: only the Ubuntu digest already pinned in `build/provision`
  (`PINNED_IMAGE`; there is no image option), never pulled and never deleted
  (`--pull=never`; only the probe container is removed). `image inspect` must
  show that digest in `RepoDigests` and no `Config.Volumes` or `ONBUILD`; the
  image ID is what gets created, with `--no-healthcheck`. Workspace root and a
  separate host-only ledger dir must be owned, symlink-free and not
  group/other-writable; root callers are refused.
* Create argv (fixed): `/bin/sh` entrypoint running the entry script, then
  `exec timeout` (same PID 1, no `--init`), `--restart=no`, `--network=none`,
  `--cap-drop=ALL`, `no-new-privileges`, `--read-only`, caller UID:GID,
  256m/1 CPU/64 PIDs, `--log-driver=none`, one bind of the fresh output workspace.
  No device, socket, home, credentials, privileged or host namespaces.
* Clock and deadline: one wall-clock epoch (host `time.time`, container
  `date +%s`; the container shares the host clock; a clock step breaks the
  bound and is not detectable here). The host passes the admission work deadline
  floored to whole seconds. At ACTUAL container start the entry script computes
  `timer = deadline - now - 1 (rounding) - 5 (kill-after)`; under 5 s it exits
  125 without running the probe, so a late daemon start cannot extend the work
  window. Budget: `probe` is 30 s work + 20 s cleanup (sentinel/fixture
  allocations are VM mode, not accepted); every Docker call is capped by
  remaining budget; deadline and cancellation are re-checked after slow calls and
  before acceptance. The host gives up at the work deadline (one final look
  first), which is a failure, never acceptance.
* Ledger (host-only, outside the container-writable workspace): one fsynced,
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
  verified removal; `hold` keeps ledger record and workspace.
* Signals: SIGTERM/SIGINT mark cancellation and unwind to cleanup (a signal
  during cleanup only sets the flag); a cancelled run is never accepted.
  Finalization exceptions become `hold`, never a crash or acceptance.
* Acceptance (probe only): exit 124/137, not OOM-killed, cleanup verified, and
  startup evidence: `/out/witness` is exactly one small regular file written by the
  fixed probe (`start <epoch> <timer>`, `probe <setsid child pid>`,
  `term_ignored`) with a timer consistent with the deadline, and the container
  ran about as long as that timer (an immediate 137 is rejected). Anything else
  in the workspace is untrusted and rejects. Exit codes: accepted 0, failed 1,
  usage 2, hold 7.

Pinned-source findings (read 2026-10-25, documented not tested): coreutils
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

Unmet before any VM mode: the real-Docker proof that descendants (including the
`setsid` child) die with PID 1 and that the exit codes above hold, observing
child existence and namespace cleanup directly (the witness records a pid; it
does not prove cleanup); `date`/`timeout`/`setsid` presence in the pinned image;
exact 124-vs-137 behavior with a TERM-ignoring probe; UID mapping of the bind (rootless/userns);
`/dev/kvm` passthrough; input verification and evidence binding (core/plugin/
base/module hashes, nonce, acceleration, normal shutdown); input mounts.

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

## Open gates (all UNRUN)

`packer validate`; authenticated inputs and licenses; a named KVM runner; that
`cd_files` globs, `-cpu host`/`-vnc none` overrides and the shell-local/`none` path
work on the pinned pair; observer and watchdog against a real forced failure
(crash, hang, bad receipt) leaving no processes or files; unchanged modules twice;
sealed boot/reboot identity, devices, network; accelerated nested execution; full
pinned VLAB and course exercises; GCP import route and its resources/IAM (no import
adapter exists; capture uses `sourceDisk`). Required offline suites are wired into
CI; shell checks cover `guest/guest-build.sh` only statically. Supported process
containment and an absolute deadline spanning admission through cleanup remain
unmet execution gates; passing offline tests cannot authorize a build.
