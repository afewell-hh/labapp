# Stock Packer/QEMU portability experiment (`build/packer-qemu/`)

An **unexecuted experiment**, not the selected build system and not an image
pipeline. It exists to cheaply falsify one candidate: stock Packer core with the
stock QEMU plugin, `communicator = "none"`, a NoCloud guest that runs the
unchanged `build/provision/` modules, and a private host-side observer. Plain
QEMU carries the same receipt, shutdown, watchdog and cleanup obligations; compare
the glue honestly and stop on a structural mismatch rather than fork the builder
or grow a framework. Status, plans and evidence live in GitHub (#253, #252, #145).
Nothing here has been run, including `packer validate`; every unit test below
uses fake owned processes/sockets and shows no Packer, QEMU, cloud-init or
hardware compatibility.

## Files

| File | Role |
|---|---|
| `labapp.pkr.hcl` | One `qemu` source (`communicator = "none"`) and one `shell-local` provisioner that only runs the verifier |
| `supervise.py` | Host watchdog: stages inputs, owns the absolute deadline, new-session child, owned-session cleanup, final success rule, preflight |
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
  before `cont` is acknowledged fails. Writes are nonblocking and resumed after
  partial writes. The ordering relies on the guest not running before `cont`; the
  builder's own boot-wait and provisioner start are **UNRUN** against `-S`.
* Strict parsing: UTF-8 only; duplicate keys (at any depth), `NaN`/`Infinity`,
  overflowing numbers, non-object messages, a response carrying both `return` and
  `error` (or missing/unknown/duplicate/wrong `id`), a `null`/malformed greeting
  and malformed event envelopes all fail with fixed reason codes.
* `DIR` is created by `supervise.py` (`mkdtemp`, 0700, safe characters only). The
  verifier refuses an endpoint that is not a socket owned by the same user.
* Startup race: the provisioner starts after `stepRun`, but sockets may not exist
  or listen yet; the verifier retries (50 ms) until its deadline and then fails.
  Serial bytes written before it connects are dropped by QEMU, so a missed receipt
  fails closed. QMP events before the verifier connects are likewise lost, and the
  guest needs minutes to reach shutdown.
* Success needs both: a serial line `LABAPP-RECEIPT v1 nonce=<64hex> inputs=<64hex>
  status=ok` equal to this run's values, and QMP `SHUTDOWN` with
  `data.guest == true` and `reason == "guest-shutdown"` (exactly those two keys; a
  second `SHUTDOWN` fails). Observation continues after the receipt: it alone never
  succeeds, a normal guest shutdown is still required. `status=fail`, a
  malformed, stale, wrong or duplicate receipt, a host/non-guest shutdown,
  `GUEST_PANICKED`, EOF before shutdown, or shutdown without a drained receipt
  (5 s) fail. QEMU exit, EOF or a vanished socket never succeed on their own.
* Bounds: QMP lines 64 KiB / 1 MiB total (violations fail); serial lines 4 KiB
  (longer lines are discarded) / 4 MiB total; one monotonic deadline. Peer bytes
  are never echoed. `reason` in `SHUTDOWN` needs QEMU 4.0+ (Ubuntu 24.04 ships 8.2).
* Trust: neither channel authenticates the guest. The private 0700 directory and
  the owned QEMU instance define the boundary; the nonce rejects stale receipts,
  not a malicious guest. Native SSH is **not** used and its identity gap is not
  waived (SDK 0.6.11 `InsecureIgnoreHostKey`).
* `WaitForShutdown` in the plugin treats any QEMU exit as shutdown, so Packer
  success alone proves nothing; `supervise.py` additionally requires
  `verified.json` (written only after both pieces of evidence, `O_EXCL`) with this
  run's nonce and digest.

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

Profiles are absolute from start, no renewal: `sentinel` 15 min work + 5 min
cleanup, `fixture` 30 + 15. These are experiment allocations, not measured
performance. Packer runs as a new-session leader; on deadline, SIGTERM/SIGINT or
any exit the supervisor sends TERM then KILL only to processes whose session id
is that child's (never by name), then requires an empty session (zombies excluded)
before the deadline and removes the private directory on failure. Escapes via
`setsid()` are not detectable. Failure leaves no accepted output. Exit codes: 0 ok,
1 failed, 2 usage/preflight, 3 timeout, 4 cancelled, 5 cleanup unverified.
Packer's shell-local `timeout` is set but not relied upon (enforcement untraced).

```bash
# Preflight only: reads /proc and /sys, runs nothing.
python3 -I /abs/build/packer-qemu/supervise.py --preflight-only
```

## Runner preflight

Linux x86_64; `/dev/kvm` readable and writable by the build user; Packer-required
host tools (`qemu-system-x86_64`, `qemu-img`, and `xorriso`, `mkisofs` or
`genisoimage` for the CD). Builder boot only needs KVM, but the later nested VLAB
proof needs a CPU exposing `vmx`/`svm` with the `kvm_intel`/`kvm_amd` `nested`
parameter enabled; GCP nested virtualization excludes E2 and Arm and costs 10%+.
The preflight requires both. TCG is never a substitute for either; with no suitable
runner the work stays static. The builder boot is separate from the accelerated
nested proof.

## Open gates (all UNRUN)

`packer validate`; authenticated inputs and licenses; a named KVM runner; that
`cd_files` globs, `-cpu host`/`-vnc none` overrides and the shell-local/`none` path
work on the pinned pair; observer and watchdog against a real forced failure
(crash, hang, bad receipt) leaving no processes or files; unchanged modules twice;
sealed boot/reboot identity, devices, network; accelerated nested execution; full
pinned VLAB and course exercises; GCP import route and its resources/IAM (no import
adapter exists; capture uses `sourceDisk`). Wire the unit-test command into CI in
the PR that enables it; shell checks cover `guest/guest-build.sh` only statically.
