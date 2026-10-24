# GCP build access and VM lease primitives

## Offline private filesystem collector

`inspection/collector.py` is a Python 3.12+ standard-library command for an
**already mounted, stable, read-only guest root on Linux**. It does not mount,
repair, chroot, execute/source guest code, or use cloud credentials. No workflow
invokes it against a guest. Mounting, private authenticated transfer/storage,
reviewer access, deletion deadlines and lifecycle authorization must be reviewed
separately before actual guest use; this module does not supply those gates.

Invoke unchanged from the repository root as an inspector user with read access
to the mount and an existing, owned mode-0700 private output directory:

```bash
python3 -m build.gcp.inspection.collector \
  --root /mnt/guest --private-output /private/inspection/inventory.json
python3 -m unittest discover -s build/gcp/inspection -t build/gcp -v
```

The new output file is exclusive-create, mode 0600, outside the guest root,
limited to 8 MiB. Never upload or print it. stdout contains only status counts
and a report hash; errors do not include guest content. Raw units/helpers can
contain secrets even at allowlisted paths. Private output still requires a
separate reviewed transfer and field-redaction pass before any public use;
neither allowlisting nor a future pattern scanner proves publication safety.

Schema 1 records guest path, kind, status and (for captured files) SHA-256.
OS release at both fixed `/etc/os-release` and `/usr/lib/os-release` paths,
six named units and their `.conf` drop-ins are captured privately.
The names are `hhfab-vlab-resume`, `vlab-netfilter`, `hhbr-ip`,
`kubeconfig-merge`, `argocd-port-fix`, `hhfab-vlab`; these are historical leads,
not evidence that the saved image has them. Installed package name/version
pairs come from the guest `/var/lib/dpkg/status` via a bounded stdlib parser,
never the inspector's package database. Other dpkg fields are not copied.

Helper discovery accepts only a simple first executable from `ExecStart`,
`ExecStartPre` or `ExecStartPost`, with a fixed basename matching those six
names (optionally `.sh`), `hhfab-vlab-runner`, `hhbr-ip-setup.sh` or
`fix-argocd-port.sh` (the last two are historical #138 candidates), in `/usr/local/bin`,
`/usr/local/sbin`, `/opt/hedgehog/bin`, `/home/ubuntu/bin` or `/home/hhlab/bin`.
It does not interpret shell wrappers, expand systemd specifiers or recursively
follow helpers. Unsupported references remain in private unit text for review.
No arbitrary home/opt directory traversal, environment-file reads, token files,
kubeconfigs, SSH keys, histories, databases, container data or VM disks occur.
Legitimate helper names containing `kubeconfig` are allowed by exact name.

Every guest path component is opened relative to a pinned directory fd with
`O_NOFOLLOW`; **all symlinks are skipped and reported**, including legitimate
`/etc/os-release` or `/lib` guest links. Files must be regular UTF-8 text, at
most 256 KiB (16 MiB for dpkg). Drop-in enumeration is nonrecursive and bounded
to 128 entries per directory; the report has a 256-capture ceiling. A gap is
not evidence that a component is absent. This is filesystem evidence, not
systemd effective configuration or runtime verification. It assumes a trusted
inspector host and no concurrent mount replacement.

The report explicitly marks network/sysctl/modules, fabric/wiring sanitization,
shell profiles, binary versions, charts, environment files, recursive helpers,
effective systemd configuration and runtime recovery unimplemented. These need
separate slices; this command cannot recover the complete appliance baseline.

### Private inventory candidate

After the separately authorized transfer, the lead can derive a smaller private
candidate on the trusted lead host without executing any report content:

```bash
python3 -m build.gcp.inspection.candidate \
  --private-input /private/inspection/inventory.json \
  --private-output /private/inspection/candidate.json
```

Both parent directories must already be owned mode0700; input must be an owned
regular mode0600 file, and output is exclusive-create0600. No raw file body,
execution/environment string, OS release body, unknown package name or dynamic
drop-in filename is copied. The candidate contains fixed kind/status counts,
installed versions only for the fixed `candidate.PACKAGES` catalog, and status/
SHA-256 entries only for compile-time named unit/helper paths. Captured text
hashes are checked against their private bodies before releasing hash metadata.
OS release is represented by status counts only; gaps are not proof of absence.

Schema1, exact keys/types, known paths/statuses, bounded sizes and duplicate JSON
keys are validated before output. Unknown data fails closed. The source image
is **not** inferred from guest claims: provenance remains
`lead-verification-required` until the lead separately binds the accepted cloud
image/disk/lease evidence. stdout contains only fixed status, counts and candidate
hash. No automatic GitHub publication or credential scanner is supplied. The
candidate remains private until lead and independent review approve its exact
hash; this tool does not claim arbitrary version strings or hashes are safe
for publication without that review. Keep raw/intermediate retention and cleanup
under the private-transfer contract; delete promptly after accepted recovery or
an abandoned attempt. Unit/helper configuration recovery is a separate reviewed
slice; metadata inventory does not recover effective settings or runtime.

### Private persisted startup candidate

The lead can derive reusable selected startup configuration using the same
private file/mode/hash checks and review/publication boundary:

```bash
python3 -m build.gcp.inspection.startup \
  --private-input /private/inspection/inventory.json \
  --private-output /private/inspection/startup.json
```

This preserves the inventory fields and adds `persisted_startup` schema1.
Named base units yield selected `[Unit]`, `[Service]` and `[Install]` settings
plus a pure formatted unit containing only those recovered settings. Dependency,
identity, directory, boolean and service-mode values use compile-time public
catalogs. Literal second values are integers from 0 through3600. Startup
commands must match complete public literal commands in `startup.COMMANDS`,
including the historical #130 inline netfilter command. No arbitrary command
arguments, environment values, descriptions, documentation URLs or unknown
directive/section names enter the output. The sole environment exception is
the complete quoted
`Environment="TERM=xterm-256color"` assignment in `[Service]`, approved in
[#201](https://github.com/afewell-hh/labapp/issues/201). `StandardOutput` and
`StandardError` accept only `journal`. Other environment assignments,
`EnvironmentFile`, specifiers and output targets remain withheld.
Unknown directives/values/syntax, duplicate assignments and resets produce
fixed gap codes. Repeated/reset directives are omitted rather than assigning
invented precedence. Backslashes
refuse the entire unit's settings because continuation/escape semantics are
unsupported; this is deliberately not a systemd parser.
CRLF is normalized to LF; lone CR and Unicode whitespace/separators refuse
the unit subset rather than creating apparent directives inside private text.

Captured helpers yield a reusable script only when the whole body matches a
public checked-in recipe: currently `hhbr_ip_131.txt`, from issue#131. Only
CRLF and one final newline are normalized; comments, shebang, quoted content
and whitespace remain significant. A mismatch yields `recipe: unknown`.
Historical recipes are not proof of saved-image configuration until matched.

`literal_subset_complete` means no unrecognized execution-related assignment
was encountered in that base file; it does not mean the formatted subset is a
complete effective service. Description/documentation are intentionally omitted.
Drop-ins are not composed; aliases/masks, generators, enabled state and runtime
remain unknown, and `effective` is always false. Correct recovered fields can
still be reviewed and reused with these limits; gaps require further recovery.
No guest code or systemd command executes. The optional canonical os-release
record is recognized by both candidate commands; older schema1 reports still
derive the original inventory without changes. `/lib` aliases are not followed;
the existing fixed `/usr/lib/systemd/system` reads provide canonical evidence.

The offline discovery suite above tests known reusable unit/script output,
mixed secret/unknown input, reset/repetition, unsupported quoting/specifiers,
canonical symlink refusal and old/new inventory compatibility. These tests
cannot prove actual image configuration, boot behavior or helper equivalence
outside the exact recipe match.

### Fixed mount wrapper

`inspection/mounted_collect.py` adds local ext4 mount/collect/unmount only.
It has no cloud, SSH, transfer, IAM or firewall behavior. The lead first binds
the local source-copy disk/partition and their major:minor device numbers to
the exact lease/cloud disk incarnation. It does not guess device names or make
that cloud identity binding itself. Caller-supplied numbers are an assertion
to verify against local evidence, not cloud provenance proof.

On the trusted clean Linux inspector, from the reviewed code directory, run as
root in a fresh mount namespace. These are example device identities, **not
values to assume for an appliance**:

```bash
sudo unshare --mount --propagation private -- \
  env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  /usr/bin/python3 -E -s -m build.gcp.inspection.mounted_collect \
  --disk /dev/sdb --partition /dev/sdb1 \
  --disk-number 8:16 --partition-number 8:17 \
  --private-dir /run/labapp-inspection-output
```

The output directory must already exist, be empty, nonsymlink, owned by the
caller and mode0700. Prepare private staging and its cleanup before running;
the wrapper does not create a tmpfs or configure swap/core-dump policy. The
collector writes only `inventory.json` there, mode0600 and bounded to8MiB.
Use a private0700/0600 lead-host destination for later authenticated transfer.
Same-UID permissions are not isolation from other same-UID processes: general
workers are trusted contributors instructed not to read raw data, and the lead
does not share raw paths/content with them. No separate recipient/account or
arbitrary retention interval is required. Remove raw/intermediate data promptly
after reviewed recovery or abandonment; publish only reviewed sanitized output.

The wrapper requires a private namespace different from PID1's and private
propagation for both the root and the mount containing the private output
directory, checked before any mount. Fixed inspector tools (`findmnt`, `lsblk`, `dumpe2fs`,
`mount`, `umount`) must already exist. Device paths must be direct nonsymlink
block nodes under `/dev`, with the supplied exact numbers. Structured `lsblk`
evidence must show one read-only disk with at most four unmounted partitions,
exactly one ext4 candidate matching the supplied partition by default, and only
empty or vfat filesystems on other partitions. A boot-filesystem match,
LVM/RAID/encryption, unexpected layout, dirty ext4 state or `needs_recovery`
refuses collection.

For a separately verified Ubuntu root plus separate ext4 boot layout, supply
both `--boot-partition /dev/EXACT_BOOT_PARTITION` and
`--boot-partition-number MAJOR:MINOR`. This accepts exactly two ext4 partitions
matching the explicit root and boot identities under the same read-only parent;
all existing partition-count, mounted-child, protected inspector-boot and
identity guards remain. Both ext4 filesystems must be clean without
`needs_recovery`. Existing trusted `/usr/sbin/debugfs` is additionally required;
there is no install fallback.

Before mounting either filesystem, the wrapper invokes only fixed default-RO
`debugfs -R 'stat PATH'` requests. The root must have `/etc` and `/usr`
directories plus regular `/var/lib/dpkg/status`, and positively lack `/grub`
and `/grub/grub.cfg`. The companion must have `/grub` directory and regular
`/grub/grub.cfg`, and positively lack every root marker. Missing lookup is
accepted only as the exact known diagnostic; IO, corruption, unknown banners,
unparsed metadata, symlinks or ambiguous roles refuse. Exit0 alone is not
existence evidence. No contents, arbitrary labels or commands are used for
role identification. Names, sizes and filesystem labels alone do not choose
root. Device numbers/RO/layout are rechecked after probes. Only root is mounted;
the verified boot companion stays unmounted and its contents are not collected.

It mounts only explicit ext4 with `ro,noload,nodev,nosuid,noexec`, disables
external mount helpers, and verifies resulting source/number/type/options/private
propagation before calling the unchanged collector. It neither uses guest fstab
nor repairs, activates, replays journals or executes guest code. Every attempted
mount gets an unmount attempt; collector failure/cancellation removes the known
partial report. Unmount failure refuses success and leaves the private mountpoint
for lead cleanup. It never recursively deletes a guest mount. Diagnostics never
relay command output. SIGTERM/SIGINT trigger cleanup; SIGKILL or VM loss still
requires the existing independent resource cleanup and lead staging cleanup.

The offline suite uses mocked commands and synthetic files, including an
unchanged collector run against a fake mount. It establishes command/validation/
cleanup behavior, not kernel mount semantics or source-image layout. Actual
execution is separate evidence: see the [inspector kernel and private-transfer
proof](https://github.com/afewell-hh/labapp/issues/170#issuecomment-6388863729) and
[whole-wrapper source collection](https://github.com/afewell-hh/labapp/issues/170#issuecomment-6389012668).
The resulting [reviewed source inventory](https://github.com/afewell-hh/labapp/issues/151#issuecomment-6388996007)
is a separate metadata-only publication.
The synthetic loop proof does not establish whole-wrapper source-layout
acceptance; each source inspection still requires its own identity/layout and
clean-state validation. Never use a public workflow artifact or serial output
for raw transfer. Existing lifecycle deadlines are never extended by this wrapper.

Sources consulted2026-10-24: [kernel ext4](https://docs.kernel.org/admin-guide/ext4.html)
(RO alone may replay journals; `noload`/`norecovery` skips replay),
[util-linux mount](https://man7.org/linux/man-pages/man8/mount.8.html) and
[unshare](https://man7.org/linux/man-pages/man1/unshare.1.html), and
[Ubuntu24.04 debugfs](https://manpages.ubuntu.com/manpages/noble/man8/debugfs.8.html)
(e2fsprogs1.47.0; default read-only and fixed inode stat). These describe
upstream behavior. Offline tests do not establish Ubuntu tool/kernel
compatibility; the linked real inspector evidence records its actual tool/kernel
scope and cannot guarantee compatibility with every Ubuntu revision.

### Synthetic inspector kernel proof

Before source-copy mounting, the lead can run the fixed no-input
`inspection/synthetic_ext4.py` on the separately authorized clean inspector:

```bash
sudo unshare --mount --propagation private -- \
  /usr/bin/python3 -E -s -m build.gcp.inspection.synthetic_ext4
```

Use Python3.12+ and already-present trusted `mkfs.ext4`, `losetup`, `blockdev`,
`udevadm` plus the wrapper tools above, from the exact reviewed code SHA. No
install/download fallback. It creates its own0700 `/run` directory,32MiB file
and harmless fixture, formats that file before read-only loop attachment, and
verifies the exact backing inode/device, zero offset, size limit, loop device
number and RO state. It neither accepts source paths nor scans/adopts disks.

This separately proves actual private ext4 `ro,noload,nodev,nosuid,noexec`
mount semantics and runs the unchanged collector. The production validator
must refuse the observed `TYPE=loop`; its `TYPE=disk` requirement stays intact.
Thus success is **not** positive whole-wrapper integration or source-layout
acceptance. Dirty-state refusal in this clean harness uses synthetic evidence;
it does not generate an actual dirty journal. Use the separate pending-journal
proof below for real on-disk refusal. Source-copy layout and clean
state remain separate gates, including an unformatted BIOS boot partition
(which normally has no filesystem type); unexpected types still refuse.

The harness unmounts and verifies no exact-target mount, revalidates ownership
before detach, waits for udev, requires the owned loop mapping absent and the
backing-file hash unchanged, then deletes only explicit generated files and
empty directories. Uncertain cleanup preserves evidence and fails; the lead
must resolve it before source inspection or slot reuse. It never recursively
deletes through a mountpoint. Output is fixed status/count/hash evidence only.
Offline tests cover mapping-identity refusal, not actual kernel mounts or all
cleanup failure paths. Record actual execution/tool versions and remaining
limits in the issue; no live execution is implied by this module's presence.

### Actual pending-journal refusal proof

On the same separately authorized clean inspector, before source inspection,
the lead can run the fixed no-input proof from reviewed code:

```bash
sudo unshare --mount --propagation private -- \
  /usr/bin/python3 -E -s -m build.gcp.inspection.dirty_ext4
```

It requires Python3.12+ and already-present trusted `mkfs.ext4`, `debugfs`,
`dumpe2fs`, `losetup`, `blockdev`, `lsblk`, `findmnt` and `udevadm`; no downloads
or install fallback. It creates only a new owned32MiB regular file in a0700
`/run` directory. Preparation formats4096-byte blocks, then fixed debugfs
`journal_open`, `journal_write -b 7000 /dev/zero`, `journal_close` commands write
one committed journal transaction to that file. `/dev/zero` supplies one fixed
block of harmless data. No superblock flag is forged, no original/source image
is accepted and no filesystem is mounted writable or snapshotted.

After preparation it hashes the file and attaches only that exact file as a
read-only loop. The existing loop verifier binds backing inode/device, offset,
size limit, kernel device number and RO state. Actual `dumpe2fs -h` must report
`needs_recovery` and nonzero journal start; default-read-only `debugfs logdump`
must show the expected pending descriptor and commit. Then the unchanged
production `validate_clean` must refuse that actual evidence. The fixture is
**never mounted**, repaired or replayed; journal_run/fsck are absent. This
proves the cleanliness guard against a real userspace-generated transaction,
not whole-wrapper disk-layout acceptance or a kernel-crash scenario. Production
loop-device refusal remains unchanged.

Cleanup revalidates exact owned read-only/unmounted loop identity, detaches it,
waits for udev, confirms its mapping absent and post-preparation hash unchanged,
then removes only explicit generated files and the empty owned directory.
Unknown mapping or failed cleanup preserves evidence and refuses success. Lead
must resolve it before source collection or slot reuse. Signals get the same
cleanup; SIGKILL/VM loss still need lead/resource cleanup. Output is fixed
status only. Offline mocks cover success, failed probe and failed detach;
the actual loop/kernel path requires separate lead execution on the existing
bounded inspector. No additional VM or lease extension is implied.

Primary recipe checked2026-10-24: e2fsprogs
[j_short_trans_64bit](https://github.com/tytso/e2fsprogs/blob/8fd79523d051d5ea881237f27eb1c664486e0078/tests/j_short_trans_64bit/script)
uses jo/jw/jc; its later fsck/replay steps are deliberately excluded.
[do_journal.c](https://github.com/tytso/e2fsprogs/blob/8fd79523d051d5ea881237f27eb1c664486e0078/debugfs/do_journal.c)
marks recovery required after committing the transaction, and
[debugfs manual](https://man7.org/linux/man-pages/man8/debugfs.8.html) documents
these journal commands. Actual userspace preparation/probe/refusal/hash/cleanup
passed with e2fsprogs1.47.2 in a credential-free Debian13 container without
host devices or mount capability; that is not kernel-loop proof.

Primary references consulted 2026-10-24: Python
[3.12 descriptor-relative filesystem APIs](https://docs.python.org/3.12/library/os.html),
[dpkg-query database/installed package fields](https://manpages.debian.org/bookworm/dpkg/dpkg-query.1.en.html)
(Debian bookworm manual, not an Ubuntu guest version claim), and
[systemd.service command syntax](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
(current upstream 262; the collector deliberately implements only discovery,
not that parser). Synthetic tests establish isolation and bounds. Real mount
and immutable-source inventory evidence is linked above; neither proves runtime
behavior of the saved appliance.

- `bootstrap-access.sh`: owner-run keyless access setup (see
  [`docs/runbooks/gcp-build-access.md`](../../docs/runbooks/gcp-build-access.md)).
- `lifecycle/`: single-slot controller, GCS/Compute adapters and trusted-runner
  CLI used by the [fixed lifecycle workflows](#fixed-lifecycle-runner).
  Offline tests inject fake storage/cloud transports and require no credentials.
  Real execution uses separate creator/cleanup identities configured by
  `bootstrap-lifecycle-access.py`; the CLI does not create IAM or the bucket.

For separately authorized owner access to an inspector, see the
[IAP access plan](../../docs/runbooks/gcp-build-access.md#owner-iap-access-to-an-owned-inspector).
The create body stays untagged. Reuse an effective protected existing SSH rule
without adopting, modifying or deleting it; do not add a redundant firewall or
tag. Bind the clean inspector public host key through privately captured
authenticated owner guest-attribute evidence and its exact confirmed immutable
ID, then use strict host checking and short-lived owner OS Login keys. This plan adds no
creator/cleanup IAM or API capability, guest execution or raw-data publication path.

## Lifecycle module contract

Python 3.12+ standard library only. The controller/spec and offline tests need
no network or credentials. State and cloud access are injected; real adapters
perform network access only when explicitly called.

| File | Role |
|---|---|
| `spec.py` | Fixed inspection spec: `e2-standard-2`, `us-central1-a`, 10 GB boot + 300 GB copy of the selected source image (both `pd-standard`; boot `READ_WRITE`/`autoDelete: true`, copy `READ_ONLY`/`autoDelete: false`), no external IP, no service account, absolute `scheduling.terminationTime` with `DELETE` (60 minutes by default). Builds, validates and hashes the exact `instances.insert` body |
| `store.py` | `SlotStore` protocol: generation-matched writes (`if_generation_match`, 0 = must not exist), **no delete**. `MemoryStore` models Cloud Storage generation semantics |
| `cloud.py` | `PolicyCloud`: the controller's mutation/inventory call surface. Allows only `instances.{insert,get,list,delete}`, `disks.{get,list,delete}`, `zoneOperations.{get,list}` in the fixed project/zone, plus read-only `{instances,disks,globalOperations}.aggregatedList` for the census. The constructor rejects any project/zone other than the approved constants. Images, snapshots, addresses, stop/start/setScheduling/setMetadata, IAM and quota calls are rejected before reaching any transport |
| `cli.py` | Trusted-runner entrypoint for the fixed workflows; validates events and performs four fixed read-only project/region/image preflight requests separately from `PolicyCloud`, then invokes creator or cleanup transitions |
| `controller.py` | State machine `FREE → RESERVED → ACTIVE → FREE`, plus `CLEANUP_FAILED`, on **one persistent slot object** |
| `fakes.py`, `test_lifecycle.py` | Fake cloud with failure injection and the invariant tests |

### Safety contract

- `Config.lease_minutes` defaults to 60 and may shorten the lease to an
  integer from 1 to 60. `min_submit_minutes` must be shorter than that lease;
  the fixed thirty-minute inspector uses a one-minute submission margin. Admission
  rechecks these bounds before writing intent; an existing deadline is never
  extended.
- **Every** transition (admit, submit, ID capture, failure, release) is a
  compare-and-swap on the slot generation, for the creator, normal cleanup
  and the janitor alike. The slot object is never deleted, so a released slot
  is reusable; a stale actor loses its write instead of overwriting a newer
  lease.
- `admit` persists the UUID (`requestId`), the exact body hash, the intended
  names and the immutable deadline **before** any cloud call. Identity fields
  and the deadline cannot change while a lease is held.
- `submit` records the attempt before sending, reuses the persisted UUID and
  body, and never mints a new UUID. Default is one attempt
  (`max_submit_attempts`); retry semantics for `requestId` are not verified.
- Admission fails closed over the **whole project** (every zone, all pages of
  `aggregatedList`; a failed page, unreachable scope or runaway paging blocks):
  any instance or disk not in the lead-supplied `baseline` (name → immutable
  id), or any non-DONE operation, blocks the lease. Baseline VMs are protected
  but still count: total VMs (running or stopped, any zone) plus the new lease
  must not exceed `max_vm_slots` (3), so four baseline VMs never admit a fifth.
  Prefix lookalikes are unknown, not owned. This is a serial one-slot gate, not
  a multi-slot allocator.
- `reconcile` is the only path to `FREE`. Before any delete it runs an
  all-or-nothing preflight: every existing resource must match name, lease
  label, zone and immutable id, and an existing VM must have **exactly** the
  two intended disks attached (boot `READ_WRITE`/`autoDelete: true`, source
  copy `READ_ONLY`/`autoDelete: false`). Any
  unexpected or mismatched child blocks the VM delete too, because VM delete
  also removes `autoDelete` disks. An id not yet recorded is adopted only with
  proof (a completed insert whose `clientOperationId` is this lease's UUID,
  whose `targetId` matches the VM incarnation, and a creation time not before
  the reservation); labels alone never suffice. Then
  it deletes the VM, then each disk, by exact name, waits for the delete
  operation, and requires a 404 for **all three** before release.
  - Compute forbids auto-delete on a read-only attachment. VM deletion, whether
    explicit or at the absolute deadline, auto-deletes only the boot disk. The
    source copy remains billable until the cleanup identity explicitly deletes
    it. Independent janitor cleanup is required; the VM deadline alone cannot
    bound data-disk retention. A failed or pending disk delete keeps capacity
    occupied, even when the VM is absent.
  - An error, identity mismatch, still-existing resource or foreign pending
    operation keeps the slot occupied (`CLEANUP_FAILED` or `blocked`).
  - A 404, timeout or HTTP error on create is not proof the create failed. A
    lease with submit attempts but no insert operation for **its own request
    id** and no VM is held (an operation that only targets the same name does
    not count) is held. Elapsed time and the deadline never release it: past
    the deadline it reports `blocked` until a terminal current-request insert
    operation is seen and VM and both disks are verified absent. If the
    operation has aged out of the list, the slot stays blocked for manual
    review (conservative; whether Compute rejects a late create after
    `terminationTime` is an unverified assumption, not relied on).
  - `reconcile(request_id)` is the owner's forced cleanup and leaves a newer
    lease alone (`superseded`). `reconcile()` is the janitor: it acts only on
    expired, stopped or previously failed leases.

### Run the tests

```bash
python3 -m unittest discover -s build/gcp/lifecycle -t build/gcp -v
```

## GCS slot adapter

`lifecycle/gcs.py` implements `SlotStore`; construct
`GcsSlotStore(bucket, token_provider=...)` with an existing private ledger
bucket. Only `slots/slot-1.json` is allowed by default. The shared
`auth_http.py` transport gets short-lived credentials from the trusted runner's
existing `gcloud` identity; it never logs tokens, follows redirects or retries
writes. Tests inject fake HTTP and credentials and make no cloud calls.

Reads fetch metadata then the body pinned to that generation. A revision lost
between requests triggers a bounded fresh read; it never becomes absence in
that call. Writes use `ifGenerationMatch`; HTTP 412 raises `PreconditionFailed`.
Other HTTP, malformed-data or network failures raise `StoreError`, blocking
progress. After an uncertain write, re-read and re-evaluate the controller
state; do not blindly repeat a transition. The adapter cannot delete objects
or manage buckets/IAM. See its module docstring for official API references.

The lifecycle discovery command above includes the HTTP-contract tests.
Mocked tests establish request/response handling, not live bucket/IAM behavior.

## Validation scope and remaining integrations

- Offline tests do not prove successful live creation or cleanup:
  `requestId` retention/idempotence, `terminationTime` plus
  `DELETE` removing the boot disk, explicit deletion of the retained data copy,
  whether disk labels from
  `initializeParams` propagate, whether an inline source-image disk is
  accepted with `READ_ONLY` mode (no writable fallback exists; if the API
  rejects it the design must change, not the check), the shape of
  `aggregatedList` warnings, org-policy effects, quota behavior and operation listing latency.
  The fake is a model, not evidence.
- Changes to the fixed workflows require independent review and authorized
  live evidence. They perform lifecycle/resource checks only; the offline
  collector and mount wrapper are not invoked by these workflows. Guest
  access, private transfer and recovery require separately reviewed integration.
- The separately reviewed lifecycle-access bootstrap must be applied and
  verified before dispatch; workflow files do not create IAM or the bucket.
- The fixed boot image is checked by immutable ID. Any later guest stage
  requires its tools verified in that image because the VM has no internet
  access; this lifecycle-only pilot runs no guest commands.
- Three-slot allocation is intentionally absent; the counter would need its
  own race tests first.

## Fixed lifecycle runner

The `labapp-lifecycle-inspect.yml` workflow accepts only a dispatch on `main`,
with no inputs. The inspector uses a fixed **thirty-minute** absolute lease,
`e2-standard-2`, a 10GB stock Debian13 boot disk and a 300GB read-only source-copy
`pd-standard` disk. Both images are checked against pinned immutable IDs before
admission. The fixed boot pin is
`projects/debian-cloud/global/images/debian-13-trixie-v20261023`, immutable ID
`1840322579453583118`; the appliance source pin remains unchanged. Initial
instance metadata contains only OS Login, project SSH-key blocking,
`enable-guest-attributes=TRUE` and `labapp-stage=none`; the spec validator
rejects missing, duplicate, changed or extra settings. Guest attributes permit
trusted-stock host-public-key publication on first boot; owner access follows
the linked runbook, with no creator/cleanup guest-attribute read capability.
Project-global CPU and regional shared CPU/standard-disk quotas must have
headroom; reads are snapshots, not reservations. Inherited project execution
metadata (startup/shutdown scripts or cloud-init user-data) blocks this pilot.
E2 uses the regional `CPUS` pool shared with N1; no `E2_CPUS` entry is required. Existing unknown resources
still block admission through the controller census. There is no guest script,
package download, SSH, serial output or filesystem extraction in this pilot.

Debian's supplier AMD64 fstab/GRUB configuration selects root and ESP by
build-generated PARTUUID, without a separate `/boot` filesystem. This avoids
the Ubuntu source's `BOOT` label selector; it is a design rationale, not proof
of this exact image's boot behavior. Before source collection, the lead must
verify actual stock cmdline/fstab/effective mount units and exact root/ESP
ancestry, no unexpected/pending automounts, required Python/tools, OS Login and
host-key publication. Immediately before and after the unchanged wrapper,
require every source child unmounted plus exact RO/identity and both ext4
clean-state checks. Unexpected or reappearing mounts refuse collection. Never
change source labels/UUIDs or relax the wrapper to accommodate an ambient mount.
The guest-attribute channel assumes a trusted stock guest: any guest process can
write it, so it is not attestation against malicious guest code. A clean boot
and actual kernel mount proof remain lead-only gates after review; container
compatibility does not establish them.

The fixed window applies to every new inspector dispatch; there is no duration
input or environment override. It remains below the 60-minute inspection limit
and never changes an existing lease. Normal cleanup can end it early. Owner
IAP access, synthetic mount validation and private collection require their
separately reviewed authorization; the creator does not run guest commands.

The runner fetches only the nine required Python module files through GitHub's
Contents API at the trusted workflow's `github.sha`, before WIF authentication.
It does not check out archived gitlinks, execute triggering-run code, download
artifacts or overwrite auth credentials. The CLI is invoked from that temporary
module directory as `python3 -m lifecycle.cli inspect` or `cleanup`; these entry
points require trusted GitHub event context and accept no cloud parameters.

Creator confirmation polls the insert operation for up to six elapsed minutes,
with at most 72 polls at five-second intervals. Time spent in requests counts
against that polling budget, and CAS conflicts do not restart it. The budget is
checked between requests: one in-flight read can finish after it, and subsequent
ownership/provenance reads take additional time. The creator job has a thirty-six-
minute timeout, leaving four minutes beyond the thirty-minute lease plus two-minute
absence grace for setup and preflight; that overhead is allowance, not a
provisioning-time guarantee. No deadline is extended. Slow or uncertain creation
still fails closed and independent cleanup retains the occupied lease.

The controller's optional `confirm_created(..., timeout_seconds=...)` argument
sets this elapsed polling budget. Calls that omit it and all cleanup operation
waits retain their existing attempt/interval defaults. Creator uses 72 attempts;
the cleanup CLI retains 30 attempts at five-second intervals. The absence wait
also has an iteration ceiling covering the full thirty-minute lease plus two-minute
grace, so early provisioning does not exhaust its observation window first.

Creator and cleanup use distinct fixed WIF pools and service accounts. Creator
cannot delete; cleanup cannot create. After confirming the insert and persisting
all three resource IDs, creator checks each actual disk's `sourceImageId`
against the pinned image ID, then prints only IDs/deadline and polls for VM absence
until the immutable deadline plus two minutes. That observation does not release
the ledger or establish disk cleanup. The independent cleanup workflow handles
completed creator runs, including failure/cancellation, only after validating
the fixed name/path, original dispatch, repository/owner, main branch, and the
ledger's run ID and attempt. Late completions cannot force another lease's
cleanup. Manual cleanup dispatch forces the current lease; scheduled cleanup
only handles due leases, on an offset ten-minute schedule. This interval is
best-effort and gives no ten-minute completion guarantee. Both use the same CAS reconciliation and verify the VM
and both disks absent before release. Schedules remain best-effort; initial
Compute `terminationTime` plus `DELETE` is the independent cloud-side bound.
That bound requests VM deletion and boot-disk auto-deletion; it does not delete
the `READ_ONLY` source-copy disk. The independent cleanup workflow must delete
that owned disk explicitly and confirm absence before releasing the ledger.

The lead can exercise normal cleanup by dispatching manual cleanup after the
creator logs confirmed IDs; cancellation by cancelling the creator and checking
its independent completed-run cleanup; and expiry by allowing the fixed lease
to expire. Run these serially and inspect cleanup/ledger evidence before another
dispatch. Missing confirmation, API/IAM failure or ambiguous cleanup keeps capacity
blocked. This module's offline tests do not prove live identity federation,
image availability, Compute expiry behavior, cancellation delivery or disk
removal. Those require the separately authorized lead-run pilots after review.

Sources checked 2026-10-24 (Compute REST v1, API version 2026-09-01):
[Compute asynchronous operation polling](https://docs.cloud.google.com/compute/docs/api/how-tos/api-requests-responses#handling_api_responses),
[GitHub job timeout](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idtimeout-minutes),
[Python monotonic clock](https://docs.python.org/3/library/time.html#time.monotonic)
(stable since Python 3.3; local tests use Python 3.10, CI uses Ubuntu 24.04),
[disk auto-delete settings](https://docs.cloud.google.com/compute/docs/disks/modify-persistent-disk#autodelete)
(explicit read-only restriction; the REST boolean schema alone does not express it),
[GitHub Contents API](https://docs.github.com/en/rest/repos/contents#get-repository-content),
[workflow_run trust and default-branch semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run),
[CPU quota pools](https://docs.cloud.google.com/compute/resource-usage#cpu_quota),
[projects.get](https://docs.cloud.google.com/compute/docs/reference/rest/v1/projects/get),
[images.get](https://docs.cloud.google.com/compute/docs/reference/rest/v1/images/get),
[disks.get sourceImageId](https://docs.cloud.google.com/compute/docs/reference/rest/v1/disks/get),
[project-level startup scripts](https://docs.cloud.google.com/compute/docs/instances/startup-scripts/linux),
and Google's [current discovery schema](https://github.com/googleapis/google-api-python-client/blob/main/googleapiclient/discovery_cache/documents/compute.v1.json)
for regions.get and numeric quota fields (the regions reference page timed out).

Inspector identity sources checked2026-10-24: Google's
[Debian OS details](https://docs.cloud.google.com/compute/docs/images/os-details#debian)
(10GB/GPT/ESP, guest environment and OS Login), Debian cloud-image
[AMD64 fstab](https://salsa.debian.org/cloud-team/debian-cloud-images/-/blob/9ea44ee81fd04d1944127f33f07adf15a3608136/config_space/13/files/etc/fstab/AMD64),
[UUID generation](https://salsa.debian.org/cloud-team/debian-cloud-images/-/blob/9ea44ee81fd04d1944127f33f07adf15a3608136/config_space/13/class/BASE.var)
and [GRUB selectors](https://salsa.debian.org/cloud-team/debian-cloud-images/-/blob/9ea44ee81fd04d1944127f33f07adf15a3608136/config_space/13/files/etc/default/grub.d/10_cloud.cfg/SYSTEM_BOOT).
Supplier source describes the intended layout, not exact published-image
attestation; actual pinned-image identities and mount behavior require the
bounded lead proof. Guest-attribute sources and trust limits are in the access
runbook. The dirty-journal refusal fixture remains separate from this pin change.
