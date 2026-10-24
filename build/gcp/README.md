# GCP build access and VM lease primitives

## Offline private filesystem collector

`inspection/collector.py` is a Python 3.12 standard-library command for an
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
OS release, six named units and their `.conf` drop-ins are captured privately.
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

Primary references consulted 2026-10-24: Python
[3.12 descriptor-relative filesystem APIs](https://docs.python.org/3.12/library/os.html),
[dpkg-query database/installed package fields](https://manpages.debian.org/bookworm/dpkg/dpkg-query.1.en.html)
(Debian bookworm manual, not an Ubuntu guest version claim), and
[systemd.service command syntax](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
(current upstream 262; the collector deliberately implements only discovery,
not that parser). Synthetic tests establish isolation and bounds, not behavior
of the saved appliance or a real mount.

- `bootstrap-access.sh`: owner-run keyless access setup (see
  [`docs/runbooks/gcp-build-access.md`](../../docs/runbooks/gcp-build-access.md)).
- `lifecycle/`: offline-testable single-slot VM lease primitives for #153.
  **Library and tests only.** Includes an opt-in GCS store adapter; no workflow
  invokes it. It grants no IAM and launches no VM.

## Lifecycle module contract

Python 3.12 standard library only. The controller/spec and offline tests need
no network or credentials. State and cloud access are injected; real adapters
perform network access only when explicitly called.

| File | Role |
|---|---|
| `spec.py` | Fixed inspection spec: `e2-standard-2`, `us-central1-a`, 10 GB boot + 300 GB copy of the selected source image (both `pd-standard`, both `autoDelete: true`, the copy attached `READ_ONLY`), no external IP, no service account, absolute `scheduling.terminationTime` with `DELETE` (60 minutes by default). Builds, validates and hashes the exact `instances.insert` body |
| `store.py` | `SlotStore` protocol: generation-matched writes (`if_generation_match`, 0 = must not exist), **no delete**. `MemoryStore` models Cloud Storage generation semantics |
| `cloud.py` | `PolicyCloud`: the only call surface. Allows only `instances.{insert,get,list,delete}`, `disks.{get,list,delete}`, `zoneOperations.{get,list}` in the fixed project/zone, plus read-only `{instances,disks,globalOperations}.aggregatedList` for the census. The constructor rejects any project/zone other than the approved constants. Images, snapshots, addresses, stop/start/setScheduling/setMetadata, IAM and quota calls are rejected before reaching any transport |
| `controller.py` | State machine `FREE → RESERVED → ACTIVE → FREE`, plus `CLEANUP_FAILED`, on **one persistent slot object** |
| `fakes.py`, `test_lifecycle.py` | Fake cloud with failure injection and the invariant tests |

### Safety contract

- `Config.lease_minutes` defaults to 60 and may shorten the lease to an
  integer from 1 to 60. `min_submit_minutes` must be shorter than that lease;
  a fixed five-minute pilot uses a one-minute submission margin. Admission
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
  two intended disks attached (boot read-write, source copy `READ_ONLY`). Any
  unexpected or mismatched child blocks the VM delete too, because VM delete
  also removes `autoDelete` disks. An id not yet recorded is adopted only with
  proof (a completed insert whose `clientOperationId` is this lease's UUID,
  whose `targetId` matches the VM incarnation, and a creation time not before
  the reservation); labels alone never suffice. Then
  it deletes the VM, then each disk, by exact name, waits for the delete
  operation, and requires a 404 for **all three** before release.
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

## Not covered yet (gates before any VM)

- The GCS and Compute adapters have mocked HTTP tests only. None of the
  live API behavior is exercised: `requestId` retention/idempotence, `terminationTime` plus
  `DELETE` removing `autoDelete` disks, whether disk labels from
  `initializeParams` propagate, whether an inline source-image disk is
  accepted with `READ_ONLY` mode (no writable fallback exists; if the API
  rejects it the design must change, not the check), the shape of
  `aggregatedList` warnings, org-policy effects, quota behavior and operation listing latency.
  The fake is a model, not evidence.
- The fixed workflows require review and authorized live evidence; no guest
  extraction stage or private output channel is implemented.
- The separately reviewed lifecycle-access bootstrap must be applied and
  verified before dispatch; workflow files do not create IAM or the bucket.
- The fixed boot image is checked by immutable ID. Any later guest stage
  requires its tools verified in that image because the VM has no internet
  access; this lifecycle-only pilot runs no guest commands.
- Three-slot allocation is intentionally absent; the counter would need its
  own race tests first.

## Fixed lifecycle runner

The `labapp-lifecycle-inspect.yml` workflow accepts only a dispatch on `main`,
with no inputs. Its first pilot uses a fixed **five-minute** absolute lease,
`e2-standard-2`, a 10GB stock Ubuntu boot disk and a 300GB read-only source-copy
`pd-standard` disk. Both images are checked against pinned immutable IDs before
admission. Project-global CPU and regional shared CPU/standard-disk quotas must have
headroom; reads are snapshots, not reservations. Inherited project execution
metadata (startup/shutdown scripts or cloud-init user-data) blocks this pilot.
E2 uses the regional `CPUS` pool shared with N1; no `E2_CPUS` entry is required. Existing unknown resources
still block admission through the controller census. There is no guest script,
package download, SSH, serial output or filesystem extraction in this pilot.

The runner fetches only the nine required Python module files through GitHub's
Contents API at the trusted workflow's `github.sha`, before WIF authentication.
It does not check out archived gitlinks, execute triggering-run code, download
artifacts or overwrite auth credentials. The CLI is invoked from that temporary
module directory as `python3 -m lifecycle.cli inspect` or `cleanup`; these entry
points require trusted GitHub event context and accept no cloud parameters.

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

The lead can exercise normal cleanup by dispatching manual cleanup after the
creator logs confirmed IDs; cancellation by cancelling the creator and checking
its independent completed-run cleanup; and expiry by allowing the fixed lease
to expire. Run these serially and inspect cleanup/ledger evidence before another
dispatch. Missing confirmation, API/IAM failure or ambiguous cleanup keeps capacity
blocked. This module's offline tests do not prove live identity federation,
image availability, Compute expiry behavior, cancellation delivery or disk
removal. Those require the separately authorized lead-run pilots after review.

Sources checked 2026-10-24 (Compute REST v1, API version 2026-09-01):
[GitHub Contents API](https://docs.github.com/en/rest/repos/contents#get-repository-content),
[workflow_run trust and default-branch semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run),
[CPU quota pools](https://docs.cloud.google.com/compute/resource-usage#cpu_quota),
[projects.get](https://docs.cloud.google.com/compute/docs/reference/rest/v1/projects/get),
[images.get](https://docs.cloud.google.com/compute/docs/reference/rest/v1/images/get),
[disks.get sourceImageId](https://docs.cloud.google.com/compute/docs/reference/rest/v1/disks/get),
[project-level startup scripts](https://docs.cloud.google.com/compute/docs/instances/startup-scripts/linux),
and Google's [current discovery schema](https://github.com/googleapis/google-api-python-client/blob/main/googleapiclient/discovery_cache/documents/compute.v1.json)
for regions.get and numeric quota fields (the regions reference page timed out).
