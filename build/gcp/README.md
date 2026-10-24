# GCP build access and VM lease primitives

- `bootstrap-access.sh`: owner-run keyless access setup (see
  [`docs/runbooks/gcp-build-access.md`](../../docs/runbooks/gcp-build-access.md)).
- `lifecycle/`: offline-testable single-slot VM lease primitives for #153.
  **Library and tests only.** No workflow uses it, it contains no real cloud
  or storage client, grants no IAM and launches no VM.

## Lifecycle module contract

Python 3.12 standard library only; no network, no credentials, no repo-cwd
dependence. State and cloud access are injected, so the same code can later run
unchanged against Cloud Storage and Compute adapters.

| File | Role |
|---|---|
| `spec.py` | Fixed inspection spec: `e2-standard-2`, `us-central1-a`, 10 GB boot + 300 GB copy of the selected source image (both `pd-standard`, both `autoDelete: true`), no external IP, no service account, absolute 60 min `scheduling.terminationTime` with `DELETE`. Builds, validates and hashes the exact `instances.insert` body |
| `store.py` | `SlotStore` protocol: generation-matched writes (`if_generation_match`, 0 = must not exist), **no delete**. `MemoryStore` models Cloud Storage generation semantics |
| `cloud.py` | `PolicyCloud`: the only call surface. Allows only `instances.{insert,get,list,delete}`, `disks.{get,list,delete}`, `zoneOperations.{get,list}` in the fixed project/zone. Images, snapshots, addresses, stop/start/setScheduling/setMetadata, IAM and quota calls are rejected before reaching any transport |
| `controller.py` | State machine `FREE → RESERVED → ACTIVE → FREE`, plus `CLEANUP_FAILED`, on **one persistent slot object** |
| `fakes.py`, `test_lifecycle.py` | Fake cloud with failure injection and the invariant tests |

### Safety contract

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
- Admission fails closed: any instance or disk not in the lead-supplied
  `baseline` (name → immutable id), or any non-DONE zone operation, blocks the
  lease. Prefix lookalikes are unknown, not owned.
- `reconcile` is the only path to `FREE`. It deletes the VM, then each disk, by
  exact name only after verifying name, `labapp-lease` label, zone and
  immutable id (or creation time for an id not yet captured), waits for the
  delete operation, and requires a 404 for **all three** before release.
  - An error, identity mismatch, still-existing resource or foreign pending
    operation keeps the slot occupied (`CLEANUP_FAILED` or `blocked`).
  - A 404, timeout or HTTP error on create is not proof the create failed. A
    lease with submit attempts but no related operation and no VM is held
    until the absolute deadline (a late create is rejected after
    `terminationTime`).
  - `reconcile(request_id)` is the owner's forced cleanup and leaves a newer
    lease alone (`superseded`). `reconcile()` is the janitor: it acts only on
    expired, stopped or previously failed leases.

### Run the tests

```bash
python3 -m unittest discover -s build/gcp/lifecycle -t build/gcp -v
```

## Not covered yet (gates before any VM)

- No Cloud Storage or Compute adapter, so none of the real API behavior is
  exercised: `requestId` retention/idempotence, `terminationTime` plus
  `DELETE` removing `autoDelete` disks, whether disk labels from
  `initializeParams` propagate, inline source-image disks with `READ_WRITE`
  mode, org-policy effects, quota behavior and operation listing latency.
  The fake is a model, not evidence.
- No workflow, guest extraction stage, or private output channel.
- No IAM: custom roles, scoped create versus delete permissions, the ledger
  bucket and separate trusted identities need separate review.
- The boot image must be a pinned stock Ubuntu 24.04 image id (supplied by the
  lead, not a family), with required guest tools verified in it because the
  VM has no internet access.
- Three-slot allocation is intentionally absent; the counter would need its
  own race tests first.
