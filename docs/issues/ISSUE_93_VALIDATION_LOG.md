# Issue #93 – Validation Run Log

This log tracks the post-PR #91 validation cycle requested in Issue #93.

## Timeline

| Timestamp (UTC) | Event |
| --- | --- |
| 2025-11-20 22:00 | Builder launch `build-20251120-220013` failed (SSD quota exceeded while `hedgehog-lab-validation-20251120` disk consumed 350 GB). |
| 2025-11-20 22:01 | Deleted stale validation VM/disk to free quota and relaunched builder as `build-20251120-220126` (branch `feature/93-validation-run`, commit `aeac1f264748ac5f8741f4c6acae25f651665b59`). |
| 2025-11-21 00:15 | Builder `build-20251120-233951` aborted: packer couldn't SSH because `hhlab` password in installed OS didn't match (autoinstall late-command patched afterwards). |
| 2025-11-21 00:40 | Builder `build-20251121-004009` running with updated password reset logic; monitoring until OVA exports. |
| _TBD_ | Builder completed, artifacts uploaded to `gs://hedgehog-lab-artifacts-teched-473722/releases/`. |
| _TBD_ | Image import + validation VM creation. |
| _TBD_ | hh-lab setup + orchestration results. |

## Build Metadata (Pending)
- **Build ID:** build-20251120-220126
- **GCP Instance:** labapp-builder-build-20251120-220126 (us-west1-b)
- **Machine Type:** n2-standard-32 (nested virt)
- **Disk:** 400 GB pd-ssd
- **Branch:** feature/93-validation-run
- **Commit:** `aeac1f264748ac5f8741f4c6acae25f651665b59`
- **OVA Output:** _TBD_
- **Checksum:** _TBD_

## Image Import Checklist (Pending)
1. Download OVA from GCS.
2. Extract VMDK and convert to RAW (`qemu-img convert`).
3. Package `disk.raw` into tarball and upload to `gs://hedgehog-lab-artifacts-teched-473722/images/`.
4. Create custom image with nested virt + UEFI guest features.
5. Launch validation VM (`hedgehog-lab-validation-20251120`) with `--enable-nested-virtualization`, `--shielded-secure-boot`, and Cascade Lake minimum CPU.

_Status updates will be filled in as the run progresses._
