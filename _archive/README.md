# Archived Content

This directory contains legacy files that are no longer part of the active project but are preserved for historical reference.

## Archive Date
2025-12-01

## Reason for Archive
The project pivoted from OVA-based distribution to a BYO Ubuntu VM installer (Issue #97). Additionally, the primary build infrastructure shifted from AWS metal instances to GCP VMs with nested virtualization.

## Contents

### aws-metal-build/
Legacy AWS EC2 metal instance build infrastructure. Superseded by GCP builder (see `scripts/launch-gcp-build.sh`).

**Contains:**
- `terraform/metal-build/` - Terraform for c5n.metal instances, DynamoDB state, Lambda watchdog
- `lambda/metal-build-watchdog/` - Lambda function to terminate stale build instances
- `scripts/` - Build launcher and user-data scripts
- `docs/` - AWS_METAL_BUILD.md, ADR-005

**Why archived:** GCP n2-standard-32 with nested virtualization is now the primary builder. AWS metal builds are no longer needed.

### ova-legacy/
OVA-specific build components (pre-warmed variant). The project now distributes a BYO VM installer instead of OVA files.

**Contains:**
- `packer/prewarmed-build.pkr.hcl` - Pre-warmed OVA template (blocked pending Issues #73-75)
- `packer/create-ova.sh` - VMDK to OVA conversion script
- `workflows/build-prewarmed.yml` - GitHub Actions for pre-warmed builds

**Why archived:** Issue #97 established BYO Ubuntu VM installer as the primary distribution method.

### ova-build/
Complete OVA build infrastructure including standard Packer template, GCP builder, and related documentation.

**Contains:**
- `packer/standard-build.pkr.hcl` - Standard OVA Packer template
- `packer/README.md` - Packer build documentation
- `scripts/launch-gcp-build.sh` - GCP VM launcher for OVA builds
- `scripts/upload-to-s3.sh` - S3 OVA artifact upload script
- `.github/workflows/build-standard.yml` - GitHub Actions workflow for OVA builds
- `docs/build/BUILD_GUIDE.md` - Complete OVA build guide
- `docs/build/GCP_BUILDER.md` - GCP nested virtualization builder documentation
- `docs/DOWNLOADS.md` - OVA download and verification guide
- `docs/adr/001-dual-build-pipeline.md` - ADR for dual OVA pipeline strategy
- `.env.gcp.example` - GCP builder environment template
- `tests/unit/test-gcp-build-script.sh` - GCP build script tests
- `tests/unit/test-publish-to-gcs.sh` - GCS publish script tests
- `tests/unit/test-desktop-services.sh` - Desktop services tests (references OVA templates)
- `docs/build/ARTIFACT_UPLOAD.md` - S3 artifact upload guide for OVA files
- `docs/build/COST_MANAGEMENT.md` - AWS metal build cost analysis
- `docs/adr/003-performance-optimizations.md` - OVA build performance ADR
- `docs/adr/004-aws-s3-artifact-storage.md` - S3 storage for OVA artifacts ADR

**Why archived:** Issue #97 established BYO Ubuntu VM installer as the primary distribution method. OVA building is no longer the project's focus.

### placeholder-directories/
Empty or minimal directories that were created as placeholders but never developed.

**Contains:**
- `hh-azure/` - Empty Azure placeholder
- `hh-aws/` - Single GCP config file (misplaced)
- `hh-gcp/` - Single GCP config file (duplicate)
- `hhfab-cambium-fe/` - Incomplete fab.yaml test

**Why archived:** No active content, not referenced by any code.

## Restoration

If any of these files are needed again:

```bash
# Restore AWS metal build
mv _archive/aws-metal-build/terraform/metal-build terraform/
mv _archive/aws-metal-build/lambda/metal-build-watchdog lambda/
mv _archive/aws-metal-build/scripts/* scripts/
mv _archive/aws-metal-build/docs/AWS_METAL_BUILD.md docs/build/
mv _archive/aws-metal-build/docs/005-aws-metal-build-system.md docs/adr/

# Restore OVA legacy (pre-warmed) components
mv _archive/ova-legacy/packer/prewarmed-build.pkr.hcl packer/
mv _archive/ova-legacy/packer/create-ova.sh packer/scripts/
mv _archive/ova-legacy/workflows/build-prewarmed.yml .github/workflows/

# Restore OVA build infrastructure
mv _archive/ova-build/packer/standard-build.pkr.hcl packer/
mv _archive/ova-build/packer/README.md packer/
mv _archive/ova-build/scripts/launch-gcp-build.sh scripts/
mv _archive/ova-build/.github/workflows/build-standard.yml .github/workflows/
mv _archive/ova-build/docs/build/BUILD_GUIDE.md docs/build/
mv _archive/ova-build/docs/build/GCP_BUILDER.md docs/build/
mv _archive/ova-build/docs/DOWNLOADS.md docs/
mv _archive/ova-build/docs/adr/001-dual-build-pipeline.md docs/adr/
```

## Related Issues
- Issue #97 - BYO VM Installer approach
- Issue #75 - GCP Builder implementation
- Issue #103 - Sprint 1 Epic (foundation cleanup)
- Issue #106 - Archive legacy OVA-related content
