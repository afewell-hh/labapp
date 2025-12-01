# Artifact Upload Guide

This guide explains how to upload pre-warmed build artifacts to AWS S3 storage.

## Overview

Pre-warmed build artifacts (80-100GB OVA files) are too large for GitHub storage and are instead uploaded to AWS S3. See [ADR-004](../adr/004-aws-s3-artifact-storage.md) for the complete storage architecture decision.

## S3 Bucket Configuration

**Bucket Name:** `hedgehog-lab-artifacts`
**Region:** `us-east-1` (US East - Northern Virginia)
**Encryption:** AES-256 (SSE-S3)
**Versioning:** Enabled
**Public Access:** Read-only for `/releases/*` path

### Directory Structure

```
s3://hedgehog-lab-artifacts/
├── releases/
│   └── v{version}/
│       ├── hedgehog-lab-{build-type}-{version}.ova
│       ├── hedgehog-lab-{build-type}-{version}.ova.sha256
│       └── hedgehog-lab-{build-type}-{version}.metadata.json
└── prewarmed/
    └── events/{event-name}/
        ├── hedgehog-lab-{event}.ova
        ├── hedgehog-lab-{event}.ova.sha256
        └── hedgehog-lab-{event}.metadata.json
```

## Upload Script

The `scripts/upload-to-s3.sh` script handles artifact uploads with the following features:

- **Large file support:** Multipart uploads for 80-100GB files
- **Checksum generation:** Automatic SHA256 checksum creation and verification
- **Metadata creation:** JSON metadata file with download URLs and system requirements
- **Retry logic:** Automatic retry on upload failures (3 attempts)
- **Progress logging:** Real-time upload progress and completion status
- **Integrity verification:** Post-upload verification of file sizes

### Usage

```bash
./scripts/upload-to-s3.sh <ova-file> <version> [event-name]
```

**Arguments:**
- `ova-file` - Path to the OVA file to upload (required)
- `version` - Version number, e.g., "0.2.0" (required)
- `event-name` - Optional event identifier, e.g., "kubecon2026"

**Examples:**

```bash
# Upload standard release
./scripts/upload-to-s3.sh \
  output-hedgehog-lab-prewarmed/hedgehog-lab-prewarmed-0.2.0.ova \
  0.2.0

# Upload event-specific build
./scripts/upload-to-s3.sh \
  hedgehog-lab-prewarmed-0.2.0-kubecon.ova \
  0.2.0 \
  kubecon2026
```

### Required Environment Variables

The script requires AWS credentials to be set:

```bash
export AWS_ACCESS_KEY_ID="<your-key-id>"
export AWS_SECRET_ACCESS_KEY="<your-secret-key>"
export AWS_DEFAULT_REGION="us-east-1"
```

For GitHub Actions, these are stored as secrets:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`

## GitHub Actions Integration

The pre-warmed build workflow (`.github/workflows/build-prewarmed.yml`) automatically uploads artifacts after a successful build.

### Workflow Steps

1. **Build pre-warmed appliance** (60-90 minutes)
2. **Validate build artifacts**
3. **Install AWS CLI**
4. **Upload artifacts to S3** using `upload-to-s3.sh`
5. **Generate release summary** with download URLs

### Triggering Manual Upload

```bash
# Trigger pre-warmed build workflow
gh workflow run build-prewarmed.yml \
  --field version=0.2.0
```

The workflow will automatically:
- Build the pre-warmed OVA
- Generate SHA256 checksum
- Create metadata JSON
- Upload all files to S3
- Display download URLs in the workflow summary

## Download URLs

After upload, artifacts are available at:

```
OVA:
https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v{version}/hedgehog-lab-{build-type}-{version}.ova

Checksum:
https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v{version}/hedgehog-lab-{build-type}-{version}.ova.sha256

Metadata:
https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v{version}/hedgehog-lab-{build-type}-{version}.metadata.json
```

**Example (v0.2.0):**
```
https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova
https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova.sha256
https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.metadata.json
```

## Verifying Downloads

After downloading, verify file integrity:

```bash
# Download OVA and checksum
wget https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova
wget https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova.sha256

# Verify checksum
sha256sum -c hedgehog-lab-prewarmed-0.2.0.ova.sha256
```

Expected output:
```
hedgehog-lab-prewarmed-0.2.0.ova: OK
```

## Metadata JSON Format

The metadata JSON file contains build information:

```json
{
  "version": "0.2.0",
  "build_type": "prewarmed",
  "build_date": "2025-11-06T10:30:00Z",
  "file_size_bytes": 85899345920,
  "file_size_gb": 80.00,
  "sha256": "abc123...",
  "download_url": "https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova",
  "first_boot_time_minutes": 5,
  "system_requirements": {
    "memory_gb": 16,
    "cpu_cores": 8,
    "disk_gb": 100
  }
}
```

For event-specific builds, an additional `event` field is included:

```json
{
  "version": "0.2.0",
  "build_type": "prewarmed",
  "event": "kubecon2026",
  ...
}
```

## Lifecycle Policies

S3 bucket lifecycle policies automatically manage storage costs:

- **After 30 days:** Transition to Standard-IA (68% cost reduction)
- **After 90 days:** Delete non-current versions (from versioning)

Event-specific builds should be manually deleted after the workshop completes.

## Cost Optimization

**Monthly Costs (estimated):**
- Storage (3 versions): ~$6-9/month
- Transfer (30 downloads/month): ~$200-250/month
- **Total:** ~$210-260/month

**Cost Reduction Strategies:**
1. Use CloudFront CDN for high-traffic releases (~50% transfer cost reduction)
2. Delete event builds after completion
3. Limit number of versions retained

See [ADR-004](../adr/004-aws-s3-artifact-storage.md) for complete cost analysis.

## Troubleshooting

### Upload Fails with Access Denied

**Problem:** AWS credentials are invalid or lack necessary permissions

**Solution:** Verify IAM policy includes all required S3 actions:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:CreateMultipartUpload",
      "s3:UploadPart",
      "s3:ListMultipartUploadParts",
      "s3:CompleteMultipartUpload",
      "s3:AbortMultipartUpload"
    ],
    "Resource": [
      "arn:aws:s3:::hedgehog-lab-artifacts/*",
      "arn:aws:s3:::hedgehog-lab-artifacts"
    ]
  }]
}
```

### Upload Hangs or Times Out

**Problem:** Large file uploads can take 30-60 minutes for 80-100GB files

**Solution:**
- Increase timeout in GitHub Actions workflow (default: 35 minutes)
- Check network connectivity
- Use multipart upload (automatic for files >100MB)

### Checksum Verification Fails

**Problem:** Downloaded file is corrupted or incomplete

**Solution:**
1. Re-download the file
2. Compare file sizes (should match exactly)
3. If issue persists, re-upload from source

### Download URL Returns 403 Forbidden

**Problem:** S3 bucket policy does not allow public read

**Solution:** Verify bucket policy allows public GetObject for `/releases/*`:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::hedgehog-lab-artifacts/releases/*"
  }]
}
```

## Manual Upload (Advanced)

For manual uploads outside of CI/CD:

```bash
# Set AWS credentials
export AWS_ACCESS_KEY_ID="<your-key>"
export AWS_SECRET_ACCESS_KEY="<your-secret>"
export AWS_DEFAULT_REGION="us-east-1"

# Upload using script
cd /path/to/labapp
./scripts/upload-to-s3.sh \
  /path/to/hedgehog-lab-prewarmed-0.2.0.ova \
  0.2.0
```

## Security Considerations

1. **Public Access:** Only `/releases/*` path is publicly accessible
2. **Encryption:** All objects encrypted at rest (SSE-S3 AES-256)
3. **Versioning:** Enabled to protect against accidental deletion
4. **Access Logging:** S3 access logs should be enabled for audit
5. **Credentials:** AWS keys stored as GitHub Secrets (encrypted)
6. **IAM Policy:** Least-privilege access for CI/CD

## Related Documentation

- [ADR-004: AWS S3 Artifact Storage](../adr/004-aws-s3-artifact-storage.md) - Storage architecture decision
- [ADR-001: Dual Build Pipeline](../adr/001-dual-build-pipeline.md) - Pre-warmed vs standard builds
- [Build Guide](BUILD_GUIDE.md) - Complete build instructions

---

**Last Updated:** November 6, 2025
**Status:** Active
