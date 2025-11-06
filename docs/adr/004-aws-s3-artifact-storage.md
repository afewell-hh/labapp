# ADR-004: AWS S3 for Pre-Warmed Artifact Storage

**Status:** Accepted
**Date:** 2025-11-05
**Deciders:** Project Lead, Engineering Team
**Technical Story:** Issue #47, Issue #42 (storage constraints)

---

## Context

The Hedgehog Lab Appliance v0.2.0 introduces pre-warmed builds that are fully initialized during the Packer build process. These builds produce OVA files sized 80-100GB (compressed), which exceed the storage capabilities of our current infrastructure:

### Storage Constraints Identified

1. **GitHub Releases:** 2GB file size limit per artifact
2. **GitHub Actions Artifacts:** Retention limits and cost prohibitive for 80-100GB files
3. **Local Development Environment:** Limited disk capacity for build artifacts
4. **Git LFS:** Not suitable for 80-100GB files, expensive, slow

### Use Cases Requiring Storage

1. **Release Distribution:** Public downloads of pre-warmed builds for workshops
2. **Event-Specific Builds:** Custom builds for conferences (e.g., KubeCon 2026)
3. **CI/CD Integration:** Automated upload from GitHub Actions workflows
4. **Version Management:** Maintain multiple versions with rollback capability

### Requirements

- Store files 80-100GB in size
- Public download access with checksum verification
- Authenticated upload from CI/CD
- Cost-effective for moderate usage (10-50 downloads/month)
- Reliable with 99.9%+ uptime
- Support for multiple versions
- Integration with existing GitHub Actions workflows

---

## Decision

We will use **AWS S3 (Simple Storage Service)** as the primary storage and distribution platform for pre-warmed build artifacts.

### S3 Bucket Configuration

**Bucket Name:** `hedgehog-lab-artifacts`
**Region:** `us-east-1` (US East - Northern Virginia)
**Access:** Public read for downloads, authenticated write for uploads
**Versioning:** Enabled
**Encryption:** AES-256 (SSE-S3)

### Directory Structure

```
s3://hedgehog-lab-artifacts/
├── releases/
│   ├── v0.1.0/
│   │   ├── hedgehog-lab-standard-0.1.0.ova
│   │   └── hedgehog-lab-standard-0.1.0.ova.sha256
│   └── v0.2.0/
│       ├── hedgehog-lab-standard-0.2.0.ova
│       ├── hedgehog-lab-standard-0.2.0.ova.sha256
│       ├── hedgehog-lab-prewarmed-0.2.0.ova
│       ├── hedgehog-lab-prewarmed-0.2.0.ova.sha256
│       └── hedgehog-lab-prewarmed-0.2.0.metadata.json
└── prewarmed/
    └── events/
        └── {event-name}/
            ├── hedgehog-lab-{event}.ova
            ├── hedgehog-lab-{event}.ova.sha256
            └── hedgehog-lab-{event}.metadata.json
```

### Naming Convention

**Format:** `hedgehog-lab-{build-type}-{version}[-{event}].{ext}`

**Examples:**
- `hedgehog-lab-standard-0.2.0.ova`
- `hedgehog-lab-prewarmed-0.2.0.ova`
- `hedgehog-lab-prewarmed-0.2.0-kubecon2026.ova`

### Lifecycle Policy

- **Versioning:** Keep all versions (S3 versioning enabled)
- **Transition to Standard-IA:** After 30 days (68% cost reduction)
- **Delete noncurrent versions:** After 90 days
- **Event builds:** Manual deletion after workshop completion

### Access Control

**Public Read Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::hedgehog-lab-artifacts/releases/*"
    }
  ]
}
```

**GitHub Actions IAM Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
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
    }
  ]
}
```

---

## Consequences

### Positive

1. **Solves Storage Problem:** Can store unlimited 80-100GB files
2. **Cost-Effective:** ~$20-30/month for moderate usage
3. **Industry Standard:** Well-documented, reliable, mature platform
4. **Scalability:** Handles traffic spikes (conferences, courses)
5. **Integration:** Easy GitHub Actions integration via AWS SDK
6. **Versioning:** Built-in version management and rollback
7. **Global Distribution:** Can add CloudFront CDN if needed
8. **Existing Resources:** AWS credentials already available
9. **Public Downloads:** Direct HTTPS URLs for users
10. **Checksum Verification:** Store .sha256 files alongside OVAs

### Negative

1. **Ongoing Cost:** Monthly AWS bill (~$20-30/month)
2. **Vendor Lock-in:** Moderate (migration possible but effort-intensive)
3. **Transfer Costs:** $0.09/GB after first 100GB/month
4. **Complexity:** Additional infrastructure to manage
5. **Regional Latency:** US East may be slower for international users

### Neutral

1. **Authentication:** Need AWS credentials in GitHub Actions (already available)
2. **Monitoring:** Should track storage costs and usage
3. **Documentation:** Need to document download URLs and procedures

---

## Cost Analysis

### Monthly Storage Costs

**S3 Standard Pricing (us-east-1):**
- First 50TB: $0.023/GB/month
- Pre-warmed build: 80-100GB ≈ $1.84-2.30/month
- Keep 3 versions: ~$6-9/month

**S3 Standard-IA (after 30 days):**
- $0.0125/GB/month (68% cheaper)
- Pre-warmed build: 80-100GB ≈ $1-1.25/month
- Keep 3 versions: ~$3-4.50/month

### Monthly Transfer Costs

**Data Transfer Out:**
- First 100GB/month: $0.09/GB
- 10 downloads/month (80GB each) = 800GB = ~$63/month
- 50 downloads/month = 4TB = ~$360/month

**Realistic Usage:**
- Development/testing: 5-10 downloads/month = ~$40-70/month
- Post-release: 20-50 downloads/month = ~$150-400/month
- Workshop events: Spike to 100+ downloads = ~$800/month (temporary)

### Optimization Strategies

1. **CloudFront CDN:** Reduce transfer costs by 40-60%
2. **Regional mirrors:** Use S3 buckets in multiple regions
3. **Torrent distribution:** For high-demand releases
4. **Lifecycle policies:** Transition to Standard-IA after 30 days
5. **Event cleanup:** Delete event-specific builds after completion

### Estimated Monthly Cost

**Conservative (10 downloads/month):**
- Storage: $6-9/month
- Transfer: $40-70/month
- **Total: $50-80/month**

**Moderate (30 downloads/month):**
- Storage: $6-9/month
- Transfer: $200-250/month
- **Total: $210-260/month**

**With CloudFront optimization:**
- Reduce transfer costs by ~50%
- **Moderate usage: $110-140/month**

---

## Alternatives Considered

### Alternative 1: GitHub Releases Only
**Rejected:** 2GB file size limit makes this impossible for pre-warmed builds (80-100GB).

### Alternative 2: Git LFS (Large File Storage)
**Rejected:**
- Not designed for 80-100GB files
- Expensive ($5/50GB/month storage + $5/50GB bandwidth)
- 80GB would cost ~$8 storage + $8 per download
- Slow for large files

### Alternative 3: Google Cloud Storage
**Rejected:**
- No existing credentials
- Similar pricing to S3
- Less familiar to team
- Would require new account setup

### Alternative 4: Azure Blob Storage
**Rejected:**
- No existing credentials
- Similar pricing to S3
- Less familiar to team
- Would require new account setup

### Alternative 5: Self-Hosted Storage Server
**Rejected:**
- High upfront cost (hardware)
- Maintenance burden
- Bandwidth limitations
- Reliability concerns
- No redundancy

### Alternative 6: CDN-Only Solution (Cloudflare R2, Bunny CDN)
**Deferred:**
- Could be reconsidered if transfer costs become prohibitive
- R2 has no egress fees (appealing)
- Bunny CDN has lower costs
- But less mature, less familiar

---

## Implementation Notes

### Phase 1: Basic S3 Setup (Issue #48)
1. Create S3 bucket: `hedgehog-lab-artifacts`
2. Configure bucket policies (public read, authenticated write)
3. Enable versioning and encryption
4. Set up lifecycle policies

### Phase 2: GitHub Actions Integration (Issue #48)
1. Store AWS credentials in GitHub Secrets
2. Create upload script using AWS CLI or SDK
3. Integrate with pre-warmed build workflow
4. Generate checksums and metadata files

### Phase 3: Documentation (Issue #49)
1. Document download URLs
2. Create verification instructions
3. Update release process
4. Add troubleshooting guide

### Phase 4: Optimization (Future)
1. Add CloudFront CDN if transfer costs high
2. Implement regional mirrors if needed
3. Consider torrent distribution for popular releases

---

## Monitoring & Alerts

**Metrics to Track:**
- Storage usage (GB)
- Download count
- Transfer bandwidth (GB/month)
- Monthly costs
- Error rates

**Alerts:**
- Monthly cost exceeds $200 (review needed)
- Storage exceeds 500GB (cleanup needed)
- Transfer exceeds 5TB/month (CDN recommended)

---

## Security Considerations

1. **Public Access:** Only /releases/* path is public
2. **Encryption:** All objects encrypted at rest (SSE-S3)
3. **Access Logging:** Enable S3 access logs for audit
4. **Credentials:** AWS keys stored in GitHub Secrets (encrypted)
5. **IAM Policy:** Least-privilege access for GitHub Actions
6. **Versioning:** Protects against accidental deletion

---

## Rollback Plan

If S3 proves unsuitable:
1. Export all artifacts using `aws s3 sync`
2. Migrate to alternative storage (GCS, Azure, self-hosted)
3. Update download URLs in documentation
4. Maintain S3 redirect for old URLs (if possible)

**Estimated Migration Effort:** 1-2 weeks

---

## Success Metrics

- ✅ Pre-warmed builds successfully stored and retrievable
- ✅ Public downloads work from documented URLs
- ✅ Checksum verification works
- ✅ GitHub Actions upload automation works
- ✅ Monthly costs within budget ($50-100/month initially)
- ✅ 99.9%+ uptime for downloads
- ✅ Download speeds acceptable (>10MB/s for most users)

---

## Related Decisions

- **ADR-001:** Dual Build Pipeline Strategy (defines pre-warmed builds)
- **ADR-002:** Orchestrator Design (implements build-time initialization)
- **ADR-003:** Performance Optimizations (impacts artifact sizes)

---

## References

- **Issue #42:** Implement build-time VLAB initialization (triggered storage discussion)
- **Issue #47:** Design artifact storage strategy (this ADR)
- **Issue #48:** Implement artifact upload automation
- **Issue #49:** Create download portal documentation
- **AWS S3 Pricing:** https://aws.amazon.com/s3/pricing/
- **AWS S3 Documentation:** https://docs.aws.amazon.com/s3/

---

**Last Updated:** November 5, 2025
**Status:** Accepted and ready for implementation
