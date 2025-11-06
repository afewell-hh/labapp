# ADR-005: AWS Metal Instance Build System for Pre-Warmed OVAs

**Status:** Accepted
**Date:** 2025-11-06
**Deciders:** Project Lead, Engineering Team
**Technical Story:** Issue #57

## Context

Pre-warmed builds (defined in ADR-001) require:
- **Disk space:** 200-300GB during build process
- **Compute:** Nested virtualization (KVM) support
- **Time:** 60-90 minute build duration
- **Cost:** ~$15-20 per build on AWS metal instances

Current development system has only 30GB available disk space, making local pre-warmed builds impossible. GitHub-hosted runners lack nested virtualization support and have resource constraints (14GB disk, no KVM).

AWS bare metal instances (c5n.metal, m5zn.metal) provide the necessary resources but cost $4.32/hour, requiring strict cost and safety controls to prevent runaway expenses.

### Key Requirements

1. **Safety:** Hard 3-hour runtime limit (2x expected build time)
2. **Cost Control:** Budget alerts, automatic termination, cost estimation before launch
3. **Reliability:** Automated cleanup on success or failure
4. **Monitoring:** CloudWatch integration, SNS notifications
5. **Simplicity:** Minimize infrastructure complexity for MVP

## Decision

Implement **Terraform-based infrastructure with shell orchestration** for AWS metal instance builds.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│  Developer / CI Pipeline                                │
│  └─> scripts/launch-metal-build.sh                     │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│  Terraform Infrastructure (terraform/metal-build/)      │
│  ├─ EC2 c5n.metal instance (3 hour max lifetime)       │
│  ├─ 500GB gp3 EBS volume                               │
│  ├─ Security group (SSH from known IPs)                │
│  ├─ IAM instance profile (S3 upload permissions)       │
│  ├─ DynamoDB table (build state tracking)              │
│  ├─ CloudWatch log group                               │
│  └─ Lambda watchdog function (15-min checks)           │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│  Build Execution (on metal instance)                    │
│  └─> user-data: scripts/metal-build-userdata.sh        │
│      ├─ Install Packer, QEMU/KVM                       │
│      ├─ Clone labapp repo                              │
│      ├─ Execute: packer build prewarmed-build.pkr.hcl  │
│      ├─ Upload to S3: scripts/upload-to-s3.sh          │
│      └─> Signal completion → Terraform destroy         │
└─────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│  Watchdog Lambda (EventBridge: every 15 minutes)        │
│  └─> Terminates instances >3 hours old with tag:       │
│      AutoDelete=true, Project=labapp                    │
└─────────────────────────────────────────────────────────┘
```

### Why Terraform + Shell (Not Step Functions)?

**Chosen Approach Benefits:**
- ✅ **Simpler:** Infrastructure as code, familiar patterns
- ✅ **Faster to implement:** Reuse existing bash scripts
- ✅ **Lower cost:** No Step Functions execution fees
- ✅ **Easier debugging:** SSH access to instance
- ✅ **MVP-appropriate:** Balances safety with simplicity

**Step Functions Approach (Deferred):**
- ⏸️ Better for production at scale
- ⏸️ Better orchestration and retries
- ⏸️ More complex to implement and test
- ⏸️ Consider for v0.3.0+ if builds become frequent

## Components

### 1. Terraform Infrastructure (`terraform/metal-build/`)

**Resources:**
- EC2 instance (c5n.metal or m5zn.metal)
- EBS gp3 volume (500GB)
- Security group (SSH access only)
- IAM role and instance profile
- DynamoDB table for state tracking
- CloudWatch log group
- Lambda watchdog function
- EventBridge rule (15-minute trigger)
- SNS topic for notifications

**Tagging Strategy:**
```hcl
tags = {
  Project     = "labapp"
  Purpose     = "prewarmed-build"
  BuildID     = "${var.build_id}"
  AutoDelete  = "true"
  CostCenter  = "development"
  MaxLifetime = "3hours"
}
```

### 2. Build Launcher Script (`scripts/launch-metal-build.sh`)

**Responsibilities:**
- Pre-flight checks (no existing builds, budget availability)
- Cost estimation and user confirmation
- Generate unique build ID
- Execute Terraform apply
- Monitor build progress
- Execute Terraform destroy on completion

**Safety Controls:**
- Check for existing builds (via DynamoDB)
- Estimate cost before launch (~$15-20)
- Require manual confirmation for production
- Timeout after 3.5 hours (includes cleanup time)
- Log all actions to CloudWatch

### 3. User Data Script (`scripts/metal-build-userdata.sh`)

**Execution Flow:**
```bash
#!/bin/bash
set -euo pipefail

1. System setup
   - Update packages
   - Install dependencies (packer, qemu-kvm, awscli)
   - Enable nested virtualization

2. Repository setup
   - Clone labapp repo
   - Checkout specified branch/tag

3. Build execution
   - Run: packer build packer/prewarmed-build.pkr.hcl
   - Stream logs to CloudWatch
   - Monitor disk usage

4. Artifact upload
   - Upload OVA to S3: s3://hedgehog-lab-artifacts/prewarmed/
   - Upload checksums and metadata
   - Verify upload integrity

5. Completion signaling
   - Update DynamoDB with success status
   - Create completion marker file
   - Exit (triggers Terraform destroy)
```

**Error Handling:**
- Trap all errors
- Update DynamoDB with failure status
- Upload partial logs to S3
- Exit with error code (triggers cleanup)

### 4. Watchdog Lambda (`lambda/metal-build-watchdog/`)

**Purpose:** External safety mechanism to terminate runaway instances

**Execution:**
- Triggered every 15 minutes via EventBridge
- Scans all EC2 instances with tags:
  - `Project=labapp`
  - `AutoDelete=true`
- Calculates instance age from launch time
- If age > 3 hours:
  - Force terminate instance
  - Delete associated EBS volumes
  - Update DynamoDB with force-termination status
  - Send SNS alert

**Runtime:** Python 3.12, 128MB memory, 60s timeout

### 5. State Tracking (DynamoDB)

**Table:** `labapp-metal-builds`

**Schema:**
```
BuildID (partition key) | string
Status                  | string  (launching, building, uploading, completed, failed, terminated)
InstanceID              | string
LaunchTime              | string  (ISO 8601)
CompletionTime          | string  (ISO 8601)
CostEstimate            | number  (USD)
BuildBranch             | string
BuildCommit             | string
ErrorMessage            | string  (if failed)
ForcedTermination       | boolean
```

**Purpose:**
- Prevent concurrent builds
- Track active instances for watchdog
- Audit trail for costs and failures
- Build history for analysis

### 6. Monitoring and Alerts

**CloudWatch Metrics:**
- Build duration (custom metric)
- Disk usage during build
- Network transfer volume
- Build success/failure rate

**SNS Notifications:**
- Build started (info)
- Build completed successfully (success)
- Build failed (warning)
- Instance force-terminated (critical)
- Cost estimate >$25 (warning)

**Email Subscription:** Configured via Terraform variable

## Cost Analysis

### Per-Build Cost Breakdown

**c5n.metal (us-east-1):**
- Instance: $4.32/hour
- EBS gp3 500GB: $0.08/hour ($40/month prorated)
- Data transfer to S3: $0.09/GB
- DynamoDB: <$0.01 (free tier)
- Lambda: <$0.01 (free tier)

**Normal Build (1.5 hours):**
- Instance: $6.48
- EBS: $0.12
- Transfer (100GB): $9.00
- **Total: ~$15.60**

**Max Timeout (3 hours):**
- Instance: $12.96
- EBS: $0.24
- Transfer: $9.00
- **Total: ~$22.20 (safety margin)**

### Monthly Cost Estimates

**Development Phase (2 builds/week):**
- Builds: 8/month × $15.60 = $124.80
- Watchdog Lambda: <$1 (free tier likely)
- DynamoDB: <$1 (free tier)
- **Total: ~$127/month**

**Production (1 build/month):**
- Build: $15.60
- Infrastructure: $2
- **Total: ~$18/month**

### Cost Controls

1. **Budget Alert:** AWS Budget with $50/month threshold
2. **Hard Limits:** 3-hour instance lifetime (enforced by watchdog)
3. **Cost Estimation:** Display before every launch
4. **Manual Confirmation:** Required for production builds
5. **Automatic Cleanup:** Terraform destroy on completion
6. **Orphan Detection:** Watchdog scans for AutoDelete tags

## Security Considerations

### Access Control
- **IAM Role:** Least privilege (S3 upload, DynamoDB write, CloudWatch logs)
- **Security Group:** SSH from known IPs only (configurable CIDR)
- **No SSH keys in code:** Use AWS Session Manager or temporary keys
- **S3 bucket:** Private with versioning enabled

### Secrets Management
- AWS credentials from GitHub Secrets or .env (not hardcoded)
- No secrets in Terraform state (use data sources)
- No secrets in user-data (use IAM roles)
- CloudTrail enabled for audit

### Instance Security
- Latest Ubuntu 22.04 LTS AMI
- Automatic security updates enabled
- No public Docker images (build from source)
- Clean instance (no persistent SSH access post-build)

## Implementation Phases

### Phase 1: Core Infrastructure (Week 1)
- ✅ Create Terraform modules
- ✅ Implement launcher script
- ✅ Create user-data script
- ✅ Deploy DynamoDB table
- ✅ Test infrastructure provisioning

### Phase 2: Safety Controls (Week 1)
- ✅ Implement watchdog Lambda
- ✅ Configure CloudWatch alarms
- ✅ Set up SNS notifications
- ✅ Test forced termination

### Phase 3: Integration (Week 2)
- ✅ Integrate with existing upload-to-s3.sh
- ✅ Test end-to-end build
- ✅ Verify S3 artifact upload
- ✅ Test failure scenarios

### Phase 4: Documentation (Week 2)
- ✅ Create AWS_METAL_BUILD.md user guide
- ✅ Create COST_MANAGEMENT.md
- ✅ Update BUILD_GUIDE.md
- ✅ Create troubleshooting runbook

## Testing Strategy

### Test 1: Normal Build
1. Launch build with `launch-metal-build.sh`
2. Monitor CloudWatch logs
3. Verify build completes in ~90 minutes
4. Confirm OVA uploaded to S3
5. Verify Terraform destroy completes
6. Check DynamoDB for success status

### Test 2: Timeout Scenario
1. Modify user-data to include `sleep 12000` (3+ hours)
2. Launch build
3. Verify watchdog terminates instance at 3-hour mark
4. Confirm SNS notification sent
5. Check cleanup completion

### Test 3: Build Failure
1. Modify Packer template to introduce error
2. Launch build
3. Verify error handling in user-data
4. Confirm partial logs uploaded to S3
5. Verify cleanup and DynamoDB failure status

### Test 4: Concurrent Build Prevention
1. Launch first build
2. Attempt to launch second build
3. Verify pre-flight check blocks second build
4. Confirm DynamoDB state check works

## Acceptance Criteria Mapping

- [✅] Terraform infrastructure created and tested
- [✅] Watchdog Lambda deployed and verified
- [✅] CloudWatch alarms configured
- [✅] SNS notifications working
- [✅] DynamoDB state table created
- [✅] S3 bucket configured (reuses existing from ADR-004)
- [✅] Successful test build on c5n.metal
- [✅] Force termination tested
- [✅] Cost tracking verified (<$20 per build)
- [✅] Documentation created in docs/build/
- [✅] All resources tagged appropriately
- [✅] Cleanup verified (no orphaned resources)

## Consequences

### Positive
- **Safe:** Multiple layers of protection prevent runaway costs
- **Automated:** One-command build launches
- **Monitored:** Full visibility into build progress and costs
- **Reusable:** Infrastructure persists, instances are ephemeral
- **Cost-effective:** Pay only for actual build time (~$15-20)
- **Flexible:** Can adjust instance type, disk size, timeouts

### Negative
- **AWS-specific:** Requires AWS account and permissions
- **Setup overhead:** Initial Terraform deployment needed
- **Region-locked:** Resources in specific region (us-east-1)
- **Manual trigger:** Not fully integrated into CI/CD (yet)

### Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Runaway instance costs | High | Watchdog Lambda, 3-hour hard limit, budget alerts |
| Build failures | Medium | Comprehensive error handling, partial log uploads |
| Concurrent builds | Medium | DynamoDB state locking, pre-flight checks |
| Orphaned resources | Low | AutoDelete tags, watchdog scanning, Terraform state |
| Security breach | High | IAM least privilege, security groups, no hardcoded secrets |

## Alternatives Considered

### Alternative 1: GitHub Actions Self-Hosted Runner
**Pros:** Integrated with existing workflows
**Cons:** Complex setup, Actions timeout limits, runner management overhead
**Decision:** Rejected - too complex for MVP

### Alternative 2: AWS Step Functions (Recommended in Issue)
**Pros:** Native orchestration, built-in retries, timeout management
**Cons:** More complex, higher cost, longer development time
**Decision:** Deferred to v0.3.0+ - over-engineered for current needs

### Alternative 3: Manual EC2 Launch + Scripts
**Pros:** Simplest possible approach
**Cons:** No infrastructure as code, manual cleanup, error-prone
**Decision:** Rejected - lacks safety controls

### Alternative 4: Local Build with External Disk
**Pros:** No cloud costs
**Cons:** Requires 500GB external drive, slow, not repeatable
**Decision:** Rejected - doesn't scale, blocks issue #45

## Migration Path to Step Functions (Future)

If builds become frequent (>10/month), consider migrating to Step Functions:

```
Step Functions Workflow:
├─ Pre-flight Lambda (checks, validation)
├─ Launch Instance Lambda (Terraform/EC2 API)
├─ Wait for Build (poll SSM/CloudWatch)
├─ Upload Artifacts Lambda (verify S3)
├─ Cleanup Lambda (Terraform destroy)
└─ Error Handler Lambda (force cleanup)
```

**Benefits at scale:**
- Better retry logic
- Easier monitoring
- Event-driven (vs polling)
- Built-in error handling

**Migration effort:** ~8 story points (convert bash to Lambda functions)

## Related Decisions

- ADR-001: Dual Build Pipeline Strategy (pre-warmed builds rationale)
- ADR-004: AWS S3 Artifact Storage (S3 bucket configuration)
- Issue #45: Test pre-warmed build end-to-end (consumer of this infrastructure)
- Issue #38: Pre-Warmed Build Pipeline (parent epic)

## References

- Terraform AWS Provider: https://registry.terraform.io/providers/hashicorp/aws/
- AWS c5n.metal pricing: https://aws.amazon.com/ec2/pricing/
- Packer builders: https://www.packer.io/docs/builders
- Issue #57: Full requirements and acceptance criteria
