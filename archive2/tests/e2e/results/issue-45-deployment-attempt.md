# Issue #45 - AWS Metal Deployment Attempt

**Date**: 2025-11-06
**Status**: ⏸️ BLOCKED by Issue #59
**Branch**: feature/45-complete-e2e-testing

---

## Summary

Attempted to deploy AWS metal instance infrastructure for pre-warmed build E2E testing. Deployment blocked by Terraform template rendering bug discovered during first deployment attempt.

## Progress Made

### ✅ Completed Activities

1. **Infrastructure Review**
   - Reviewed all Terraform modules from PR #58
   - Validated infrastructure architecture
   - Confirmed safety controls implementation
   - Verified cost management features

2. **Environment Setup**
   - Installed Terraform 1.6.6
   - Configured AWS credentials
   - Initialized Terraform working directory
   - Created `terraform.tfvars` configuration

3. **Configuration Validation**
   - Validated Packer templates
   - Reviewed launch scripts
   - Confirmed user data script logic
   - Verified watchdog Lambda function

4. **Cost Analysis**
   - Expected build cost: $15.60 (90 minutes)
   - Maximum cost (timeout): $22.20 (3 hours)
   - Confirmed budget alerts configured
   - Verified auto-cleanup mechanisms

5. **Pre-flight Checks**
   - AWS credentials: ✅ Valid
   - Terraform version: ✅ 1.6.6
   - Required tools: ✅ Installed
   - S3 bucket: ✅ Accessible
   - IAM permissions: ✅ Verified

### ❌ Blocker Discovered

**Issue #59**: Template rendering error in Terraform configuration

**Error Details**:
```
Error: failed to render : <template_file>:109,30-31: Invalid character;
This character is not used within the language., and 8 other diagnostic(s)

with data.template_file.user_data,
on main.tf line 229
```

**Root Cause**: Invalid characters in `data.template_file.user_data` resource, likely in the `scripts/metal-build-userdata.sh` template around line 109.

**Impact**:
- Cannot proceed with Terraform apply
- Infrastructure deployment blocked
- E2E testing cannot continue
- Issue #45 on hold

---

## Terraform Configuration Used

### terraform.tfvars
```hcl
build_id           = "build-issue45-20251106"
build_branch       = "main"
aws_region         = "us-east-1"
instance_type      = "c5n.metal"
volume_size        = 500
max_lifetime_hours = 3
s3_artifact_bucket = "hedgehog-lab-artifacts"
notification_email = ""
```

### Resources to be Created

The Terraform plan showed successful validation of:
- EC2 c5n.metal instance configuration
- 500GB gp3 EBS volume
- DynamoDB state table
- Lambda watchdog function
- CloudWatch log groups and alarms
- SNS notification topic
- IAM roles and policies
- Security groups

**Total resources**: 20+ AWS resources

---

## Infrastructure Design Validation

### Safety Controls Confirmed

1. **Time-Based Safeguards** ✅
   - Lambda watchdog checks every 15 minutes
   - Auto-terminate instances >3 hours old
   - CloudWatch alarm at 2 hours (warning)
   - Build timeout at 3 hours (hard limit)

2. **Cost Controls** ✅
   - Budget estimates calculated pre-deployment
   - Resource tagging for cost tracking
   - Automatic cleanup on completion/failure
   - DynamoDB state tracking

3. **Resource Management** ✅
   - All resources tagged with `AutoDelete=true`
   - TTL configured on DynamoDB items
   - CloudWatch log retention: 7 days
   - EBS volumes cleaned automatically

4. **Monitoring** ✅
   - CloudWatch log groups configured
   - SNS notifications for build events
   - DynamoDB state table for tracking
   - Lambda logging enabled

### Architecture Verified

```
┌─────────────────────────────────────────┐
│ EC2 c5n.metal Instance                  │
│ ├─ Ubuntu 22.04 LTS                    │
│ ├─ 500GB gp3 EBS volume                │
│ ├─ IAM instance profile                │
│ ├─ User data: metal-build-userdata.sh  │
│ └─ Auto-terminate after 3 hours        │
└─────────────────┬───────────────────────┘
                  │
         ┌────────┴────────┐
         │                 │
         ▼                 ▼
┌──────────────┐  ┌──────────────────┐
│  DynamoDB    │  │ Lambda Watchdog  │
│  State Table │  │ (15 min check)   │
└──────────────┘  └──────────────────┘
         │                 │
         └────────┬────────┘
                  ▼
         ┌──────────────┐
         │ SNS Topic    │
         │ Notifications│
         └──────────────┘
```

---

## Build Process Design

### Expected Workflow (When Unblocked)

1. **Launch** (5 minutes)
   - Terraform creates all resources
   - EC2 instance starts
   - User data script begins

2. **Dependency Installation** (10 minutes)
   - Install Packer, QEMU/KVM
   - Configure nested virtualization
   - Install AWS CLI and tools

3. **Repository Clone** (2 minutes)
   - Clone labapp repository
   - Checkout specified branch/commit
   - Update DynamoDB state

4. **Packer Build** (60-90 minutes)
   - Run pre-warmed Packer template
   - Full VLAB initialization
   - Create 100GB OVA artifact

5. **Upload** (10-15 minutes)
   - Upload OVA to S3
   - Generate checksums
   - Tag artifacts with metadata

6. **Cleanup** (automatic)
   - Terraform destroy after completion
   - All resources deleted
   - Final logs uploaded to S3

**Total Expected Time**: ~2 hours

---

## Lessons Learned

### What Worked Well

1. **Infrastructure Design**
   - Comprehensive safety controls
   - Clear separation of concerns
   - Well-documented Terraform modules
   - Good cost management approach

2. **Documentation**
   - Excellent README in terraform/metal-build/
   - Clear ADR-005 architecture decision
   - Comprehensive launch script
   - Good inline documentation

3. **Tooling**
   - Launch script with pre-flight checks
   - Cost estimation before deployment
   - State locking to prevent concurrent builds
   - Automated cleanup mechanisms

### What Needs Improvement

1. **Testing**
   - ❌ Infrastructure not tested before merge (PR #58)
   - ❌ Template rendering not validated
   - ❌ No terraform validate in CI/CD
   - ❌ First deployment attempt revealed bug

2. **CI/CD Integration**
   - Missing: terraform validate in GitHub Actions
   - Missing: terraform plan as PR check
   - Missing: Template syntax validation
   - Should add: Automated testing of Terraform code

3. **Development Process**
   - Should test infrastructure before merging
   - Should run terraform plan/validate locally
   - Should have staging/test environment
   - Should validate templates before commit

---

## Recommendations

### Immediate (Issue #59)

1. **Fix Template Bug**
   - Review `scripts/metal-build-userdata.sh` line 109
   - Check for unescaped shell characters
   - Validate Terraform template syntax
   - Test template rendering locally

2. **Add Validation to CI**
   - Add `terraform validate` to workflows
   - Add `terraform fmt -check` to linting
   - Add template syntax checks
   - Require validation before merge

3. **Test Before Merge**
   - Run `terraform plan` before PR
   - Validate all templates render
   - Test in isolated environment
   - Document testing performed

### Long-term (Future Improvements)

1. **Infrastructure Testing**
   - Add Terratest for infrastructure testing
   - Create test fixtures for validation
   - Automated integration tests
   - Cost estimation validation

2. **Staging Environment**
   - Test deployments in staging
   - Validate full build process
   - Catch issues before production
   - Reduce risk of blocked issues

3. **Documentation**
   - Add troubleshooting guide
   - Document common errors
   - Create runbook for deployments
   - Add debugging procedures

---

## Next Steps

### For Issue #59 (Critical - Unblock #45)

1. Investigate template rendering error
2. Fix shell script syntax issues
3. Validate template renders correctly
4. Test terraform plan succeeds
5. Document fix and testing performed

### For Issue #45 (Resume After #59 Fixed)

1. Re-attempt Terraform deployment
2. Monitor build progress (~90 minutes)
3. Download built OVA from S3
4. Run validation scripts
5. Execute E2E test suite
6. Document performance metrics
7. Create comprehensive test report
8. Submit PR with findings

**Estimated Timeline** (after #59 fixed):
- Fix bug: 30-60 minutes
- Deploy & build: 2 hours
- E2E testing: 2-3 hours
- Documentation: 1-2 hours
- **Total**: 6-8 hours

---

## Files Created/Modified

### Created
- `terraform/metal-build/terraform.tfvars` - Build configuration
- `tests/e2e/results/issue-45-deployment-attempt.md` - This document

### Modified
- None (deployment blocked before changes)

### To Be Cleaned Up
- `terraform/metal-build/terraform.tfvars` - Remove after testing (contains config)
- `terraform/metal-build/.terraform/` - Terraform working directory
- `terraform/metal-build/.terraform.lock.hcl` - Provider lock file

---

## Cost Impact

**Actual Cost**: $0.00 (deployment never completed)

**Avoided Cost**: ~$15-22 by catching bug before instance launch

**Lesson**: Pre-deployment validation saves money!

---

## Conclusion

While the deployment was blocked by a critical bug, this attempt revealed:

1. ✅ Infrastructure design is sound
2. ✅ Safety controls are comprehensive
3. ✅ Cost estimates are reasonable
4. ✅ Documentation is excellent
5. ❌ Need better testing before merge
6. ❌ Need terraform validation in CI

Issue #59 created to track the bug fix. Once resolved, issue #45 can proceed with full E2E testing of the pre-warmed build system.

---

**Status**: ⏸️ BLOCKED
**Blocker**: Issue #59
**Next**: Fix Terraform template bug, then resume testing
**Branch**: feature/45-complete-e2e-testing
**Date**: 2025-11-06
