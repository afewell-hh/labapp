# AWS Metal Build System - Cost Management Guide

## Overview

This document provides detailed cost analysis and management strategies for the AWS metal instance build system used to create pre-warmed Hedgehog Lab appliance OVAs.

## Cost Breakdown

### Per-Build Costs (us-east-1)

#### c5n.metal Instance
- **Hourly Rate**: $4.32/hour
- **Expected Build Time**: 1.5 hours
- **Expected Cost**: $6.48
- **Maximum (3h timeout)**: $12.96

#### EBS Storage (gp3)
- **Volume Size**: 500GB
- **Hourly Rate**: ~$0.08/hour ($40/month ÷ 30 days ÷ 24 hours)
- **Expected Cost (1.5h)**: $0.12
- **Maximum (3h)**: $0.24

#### Data Transfer
- **Expected Upload Size**: 100GB (compressed OVA)
- **Rate**: $0.09/GB
- **Cost**: $9.00
- **Note**: First GB/month free, minimal inbound transfer costs

#### AWS Service Costs
- **DynamoDB**: Free tier (25GB, 25 WCU, 25 RCU) - negligible
- **Lambda**: Free tier (1M requests, 400K GB-seconds) - negligible
- **CloudWatch Logs**: $0.50/GB ingested (~100MB logs) - $0.05
- **SNS**: $0.50/million notifications (~4 per build) - negligible

### Total Costs

| Scenario | Instance | EBS | Transfer | Services | **Total** |
|----------|----------|-----|----------|----------|-----------|
| **Expected (90 min)** | $6.48 | $0.12 | $9.00 | $0.05 | **$15.65** |
| **Median (2 hours)** | $8.64 | $0.16 | $9.00 | $0.05 | **$17.85** |
| **Maximum (3h timeout)** | $12.96 | $0.24 | $9.00 | $0.05 | **$22.25** |

## Monthly Cost Projections

### Development Phase (Frequent Builds)

**Assumption**: 2 builds per week = 8 builds/month

| Cost Category | Per Build | Monthly (8 builds) |
|---------------|-----------|-------------------|
| Compute (instance + EBS) | $6.60 | $52.80 |
| Data Transfer | $9.00 | $72.00 |
| AWS Services | $0.05 | $0.40 |
| **Total** | **$15.65** | **$125.20** |

### Production Phase (Stable Releases)

**Assumption**: 1 build per month

| Cost Category | Monthly |
|---------------|---------|
| Compute | $6.60 |
| Data Transfer | $9.00 |
| AWS Services | $0.40 |
| Infrastructure (DynamoDB, Lambda, watchdog) | $2.00 |
| **Total** | **$18.00** |

### Event-Specific Builds

**Assumption**: 1 large event every 3 months

| Cost Category | Per Event |
|---------------|-----------|
| Pre-event test build | $15.65 |
| Final production build | $15.65 |
| **Total per event** | **$31.30** |

**Annual (4 events)**: ~$125/year

## Cost Optimization Strategies

### 1. Instance Type Selection

| Instance Type | vCPUs | RAM | Hourly | Expected Build | Pros | Cons |
|---------------|-------|-----|--------|----------------|------|------|
| **c5n.metal** | 72 | 192GB | $4.32 | $15.65 | ✓ Nested virt<br>✓ High network | Higher cost |
| **m5zn.metal** | 48 | 192GB | $3.96 | $14.40 | ✓ Lower cost<br>✓ Nested virt | Slower network |
| c6i.metal | 128 | 256GB | $6.80 | $19.65 | ✓ Latest gen | ⚠️ Higher cost |

**Recommendation**: Use c5n.metal (current default) for balance of performance and cost.

### 2. Timing Optimization

**Build Duration vs Instance Cost:**
- Reducing build time by 15 min saves ~$1.08/build
- Optimization opportunities:
  - Packer caching (saves ~10 min) = $0.72/build
  - Parallel provisioning (saves ~5 min) = $0.36/build
  - Pre-pulled Docker images (saves ~5 min) = $0.36/build

**Total Potential Savings**: ~$1.44/build (9% reduction)

### 3. Scheduled Builds

**Off-Peak Pricing**: Currently not applicable to on-demand instances
- Consider: Reserved instances if >10 builds/month (not recommended for MVP)
- Consider: Spot instances (not recommended - build interruptions risky)

### 4. Data Transfer Optimization

**S3 Transfer Acceleration**: $0.04-0.08/GB additional
- **Not Recommended**: Adds $4-8 per build for minimal speed improvement
- Upload speed already sufficient (~1 hour for 100GB)

**Compression Optimization**:
- Current: gzip compression (~100GB)
- Potential: xz compression (~85GB, saves $1.35 transfer)
- **Trade-off**: 10-15 min longer build (+$0.72) = Net loss
- **Not Recommended**

### 5. Storage Lifecycle

**S3 Storage Costs** (separate from build costs):

| Tier | Monthly Cost (100GB) | Use Case |
|------|---------------------|----------|
| Standard | $2.30 | Active downloads |
| Standard-IA | $1.25 | Archive (>30 days) |
| Glacier Instant | $0.40 | Long-term archive |

**Automated Lifecycle** (from ADR-004):
- Transition to Standard-IA after 30 days (saves $1.05/month per artifact)
- Delete non-current versions after 90 days
- Keep latest 3 versions

**Annual Storage Savings**: ~$12.60/year per version

## Cost Controls and Safeguards

### 1. Automated Controls

#### Watchdog Lambda
- **Function**: Terminates instances >3 hours old
- **Trigger**: Every 15 minutes
- **Cost Impact**: Prevents runaway charges (saves up to $100+ in case of hung build)
- **Lambda Cost**: ~$0.20/month (negligible)

#### Build Timeout
- **Packer Timeout**: 3 hours
- **User-Data Timeout**: 3 hours
- **Cost Impact**: Hard limit at $22.25 per build

#### DynamoDB State Locking
- **Function**: Prevents concurrent builds
- **Cost Impact**: Prevents accidental double-charges
- **DynamoDB Cost**: Free tier

### 2. Manual Controls

#### Pre-Launch Cost Estimation
```
Launch script displays:
- Expected cost: $15.65
- Maximum cost: $22.25
- Requires manual confirmation
```

#### Budget Alerts (Optional)
```bash
# Set up AWS Budget
aws budgets create-budget \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --budget file://budget.json \
  --notifications-with-subscribers file://notifications.json
```

**budget.json**:
```json
{
  "BudgetName": "labapp-monthly",
  "BudgetLimit": {
    "Amount": "50",
    "Unit": "USD"
  },
  "TimeUnit": "MONTHLY",
  "BudgetType": "COST",
  "CostFilters": {
    "TagKeyValue": ["user:Project$labapp"]
  }
}
```

### 3. Monitoring and Alerts

#### CloudWatch Alarms

**Instance Age Warning** (2 hours):
- Purpose: Early warning before timeout
- Action: SNS notification
- Response: Check build progress, investigate if hung

**Cost Anomaly Detection**:
```bash
# Enable AWS Cost Anomaly Detection
aws ce create-anomaly-monitor \
  --anomaly-monitor '{
    "MonitorName": "labapp-builds",
    "MonitorType": "CUSTOM",
    "MonitorSpecification": {
      "Tags": {
        "Key": "Project",
        "Values": ["labapp"]
      }
    }
  }'
```

## Cost Tracking and Reporting

### 1. Tag-Based Cost Allocation

All resources tagged with:
```
Project=labapp
Purpose=prewarmed-build
BuildID=<unique-id>
CostCenter=development
```

**Enable Cost Allocation Tags**:
1. AWS Console → Billing → Cost Allocation Tags
2. Activate: `Project`, `Purpose`, `BuildID`, `CostCenter`
3. Wait 24 hours for data

### 2. Cost Explorer Queries

**Monthly Costs by Project**:
```bash
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '1 month ago' +%Y-%m-01),End=$(date +%Y-%m-%d) \
  --granularity MONTHLY \
  --metrics BlendedCost UnblendedCost \
  --group-by Type=TAG,Key=Project \
  --filter file://project-filter.json
```

**project-filter.json**:
```json
{
  "Tags": {
    "Key": "Project",
    "Values": ["labapp"]
  }
}
```

**Per-Build Cost Analysis**:
```bash
# Get cost for specific build
aws ce get-cost-and-usage \
  --time-period Start=<build-date>,End=<build-date+1> \
  --granularity DAILY \
  --filter '{
    "Tags": {
      "Key": "BuildID",
      "Values": ["<build-id>"]
    }
  }'
```

### 3. DynamoDB Cost Tracking

Each build entry includes:
```json
{
  "BuildID": "build-20251106-143022",
  "CostEstimate": 20.00,
  "ActualInstanceHours": 1.5,
  "ActualCost": 15.65  // Updated post-build
}
```

**Query Total Spend**:
```bash
aws dynamodb scan \
  --table-name labapp-metal-builds \
  --projection-expression "BuildID, ActualCost" \
  --filter-expression "attribute_exists(ActualCost)"
```

## Budget Recommendations

### Development Phase (Weeks 1-4)

**Monthly Budget**: $150
- 8 builds × $15.65 = $125.20
- Infrastructure: $2.00
- Buffer (20%): $22.80

**Alert Thresholds**:
- 50% ($75): Informational
- 80% ($120): Warning
- 100% ($150): Critical - pause builds

### Production Phase (Ongoing)

**Monthly Budget**: $50
- 1-2 builds × $15.65 = $15.65-31.30
- Infrastructure: $2.00
- S3 storage: $6-9
- Buffer: $10-20

**Annual Budget**: $600
- 12 monthly builds: $187.80
- 4 event builds: $62.60
- Infrastructure: $24
- S3 storage: $90
- Buffer: $235.60

## Risk Mitigation

### High-Risk Scenarios

| Risk | Impact | Probability | Mitigation | Residual Risk |
|------|--------|-------------|------------|---------------|
| **Runaway instance (24h)** | $103.68 | Low | Watchdog Lambda (3h limit) | $22.25 max |
| **Concurrent builds (10×)** | $156.50 | Medium | DynamoDB state lock | $15.65 (single) |
| **Failed cleanup** | $103.68/month | Low | Watchdog scans for AutoDelete tag | ~$4/day until detected |
| **Budget overrun** | Variable | Medium | Budget alerts, manual confirmation | Notification-based |

### Cost Ceiling Guarantees

**Per-Build Maximum**: $22.25
- Instance: $12.96 (3h)
- EBS: $0.24 (3h)
- Transfer: $9.00
- Services: $0.05

**Monthly Maximum** (assuming 10 builds/month):
- Builds: $222.50
- Infrastructure: $2.00
- **Total: $224.50**

**Hard Stop Mechanisms**:
1. Watchdog Lambda (3h)
2. Packer timeout (3h)
3. Budget alerts ($50, $150)
4. Manual approval required

## Optimization Checklist

Before each build:
- [ ] Verify build is necessary (not duplicate)
- [ ] Check DynamoDB for active builds
- [ ] Review cost estimate ($15.65 expected)
- [ ] Confirm budget availability
- [ ] Set monitoring reminder (2 hours)

After each build:
- [ ] Verify Terraform destroy completed
- [ ] Check for orphaned resources (EBS volumes)
- [ ] Review actual vs estimated cost
- [ ] Update cost tracking spreadsheet
- [ ] Archive build logs (cost: <$0.01)

Monthly:
- [ ] Review Cost Explorer for anomalies
- [ ] Verify budget is on track
- [ ] Check S3 lifecycle transitions
- [ ] Review watchdog Lambda logs
- [ ] Update cost projections

## Cost Comparison: Alternatives

### Alternative 1: Dedicated Self-Hosted Runner

**One-Time Hardware Cost**: $3,000-5,000
- High-end workstation with:
  - 500GB NVMe SSD
  - 64GB RAM
  - KVM support

**Ongoing Costs**: $0/build
- Electricity: ~$10/month
- Maintenance: $0 (self-managed)

**Break-Even**: 191-319 builds (~2-3 years at 8 builds/month)

**Cons**:
- High upfront cost
- Maintenance burden
- No redundancy
- Limited scalability

### Alternative 2: GitHub Actions Self-Hosted

**Runner Cost**: Same as Alternative 1
**GitHub Actions**: $0 (unlimited for self-hosted)

**Additional Costs**:
- Runner management overhead
- Same break-even as Alternative 1

**Cons**:
- Complex setup
- GitHub Actions timeout limits
- Runner lifecycle management

### Alternative 3: AWS ECS Fargate

**Not viable**: Fargate doesn't support nested virtualization

### Recommendation

**For MVP (first year)**:
- Use metal instance system ($125-225/month)
- Evaluate after 6 months based on actual usage
- If >15 builds/month consistently: Consider dedicated hardware

## Conclusion

**Target Cost**: $15.65 per build
**Maximum Cost**: $22.25 per build (guaranteed)
**Monthly Budget**:
- Development: $150
- Production: $50

**Key Safeguards**:
1. 3-hour watchdog timeout
2. Manual confirmation required
3. DynamoDB state locking
4. Budget alerts configured
5. Cost estimation pre-flight

**ROI**:
- Eliminates need for dedicated hardware ($3-5K)
- Pay-per-use model (no idle costs)
- Scales with demand
- Low operational overhead

**Next Steps**:
1. Deploy infrastructure
2. Run test build
3. Validate actual costs
4. Configure budget alerts
5. Monitor for 30 days
6. Reassess strategy

## References

- [ADR-005: AWS Metal Build System](../adr/005-aws-metal-build-system.md)
- [AWS Pricing Calculator](https://calculator.aws/)
- [EC2 On-Demand Pricing](https://aws.amazon.com/ec2/pricing/on-demand/)
- [S3 Pricing](https://aws.amazon.com/s3/pricing/)
- [Cost Management Guide](AWS_METAL_BUILD.md#cost-management)
