## AWS Metal Instance Build System - User Guide

This guide explains how to use the AWS metal instance build system to create pre-warmed OVA builds for the Hedgehog Lab appliance.

### Overview

Pre-warmed builds require significant resources that exceed typical development environments:
- **Disk Space**: 200-300GB during build
- **Nested Virtualization**: KVM support required
- **Build Time**: 60-90 minutes
- **Cost**: ~$15-20 per build

The metal build system provides a safe, automated way to launch AWS c5n.metal instances for these builds with built-in cost controls and automatic cleanup.

### Architecture

```
┌─────────────────────────────────────────────┐
│  Developer                                  │
│  └─> scripts/launch-metal-build.sh         │
└───────────────┬─────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────┐
│  Terraform Infrastructure                   │
│  ├─ EC2 c5n.metal instance                 │
│  ├─ 500GB EBS volume                       │
│  ├─ DynamoDB state table                   │
│  ├─ CloudWatch logs                        │
│  └─ Lambda watchdog (auto-terminate)       │
└───────────────┬─────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────┐
│  Build Execution (on instance)              │
│  └─> Packer → Build → Upload to S3         │
└─────────────────────────────────────────────┘
```

### Prerequisites

#### 1. Install Required Tools

```bash
# Terraform
brew install terraform  # macOS
# or
sudo apt-get install terraform  # Ubuntu

# AWS CLI
brew install awscli  # macOS
# or
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# jq (JSON processor)
brew install jq  # macOS
# or
sudo apt-get install jq  # Ubuntu
```

#### 2. Configure AWS Credentials

The system uses credentials from `.env` file (already configured in the project):

```bash
# Credentials are in /home/ubuntu/afewell-hh/labapp/.env
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=zUP...
```

Verify credentials:
```bash
aws sts get-caller-identity
```

#### 3. Verify AWS Quotas

Ensure your AWS account has quota for c5n.metal instances:

```bash
aws service-quotas get-service-quota \
  --service-code ec2 \
  --quota-code L-DB2E81BA
```

If quota is 0, request an increase via AWS Console.

### Quick Start

#### Launch a Build

```bash
cd /home/ubuntu/afewell-hh/labapp

# Build from main branch
./scripts/launch-metal-build.sh main

# Build from specific branch
./scripts/launch-metal-build.sh feature/45-test-prewarmed-build

# Build from specific commit
./scripts/launch-metal-build.sh main abc1234
```

The script will:
1. Check prerequisites
2. Verify no existing builds are running
3. Display cost estimate
4. Ask for confirmation
5. Launch infrastructure via Terraform
6. Optionally monitor build progress
7. Optionally cleanup resources when done

#### Monitor Build Progress

**Option 1: CloudWatch Logs (Recommended)**
```bash
# Get log group name from Terraform output
aws logs tail /labapp/metal-builds/<build-id> --follow
```

**Option 2: DynamoDB State**
```bash
# Check build status
aws dynamodb get-item \
  --table-name labapp-metal-builds \
  --key '{"BuildID":{"S":"<build-id>"}}'
```

**Option 3: SSH to Instance**
```bash
# Get public IP from Terraform output
ssh ubuntu@<public-ip>

# View logs on instance
tail -f /var/log/metal-build.log
```

#### Cleanup Resources

**Automatic Cleanup:**
- Build completes successfully → Instance terminates automatically
- Build fails → Instance terminates automatically
- Timeout (3 hours) → Watchdog Lambda terminates instance

**Manual Cleanup:**
```bash
cd terraform/metal-build
terraform destroy -auto-approve
```

### Cost Management

#### Estimated Costs

**Normal Build (~90 minutes):**
- c5n.metal instance: $6.48
- EBS 500GB: $0.12
- Data transfer (100GB): $9.00
- **Total: ~$15.60**

**Maximum (3-hour timeout):**
- c5n.metal instance: $12.96
- EBS 500GB: $0.24
- Data transfer: $9.00
- **Total: ~$22.20**

#### Cost Controls

1. **Watchdog Lambda**: Terminates instances >3 hours old
2. **Build Timeout**: Packer times out after 3 hours
3. **Budget Alerts**: Configure AWS Budgets for $50/month (optional)
4. **Cost Estimation**: Displayed before every launch
5. **Manual Confirmation**: Required to proceed

#### View Current Costs

```bash
# Check current month's costs
aws ce get-cost-and-usage \
  --time-period Start=$(date +%Y-%m-01),End=$(date +%Y-%m-%d) \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --filter file://cost-filter.json

# cost-filter.json:
{
  "Tags": {
    "Key": "Project",
    "Values": ["labapp"]
  }
}
```

### Safety Controls

#### 1. Time-Based Safeguards

- **Maximum Runtime**: 3 hours hard limit
- **Watchdog Lambda**: Checks every 15 minutes
- **Auto-Termination**: Force terminates instances >3 hours
- **Build Timeout**: Packer times out after 3 hours

#### 2. Resource Tagging

All resources tagged with:
```
Project=labapp
Purpose=prewarmed-build
BuildID=<unique-id>
AutoDelete=true
MaxLifetime=3hours
```

#### 3. State Tracking

DynamoDB table tracks:
- Build ID and status
- Instance ID
- Launch time
- Cost estimate
- Error messages
- Forced termination flag

#### 4. Notifications

SNS notifications sent for:
- Build started
- Build completed
- Build failed
- Instance force-terminated

### Troubleshooting

#### Build Fails to Launch

**Error: "Missing required tools"**
- Install Terraform, AWS CLI, and jq (see Prerequisites)

**Error: "AWS credentials not configured"**
- Check `.env` file exists in project root
- Verify credentials with `aws sts get-caller-identity`

**Error: "No quota for c5n.metal"**
- Request quota increase via AWS Console
- Alternative: Modify `instance_type` in Terraform variables to m5zn.metal

#### Build Fails During Execution

**Packer build fails:**
- Check CloudWatch logs: `/labapp/metal-builds/<build-id>`
- SSH to instance and check `/var/log/metal-build.log`
- Common causes: insufficient disk space, KVM issues, network problems

**Upload to S3 fails:**
- Verify IAM permissions (S3 PutObject)
- Check S3 bucket exists: `hedgehog-lab-artifacts`
- Verify network connectivity from instance

#### Watchdog Terminates Instance

**Instance runs >3 hours:**
- Check if build is hung (CloudWatch logs)
- Verify Packer configuration for inefficiencies
- Consider increasing timeout (edit `max_lifetime_hours` variable)

#### Resources Not Cleaned Up

**Orphaned instances:**
- Run watchdog Lambda manually:
  ```bash
  aws lambda invoke \
    --function-name labapp-metal-build-watchdog \
    --log-type Tail \
    /tmp/watchdog-output.json
  ```

**Orphaned EBS volumes:**
- List volumes with AutoDelete tag:
  ```bash
  aws ec2 describe-volumes \
    --filters "Name=tag:AutoDelete,Values=true" \
              "Name=tag:Project,Values=labapp"
  ```
- Delete manually if needed

### Advanced Usage

#### Custom Instance Type

```bash
# Edit terraform/metal-build/terraform.tfvars
instance_type = "m5zn.metal"
```

#### Custom Disk Size

```bash
# Edit terraform/metal-build/terraform.tfvars
volume_size = 1000  # 1TB
```

#### Increase Timeout

```bash
# Edit terraform/metal-build/terraform.tfvars
max_lifetime_hours = 5
```

#### Enable SNS Email Notifications

```bash
# Edit terraform/metal-build/terraform.tfvars
notification_email = "your-email@example.com"

# Confirm subscription in email
```

#### SSH Access Restriction

```bash
# Edit terraform/metal-build/terraform.tfvars
ssh_allowed_cidrs = ["YOUR.PUBLIC.IP.ADDRESS/32"]
```

### Build Artifacts

Successful builds upload to S3:

**Bucket**: `s3://hedgehog-lab-artifacts/`

**Path Structure**:
```
releases/v<version>/
  ├─ hedgehog-lab-prewarmed-<version>.ova
  ├─ hedgehog-lab-prewarmed-<version>.ova.sha256
  └─ hedgehog-lab-prewarmed-<version>.json  (metadata)

builds/<build-id>/
  └─ logs/
     └─ build.log
```

**Download Artifact**:
```bash
aws s3 cp \
  s3://hedgehog-lab-artifacts/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova \
  ./
```

### Monitoring and Observability

#### CloudWatch Logs

**Log Groups**:
- `/labapp/metal-builds/<build-id>` - Build logs
- `/aws/lambda/labapp-metal-build-watchdog` - Watchdog logs

**View Logs**:
```bash
# Tail build logs
aws logs tail /labapp/metal-builds/<build-id> --follow

# View watchdog executions
aws logs tail /aws/lambda/labapp-metal-build-watchdog --since 1h
```

#### DynamoDB State

**Query All Builds**:
```bash
aws dynamodb scan --table-name labapp-metal-builds
```

**Query by Status**:
```bash
aws dynamodb query \
  --table-name labapp-metal-builds \
  --index-name StatusIndex \
  --key-condition-expression "#status = :status" \
  --expression-attribute-names '{"#status":"Status"}' \
  --expression-attribute-values '{":status":{"S":"completed"}}'
```

#### CloudWatch Alarms

Alarms created per build:
- `labapp-build-<build-id>-age-warning` - Triggers at 2 hours

### Security Considerations

#### IAM Permissions

Instance profile has minimal permissions:
- S3: PutObject, GetObject (hedgehog-lab-artifacts bucket only)
- DynamoDB: PutItem, UpdateItem, GetItem (labapp-metal-builds table)
- CloudWatch Logs: CreateLogStream, PutLogEvents
- SNS: Publish (notifications topic)

#### Network Security

- Security group allows SSH from specified CIDRs only (default: 0.0.0.0/0)
- All outbound traffic allowed (required for package downloads)
- IMDSv2 enforced (instance metadata security)

#### Secrets Management

- GitHub token passed via Terraform variable (not logged)
- AWS credentials from IAM role (not hardcoded)
- No secrets in user-data or CloudWatch logs

### Integration with CI/CD

#### GitHub Actions Integration (Future)

```yaml
name: Metal Build

on:
  workflow_dispatch:
    inputs:
      branch:
        description: 'Branch to build'
        required: true
        default: 'main'

jobs:
  launch-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Configure AWS
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Launch Build
        run: |
          cd terraform/metal-build
          terraform init
          terraform apply -auto-approve \
            -var="build_branch=${{ github.event.inputs.branch }}"
```

### References

- [ADR-005: AWS Metal Build System](../adr/005-aws-metal-build-system.md)
- [ADR-001: Dual Build Pipeline](../adr/001-dual-build-pipeline.md)
- [Cost Management Guide](COST_MANAGEMENT.md)
- [Issue #57: Implementation Details](https://github.com/afewell-hh/labapp/issues/57)

### Support

For issues or questions:
1. Check CloudWatch logs first
2. Review DynamoDB build state
3. Check this troubleshooting guide
4. Create GitHub issue with logs attached
