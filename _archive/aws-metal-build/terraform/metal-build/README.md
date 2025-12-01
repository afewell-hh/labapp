# Terraform Module: Metal Build Infrastructure

This Terraform module provisions AWS infrastructure for building pre-warmed Hedgehog Lab appliance OVAs on bare metal instances.

## Overview

Creates and manages:
- EC2 c5n.metal/m5zn.metal instance with nested virtualization
- 500GB EBS gp3 volume for build workspace
- DynamoDB table for build state tracking
- Lambda watchdog function for automatic termination
- CloudWatch alarms and log groups
- SNS topic for notifications
- IAM roles and security groups

## Architecture

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

## Prerequisites

1. **Terraform**: >= 1.0
2. **AWS CLI**: Configured with credentials
3. **AWS Permissions**: Ability to create:
   - EC2 instances (c5n.metal or m5zn.metal)
   - IAM roles and policies
   - DynamoDB tables
   - Lambda functions
   - CloudWatch resources
   - SNS topics

4. **AWS Quotas**: Ensure quota for metal instances in target region

## Usage

### Quick Start

```bash
cd terraform/metal-build

# Initialize Terraform
terraform init

# Create terraform.tfvars (or use variables on command line)
cat > terraform.tfvars <<EOF
build_id           = "build-$(date +%Y%m%d-%H%M%S)"
build_branch       = "main"
aws_region         = "us-east-1"
instance_type      = "c5n.metal"
volume_size        = 500
max_lifetime_hours = 3
EOF

# Plan
terraform plan

# Apply
terraform apply

# Get outputs
terraform output

# Destroy when done
terraform destroy
```

### Using the Launch Script (Recommended)

```bash
# From project root
./scripts/launch-metal-build.sh main
```

The launch script handles:
- Pre-flight checks
- Cost estimation
- Terraform initialization
- Resource cleanup

## Variables

### Required Variables

None - all variables have defaults.

### Optional Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `aws_region` | string | `us-east-1` | AWS region for resources |
| `instance_type` | string | `c5n.metal` | EC2 instance type (c5n.metal or m5zn.metal) |
| `volume_size` | number | `500` | EBS volume size in GB |
| `build_id` | string | auto-generated | Unique build identifier |
| `build_branch` | string | `main` | Git branch to build |
| `build_commit` | string | `""` | Git commit SHA (optional) |
| `max_lifetime_hours` | number | `3` | Max instance lifetime before forced termination |
| `ssh_allowed_cidrs` | list(string) | `["0.0.0.0/0"]` | CIDRs allowed to SSH |
| `notification_email` | string | `""` | Email for SNS notifications |
| `s3_artifact_bucket` | string | `hedgehog-lab-artifacts` | S3 bucket for artifacts |
| `github_token` | string | `""` | GitHub token (sensitive) |
| `enable_termination_protection` | bool | `false` | Enable termination protection |

### Variable Examples

**Minimal (defaults)**:
```hcl
# Uses all defaults
```

**Custom instance type**:
```hcl
instance_type = "m5zn.metal"
```

**Custom timeout**:
```hcl
max_lifetime_hours = 5
```

**With notifications**:
```hcl
notification_email = "devops@example.com"
```

**Production build**:
```hcl
build_id         = "build-v0.2.0-production"
build_branch     = "v0.2.0"
build_commit     = "abc123def456"
instance_type    = "c5n.metal"
volume_size      = 500
max_lifetime_hours = 3
notification_email = "team@example.com"
ssh_allowed_cidrs = ["YOUR.IP.ADDRESS/32"]
```

## Outputs

| Output | Description |
|--------|-------------|
| `build_id` | Unique build identifier |
| `instance_id` | EC2 instance ID |
| `instance_public_ip` | Public IP of build instance |
| `instance_private_ip` | Private IP of build instance |
| `ssh_command` | SSH command to connect |
| `cloudwatch_log_group` | Log group for build logs |
| `dynamodb_table` | DynamoDB table name |
| `sns_topic_arn` | SNS topic ARN |
| `watchdog_lambda_arn` | Watchdog Lambda ARN |
| `estimated_hourly_cost` | Estimated hourly cost |
| `estimated_build_cost` | Estimated total build cost |
| `max_cost` | Maximum cost if timeout reached |

## Resources Created

### Compute
- `aws_instance.build` - c5n.metal instance
- `aws_security_group.build_instance` - Security group

### Storage
- EBS gp3 volume (attached to instance, 500GB)

### IAM
- `aws_iam_role.build_instance` - Instance role
- `aws_iam_role_policy.build_instance` - Instance policy
- `aws_iam_instance_profile.build_instance` - Instance profile
- `aws_iam_role.watchdog_lambda` - Lambda execution role
- `aws_iam_role_policy.watchdog_lambda` - Lambda policy

### Database
- `aws_dynamodb_table.builds` - Build state table
- `aws_dynamodb_table_item.build_state` - Initial state entry

### Monitoring
- `aws_cloudwatch_log_group.build_logs` - Instance logs
- `aws_cloudwatch_log_group.watchdog_lambda` - Lambda logs
- `aws_cloudwatch_metric_alarm.instance_age_warning` - Age alarm

### Serverless
- `aws_lambda_function.watchdog` - Watchdog function
- `aws_cloudwatch_event_rule.watchdog_schedule` - EventBridge rule
- `aws_cloudwatch_event_target.watchdog` - Event target
- `aws_lambda_permission.allow_eventbridge` - Invoke permission

### Notifications
- `aws_sns_topic.build_notifications` - Notification topic
- `aws_sns_topic_subscription.email` - Email subscription (if configured)

## State Management

### Local State

By default, Terraform uses local state:
```
terraform/metal-build/terraform.tfstate
```

**Important**: Do not commit `terraform.tfstate` to git (already in `.gitignore`).

### Remote State (Production)

For production, configure S3 backend:

```hcl
# backend.tf
terraform {
  backend "s3" {
    bucket         = "labapp-terraform-state"
    key            = "metal-build/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}
```

Create backend resources:
```bash
# Create S3 bucket
aws s3 mb s3://labapp-terraform-state --region us-east-1

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket labapp-terraform-state \
  --versioning-configuration Status=Enabled

# Create DynamoDB lock table
aws dynamodb create-table \
  --table-name terraform-state-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-1
```

## Cost Estimates

See `terraform output` for real-time estimates:

```bash
terraform output estimated_build_cost
# Output: ~$15.60 (90 min build + upload)

terraform output max_cost
# Output: ~$22.20 (3 hour timeout)
```

See [COST_MANAGEMENT.md](../../docs/build/COST_MANAGEMENT.md) for detailed analysis.

## Safety Features

### Automatic Safeguards

1. **Watchdog Lambda**: Terminates instances >3 hours old
2. **Instance Tagging**: All resources tagged with `AutoDelete=true`
3. **CloudWatch Alarms**: Warning at 2 hours
4. **Build Timeout**: Packer times out after 3 hours
5. **IAM Least Privilege**: Minimal permissions

### Manual Safeguards

1. **Cost Estimation**: Displayed before apply
2. **State Locking**: DynamoDB prevents concurrent builds
3. **Terraform Plan**: Review changes before apply

## Monitoring

### CloudWatch Logs

**Build Logs**:
```bash
LOG_GROUP=$(terraform output -raw cloudwatch_log_group)
aws logs tail $LOG_GROUP --follow
```

**Lambda Logs**:
```bash
aws logs tail /aws/lambda/labapp-metal-build-watchdog --follow
```

### DynamoDB State

```bash
BUILD_ID=$(terraform output -raw build_id)
aws dynamodb get-item \
  --table-name labapp-metal-builds \
  --key "{\"BuildID\":{\"S\":\"$BUILD_ID\"}}"
```

### SSH Access

```bash
terraform output ssh_command
# ssh -i <key.pem> ubuntu@<public-ip>
```

## Troubleshooting

### Terraform Init Fails

**Error**: "Backend initialization required"
```bash
terraform init -reconfigure
```

### Apply Fails: Quota Exceeded

**Error**: "You have requested more instances than your current limit"
- Request quota increase for metal instances in AWS Console
- Or change `instance_type` variable to available type

### Instance Not Launching

Check:
1. AMI availability in region
2. VPC default settings
3. IAM permissions
4. Service quotas

### Destroy Fails

**Graceful destroy**:
```bash
terraform destroy -auto-approve
```

**Force destroy** (if resources stuck):
```bash
# Terminate instance manually
aws ec2 terminate-instances --instance-ids <instance-id>

# Delete stack resources
terraform destroy -refresh=false
```

### Orphaned Resources

**Find AutoDelete resources**:
```bash
# EC2 instances
aws ec2 describe-instances \
  --filters "Name=tag:Project,Values=labapp" \
            "Name=tag:AutoDelete,Values=true" \
            "Name=instance-state-name,Values=running"

# EBS volumes
aws ec2 describe-volumes \
  --filters "Name=tag:Project,Values=labapp" \
            "Name=tag:AutoDelete,Values=true"
```

**Cleanup via watchdog**:
```bash
aws lambda invoke \
  --function-name labapp-metal-build-watchdog \
  /tmp/output.json
```

## Development

### Testing Infrastructure

**Validate configuration**:
```bash
terraform validate
```

**Plan without applying**:
```bash
terraform plan -out=tfplan
```

**Dry-run with smaller instance** (testing only):
```bash
terraform apply -var="instance_type=t3.large"
```

### Module Updates

1. Make changes to `*.tf` files
2. Run `terraform fmt` to format
3. Run `terraform validate` to check syntax
4. Test with `terraform plan`
5. Document changes in git commit

## Security Considerations

- **Secrets**: Never commit `terraform.tfvars` with sensitive data
- **State Files**: Exclude from git, contain sensitive data
- **SSH Keys**: Use temporary keys or AWS Session Manager
- **IAM Roles**: Least privilege permissions only
- **Security Groups**: Restrict SSH to known IPs in production

## Files

```
terraform/metal-build/
├── README.md              # This file
├── main.tf                # Core infrastructure
├── variables.tf           # Input variables
├── outputs.tf             # Output values
├── lambda.tf              # Watchdog Lambda function
├── .gitignore             # Ignore state files
└── terraform.tfvars       # Variable values (gitignored)

../../scripts/
├── launch-metal-build.sh      # Orchestration script
└── metal-build-userdata.sh    # Instance initialization

../../lambda/metal-build-watchdog/
├── handler.py             # Watchdog Lambda code
└── requirements.txt       # Python dependencies
```

## References

- [ADR-005: Metal Build System Architecture](../../docs/adr/005-aws-metal-build-system.md)
- [AWS Metal Build User Guide](../../docs/build/AWS_METAL_BUILD.md)
- [Cost Management Guide](../../docs/build/COST_MANAGEMENT.md)
- [Issue #57](https://github.com/afewell-hh/labapp/issues/57)

## Support

For issues:
1. Check Terraform logs
2. Review CloudWatch logs
3. Verify DynamoDB state
4. See troubleshooting section above
5. Create GitHub issue with logs
