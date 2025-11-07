terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Generate unique build ID if not provided
resource "random_id" "build_id" {
  byte_length = 8
}

locals {
  build_id = var.build_id != "" ? var.build_id : "build-${random_id.build_id.hex}"

  common_tags = {
    Project     = "labapp"
    Purpose     = "prewarmed-build"
    BuildID     = local.build_id
    AutoDelete  = "true"
    CostCenter  = "development"
    MaxLifetime = "${var.max_lifetime_hours}hours"
    ManagedBy   = "terraform"
  }
}

# Data source for latest Ubuntu 22.04 LTS AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# DynamoDB table for build state tracking
resource "aws_dynamodb_table" "builds" {
  name         = "labapp-metal-builds"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "BuildID"

  attribute {
    name = "BuildID"
    type = "S"
  }

  attribute {
    name = "Status"
    type = "S"
  }

  global_secondary_index {
    name            = "StatusIndex"
    hash_key        = "Status"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ExpirationTime"
    enabled        = true
  }

  tags = merge(local.common_tags, {
    Name = "labapp-metal-builds"
  })
}

# SNS topic for build notifications
resource "aws_sns_topic" "build_notifications" {
  name = "labapp-metal-build-notifications"

  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.build_notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# CloudWatch log group for build logs
resource "aws_cloudwatch_log_group" "build_logs" {
  name              = "/labapp/metal-builds/${local.build_id}"
  retention_in_days = 7

  tags = local.common_tags
}

# Security group for build instance
resource "aws_security_group" "build_instance" {
  name        = "labapp-metal-build-${local.build_id}"
  description = "Security group for labapp metal build instance"

  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_allowed_cidrs
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "labapp-metal-build-${local.build_id}"
  })
}

# IAM role for build instance
resource "aws_iam_role" "build_instance" {
  name = "labapp-metal-build-instance-${local.build_id}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

# IAM policy for instance permissions
resource "aws_iam_role_policy" "build_instance" {
  name = "labapp-metal-build-policy"
  role = aws_iam_role.build_instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.s3_artifact_bucket}",
          "arn:aws:s3:::${var.s3_artifact_bucket}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:GetItem"
        ]
        Resource = aws_dynamodb_table.builds.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.build_logs.arn}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.build_notifications.arn
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:UpdateInstanceInformation",
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "build_instance" {
  name = "labapp-metal-build-${local.build_id}"
  role = aws_iam_role.build_instance.name

  tags = local.common_tags
}

# Locals for user data script generation
locals {
  user_data_script = <<EOF
#!/bin/bash
# User data script for AWS metal instance pre-warmed builds
# This script runs on instance launch and performs the complete build process

set -euo pipefail

# Template variables (injected by Terraform)
export BUILD_ID="${local.build_id}"
export BUILD_BRANCH="${var.build_branch}"
export BUILD_COMMIT="${var.build_commit}"
export S3_BUCKET="${var.s3_artifact_bucket}"
export DYNAMODB_TABLE="${aws_dynamodb_table.builds.name}"
export SNS_TOPIC_ARN="${aws_sns_topic.build_notifications.arn}"
export CLOUDWATCH_LOG_GROUP="${aws_cloudwatch_log_group.build_logs.name}"
export GITHUB_TOKEN="${var.github_token}"
export AWS_REGION="${var.aws_region}"

${file("${path.module}/../../scripts/metal-build-userdata-body.sh")}
EOF
}

# EC2 instance for builds
resource "aws_instance" "build" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  iam_instance_profile   = aws_iam_instance_profile.build_instance.name
  vpc_security_group_ids = [aws_security_group.build_instance.id]
  key_name               = var.ssh_key_name != "" ? var.ssh_key_name : null

  user_data = local.user_data_script

  disable_api_termination = var.enable_termination_protection

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # Require IMDSv2
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.volume_size
    delete_on_termination = true
    encrypted             = true

    tags = merge(local.common_tags, {
      Name = "labapp-metal-build-root-${local.build_id}"
    })
  }

  tags = merge(local.common_tags, {
    Name       = "labapp-metal-build-${local.build_id}"
    LaunchTime = time_static.build_time.rfc3339
  })

  lifecycle {
    ignore_changes = [tags["LaunchTime"]]
  }
}

# CloudWatch alarm for instance age
resource "aws_cloudwatch_metric_alarm" "instance_age_warning" {
  alarm_name          = "labapp-build-${local.build_id}-age-warning"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = "300" # 5 minutes
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Warning: Build instance has been running for >2 hours"
  treat_missing_data  = "notBreaching"

  dimensions = {
    InstanceId = aws_instance.build.id
  }

  alarm_actions = [aws_sns_topic.build_notifications.arn]

  tags = local.common_tags
}

# Time resource for Unix epoch calculation
resource "time_static" "build_time" {}

# Initial DynamoDB entry for this build
resource "aws_dynamodb_table_item" "build_state" {
  table_name = aws_dynamodb_table.builds.name
  hash_key   = "BuildID"

  item = jsonencode(merge(
    {
      BuildID = {
        S = local.build_id
      }
      Status = {
        S = "launching"
      }
      InstanceID = {
        S = aws_instance.build.id
      }
      LaunchTime = {
        S = time_static.build_time.rfc3339
      }
      BuildBranch = {
        S = var.build_branch
      }
      CostEstimate = {
        N = "20.00" # Estimated max cost
      }
      ExpirationTime = {
        N = tostring(time_static.build_time.unix + 604800) # 7 days TTL
      }
    },
    # Only include BuildCommit if it's not empty (DynamoDB rejects empty strings)
    var.build_commit != "" ? {
      BuildCommit = {
        S = var.build_commit
      }
    } : {}
  ))

  lifecycle {
    ignore_changes = all # Instance will update this
  }
}
