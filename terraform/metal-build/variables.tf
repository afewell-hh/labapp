variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type for builds (c5n.metal or m5zn.metal)"
  type        = string
  default     = "c5n.metal"
}

variable "volume_size" {
  description = "EBS volume size in GB for build workspace"
  type        = number
  default     = 500
}

variable "build_id" {
  description = "Unique identifier for this build (auto-generated if not provided)"
  type        = string
  default     = ""
}

variable "build_branch" {
  description = "Git branch to build from"
  type        = string
  default     = "main"
}

variable "build_commit" {
  description = "Git commit SHA to build (optional)"
  type        = string
  default     = ""
}

variable "max_lifetime_hours" {
  description = "Maximum instance lifetime in hours before forced termination"
  type        = number
  default     = 3
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed to SSH to build instance"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # TODO: Restrict in production
}

variable "ssh_key_name" {
  description = "EC2 key pair name for SSH access (optional - uses SSM Session Manager if not provided)"
  type        = string
  default     = ""
}

variable "notification_email" {
  description = "Email address for build notifications"
  type        = string
  default     = ""
}

variable "s3_artifact_bucket" {
  description = "S3 bucket for storing build artifacts"
  type        = string
  default     = "hedgehog-lab-artifacts"
}

variable "github_token" {
  description = "GitHub token for cloning private repos (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_termination_protection" {
  description = "Enable termination protection (disable for testing)"
  type        = bool
  default     = false
}
