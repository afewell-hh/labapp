output "build_id" {
  description = "Unique build identifier"
  value       = local.build_id
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.build.id
}

output "instance_public_ip" {
  description = "Public IP of build instance"
  value       = aws_instance.build.public_ip
}

output "instance_private_ip" {
  description = "Private IP of build instance"
  value       = aws_instance.build.private_ip
}

output "ssh_command" {
  description = "SSH command to connect to instance"
  value       = "ssh -i <key.pem> ubuntu@${aws_instance.build.public_ip}"
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for build logs"
  value       = aws_cloudwatch_log_group.build_logs.name
}

output "dynamodb_table" {
  description = "DynamoDB table for build state"
  value       = aws_dynamodb_table.builds.name
}

output "sns_topic_arn" {
  description = "SNS topic for notifications"
  value       = aws_sns_topic.build_notifications.arn
}

output "watchdog_lambda_arn" {
  description = "Watchdog Lambda function ARN"
  value       = aws_lambda_function.watchdog.arn
}

output "estimated_hourly_cost" {
  description = "Estimated hourly cost in USD"
  value       = "~$4.40/hour (instance + storage + transfer)"
}

output "estimated_build_cost" {
  description = "Estimated total build cost (1.5 hours)"
  value       = "~$15.60 (90 min build + upload)"
}

output "max_cost" {
  description = "Maximum cost if timeout reached"
  value       = "~$22.20 (3 hour timeout)"
}
