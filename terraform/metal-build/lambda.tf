# Watchdog Lambda function to terminate old instances

resource "aws_iam_role" "watchdog_lambda" {
  name = "labapp-metal-build-watchdog"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "watchdog_lambda" {
  name = "watchdog-policy"
  role = aws_iam_role.watchdog_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags",
          "ec2:TerminateInstances",
          "ec2:DeleteVolume",
          "ec2:DescribeVolumes"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:Scan",
          "dynamodb:UpdateItem",
          "dynamodb:GetItem"
        ]
        Resource = aws_dynamodb_table.builds.arn
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.build_notifications.arn
      }
    ]
  })
}

# Package Lambda function code
data "archive_file" "watchdog_lambda" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/metal-build-watchdog/handler.py"
  output_path = "${path.module}/watchdog-lambda.zip"
}

resource "aws_lambda_function" "watchdog" {
  filename         = data.archive_file.watchdog_lambda.output_path
  function_name    = "labapp-metal-build-watchdog"
  role             = aws_iam_role.watchdog_lambda.arn
  handler          = "handler.lambda_handler"
  source_code_hash = data.archive_file.watchdog_lambda.output_base64sha256
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 128

  environment {
    variables = {
      MAX_LIFETIME_HOURS = var.max_lifetime_hours
      DYNAMODB_TABLE     = aws_dynamodb_table.builds.name
      SNS_TOPIC_ARN      = aws_sns_topic.build_notifications.arn
    }
  }

  tags = local.common_tags
}

# CloudWatch log group for Lambda
resource "aws_cloudwatch_log_group" "watchdog_lambda" {
  name              = "/aws/lambda/${aws_lambda_function.watchdog.function_name}"
  retention_in_days = 7

  tags = local.common_tags
}

# EventBridge rule to trigger watchdog every 15 minutes
resource "aws_cloudwatch_event_rule" "watchdog_schedule" {
  name                = "labapp-metal-build-watchdog-schedule"
  description         = "Trigger watchdog Lambda every 15 minutes"
  schedule_expression = "rate(15 minutes)"

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "watchdog" {
  rule      = aws_cloudwatch_event_rule.watchdog_schedule.name
  target_id = "WatchdogLambda"
  arn       = aws_lambda_function.watchdog.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.watchdog.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.watchdog_schedule.arn
}
