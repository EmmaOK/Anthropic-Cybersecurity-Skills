data "aws_caller_identity" "current" {}

# ── ECS Task Execution Role (used by ECS agent to pull image + inject secrets) ──

resource "aws_iam_role" "ecs_execution" {
  name = "phantom-mcp-ecs-execution-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "ecs_execution_managed" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Allow ECS to pull the Phantom API key from Secrets Manager at task start
resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name = "phantom-mcp-secrets"
  role = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "kms:Decrypt"
        ]
        Resource = [
          aws_secretsmanager_secret.phantom_api_key.arn,
          aws_secretsmanager_secret.admin_shutdown_token.arn,
          aws_secretsmanager_secret.kali_ssh_key.arn,
        ]
      }
    ]
  })
}

# ── ECS Task Role (runtime permissions for the running container) ─────────────

resource "aws_iam_role" "ecs_task" {
  name = "phantom-mcp-ecs-task-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

# Allow ECS Exec (SSM) — required for aws ecs execute-command
# LPP-03 formal exception: SSM Messages actions do not support resource-level restrictions;
# AWS requires Resource = "*" for all ssmmessages:* actions used by ECS Exec.
# Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html
resource "aws_iam_role_policy" "ecs_task_exec_command" {
  name = "phantom-mcp-task-exec-command"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ]
      Resource = "*"
    }]
  })
}

# Allow the task agent to invoke Claude via Bedrock (cross-region inference profiles + foundation models)
resource "aws_iam_role_policy" "ecs_task_bedrock" {
  name = "phantom-mcp-task-bedrock"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
      ]
      Resource = [
        # Foundation models (no account ID in ARN)
        "arn:aws:bedrock:${var.aws_region}::foundation-model/anthropic.claude-*",
        # Cross-region inference profiles (scoped to this account + Claude only)
        "arn:aws:bedrock:${var.aws_region}:${data.aws_caller_identity.current.account_id}:inference-profile/us.anthropic.claude-*",
      ]
    }]
  })
}

# Allow the kill switch to rotate the Phantom API key in Secrets Manager
resource "aws_iam_role_policy" "ecs_task_secrets_rotate" {
  name = "phantom-mcp-task-secrets-rotate"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:PutSecretValue"]
      Resource = [aws_secretsmanager_secret.phantom_api_key.arn]
    }]
  })
}

# Allow the container to write CloudWatch logs
resource "aws_iam_role_policy" "ecs_task_logs" {
  name = "phantom-mcp-task-logs"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.phantom_mcp.arn}:*"
    }]
  })
}
