# ── ECS Execution Role (pulls ECR image, reads secrets, writes logs) ──────────

resource "aws_iam_role" "ecs_execution" {
  name               = "phantom-web-ecs-execution-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.assume_ecs_execution.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "assume_ecs_execution" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role_policy" "ecs_execution" {
  name   = "phantom-web-execution-policy"
  role   = aws_iam_role.ecs_execution.id
  policy = data.aws_iam_policy_document.ecs_execution.json
}

data "aws_iam_policy_document" "ecs_execution" {
  statement {
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "${aws_cloudwatch_log_group.phantom_web.arn}:*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
    ]
    resources = [
      aws_secretsmanager_secret.anthropic_api_key.arn,
      aws_secretsmanager_secret.phantom_admin_token.arn,
      aws_secretsmanager_secret.google_chat_webhook.arn,
      aws_secretsmanager_secret.defectdojo_api_key.arn,
    ]
  }
}

# ── ECS Task Role (permissions for skills, AWS service calls, etc.) ────────────

resource "aws_iam_role" "ecs_task" {
  name               = "phantom-web-ecs-task-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.assume_ecs_task.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "assume_ecs_task" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role_policy" "ecs_task" {
  name   = "phantom-web-task-policy"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.ecs_task.json
}

data "aws_iam_policy_document" "ecs_task" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "${aws_cloudwatch_log_group.phantom_web.arn}:*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "inspector2:DescribeFindings",
      "inspector2:ListFindings",
      "inspector:DescribeFindings",
      "inspector:ListFindings",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "guardduty:ListDetectors",
      "guardduty:GetFindings",
      "guardduty:ListFindings",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeImages",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeNetworkInterfaces",
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "ecr:DescribeImages",
      "ecr:ListImages",
      "ecr:DescribeRepositories",
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::phantom-*",
      "arn:aws:s3:::phantom-*/*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["s3*.${var.aws_region}.amazonaws.com"]
    }
  }

  # Bedrock inference for Phantom's reasoning (only when var.use_bedrock).
  # Scoped to Anthropic Claude foundation models and cross-region inference
  # profiles; both are required because Claude on Bedrock is served via
  # cross-region inference profiles that fan out to the underlying models.
  dynamic "statement" {
    for_each = var.use_bedrock ? [1] : []
    content {
      sid    = "BedrockInvokeClaude"
      effect = "Allow"
      actions = [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
      ]
      resources = [
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-*",
        "arn:aws:bedrock:*:${data.aws_caller_identity.current.account_id}:inference-profile/*anthropic.claude-*",
      ]
    }
  }
}
