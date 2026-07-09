# ---------------------------------------------------------------------------
# Three roles, least privilege:
#   execution_role — ECS pulls the image, writes logs, resolves the task secrets
#   api_task_role  — the API app: read reports from S3 (serve them)
#   worker_task_role — the worker app: RW reports + READ GuardDuty/CloudTrail for
#                      investigation. CONTAINMENT perms are a SEPARATE, opt-in
#                      policy (below) so acting in prod is a deliberate decision.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# --- Execution role ---
resource "aws_iam_role" "execution" {
  name               = "${var.name}-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}
resource "aws_iam_role_policy_attachment" "exec_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
data "aws_iam_policy_document" "exec_secrets" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = values(local.task_secrets)
  }
}
resource "aws_iam_role_policy" "exec_secrets" {
  name   = "read-task-secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.exec_secrets.json
}

# --- API task role: read reports ---
resource "aws_iam_role" "api_task" {
  name               = "${var.name}-api-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}
data "aws_iam_policy_document" "api_task" {
  statement {
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]
  }
}
resource "aws_iam_role_policy" "api_task" {
  name   = "phantom-api"
  role   = aws_iam_role.api_task.id
  policy = data.aws_iam_policy_document.api_task.json
}

# --- Worker task role: write reports + read cloud findings ---
resource "aws_iam_role" "worker_task" {
  name               = "${var.name}-worker-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}
data "aws_iam_policy_document" "worker_task" {
  statement {
    sid       = "Reports"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]
  }
  statement {
    sid = "Investigate"
    actions = [
      "guardduty:GetFindings", "guardduty:ListFindings", "guardduty:ListDetectors",
      "cloudtrail:LookupEvents",
    ]
    resources = ["*"] # these read APIs don't support resource-level scoping
  }
}
resource "aws_iam_role_policy" "worker_task" {
  name   = "phantom-worker"
  role   = aws_iam_role.worker_task.id
  policy = data.aws_iam_policy_document.worker_task.json
}

# --- OPT-IN containment policy (attach only when you wire real containment) ---
# Kept narrow and separate on purpose. Uncomment + scope to your accounts.
# data "aws_iam_policy_document" "worker_containment" {
#   statement {
#     actions   = ["iam:UpdateAccessKey"]                       # disable a leaked key
#     resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"]
#   }
#   statement {
#     actions   = ["ec2:CreateTags", "ec2:ModifyInstanceAttribute"] # quarantine SG
#     resources = ["*"]
#   }
# }
# resource "aws_iam_role_policy" "worker_containment" {
#   name   = "phantom-worker-containment"
#   role   = aws_iam_role.worker_task.id
#   policy = data.aws_iam_policy_document.worker_containment.json
# }
