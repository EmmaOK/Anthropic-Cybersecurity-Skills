terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  backend "s3" {
    bucket  = "tfstate-169661417290-phantom-web"
    key     = "phantom-web/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

locals {
  name_prefix = "phantom-web"
  common_tags = {
    Project     = "phantom-web"
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = "security-team"
  }

  # On Bedrock the app authenticates via the task role, so the API-key secret
  # is not injected (and need not be populated).
  container_secrets = concat(
    var.use_bedrock ? [] : [
      {
        name      = "ANTHROPIC_API_KEY"
        valueFrom = aws_secretsmanager_secret.anthropic_api_key.arn
      },
    ],
    [
      {
        name      = "PHANTOM_ADMIN_TOKEN"
        valueFrom = aws_secretsmanager_secret.phantom_admin_token.arn
      },
      {
        name      = "GOOGLE_CHAT_WEBHOOK"
        valueFrom = aws_secretsmanager_secret.google_chat_webhook.arn
      },
    ]
  )

  container_environment = concat(
    [
      { name = "PORT", value = "8080" },
      { name = "AWS_REGION", value = var.aws_region },
    ],
    var.use_bedrock ? [{ name = "PHANTOM_USE_BEDROCK", value = "1" }] : []
  )
}

# ── ECR Repository ─────────────────────────────────────────────────────────────

resource "aws_ecr_repository" "phantom_web" {
  name                 = "${local.name_prefix}"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "phantom_web" {
  repository = aws_ecr_repository.phantom_web.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

# ── CloudWatch Logs ────────────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "phantom_web" {
  name              = "/ecs/${local.name_prefix}/${var.environment}"
  retention_in_days = 90
}

# ── Secrets Manager ────────────────────────────────────────────────────────────

resource "aws_secretsmanager_secret" "anthropic_api_key" {
  name        = "${local.name_prefix}/${var.environment}/anthropic-api-key"
  description = "Anthropic API key for Phantom autonomous operator"

  tags = local.common_tags

  lifecycle {
    ignore_changes = [tags]
  }
}

resource "aws_secretsmanager_secret" "phantom_admin_token" {
  name        = "${local.name_prefix}/${var.environment}/admin-token"
  description = "Admin token for Phantom approval workflows"

  tags = local.common_tags

  lifecycle {
    ignore_changes = [tags]
  }
}

resource "aws_secretsmanager_secret" "google_chat_webhook" {
  name        = "${local.name_prefix}/${var.environment}/google-chat-webhook"
  description = "Google Chat webhook for Phantom notifications"

  tags = local.common_tags

  lifecycle {
    ignore_changes = [tags]
  }
}

# ── Security Groups ────────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb-${var.environment}"
  description = "ALB for phantom-web - allows HTTPS from allowed CIDRs"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from allowed CIDRs (VPN / office / peered VPCs)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  egress {
    description = "Forward to ECS tasks"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-alb" })
}

resource "aws_security_group" "ecs" {
  name        = "${local.name_prefix}-ecs-${var.environment}"
  description = "ECS tasks for phantom-web - only accepts traffic from ALB"
  vpc_id      = var.vpc_id

  ingress {
    description     = "From ALB only"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "HTTPS to VPC endpoints and AWS services"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr_block]
  }

  egress {
    description = "HTTPS to internet - external APIs (AWS services, Claude API)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-ecs" })
}

# ── ALB ────────────────────────────────────────────────────────────────────────

resource "aws_lb" "phantom_web" {
  name               = "${local.name_prefix}-${var.environment}"
  internal           = var.alb_internal
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = var.enable_deletion_protection

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.bucket
    prefix  = "${local.name_prefix}"
    enabled = true
  }

  tags = local.common_tags
}

resource "aws_lb_target_group" "phantom_web" {
  name        = "${local.name_prefix}-${var.environment}"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/health"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "200"
  }

  stickiness {
    type    = "lb_cookie"
    enabled = false
  }

  tags = local.common_tags
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.phantom_web.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.phantom_web.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.phantom_web.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# S3 bucket for ALB access logs
resource "aws_s3_bucket" "alb_logs" {
  bucket        = "${local.name_prefix}-alb-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
  tags          = local.common_tags
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = 90
    }
  }
}

# ── ECS Cluster ────────────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "phantom_web" {
  name = "${local.name_prefix}-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = local.common_tags
}

resource "aws_ecs_cluster_capacity_providers" "phantom_web" {
  cluster_name       = aws_ecs_cluster.phantom_web.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# ── ECS Task Definition ────────────────────────────────────────────────────────

resource "aws_ecs_task_definition" "phantom_web" {
  family                   = "${local.name_prefix}-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "phantom-web"
    image     = "${aws_ecr_repository.phantom_web.repository_url}:${var.image_tag}"
    essential = true

    portMappings = [{
      containerPort = 8080
      protocol      = "tcp"
    }]

    environment = local.container_environment

    secrets = local.container_secrets

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.phantom_web.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "python3 -c \"import urllib.request; urllib.request.urlopen('http://localhost:8080/health')\" || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 15
    }
  }])

  tags = local.common_tags
}

# ── ECS Service ────────────────────────────────────────────────────────────────

resource "aws_ecs_service" "phantom_web" {
  name            = "${local.name_prefix}-${var.environment}"
  cluster         = aws_ecs_cluster.phantom_web.id
  task_definition = aws_ecs_task_definition.phantom_web.arn
  desired_count   = var.desired_count

  capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.phantom_web.arn
    container_name   = "phantom-web"
    container_port   = 8080
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_controller {
    type = "ECS"
  }

  enable_execute_command = true

  health_check_grace_period_seconds = 30

  depends_on = [aws_lb_listener.https]

  tags = local.common_tags

  lifecycle {
    ignore_changes = [task_definition, desired_count]
  }
}

# ── Auto Scaling ───────────────────────────────────────────────────────────────

resource "aws_appautoscaling_target" "phantom_web" {
  max_capacity       = 6
  min_capacity       = var.desired_count
  resource_id        = "service/${aws_ecs_cluster.phantom_web.name}/${aws_ecs_service.phantom_web.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "phantom_web_cpu" {
  name               = "${local.name_prefix}-cpu-${var.environment}"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.phantom_web.resource_id
  scalable_dimension = aws_appautoscaling_target.phantom_web.scalable_dimension
  service_namespace  = aws_appautoscaling_target.phantom_web.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

# ── Route53 DNS Record ─────────────────────────────────────────────────────────

resource "aws_route53_record" "phantom_web" {
  zone_id = var.route53_zone_id
  name    = "phantom.${var.dns_domain}"
  type    = "A"

  alias {
    name                   = aws_lb.phantom_web.dns_name
    zone_id                = aws_lb.phantom_web.zone_id
    evaluate_target_health = true
  }
}

# ── ALB Access Logs Bucket Policy ──────────────────────────────────────────────

data "aws_elb_service_account" "main" {}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = data.aws_elb_service_account.main.arn }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.alb_logs.arn}/${local.name_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    }]
  })
}

# ── Data Sources ───────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
