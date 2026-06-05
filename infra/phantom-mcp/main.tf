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
    bucket  = "tfstate-[AWS-ACCOUNT-ID]-phantom-mcp"
    key     = "phantom-mcp/terraform.tfstate"
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
  name_prefix = "phantom-mcp"
  common_tags = {
    Project     = "phantom-mcp"
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = "security-team"
  }
}

# ── ECR Repository ─────────────────────────────────────────────────────────────

resource "aws_ecr_repository" "phantom_mcp" {
  name                 = "${local.name_prefix}"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "phantom_mcp" {
  repository = aws_ecr_repository.phantom_mcp.name

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

resource "aws_cloudwatch_log_group" "phantom_mcp" {
  name              = "/ecs/${local.name_prefix}/${var.environment}"
  retention_in_days = 90
}

# ── API Key Secret (Secrets Manager) ──────────────────────────────────────────

resource "aws_secretsmanager_secret" "admin_shutdown_token" {
  name        = "${local.name_prefix}/${var.environment}/admin-shutdown-token"
  description = "Admin shutdown/throttle token for phantom-mcp /admin/* endpoints"

  tags = local.common_tags

  lifecycle {
    ignore_changes = [tags]
  }
}

resource "random_password" "phantom_api_key" {
  length  = 40
  special = false
}

resource "aws_secretsmanager_secret" "phantom_api_key" {
  name        = "${local.name_prefix}/${var.environment}/api-key"
  description = "Bearer token for phantom-mcp HTTP API — distribute to developers via SSM or shared secret"

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "phantom_api_key" {
  secret_id     = aws_secretsmanager_secret.phantom_api_key.id
  secret_string = random_password.phantom_api_key.result
}

# ── Security Groups ────────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb-${var.environment}"
  description = "ALB for phantom-mcp - allows HTTPS from allowed CIDRs"
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
  description = "ECS tasks for phantom-mcp - only accepts traffic from ALB"
  vpc_id      = var.vpc_id

  ingress {
    description     = "From ALB only"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Outbound for AWS APIs (ECR, Secrets Manager, CloudWatch)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-ecs" })
}

# ── ALB ────────────────────────────────────────────────────────────────────────

resource "aws_lb" "phantom_mcp" {
  name               = "${local.name_prefix}-${var.environment}"
  internal           = var.alb_internal
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = var.environment == "production"

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.bucket
    prefix  = "${local.name_prefix}"
    enabled = true
  }

  tags = local.common_tags
}

resource "aws_lb_target_group" "phantom_mcp" {
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

  # SSE connections can be long-lived — increase idle timeout
  stickiness {
    type    = "lb_cookie"
    enabled = false
  }

  tags = local.common_tags
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.phantom_mcp.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.phantom_mcp.arn
  }
}

# HTTP → HTTPS redirect
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.phantom_mcp.arn
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

resource "aws_ecs_cluster" "phantom_mcp" {
  name = "${local.name_prefix}-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = local.common_tags
}

resource "aws_ecs_cluster_capacity_providers" "phantom_mcp" {
  cluster_name       = aws_ecs_cluster.phantom_mcp.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# ── ECS Task Definition ────────────────────────────────────────────────────────

resource "aws_ecs_task_definition" "phantom_mcp" {
  family                   = "${local.name_prefix}-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "phantom-mcp"
    image     = "${aws_ecr_repository.phantom_mcp.repository_url}:${var.image_tag}"
    essential = true

    portMappings = [{
      containerPort = 8080
      protocol      = "tcp"
    }]

    environment = [
      { name = "PORT", value = "8080" }
    ]

    secrets = [
      {
        name      = "PHANTOM_API_KEY"
        valueFrom = aws_secretsmanager_secret.phantom_api_key.arn
      },
      {
        name      = "ADMIN_SHUTDOWN_TOKEN"
        valueFrom = aws_secretsmanager_secret.admin_shutdown_token.arn
      }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.phantom_mcp.name
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

resource "aws_ecs_service" "phantom_mcp" {
  name            = "${local.name_prefix}-${var.environment}"
  cluster         = aws_ecs_cluster.phantom_mcp.id
  task_definition = aws_ecs_task_definition.phantom_mcp.arn
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
    target_group_arn = aws_lb_target_group.phantom_mcp.arn
    container_name   = "phantom-mcp"
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

  # SSE connections are long-lived — give tasks time to drain
  health_check_grace_period_seconds = 30

  depends_on = [aws_lb_listener.https]

  tags = local.common_tags

  lifecycle {
    ignore_changes = [task_definition, desired_count]
  }
}

# ── Auto Scaling ───────────────────────────────────────────────────────────────

resource "aws_appautoscaling_target" "phantom_mcp" {
  max_capacity       = 6
  min_capacity       = var.desired_count
  resource_id        = "service/${aws_ecs_cluster.phantom_mcp.name}/${aws_ecs_service.phantom_mcp.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

# ── Route53 Alias Record ───────────────────────────────────────────────────────

resource "aws_route53_record" "phantom_mcp" {
  zone_id = "Z09638163IEREBBF4EHG9"
  name    = "phantom-mcp.tstsecurity.[org].engineering"
  type    = "A"

  alias {
    name                   = aws_lb.phantom_mcp.dns_name
    zone_id                = aws_lb.phantom_mcp.zone_id
    evaluate_target_health = true
  }
}

# ── ALB Access Logs Bucket Policy (required by AWS ELB service account) ────────

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

resource "aws_appautoscaling_policy" "phantom_mcp_cpu" {
  name               = "${local.name_prefix}-cpu-${var.environment}"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.phantom_mcp.resource_id
  scalable_dimension = aws_appautoscaling_target.phantom_mcp.scalable_dimension
  service_namespace  = aws_appautoscaling_target.phantom_mcp.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
