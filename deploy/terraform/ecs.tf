# ---------------------------------------------------------------------------
# One image, two Fargate services (the API/worker split from jobs.py/worker.py):
#   api    — behind the ALB, uvicorn; scales on request load
#   worker — no inbound, python phantom/worker.py; scales on CPU (queue depth ideal)
# They differ only by container `command` and LB attachment.
# ---------------------------------------------------------------------------
resource "aws_ecs_cluster" "phantom" {
  name = var.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

locals {
  image = "${aws_ecr_repository.phantom.repository_url}:${var.image_tag}"

  # env shared by both roles; the queue + state backends point at the managed services.
  common_env = [
    { name = "PHANTOM_QUEUE_BACKEND", value = "redis" },
    { name = "REDIS_URL", value = "redis://${aws_elasticache_cluster.phantom.cache_nodes[0].address}:6379/0" },
    { name = "PHANTOM_REPORTS_BUCKET", value = aws_s3_bucket.reports.id },
    { name = "AWS_DEFAULT_REGION", value = var.region },
    { name = "PHANTOM_BASE_URL", value = "https://${aws_lb.api.dns_name}" },
  ]

  # secrets shared by both (resolved by the execution role)
  common_secrets = [for name, arn in local.task_secrets : { name = name, valueFrom = arn }]
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/${var.name}/api"
  retention_in_days = 30
}
resource "aws_cloudwatch_log_group" "worker" {
  name              = "/ecs/${var.name}/worker"
  retention_in_days = 30
}

# --- API task ---
resource "aws_ecs_task_definition" "api" {
  family                   = "${var.name}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.api_cpu
  memory                   = var.api_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.api_task.arn
  container_definitions = jsonencode([{
    name      = "api"
    image     = local.image
    essential = true
    command   = ["uvicorn", "phantom.server:app", "--host", "0.0.0.0", "--port", "8080"]
    portMappings = [{ containerPort = 8080, protocol = "tcp" }]
    environment = local.common_env
    secrets     = local.common_secrets
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.api.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "api"
      }
    }
  }])
}

# --- Worker task ---
resource "aws_ecs_task_definition" "worker" {
  family                   = "${var.name}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.worker_task.arn
  container_definitions = jsonencode([{
    name        = "worker"
    image       = local.image
    essential   = true
    command     = ["python", "phantom/worker.py"]
    environment = local.common_env
    secrets     = local.common_secrets
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.worker.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "worker"
      }
    }
  }])
}

# --- API service (LB-attached) ---
resource "aws_ecs_service" "api" {
  name            = "${var.name}-api"
  cluster         = aws_ecs_cluster.phantom.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_desired
  launch_type     = "FARGATE"
  network_configuration {
    subnets         = module.vpc.private_subnets
    security_groups = [aws_security_group.service.id]
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8080
  }
  depends_on = [aws_lb_listener.http]
}

# --- Worker service (no LB) ---
resource "aws_ecs_service" "worker" {
  name            = "${var.name}-worker"
  cluster         = aws_ecs_cluster.phantom.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_desired
  launch_type     = "FARGATE"
  network_configuration {
    subnets         = module.vpc.private_subnets
    security_groups = [aws_security_group.service.id]
  }
}

# ---------------------------------------------------------------------------
# Autoscaling — API on CPU, worker on CPU. For the worker, queue depth is the
# better signal: publish Redis LLEN as a CloudWatch metric (or use KEDA on EKS)
# and target-track that instead. CPU is a safe default to start.
# ---------------------------------------------------------------------------
resource "aws_appautoscaling_target" "api" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.phantom.name}/${aws_ecs_service.api.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = var.api_desired
  max_capacity       = var.api_max
}
resource "aws_appautoscaling_policy" "api_cpu" {
  name               = "${var.name}-api-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.api.service_namespace
  resource_id        = aws_appautoscaling_target.api.resource_id
  scalable_dimension = aws_appautoscaling_target.api.scalable_dimension
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification { predefined_metric_type = "ECSServiceAverageCPUUtilization" }
    target_value = 60
  }
}

resource "aws_appautoscaling_target" "worker" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.phantom.name}/${aws_ecs_service.worker.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = var.worker_desired
  max_capacity       = var.worker_max
}
resource "aws_appautoscaling_policy" "worker_cpu" {
  name               = "${var.name}-worker-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.worker.service_namespace
  resource_id        = aws_appautoscaling_target.worker.resource_id
  scalable_dimension = aws_appautoscaling_target.worker.scalable_dimension
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification { predefined_metric_type = "ECSServiceAverageCPUUtilization" }
    target_value = 65
  }
}
