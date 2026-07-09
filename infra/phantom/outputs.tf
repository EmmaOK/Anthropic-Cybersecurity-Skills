output "alb_dns_name" {
  value       = aws_lb.phantom_web.dns_name
  description = "DNS name of the ALB"
}

output "alb_arn" {
  value       = aws_lb.phantom_web.arn
  description = "ARN of the ALB"
}

output "ecr_repository_url" {
  value       = aws_ecr_repository.phantom_web.repository_url
  description = "ECR repository URL for Phantom images"
}

output "ecs_cluster_name" {
  value       = aws_ecs_cluster.phantom_web.name
  description = "ECS cluster name"
}

output "ecs_service_name" {
  value       = aws_ecs_service.phantom_web.name
  description = "ECS service name"
}

output "cloudwatch_log_group" {
  value       = aws_cloudwatch_log_group.phantom_web.name
  description = "CloudWatch log group for Phantom"
}

output "phantom_url" {
  value       = "https://phantom.${var.dns_domain}"
  description = "Public URL for Phantom (internal access only)"
}

output "secrets_manager_keys" {
  value = {
    anthropic_api_key      = aws_secretsmanager_secret.anthropic_api_key.name
    phantom_admin_token    = aws_secretsmanager_secret.phantom_admin_token.name
    google_chat_webhook    = aws_secretsmanager_secret.google_chat_webhook.name
  }
  description = "Secrets Manager secret names to populate"
}
