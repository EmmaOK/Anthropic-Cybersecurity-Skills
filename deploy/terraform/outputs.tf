output "alb_url" {
  description = "Phantom control-plane URL (put DNS + a cert in front for prod)."
  value       = var.certificate_arn == "" ? "http://${aws_lb.api.dns_name}" : "https://${aws_lb.api.dns_name}"
}

output "ecr_repository_url" {
  description = "Push the deploy/Dockerfile image here before apply completes the services."
  value       = aws_ecr_repository.phantom.repository_url
}

output "reports_bucket" {
  value = aws_s3_bucket.reports.id
}

output "rds_endpoint" {
  value = aws_db_instance.phantom.address
}

output "redis_endpoint" {
  value = aws_elasticache_cluster.phantom.cache_nodes[0].address
}

output "guardduty_webhook" {
  description = "Point an EventBridge API Destination here (with a service-guardduty bearer token)."
  value       = "${var.certificate_arn == "" ? "http" : "https"}://${aws_lb.api.dns_name}/api/webhook/guardduty"
}
