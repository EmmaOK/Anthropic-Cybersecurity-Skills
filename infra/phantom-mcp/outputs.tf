output "alb_dns_name" {
  description = "ALB DNS name — use this in Route53 CNAME for phantom-mcp.security.[organization].com"
  value       = aws_lb.phantom_mcp.dns_name
}

output "ecr_repository_url" {
  description = "ECR URL for docker push — needed by CI pipeline"
  value       = aws_ecr_repository.phantom_mcp.repository_url
}

output "api_key_secret_arn" {
  description = "Secrets Manager ARN for the phantom API key — share with developers via SSM or Okta secrets"
  value       = aws_secretsmanager_secret.phantom_api_key.arn
}

output "api_key_retrieve_command" {
  description = "Command for developers to retrieve their API key"
  value       = "aws secretsmanager get-secret-value --secret-id ${aws_secretsmanager_secret.phantom_api_key.name} --query SecretString --output text --profile AdministratorAccess-${data.aws_caller_identity.current.account_id}"
}

output "ecs_cluster_name" {
  description = "ECS cluster name — used in force-deploy command"
  value       = aws_ecs_cluster.phantom_mcp.name
}

output "ecs_service_name" {
  description = "ECS service name — used in force-deploy command"
  value       = aws_ecs_service.phantom_mcp.name
}

output "mcp_sse_url" {
  description = "MCP SSE endpoint URL for .mcp.json configuration"
  value       = "https://${aws_lb.phantom_mcp.dns_name}/sse"
  sensitive   = false
}

output "kali_private_ip" {
  description = "Private IP of the Kali pentest backend — SSH target for Phantom ECS tasks"
  value       = aws_instance.kali.private_ip
}

output "kali_instance_id" {
  description = "Kali EC2 instance ID — use to start/stop the instance via AWS console or CLI"
  value       = aws_instance.kali.id
}

output "kali_ssh_command" {
  description = "SSH command to connect to Kali manually (run from a host with VPC access)"
  value       = "ssh -i <(aws secretsmanager get-secret-value --secret-id ${aws_secretsmanager_secret.kali_ssh_key.name} --query SecretString --output text) ${var.kali_user}@${aws_instance.kali.private_ip}"
  sensitive   = false
}

output "developer_mcp_config" {
  description = "Drop this into .mcp.json for developer Claude Code setup"
  value       = <<-EOT
    {
      "phantom-skills": {
        "command": "npx",
        "args": ["-y", "mcp-remote", "https://${aws_lb.phantom_mcp.dns_name}/sse"],
        "env": {
          "MCP_REMOTE_HEADER_AUTHORIZATION": "Bearer <token-from-secrets-manager>"
        }
      }
    }
  EOT
}
