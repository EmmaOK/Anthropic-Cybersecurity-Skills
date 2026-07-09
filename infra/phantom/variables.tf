variable "aws_region" {
  type        = string
  description = "AWS region"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Environment (production, staging, etc.)"
  default     = "production"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID where Phantom will be deployed"
  default     = "vpc-0f925c1c0bee69309"
}

variable "vpc_cidr_block" {
  type        = string
  description = "VPC CIDR block for internal egress rules"
  default     = "10.0.0.0/16"
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Public subnet IDs for ALB (must be in >= 2 AZs)"
  default     = ["subnet-0fe34f5aea894213a", "subnet-0b5283c08ca248f9d", "subnet-0a0b75b2bd17a91a0"]
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnet IDs for ECS tasks (must be in >= 2 AZs)"
  default     = ["subnet-04ea92cfdde0596b3", "subnet-07f14fd39b6c29fcf", "subnet-0d16bef08d127a52c"]
}

variable "allowed_cidr_blocks" {
  type        = list(string)
  description = "CIDR blocks allowed to access the ALB (VPN, office, peered VPCs)"
  default     = ["0.0.0.0/0"]
}

variable "acm_certificate_arn" {
  type        = string
  description = "ACM certificate ARN for HTTPS listener"
  default     = "arn:aws:acm:us-east-1:169661417290:certificate/e1416471-a960-4de3-a9a3-7a204dc87f91"
}

variable "route53_zone_id" {
  type        = string
  description = "Route53 hosted zone ID"
  default     = "Z09638163IEREBBF4EHG9"
}

variable "dns_domain" {
  type        = string
  description = "DNS domain for Route53"
  default     = "tstsecurity.pivotree.engineering"
}

variable "alb_internal" {
  type        = bool
  description = "Whether ALB is internal (true) or internet-facing (false)"
  default     = true
}

variable "task_cpu" {
  type        = string
  description = "ECS task CPU (256, 512, 1024, 2048, 4096)"
  default     = "1024"
}

variable "task_memory" {
  type        = string
  description = "ECS task memory (512, 1024, 2048, 3072, 4096, ...)"
  default     = "2048"
}

variable "desired_count" {
  type        = number
  description = "Desired number of ECS tasks"
  default     = 2
}

variable "image_tag" {
  type        = string
  description = "Docker image tag to deploy"
  default     = "latest"
}

variable "use_bedrock" {
  type        = bool
  description = "Route Phantom inference through Amazon Bedrock (task role) instead of the Anthropic API key"
  default     = false
}

variable "enable_deletion_protection" {
  type        = bool
  description = "ALB deletion protection. Disable to allow scheme changes / teardown during testing."
  default     = true
}

variable "defectdojo_url" {
  type        = string
  description = "DefectDojo base URL (e.g. https://defectdojo.example.com). Empty disables the DEFECTDOJO_URL env var."
  default     = ""
}
