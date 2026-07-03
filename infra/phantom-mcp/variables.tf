variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment tag (e.g. production, staging)"
  type        = string
  default     = "production"
}

variable "vpc_id" {
  description = "VPC ID where the ECS service and ALB will be deployed"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for the ECS Fargate tasks (min 2 AZs)"
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for the internal ALB (or private if VPN-accessible)"
  type        = list(string)
}

variable "alb_internal" {
  description = "Set to true to make the ALB internal (VPN-only access). false = internet-facing with WAF."
  type        = bool
  default     = true
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to reach the ALB (e.g. VPN CIDR, office IPs)"
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

variable "acm_certificate_arn" {
  description = "ARN of ACM certificate for HTTPS on the ALB (e.g. *.security.[organization].com)"
  type        = string
}

variable "image_tag" {
  description = "Docker image tag to deploy (set by CI pipeline)"
  type        = string
  default     = "latest"
}

variable "task_cpu" {
  description = "Fargate task CPU units (256=0.25vCPU, 512=0.5vCPU, 1024=1vCPU)"
  type        = number
  default     = 512
}

variable "task_memory" {
  description = "Fargate task memory in MB"
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "Number of ECS tasks to run (min 2 for HA)"
  type        = number
  default     = 2
}

variable "bedrock_model_id" {
  description = "Bedrock cross-region inference profile ID for the task agent. Verify with: aws bedrock list-inference-profiles --region us-east-1"
  type        = string
  default     = "us.anthropic.claude-opus-4-8"
}

variable "vpc_cidr_block" {
  description = "VPC CIDR block — used to scope ECS task egress to VPC-internal traffic (AWS service VPC endpoints)"
  type        = string
  default     = "10.0.0.0/16"
}

variable "kali_instance_type" {
  description = "EC2 instance type for the Kali pentest backend (min t3.medium for tool databases)"
  type        = string
  default     = "t3.medium"
}

variable "kali_user" {
  description = "SSH username on the pentest backend instance (ubuntu for Ubuntu AMI)"
  type        = string
  default     = "ubuntu"
}
