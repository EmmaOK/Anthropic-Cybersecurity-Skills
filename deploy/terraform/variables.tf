variable "region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "name" {
  description = "Name prefix for all resources."
  type        = string
  default     = "phantom"
}

# --- Networking ---
variable "vpc_cidr" {
  type    = string
  default = "10.60.0.0/16"
}

variable "az_count" {
  description = "Number of AZs (private+public subnet pairs)."
  type        = number
  default     = 2
}

variable "allowed_cidrs" {
  description = "CIDRs allowed to reach the ALB (lock down to your VPN/office; webhooks come via API Destination in-AWS)."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# --- Image ---
variable "image_tag" {
  description = "Tag of the phantom image in the created ECR repo (build & push separately)."
  type        = string
  default     = "latest"
}

# --- Fargate sizing ---
variable "api_cpu" { default = 512 }      # 0.5 vCPU
variable "api_memory" { default = 1024 }
variable "api_desired" { default = 2 }
variable "api_max" { default = 6 }

variable "worker_cpu" { default = 1024 }  # 1 vCPU — agent runs are token/CPU heavy
variable "worker_memory" { default = 2048 }
variable "worker_desired" { default = 2 }
variable "worker_max" { default = 10 }

# --- Data stores ---
variable "db_instance_class" { default = "db.t4g.micro" }   # bump for prod
variable "db_allocated_storage" { default = 20 }
variable "redis_node_type" { default = "cache.t4g.micro" }

# --- TLS / ingress (optional) ---
variable "certificate_arn" {
  description = "ACM cert ARN for the HTTPS listener. If empty, only an HTTP listener is created (dev only)."
  type        = string
  default     = ""
}

variable "enable_waf" {
  type    = bool
  default = true
}

# --- Secrets the app reads. Provide the ANthropic key; others are optional. ---
# These are written into Secrets Manager and injected into the tasks.
variable "anthropic_api_key" {
  type      = string
  sensitive = true
}

variable "phantom_admin_token" {
  description = "Bootstrap admin bearer token (role=admin). Rotate to an auth file for real multi-user."
  type        = string
  sensitive   = true
}

variable "extra_secrets" {
  description = "Map of ENV_VAR_NAME => secret string for integrations (VIRUSTOTAL_API_KEY, SHODAN_API_KEY, THEHIVE_API_KEY, MISP_API_KEY, JIRA_API_TOKEN, ...). Injected into api+worker."
  type        = map(string)
  default     = {}
  sensitive   = true
}
