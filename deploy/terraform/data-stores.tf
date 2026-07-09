# ---------------------------------------------------------------------------
# Persistent state: RDS Postgres (campaigns/approvals/audit) + ElastiCache Redis
# (job queue) + S3 (reports) + ECR (image). Matches phantom/store.py + jobs.py.
# ---------------------------------------------------------------------------

# --- ECR (push the deploy/Dockerfile image here) ---
resource "aws_ecr_repository" "phantom" {
  name                 = var.name
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration { scan_on_push = true }
}

# --- S3 reports bucket (PHANTOM_REPORTS_BUCKET) ---
resource "aws_s3_bucket" "reports" {
  bucket = "${var.name}-reports-${data.aws_caller_identity.current.account_id}"
}
resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}
data "aws_caller_identity" "current" {}

# --- RDS Postgres ---
resource "random_password" "db" {
  length  = 24
  special = false
}

resource "aws_db_subnet_group" "phantom" {
  name       = "${var.name}-db"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_db_instance" "phantom" {
  identifier             = "${var.name}-pg"
  engine                 = "postgres"
  engine_version         = "16"
  instance_class         = var.db_instance_class
  allocated_storage      = var.db_allocated_storage
  db_name                = "phantom"
  username               = "phantom"
  password               = random_password.db.result
  db_subnet_group_name   = aws_db_subnet_group.phantom.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  storage_encrypted      = true
  skip_final_snapshot    = true    # set false + a snapshot id for prod
  deletion_protection    = false   # set true for prod
  multi_az               = false   # set true for prod HA
}

# --- ElastiCache Redis ---
resource "aws_elasticache_subnet_group" "phantom" {
  name       = "${var.name}-redis"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_elasticache_cluster" "phantom" {
  cluster_id           = "${var.name}-redis"
  engine               = "redis"
  node_type            = var.redis_node_type
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379
  subnet_group_name    = aws_elasticache_subnet_group.phantom.name
  security_group_ids   = [aws_security_group.redis.id]
}

# ---------------------------------------------------------------------------
# Secrets Manager — injected into the tasks (resolved by the execution role).
# PHANTOM_DB_URL is assembled from the RDS endpoint + generated password so the
# password never appears in plaintext env.
# ---------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "db_url" { name = "${var.name}/PHANTOM_DB_URL" }
resource "aws_secretsmanager_secret_version" "db_url" {
  secret_id     = aws_secretsmanager_secret.db_url.id
  secret_string = "postgresql+psycopg://phantom:${random_password.db.result}@${aws_db_instance.phantom.address}:5432/phantom"
}

resource "aws_secretsmanager_secret" "anthropic" { name = "${var.name}/ANTHROPIC_API_KEY" }
resource "aws_secretsmanager_secret_version" "anthropic" {
  secret_id     = aws_secretsmanager_secret.anthropic.id
  secret_string = var.anthropic_api_key
}

resource "aws_secretsmanager_secret" "admin_token" { name = "${var.name}/PHANTOM_ADMIN_TOKEN" }
resource "aws_secretsmanager_secret_version" "admin_token" {
  secret_id     = aws_secretsmanager_secret.admin_token.id
  secret_string = var.phantom_admin_token
}

# Integration keys (VIRUSTOTAL_API_KEY, SHODAN_API_KEY, THEHIVE_API_KEY, ...).
resource "aws_secretsmanager_secret" "extra" {
  for_each = var.extra_secrets
  name     = "${var.name}/${each.key}"
}
resource "aws_secretsmanager_secret_version" "extra" {
  for_each      = var.extra_secrets
  secret_id     = aws_secretsmanager_secret.extra[each.key].id
  secret_string = each.value
}

locals {
  # container `secrets` blocks: ENV_NAME => secret ARN
  task_secrets = merge(
    {
      PHANTOM_DB_URL      = aws_secretsmanager_secret.db_url.arn
      ANTHROPIC_API_KEY   = aws_secretsmanager_secret.anthropic.arn
      PHANTOM_ADMIN_TOKEN = aws_secretsmanager_secret.admin_token.arn
    },
    { for k, s in aws_secretsmanager_secret.extra : k => s.arn }
  )
}
