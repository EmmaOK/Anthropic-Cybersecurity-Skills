# Phantom on AWS Fargate — Terraform

A starting Terraform layout for the API/worker/queue/state architecture. It maps
1:1 onto the app: `phantom/server.py` (API), `phantom/worker.py` (worker),
`jobs.py` (Redis queue), `store.py` (Postgres + S3).

> **This is a reviewed-before-apply scaffold, not a turnkey module.** It has not
> been `terraform apply`-tested against a live account. Read every file, adjust
> for your org (state backend, prod flags, CIDRs, cert), and run `plan` first.

## What it creates

| File | Resources |
|---|---|
| `network.tf` | VPC (public+private subnets, NAT), 4 security groups |
| `data-stores.tf` | ECR repo, S3 reports bucket, RDS Postgres, ElastiCache Redis, Secrets Manager |
| `iam.tf` | execution role + `api`/`worker` task roles (least privilege; opt-in containment policy) |
| `alb.tf` | ALB, target group, HTTP/HTTPS listeners, optional WAF |
| `ecs.tf` | cluster, `api` + `worker` task defs & services, CPU autoscaling |
| `outputs.tf` | ALB URL, ECR URL, GuardDuty webhook URL, endpoints |

## How the app wires in

The task definitions set exactly the env the app reads:
- `PHANTOM_QUEUE_BACKEND=redis` + `REDIS_URL` → the Redis job queue (`jobs.py`)
- `PHANTOM_DB_URL` (from Secrets Manager) → Postgres (`store.py`)
- `PHANTOM_REPORTS_BUCKET` → S3 for reports (`store.py`)
- `ANTHROPIC_API_KEY`, `PHANTOM_ADMIN_TOKEN`, and `extra_secrets` → Secrets Manager

API and worker run the **same image**, differing only by container `command`.

## Deploy order

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # fill in (keep secrets out of git)

terraform init
terraform apply -target=aws_ecr_repository.phantom   # create the repo first

# build & push the image (context = repo root, uses deploy/Dockerfile)
REPO=$(terraform output -raw ecr_repository_url)
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin "${REPO%/*}"
docker build -t "$REPO:v1" -f ../Dockerfile ../..
docker push "$REPO:v1"

terraform apply         # stand up everything else (image_tag = "v1")
```

Then: point an **EventBridge → API Destination** at the `guardduty_webhook` output
(with a `service-guardduty` bearer token), and put DNS + your OIDC/SSO in front of
the ALB for the browser UI.

## Before production — the flags to flip

- `data-stores.tf`: RDS `multi_az = true`, `deletion_protection = true`, `skip_final_snapshot = false`.
- `network.tf`: `single_nat_gateway = false` (one NAT per AZ).
- `versions.tf`: enable the S3 remote state backend.
- `alb.tf`: supply `certificate_arn` (forces HTTPS + HTTP→HTTPS redirect) and add an
  `authenticate-oidc` action for SSO on the browser UI.
- `iam.tf`: attach the opt-in containment policy only when you wire real containment
  execution (today the worker investigates and files approvals; it does not act).
- `ecs.tf`: switch worker autoscaling from CPU to **Redis queue depth** (publish `LLEN
  phantom:jobs:queue` as a CloudWatch metric and target-track it).

## Not included (deliberate)

- **Offensive/Kali plane** — isolate that in a **separate account/VPC**, not this cluster.
- **Overwatch dashboard** — deploy as its own service (it reads the same stores).
- DNS/Route53 records and the ACM cert itself (bring your own).
