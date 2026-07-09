# Phantom Web Server Deployment Guide

Deploy the Phantom autonomous cybersecurity operator to AWS ECS Fargate.

## Prerequisites

- AWS CLI configured with credentials
- Docker installed locally
- Terraform >= 1.5
- Git push access to ECR

## Deployment Steps

### 1. Create S3 backend bucket (one-time)

```bash
ACCOUNT_ID=169661417290
aws s3 mb s3://tfstate-${ACCOUNT_ID}-phantom-web --region us-east-1
aws s3api put-bucket-versioning \
  --bucket tfstate-${ACCOUNT_ID}-phantom-web \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-encryption \
  --bucket tfstate-${ACCOUNT_ID}-phantom-web \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
    }]
  }'
```

### 2. Build and push Docker image

```bash
cd /path/to/Anthropic-Cybersecurity-Skills-1

# Authenticate to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin 169661417290.dkr.ecr.us-east-1.amazonaws.com

# Build image
docker build -f phantom/Dockerfile -t phantom-web:latest .

# Tag and push
docker tag phantom-web:latest 169661417290.dkr.ecr.us-east-1.amazonaws.com/phantom-web:latest
docker push 169661417290.dkr.ecr.us-east-1.amazonaws.com/phantom-web:latest
```

### 3. Initialize Terraform

```bash
cd infra/phantom

terraform init -upgrade

# Verify plan
terraform plan
```

### 4. Create Secrets Manager entries

Before applying, populate the required secrets:

```bash
# Anthropic API Key
aws secretsmanager put-secret-value \
  --secret-id phantom-web/production/anthropic-api-key \
  --secret-string "sk-..." \
  --region us-east-1

# Admin Token (optional)
aws secretsmanager put-secret-value \
  --secret-id phantom-web/production/admin-token \
  --secret-string "$(openssl rand -hex 32)" \
  --region us-east-1

# Google Chat Webhook (optional)
aws secretsmanager put-secret-value \
  --secret-id phantom-web/production/google-chat-webhook \
  --secret-string "https://chat.googleapis.com/v1/spaces/..." \
  --region us-east-1
```

### 5. Deploy infrastructure

```bash
cd infra/phantom

terraform apply

# Note the outputs:
#   - phantom_url: https://phantom.tstsecurity.pivotree.engineering
#   - ecr_repository_url: ECR URL for future image pushes
#   - ecs_service_name: For ECS exec access
```

### 6. Verify deployment

```bash
# Check ECS service
aws ecs describe-services \
  --cluster phantom-web-production \
  --services phantom-web-production \
  --region us-east-1

# Check task status
aws ecs list-tasks \
  --cluster phantom-web-production \
  --region us-east-1

# View logs
aws logs tail /ecs/phantom-web/production --follow --region us-east-1

# Test health endpoint (requires VPN access)
curl -v https://phantom.tstsecurity.pivotree.engineering/health
```

## Post-Deployment

1. **Access the UI** (VPN required):
   - Navigate to `https://phantom.tstsecurity.pivotree.engineering`

2. **Test phishing investigation API**:
   ```bash
   curl -X POST https://phantom.tstsecurity.pivotree.engineering/api/webhook/phishing-report \
     -H "Content-Type: application/json" \
     -d '{
       "subject": "Urgent Account Verification",
       "from_address": "noreply@fake-bank.com",
       "body_text": "Click here to verify: http://malicious-site.com",
       "reported_by": "test@company.com"
     }'
   ```

3. **View running tasks**:
   ```bash
   aws ecs describe-tasks \
     --cluster phantom-web-production \
     --tasks $(aws ecs list-tasks --cluster phantom-web-production --query 'taskArns[0]' --output text) \
     --region us-east-1
   ```

## Troubleshooting

**Tasks not starting:**
```bash
# Check service events
aws ecs describe-services \
  --cluster phantom-web-production \
  --services phantom-web-production \
  --region us-east-1 | jq '.services[0].events'

# Check task logs
aws logs tail /ecs/phantom-web/production --follow --region us-east-1
```

**Health check failing:**
- Verify Anthropic API key is set in Secrets Manager
- Check that skill_loader.py can read index.json
- Ensure /phantom/templates and /phantom/static directories are copied in Dockerfile

**ALB not routing traffic:**
- Verify security group allows 443 from your IP: `aws ec2 describe-security-groups --group-ids sg-... --region us-east-1`
- Check Route53 DNS: `nslookup phantom.tstsecurity.pivotree.engineering`
- Verify ACM certificate: `aws acm describe-certificate --certificate-arn <arn> --region us-east-1`

## Cleanup

To destroy infrastructure (not recommended for production):

```bash
cd infra/phantom
terraform destroy
```

## Updates & Redeployment

**Push new image:**
```bash
docker tag phantom-web:v2 169661417290.dkr.ecr.us-east-1.amazonaws.com/phantom-web:v2
docker push 169661417290.dkr.ecr.us-east-1.amazonaws.com/phantom-web:v2

# Update task definition image_tag variable
cd infra/phantom
terraform apply -var="image_tag=v2"
```

ECS will automatically roll out new tasks using the new image.
