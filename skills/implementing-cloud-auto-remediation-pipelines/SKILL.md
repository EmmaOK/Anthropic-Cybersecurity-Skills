---
name: implementing-cloud-auto-remediation-pipelines
description: >-
  Build event-driven auto-remediation pipelines that automatically correct cloud
  security misconfigurations within minutes of detection. Covers AWS Config Rules
  with Systems Manager Automation remediation, EventBridge-triggered Lambda
  remediators, GuardDuty automated response, and equivalent patterns in Azure
  (Policy remediation tasks) and GCP (SCC Pub/Sub + Cloud Functions). Includes
  a self-healing loop pattern with rollback safeguards, drift detection, and
  remediation audit trails for compliance evidence.
domain: cybersecurity
subdomain: cloud-security
tags:
  - auto-remediation
  - aws-config
  - eventbridge
  - lambda
  - self-healing
  - guardrails
  - cloud-security
  - devsecops
version: '1.0'
author: emmanuelokonkwo
license: Apache-2.0
nist_csf:
  - RS.MI-01
  - RS.MI-02
  - PR.IR-01
  - DE.CM-01
  - ID.IM-02
d3fend_techniques:
  - Restore
  - Disconnect
  - Isolate
---

# Implementing Cloud Auto-Remediation Pipelines

## When to Use

- When recurring misconfigurations (public S3 buckets, open security groups, disabled logging) waste engineer time being fixed manually
- When your mean time to remediate (MTTR) for known-bad configurations exceeds acceptable SLAs
- When compliance frameworks require demonstrable, time-stamped evidence of remediation actions
- When GuardDuty or Security Hub findings need automated containment before a human analyst responds
- When building self-healing infrastructure that restores secure state after accidental or malicious drift

**Do not use** for novel threat response requiring analyst judgment, for changes to production database schemas or stateful resources without human approval, or as a replacement for fixing root-cause misconfigurations in IaC.

## Prerequisites

- AWS: Config enabled in all target regions; IAM roles for `config:*`, `ssm:StartAutomationExecution`, `lambda:InvokeFunction`, `events:*`
- Azure: Azure Policy contributor role; remediation tasks require Managed Identity with appropriate resource permissions
- GCP: SCC Premium with Pub/Sub notification config (see `implementing-gcp-security-command-center`); Cloud Functions with Workload Identity

## Workflow

### Step 1: Define Remediable Rules in AWS Config

AWS Config evaluates rules continuously. Tag rules as auto-remediable and associate each with a Systems Manager Automation document.

```bash
# Enable AWS Config recording in all regions
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::ACCOUNT_ID:role/ConfigRole \
  --recording-group allSupported=true,includeGlobalResourceTypes=true

aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName=config-bucket-ACCOUNT_ID

aws configservice start-configuration-recorder --configuration-recorder-name default

# Deploy a managed Config rule: S3 buckets must block public access
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-public-access-prohibited",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  },
  "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]}
}'

# Attach auto-remediation to the rule using SSM Automation
aws configservice put-remediation-configurations --remediation-configurations '[{
  "ConfigRuleName": "s3-bucket-public-access-prohibited",
  "TargetType": "SSM_DOCUMENT",
  "TargetId": "AWS-DisableS3BucketPublicReadWrite",
  "Parameters": {
    "AutomationAssumeRole": {
      "StaticValue": {"Values": ["arn:aws:iam::ACCOUNT_ID:role/ConfigRemediationRole"]}
    },
    "S3BucketName": {
      "ResourceValue": {"Value": "RESOURCE_ID"}
    }
  },
  "Automatic": true,
  "MaximumAutomaticAttempts": 3,
  "RetryAttemptSeconds": 60
}]'
```

### Step 2: Build EventBridge-Triggered Lambda Remediators

For misconfigurations not covered by SSM Automation documents, use EventBridge to route Security Hub findings to custom Lambda functions.

```python
# lambda/remediate_sg.py — auto-revoke overly permissive ingress rules
import boto3
import json

ec2 = boto3.client('ec2')

def handler(event, context):
    for finding in event['detail']['findings']:
        resources = finding.get('Resources', [])
        for resource in resources:
            if resource['Type'] != 'AwsEc2SecurityGroup':
                continue
            sg_id = resource['Id'].split('/')[-1]
            remediate_open_ingress(sg_id, finding['Id'])

def remediate_open_ingress(sg_id, finding_id):
    sg = ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
    for rule in sg['IpPermissions']:
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0' and rule.get('FromPort') not in (80, 443):
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[rule]
                )
                print(json.dumps({
                    "action": "REVOKED_OPEN_INGRESS",
                    "security_group": sg_id,
                    "port": rule.get('FromPort'),
                    "finding_id": finding_id
                }))
```

```bash
# Deploy the Lambda
zip remediate_sg.zip lambda/remediate_sg.py
aws lambda create-function \
  --function-name auto-remediate-open-sg \
  --runtime python3.12 \
  --role arn:aws:iam::ACCOUNT_ID:role/RemediationLambdaRole \
  --handler remediate_sg.handler \
  --zip-file fileb://remediate_sg.zip \
  --timeout 60

# EventBridge rule: route Security Hub HIGH/CRITICAL EC2 SG findings to Lambda
aws events put-rule \
  --name SecurityHub-Remediate-OpenSG \
  --event-pattern '{
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported"],
    "detail": {
      "findings": {
        "Severity": {"Label": ["HIGH","CRITICAL"]},
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"],
        "Resources": {"Type": ["AwsEc2SecurityGroup"]}
      }
    }
  }'

aws events put-targets \
  --rule SecurityHub-Remediate-OpenSG \
  --targets Id=1,Arn=arn:aws:lambda:us-east-1:ACCOUNT_ID:function:auto-remediate-open-sg
```

### Step 3: GuardDuty Automated Containment

Route GuardDuty high-confidence findings to containment Lambda functions that isolate compromised EC2 instances.

```python
# lambda/isolate_instance.py — quarantine instances flagged by GuardDuty
import boto3, json

ec2 = boto3.client('ec2')

QUARANTINE_SG = 'sg-quarantine00000'  # deny-all SG, pre-created

def handler(event, context):
    detail = event['detail']
    resource = detail.get('resource', {})
    instance_id = resource.get('instanceDetails', {}).get('instanceId')
    if not instance_id:
        return
    finding_type = detail.get('type', '')

    if any(t in finding_type for t in ['CryptoCurrency', 'Backdoor', 'Trojan', 'UnauthorizedAccess']):
        isolate(instance_id, finding_type)

def isolate(instance_id, finding_type):
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[QUARANTINE_SG]
    )
    ec2.create_tags(Resources=[instance_id], Tags=[
        {'Key': 'SecurityStatus', 'Value': 'QUARANTINED'},
        {'Key': 'QuarantineReason', 'Value': finding_type}
    ])
    print(json.dumps({"action": "ISOLATED", "instance": instance_id, "reason": finding_type}))
```

```bash
# EventBridge rule for GuardDuty HIGH/CRITICAL findings
aws events put-rule \
  --name GuardDuty-Isolate-Compromised-Instance \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [{"numeric": [">=", 7.0]}],
      "resource": {"resourceType": ["Instance"]}
    }
  }'
```

### Step 4: Azure Policy Auto-Remediation

Deploy Azure Policy definitions with deployIfNotExists effects that automatically remediate non-compliant resources.

```bash
# Assign built-in policy to enable Storage Account HTTPS-only
az policy assignment create \
  --name enforce-storage-https \
  --policy /providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9 \
  --scope /subscriptions/SUBSCRIPTION_ID \
  --assign-identity \
  --location eastus

# Create remediation task to fix existing non-compliant resources
az policy remediation create \
  --name remediate-storage-https \
  --policy-assignment enforce-storage-https \
  --resource-discovery-mode ReEvaluateCompliance

# Monitor remediation status
az policy remediation show \
  --name remediate-storage-https \
  --query '{status:properties.provisioningState, succeeded:properties.deploymentSummary.successfulDeployments, failed:properties.deploymentSummary.failedDeployments}'
```

### Step 5: Implement Rollback Safeguards and Audit Trail

Prevent runaway remediation by enforcing per-resource dry-run modes, change windows, and writing an immutable audit trail.

```python
# Remediation wrapper with dry-run, rate limiting, and CloudTrail audit
import boto3, json, os
from datetime import datetime

DRY_RUN = os.environ.get('DRY_RUN', 'false').lower() == 'true'
logs = boto3.client('logs')

def remediate_with_audit(action_fn, resource_id, finding_id, metadata):
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "resource_id": resource_id,
        "finding_id": finding_id,
        "dry_run": DRY_RUN,
        "action": action_fn.__name__,
        **metadata
    }
    if DRY_RUN:
        event["result"] = "DRY_RUN_SKIPPED"
    else:
        try:
            action_fn(resource_id)
            event["result"] = "SUCCESS"
        except Exception as e:
            event["result"] = "FAILED"
            event["error"] = str(e)

    # Write to immutable CloudWatch log group with 7-year retention
    logs.put_log_events(
        logGroupName='/security/auto-remediation-audit',
        logStreamName=datetime.utcnow().strftime('%Y/%m/%d'),
        logEvents=[{'timestamp': int(datetime.utcnow().timestamp() * 1000),
                    'message': json.dumps(event)}]
    )
    return event
```

## Key Concepts

| Term | Definition |
|---|---|
| Auto-remediation | Automated correction of a detected misconfiguration without human intervention, triggered by a security finding event |
| SSM Automation Document | AWS Systems Manager runbook that executes multi-step operational tasks; used by Config as the remediation target |
| EventBridge | AWS serverless event bus that routes security findings from Config, GuardDuty, and Security Hub to Lambda remediators |
| Self-healing loop | Detect → Remediate → Verify cycle where the system continuously restores desired secure state after drift |
| Dry-run mode | Remediation pipeline execution that logs planned actions without applying changes; used to validate logic in staging |
| Change window | Time-bounded remediation execution policy that restricts automated changes to low-traffic hours to reduce blast radius |
| Quarantine SG | A pre-created AWS security group with deny-all rules used to isolate compromised EC2 instances from the network |
| Remediation task (Azure) | Azure Policy mechanism that applies a policy's deployIfNotExists effect to existing non-compliant resources retroactively |

## Tools & Systems

- **AWS Config**: Continuous configuration evaluation engine that triggers remediation on non-compliant resources
- **AWS Systems Manager Automation**: Runbook engine for executing pre-built and custom remediation documents
- **Amazon EventBridge**: Event router connecting finding sources (GuardDuty, Security Hub, Config) to Lambda remediators
- **AWS Lambda**: Serverless compute for custom remediation logic not covered by SSM Automation documents
- **Azure Policy**: Azure's policy engine with deployIfNotExists effects for automatic remediation tasks
- **GCP Cloud Functions**: Serverless compute triggered by SCC Pub/Sub exports for GCP auto-remediation
- **CloudTrail / CloudWatch Logs**: Immutable audit trail for all automated remediation actions

## Common Scenarios

### Scenario: S3 Bucket Made Public by Accident

**Context**: A developer accidentally enables ACL public access on a production data bucket. Config evaluates within 3 minutes and flags it as NON_COMPLIANT.

**Approach**:
1. AWS Config rule `s3-bucket-public-access-prohibited` evaluates the change within the Config polling interval
2. Auto-remediation invokes `AWS-DisableS3BucketPublicReadWrite` SSM document automatically
3. Bucket access is restored to private within 5 minutes of the change
4. CloudTrail records the remediation; an SNS notification alerts the security team
5. A Jira ticket is auto-created linking the Config finding to the remediation action for the post-incident record

### Scenario: GuardDuty Detects Crypto Mining on EC2

**Context**: GuardDuty fires a `CryptoCurrency:EC2/BitcoinTool.B!DNS` finding at severity 8.0 on a production web server.

**Approach**:
1. EventBridge routes the finding to `isolate_instance` Lambda within 30 seconds
2. Lambda replaces the instance's security groups with the quarantine SG (deny-all)
3. Instance stays running for forensic memory capture via SSM Run Command
4. Security team is paged; instance is terminated post-investigation after snapshot
5. Root cause (compromised SSH key from exposed .env file) is identified and rotated

## Output Format

```json
{
  "pipeline": "cloud-auto-remediation",
  "run_date": "2026-06-06T14:22:00Z",
  "dry_run": false,
  "remediations": [
    {
      "resource_id": "arn:aws:s3:::prod-data-bucket",
      "finding_id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.2/finding/abc123",
      "action": "DisableS3PublicAccess",
      "result": "SUCCESS",
      "duration_seconds": 3,
      "timestamp": "2026-06-06T14:22:01Z"
    },
    {
      "resource_id": "i-0abc123def456",
      "finding_id": "arn:aws:guardduty:us-east-1:123456789012:detector/det123/finding/find456",
      "action": "IsolateInstance",
      "result": "SUCCESS",
      "duration_seconds": 1,
      "timestamp": "2026-06-06T14:22:04Z"
    }
  ],
  "summary": {
    "total": 2,
    "success": 2,
    "failed": 0,
    "dry_run_skipped": 0
  }
}
```
