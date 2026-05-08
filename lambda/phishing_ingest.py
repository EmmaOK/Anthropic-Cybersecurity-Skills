"""
AWS Lambda — Phishing Email Ingest

Triggered by: S3 PutObject event (SES → S3 bucket)

Flow:
  1. SES receives email at phishing@company.com
  2. SES receipt rule stores the raw .eml in S3 (phishing-inbox bucket)
  3. S3 notifies Lambda via event notification
  4. Lambda fetches the .eml from S3
  5. Lambda POSTs to Phantom's /api/investigate/phishing endpoint
  6. Lambda publishes verdict to SNS (alerts security team via email/Slack)

Environment variables (set in SAM template / Lambda console):
  PHANTOM_URL         — Phantom web server URL, e.g. https://phantom.corp.com
  PHANTOM_API_KEY     — optional bearer token for Phantom (if auth is enabled)
  SNS_TOPIC_ARN       — ARN of SNS topic for verdict notifications
  INVESTIGATION_TIMEOUT — seconds to wait for Phantom (default 180)

IAM permissions required:
  s3:GetObject        — read emails from the inbox bucket
  sns:Publish         — send verdict notifications
  secretsmanager:GetSecretValue — optional, if Phantom URL/key stored in Secrets Manager

Deploy with SAM: see template.yaml in this directory.
"""

import json
import os
import urllib.error
import urllib.request
from urllib.parse import quote

import boto3

PHANTOM_URL  = os.environ.get("PHANTOM_URL", "").rstrip("/")
PHANTOM_KEY  = os.environ.get("PHANTOM_API_KEY", "")
SNS_TOPIC    = os.environ.get("SNS_TOPIC_ARN", "")
TIMEOUT      = int(os.environ.get("INVESTIGATION_TIMEOUT", "180"))

s3_client  = boto3.client("s3")
sns_client = boto3.client("sns") if SNS_TOPIC else None


def _get_email_from_s3(bucket: str, key: str) -> str:
    """Fetch raw .eml content from S3."""
    obj = s3_client.get_object(Bucket=bucket, Key=key)
    raw = obj["Body"].read()
    # SES stores emails as raw bytes; decode best-effort
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


def _extract_reporter(s3_key: str, raw_email: str) -> str:
    """
    Extract the reporter's email from the forwarded email's From: header.
    When an employee forwards a phishing email to phishing@corp.com, the outer
    email's From: is the employee. To: is always phishing@corp.com (not useful).
    """
    import re
    # Extract email address from From: header (handles "Name <email>" and bare formats)
    m = re.search(r'^From:\s*.*?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})',
                  raw_email, re.MULTILINE | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return ""


def _call_phantom(raw_email: str, reported_by: str, report_id: str) -> dict:
    """POST to Phantom /api/investigate/phishing. Returns result dict."""
    if not PHANTOM_URL:
        raise ValueError("PHANTOM_URL environment variable not set")

    payload = json.dumps({
        "raw_email":   raw_email,
        "reported_by": reported_by,
        "report_id":   report_id,
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Accept":        "application/json",
    }
    if PHANTOM_KEY:
        headers["Authorization"] = f"Bearer {PHANTOM_KEY}"

    req = urllib.request.Request(
        f"{PHANTOM_URL}/api/investigate/phishing",
        data=payload,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        raise RuntimeError(f"Phantom API HTTP {e.code}: {detail[:500]}")


def _notify_sns(result: dict, s3_key: str) -> None:
    """Publish investigation verdict to SNS."""
    if not sns_client or not SNS_TOPIC:
        return

    verdict    = result.get("verdict", "UNKNOWN")
    confidence = result.get("confidence", 0)
    action     = result.get("recommended_action", "QUARANTINE")
    subject_line = result.get("subject", "")
    from_email   = result.get("from_email", "")
    report_url   = f"{PHANTOM_URL}/api/investigate/phishing/{result.get('report_id', '')}"

    subject = f"[Phantom] Phishing Investigation: {verdict} — {subject_line[:50]}"

    body = f"""Phantom Phishing Investigation Complete

Verdict:            {verdict} ({confidence}% confidence)
Recommended Action: {action}
Email From:         {from_email}
Subject:            {subject_line}
S3 Key:             {s3_key}
Report ID:          {result.get('report_id', '')}
Report URL:         {report_url}

Summary:
{result.get('summary', 'No summary available.')}

IOCs:
{json.dumps(result.get('iocs', {}), indent=2)}
"""

    sns_client.publish(
        TopicArn=SNS_TOPIC,
        Subject=subject[:100],
        Message=body,
        MessageAttributes={
            "verdict": {
                "DataType": "String",
                "StringValue": verdict,
            },
            "action": {
                "DataType": "String",
                "StringValue": action,
            },
        },
    )
    print(f"[lambda] SNS notification sent: {verdict}")


def handler(event, context):
    """
    Lambda entry point. Handles S3 event notifications.
    Also supports direct invocation with {raw_email, reported_by, report_id}.
    """

    # ── Direct invocation (for testing) ────────────────────────────────────
    if "raw_email" in event:
        raw_email   = event["raw_email"]
        reported_by = event.get("reported_by", "direct-invoke")
        report_id   = event.get("report_id", "")
        s3_key      = "direct-invoke"
        result = _call_phantom(raw_email, reported_by, report_id)
        _notify_sns(result, s3_key)
        return {"statusCode": 200, "body": json.dumps(result)}

    # ── S3 event (SES delivery) ─────────────────────────────────────────────
    records = event.get("Records", [])
    responses = []

    for record in records:
        event_source = record.get("eventSource", "")
        if event_source != "aws:s3":
            print(f"[lambda] Skipping non-S3 record: {event_source}")
            continue

        bucket = record["s3"]["bucket"]["name"]
        key    = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
        print(f"[lambda] Processing s3://{bucket}/{key}")

        try:
            raw_email   = _get_email_from_s3(bucket, key)
            reported_by = _extract_reporter(key, raw_email)
            # Use S3 key (message ID) as report ID — stable and traceable
            report_id   = key.replace("/", "-").replace(".", "-")[:64]

            result = _call_phantom(raw_email, reported_by, report_id)
            _notify_sns(result, key)

            responses.append({
                "s3_key":    key,
                "report_id": result.get("report_id"),
                "verdict":   result.get("verdict"),
                "action":    result.get("recommended_action"),
            })
            print(f"[lambda] Done: {result.get('verdict')} ({result.get('confidence')}%)")

        except Exception as e:
            print(f"[lambda] ERROR processing {key}: {e}")
            responses.append({"s3_key": key, "error": str(e)})

    return {
        "statusCode": 200,
        "body": json.dumps({"processed": len(responses), "results": responses}),
    }
