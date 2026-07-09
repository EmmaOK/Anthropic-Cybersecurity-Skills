#!/usr/bin/env python3
"""
phantom/guardduty_intake.py — AWS GuardDuty finding intake + IR pipeline.

The cloud analog of phishingbox_intake.py. A GuardDuty finding (delivered via
EventBridge, or pulled with the AWS CLI) is normalized, investigated
autonomously, enriched, turned into a case, and — for a confirmed compromise —
filed as *approval-gated* containment actions. Nothing destructive runs
automatically: containment is proposed and queued for human approval.

Flow (mirrors the phishing pipeline, reusing the same machinery):
  GuardDuty finding
    -> normalize_finding()                 canonical shape (type/severity/actor/principal/resource)
    -> investigate_finding()               autonomous loop on task_agent, pulls the GuardDuty skills
         · enrich_indicator                actor IP -> Shodan/AbuseIPDB/GreyNoise/ThreatFox/MISP
         · cloudtrail_lookback             what did the principal actually do? (aws CLI)
    -> sync_campaign()                     TheHive case + MISP event + Jira ticket (case_sync)
    -> file containment approvals          approvals.create_approval (Google-Chat approve/deny)
    -> report + return

Intake sources:
  1. normalize_eventbridge(payload)  — EventBridge wraps the finding under "detail"
     (server.py POSTs to /api/webhook/guardduty)
  2. poll_guardduty()                — pull open findings via the AWS CLI on a timer

Every stage is guarded: no aws CLI, no configured integration, or a missing key
skips that stage and is reported — never fatal. Only HIGH/COMPROMISED findings
escalate to case-sync + containment.

Environment (all optional):
  AWS CLI + creds (for poll_guardduty / cloudtrail_lookback)
  GUARDDUTY_REGION            — region for the CLI (else AWS_DEFAULT_REGION)
  PHANTOM_GUARDDUTY_CASE_SYNC — default on ; open TheHive/MISP/Jira case
  PHANTOM_GUARDDUTY_APPROVALS — default on ; file containment as pending approvals
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from task_agent import (SKILL_TOOLS, run_agent_loop, save_report, _BASE_RULES)

# findings already processed this run (dedupe by GuardDuty finding Id)
_PROCESSED: set[str] = set()


def _truthy(name: str, default: bool) -> bool:
    v = os.environ.get(name, "").lower()
    return default if not v else v in ("1", "true", "yes", "on")


# ── AWS CLI helper (graceful) ────────────────────────────────────────────────

def _aws(args: list[str], timeout: int = 30) -> dict:
    """Run `aws <args> --output json`. Returns parsed JSON or {'_error': ...}."""
    region = os.environ.get("GUARDDUTY_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    cmd = ["aws", *args, "--output", "json"]
    if region:
        cmd += ["--region", region]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return {"_error": "aws CLI not found on PATH"}
    except subprocess.TimeoutExpired:
        return {"_error": "aws CLI timed out"}
    if out.returncode != 0:
        return {"_error": (out.stderr or "aws error").strip()[:300]}
    try:
        return json.loads(out.stdout) if out.stdout.strip() else {}
    except json.JSONDecodeError as e:
        return {"_error": f"bad JSON from aws: {e}"}


# ── Normalization ────────────────────────────────────────────────────────────

def _sev_band(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    return "high" if s >= 7 else "medium" if s >= 4 else "low"


def normalize_finding(finding: dict) -> dict:
    """Flatten a raw GuardDuty finding into the fields the pipeline needs."""
    svc = finding.get("Service", {}) or {}
    action = svc.get("Action", {}) or {}
    resource = finding.get("Resource", {}) or {}

    # actor IP — location differs by action type (network/aws-api/dns)
    actor_ip = ""
    for path in (("AwsApiCallAction", "RemoteIpDetails", "IpAddressV4"),
                 ("NetworkConnectionAction", "RemoteIpDetails", "IpAddressV4"),
                 ("KubernetesApiCallAction", "RemoteIpDetails", "IpAddressV4")):
        node = action
        for k in path:
            node = (node or {}).get(k, {}) if isinstance(node, dict) else {}
        if isinstance(node, str) and node:
            actor_ip = node
            break

    # principal / affected resource
    rtype = resource.get("ResourceType", "")
    principal, target = "", ""
    if rtype == "AccessKey":
        ak = resource.get("AccessKeyDetails", {})
        principal = ak.get("UserName", "")
        target = ak.get("AccessKeyId", "")
    elif rtype == "Instance":
        principal = resource.get("InstanceDetails", {}).get("InstanceId", "")
        target = principal
    elif rtype == "S3Bucket":
        buckets = resource.get("S3BucketDetails", []) or [{}]
        target = buckets[0].get("Name", "")

    return {
        "finding_id": finding.get("Id", ""),
        "type": finding.get("Type", ""),
        "title": finding.get("Title", finding.get("Type", "")),
        "description": finding.get("Description", ""),
        "severity_score": finding.get("Severity", 0),
        "severity": _sev_band(finding.get("Severity", 0)),
        "region": finding.get("Region", ""),
        "account_id": finding.get("AccountId", ""),
        "resource_type": rtype,
        "principal": principal,
        "target": target,
        "actor_ip": actor_ip,
        "count": svc.get("Count", 1),
        "first_seen": svc.get("EventFirstSeen", ""),
        "last_seen": svc.get("EventLastSeen", ""),
    }


def normalize_eventbridge(payload: dict) -> dict | None:
    """EventBridge delivers the finding under payload['detail']."""
    if not isinstance(payload, dict):
        return None
    detail = payload.get("detail") if isinstance(payload.get("detail"), dict) else payload
    if not detail.get("Type") and not detail.get("Id"):
        return None
    return normalize_finding(detail)


def poll_guardduty(max_findings: int = 25) -> list[dict]:
    """Pull recent findings via the AWS CLI. Best-effort; returns normalized findings."""
    detectors = _aws(["guardduty", "list-detectors"])
    if detectors.get("_error"):
        print(f"[guardduty] {detectors['_error']}", flush=True)
        return []
    ids = detectors.get("DetectorIds", [])
    if not ids:
        print("[guardduty] no detectors in this region", flush=True)
        return []
    det = ids[0]
    listing = _aws(["guardduty", "list-findings", "--detector-id", det,
                    "--max-results", str(max_findings)])
    fids = listing.get("FindingIds", [])
    if not fids:
        return []
    got = _aws(["guardduty", "get-findings", "--detector-id", det,
                "--finding-ids", *fids])
    return [normalize_finding(f) for f in got.get("Findings", [])]


# ── Investigation tools (task_agent harness) ────────────────────────────────

def _tool_enrich(indicator: str, indicator_type: str) -> dict:
    try:
        from phishing import _tool_threat_intel  # reuse the fan-out
        return _tool_threat_intel(indicator, indicator_type)
    except Exception as e:  # noqa: BLE001
        return {"error": f"enrichment unavailable: {e}", "indicator": indicator}


def _tool_cloudtrail(principal: str, hours: int = 24) -> dict:
    """Look up recent CloudTrail events for a principal (what the creds did)."""
    if not principal:
        return {"error": "no principal"}
    res = _aws(["cloudtrail", "lookup-events",
                "--lookup-attributes", f"AttributeKey=Username,AttributeValue={principal}",
                "--max-results", "25"])
    if res.get("_error"):
        return {"available": False, "reason": res["_error"]}
    events = []
    for e in res.get("Events", []):
        events.append({"event": e.get("EventName"), "time": e.get("EventTime"),
                       "source": e.get("EventSource")})
    from collections import Counter
    return {"available": True, "principal": principal, "event_count": len(events),
            "top_actions": [f"{n} ({c})" for n, c in
                            Counter(e["event"] for e in events if e["event"]).most_common(8)],
            "recent": events[:10]}


GD_TOOLS = SKILL_TOOLS + [
    {"name": "enrich_indicator",
     "description": "Enrich an IP/domain across external threat intel (Shodan, AbuseIPDB, GreyNoise, "
                    "ThreatFox, MISP). Use on the finding's actor IP. Unconfigured sources are skipped.",
     "input_schema": {"type": "object", "properties": {
         "indicator": {"type": "string"},
         "indicator_type": {"type": "string", "enum": ["ip", "domain", "url", "hash"]}},
         "required": ["indicator", "indicator_type"]}},
    {"name": "cloudtrail_lookback",
     "description": "Query CloudTrail for a principal's recent API activity to judge whether the "
                    "credentials/role are being abused. Requires the AWS CLI + creds.",
     "input_schema": {"type": "object", "properties": {
         "principal": {"type": "string"}, "hours": {"type": "integer"}},
         "required": ["principal"]}},
    {"name": "write_investigation_report",
     "description": "Write the final GuardDuty investigation. Call LAST.",
     "input_schema": {"type": "object", "properties": {
         "verdict": {"type": "string", "enum": ["BENIGN", "SUSPICIOUS", "COMPROMISED", "UNKNOWN"]},
         "confidence": {"type": "integer"},
         "attack_mapping": {"type": "array", "items": {"type": "string"}},
         "iocs": {"type": "object", "properties": {
             "ips": {"type": "array", "items": {"type": "string"}},
             "domains": {"type": "array", "items": {"type": "string"}},
             "hashes": {"type": "array", "items": {"type": "string"}}}},
         "containment_recommendations": {"type": "array", "items": {"type": "object",
             "properties": {"action": {"type": "string"}, "target": {"type": "string"},
                            "rationale": {"type": "string"},
                            "impact_level": {"type": "string", "enum": ["low", "medium", "high"]}}},
             "description": "proposed containment — filed for human approval, NOT auto-executed"},
         "skills_used": {"type": "array", "items": {"type": "string"}},
         "summary": {"type": "string"},
         "report_markdown": {"type": "string"},
     }, "required": ["verdict", "confidence", "summary", "report_markdown"]}},
]

GD_SYSTEM = (
    "You are Phantom investigating an AWS GuardDuty finding. Determine whether it is a real "
    "compromise, then propose (never execute) containment.\n\n"
    "Method:\n"
    "1. search_skills for the matching GuardDuty/cloud skill (e.g. 'detecting-cloud-threats-with-"
    "guardduty', 'detecting-compromised-cloud-credentials', 'performing-cloud-forensics-with-aws-"
    "cloudtrail') and load it.\n"
    "2. enrich_indicator on the actor IP — treat malicious_signals as evidence; a skipped source is "
    "NOT 'clean'.\n"
    "3. cloudtrail_lookback on the principal — did the credentials do anything unusual (new keys, "
    "data access, privilege changes)?\n"
    "4. Map to ATT&CK and reach a verdict: BENIGN / SUSPICIOUS / COMPROMISED / UNKNOWN.\n"
    "5. Propose containment_recommendations with concrete targets (access key id, instance id) and "
    "impact_level — these are queued for HUMAN approval, so be specific and justify each.\n"
    "6. write_investigation_report.\n\n"
    "GuardDuty severity: >=7 high, 4-6.9 medium, <4 low. Weight the finding type heavily. "
    + _BASE_RULES)


def _dispatch(name: str, inp: dict) -> tuple[str, dict | None]:
    if name == "enrich_indicator":
        return json.dumps(_tool_enrich(inp.get("indicator", ""), inp.get("indicator_type", ""))), None
    if name == "cloudtrail_lookback":
        return json.dumps(_tool_cloudtrail(inp.get("principal", ""), inp.get("hours", 24))), None
    if name == "write_investigation_report":
        return json.dumps({"written": True}), dict(inp)
    return json.dumps({"error": f"unknown tool {name}"}), None


def investigate_finding(nf: dict) -> dict:
    """Run the autonomous investigation loop for one normalized finding."""
    initial = (
        f"Investigate this AWS GuardDuty finding.\n\n"
        f"Finding ID:   {nf['finding_id']}\n"
        f"Type:         {nf['type']}\n"
        f"Title:        {nf['title']}\n"
        f"Severity:     {nf['severity']} ({nf['severity_score']})\n"
        f"Account/Region: {nf['account_id']} / {nf['region']}\n"
        f"Resource:     {nf['resource_type']}  principal={nf['principal'] or 'n/a'}  target={nf['target'] or 'n/a'}\n"
        f"Actor IP:     {nf['actor_ip'] or 'n/a'}\n"
        f"Seen:         {nf['count']}x  ({nf['first_seen']} → {nf['last_seen']})\n"
        f"Description:  {nf['description']}\n\n"
        "Begin the investigation now.")
    report, _ = run_agent_loop(GD_SYSTEM, initial, GD_TOOLS, _dispatch, label="guardduty")
    return report or {}


# ── Pipeline ─────────────────────────────────────────────────────────────────

def run_pipeline(finding: dict, source: str = "manual",
                 case_sync: bool | None = None, file_approvals: bool | None = None) -> dict:
    """Normalize → investigate → case-sync → file containment approvals."""
    nf = normalize_finding(finding) if "Type" in finding or "Id" in finding else finding
    fid = nf.get("finding_id", "")
    do_case = _truthy("PHANTOM_GUARDDUTY_CASE_SYNC", True) if case_sync is None else case_sync
    do_appr = _truthy("PHANTOM_GUARDDUTY_APPROVALS", True) if file_approvals is None else file_approvals

    summary = {"finding_id": fid, "type": nf.get("type"), "severity": nf.get("severity"),
               "source": source, "verdict": None, "case_refs": None, "approvals": None}

    if fid and fid in _PROCESSED:
        summary["duplicate"] = True
        return summary
    if fid:
        _PROCESSED.add(fid)

    report = investigate_finding(nf)
    if not report:
        summary["error"] = "no report produced (check ANTHROPIC_API_KEY)"
        return summary
    summary["verdict"] = report.get("verdict")
    summary["confidence"] = report.get("confidence")

    task_id = f"guardduty-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{(fid or 'x')[-6:]}"
    report.update({"task_id": task_id, "task_type": "guardduty", "finding_id": fid,
                   "finding_type": nf.get("type"), "actor_ip": nf.get("actor_ip")})
    report["report_path"] = save_report("guardduty", task_id, report)

    if report.get("verdict") not in ("COMPROMISED", "SUSPICIOUS"):
        return summary  # benign/unknown — investigated + recorded, no escalation

    # Case management + IOC push (reuses the phishing case_sync)
    result_shape = {
        "subject": nf.get("title"), "from_email": nf.get("actor_ip", ""),
        "verdict": report.get("verdict"), "confidence": report.get("confidence"),
        "summary": report.get("summary", ""),
        "iocs": _merge_iocs(report.get("iocs", {}), nf),
    }
    campaign = {"campaign_id": fid or task_id, "report_count": nf.get("count", 1)}
    if do_case:
        try:
            import case_sync as cs
            summary["case_refs"] = cs.sync_campaign(result_shape, campaign)
        except Exception as e:  # noqa: BLE001
            summary["case_refs"] = {"error": str(e)}

    # Containment — filed as pending approvals, never auto-executed
    if do_appr and report.get("verdict") == "COMPROMISED":
        summary["approvals"] = _file_containment(
            report.get("containment_recommendations", []), fid or task_id, nf)

    return summary


def _merge_iocs(iocs: dict, nf: dict) -> dict:
    out = {k: list(v or []) for k, v in iocs.items()}
    if nf.get("actor_ip"):
        out.setdefault("ips", [])
        if nf["actor_ip"] not in out["ips"]:
            out["ips"].append(nf["actor_ip"])
    return out


def _file_containment(recs: list, session_id: str, nf: dict) -> list:
    """Queue each containment recommendation as a pending human approval."""
    if not recs:
        return []
    try:
        from approvals import create_approval
    except Exception as e:  # noqa: BLE001
        return [{"error": f"approvals unavailable: {e}"}]
    filed = []
    for r in recs:
        try:
            a = create_approval(
                session_id=session_id,
                action_type=r.get("action", "containment"),
                resources=[r.get("target", "")],
                justification=r.get("rationale", ""),
                impact=f"GuardDuty {nf.get('type', '')} on {nf.get('resource_type', '')}",
                impact_level=r.get("impact_level", "high"),
                requested_by="phantom-guardduty")
            filed.append({"approval_id": a.get("id"), "action": r.get("action"),
                          "target": r.get("target"), "status": "pending"})
        except Exception as e:  # noqa: BLE001
            filed.append({"error": str(e), "action": r.get("action")})
    return filed


def process_intake(findings: list[dict]) -> list[dict]:
    out = []
    for f in findings:
        nf = normalize_finding(f) if "Type" in f else f
        print(f"[guardduty] processing {nf.get('type')} (sev {nf.get('severity')})", flush=True)
        out.append(run_pipeline(f, source="poll"))
    return out


# ── CLI ──────────────────────────────────────────────────────────────────────

def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="GuardDuty finding intake + IR pipeline")
    p.add_argument("--finding-file", help="a GuardDuty finding (or EventBridge payload) JSON file")
    p.add_argument("--poll", action="store_true", help="pull findings via the AWS CLI")
    p.add_argument("--no-case-sync", action="store_true")
    p.add_argument("--no-approvals", action="store_true")
    args = p.parse_args(argv)

    cs = False if args.no_case_sync else None
    ap = False if args.no_approvals else None
    if args.finding_file:
        payload = json.loads(Path(args.finding_file).read_text())
        finding = normalize_eventbridge(payload) or payload
        results = [run_pipeline(finding, "cli", cs, ap)]
    elif args.poll:
        results = process_intake(poll_guardduty())
    else:
        p.print_help()
        return 0
    print(json.dumps(results, indent=2, default=str))
    return 1 if any(r.get("verdict") == "COMPROMISED" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
