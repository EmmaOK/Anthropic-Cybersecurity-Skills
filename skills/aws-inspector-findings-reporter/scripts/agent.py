#!/usr/bin/env python3
"""
AWS Inspector Findings Reporter

Subcommands:
  report — Pull findings from AWS Inspector v2 and generate a monthly report.
  trends — Compare two reporting periods and show remediation velocity.

Usage:
    agent.py report [--start-date 2026-03-01] [--end-date 2026-03-31]
                    [--regions us-east-1,us-west-2] [--profile default]
                    [--kev] [--output inspector_report.json]
    agent.py trends --current report_march.json --previous report_feb.json
                    [--output inspector_trends.json]

AWS permissions required: inspector2:ListFindings
"""

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}


def fetch_kev_catalog() -> set[str]:
    try:
        with urllib.request.urlopen(CISA_KEV_URL, timeout=15) as resp:
            data = json.loads(resp.read())
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as e:
        print(f"[warn] Could not fetch KEV catalog: {e}", file=sys.stderr)
        return set()


def paginate_findings(client, filters: dict) -> list[dict]:
    findings = []
    paginator = client.get_paginator("list_findings")
    for page in paginator.paginate(filterCriteria=filters):
        findings.extend(page.get("findings", []))
    return findings


def build_date_filter(start: datetime, end: datetime) -> dict:
    return {
        "updatedAt": [
            {
                "startInclusive": start,
                "endInclusive": end,
            }
        ]
    }


def aggregate_findings(findings: list[dict], kev_ids: set[str]) -> dict:
    by_severity: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0
    }
    by_resource_type: dict[str, int] = {}
    by_region: dict[str, int] = {}
    by_account: dict[str, int] = {}
    by_status: dict[str, int] = {"ACTIVE": 0, "SUPPRESSED": 0, "CLOSED": 0}

    kev_findings: list[dict] = []
    high_epss: list[dict] = []
    top_cves: dict[str, int] = {}

    for f in findings:
        sev = f.get("severity", "INFORMATIONAL")
        if sev in by_severity:
            by_severity[sev] += 1

        resources = f.get("resources", [])
        first = resources[0] if resources else {}
        rtype = first.get("type", "UNKNOWN")
        region = first.get("region", "UNKNOWN")
        resource_id = first.get("id", "")

        by_resource_type[rtype] = by_resource_type.get(rtype, 0) + 1
        by_region[region] = by_region.get(region, 0) + 1

        account = f.get("awsAccountId", "UNKNOWN")
        by_account[account] = by_account.get(account, 0) + 1

        status = f.get("status", "ACTIVE")
        if status in by_status:
            by_status[status] += 1

        pkg = f.get("packageVulnerabilityDetails", {})
        cve = pkg.get("vulnerabilityId", "")

        if cve:
            top_cves[cve] = top_cves.get(cve, 0) + 1

            if kev_ids and cve in kev_ids:
                kev_findings.append({
                    "finding_arn": f.get("findingArn", ""),
                    "cve": cve,
                    "severity": sev,
                    "resource_id": resource_id,
                    "resource_type": rtype,
                    "region": region,
                    "account": account,
                })

            epss_score = pkg.get("epss", {}).get("score")
            if epss_score is not None and epss_score >= 0.7:
                high_epss.append({
                    "finding_arn": f.get("findingArn", ""),
                    "cve": cve,
                    "epss_score": round(epss_score, 4),
                    "severity": sev,
                    "resource_id": resource_id,
                    "resource_type": rtype,
                    "region": region,
                })

    top_10 = sorted(top_cves.items(), key=lambda x: x[1], reverse=True)[:10]
    high_epss_sorted = sorted(high_epss, key=lambda x: x["epss_score"], reverse=True)[:20]

    return {
        "by_severity": by_severity,
        "by_resource_type": dict(sorted(by_resource_type.items(), key=lambda x: x[1], reverse=True)),
        "by_region": dict(sorted(by_region.items(), key=lambda x: x[1], reverse=True)),
        "by_account": by_account,
        "by_status": by_status,
        "kev_findings_count": len(kev_findings),
        "kev_findings": kev_findings[:20],
        "high_epss_findings_count": len(high_epss),
        "high_epss_findings": high_epss_sorted,
        "top_cves": [{"cve": c, "affected_resources": n} for c, n in top_10],
    }


def cmd_report(args) -> dict:
    if not HAS_BOTO3:
        print("[error] boto3 not installed. Run: pip install boto3", file=sys.stderr)
        sys.exit(2)

    end_dt = (
        datetime.fromisoformat(args.end_date).replace(tzinfo=timezone.utc)
        if args.end_date
        else datetime.now(timezone.utc)
    )
    start_dt = (
        datetime.fromisoformat(args.start_date).replace(tzinfo=timezone.utc)
        if args.start_date
        else end_dt - timedelta(days=30)
    )

    regions = [r.strip() for r in args.regions.split(",")]

    kev_ids: set[str] = set()
    if args.kev:
        print("[*] Fetching CISA KEV catalog...", file=sys.stderr)
        kev_ids = fetch_kev_catalog()
        if kev_ids:
            print(f"[*] KEV catalog loaded: {len(kev_ids)} CVEs", file=sys.stderr)

    session_kwargs: dict = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile

    all_findings: list[dict] = []

    for region in regions:
        print(f"[*] Pulling findings from {region}...", file=sys.stderr)
        try:
            session = boto3.Session(**session_kwargs, region_name=region)
            client = session.client("inspector2")
            filters = build_date_filter(start_dt, end_dt)
            region_findings = paginate_findings(client, filters)
            all_findings.extend(region_findings)
            print(f"[*]   {len(region_findings)} findings", file=sys.stderr)
        except NoCredentialsError:
            print(
                "[error] No AWS credentials found. Configure via ~/.aws/credentials, "
                "environment variables, or an IAM instance role.",
                file=sys.stderr,
            )
            sys.exit(2)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AccessDeniedException":
                print(
                    f"[error] Access denied in {region}. "
                    "Ensure inspector2:ListFindings permission is granted.",
                    file=sys.stderr,
                )
            elif code == "ValidationException":
                print(f"[error] Inspector v2 may not be enabled in {region}: {e}", file=sys.stderr)
            else:
                print(f"[error] AWS error in {region}: {e}", file=sys.stderr)
            sys.exit(2)

    metrics = aggregate_findings(all_findings, kev_ids)

    overall_risk = (
        "CRITICAL" if metrics["by_severity"]["CRITICAL"] > 0
        else "HIGH" if metrics["by_severity"]["HIGH"] > 0
        else "MEDIUM" if metrics["by_severity"]["MEDIUM"] > 0
        else "LOW"
    )

    report = {
        "report_timestamp": datetime.now(timezone.utc).isoformat(),
        "period": {
            "start": start_dt.isoformat(),
            "end": end_dt.isoformat(),
        },
        "regions_scanned": regions,
        "total_findings": len(all_findings),
        "overall_risk": overall_risk,
        "metrics": metrics,
        "kev_enriched": args.kev,
        "kev_catalog_size": len(kev_ids) if kev_ids else None,
        "recommendation": (
            f"{metrics['by_severity']['CRITICAL']} CRITICAL and "
            f"{metrics['by_severity']['HIGH']} HIGH findings require immediate attention."
            if overall_risk in ("CRITICAL", "HIGH")
            else "No critical findings. Review MEDIUM findings for remediation planning."
        ),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] Report saved to {args.output}", file=sys.stderr)

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)

    return report


def cmd_trends(args) -> dict:
    for path_str in (args.current, args.previous):
        if not Path(path_str).exists():
            print(f"[error] File not found: {path_str}", file=sys.stderr)
            sys.exit(1)

    with open(args.current) as f:
        current = json.load(f)
    with open(args.previous) as f:
        previous = json.load(f)

    curr_sev = current.get("metrics", {}).get("by_severity", {})
    prev_sev = previous.get("metrics", {}).get("by_severity", {})

    levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    delta = {sev: curr_sev.get(sev, 0) - prev_sev.get(sev, 0) for sev in levels}
    trend = {
        sev: ("INCREASED" if delta[sev] > 0 else "DECREASED" if delta[sev] < 0 else "UNCHANGED")
        for sev in levels
    }

    curr_total = current.get("total_findings", 0)
    prev_total = previous.get("total_findings", 0)

    curr_kev = current.get("metrics", {}).get("kev_findings_count", 0)
    prev_kev = previous.get("metrics", {}).get("kev_findings_count", 0)

    trends = {
        "report_timestamp": datetime.now(timezone.utc).isoformat(),
        "current_period": current.get("period", {}),
        "previous_period": previous.get("period", {}),
        "total_findings_delta": curr_total - prev_total,
        "severity_delta": delta,
        "severity_trend": trend,
        "remediation_velocity": {
            "closed_this_period": current.get("metrics", {}).get("by_status", {}).get("CLOSED", 0),
            "closed_previous_period": previous.get("metrics", {}).get("by_status", {}).get("CLOSED", 0),
            "note": "MTTR requires finding-level timestamps; use Inspector console metrics for precise MTTR.",
        },
        "kev_delta": curr_kev - prev_kev,
        "new_kev_findings": curr_kev,
        "overall_risk_current": current.get("overall_risk", "UNKNOWN"),
        "overall_risk_previous": previous.get("overall_risk", "UNKNOWN"),
        "summary": (
            f"CRITICAL: {delta['CRITICAL']:+d}, HIGH: {delta['HIGH']:+d} vs previous period. "
            f"Total findings moved from {prev_total} to {curr_total}."
        ),
    }

    with open(args.output, "w") as f:
        json.dump(trends, f, indent=2)

    print(json.dumps(trends, indent=2))
    print(f"\n[*] Trends report saved to {args.output}", file=sys.stderr)

    return trends


def main():
    parser = argparse.ArgumentParser(description="AWS Inspector Findings Reporter")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_report = sub.add_parser("report", help="Generate monthly findings report from Inspector v2")
    p_report.add_argument("--start-date", help="Period start date (ISO 8601, default: 30 days ago)")
    p_report.add_argument("--end-date", help="Period end date (ISO 8601, default: now)")
    p_report.add_argument("--regions", default="us-east-1", help="Comma-separated AWS regions")
    p_report.add_argument("--profile", help="AWS CLI profile name")
    p_report.add_argument("--kev", action="store_true", help="Cross-reference CISA KEV catalog")
    p_report.add_argument("--output", default="inspector_report.json")

    p_trends = sub.add_parser("trends", help="Compare two reporting periods")
    p_trends.add_argument("--current", required=True, help="Current period report JSON")
    p_trends.add_argument("--previous", required=True, help="Previous period report JSON")
    p_trends.add_argument("--output", default="inspector_trends.json")

    args = parser.parse_args()
    if args.subcommand == "report":
        cmd_report(args)
    elif args.subcommand == "trends":
        cmd_trends(args)


if __name__ == "__main__":
    main()
