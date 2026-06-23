#!/usr/bin/env python3
"""
AWS Inspector Findings Reporter

Subcommands:
  report — Pull findings from AWS Inspector v2 and generate a monthly report.
  trends — Compare two reporting periods and show remediation velocity.

Usage:
    # Single-account / delegated-admin mode:
    agent.py report [--start-date 2026-03-01] [--end-date 2026-03-31]
                    [--regions us-east-1,us-west-2] [--profile default]
                    [--kev] [--output inspector_report.json]

    # Multi-account team mode:
    agent.py report --team-config teams.json
                    [--role-name InspectorReadOnly]
                    [--regions us-east-1,us-west-2] [--kev]
                    [--split-by-team] [--output inspector_report.json]

    agent.py trends --current report_march.json --previous report_feb.json
                    [--output inspector_trends.json]

teams.json format:
    {
      "platform": ["123456789012", "234567890123"],
      "security": ["345678901234"],
      "data":     ["456789012345", "567890123456"],
      "frontend": ["678901234567"]
    }

AWS permissions:
  inspector2:ListFindings
  sts:AssumeRole on --role-name in each target account (cross-account mode only)
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


def fetch_kev_catalog() -> set:
    try:
        with urllib.request.urlopen(CISA_KEV_URL, timeout=15) as resp:
            data = json.loads(resp.read())
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as e:
        print(f"[warn] Could not fetch KEV catalog: {e}", file=sys.stderr)
        return set()


def paginate_findings(client, filters: dict) -> list:
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


def assume_role_session(base_session, account_id: str, role_name: str, region: str):
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    sts = base_session.client("sts")
    resp = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="InspectorReporter",
        DurationSeconds=3600,
    )
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def _empty_bucket() -> dict:
    return {
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0},
        "by_resource_type": {},
        "by_region": {},
        "by_account": {},
        "by_status": {"ACTIVE": 0, "SUPPRESSED": 0, "CLOSED": 0},
        "_kev": [],
        "_epss": [],
        "_top_cves": {},
    }


def _process_finding(f: dict, kev_ids: set, bucket: dict):
    sev = f.get("severity", "INFORMATIONAL")
    if sev in bucket["by_severity"]:
        bucket["by_severity"][sev] += 1

    resources = f.get("resources", [])
    first = resources[0] if resources else {}
    rtype = first.get("type", "UNKNOWN")
    region = first.get("region", "UNKNOWN")
    resource_id = first.get("id", "")

    bucket["by_resource_type"][rtype] = bucket["by_resource_type"].get(rtype, 0) + 1
    bucket["by_region"][region] = bucket["by_region"].get(region, 0) + 1

    account = f.get("awsAccountId", "UNKNOWN")
    bucket["by_account"][account] = bucket["by_account"].get(account, 0) + 1

    status = f.get("status", "ACTIVE")
    if status in bucket["by_status"]:
        bucket["by_status"][status] += 1

    pkg = f.get("packageVulnerabilityDetails", {})
    cve = pkg.get("vulnerabilityId", "")
    if not cve:
        return

    bucket["_top_cves"][cve] = bucket["_top_cves"].get(cve, 0) + 1

    if kev_ids and cve in kev_ids:
        bucket["_kev"].append({
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
        bucket["_epss"].append({
            "finding_arn": f.get("findingArn", ""),
            "cve": cve,
            "epss_score": round(epss_score, 4),
            "severity": sev,
            "resource_id": resource_id,
            "resource_type": rtype,
            "region": region,
            "account": account,
        })


def _finalize(bucket: dict) -> dict:
    top_10 = sorted(bucket["_top_cves"].items(), key=lambda x: x[1], reverse=True)[:10]
    epss_sorted = sorted(bucket["_epss"], key=lambda x: x["epss_score"], reverse=True)[:20]
    return {
        "by_severity": bucket["by_severity"],
        "by_resource_type": dict(sorted(bucket["by_resource_type"].items(), key=lambda x: x[1], reverse=True)),
        "by_region": dict(sorted(bucket["by_region"].items(), key=lambda x: x[1], reverse=True)),
        "by_account": bucket["by_account"],
        "by_status": bucket["by_status"],
        "kev_findings_count": len(bucket["_kev"]),
        "kev_findings": bucket["_kev"][:20],
        "high_epss_findings_count": len(bucket["_epss"]),
        "high_epss_findings": epss_sorted,
        "top_cves": [{"cve": c, "affected_resources": n} for c, n in top_10],
    }


def aggregate_findings(findings: list, kev_ids: set) -> dict:
    bucket = _empty_bucket()
    for f in findings:
        _process_finding(f, kev_ids, bucket)
    return _finalize(bucket)


def aggregate_by_team(findings: list, account_to_team: dict, kev_ids: set) -> dict:
    buckets: dict = {}
    for f in findings:
        account = f.get("awsAccountId", "UNKNOWN")
        team = account_to_team.get(account, "__unassigned__")
        if team not in buckets:
            buckets[team] = _empty_bucket()
        _process_finding(f, kev_ids, buckets[team])
    return {team: _finalize(b) for team, b in buckets.items()}


def risk_level(metrics: dict) -> str:
    sev = metrics["by_severity"]
    for level in ("CRITICAL", "HIGH", "MEDIUM"):
        if sev.get(level, 0) > 0:
            return level
    return "LOW"


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

    kev_ids: set = set()
    if args.kev:
        print("[*] Fetching CISA KEV catalog...", file=sys.stderr)
        kev_ids = fetch_kev_catalog()
        if kev_ids:
            print(f"[*] KEV catalog loaded: {len(kev_ids)} CVEs", file=sys.stderr)

    # Load team config
    team_config: dict = {}       # team_name -> [account_ids]
    account_to_team: dict = {}   # account_id -> team_name
    if args.team_config:
        try:
            with open(args.team_config) as fh:
                team_config = json.load(fh)
            for team, accounts in team_config.items():
                for acct in accounts:
                    account_to_team[str(acct)] = team
            print(
                f"[*] Team config: {len(team_config)} teams, {len(account_to_team)} accounts",
                file=sys.stderr,
            )
        except Exception as e:
            print(f"[error] Could not load team config: {e}", file=sys.stderr)
            sys.exit(2)

    session_kwargs: dict = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile

    filters = build_date_filter(start_dt, end_dt)
    all_findings: list = []

    if team_config and args.role_name:
        # Cross-account mode: assume a role in each account
        base_session = boto3.Session(**session_kwargs)
        for team, accounts in team_config.items():
            for account_id in accounts:
                for region in regions:
                    print(
                        f"[*] {team} / {account_id} / {region} ...",
                        file=sys.stderr,
                    )
                    try:
                        acct_session = assume_role_session(
                            base_session, account_id, args.role_name, region
                        )
                        client = acct_session.client("inspector2")
                        found = paginate_findings(client, filters)
                        for f in found:
                            f.setdefault("awsAccountId", account_id)
                        all_findings.extend(found)
                        print(f"[*]   {len(found)} findings", file=sys.stderr)
                    except ClientError as e:
                        code = e.response["Error"]["Code"]
                        if code in ("AccessDenied", "AccessDeniedException"):
                            print(
                                f"[warn] Access denied assuming role in {account_id}: {e}",
                                file=sys.stderr,
                            )
                        else:
                            print(
                                f"[warn] AWS error for {account_id}/{region}: {e}",
                                file=sys.stderr,
                            )
    else:
        # Single credential set (delegated admin or single account)
        for region in regions:
            print(f"[*] Pulling findings from {region}...", file=sys.stderr)
            try:
                session = boto3.Session(**session_kwargs, region_name=region)
                client = session.client("inspector2")
                found = paginate_findings(client, filters)
                all_findings.extend(found)
                print(f"[*]   {len(found)} findings", file=sys.stderr)
            except NoCredentialsError:
                print(
                    "[error] No AWS credentials. Configure via ~/.aws/credentials, "
                    "env vars, or IAM instance role.",
                    file=sys.stderr,
                )
                sys.exit(2)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "AccessDeniedException":
                    print(
                        f"[error] Access denied in {region}. "
                        "Ensure inspector2:ListFindings is granted.",
                        file=sys.stderr,
                    )
                elif code == "ValidationException":
                    print(
                        f"[error] Inspector v2 may not be enabled in {region}: {e}",
                        file=sys.stderr,
                    )
                else:
                    print(f"[error] AWS error in {region}: {e}", file=sys.stderr)
                sys.exit(2)

    overall_metrics = aggregate_findings(all_findings, kev_ids)
    overall_risk = risk_level(overall_metrics)

    report = {
        "report_timestamp": datetime.now(timezone.utc).isoformat(),
        "period": {"start": start_dt.isoformat(), "end": end_dt.isoformat()},
        "regions_scanned": regions,
        "total_findings": len(all_findings),
        "overall_risk": overall_risk,
        "metrics": overall_metrics,
        "kev_enriched": args.kev,
        "kev_catalog_size": len(kev_ids) if kev_ids else None,
        "recommendation": (
            f"{overall_metrics['by_severity']['CRITICAL']} CRITICAL and "
            f"{overall_metrics['by_severity']['HIGH']} HIGH findings require immediate attention."
            if overall_risk in ("CRITICAL", "HIGH")
            else "No critical findings. Review MEDIUM findings for remediation planning."
        ),
    }

    # Per-team breakdown
    if team_config:
        team_metrics_map = aggregate_by_team(all_findings, account_to_team, kev_ids)
        report["by_team"] = {}
        for team_name in team_config:
            t_metrics = team_metrics_map.get(team_name, _finalize(_empty_bucket()))
            t_risk = risk_level(t_metrics)
            t_total = sum(t_metrics["by_severity"].values())
            report["by_team"][team_name] = {
                "accounts": team_config[team_name],
                "total_findings": t_total,
                "overall_risk": t_risk,
                "metrics": t_metrics,
            }

        # Unassigned accounts (present in findings but not in team config)
        if "__unassigned__" in team_metrics_map:
            u = team_metrics_map["__unassigned__"]
            u_total = sum(u["by_severity"].values())
            if u_total > 0:
                report["by_team"]["__unassigned__"] = {
                    "accounts": list(u["by_account"].keys()),
                    "total_findings": u_total,
                    "overall_risk": risk_level(u),
                    "metrics": u,
                }

        if args.split_by_team:
            out = Path(args.output)
            for team_name, team_data in report["by_team"].items():
                team_file = out.parent / f"{out.stem}_{team_name}{out.suffix}"
                team_report = {
                    k: v for k, v in report.items() if k != "by_team"
                }
                team_report.update({
                    "team": team_name,
                    "accounts": team_data["accounts"],
                    "total_findings": team_data["total_findings"],
                    "overall_risk": team_data["overall_risk"],
                    "metrics": team_data["metrics"],
                })
                with open(team_file, "w") as fh:
                    json.dump(team_report, fh, indent=2)
                print(f"[*] Team report: {team_file}", file=sys.stderr)

    with open(args.output, "w") as fh:
        json.dump(report, fh, indent=2)

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

    # Per-team trends if both reports contain by_team
    if "by_team" in current and "by_team" in previous:
        teams = set(current["by_team"]) | set(previous["by_team"])
        team_trends = {}
        for team in teams:
            c_sev = current["by_team"].get(team, {}).get("metrics", {}).get("by_severity", {})
            p_sev = previous["by_team"].get(team, {}).get("metrics", {}).get("by_severity", {})
            t_delta = {sev: c_sev.get(sev, 0) - p_sev.get(sev, 0) for sev in levels}
            team_trends[team] = {
                "severity_delta": t_delta,
                "severity_trend": {
                    sev: ("INCREASED" if t_delta[sev] > 0 else "DECREASED" if t_delta[sev] < 0 else "UNCHANGED")
                    for sev in levels
                },
                "total_delta": current["by_team"].get(team, {}).get("total_findings", 0)
                    - previous["by_team"].get(team, {}).get("total_findings", 0),
            }
        trends["by_team"] = team_trends

    with open(args.output, "w") as f:
        json.dump(trends, f, indent=2)

    print(json.dumps(trends, indent=2))
    print(f"\n[*] Trends report saved to {args.output}", file=sys.stderr)

    return trends


def main():
    parser = argparse.ArgumentParser(description="AWS Inspector Findings Reporter")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_report = sub.add_parser("report", help="Generate monthly findings report from Inspector v2")
    p_report.add_argument("--start-date", help="Period start (ISO 8601, default: 30 days ago)")
    p_report.add_argument("--end-date", help="Period end (ISO 8601, default: now)")
    p_report.add_argument("--regions", default="us-east-1", help="Comma-separated AWS regions")
    p_report.add_argument("--profile", help="AWS CLI profile name")
    p_report.add_argument("--team-config", help="JSON file mapping team names to account ID lists")
    p_report.add_argument(
        "--role-name",
        help="IAM role name to assume in each account (enables cross-account pull)",
    )
    p_report.add_argument(
        "--split-by-team",
        action="store_true",
        help="Write a separate report JSON for each team",
    )
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
