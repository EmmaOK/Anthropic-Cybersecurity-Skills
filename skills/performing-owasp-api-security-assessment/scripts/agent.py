#!/usr/bin/env python3
"""OWASP API Security Top 10 (2023) — Full assessment orchestrator."""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

SEVERITY_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "PASS": 0}

TEST_PLAN = [
    # Phase 1 — Discovery
    {
        "id": "api9a",
        "owasp_id": "API9:2023",
        "risk": "Improper Inventory Management — Endpoint Discovery",
        "skill": "performing-api-inventory-and-discovery",
        "args_fn": lambda url, token, low_token, out: [
            "--target-url", url,
            *(["--token", token] if token else []),
            "--output", out,
        ],
    },
    {
        "id": "api9b",
        "owasp_id": "API9:2023",
        "risk": "Improper Inventory Management — Shadow Endpoints",
        "skill": "detecting-shadow-api-endpoints",
        "args_fn": lambda url, token, low_token, out: [
            "--access-log", "/dev/null",
            "--output", out,
        ],
    },
    # Phase 2 — Authentication & Authorization
    {
        "id": "api2",
        "owasp_id": "API2:2023",
        "risk": "Broken Authentication",
        "skill": "testing-api-authentication-weaknesses",
        "args_fn": lambda url, token, low_token, out: [
            url,
            *(["--token", token] if token else []),
        ],
    },
    {
        "id": "api1",
        "owasp_id": "API1:2023",
        "risk": "Broken Object Level Authorization (BOLA)",
        "skill": "testing-api-for-broken-object-level-authorization",
        "args_fn": lambda url, token, low_token, out: [
            url,
            *(["--token", token] if token else []),
        ],
    },
    {
        "id": "api5",
        "owasp_id": "API5:2023",
        "risk": "Broken Function Level Authorization (BFLA)",
        "skill": "exploiting-broken-function-level-authorization",
        "args_fn": lambda url, token, low_token, out: [
            "--url", url,
            *(["--token", token] if token else []),
            "--output", out,
        ],
    },
    # Phase 3 — Data & Input
    {
        "id": "api3a",
        "owasp_id": "API3:2023",
        "risk": "Broken Object Property Level Auth — Excessive Data Exposure",
        "skill": "exploiting-excessive-data-exposure-in-api",
        "args_fn": lambda url, token, low_token, out: [
            "--url", url,
            *(["--token", token] if token else []),
            "--output", out,
        ],
    },
    {
        "id": "api3b",
        "owasp_id": "API3:2023",
        "risk": "Broken Object Property Level Auth — Mass Assignment",
        "skill": "testing-api-for-mass-assignment-vulnerability",
        "args_fn": lambda url, token, low_token, out: [
            url,
            *(["--token", token] if token else []),
        ],
    },
    {
        "id": "api7",
        "owasp_id": "API7:2023",
        "risk": "Server Side Request Forgery (SSRF)",
        "skill": "exploiting-api-injection-vulnerabilities",
        "args_fn": lambda url, token, low_token, out: [
            "--url", url + "/api/data",
            "--params", "url,redirect,webhook,callback",
            *(["--token", token] if token else []),
            "--output", out,
        ],
    },
    {
        "id": "api8",
        "owasp_id": "API8:2023",
        "risk": "Security Misconfiguration",
        "skill": "conducting-api-security-testing",
        "args_fn": lambda url, token, low_token, out: [
            "--base-url", url,
            *(["--token", token] if token else []),
            *(["--low-priv-token", low_token] if low_token else []),
            "--output", out,
        ],
    },
    # Phase 4 — Resource & Business Logic
    {
        "id": "api4",
        "owasp_id": "API4:2023",
        "risk": "Unrestricted Resource Consumption",
        "skill": "performing-api-rate-limiting-bypass",
        "args_fn": lambda url, token, low_token, out: [
            "--url", url,
            *(["--auth", token] if token else []),
            "--output", out,
        ],
    },
    {
        "id": "api6",
        "owasp_id": "API6:2023",
        "risk": "Unrestricted Access to Sensitive Business Flows",
        "skill": "testing-api-for-unrestricted-business-flows",
        "args_fn": lambda url, token, low_token, out: [
            "--target-url", url,
            *(["--token", token] if token else []),
            "--output", out,
        ],
    },
    {
        "id": "api10",
        "owasp_id": "API10:2023",
        "risk": "Unsafe Consumption of APIs",
        "skill": "testing-api-for-unsafe-consumption",
        "args_fn": lambda url, token, low_token, out: [
            "--target-url", url,
            *(["--token", token] if token else []),
            "--output", out,
        ],
    },
]


def run_test(test, target_url, token, low_priv_token, timeout):
    skill_path = ROOT / "skills" / test["skill"] / "scripts" / "agent.py"
    if not skill_path.exists():
        return {
            "owasp_id": test["owasp_id"],
            "risk": test["risk"],
            "skill": test["skill"],
            "status": "SKIPPED",
            "severity": "INFO",
            "exit_code": -1,
            "duration_seconds": 0,
            "findings": [],
            "error": f"agent.py not found at {skill_path}",
        }

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_file = tmp.name

    args = test["args_fn"](target_url, token, low_priv_token, out_file)
    cmd = [sys.executable, str(skill_path)] + args
    start = datetime.now(timezone.utc)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=str(ROOT)
        )
        duration = (datetime.now(timezone.utc) - start).total_seconds()
        exit_code = result.returncode

        findings = []
        try:
            with open(out_file) as f:
                data = json.load(f)
            raw_findings = data.get("findings", [])
            overall = data.get("overall_risk", "UNKNOWN")
            findings = [fi for fi in raw_findings if fi.get("severity") not in ("INFO", None)]
        except Exception:
            overall = "UNKNOWN"

        severity = overall if overall in SEVERITY_WEIGHTS else ("HIGH" if exit_code == 1 else "PASS")

        return {
            "owasp_id": test["owasp_id"],
            "risk": test["risk"],
            "skill": test["skill"],
            "status": "FINDING" if exit_code == 1 else "PASS",
            "severity": severity,
            "exit_code": exit_code,
            "duration_seconds": round(duration, 1),
            "findings": findings,
        }

    except subprocess.TimeoutExpired:
        duration = (datetime.now(timezone.utc) - start).total_seconds()
        return {
            "owasp_id": test["owasp_id"],
            "risk": test["risk"],
            "skill": test["skill"],
            "status": "TIMEOUT",
            "severity": "MEDIUM",
            "exit_code": -1,
            "duration_seconds": round(duration, 1),
            "findings": [],
            "error": f"Test timed out after {timeout}s",
        }
    except Exception as e:
        return {
            "owasp_id": test["owasp_id"],
            "risk": test["risk"],
            "skill": test["skill"],
            "status": "ERROR",
            "severity": "INFO",
            "exit_code": -1,
            "duration_seconds": 0,
            "findings": [],
            "error": str(e),
        }
    finally:
        try:
            os.unlink(out_file)
        except Exception:
            pass


def print_summary(results, target_url):
    print(f"\nOWASP API Security Assessment — {target_url}")
    print("═" * 60)
    for r in results:
        icon = "✗" if r["status"] == "FINDING" else ("?" if r["status"] in ("TIMEOUT", "ERROR", "SKIPPED") else "✓")
        count = len(r["findings"])
        label = f"{count} finding{'s' if count != 1 else ''}" if count else "0 findings"
        print(f" {r['owasp_id']:<12} {r['risk']:<44} {icon} {r['severity']:<10} {label}")
    print("═" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="OWASP API Security Top 10 (2023) — Full assessment orchestrator"
    )
    parser.add_argument("--target-url", required=True, help="Base URL of the target API")
    parser.add_argument("--token", default=None, help="High-privilege bearer token")
    parser.add_argument("--low-priv-token", default=None, help="Low-privilege bearer token")
    parser.add_argument("--output", default="owasp_api_report.json", help="Output JSON report file")
    parser.add_argument("--tests", default=None,
                        help="Comma-separated subset: api1,api2,...api10 (default: all)")
    parser.add_argument("--timeout", type=int, default=55,
                        help="Per-test timeout in seconds (default: 55)")
    args = parser.parse_args()

    selected = None
    if args.tests:
        selected = {t.strip().lower() for t in args.tests.split(",")}

    plan = [t for t in TEST_PLAN if selected is None or t["id"] in selected]
    results = []
    start_time = datetime.now(timezone.utc)

    for test in plan:
        print(f"  Running {test['owasp_id']} — {test['risk']} ...", flush=True)
        result = run_test(test, args.target_url, args.token, args.low_priv_token, args.timeout)
        results.append(result)

    max_sev = max((SEVERITY_WEIGHTS.get(r["severity"], 0) for r in results), default=0)
    sev_names = {v: k for k, v in SEVERITY_WEIGHTS.items()}
    overall_risk = sev_names.get(max_sev, "PASS")

    summary = {
        "total_tests": len(results),
        "passed": sum(1 for r in results if r["status"] == "PASS"),
        "with_findings": sum(1 for r in results if r["status"] == "FINDING"),
        "skipped_or_error": sum(1 for r in results if r["status"] in ("SKIPPED", "ERROR", "TIMEOUT")),
        "critical": sum(1 for r in results if r["severity"] == "CRITICAL"),
        "high": sum(1 for r in results if r["severity"] == "HIGH"),
        "medium": sum(1 for r in results if r["severity"] == "MEDIUM"),
        "low": sum(1 for r in results if r["severity"] == "LOW"),
        "overall_risk": overall_risk,
    }

    report = {
        "methodology": "OWASP API Security Top 10 (2023) — performing-owasp-api-security-assessment v1.0",
        "assessment_timestamp": start_time.isoformat(),
        "target_url": args.target_url,
        "tests_requested": [t["id"] for t in plan],
        "summary": summary,
        "results": results,
    }

    print_summary(results, args.target_url)
    print(f"\nOverall risk: {overall_risk}  |  Report: {args.output}\n")
    print(json.dumps(report, indent=2))

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)


if __name__ == "__main__":
    main()
