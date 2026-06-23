#!/usr/bin/env python3
"""
phantom_ci.py — Headless CD pentest runner for staging gates.

Detects CI platform automatically (GitHub Actions / Bitbucket Pipelines).
Uses Docker executor instead of UTM SSH when running in CI.

Usage:
    python phantom/phantom_ci.py --config pentest_config.yml
    python phantom/phantom_ci.py --target https://staging.myapp.com --scope web,api
    python phantom/phantom_ci.py --target 10.10.0.0/24 --scope full --threshold CRITICAL

Exit codes:
    0  No findings at or above threshold (deploy proceeds)
    1  HIGH or CRITICAL findings found (deploy blocked)
    2  Scanner error

Environment variables required:
    ANTHROPIC_API_KEY       Claude API key (set as CI secret)

Optional:
    DEFECTDOJO_URL          DefectDojo instance URL (e.g. http://defectdojo:8080)
    DEFECTDOJO_API_KEY      DefectDojo API token
    DEFECTDOJO_PRODUCT_ID   Product ID to import findings into
    JIRA_URL / JIRA_USER / JIRA_TOKEN / JIRA_PROJECT   Auto-create Jira tickets
    GOOGLE_CHAT_WEBHOOK_URL Post summary to Google Chat space
    FAIL_THRESHOLD          Override threshold (CRITICAL|HIGH|MEDIUM) — default HIGH
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Detect CI platform
IS_CI = os.environ.get("CI", "").lower() == "true"
IS_GITHUB = os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
IS_BITBUCKET = bool(os.environ.get("BITBUCKET_BUILD_NUMBER"))

# Force Docker executor in CI
if IS_CI:
    os.environ["PHANTOM_EXECUTOR"] = "docker"

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

try:
    import anthropic
except ImportError:
    print("[phantom-ci] ERROR: pip install anthropic", file=sys.stderr)
    sys.exit(2)

from orchestrator import PhantomOrchestrator, SPECIALIST_PERSONAS
from tools import TOOLS
from main import dispatch_tool

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
DEFAULT_THRESHOLD = os.environ.get("FAIL_THRESHOLD", "HIGH")
MODEL = "claude-opus-4-8"
MAX_TOKENS = 8096

SCOPE_TO_AGENTS = {
    "web":   ["recon", "webapp"],
    "api":   ["recon", "webapp"],
    "ad":    ["recon", "ad"],
    "cloud": ["cloud"],
    "ai":    ["ai"],
    "full":  ["recon", "webapp", "ad", "cloud", "ai"],
}

CI_COORDINATOR_SYSTEM = (
    "You are Phantom CI Coordinator running in a CD pipeline staging gate. "
    "Your job is to orchestrate a security assessment of the staging environment and "
    "produce a structured JSON findings report. "
    "Use spawn_agent to dispatch specialist agents (recon, webapp, ad, cloud, exploit). "
    "Use get_agent_results to collect their output. "
    "When all agents are done, output ONLY valid JSON in this exact format:\n"
    "{\n"
    '  "findings": [\n'
    '    {\n'
    '      "id": "F001",\n'
    '      "title": "Finding title",\n'
    '      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",\n'
    '      "category": "injection|auth|config|exposure|crypto|dos|other",\n'
    '      "target": "url or IP",\n'
    '      "description": "What was found",\n'
    '      "evidence": "Command output or proof",\n'
    '      "remediation": "How to fix",\n'
    '      "cve": null,\n'
    '      "attack_technique": "T1190 or null",\n'
    '      "confirmed": true\n'
    "    }\n"
    "  ],\n"
    '  "summary": {\n'
    '    "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,\n'
    '    "risk_score": 0,\n'
    '    "recommendation": "BLOCK_DEPLOY|PROCEED_WITH_CAUTION|PROCEED"\n'
    "  }\n"
    "}\n"
    "Do not output any text outside the JSON block. This output is machine-parsed."
)

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    """Load YAML or JSON pentest config file."""
    try:
        import yaml  # type: ignore
        with open(path) as f:
            return yaml.safe_load(f)
    except ImportError:
        with open(path) as f:
            return json.load(f)


def build_config_from_args(args: argparse.Namespace) -> dict:
    return {
        "engagement": {
            "name": args.name or f"staging-pentest-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            "targets": args.target,
            "scope": [s.strip() for s in args.scope.split(",")],
            "fail_threshold": args.threshold,
            "timeout": args.timeout,
        },
        "output": {
            "json": args.output,
            "sarif": args.sarif,
            "markdown": args.output.replace(".json", ".md") if args.output else None,
        },
    }

# ---------------------------------------------------------------------------
# Coordinator agent (headless agentic loop)
# ---------------------------------------------------------------------------

def run_coordinator(config: dict, api_key: str) -> dict:
    """
    Run the CI coordinator agent. Returns parsed findings dict.
    """
    from orchestrator import spawn_agent_tool_def, get_agent_results_tool_def

    engagement = config.get("engagement", {})
    targets = engagement.get("targets", [])
    scope = engagement.get("scope", ["web"])
    timeout = int(engagement.get("timeout", 1800))
    name = engagement.get("name", "CI Pentest")

    orch = PhantomOrchestrator(api_key=api_key)
    client = anthropic.Anthropic(api_key=api_key)

    agent_types = set()
    for s in scope:
        agent_types.update(SCOPE_TO_AGENTS.get(s, ["recon", "webapp"]))

    target_str = ", ".join(targets) if isinstance(targets, list) else str(targets)
    task_prompt = (
        f"Engagement: {name}\n"
        f"Targets: {target_str}\n"
        f"Scope: {', '.join(scope)}\n"
        f"Required agent types: {', '.join(sorted(agent_types))}\n\n"
        "Start by spawning the required specialist agents in parallel. "
        "Wait for all agents to complete using get_agent_results. "
        "Then output the consolidated JSON findings report."
    )

    ci_tools = TOOLS + [spawn_agent_tool_def(), get_agent_results_tool_def()]

    messages = [{"role": "user", "content": task_prompt}]
    deadline = time.time() + timeout
    final_text = ""

    print(f"[phantom-ci] Coordinator started — targets={target_str} scope={scope}")

    while time.time() < deadline:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=CI_COORDINATOR_SYSTEM,
            tools=ci_tools,
            messages=messages,
        )

        text_parts = [b.text for b in response.content if b.type == "text"]

        if response.stop_reason == "end_turn":
            final_text = "\n".join(text_parts)
            break

        if response.stop_reason == "tool_use":
            assistant_blocks = []
            for b in response.content:
                if b.type == "tool_use":
                    assistant_blocks.append({
                        "type": "tool_use", "id": b.id,
                        "name": b.name, "input": b.input,
                    })
                else:
                    assistant_blocks.append({"type": "text", "text": getattr(b, "text", "")})
            messages.append({"role": "assistant", "content": assistant_blocks})

            tool_results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue
                name_t, inp = block.name, block.input
                print(f"  [coordinator] {name_t}({json.dumps(inp, separators=(',', ':'))[:120]})")

                if name_t == "spawn_agent":
                    result = orch.spawn_agent(
                        agent_type=inp.get("agent_type", "recon"),
                        task=inp.get("task", ""),
                        targets=inp.get("targets", []),
                        context=inp.get("context", ""),
                        depth=0,
                    )
                elif name_t == "get_agent_results":
                    req = inp.get("agent_id")
                    result = json.dumps(
                        orch.get_result(req) if req else orch.get_all_results(),
                        indent=2,
                    )
                else:
                    result = dispatch_tool(name_t, inp)

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": str(result),
                })

            messages.append({"role": "user", "content": tool_results})
            continue

        final_text = "\n".join(text_parts) if text_parts else ""
        break

    return _extract_json(final_text)


def _extract_json(text: str) -> dict:
    """Extract JSON findings block from coordinator output."""
    # Try direct parse
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass
    # Try extracting from markdown code block
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Try finding first { ... } block
    match = re.search(r"(\{.*\})", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    print("[phantom-ci] WARNING: Could not parse coordinator JSON output.", file=sys.stderr)
    return {"findings": [], "summary": {"total": 0, "critical": 0, "high": 0,
                                         "medium": 0, "low": 0, "info": 0,
                                         "risk_score": 0, "recommendation": "PROCEED"}}

# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_json_report(findings: dict, config: dict, path: str, scorecard: dict | None = None):
    report = {
        "tool": "Phantom CI",
        "version": "1.0.0",
        "platform": "github" if IS_GITHUB else "bitbucket" if IS_BITBUCKET else "local",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "engagement": config.get("engagement", {}),
        **findings,
    }
    if scorecard:
        report["scorecard"] = scorecard
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(report, indent=2))
    print(f"[phantom-ci] JSON report → {path}")


def write_markdown_summary(findings: dict, path: str, scorecard: dict | None = None):
    summary = findings.get("summary", {})
    items = findings.get("findings", [])
    lines = [
        "# Phantom CI — Pentest Report",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Risk Score:** {summary.get('risk_score', 0)}/100  ",
        f"**Recommendation:** `{summary.get('recommendation', 'UNKNOWN')}`\n",
        "## Summary",
        f"| Severity | Count |",
        f"|---|---|",
        f"| 🔴 CRITICAL | {summary.get('critical', 0)} |",
        f"| 🟠 HIGH     | {summary.get('high', 0)} |",
        f"| 🟡 MEDIUM   | {summary.get('medium', 0)} |",
        f"| 🟢 LOW      | {summary.get('low', 0)} |",
        f"| ℹ INFO     | {summary.get('info', 0)} |",
        "",
    ]

    if scorecard:
        from reports.scorecard import render_markdown_scorecard
        lines.append(render_markdown_scorecard(scorecard))

    lines.append("\n## Findings")
    for f in sorted(items, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 0), reverse=True):
        lines += [
            f"### [{f.get('severity')}] {f.get('title')}",
            f"**Target:** `{f.get('target')}`  ",
            f"**Category:** {f.get('category')}  ",
            f"**CVE:** {f.get('cve') or 'N/A'}  ",
            f"**ATT&CK:** {f.get('attack_technique') or 'N/A'}\n",
            f"**Description:** {f.get('description')}\n",
            f"**Evidence:**\n```\n{f.get('evidence', '')}\n```\n",
            f"**Remediation:** {f.get('remediation')}\n",
            "---",
        ]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(lines))
    print(f"[phantom-ci] Markdown report → {path}")


def create_jira_tickets(findings: dict, threshold: str):
    """Create Jira tickets for findings at or above threshold."""
    jira_url = os.environ.get("JIRA_URL")
    jira_user = os.environ.get("JIRA_USER")
    jira_token = os.environ.get("JIRA_TOKEN")
    jira_project = os.environ.get("JIRA_PROJECT")

    if not all([jira_url, jira_user, jira_token, jira_project]):
        return

    try:
        import httpx
    except ImportError:
        return

    thresh_level = SEVERITY_ORDER.get(threshold, 3)
    eligible = [
        f for f in findings.get("findings", [])
        if SEVERITY_ORDER.get(f.get("severity", "INFO"), 0) >= thresh_level
    ]

    if not eligible:
        return

    auth = (jira_user, jira_token)
    headers = {"Content-Type": "application/json"}

    for finding in eligible:
        sev = finding.get("severity", "HIGH")
        priority = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium"}.get(sev, "Low")
        payload = {
            "fields": {
                "project": {"key": jira_project},
                "summary": f"[Phantom CI] [{sev}] {finding.get('title')}",
                "description": (
                    f"*Target:* {finding.get('target')}\n\n"
                    f"*Description:* {finding.get('description')}\n\n"
                    f"*Evidence:*\n{{code}}{finding.get('evidence', '')}{{code}}\n\n"
                    f"*Remediation:* {finding.get('remediation')}\n\n"
                    f"*CVE:* {finding.get('cve') or 'N/A'} | "
                    f"*ATT&CK:* {finding.get('attack_technique') or 'N/A'}"
                ),
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority},
            }
        }
        try:
            r = httpx.post(
                f"{jira_url}/rest/api/2/issue",
                json=payload, auth=auth, headers=headers, timeout=15,
            )
            if r.status_code in (200, 201):
                key = r.json().get("key")
                print(f"[phantom-ci] Jira ticket created: {key} — {finding.get('title')}")
            else:
                print(f"[phantom-ci] Jira error {r.status_code}: {r.text[:200]}", file=sys.stderr)
        except Exception as e:
            print(f"[phantom-ci] Jira request failed: {e}", file=sys.stderr)


def post_google_chat_summary(findings: dict, dd_url: str | None = None):
    """Post pentest summary to a Google Chat space via incoming webhook."""
    webhook = os.environ.get("GOOGLE_CHAT_WEBHOOK_URL")
    if not webhook:
        return
    try:
        import httpx
        summary = findings.get("summary", {})
        rec = summary.get("recommendation", "UNKNOWN")
        icon = {"BLOCK_DEPLOY": "🚨", "PROCEED_WITH_CAUTION": "⚠️", "PROCEED": "✅"}.get(rec, "🔍")
        risk = summary.get("risk_score", 0)

        # Google Chat Card v2 format
        rows = [
            {"keyValue": {"topLabel": "Recommendation", "content": f"{icon} {rec}"}},
            {"keyValue": {"topLabel": "Risk Score",     "content": f"{risk}/100"}},
            {"keyValue": {"topLabel": "Critical / High", "content": f"{summary.get('critical',0)} / {summary.get('high',0)}"}},
            {"keyValue": {"topLabel": "Medium / Low",   "content": f"{summary.get('medium',0)} / {summary.get('low',0)}"}},
        ]
        if dd_url:
            rows.append({"keyValue": {"topLabel": "DefectDojo", "content": dd_url,
                                      "onClick": {"openLink": {"url": dd_url}}}})

        payload = {
            "cards": [{
                "header": {
                    "title": "Phantom CI — Pentest Complete",
                    "subtitle": os.environ.get("GITHUB_REPOSITORY") or os.environ.get("BITBUCKET_REPO_SLUG", ""),
                    "imageUrl": "https://raw.githubusercontent.com/EmmaOK/Anthropic-Cybersecurity-Skills/main/phantom/static/killphish/taskpane.html",
                },
                "sections": [{"widgets": rows}],
            }]
        }
        httpx.post(webhook, json=payload, timeout=10)
        print("[phantom-ci] Google Chat notification sent.")
    except Exception as e:
        print(f"[phantom-ci] Google Chat notification failed: {e}", file=sys.stderr)


def push_to_defectdojo(findings: dict, config: dict) -> str | None:
    """
    Push pentest findings into DefectDojo:
      1. Create a CI/CD engagement for this pipeline run
      2. Import all findings via Generic Findings Import

    Returns the DefectDojo engagement URL on success, or None on failure.
    Reads DEFECTDOJO_URL, DEFECTDOJO_API_KEY, DEFECTDOJO_PRODUCT_ID from env.
    """
    dd_url    = os.environ.get("DEFECTDOJO_URL", "").rstrip("/")
    dd_key    = os.environ.get("DEFECTDOJO_API_KEY", "")
    product_id = os.environ.get("DEFECTDOJO_PRODUCT_ID", "")

    if not all([dd_url, dd_key, product_id]):
        return None  # DefectDojo not configured — skip silently

    try:
        product_id = int(product_id)
    except ValueError:
        print("[phantom-ci] DEFECTDOJO_PRODUCT_ID must be an integer.", file=sys.stderr)
        return None

    try:
        import urllib.request, urllib.parse, urllib.error
    except ImportError:
        return None

    headers = {
        "Authorization": f"Token {dd_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    def _post(endpoint: str, data: dict) -> dict:
        url = f"{dd_url}/api/v2/{endpoint.lstrip('/')}/"
        body = json.dumps(data).encode()
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}", "detail": e.read().decode(errors="replace")}
        except Exception as e:
            return {"error": str(e)}

    engagement = config.get("engagement", {})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    build_id = (
        os.environ.get("GITHUB_RUN_NUMBER")
        or os.environ.get("BITBUCKET_BUILD_NUMBER")
        or "local"
    )
    engagement_name = f"Phantom CI #{build_id} — {engagement.get('name', 'Pentest')}"

    # Step 1 — Create engagement
    eng = _post("engagements", {
        "name":            engagement_name,
        "product":         product_id,
        "target_start":    today,
        "target_end":      today,
        "engagement_type": "CI/CD",
        "status":          "In Progress",
        "description":     (
            f"Automated pentest by Phantom CI.\n"
            f"Targets: {engagement.get('targets')}\n"
            f"Scope: {engagement.get('scope')}"
        ),
    })

    if "error" in eng:
        print(f"[phantom-ci] DefectDojo engagement creation failed: {eng}", file=sys.stderr)
        return None

    engagement_id  = eng["id"]
    engagement_url = f"{dd_url}/engagement/{engagement_id}"
    print(f"[phantom-ci] DefectDojo engagement created: {engagement_url}")

    # Step 2 — Create a test inside the engagement
    test = _post("tests", {
        "engagement":  engagement_id,
        "test_type":   104,            # 104 = Generic Findings Import in default DD installs
        "title":       "Phantom CI Automated Pentest",
        "target_start": today,
        "target_end":   today,
        "environment":  1,             # 1 = Development (adjust per your DD setup)
    })

    if "error" in test:
        print(f"[phantom-ci] DefectDojo test creation failed: {test}", file=sys.stderr)
        # Engagement exists but no test — still return the URL
        return engagement_url

    test_id = test["id"]
    print(f"[phantom-ci] DefectDojo test created: id={test_id}")

    # Step 3 — Import individual findings
    imported = 0
    for f in findings.get("findings", []):
        sev_map = {
            "CRITICAL": "Critical", "HIGH": "High",
            "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info",
        }
        result = _post("findings", {
            "test":        test_id,
            "title":       f.get("title", "Untitled Finding"),
            "severity":    sev_map.get(f.get("severity", "INFO"), "Info"),
            "description": f.get("description", ""),
            "mitigation":  f.get("remediation", ""),
            "references":  (
                f"ATT&CK: {f.get('attack_technique')}\nCVE: {f.get('cve')}"
                if f.get("attack_technique") or f.get("cve") else ""
            ),
            "cve":         f.get("cve"),
            "active":      True,
            "verified":    False,
            "numerical_severity": sev_map.get(f.get("severity", "INFO"), "I"),
            "endpoints":   [{"host": f.get("target", "")}] if f.get("target") else [],
        })
        if "error" not in result:
            imported += 1

    # Step 4 — Close the engagement
    close_url = f"{dd_url}/api/v2/engagements/{engagement_id}/"
    body = json.dumps({"status": "Completed"}).encode()
    req = urllib.request.Request(close_url, data=body, headers=headers, method="PATCH")
    try:
        with urllib.request.urlopen(req, timeout=30):
            pass
    except Exception:
        pass

    print(f"[phantom-ci] DefectDojo: {imported}/{len(findings.get('findings', []))} findings imported → {engagement_url}")
    return engagement_url


def emit_github_annotations(findings: dict, threshold: str):
    """Emit GitHub Actions workflow commands for inline PR annotations."""
    if not IS_GITHUB:
        return
    thresh_level = SEVERITY_ORDER.get(threshold, 3)
    for f in findings.get("findings", []):
        level = SEVERITY_ORDER.get(f.get("severity", "INFO"), 0)
        if level >= thresh_level:
            cmd = "error" if level >= 3 else "warning"
            title = f"[{f.get('severity')}] {f.get('title')}"
            msg = f"{f.get('description')} | Remediation: {f.get('remediation')}"
            print(f"::{cmd} title={title}::{msg}")

# ---------------------------------------------------------------------------
# Threshold check
# ---------------------------------------------------------------------------

def check_threshold(findings: dict, threshold: str) -> bool:
    """Returns True if any finding is at or above threshold (deploy should be blocked)."""
    thresh_level = SEVERITY_ORDER.get(threshold.upper(), 3)
    for f in findings.get("findings", []):
        if SEVERITY_ORDER.get(f.get("severity", "INFO"), 0) >= thresh_level:
            return True
    return False

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Phantom CI — headless pentest runner for CD staging gates"
    )
    p.add_argument("--config", help="Path to YAML/JSON pentest config file")
    p.add_argument("--target", nargs="+", help="Target URL(s) or IP ranges")
    p.add_argument("--scope", default="web,api",
                   help="Comma-separated scope: web,api,ad,cloud,full (default: web,api)")
    p.add_argument("--threshold", default=DEFAULT_THRESHOLD,
                   choices=["CRITICAL", "HIGH", "MEDIUM"],
                   help="Severity threshold that blocks deploy (default: HIGH)")
    p.add_argument("--timeout", type=int, default=1800,
                   help="Max engagement duration in seconds (default: 1800)")
    p.add_argument("--output", default="reports/pentest_report.json",
                   help="JSON report output path")
    p.add_argument("--sarif", default="reports/pentest.sarif",
                   help="SARIF output path (for GitHub Security tab)")
    p.add_argument("--name", help="Engagement name (defaults to timestamp)")
    p.add_argument("--llm-endpoint", help="LLM/AI target (model name or REST URL) for --scope ai")
    p.add_argument("--llm-type", default="anthropic",
                   choices=["anthropic", "openai", "huggingface", "rest"],
                   help="LLM provider type (default: anthropic)")
    p.add_argument("--llm-api-key", help="API key for LLM provider (or set env var)")
    p.add_argument("--llm-risks", default="all",
                   help="OWASP LLM risk IDs to test: LLM01,LLM02,... or 'all' (default: all)")
    p.add_argument("--mcp-server-url", help="MCP server URL for MCP Top 10 testing")
    p.add_argument("--fail-on-error", action="store_true",
                   help="Exit 2 on scanner error instead of 0 (fail closed)")
    return p.parse_args()


def main():
    args = parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[phantom-ci] ERROR: ANTHROPIC_API_KEY not set.", file=sys.stderr)
        sys.exit(2)

    # Build config
    if args.config:
        config = load_config(args.config)
    elif args.target:
        config = build_config_from_args(args)
    else:
        print("[phantom-ci] ERROR: Provide --config or --target.", file=sys.stderr)
        sys.exit(2)

    engagement = config.get("engagement", {})
    threshold = engagement.get("fail_threshold", args.threshold).upper()
    output_cfg = config.get("output", {})
    json_path = output_cfg.get("json", args.output)
    sarif_path = output_cfg.get("sarif", args.sarif)
    md_path = output_cfg.get("markdown", json_path.replace(".json", ".md") if json_path else None)

    platform = "GitHub Actions" if IS_GITHUB else "Bitbucket Pipelines" if IS_BITBUCKET else "local"
    print(f"[phantom-ci] Platform   : {platform}")
    print(f"[phantom-ci] Executor   : {'Docker' if IS_CI else 'UTM VM'}")
    print(f"[phantom-ci] Threshold  : {threshold}")
    print(f"[phantom-ci] Targets    : {engagement.get('targets')}")
    print(f"[phantom-ci] Scope      : {engagement.get('scope')}")
    print()

    # Run coordinator
    try:
        findings = run_coordinator(config, api_key)
    except Exception as e:
        print(f"[phantom-ci] ERROR: Coordinator failed: {e}", file=sys.stderr)
        sys.exit(2 if args.fail_on_error else 0)

    summary = findings.get("summary", {})
    print(f"\n[phantom-ci] ── Results ──────────────────────────")
    print(f"[phantom-ci] CRITICAL : {summary.get('critical', 0)}")
    print(f"[phantom-ci] HIGH     : {summary.get('high', 0)}")
    print(f"[phantom-ci] MEDIUM   : {summary.get('medium', 0)}")
    print(f"[phantom-ci] LOW      : {summary.get('low', 0)}")
    print(f"[phantom-ci] Risk     : {summary.get('risk_score', 0)}/100")
    print(f"[phantom-ci] Decision : {summary.get('recommendation', 'UNKNOWN')}")
    print(f"[phantom-ci] ─────────────────────────────────────")

    # Build scorecard
    scorecard = None
    try:
        from reports.scorecard import build_scorecard, render_html
        scorecard = build_scorecard(findings, config)
        sc_html_path = json_path.replace(".json", "_scorecard.html") if json_path else "reports/scorecard.html"
        Path(sc_html_path).parent.mkdir(parents=True, exist_ok=True)
        Path(sc_html_path).write_text(render_html(scorecard))
        ov = scorecard["overall"]
        print(f"[phantom-ci] Scorecard      : Grade {ov['grade']} ({ov['score']}/100) → {sc_html_path}")
    except Exception as e:
        print(f"[phantom-ci] Scorecard generation failed: {e}", file=sys.stderr)

    # Write reports
    if json_path:
        write_json_report(findings, config, json_path, scorecard=scorecard)
    if md_path:
        write_markdown_summary(findings, md_path, scorecard=scorecard)

    # SARIF (GitHub)
    if IS_GITHUB and sarif_path:
        from reports.to_sarif import convert_to_sarif
        sarif = convert_to_sarif(findings, config)
        Path(sarif_path).parent.mkdir(parents=True, exist_ok=True)
        Path(sarif_path).write_text(json.dumps(sarif, indent=2))
        print(f"[phantom-ci] SARIF report → {sarif_path}")

    # Jira tickets
    create_jira_tickets(findings, threshold)

    # Google Chat
    dd_engagement_url = push_to_defectdojo(findings, config)
    if dd_engagement_url:
        print(f"[phantom-ci] DefectDojo engagement → {dd_engagement_url}")
    post_google_chat_summary(findings, dd_url=dd_engagement_url)

    # GitHub annotations
    emit_github_annotations(findings, threshold)

    # Gate decision
    blocked = check_threshold(findings, threshold)
    if blocked:
        print(f"\n[phantom-ci] ✗ DEPLOY BLOCKED — findings at or above {threshold} detected.")
        sys.exit(1)
    else:
        print(f"\n[phantom-ci] ✓ Deploy gate passed — no findings at or above {threshold}.")
        sys.exit(0)


if __name__ == "__main__":
    main()
