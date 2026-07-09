---
name: shadow-ai-and-saas-discovery
description: >-
  Discover and inventory unauthorized AI tools and SaaS applications in use
  across a 400+ remote workforce. Combines browser telemetry, network egress
  analysis, IdP sign-in logs, and cloud access security broker (CASB) data to
  surface shadow AI tools (ChatGPT personal accounts, Gemini, Perplexity,
  consumer Copilot) and unsanctioned SaaS. Produces a risk-ranked inventory
  so security teams can decide to block, monitor, or formally onboard each
  discovered application.
domain: cybersecurity
subdomain: cloud-security
tags:
  - shadow-ai
  - saas-discovery
  - ai-governance
  - casb
  - browser-security
  - unsanctioned-apps
  - remote-workforce
  - data-governance
version: '1.0'
author: emmanuelokonkwo
license: Apache-2.0
nist_csf:
  - ID.AM-01
  - ID.AM-02
  - DE.CM-01
  - DE.CM-06
d3fend_techniques:
  - Network Traffic Analysis
  - Software Inventory
---

# Shadow AI and SaaS Discovery

## When to Use

- When you need to know which AI tools employees are actually using, not just which ones are approved
- When a data loss incident or audit surfaces unknown SaaS applications in network logs
- Before rolling out an AI governance policy — establish baseline usage first
- When IdP logs show OAuth grants to applications outside your sanctioned list
- Quarterly, as part of your SaaS spend and risk review cycle

**Do not use** as a substitute for a formal CASB deployment — this skill surfaces the discovery workflow; a CASB provides continuous enforcement.

## Prerequisites

- Read access to IdP sign-in logs (Entra ID / Okta / Google Workspace)
- DNS query logs or web proxy logs (Zscaler, Netskope, Palo Alto) covering remote workforce traffic
- Admin access to a CASB or SSE platform (Netskope, Microsoft Defender for Cloud Apps, Zscaler CASB)
- Browser management in place (Chrome CBCM or Edge Intune) for browser-level telemetry
- List of currently sanctioned SaaS and AI applications from IT/procurement

## Workflow

### Step 1: Extract OAuth Grants from IdP to Find Sanctioned vs Shadow Apps

OAuth consent grants are the fastest signal — any app an employee has granted access to appears here regardless of whether IT approved it.

```bash
# Entra ID: export OAuth app grants via Microsoft Graph
az login --tenant your-tenant-id

# List all OAuth2 permission grants (delegated permissions granted by users)
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?\$top=999" \
  --query "value[].{app:clientId, scope:scope, user:principalId}" \
  --output table > oauth_grants.txt

# Cross-reference against your sanctioned app list
python3 << 'EOF'
import json, subprocess

sanctioned = {
    "microsoft-365", "slack", "zoom", "github",
    "anthropic-claude-enterprise", "openai-chatgpt-enterprise"
}

result = subprocess.run([
    "az", "rest", "--method", "GET",
    "--url", "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999",
    "--query", "value[].{appId:clientId,scope:scope}"
], capture_output=True, text=True)

grants = json.loads(result.stdout)
shadow = [g for g in grants if g.get("appId") not in sanctioned]
print(f"Shadow apps found: {len(shadow)}")
for app in shadow[:20]:
    print(f"  App ID: {app['appId']} | Scopes: {app['scope']}")
EOF
```

```bash
# Okta: export third-party app grants
okta-cli apps list --filter 'status eq "ACTIVE"' --format json | \
  jq '.[] | select(.label | test("(?i)chatgpt|gemini|perplexity|claude|copilot|cursor|midjourney|runway|elevenlabs|notion|monday|linear"))' \
  > shadow_ai_candidates.json
```

### Step 2: Analyse DNS / Proxy Logs for AI Tool Traffic

Network egress shows what employees are reaching even without OAuth — browser-based AI tools often don't require a grant.

```python
#!/usr/bin/env python3
"""Parse proxy/DNS logs to find AI and SaaS tool usage."""

import re
from collections import defaultdict
from datetime import datetime

AI_TOOL_DOMAINS = {
    "chat.openai.com": "ChatGPT (consumer)",
    "chatgpt.com": "ChatGPT (consumer)",
    "claude.ai": "Claude (consumer)",
    "gemini.google.com": "Gemini (consumer)",
    "perplexity.ai": "Perplexity",
    "copilot.microsoft.com": "Copilot (consumer)",
    "www.bing.com/chat": "Copilot/Bing Chat",
    "poe.com": "Poe AI",
    "character.ai": "Character.ai",
    "huggingface.co": "HuggingFace",
    "replicate.com": "Replicate",
    "together.ai": "Together AI",
    "groq.com": "Groq",
    "cursor.sh": "Cursor IDE",
    "codeium.com": "Codeium",
    "tabnine.com": "Tabnine",
    "v0.dev": "Vercel v0",
    "lovable.dev": "Lovable",
    "bolt.new": "Bolt.new",
    "gamma.app": "Gamma AI",
    "runway.com": "Runway ML",
    "midjourney.com": "Midjourney",
    "elevenlabs.io": "ElevenLabs",
    "suno.com": "Suno AI",
}

def parse_proxy_log(log_file: str) -> dict:
    """Parse standard W3C/NCSA proxy log format."""
    usage = defaultdict(lambda: {"hits": 0, "users": set(), "bytes": 0})

    with open(log_file) as f:
        for line in f:
            for domain, tool_name in AI_TOOL_DOMAINS.items():
                if domain in line:
                    parts = line.split()
                    user = parts[2] if len(parts) > 2 else "unknown"
                    bytes_sent = int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else 0
                    usage[tool_name]["hits"] += 1
                    usage[tool_name]["users"].add(user)
                    usage[tool_name]["bytes"] += bytes_sent

    return {
        tool: {
            "hits": data["hits"],
            "unique_users": len(data["users"]),
            "total_bytes_mb": round(data["bytes"] / 1_048_576, 2)
        }
        for tool, data in sorted(usage.items(), key=lambda x: -x[1]["hits"])
    }

if __name__ == "__main__":
    import sys, json
    log_file = sys.argv[1] if len(sys.argv) > 1 else "proxy.log"
    report = parse_proxy_log(log_file)
    print(json.dumps(report, indent=2))
```

### Step 3: CASB-Based Risk Scoring and Classification

Once you have the raw list, pull CASB risk metadata to prioritise which apps need immediate action.

```bash
# Microsoft Defender for Cloud Apps — discover shadow apps via Cloud App Catalog
# Portal: security.microsoft.com → Cloud Apps → Cloud Discovery → Dashboard

# Export discovered apps via MDCA API
curl -H "Authorization: Bearer $MDCA_TOKEN" \
  "https://yourorg.portal.cloudappsecurity.com/api/v1/discovery/discovered_apps/" \
  -G --data-urlencode "filters={\"risk\":{\"gte\":7}}" \
  | jq '.data[] | {name:.app.name, risk_score:.app.risk, users:.users, traffic_gb:.traffic}'

# Netskope: pull app instance discovery report
curl -H "Netskope-Api-Token: $NETSKOPE_TOKEN" \
  "https://yourorg.goskope.com/api/v1/discovery?type=app_instance&timeperiod=last30days" \
  | jq '.data.apps[] | select(.cci < 50) | {app:.app_name, cci:.cci, users:.users}'
```

### Step 4: Build the Shadow AI / SaaS Inventory

Consolidate all signals into a risk-ranked inventory with a recommended action per app.

```python
#!/usr/bin/env python3
"""Consolidate shadow app signals into a risk-ranked inventory."""

import json
from dataclasses import dataclass, asdict
from typing import Literal

Action = Literal["block", "monitor", "onboard", "review"]

@dataclass
class ShadowApp:
    name: str
    category: str
    unique_users: int
    data_exposure_risk: str  # high/medium/low
    casb_risk_score: int     # 0-10
    oauth_grants: bool
    recommended_action: Action
    rationale: str

def score_action(app: ShadowApp) -> Action:
    if app.casb_risk_score >= 8 or app.data_exposure_risk == "high":
        return "block"
    if app.unique_users > 50 and app.casb_risk_score < 5:
        return "onboard"
    if app.unique_users > 10:
        return "monitor"
    return "review"

def generate_inventory(raw_apps: list[dict]) -> dict:
    apps = [ShadowApp(**a) for a in raw_apps]
    for app in apps:
        app.recommended_action = score_action(app)

    return {
        "generated": "2026-06-08",
        "total_shadow_apps": len(apps),
        "block_count": sum(1 for a in apps if a.recommended_action == "block"),
        "onboard_count": sum(1 for a in apps if a.recommended_action == "onboard"),
        "apps": [asdict(a) for a in sorted(apps, key=lambda x: -x.casb_risk_score)]
    }
```

### Step 5: Continuous Discovery Pipeline

Set up ongoing discovery so new AI tools are caught within 24 hours of first use.

```bash
# Entra ID: alert on new OAuth grants to unknown apps
# Azure Monitor → Alerts → New alert rule
# Signal: Audit Logs → "Consent to application"
# Condition: ServicePrincipal not in sanctioned_app_object_ids
# Action: send to SIEM + notify IT-security Slack channel

# Chrome CBCM: enable Safe Browsing Extended Reporting to surface new domains
# Admin Console → Chrome → Reporting → Chrome Safe Browsing Extended Reporting = Enabled

# Weekly cron: re-run proxy log parser and diff against last week's inventory
# crontab entry: 0 6 * * 1 python3 /opt/security/shadow_ai_discovery.py --diff last_week.json
```

## Key Concepts

| Term | Definition |
|---|---|
| Shadow AI | AI tools (ChatGPT, Gemini, Perplexity, etc.) accessed via personal or consumer accounts rather than corporate-provisioned ones — identical capability, zero IT visibility or data governance |
| Shadow SaaS | Any SaaS application in use without IT approval or procurement involvement; discovered via OAuth grants, DNS, or proxy logs rather than asset inventory |
| CASB (Cloud Access Security Broker) | Security control plane that sits between users and cloud services; provides visibility, compliance, DLP, and threat protection for SaaS traffic |
| Cloud Confidence Index (CCI) | Netskope's 0–100 risk score for SaaS/AI apps; below 50 typically triggers block or monitor policy |
| OAuth consent grant | Permission a user grants an app to access their IdP-managed resources (email, files, identity); visible in IdP admin console and a reliable signal for shadow app discovery |
| SSE (Security Service Edge) | Converged cloud-native security stack combining CASB, SWG, and ZTNA; primary enforcement point for remote workforce SaaS traffic |

## Tools & Systems

- **Microsoft Defender for Cloud Apps (MDCA)**: Integrated CASB with Cloud App Catalog risk scoring; native integration with Entra ID and Microsoft 365 telemetry
- **Netskope**: CASB/SSE platform with granular app instance controls (e.g., block personal ChatGPT accounts while allowing enterprise)
- **Zscaler Internet Access**: SWG/CASB with AI app discovery and URL categorisation for 400,000+ cloud apps
- **Entra ID Audit Logs**: OAuth consent grant events; source of truth for which third-party apps have been granted access to corporate identities
- **Google Workspace Admin**: App access control panel showing OAuth grants to Google-identity-authenticated users

## Common Scenarios

### Scenario: Marketing team using Gemini with client data

**Context**: Proxy logs show 23 marketing employees hitting `gemini.google.com` with large upload payloads. Personal Google accounts — no DLP controls in place.

**Approach**:
1. CASB confirms personal Gemini instance (not Google Workspace AI) — CCI score 62 (medium risk due to data retention policy ambiguity)
2. Block personal Gemini instance via Netskope app instance policy; allow Gemini for Google Workspace (enterprise instance) if licensed
3. Send policy-violation notification to users explaining the distinction
4. Fast-track enterprise Gemini provisioning if demand is legitimate

### Scenario: Developers using Cursor IDE with proprietary code

**Context**: DNS logs reveal 15 engineers hitting `cursor.sh` and `api2.cursor.sh` — code completion sending proprietary source to Cursor's cloud.

**Approach**:
1. Assess Cursor's data processing agreement — does it train on user code?
2. If training opt-out is available and DPA is acceptable: onboard formally, distribute enterprise license, add to sanctioned list
3. If not acceptable: block domain, offer approved alternative (GitHub Copilot with enterprise privacy mode or Codeium self-hosted)

## Output Format

```json
{
  "discovery_report": {
    "period": "2026-05-09 to 2026-06-08",
    "total_shadow_apps": 34,
    "ai_tools": 18,
    "other_saas": 16
  },
  "action_summary": {
    "block": 6,
    "monitor": 12,
    "onboard": 9,
    "review": 7
  },
  "top_risk_apps": [
    {
      "name": "ChatGPT (consumer)",
      "unique_users": 87,
      "data_exposure_risk": "high",
      "casb_risk_score": 8,
      "recommended_action": "block",
      "rationale": "No enterprise DPA; training on input data by default; 87 users uploading files"
    },
    {
      "name": "Cursor IDE",
      "unique_users": 15,
      "data_exposure_risk": "high",
      "casb_risk_score": 6,
      "recommended_action": "review",
      "rationale": "Source code exfiltration risk; pending DPA review"
    }
  ]
}
```
