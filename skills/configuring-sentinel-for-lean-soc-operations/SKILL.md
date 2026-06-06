---
name: configuring-sentinel-for-lean-soc-operations
description: >-
  Configure Microsoft Sentinel for a one-person or lean security operations
  team where alert volume, cost, and analyst bandwidth are all constrained.
  Covers ingestion cost optimization and free data source prioritization,
  Content Hub solution deployment for instant detection coverage, automated
  Tier-1 triage playbooks (enrichment, FP suppression, severity scoring),
  watchlist-driven context injection, incident queue hygiene rules, and a
  scheduled daily digest so a solo analyst can run an effective SOC without
  real-time console monitoring.
domain: cybersecurity
subdomain: soc-operations
tags:
  - microsoft-sentinel
  - soc-operations
  - alert-triage
  - cost-optimization
  - soar-automation
  - lean-soc
  - incident-response
  - kql
version: '1.0'
author: emmanuelokonkwo
license: Apache-2.0
nist_csf:
  - DE.CM-01
  - DE.AE-02
  - RS.AN-01
  - RS.MI-01
  - ID.IM-02
d3fend_techniques:
  - Log Analysis
  - Platform Monitoring
---

# Configuring Sentinel for Lean SOC Operations

## When to Use

- When operating Sentinel as a solo analyst or a team of two with no dedicated Tier-1 staff
- When monthly Sentinel ingestion costs are uncontrolled or growing faster than the security budget
- When alert volume exceeds what one person can triage in a working day
- When standing up a new Sentinel deployment and wanting to reach operational maturity fast without building everything from scratch
- When transitioning from a managed SOC back to in-house with a small team

**Do not use** as a replacement for `building-cloud-siem-with-sentinel` (which covers initial deployment and multi-cloud connector setup) — this skill assumes Sentinel is already provisioned and ingesting logs.

## Prerequisites

- Microsoft Sentinel deployed on a Log Analytics workspace (see `building-cloud-siem-with-sentinel`)
- Microsoft 365 E3/E5 or Defender for Office 365/Endpoint licenses (unlock free data connectors)
- Logic Apps Contributor and Microsoft Sentinel Contributor IAM roles
- Azure Automation Account (for the daily digest runbook)
- Basic KQL proficiency

## Workflow

### Step 1: Optimize Ingestion Costs — Free Sources First

A one-person SOC lives and dies by budget. Sentinel charges per GB of ingested data. Maximize free-tier sources before paying for anything else.

```bash
# Free data sources — zero ingestion cost, enable all of these first
FREE_CONNECTORS=(
  "MicrosoftDefenderAdvancedThreatProtection"   # Defender for Endpoint alerts
  "MicrosoftCloudAppSecurity"                   # Defender for Cloud Apps
  "AzureSecurityCenter"                         # Defender for Cloud alerts
  "Office365"                                   # M365 audit logs (Exchange, SharePoint, Teams)
  "AzureActiveDirectory"                        # Entra ID sign-in + audit logs
  "AzureActivity"                               # Azure control plane logs
  "MicrosoftThreatProtection"                   # Microsoft 365 Defender incidents
)

for connector in "${FREE_CONNECTORS[@]}"; do
  echo "Enabling free connector: $connector"
done

# Paid connectors — enable only what you actively query (cost = GB ingested)
# CEF/Syslog: filter at the source forwarder before sending to Sentinel
# AWS CloudTrail: consider enabling only for CloudTrail Insights events, not all API calls
# Third-party firewalls: use Basic Logs tier (8x cheaper) for high-volume, low-query tables
```

```bash
# Switch high-volume, rarely-queried tables to Basic Logs tier ($0.60/GB vs $4.30/GB)
# Suitable for: AzureDiagnostics, NetworkAccessTraffic, CommonSecurityLog (firewall raw)
az monitor log-analytics workspace table update \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --name "AzureDiagnostics" \
  --plan "Basic"

# Set retention: 90 days hot (included), archive beyond that at $0.03/GB/month
az monitor log-analytics workspace table update \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --name "SecurityEvent" \
  --retention-time 90 \
  --total-retention-time 365

# Commit tier pricing — if ingesting > 100 GB/day, commitment beats pay-as-you-go
# Calculate your daily average first:
# SecurityEvent | summarize sum(estimate_data_size(*)) by bin(TimeGenerated, 1d)
az monitor log-analytics workspace update \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --sku CapacityReservation \
  --capacity-reservation-level 100   # GB/day commitment tier
```

```kql
// Monitor daily ingestion cost by table — run weekly to spot cost spikes
Usage
| where TimeGenerated > ago(7d)
| where IsBillable == true
| summarize TotalGB = sum(Quantity) / 1024, EstimatedCostUSD = sum(Quantity) / 1024 * 4.30
            by DataType
| sort by TotalGB desc
| take 15
```

### Step 2: Deploy Content Hub Solutions for Instant Detection Coverage

Content Hub provides Microsoft-maintained detection rule packs mapped to ATT&CK. A solo analyst should not write rules from scratch — deploy these first and tune, rather than author from zero.

```bash
# Install priority Content Hub solutions for a lean SOC
# These install analytics rules, workbooks, hunting queries, and playbooks in bulk

PRIORITY_SOLUTIONS=(
  "Microsoft Entra ID"              # Identity threats — highest ROI for most orgs
  "Microsoft 365 Defender"          # Endpoint + email + identity unified alerts
  "Microsoft Defender for Cloud"    # Cloud posture alerts pre-wired to Sentinel
  "Endpoint Threat Protection Essentials"  # Core endpoint detection rules
  "SOC Handbook"                    # Pre-built SOC process workbooks
  "MITRE ATT&CK Solution for Sentinel"    # ATT&CK coverage heatmap + hunting
  "Threat Intelligence"             # MSTIC feed + TI matching rules
)

# Install via portal: Sentinel → Content Hub → search each solution → Install
# Or via REST API:
SUBSCRIPTION_ID="your-subscription-id"
RG="security-rg"
WORKSPACE="sentinel-workspace"

curl -X PUT \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE/providers/Microsoft.SecurityInsights/contentPackages/azuresentinel.azure-sentinel-solution-azureactivedirectory?api-version=2023-06-01-preview" \
  -H "Authorization: Bearer $AZURE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"properties": {"contentId": "azuresentinel.azure-sentinel-solution-azureactivedirectory", "version": "3.0.0"}}'
```

```kql
// After installing solutions, check how many rules are enabled vs available
_GetWatchlist('SOC-Config')   // reference your own config watchlist (see Step 4)

// List all installed analytics rules with their MITRE technique coverage
SecurityAlert
| union (
    _SentinelEntitiesGetById("")
)
// Use portal: Analytics → Active rules → export to CSV for gap analysis
```

### Step 3: Automated Tier-1 Triage Playbook

A solo analyst cannot manually triage every incident. This Logic App runs automatically on every new incident, enriches entities, scores severity, and closes known false positives — so you only touch incidents that need human judgment.

```json
// Logic App: Auto-Triage-Incident
// Trigger: Microsoft Sentinel incident creation
{
  "definition": {
    "triggers": {
      "Sentinel_incident_created": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['microsoftsentinel']['connectionId']"}},
          "path": "/subscribe"
        }
      }
    },
    "actions": {

      "1_Get_incident_entities": {
        "type": "ApiConnection",
        "runAfter": {},
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['microsoftsentinel']['connectionId']"}},
          "method": "post",
          "path": "/Incidents/entities",
          "body": {"incidentArmId": "@triggerBody()?['object']?['id']"}
        }
      },

      "2_Check_watchlist_FP_suppression": {
        "type": "ApiConnection",
        "runAfter": {"1_Get_incident_entities": ["Succeeded"]},
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['microsoftsentinel']['connectionId']"}},
          "method": "get",
          "path": "/Watchlists/FP-Suppression/WatchlistItems",
          "queries": {"$filter": "properties/itemsKeyValue/RuleName eq '@{triggerBody()?['object']?['properties']?['title']}'"}
        }
      },

      "3_Auto_close_if_FP": {
        "type": "If",
        "runAfter": {"2_Check_watchlist_FP_suppression": ["Succeeded"]},
        "expression": {"greater": ["@length(body('2_Check_watchlist_FP_suppression')?['value'])", 0]},
        "actions": {
          "Close_as_FP": {
            "type": "ApiConnection",
            "inputs": {
              "host": {"connection": {"name": "@parameters('$connections')['microsoftsentinel']['connectionId']"}},
              "method": "put",
              "path": "/Incidents/@{triggerBody()?['object']?['properties']?['incidentNumber']}",
              "body": {
                "status": "Closed",
                "classification": "FalsePositive",
                "classificationComment": "Auto-closed: matched FP-Suppression watchlist entry"
              }
            }
          }
        }
      },

      "4_Enrich_IPs_with_GeoIP": {
        "type": "Foreach",
        "runAfter": {"3_Auto_close_if_FP": ["Skipped", "Succeeded"]},
        "foreach": "@body('1_Get_incident_entities')?['IPs']",
        "actions": {
          "Get_IP_geo": {
            "type": "Http",
            "inputs": {
              "method": "GET",
              "uri": "https://ipapi.co/@{items('4_Enrich_IPs_with_GeoIP')?['Address']}/json/"
            }
          }
        }
      },

      "5_Check_IP_against_TI": {
        "type": "ApiConnection",
        "runAfter": {"4_Enrich_IPs_with_GeoIP": ["Succeeded"]},
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['microsoftsentinel']['connectionId']"}},
          "method": "post",
          "path": "/ThreatIntelligence/queryIndicators",
          "body": {"keywords": "@body('1_Get_incident_entities')?['IPs'][0]?['Address']"}
        }
      },

      "6_Check_user_risk_score": {
        "type": "ApiConnection",
        "runAfter": {"5_Check_IP_against_TI": ["Succeeded"]},
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azuread']['connectionId']"}},
          "method": "get",
          "path": "/v1.0/identityProtection/riskyUsers/@{body('1_Get_incident_entities')?['Accounts'][0]?['AadUserId']}"
        }
      },

      "7_Check_watchlist_VIP": {
        "type": "ApiConnection",
        "runAfter": {"6_Check_user_risk_score": ["Succeeded"]},
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['microsoftsentinel']['connectionId']"}},
          "method": "get",
          "path": "/Watchlists/VIP-Users/WatchlistItems",
          "queries": {"$filter": "properties/itemsKeyValue/UPN eq '@{body('1_Get_incident_entities')?['Accounts'][0]?['UserPrincipalName']}'"}
        }
      },

      "8_Auto_escalate_VIP_or_TI_hit": {
        "type": "If",
        "runAfter": {"7_Check_watchlist_VIP": ["Succeeded"]},
        "expression": {
          "or": [
            {"greater": ["@length(body('7_Check_watchlist_VIP')?['value'])", 0]},
            {"greater": ["@length(body('5_Check_IP_against_TI')?['value'])", 0]}
          ]
        },
        "actions": {
          "Set_severity_High": {
            "type": "ApiConnection",
            "inputs": {
              "host": {"connection": {"name": "@parameters('$connections')['microsoftsentinel']['connectionId']"}},
              "method": "put",
              "path": "/Incidents/@{triggerBody()?['object']?['properties']?['incidentNumber']}",
              "body": {"severity": "High"}
            }
          }
        }
      },

      "9_Post_enrichment_comment": {
        "type": "ApiConnection",
        "runAfter": {"8_Auto_escalate_VIP_or_TI_hit": ["Succeeded", "Skipped"]},
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['microsoftsentinel']['connectionId']"}},
          "method": "post",
          "path": "/Incidents/@{triggerBody()?['object']?['properties']?['incidentNumber']}/Comments",
          "body": {
            "message": "**Auto-Triage Summary**\n- IP Geo: @{body('4_Enrich_IPs_with_GeoIP')?[0]?['country_name']}\n- TI Match: @{length(body('5_Check_IP_against_TI')?['value'])} indicators\n- User Risk: @{body('6_Check_user_risk_score')?['riskLevel']}\n- VIP User: @{if(greater(length(body('7_Check_watchlist_VIP')?['value']), 0), 'YES — escalated', 'No')}"
          }
        }
      }

    }
  }
}
```

### Step 4: Build Watchlists for Instant Context

Watchlists are CSV-backed lookup tables in Sentinel. They eliminate the manual hunting a solo analyst would otherwise do on every alert.

```bash
# Create the four watchlists a lean SOC needs most

# 1. VIP Users — alerts involving these always get escalated to High
az sentinel watchlist create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --watchlist-alias VIP-Users \
  --display-name "VIP Users" \
  --item-search-key UPN \
  --source-type Local \
  --raw-content "UPN,Name,Title,Department
ceo@company.com,Jane Smith,CEO,Executive
cfo@company.com,John Doe,CFO,Finance
ciso@company.com,Alice Brown,CISO,Security"

# 2. FP-Suppression — known-good rules to auto-close
az sentinel watchlist create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --watchlist-alias FP-Suppression \
  --display-name "False Positive Suppression" \
  --item-search-key RuleName \
  --raw-content "RuleName,Reason,AddedBy,AddedDate
'Impossible Travel Activity',IT team VPN exit node in US and UK,soc-analyst,2026-06-01
'Mass Download from SharePoint',Backup service account nightly job,soc-analyst,2026-05-15"

# 3. Approved Jump Hosts — prevents noise from legitimate admin access
az sentinel watchlist create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --watchlist-alias Approved-Jump-Hosts \
  --display-name "Approved Jump Hosts" \
  --item-search-key IPAddress \
  --raw-content "IPAddress,Hostname,Owner,Purpose
10.0.1.50,jumphost-prod,IT Ops,Production admin access
10.0.1.51,jumphost-dev,IT Ops,Dev environment access"

# 4. Critical Assets — servers and resources that always warrant investigation
az sentinel watchlist create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --watchlist-alias Critical-Assets \
  --display-name "Critical Assets" \
  --item-search-key Hostname \
  --raw-content "Hostname,Owner,Tier,DataClassification
dc01.corp.local,IT Ops,Tier0,Confidential
payroll-sql01,Finance,Tier1,Restricted
pki-ca01.corp.local,IT Ops,Tier0,Confidential"
```

```kql
// Use watchlists in detection rules to auto-suppress known FPs
SecurityAlert
| where TimeGenerated > ago(1h)
| join kind=leftanti (
    _GetWatchlist('FP-Suppression')
    | project RuleName
) on $left.AlertName == $right.RuleName
// Only returns alerts NOT in the FP suppression list

// Enrich any alert with asset criticality from the Critical-Assets watchlist
SecurityIncident
| extend Entities = parse_json(tostring(Entities))
| mv-expand Entities
| extend Hostname = tostring(Entities.HostName)
| join kind=leftouter (
    _GetWatchlist('Critical-Assets')
    | project Hostname, Tier, DataClassification
) on Hostname
| extend Priority = iff(Tier == "Tier0", "CRITICAL", iff(Tier == "Tier1", "HIGH", "NORMAL"))
```

### Step 5: Incident Queue Hygiene — Auto-Group and Auto-Score

Configure alert grouping and automation rules so correlated events arrive as one incident, not fifty separate tickets.

```bash
# Configure analytics rules to group related alerts into one incident
# (prevents alert storms flooding the queue)
# In portal: Analytics rule → Incident settings → Alert grouping

# Equivalent via REST API — enable grouping on a rule
RULE_ID="your-analytics-rule-id"
az rest --method PUT \
  --url "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE/providers/Microsoft.SecurityInsights/alertRules/$RULE_ID?api-version=2023-02-01" \
  --body '{
    "kind": "Scheduled",
    "properties": {
      "incidentConfiguration": {
        "createIncident": true,
        "groupingConfiguration": {
          "enabled": true,
          "reopenClosedIncident": false,
          "lookbackDuration": "PT5H",
          "matchingMethod": "AnyAlert",
          "groupByEntities": ["Account", "Host"]
        }
      }
    }
  }'
```

```bash
# Automation rules — run before playbooks, zero cost, instant execution
# Rule 1: Auto-assign all incidents to the solo analyst
az sentinel automation-rule create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --automation-rule-name "Auto-Assign-To-SOC-Analyst" \
  --order 1 \
  --actions '[{
    "order": 1,
    "actionType": "ModifyProperties",
    "actionConfiguration": {
      "owner": {"assignedTo": "soc-analyst@company.com", "objectId": "ANALYST_OBJECT_ID"}
    }
  }]' \
  --triggers-on "Incidents" \
  --triggers-when "Created"

# Rule 2: Auto-close Informational incidents older than 7 days with no activity
az sentinel automation-rule create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --automation-rule-name "Auto-Close-Stale-Informational" \
  --order 2 \
  --conditions '[{
    "conditionType": "Property",
    "conditionProperties": {
      "propertyName": "IncidentSeverity",
      "operator": "Equals",
      "propertyValues": ["Informational"]
    }
  }]' \
  --actions '[{
    "order": 1,
    "actionType": "ModifyProperties",
    "actionConfiguration": {
      "status": "Closed",
      "classification": "Undetermined",
      "classificationComment": "Auto-closed: Informational severity, no analyst action required"
    }
  }]' \
  --triggers-on "Incidents" \
  --triggers-when "Updated"
```

### Step 6: Daily Digest — Morning Briefing Playbook

A solo analyst cannot watch the console all day. This Logic App runs at 07:00 every morning and sends a prioritized overnight summary — the only thing you need to read before starting your day.

```bash
# Create the Logic App with a recurrence trigger
az logic workflow create \
  --resource-group security-rg \
  --name sentinel-daily-digest \
  --location eastus \
  --definition @daily_digest_definition.json
```

```json
// daily_digest_definition.json
{
  "definition": {
    "triggers": {
      "Daily_at_0700": {
        "type": "Recurrence",
        "recurrence": {"frequency": "Day", "interval": 1, "startTime": "2026-06-06T07:00:00Z"}
      }
    },
    "actions": {

      "Query_overnight_incidents": {
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['microsoftsentinel']['connectionId']"}},
          "method": "get",
          "path": "/Incidents",
          "queries": {
            "$filter": "properties/createdTimeUtc ge @{addHours(utcNow(), -12)} and properties/status ne 'Closed'",
            "$orderby": "properties/severity desc",
            "$top": 50
          }
        }
      },

      "Query_KQL_overnight_summary": {
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azuremonitorlogs']['connectionId']"}},
          "method": "post",
          "path": "/queryData",
          "body": {
            "query": "SecurityIncident | where TimeGenerated > ago(12h) | summarize Total=count(), Critical=countif(Severity=='High'), Medium=countif(Severity=='Medium'), AutoClosed=countif(Status=='Closed' and Classification=='FalsePositive') by bin(TimeGenerated, 12h)",
            "timerange": "last12hours"
          }
        }
      },

      "Build_digest_HTML": {
        "type": "Compose",
        "inputs": "<html><body><h2>🔐 Sentinel Daily Digest — @{formatDateTime(utcNow(), 'yyyy-MM-dd')}</h2><h3>Overnight Summary (last 12h)</h3><table border='1'><tr><th>Severity</th><th>Count</th></tr><tr><td>🔴 High/Critical</td><td>@{body('Query_overnight_incidents')?['value'] | length}</td></tr></table><h3>Open Incidents Requiring Action</h3><ul>@{join(body('Query_overnight_incidents')?['value'], '<br/>')}</ul><p>Auto-closed FPs: @{body('Query_KQL_overnight_summary')?['tables'][0]?['rows'][0]?[3]}</p></body></html>"
      },

      "Send_Teams_digest": {
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['teams']['connectionId']"}},
          "method": "post",
          "path": "/v3/beta/teams/@{parameters('TeamsChannelId')}/messages",
          "body": {
            "body": {
              "contentType": "html",
              "content": "@{outputs('Build_digest_HTML')}"
            }
          }
        }
      },

      "Send_email_digest": {
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['office365']['connectionId']"}},
          "method": "post",
          "path": "/v2/Mail",
          "body": {
            "To": "@{parameters('AnalystEmail')}",
            "Subject": "🔐 Sentinel Morning Digest — @{formatDateTime(utcNow(), 'yyyy-MM-dd')} | @{length(body('Query_overnight_incidents')?['value'])} open incidents",
            "Body": "@{outputs('Build_digest_HTML')}",
            "IsHtml": true
          }
        }
      }

    }
  }
}
```

### Step 7: Lean SOC KQL Hunting Pack

A curated set of daily hunting queries a solo analyst can run in 30 minutes each morning to cover what automated rules may miss.

```kql
// ── 1. New admin accounts created overnight ──────────────────────────────
AuditLogs
| where TimeGenerated > ago(12h)
| where OperationName == "Add member to role"
| extend Role = tostring(TargetResources[0].displayName)
| where Role contains "Admin" or Role contains "Global"
| project TimeGenerated, InitiatedBy=tostring(InitiatedBy.user.userPrincipalName),
          NewAdmin=tostring(TargetResources[1].userPrincipalName), Role

// ── 2. Sign-ins from new countries (baseline: last 30 days) ─────────────
let known_countries = SigninLogs
| where TimeGenerated between(ago(30d)..ago(1d))
| summarize KnownCountries=make_set(Location) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(12h)
| where ResultType == 0
| join kind=leftouter known_countries on UserPrincipalName
| where Location !in (KnownCountries)
| project TimeGenerated, UserPrincipalName, Location, IPAddress, AppDisplayName

// ── 3. Service principal credential additions (potential backdoor) ───────
AuditLogs
| where TimeGenerated > ago(12h)
| where OperationName in ("Add service principal credentials", "Update application - Certificates and secrets management")
| project TimeGenerated, Actor=tostring(InitiatedBy.user.userPrincipalName),
          SP=tostring(TargetResources[0].displayName), OperationName

// ── 4. Anomalous data volume from SharePoint/OneDrive ───────────────────
OfficeActivity
| where TimeGenerated > ago(12h)
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize FilesDownloaded=count(), SizeBytes=sum(toint(SourceFileSize))
            by UserId, ClientIP, bin(TimeGenerated, 1h)
| where FilesDownloaded > 100
| sort by FilesDownloaded desc

// ── 5. MFA fatigue — repeated MFA push denials ──────────────────────────
SigninLogs
| where TimeGenerated > ago(12h)
| where ResultType == "500121"  // MFA required but not satisfied
| summarize DenialCount=count(), IPList=make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h)
| where DenialCount > 5
| sort by DenialCount desc

// ── 6. Privileged actions outside business hours ─────────────────────────
AuditLogs
| where TimeGenerated > ago(12h)
| extend Hour = hourofday(TimeGenerated)
| where Hour !between (8 .. 18)   // outside 08:00–18:00
| where OperationName in ("Delete user", "Reset user password", "Add app role assignment to service principal")
| project TimeGenerated, Hour, OperationName,
          Actor=tostring(InitiatedBy.user.userPrincipalName),
          Target=tostring(TargetResources[0].displayName)
```

## Key Concepts

| Term | Definition |
|---|---|
| Basic Logs tier | Azure Monitor log storage tier at ~$0.60/GB (vs $4.30/GB Analytics tier); supports limited KQL queries — suitable for high-volume, rarely-queried tables like raw firewall logs |
| Commitment tier | Pre-committed daily ingestion volume that reduces per-GB cost by 15–60% vs pay-as-you-go; break-even starts around 100 GB/day |
| Content Hub | Sentinel's marketplace of Microsoft and partner-maintained solution packs that bundle analytics rules, workbooks, hunting queries, and playbooks for a specific product or threat domain |
| Automation rule | Zero-cost, instant rule evaluated before playbooks; used for property modification (assign owner, change severity) and suppression; runs in milliseconds with no Logic App overhead |
| Alert grouping | Analytics rule setting that consolidates multiple related alerts firing within a time window into a single incident rather than N separate tickets |
| Watchlist | CSV-backed lookup table in Sentinel that rules and playbooks can query in real time to inject context (VIP status, asset tier, approved IPs) without re-writing rule logic |
| FP suppression | Watchlist-driven auto-close pattern that silences known-good alerts matching a rule name, freeing the analyst from repetitive manual closes |
| Daily digest | Scheduled Logic App that runs at a fixed time and delivers a prioritized overnight incident summary via Teams or email — enables async SOC operations without 24/7 console monitoring |
| Fusion detection | Sentinel's built-in ML engine that correlates low-signal alerts across multiple data sources to surface multi-stage attack chains; no configuration required, always-on |

## Tools & Systems

- **Microsoft Sentinel**: Cloud-native SIEM/SOAR platform — core platform for all steps in this skill
- **Logic Apps**: Serverless workflow engine for triage playbooks and daily digest automation
- **Sentinel Automation Rules**: Zero-cost instant rules for incident property modification and FP suppression
- **Content Hub**: Sentinel's solution marketplace for bulk-deploying Microsoft-maintained detection coverage
- **Azure Monitor Workbooks**: Dashboard framework for building a lean SOC operations view
- **Microsoft Teams / Outlook**: Digest delivery channels for async analyst workflow
- **Sentinel Watchlists**: CSV lookup tables providing real-time context injection into rules and playbooks
- **Fusion ML**: Always-on correlation engine requiring no configuration, providing multi-stage attack detection

## Common Scenarios

### Scenario: Alert Storm After a New Connector Goes Live

**Context**: A solo analyst enables the Defender for Endpoint connector on Monday morning. By noon, 340 new incidents have been created — 290 are informational alerts about standard IT activity.

**Approach**:
1. Immediately set an Automation Rule to auto-close all Informational incidents from that connector for 48 hours while baselining
2. Run the ingestion cost KQL query to confirm the connector isn't blowing the budget
3. Review the 50 remaining Medium+ incidents and add recurring patterns to the FP-Suppression watchlist
4. After one week, remove the blanket suppression and let only the tuned rules through
5. Net result: 340 daily alerts reduced to 8–12 actionable incidents

### Scenario: Solo Analyst Goes on Holiday for a Week

**Context**: The only security analyst is taking PTO. There's no cover. The business needs a minimum viable security posture maintained.

**Approach**:
1. Enable the daily digest to send to a senior IT manager as a backup recipient
2. Create a temporary Automation Rule to auto-escalate all Critical incidents to the IT manager via Teams alert
3. Set all Medium and Low incidents to auto-close after 72 hours if no activity (document this decision)
4. On return, run the 30-day incident backlog KQL to identify any patterns missed during absence
5. Review the FP-Suppression watchlist — auto-closes during the week reveal tuning opportunities

### Scenario: Reducing Monthly Sentinel Bill by 40%

**Context**: The monthly Sentinel invoice has grown to $4,200 and the security budget is $2,500.

**Approach**:
1. Run the ingestion cost query — discover AzureDiagnostics is 1.8 TB/month at $7,700/TB
2. Switch AzureDiagnostics to Basic Logs tier: cost drops from $7.74/GB to $0.60/GB — saves $2,600/month alone
3. Audit paid connectors — CEF/Syslog firewall logs are ingesting raw traffic logs never used in any rule; filter at the forwarder to send only DENY events
4. Set 90-day hot retention on SecurityEvent (down from 365 days); archive older data at $0.03/GB/month
5. Calculate daily ingestion average — at 85 GB/day, the 100 GB/day commitment tier saves 15% on remaining costs
6. Final bill: ~$2,200/month — under budget with full detection capability preserved

## Output Format

```json
{
  "lean_soc_health_check": {
    "date": "2026-06-06",
    "analyst_count": 1,
    "workspace": "sentinel-workspace"
  },
  "cost": {
    "daily_ingestion_gb": 84.3,
    "estimated_monthly_usd": 2180,
    "tables_on_basic_tier": ["AzureDiagnostics", "NetworkAccessTraffic"],
    "commitment_tier_gb_day": 100
  },
  "coverage": {
    "analytics_rules_enabled": 94,
    "content_hub_solutions_installed": 7,
    "attack_techniques_covered": 89
  },
  "queue": {
    "incidents_last_24h": 47,
    "auto_closed_fp": 31,
    "auto_closed_informational": 8,
    "requiring_analyst_action": 8,
    "avg_triage_time_minutes": 6
  },
  "watchlists": {
    "vip_users": 12,
    "fp_suppression_rules": 23,
    "approved_jump_hosts": 4,
    "critical_assets": 18
  },
  "digest": {
    "last_sent": "2026-06-06T07:00:00Z",
    "overnight_incidents": 8,
    "high_priority": 2,
    "delivery_channels": ["Teams", "Email"]
  }
}
```
