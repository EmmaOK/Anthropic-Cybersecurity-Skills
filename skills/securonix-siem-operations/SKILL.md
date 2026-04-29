---
name: securonix-siem-operations
description: >-
  Operates Securonix SIEM/UEBA for SOC alert triage, threat chain investigation,
  SPOTTER query authoring, policy management, and incident response workflow.
  Covers the full Tier 1–3 analyst workflow: investigating violations in the
  Spotter search interface, pivoting across activity and violation indexes,
  managing watchlists, using risk scoring and behavior analytics, and building
  detection policies. Includes SPOTTER query reference for common attack
  scenarios (brute force, lateral movement, data exfiltration, insider threat,
  cloud account abuse) and Splunk SPL to SPOTTER translation patterns.
  Activates for requests involving Securonix, SPOTTER queries, Securonix
  policies, UEBA investigation, or Securonix alert triage.
domain: cybersecurity
subdomain: soc-operations
tags:
  - securonix
  - siem
  - ueba
  - spotter
  - soc
  - alert-triage
  - threat-hunting
  - detection-engineering
  - insider-threat
  - T1078
  - T1110
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - DE.CM-01
  - DE.CM-09
  - DE.AE-02
  - DE.AE-06
  - RS.MA-01
  - RS.AN-01
  - RS.AN-03
d3fend_techniques:
  - Audit Log Analysis
  - User Behavior Analysis
  - Network Traffic Analysis
nist_ai_rmf:
  - GOVERN-6.1
  - MEASURE-3.1
  - MANAGE-2.2
---
# Securonix SIEM Operations

## When to Use

- Tier 1 analyst processing the Securonix violation queue — classifying, investigating, and escalating/closing alerts
- Tier 2/3 analyst building SPOTTER queries to hunt for threats not yet surfaced by policies
- Detection engineer creating or tuning Securonix activity/threat policies
- SOC lead measuring MTTD/MTTR via Securonix dashboards and reports
- Any analyst who needs to translate a Splunk SPL query, Sigma rule, or detection idea into Securonix SPOTTER syntax

**Do not use** for deep disk forensics — Securonix operates on log and behavioral data. Escalate to endpoint forensics tools (Velociraptor, CrowdStrike Falcon) for memory/disk investigation.

## Prerequisites

- Securonix analyst role with access to Spotter, Activity Data, and Violations dashboards
- Understanding of your organization's data source onboarding (which `rg_category` maps to which log source)
- For policy creation: Securonix policy author permissions
- For API use: Securonix API token (Settings → API Keys)

## Workflow

### Step 1: Alert Triage — Processing the Violation Queue

Navigate to **Violations** → **Violation Queue** and work the queue in priority order (Critical → High → Medium).

For each violation:

```
1. Read the violation name and associated policy
2. Note the entity (user / host / IP) and the risk score delta
3. Open the violation detail — check:
   - Which activity records triggered it
   - The behavior timeline (Spotter pivot from the violation)
   - Related violations on the same entity (look for clustering)
4. Make a disposition decision:
   - True Positive  → escalate to Tier 2, open incident ticket
   - False Positive → tune the policy or add entity to exception list
   - Benign         → close with documented justification
```

**Risk score context:**

| Risk Score | Meaning | Action |
|---|---|---|
| 0–25 | Low baseline activity | Monitor — no action required |
| 26–50 | Moderate anomaly | Investigate if combined with other violations |
| 51–75 | High anomaly | Tier 1 investigation required |
| 76–100 | Critical — significant deviation | Immediate Tier 2 escalation |

---

### Step 2: SPOTTER Query Fundamentals

SPOTTER is Securonix's search language. Every query follows this structure:

```
index = <index_name> AND <field> = "<value>" [AND|OR <field> = "<value>"]
  | <command> [arguments]
  | <command> [arguments]
```

**Key indexes:**

| Index | Contains |
|---|---|
| `activity` | All raw log activity (authentication, network, endpoint, email) |
| `violation` | Generated violations / triggered policies |
| `riskscore` | Entity risk score history |
| `lookup` | Reference/enrichment data |

**Core field reference:**

| Field | Description | Example |
|---|---|---|
| `rg_category` | Log source category | `"Authentication"`, `"Web"`, `"Endpoint"`, `"Email"`, `"DLP"`, `"Cloud"` |
| `rg_vendor` | Log source vendor | `"Microsoft"`, `"Palo Alto"`, `"Okta"` |
| `employeeid` | User identifier | `"jsmith"` |
| `accountname` | Account/username used | `"DOMAIN\\jsmith"` |
| `ipaddress` | Source IP | `"10.1.2.3"` |
| `destinationaddress` | Destination IP/host | `"192.168.1.100"` |
| `resourcename` | Hostname or resource | `"DC01"` |
| `action` | Event outcome | `"failed"`, `"success"`, `"blocked"`, `"allowed"` |
| `categorybehavior` | Behavior classification | `"Authentication Failure"`, `"Privilege Escalation"` |
| `message` | Raw event message | |
| `transactionstring1`–`5` | Custom parsed fields | Varies by data source |
| `eventtime` | Event timestamp | |

**Essential SPOTTER commands:**

```spotter
-- Aggregate
| stats count by employeeid, ipaddress

-- Filter after aggregation
| where count > 10

-- Time-based chart
| timechart span=1h count by action

-- Sort and limit
| sort -count | head 20

-- Compute a new field
| eval risk_flag = if(count > 50, "HIGH", "NORMAL")

-- Select fields to display
| table employeeid, ipaddress, count, risk_flag

-- Rename a field
| rename employeeid as user

-- Deduplicate
| dedup employeeid

-- Lookup enrichment
| lookup <lookup_name> employeeid OUTPUT department, manager
```

---

### Step 3: SPOTTER Queries for Common Attack Scenarios

#### Brute Force / Password Spray

```spotter
-- Failed authentication spike per user (brute force)
index = activity AND rg_category = "Authentication" AND action = "failed"
  | stats count by employeeid, ipaddress, resourcename
  | where count > 10
  | sort -count
  | head 50

-- Password spray — many users, few failures each, same source IP
index = activity AND rg_category = "Authentication" AND action = "failed"
  | stats count as failure_count, dc(employeeid) as unique_users by ipaddress
  | where unique_users > 20 AND failure_count < unique_users * 3
  | sort -unique_users

-- Successful login after multiple failures (credential stuffing hit)
index = activity AND rg_category = "Authentication"
  | stats
      sum(eval(if(action="failed",1,0))) as failures,
      sum(eval(if(action="success",1,0))) as successes
    by employeeid, ipaddress
  | where failures > 5 AND successes > 0
  | sort -failures
```

#### Lateral Movement

```spotter
-- Abnormal internal RDP/SMB connections
index = activity AND rg_category = "Network"
  AND (destinationport = "3389" OR destinationport = "445")
  AND ipaddress != destinationaddress
  | stats dc(destinationaddress) as unique_targets, count by employeeid, ipaddress
  | where unique_targets > 5
  | sort -unique_targets

-- Admin share access (T1021.002)
index = activity AND rg_category = "Endpoint"
  AND resourcename matches ".*\\$"
  AND action = "success"
  | stats count, dc(resourcename) as shares_accessed by employeeid, ipaddress
  | where shares_accessed > 3
  | sort -shares_accessed

-- Pass-the-hash / Pass-the-ticket indicators
index = activity AND rg_category = "Authentication"
  AND message contains "NTLM" AND action = "success"
  AND ipaddress != resourcename
  | stats dc(resourcename) as targets by employeeid, ipaddress
  | where targets > 3
```

#### Data Exfiltration

```spotter
-- Large data transfer to external destination (DLP)
index = activity AND rg_category = "DLP"
  | stats sum(transactionstring1) as bytes_sent by employeeid, destinationaddress
  | where bytes_sent > 104857600
  | eval mb_sent = round(bytes_sent / 1048576, 2)
  | sort -bytes_sent
  | table employeeid, destinationaddress, mb_sent

-- Anomalous email attachment volume
index = activity AND rg_category = "Email"
  AND action = "sent" AND transactionstring2 = "attachment"
  | stats count as emails_with_attachments by employeeid
  | where emails_with_attachments > 50
  | sort -emails_with_attachments

-- USB / removable media write
index = activity AND rg_category = "Endpoint"
  AND categorybehavior = "Removable Media"
  AND action = "write"
  | stats sum(transactionstring1) as bytes_written, count by employeeid, resourcename
  | sort -bytes_written
```

#### Insider Threat

```spotter
-- Access outside business hours (late night / weekend)
index = activity AND rg_category = "Authentication" AND action = "success"
  | eval hour = tonumber(strftime(eventtime, "%H"))
  | eval day = strftime(eventtime, "%A")
  | where (hour < 7 OR hour > 20) OR (day = "Saturday" OR day = "Sunday")
  | stats count, dc(resourcename) as systems_accessed by employeeid
  | where count > 5
  | sort -count

-- Access to sensitive systems by departing employees
-- (assumes watchlist "departing_employees" exists)
index = activity AND rg_category = "Authentication" AND action = "success"
  | lookup departing_employees employeeid OUTPUT departure_date, department
  | where isnotnull(departure_date)
  | stats count, dc(resourcename) as systems by employeeid, departure_date
  | sort -count

-- Mass file download / staging before departure
index = activity AND rg_category = "Endpoint"
  AND action = "read" AND transactionstring3 = "file"
  | stats count as file_reads, dc(transactionstring4) as unique_files by employeeid
  | where file_reads > 200
  | sort -file_reads
```

#### Cloud Account Abuse

```spotter
-- Impossible travel (login from two distant locations in short time)
index = activity AND rg_category = "Cloud" AND action = "success"
  | stats
      earliest(eventtime) as first_login,
      latest(eventtime) as last_login,
      values(ipaddress) as ips,
      dc(ipaddress) as unique_ips
    by employeeid
  | where unique_ips > 2

-- Cloud privilege escalation
index = activity AND rg_category = "Cloud"
  AND (categorybehavior = "Privilege Escalation" OR
       message contains "AttachRolePolicy" OR
       message contains "CreateAdminUser" OR
       message contains "AddUserToGroup")
  | stats count by employeeid, ipaddress, message
  | sort -count

-- Dormant account activation
index = activity AND rg_category = "Authentication" AND action = "success"
  | stats min(eventtime) as first_seen by employeeid
  | where first_seen > relative_time(now(), "-7d")
    AND first_seen < relative_time(now(), "-180d")
```

#### Threat Hunting — Living off the Land

```spotter
-- PowerShell execution on hosts where it's rare
index = activity AND rg_category = "Endpoint"
  AND (message contains "powershell" OR message contains "pwsh")
  AND action = "process_create"
  | stats count by resourcename, employeeid
  | sort -count

-- Scheduled task creation (T1053.005)
index = activity AND rg_category = "Endpoint"
  AND (message contains "schtasks" OR categorybehavior = "Scheduled Task")
  | stats count, values(message) as commands by resourcename, employeeid
  | sort -count

-- New service installed (T1543.003)
index = activity AND rg_category = "Endpoint"
  AND (categorybehavior = "Service Created" OR message contains "sc create")
  | table eventtime, resourcename, employeeid, message
  | sort -eventtime
```

---

### Step 4: SPL to SPOTTER Translation

Common translation patterns when converting Splunk searches:

| Splunk SPL | Securonix SPOTTER |
|---|---|
| `index=auth sourcetype=wineventlog` | `index = activity AND rg_category = "Authentication"` |
| `EventCode=4625` | `message contains "4625"` or use field mapping |
| `src_ip="10.0.0.1"` | `ipaddress = "10.0.0.1"` |
| `dest="DC01"` | `destinationaddress = "DC01"` or `resourcename = "DC01"` |
| `user="jsmith"` | `employeeid = "jsmith"` |
| `\| stats count by src_ip` | `\| stats count by ipaddress` |
| `\| where count > 10` | `\| where count > 10` (identical) |
| `\| eval field=if(x>1,"a","b")` | `\| eval field = if(x > 1, "a", "b")` (identical) |
| `\| table _time, src_ip, user` | `\| table eventtime, ipaddress, employeeid` |
| `\| timechart span=1h count` | `\| timechart span=1h count` (identical) |
| `\| dedup src_ip` | `\| dedup ipaddress` |
| `earliest=-24h latest=now` | Use the Spotter time picker (no inline time in SPOTTER) |

**Key differences to watch:**
- SPOTTER uses `AND`/`OR` (uppercase) for boolean logic; SPL uses lowercase or implicit AND
- Field names differ — map `src_ip`→`ipaddress`, `dest`→`destinationaddress`, `user`→`employeeid`
- SPOTTER has no `lookup` command equivalent for inline CSV lookups — use Securonix Lookup Tables configured in the platform
- Regex in SPOTTER uses `matches` keyword: `resourcename matches ".*DC.*"` vs SPL's `| rex`

---

### Step 5: Policy Management

**Creating a detection policy:**

1. Navigate to **Policies** → **Activity Policies** (log-based) or **Threat Policies** (behavior-based)
2. Choose **Activity Policy** for threshold-based rules (similar to Splunk correlation searches)
3. Build the SPOTTER query in the policy editor — test it in Spotter first
4. Set:
   - **Criticality**: Critical / High / Medium / Low
   - **Entity type**: User / Host / IP / Application
   - **Evaluation frequency**: Real-time / Hourly / Daily
   - **Violation message template**: include key fields for analyst context
5. Set the **Exception** list if known-good entities should be excluded
6. Enable and monitor the violation rate for the first 48 hours — tune if false positive rate > 20%

**Tuning a noisy policy:**

```spotter
-- Find the top entities generating false positives on a policy
index = violation AND violationname = "<your_policy_name>"
  | stats count by employeeid, resourcename
  | sort -count
  | head 20
-- Add the top offenders to the policy exception list
```

---

### Step 6: Watchlist Management

Watchlists flag entities for elevated scrutiny — every activity event from a watchlisted entity gets a risk score boost.

```
Common watchlist use cases:
- Departing employees (HR-fed, auto-added on termination notice)
- Privileged accounts (service accounts, admins)
- Accounts under active investigation
- Third-party / contractor accounts with elevated access
- Accounts flagged by threat intelligence (compromised credentials)
```

**Add entity to watchlist via API:**

```bash
# Get auth token
TOKEN=$(curl -s -X POST \
  "https://<securonix-host>/Snypr/ws/token/generate" \
  -H "Content-Type: application/json" \
  -d '{"username":"api_user","password":"api_pass","tenant":"<tenant>"}' | jq -r '.token')

# Add user to watchlist
curl -s -X POST \
  "https://<securonix-host>/Snypr/ws/watchlist/addToWatchlist" \
  -H "token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "watchlistname": "Departing Employees",
    "entityType": "Users",
    "entityId": "jsmith@company.com",
    "reason": "Voluntary resignation — last day 2026-05-15"
  }'
```

---

### Step 7: Incident Response Integration

**Export violation data for ticket creation:**

```bash
# Pull violations from the last 24 hours via API
curl -s -G \
  "https://<securonix-host>/Snypr/ws/violation/listViolations" \
  -H "token: $TOKEN" \
  --data-urlencode "from=$(date -v-1d +%s)000" \
  --data-urlencode "to=$(date +%s)000" \
  --data-urlencode "criticality=high,critical" \
  | jq '.violations[] | {id, violationname, entity, riskscore, criticality}'
```

**Use `agent.py` to generate triage checklists and SPOTTER queries:**

```bash
python3 agent.py query --use-case brute-force --output spotter_queries.json
python3 agent.py triage --alert-type "lateral-movement" --output triage_checklist.json
python3 agent.py convert --spl "index=auth EventCode=4625 | stats count by src_ip | where count > 10" \
  --output spotter_equivalent.txt
```

## Key Concepts

| Term | Definition |
|---|---|
| SPOTTER | Securonix's search language — pipe-delimited, similar to Splunk SPL |
| Violation | A generated alert produced when a policy threshold or behavior rule is triggered |
| Risk score | 0–100 entity-level score reflecting cumulative anomalous behavior; decays over time |
| UEBA | User and Entity Behavior Analytics — Securonix's core differentiator; baselines normal behavior per entity |
| Activity policy | Threshold/rule-based detection (log count exceeds N) — analogous to Splunk correlation search |
| Threat policy | Behavior-based detection using ML baselines — fires when deviation exceeds a threshold |
| Watchlist | Named list of entities that receive elevated risk scoring and analyst attention |
| Threat chain | Sequence of related violations across time that collectively indicate a more serious threat |
| Entity risk timeline | Chronological view of all violations and risk score changes for a user or host |
| `rg_category` | Resource group category — the log source type (Authentication, Web, Endpoint, etc.) |

## Tools & Systems

| Tool | Purpose |
|---|---|
| Securonix Spotter | Primary search interface — ad-hoc SPOTTER queries |
| Securonix Violation Dashboard | Alert triage queue — Tier 1 workflow |
| Securonix Risk Dashboard | Entity risk score overview — identifies highest-risk users/hosts |
| Securonix REST API | Programmatic access to violations, watchlists, risk scores |
| `agent.py` (this skill) | Query generation, SPL→SPOTTER conversion, triage checklists |
| Sigma | Platform-agnostic rule format — convert to SPOTTER via `agent.py convert` |

## Common Scenarios

**Scenario 1: Account Compromise Investigation**
A user's risk score spikes to 85. Open their entity timeline → find three violations clustering within 2 hours: off-hours login, access to sensitive share, large email attachment sent externally. Run the brute-force query to check for prior failed logins. Correlate source IPs — if the login came from an unusual country, escalate as likely account compromise.

**Scenario 2: Departing Employee Monitoring**
HR notifies security of a resignation. Add the employee to the "Departing Employees" watchlist via API. Over the next two weeks, any file download, cloud access, or USB write triggers heightened risk scoring. Run the insider threat queries daily against the employee's `employeeid`. At last-day, verify account is disabled and violations close out.

**Scenario 3: New Detection Policy Deployment**
Threat intel reports password spray campaigns targeting your sector. Build the password spray SPOTTER query, test it in Spotter against the last 30 days — identify baseline results. Tune the `unique_users > 20` threshold so it produces < 5 results per day on known-clean data. Create an Activity Policy wrapping the query, set criticality to High, and enable it.

**Scenario 4: Sigma Rule Onboarding**
Red team provides a new Sigma rule for DCSync detection. Use `agent.py convert --sigma dcsync.yml` to get the SPOTTER equivalent. Validate the field mappings against your data in Spotter. Create an Activity Policy and add the triggering entities to the Privileged Accounts watchlist.

## Output Format

The `agent.py` script outputs structured JSON:

```json
{
  "generated_at": "2026-04-28T10:00:00Z",
  "use_case": "brute-force",
  "spotter_queries": [
    {
      "name": "Failed authentication spike per user",
      "description": "Detects brute force by finding users with >10 failed logins",
      "query": "index = activity AND rg_category = \"Authentication\" AND action = \"failed\" | stats count by employeeid, ipaddress | where count > 10 | sort -count | head 50",
      "technique": "T1110",
      "threshold": "count > 10",
      "tuning_notes": "Adjust threshold based on your baseline failed login rate"
    }
  ]
}
```
