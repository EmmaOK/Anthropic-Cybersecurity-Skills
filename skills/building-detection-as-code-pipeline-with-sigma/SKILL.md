---
name: building-detection-as-code-pipeline-with-sigma
description: >-
  Build a Detection-as-Code (DaC) pipeline that manages Sigma detection rules
  in a Git repository, validates and unit-tests rules in CI, compiles them to
  target SIEM query languages (Splunk SPL, Microsoft Sentinel KQL, Elastic EQL,
  Chronicle YARA-L) using pySigma, and deploys them to production SIEMs via
  automated CD. Covers rule authoring standards, false-positive tuning workflows,
  MITRE ATT&CK coverage gap analysis, and rollback procedures for bad detections.
domain: cybersecurity
subdomain: soc-operations
tags:
  - detection-as-code
  - sigma
  - detection-engineering
  - gitops
  - ci-cd
  - siem
  - mitre-attack
  - devsecops
version: '1.0'
author: emmanuelokonkwo
license: Apache-2.0
nist_csf:
  - DE.CM-01
  - DE.AE-02
  - DE.AE-06
  - ID.IM-02
d3fend_techniques:
  - Log Analysis
  - Platform Monitoring
---

# Building a Detection-as-Code Pipeline with Sigma

## When to Use

- When detection rules are managed ad-hoc in SIEM UIs and drift occurs across environments
- When there is no peer review, versioning, or rollback capability for detection logic
- When the same detection needs to be deployed across multiple SIEM platforms simultaneously
- When you need an auditable, compliance-evidenced history of all detection changes
- When building a scalable detection engineering practice that can onboard new analysts quickly

**Do not use** as a replacement for SIEM-native detection validation tools, or for incident-specific custom queries that are not intended to run continuously.

## Prerequisites

- Git repository (GitHub, GitLab, or Bitbucket) for storing Sigma rules
- Python 3.11+ with `sigma-cli` and `pySigma` backend packages installed (including `pySigma-backend-securonix` for SPOTTER output)
- CI/CD platform (GitHub Actions, GitLab CI, or Jenkins)
- At least one target SIEM with an API for programmatic rule deployment (Splunk, Sentinel, Elastic, Chronicle)
- MITRE ATT&CK Navigator JSON export for coverage gap tracking

## Workflow

### Step 1: Set Up the Detection Repository Structure

Establish a standardized directory layout and Sigma rule authoring conventions.

```
detection-rules/
├── rules/
│   ├── windows/
│   │   ├── process_creation/
│   │   │   └── proc_creation_win_lolbas_regsvr32.yml
│   │   └── registry/
│   ├── linux/
│   ├── cloud/
│   │   ├── aws/
│   │   └── azure/
│   └── network/
├── tests/
│   └── proc_creation_win_lolbas_regsvr32_test.yml
├── pipelines/
│   ├── splunk_enterprise.yml
│   ├── sentinel_asim.yml
│   ├── elastic_ecs.yml
│   └── securonix_spotter.yml
├── .github/workflows/
│   ├── validate.yml
│   └── deploy.yml
├── sigmac_config.yml
└── coverage_report.json
```

```bash
# Install sigma-cli and target backends
pip install sigma-cli
pip install pySigma-backend-splunk pySigma-backend-microsoft365defender \
            pySigma-backend-elasticsearch pySigma-backend-chronicle \
            pySigma-backend-securonix

# Verify backends
sigma list backends
```

### Step 2: Author Sigma Rules to Standard

Write detection rules in the Sigma format with required metadata fields for DaC workflows.

```yaml
# rules/windows/process_creation/proc_creation_win_lolbas_regsvr32.yml
title: Regsvr32 Spawning Suspicious Child Process
id: a6b2c3d4-e5f6-7890-abcd-ef1234567890
status: test
description: >
  Detects regsvr32.exe spawning unusual child processes, a common LOLBas
  technique used by Squiblydoo and similar attacks (T1218.010).
author: detection-team
date: 2026/06/06
modified: 2026/06/06
tags:
  - attack.defense_evasion
  - attack.t1218.010
  - detection.emerging_threat
references:
  - https://attack.mitre.org/techniques/T1218/010/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\regsvr32.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
  condition: selection
falsepositives:
  - Legitimate software installers using regsvr32 as a parent process
level: high
```

### Step 3: Write Unit Tests for Each Rule

Create test cases that specify expected matches (true positives) and non-matches (true negatives) to run in CI before deployment.

```yaml
# tests/proc_creation_win_lolbas_regsvr32_test.yml
title: Test - Regsvr32 Spawning Suspicious Child Process
name: proc_creation_win_lolbas_regsvr32
tests:
  - name: Regsvr32 spawns cmd.exe (TP)
    rule_conditions:
      - ParentImage: 'C:\Windows\System32\regsvr32.exe'
        Image: 'C:\Windows\System32\cmd.exe'
        CommandLine: 'cmd.exe /c whoami'
    result: positive

  - name: Regsvr32 spawns powershell.exe (TP)
    rule_conditions:
      - ParentImage: 'C:\Windows\SysWOW64\regsvr32.exe'
        Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    result: positive

  - name: Regsvr32 spawns regasm.exe (FP - benign installer)
    rule_conditions:
      - ParentImage: 'C:\Windows\System32\regsvr32.exe'
        Image: 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe'
    result: negative
```

```bash
# Run unit tests locally with sigma-cli test
sigma test --config sigmac_config.yml rules/windows/process_creation/
```

### Step 4: Configure the CI Validation Pipeline

Set up GitHub Actions to validate, test, and compile rules on every pull request.

```yaml
# .github/workflows/validate.yml
name: Validate Detection Rules

on:
  pull_request:
    paths:
      - 'rules/**'
      - 'tests/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install sigma tools
        run: |
          pip install sigma-cli pySigma-backend-splunk \
            pySigma-backend-microsoft365defender pySigma-backend-elasticsearch \
            pySigma-backend-securonix

      - name: Validate rule syntax
        run: sigma check rules/

      - name: Run unit tests
        run: sigma test rules/

      - name: Compile to Splunk SPL (smoke test)
        run: |
          sigma convert -t splunk -p pipelines/splunk_enterprise.yml \
            rules/ -o /tmp/splunk_rules.conf

      - name: Compile to Sentinel KQL (smoke test)
        run: |
          sigma convert -t microsoft365defender \
            -p pipelines/sentinel_asim.yml rules/ -o /tmp/sentinel_rules.json

      - name: Compile to Securonix SPOTTER (smoke test)
        run: |
          sigma convert -t securonix \
            -p pipelines/securonix_spotter.yml rules/ -o /tmp/securonix_rules.json

      - name: Check ATT&CK coverage delta
        run: python3 scripts/coverage_delta.py --base main --head ${{ github.sha }}

      - name: Comment PR with compilation summary
        uses: actions/github-script@v7
        with:
          script: |
            const output = require('fs').readFileSync('/tmp/compile_summary.txt', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '## Detection Rule Compilation Summary\n```\n' + output + '\n```'
            });
```

### Step 5: Automate Deployment to Production SIEMs

Deploy compiled rules to SIEM platforms on merge to main via a CD workflow.

```yaml
# .github/workflows/deploy.yml
name: Deploy Detection Rules

on:
  push:
    branches: [main]
    paths:
      - 'rules/**'

jobs:
  deploy-splunk:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4

      - name: Install tools
        run: pip install sigma-cli pySigma-backend-splunk requests

      - name: Compile rules to SPL
        run: |
          sigma convert -t splunk -p pipelines/splunk_enterprise.yml \
            rules/ --output-format savedsearches -o compiled/splunk_rules.conf

      - name: Deploy to Splunk via REST API
        env:
          SPLUNK_HOST: ${{ secrets.SPLUNK_HOST }}
          SPLUNK_TOKEN: ${{ secrets.SPLUNK_TOKEN }}
        run: python3 scripts/deploy_splunk.py --rules compiled/splunk_rules.conf

  deploy-sentinel:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4

      - name: Compile rules to Sentinel KQL
        run: |
          sigma convert -t microsoft365defender \
            -p pipelines/sentinel_asim.yml rules/ -o compiled/sentinel_rules.json

      - name: Deploy to Sentinel via Azure CLI
        env:
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
        run: python3 scripts/deploy_sentinel.py --rules compiled/sentinel_rules.json

  deploy-securonix:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4

      - name: Install tools
        run: pip install sigma-cli pySigma-backend-securonix requests

      - name: Compile rules to Securonix SPOTTER
        run: |
          sigma convert -t securonix \
            -p pipelines/securonix_spotter.yml rules/ -o compiled/securonix_rules.json

      - name: Deploy to Securonix via REST API
        env:
          SECURONIX_URL: ${{ secrets.SECURONIX_URL }}
          SECURONIX_TOKEN: ${{ secrets.SECURONIX_TOKEN }}
        run: python3 scripts/deploy_securonix.py --rules compiled/securonix_rules.json
```

The Securonix pipeline file maps Sigma's generic field names to Securonix's SPOTTER attribute naming convention and wraps each compiled query in the policy definition structure the REST API expects:

```yaml
# pipelines/securonix_spotter.yml
name: Securonix SPOTTER Pipeline
priority: 20
transformations:
  - id: securonix_process_fieldmapping
    type: field_name_mapping
    mapping:
      Image: destinationprocessname
      ParentImage: sourceprocessname
      CommandLine: requestcmd
      User: sourceuserid
      Computer: devicehostname
      EventID: baseeventid
      TargetUserName: destinationuserid
      TargetDomainName: destinationdomain
      SourceIp: sourceaddress
      DestinationIp: destinationaddress
      DestinationPort: destinationport
```

```python
# scripts/deploy_securonix.py — deploy compiled SPOTTER policies via Securonix REST API
import requests, json, os, sys

SECURONIX_URL = os.environ["SECURONIX_URL"]
SECURONIX_TOKEN = os.environ["SECURONIX_TOKEN"]
VERIFY_TLS = os.environ.get("SKIP_TLS_VERIFY", "").lower() not in ("1", "true", "yes")

headers = {
    "token": SECURONIX_TOKEN,
    "Content-Type": "application/json"
}

def deploy_policy(policy_name, spotter_query, criticality="High"):
    payload = {
        "policyname": policy_name,
        "policyDescription": f"Deployed via Detection-as-Code pipeline",
        "criticality": criticality,
        "query": spotter_query,
        "enabled": True
    }
    resp = requests.post(
        f"{SECURONIX_URL}/Snypr/ws/policy/createPolicy",
        headers=headers,
        json=payload,
        verify=VERIFY_TLS
    )
    resp.raise_for_status()
    return resp.json()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", required=True)
    args = parser.parse_args()

    rules = json.loads(open(args.rules).read())
    deployed, failed = 0, 0
    for rule in rules:
        try:
            result = deploy_policy(rule["name"], rule["query"])
            print(json.dumps({"status": "deployed", "policy": rule["name"], "result": result}))
            deployed += 1
        except Exception as e:
            print(json.dumps({"status": "failed", "policy": rule["name"], "error": str(e)}))
            failed += 1

    print(f"\nDeployed: {deployed} | Failed: {failed}")
    if failed > 0:
        sys.exit(1)
```

### Step 6: Measure ATT&CK Coverage and Track Gaps

Generate a coverage heatmap showing which MITRE ATT&CK techniques are detected and where gaps remain.

```python
# scripts/coverage_delta.py
import json, subprocess, sys
from pathlib import Path
import yaml

def extract_attack_tags(rules_dir):
    techniques = set()
    for rule_path in Path(rules_dir).rglob('*.yml'):
        try:
            rule = yaml.safe_load(rule_path.read_text())
            for tag in rule.get('tags', []):
                if tag.startswith('attack.t'):
                    techniques.add(tag.replace('attack.', '').upper())
        except Exception:
            continue
    return techniques

covered = extract_attack_tags('rules/')
print(f"ATT&CK techniques covered: {len(covered)}")
print(f"Techniques: {sorted(covered)}")

# Output coverage report for Navigator import
navigator_layer = {
    "name": "Detection Coverage",
    "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
    "domain": "enterprise-attack",
    "techniques": [
        {"techniqueID": t, "color": "#00c0c7", "score": 1}
        for t in covered
    ]
}
Path('coverage_report.json').write_text(json.dumps(navigator_layer, indent=2))
print("Coverage layer written to coverage_report.json")
```

### Step 7: False-Positive Tuning Workflow

Implement a structured PR-based workflow for tuning noisy rules without breaking the audit trail.

```yaml
# Example: tuning a noisy rule via filter condition
# Before: fires on all PowerShell with encoded commands
detection:
  selection:
    CommandLine|contains: '-EncodedCommand'
  condition: selection

# After: add allowlist filter as a separate named condition
detection:
  selection:
    CommandLine|contains: '-EncodedCommand'
  filter_main_known_software:
    Image|endswith:
      - '\Microsoft.ConfigCI.Commands.dll'
    CommandLine|contains: 'Get-SystemDriver'
  filter_main_psadt:
    ParentImage|endswith: '\Deploy-Application.exe'
  condition: selection and not 1 of filter_main_*
```

## Key Concepts

| Term | Definition |
|---|---|
| Detection-as-Code | Practice of managing detection rules as versioned code in a Git repository with the same peer review and CI/CD rigor applied to application code |
| Sigma | Vendor-agnostic YAML-based detection rule format that compiles to Splunk SPL, Sentinel KQL, Elastic EQL, Chronicle YARA-L, and 20+ other targets |
| pySigma | Python library and CLI toolchain for validating, testing, and compiling Sigma rules via pluggable backends and processing pipelines |
| Processing Pipeline | pySigma configuration that maps generic Sigma field names to SIEM-specific schema fields (e.g., `Image` → `process.executable` for Elastic ECS) |
| ATT&CK Coverage | The set of MITRE ATT&CK technique IDs present in the `tags` field of deployed rules; visualized as a Navigator heatmap |
| Rule Status | Sigma lifecycle state: `test` (experimental), `experimental`, `stable`, `deprecated`; only `stable` rules should deploy to production |
| False-Positive Filter | Named `filter_*` condition in a Sigma rule's detection section that excludes known-benign patterns while preserving full audit trail of the exclusion reason |
| Saved Search (Splunk) | The Splunk equivalent of a scheduled detection rule; sigma converts to `savedsearches.conf` stanzas for REST API deployment |
| SPOTTER | Securonix's native query language for threat detection policies; pySigma compiles Sigma rules to SPOTTER via the `pySigma-backend-securonix` package and deploys them via the SNYPR REST API |

## Tools & Systems

- **sigma-cli**: Official Sigma command-line tool for validation, testing, and compilation
- **pySigma**: Python library providing the compilation engine and backend plugin interface
- **GitHub Actions / GitLab CI**: CI/CD orchestration for automated validation and deployment workflows
- **Splunk REST API**: `saved/searches` endpoint for programmatic rule creation and updates
- **Azure Sentinel / Microsoft Defender API**: Analytics rules API for Sentinel KQL rule deployment
- **MITRE ATT&CK Navigator**: Coverage visualization tool that accepts the exported JSON heatmap layer
- **pySigma backends**: `pySigma-backend-splunk`, `pySigma-backend-microsoft365defender`, `pySigma-backend-elasticsearch`, `pySigma-backend-chronicle`, `pySigma-backend-securonix`
- **Securonix SNYPR REST API**: `createPolicy` / `updatePolicy` endpoints used by the deploy script to push compiled SPOTTER queries as detection policies

## Common Scenarios

### Scenario: Onboarding 300 SigmaHQ Community Rules

**Context**: A new detection engineering team inherits 300 community Sigma rules from the SigmaHQ repository and needs to deploy relevant ones to Splunk and Sentinel without manually reviewing each one.

**Approach**:
1. Clone the SigmaHQ rules repository and filter to `status: stable` and `level: high` or `critical` rules
2. Run `sigma check` to identify any rules that fail schema validation
3. Compile to Splunk SPL using the enterprise pipeline; count compilation errors (typically schema mismatches)
4. Deploy to a staging Splunk environment and run for one week; collect false-positive rate per rule
5. Create tuning PRs for rules exceeding 5 false positives per day before promoting to production

### Scenario: Detecting a New Threat Actor TTP on Day Zero

**Context**: Threat intelligence publishes a new LOLBas technique used by an APT group on Monday morning.

**Approach**:
1. Detection engineer authors a new Sigma rule and opens a PR by end of day
2. CI validates syntax, runs unit tests, and compiles to all target backends within 2 minutes
3. A second detection engineer reviews the rule logic and the ATT&CK tag mapping
4. On merge, CD deploys the rule to Splunk and Sentinel within 5 minutes
5. The coverage delta script updates the Navigator heatmap showing T1XXX.XXX now covered

## Output Format

```json
{
  "pipeline": "detection-as-code",
  "run_date": "2026-06-06",
  "rules_validated": 342,
  "rules_failed_validation": 3,
  "compilation_targets": {
    "splunk_spl": {"compiled": 339, "errors": 3},
    "sentinel_kql": {"compiled": 341, "errors": 1},
    "elastic_eql": {"compiled": 338, "errors": 4},
    "securonix_spotter": {"compiled": 340, "errors": 2}
  },
  "attack_coverage": {
    "techniques_covered": 127,
    "tactics_covered": ["initial-access", "execution", "persistence", "privilege-escalation",
                        "defense-evasion", "credential-access", "discovery", "lateral-movement",
                        "collection", "exfiltration", "command-and-control"],
    "coverage_layer_file": "coverage_report.json"
  },
  "deployment": {
    "splunk": {"deployed": 339, "updated": 12, "removed": 2},
    "sentinel": {"deployed": 341, "updated": 8, "removed": 1},
    "securonix": {"deployed": 340, "updated": 6, "removed": 0}
  },
  "false_positive_tuning_prs_open": 4
}
```
