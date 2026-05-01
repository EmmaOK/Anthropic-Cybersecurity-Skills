---
name: writing-bitbucket-pipelines
description: >-
  Design, generate, and security-audit Bitbucket Pipelines configurations
  integrating enterprise security tooling: SonarQube and Coverity for SAST,
  OWASP Dependency-Check, Dependency Track (SBOM/CycloneDX), and Black Duck
  for SCA, Trivy for container scanning, OWASP ZAP and Burp Suite Enterprise
  for DAST, DefectDojo for centralized finding aggregation, and AWS Inspector
  for post-deployment cloud workload scanning. Covers multi-stage pipeline
  authoring, parallel step execution, per-branch and pull-request triggers,
  deployment environments with manual approval gates, and security posture
  auditing of existing bitbucket-pipelines.yml files.
domain: cybersecurity
subdomain: devsecops
tags:
  - bitbucket
  - bitbucket-pipelines
  - cicd
  - devsecops
  - sonarqube
  - coverity
  - dependency-check
  - dependency-track
  - blackduck
  - defectdojo
  - trivy
  - owasp-zap
  - burpsuite
  - aws-inspector
  - secure-sdlc
  - pipeline-security
  - sbom
  - sast
  - sca
  - dast
version: '1.0'
author: phantom
license: Apache-2.0
nist_csf:
  - PR.PS-01
  - PR.PS-04
  - GV.SC-07
  - ID.IM-04
  - RS.AN-03
d3fend_techniques:
  - Software Bill of Materials
  - Dynamic Analysis
  - Credential Hardening
  - Platform Hardening
---

# Writing Bitbucket Pipelines

## When to Use

- When scaffolding a new Bitbucket repository that needs a production-ready `bitbucket-pipelines.yml` wired to your enterprise security toolchain
- When integrating SonarQube, Coverity, Black Duck, Dependency Track, DefectDojo, Trivy, or ZAP into an existing pipeline
- When auditing an existing `bitbucket-pipelines.yml` for hardcoded secrets, unpinned images, missing security gates, or absent manual approval steps
- When establishing shift-left security controls aligned to NIST CSF PR.PS-04 and your AppSec program's tool coverage requirements
- When migrating from Jenkins, GitHub Actions, or GitLab CI to Bitbucket while preserving your security scan integrations

## Prerequisites

- Bitbucket Cloud or Bitbucket Data Center with Pipelines enabled
- Bitbucket **repository variables** configured (Settings → Repository variables) — all credentials must be marked **Secured**:

| Variable | Purpose | Used by |
|---|---|---|
| `SONAR_TOKEN` | SonarQube user token | SonarQube SAST |
| `SONAR_HOST_URL` | SonarQube server URL | SonarQube SAST |
| `SONAR_PROJECT_KEY` | Project key in SonarQube | SonarQube SAST |
| `COVERITY_HOST` | Coverity Connect hostname | Coverity SAST |
| `COVERITY_AUTH_KEY` | Coverity auth key file contents | Coverity SAST |
| `COVERITY_STREAM` | Coverity project stream name | Coverity SAST |
| `BLACKDUCK_URL` | Black Duck server URL | Black Duck SCA |
| `BLACKDUCK_API_TOKEN` | Black Duck API token | Black Duck SCA |
| `DEPTRACK_URL` | Dependency Track server URL | Dependency Track |
| `DEPTRACK_API_KEY` | Dependency Track API key | Dependency Track |
| `DEFECTDOJO_URL` | DefectDojo server URL | All tools → DefectDojo |
| `DEFECTDOJO_API_KEY` | DefectDojo API token | All tools → DefectDojo |
| `BURP_ENTERPRISE_URL` | Burp Suite Enterprise API URL | Burp DAST |
| `BURP_ENTERPRISE_API_KEY` | Burp Suite Enterprise API key | Burp DAST |
| `AWS_ACCESS_KEY_ID` | AWS credentials (prefer OIDC) | AWS Inspector |
| `AWS_SECRET_ACCESS_KEY` | AWS credentials (prefer OIDC) | AWS Inspector |

- **Deployment environments** configured in Bitbucket (Settings → Deployments): `staging`, `production`
- SonarQube project created with a Quality Gate configured to fail on new CRITICAL/HIGH findings
- DefectDojo product and engagement created for this repository

## Workflow

### Step 1 — Generate a Pipeline Configuration

```bash
# Full enterprise pipeline: SonarQube + Coverity + Black Duck + Trivy + ZAP + DefectDojo
agent.py generate \
  --project-type java \
  --security-level full \
  --pipeline-name "PaymentService" \
  --output bitbucket-pipelines.yml

# Standard pipeline: SonarQube + Dependency-Check + Dependency Track + Trivy
agent.py generate \
  --project-type python \
  --security-level standard \
  --pipeline-name "DataIngestionAPI"

# Basic pipeline: SonarQube + Dependency-Check only
agent.py generate \
  --project-type node \
  --security-level basic \
  --pipeline-name "InternalDashboard"
```

**Security levels and included tools:**

| Level | SAST | SCA | Container | DAST | Reporting |
|---|---|---|---|---|---|
| basic | SonarQube | Dependency-Check | — | — | DefectDojo |
| standard | SonarQube | Dependency-Check + Dependency Track | Trivy | — | DefectDojo |
| full | SonarQube + Coverity | Black Duck + Dependency Track | Trivy | OWASP ZAP / Burp | DefectDojo |

### Step 2 — Audit an Existing Pipeline

```bash
agent.py audit \
  --pipeline bitbucket-pipelines.yml \
  --output audit_report.json
```

Checks for: hardcoded credentials, unpinned image tags, missing security tools from your stack, production deployments without manual gates, privileged Docker access, and missing step timeouts.

### Step 3 — Generate Security Report

```bash
agent.py report \
  --audit audit_report.json \
  --output pipeline_security_report.json
```

Exits with code 1 when overall risk is HIGH or CRITICAL (CI-gate compatible for branch protection rules).

## Key Concepts

| Concept | Description |
|---|---|
| SonarQube Quality Gate | Pass/fail threshold on code coverage, duplication, bugs, vulnerabilities, and security hotspots |
| Coverity stream | A named analysis target in Coverity Connect; results are committed to the stream per build |
| CycloneDX SBOM | Machine-readable software bill of materials consumed by Dependency Track for continuous component tracking |
| Black Duck Detect | Synopsys CLI that runs SCA, licence compliance, and snippet scanning; output feeds DefectDojo |
| Dependency Track | OWASP project that ingests CycloneDX SBOMs and correlates components against NVD/OSV/GitHub Advisories |
| DefectDojo engagement | A time-boxed test run linked to a product; each pipeline run creates or re-uses an engagement |
| Trivy | Aqua Security scanner for OS packages, language dependencies, and IaC misconfigs in container images |
| ZAP baseline scan | Passive DAST scan suitable for CI; `zap-full-scan` adds active attack payloads for staging gates |
| Burp Suite Enterprise | REST API-driven DAST; scan results can be exported as XML and imported into DefectDojo |
| AWS Inspector v2 | Agent-based and agentless cloud workload scanner; findings retrievable via `aws inspector2` CLI |
| YAML anchor (`&name`) | Defines a reusable step template in `definitions.steps` |
| YAML alias (`*name`) | References a previously anchored template — keeps the pipeline DRY |
| `trigger: manual` | Requires explicit approval in Bitbucket UI before the step executes |
| `deployment` | Tags a step with a named environment for Bitbucket deployment dashboards and history |
| `max-time` | Maximum minutes a step may run before Bitbucket cancels it |

## Tools & Systems

| Tool | Category | Integration method |
|---|---|---|
| SonarQube | SAST | `sonarsource/sonarcloud-scan` pipe or `sonar-scanner` CLI; Quality Gate blocks step on failure |
| Coverity (Synopsys) | SAST | `cov-build` + `cov-analyze` + `cov-commit-defects` CLI; results pushed to Coverity Connect |
| OWASP Dependency-Check | SCA | `owasp/dependency-check` Docker image; CVSS threshold gate via `--failOnCVSS` |
| Dependency Track | SCA/SBOM | CycloneDX SBOM generated by `syft`; uploaded via Dependency Track `/api/v1/bom` REST endpoint |
| Black Duck (Synopsys) | SCA + License | Synopsys Detect (`detect.sh`) CLI; scans source, binaries, and Docker layers |
| Trivy | Container | `aquasec/trivy` Docker image or Bitbucket Pipe; scans image layers for CVEs |
| OWASP ZAP | DAST | `ghcr.io/zaproxy/zaproxy:stable`; baseline or full-scan against a running staging environment |
| Burp Suite Enterprise | DAST | REST API scan trigger; XML results imported into DefectDojo |
| DefectDojo | Aggregation | `/api/v2/import-scan/` REST endpoint; consolidates all tool findings into one product |
| AWS Inspector v2 | Cloud workload | `aws inspector2 list-findings` CLI; post-deploy step or triggered via EventBridge |

## Common Scenarios

### Parallel Security Gates on Pull Requests

Run SonarQube and Dependency-Check in parallel to keep PR feedback under 10 minutes:

```yaml
pull-requests:
  '**':
    - step: *build
    - parallel:
        - step: *sast-sonarqube
        - step: *sca-dependency-check
```

### Uploading All Findings to DefectDojo

Each tool produces a report artifact; a dedicated import step pushes them all to DefectDojo after scans complete:

```yaml
- step: &defectdojo-import
    name: "DefectDojo - Import Findings"
    max-time: 10
    script:
      # SonarQube import
      - |
        curl -sf -X POST "$DEFECTDOJO_URL/api/v2/import-scan/" \
          -H "Authorization: Token $DEFECTDOJO_API_KEY" \
          -F "scan_type=SonarQube API Import" \
          -F "product_name=$BITBUCKET_REPO_SLUG" \
          -F "engagement_name=Pipeline-$BITBUCKET_BUILD_NUMBER" \
          -F "minimum_severity=High" \
          -F "sonarqube_url=$SONAR_HOST_URL" \
          -F "sonarqube_api_key=$SONAR_TOKEN"
      # Dependency-Check import
      - |
        curl -sf -X POST "$DEFECTDOJO_URL/api/v2/import-scan/" \
          -H "Authorization: Token $DEFECTDOJO_API_KEY" \
          -F "scan_type=Dependency Check Scan" \
          -F "product_name=$BITBUCKET_REPO_SLUG" \
          -F "engagement_name=Pipeline-$BITBUCKET_BUILD_NUMBER" \
          -F "minimum_severity=High" \
          -F "file=@reports/dependency-check-report.json"
      # Trivy import
      - |
        curl -sf -X POST "$DEFECTDOJO_URL/api/v2/import-scan/" \
          -H "Authorization: Token $DEFECTDOJO_API_KEY" \
          -F "scan_type=Trivy Scan" \
          -F "product_name=$BITBUCKET_REPO_SLUG" \
          -F "engagement_name=Pipeline-$BITBUCKET_BUILD_NUMBER" \
          -F "minimum_severity=High" \
          -F "file=@trivy-results.json"
```

### Dependency Track SBOM Upload

Generate a CycloneDX SBOM with `syft` and upload to Dependency Track for continuous component tracking:

```yaml
- step: &sca-deptrack
    name: "SCA - Dependency Track (SBOM)"
    image: anchore/syft:latest
    max-time: 15
    script:
      - syft . -o cyclonedx-json > sbom.cyclonedx.json
      - |
        curl -sf -X POST "$DEPTRACK_URL/api/v1/bom" \
          -H "X-Api-Key: $DEPTRACK_API_KEY" \
          -H "Content-Type: multipart/form-data" \
          -F "projectName=$BITBUCKET_REPO_SLUG" \
          -F "projectVersion=$BITBUCKET_BRANCH" \
          -F "autoCreate=true" \
          -F "bom=@sbom.cyclonedx.json"
    artifacts:
      - sbom.cyclonedx.json
```

### Burp Suite Enterprise DAST

Trigger a Burp Enterprise scan via API and poll for results:

```yaml
- step: &dast-burp
    name: "DAST - Burp Suite Enterprise"
    max-time: 60
    script:
      - |
        SCAN_ID=$(curl -sf -X POST "$BURP_ENTERPRISE_URL/api/v1/scans" \
          -H "Authorization: $BURP_ENTERPRISE_API_KEY" \
          -H "Content-Type: application/json" \
          -d "{\"scope\": {\"included_urls\": [\"$APP_STAGING_URL\"]}, \"scan_configuration\": [{\"name\": \"Crawl strategy - fastest\"}]}" \
          | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
      - echo "Burp scan ID: $SCAN_ID"
      - |
        while true; do
          STATUS=$(curl -sf "$BURP_ENTERPRISE_URL/api/v1/scans/$SCAN_ID" \
            -H "Authorization: $BURP_ENTERPRISE_API_KEY" \
            | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_metrics']['crawl_and_audit_progress'])")
          echo "Progress: $STATUS%"
          [ "$STATUS" = "100" ] && break
          sleep 30
        done
      - |
        curl -sf "$BURP_ENTERPRISE_URL/api/v1/scans/$SCAN_ID/report" \
          -H "Authorization: $BURP_ENTERPRISE_API_KEY" \
          -o burp-report.xml
    artifacts:
      - burp-report.xml
```

### AWS Inspector Post-Deployment Findings

Pull Inspector v2 findings for a specific ECR image after it is deployed:

```yaml
- step: &aws-inspector
    name: "AWS Inspector - ECR Image Findings"
    image: amazon/aws-cli:latest
    max-time: 10
    script:
      - |
        aws inspector2 list-findings \
          --filter-criteria "{\"ecrImageRepositoryName\":[{\"comparison\":\"EQUALS\",\"value\":\"$BITBUCKET_REPO_SLUG\"}]}" \
          --output json > inspector-findings.json
      - |
        CRITICAL=$(python3 -c "import json; d=json.load(open('inspector-findings.json')); print(sum(1 for f in d.get('findings',[]) if f.get('severity')=='CRITICAL'))")
        echo "Inspector CRITICAL findings: $CRITICAL"
        [ "$CRITICAL" -gt 0 ] && exit 1 || exit 0
    artifacts:
      - inspector-findings.json
```

### Protected Production Deployments

```yaml
- step: &deploy-production
    name: "Deploy to Production"
    deployment: production
    trigger: manual
    max-time: 20
    script:
      - kubectl set image deployment/app app=$IMAGE_TAG -n production
      - kubectl rollout status deployment/app -n production --timeout=300s
```

## Output Format

### generate subcommand

Writes `bitbucket-pipelines.yml` and prints a JSON summary:

```json
{
  "timestamp": "2026-05-01T12:00:00+00:00",
  "pipeline_name": "PaymentService",
  "project_type": "java",
  "security_level": "full",
  "security_steps": ["sast-sonarqube", "sast-coverity", "sca-dependency-check", "sca-dependency-track", "sca-blackduck", "container-trivy", "dast-zap", "defectdojo-import"],
  "output_file": "bitbucket-pipelines.yml",
  "coverage": {
    "sast": ["sonarqube", "coverity"],
    "sca": ["dependency-check", "dependency-track", "blackduck"],
    "container_scan": ["trivy"],
    "dast": ["owasp-zap"],
    "aggregation": ["defectdojo"]
  },
  "required_variables": ["SONAR_TOKEN", "SONAR_HOST_URL", "SONAR_PROJECT_KEY", "COVERITY_HOST", "..."],
  "recommendations": [...]
}
```

### audit subcommand

```json
{
  "timestamp": "2026-05-01T12:00:00+00:00",
  "pipeline_file": "bitbucket-pipelines.yml",
  "findings": [
    {
      "id": "F-001",
      "severity": "CRITICAL",
      "category": "hardcoded-secret",
      "description": "Possible hardcoded API token in script block",
      "line_hint": "Line 42: BLACKDUCK_API_TOKEN: abc123...",
      "recommendation": "Move to a secured Bitbucket repository variable"
    },
    {
      "id": "F-002",
      "severity": "HIGH",
      "category": "missing-security-tool",
      "description": "No SCA tool detected (dependency-check, blackduck, dependency-track)",
      "line_hint": "N/A",
      "recommendation": "Add OWASP Dependency-Check or Black Duck Detect as an SCA step"
    }
  ],
  "overall_risk": "CRITICAL",
  "summary": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
}
```

### report subcommand

```json
{
  "timestamp": "2026-05-01T12:00:00+00:00",
  "pipeline_file": "bitbucket-pipelines.yml",
  "overall_risk": "HIGH",
  "findings_count": 4,
  "by_severity": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 1},
  "by_category": {"missing-security-tool": 2, "unpinned-image": 1, "missing-max-time": 1},
  "action_plan": [
    "Add SonarQube SAST step with Quality Gate enforcement",
    "Add OWASP Dependency-Check or Black Duck SCA step",
    "Pin all Docker image references to specific version tags"
  ]
}
```
