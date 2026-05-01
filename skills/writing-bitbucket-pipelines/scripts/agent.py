#!/usr/bin/env python3
"""
Bitbucket Pipelines Security Agent

Three subcommands:
  generate — Scaffold a secure bitbucket-pipelines.yml wired to your enterprise security stack.
  audit    — Audit an existing bitbucket-pipelines.yml for security issues.
  report   — Summarize audit findings into a prioritized security report.

Security stack: SonarQube, Coverity, OWASP Dependency-Check, Dependency Track,
Black Duck, Trivy, OWASP ZAP, Burp Suite Enterprise, DefectDojo, AWS Inspector.

Usage:
    agent.py generate --project-type java --security-level full --pipeline-name "PaymentService"
    agent.py generate --project-type python --security-level standard --pipeline-name "DataAPI"
    agent.py audit --pipeline bitbucket-pipelines.yml [--output audit_report.json]
    agent.py report --audit audit_report.json [--output pipeline_security_report.json]
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Project-type build configurations ────────────────────────────────────────

PROJECT_CONFIGS = {
    "java": {
        "image": "maven:3.9-eclipse-temurin-21",
        "cache_key": "maven",
        "cache_path": "~/.m2/repository",
        "build_script": [
            "mvn -B verify --file pom.xml -Dsurefire.failIfNoSpecifiedTests=false",
        ],
        "sonar_extra": "-Dsonar.java.binaries=target/classes",
        "depcheck_opts": "--enableExperimental",
        "package_manifest": "pom.xml",
    },
    "python": {
        "image": "python:3.12-slim",
        "cache_key": "pip",
        "cache_path": "~/.cache/pip",
        "build_script": [
            "pip install -r requirements.txt",
            "python -m pytest tests/ --junitxml=test-results/pytest.xml || true",
        ],
        "sonar_extra": "",
        "depcheck_opts": "--enableExperimental",
        "package_manifest": "requirements.txt",
    },
    "node": {
        "image": "node:20-slim",
        "cache_key": "node",
        "cache_path": "node_modules",
        "build_script": [
            "npm ci",
            "npm run build --if-present",
            "npm test -- --ci || true",
        ],
        "sonar_extra": "",
        "depcheck_opts": "",
        "package_manifest": "package-lock.json",
    },
    "go": {
        "image": "golang:1.22-alpine",
        "cache_key": "go",
        "cache_path": "~/go/pkg/mod",
        "build_script": [
            "go mod download",
            "go build ./...",
            "go test ./... -v 2>&1 | tee test-results/go-test.txt || true",
        ],
        "sonar_extra": "",
        "depcheck_opts": "--enableExperimental",
        "package_manifest": "go.mod",
    },
    "dotnet": {
        "image": "mcr.microsoft.com/dotnet/sdk:8.0",
        "cache_key": "nuget",
        "cache_path": "~/.nuget/packages",
        "build_script": [
            "dotnet restore",
            "dotnet build --no-restore",
            "dotnet test --no-build --logger trx --results-directory test-results/ || true",
        ],
        "sonar_extra": "",
        "depcheck_opts": "--enableExperimental",
        "package_manifest": "*.csproj",
    },
    "docker": {
        "image": "atlassian/default-image:4",
        "cache_key": "",
        "cache_path": "",
        "build_script": [
            "docker build -t $BITBUCKET_REPO_SLUG:$BITBUCKET_COMMIT .",
        ],
        "sonar_extra": "",
        "depcheck_opts": "",
        "package_manifest": "Dockerfile",
    },
}

SECURITY_LEVELS = {
    "basic": {
        "description": "SonarQube SAST + OWASP Dependency-Check SCA + DefectDojo reporting",
        "sast": ["sonarqube"],
        "sca": ["dependency-check"],
        "container": [],
        "dast": [],
        "aggregation": ["defectdojo"],
    },
    "standard": {
        "description": "SonarQube + Dependency-Check + Dependency Track (SBOM) + Trivy + DefectDojo",
        "sast": ["sonarqube"],
        "sca": ["dependency-check", "dependency-track"],
        "container": ["trivy"],
        "dast": [],
        "aggregation": ["defectdojo"],
    },
    "full": {
        "description": "SonarQube + Coverity + Black Duck + Dependency Track + Trivy + ZAP + DefectDojo",
        "sast": ["sonarqube", "coverity"],
        "sca": ["blackduck", "dependency-track"],
        "container": ["trivy"],
        "dast": ["zap"],
        "aggregation": ["defectdojo"],
    },
}

# ── Step YAML builders ────────────────────────────────────────────────────────

def _build_step(cfg: dict) -> str:
    cache_block = f"\n        caches:\n          - {cfg['cache_key']}" if cfg["cache_key"] else ""
    scripts = "\n".join(f"          - {s}" for s in cfg["build_script"])
    return f"""\
    - step: &build
        name: "Build & Unit Tests"
        max-time: 30{cache_block}
        script:
{scripts}
        artifacts:
          - target/**
          - dist/**
          - build/**
          - "*.jar"
"""


def _sonarqube_step(cfg: dict) -> str:
    extra = f"\n          - {cfg['sonar_extra']}" if cfg["sonar_extra"] else ""
    return f"""\
    - step: &sast-sonarqube
        name: "SAST - SonarQube"
        image: sonarsource/sonar-scanner-cli:5
        max-time: 30
        script:
          - sonar-scanner
              -Dsonar.host.url=$SONAR_HOST_URL
              -Dsonar.login=$SONAR_TOKEN
              -Dsonar.projectKey=$SONAR_PROJECT_KEY
              -Dsonar.scm.revision=$BITBUCKET_COMMIT
              -Dsonar.pullrequest.key=$BITBUCKET_PR_ID
              -Dsonar.pullrequest.branch=$BITBUCKET_BRANCH
              -Dsonar.qualitygate.wait=true{extra}
"""


def _coverity_step() -> str:
    return """\
    - step: &sast-coverity
        name: "SAST - Coverity"
        max-time: 60
        script:
          - cov-configure --template --compiler cc --comptype gcc
          - cov-build --dir idir --no-command --fs-capture-search .
          - cov-analyze --dir idir --all --concurrency --security --enable-fnptr
          - >
            cov-commit-defects
              --dir idir
              --host $COVERITY_HOST
              --stream $COVERITY_STREAM
              --auth-key-file <(echo "$COVERITY_AUTH_KEY")
              --url https://$COVERITY_HOST/
"""


def _dependency_check_step(cfg: dict) -> str:
    extra_opts = f" {cfg['depcheck_opts']}" if cfg["depcheck_opts"] else ""
    return f"""\
    - step: &sca-dependency-check
        name: "SCA - OWASP Dependency-Check"
        image: owasp/dependency-check:10
        max-time: 30
        script:
          - mkdir -p reports
          - >
            /usr/share/dependency-check/bin/dependency-check.sh
              --scan .
              --format JSON
              --format HTML
              --out reports/{extra_opts}
              --failOnCVSS 7
              --prettyPrint
        artifacts:
          - reports/dependency-check-report.json
          - reports/dependency-check-report.html
"""


def _dependency_track_step() -> str:
    return """\
    - step: &sca-dependency-track
        name: "SCA - Dependency Track (SBOM)"
        image: anchore/syft:1.4.1
        max-time: 15
        script:
          - syft . -o cyclonedx-json > sbom.cyclonedx.json
          - |
            curl -sf -X POST "$DEPTRACK_URL/api/v1/bom" \\
              -H "X-Api-Key: $DEPTRACK_API_KEY" \\
              -H "Content-Type: multipart/form-data" \\
              -F "projectName=$BITBUCKET_REPO_SLUG" \\
              -F "projectVersion=$BITBUCKET_BRANCH" \\
              -F "autoCreate=true" \\
              -F "bom=@sbom.cyclonedx.json"
        artifacts:
          - sbom.cyclonedx.json
"""


def _blackduck_step() -> str:
    return """\
    - step: &sca-blackduck
        name: "SCA - Black Duck"
        max-time: 45
        script:
          - >
            bash <(curl -s -L https://detect.synopsys.com/detect9.sh)
              --blackduck.url=$BLACKDUCK_URL
              --blackduck.api.token=$BLACKDUCK_API_TOKEN
              --detect.project.name=$BITBUCKET_REPO_SLUG
              --detect.project.version.name=$BITBUCKET_BRANCH
              --detect.risk.report.pdf=true
              --detect.policy.check.fail.on.severities=BLOCKER,CRITICAL
              --detect.report.timeout=300
        artifacts:
          - "*.pdf"
          - blackduck/**
"""


def _trivy_step() -> str:
    return """\
    - step: &container-trivy
        name: "Container Scan - Trivy"
        image: aquasec/trivy:0.52.2
        max-time: 20
        services:
          - docker
        script:
          - docker build -t $BITBUCKET_REPO_SLUG:$BITBUCKET_COMMIT .
          - >
            trivy image
              --exit-code 1
              --severity HIGH,CRITICAL
              --format json
              --output trivy-results.json
              --ignore-unfixed
              $BITBUCKET_REPO_SLUG:$BITBUCKET_COMMIT
        artifacts:
          - trivy-results.json
"""


def _zap_step() -> str:
    return """\
    - step: &dast-zap
        name: "DAST - OWASP ZAP"
        image: ghcr.io/zaproxy/zaproxy:stable
        max-time: 60
        script:
          - mkdir -p zap-reports
          - >
            zap-baseline.py
              -t $APP_STAGING_URL
              -r zap-reports/zap-report.html
              -J zap-reports/zap-report.json
              -I
              --auto
          - |
            python3 -c "
            import json, sys
            r = json.load(open('zap-reports/zap-report.json'))
            highs = sum(1 for a in r.get('alerts', []) if int(a.get('riskcode', 0)) >= 3)
            print(f'ZAP: {highs} HIGH/CRITICAL alerts')
            sys.exit(1 if highs > 0 else 0)
            "
        artifacts:
          - zap-reports/**
"""


def _defectdojo_step(level: dict) -> str:
    imports = []

    if "sonarqube" in level["sast"]:
        imports.append("""\
          - |
            curl -sf -X POST "$DEFECTDOJO_URL/api/v2/import-scan/" \\
              -H "Authorization: Token $DEFECTDOJO_API_KEY" \\
              -F "scan_type=SonarQube API Import" \\
              -F "product_name=$BITBUCKET_REPO_SLUG" \\
              -F "engagement_name=Pipeline-$BITBUCKET_BUILD_NUMBER" \\
              -F "minimum_severity=High" \\
              -F "sonarqube_url=$SONAR_HOST_URL" \\
              -F "sonarqube_api_key=$SONAR_TOKEN" \\
              || echo "SonarQube import failed (non-blocking)" """)

    if "dependency-check" in level["sca"]:
        imports.append("""\
          - |
            curl -sf -X POST "$DEFECTDOJO_URL/api/v2/import-scan/" \\
              -H "Authorization: Token $DEFECTDOJO_API_KEY" \\
              -F "scan_type=Dependency Check Scan" \\
              -F "product_name=$BITBUCKET_REPO_SLUG" \\
              -F "engagement_name=Pipeline-$BITBUCKET_BUILD_NUMBER" \\
              -F "minimum_severity=High" \\
              -F "file=@reports/dependency-check-report.json" \\
              || echo "Dependency-Check import failed (non-blocking)" """)

    if "trivy" in level["container"]:
        imports.append("""\
          - |
            curl -sf -X POST "$DEFECTDOJO_URL/api/v2/import-scan/" \\
              -H "Authorization: Token $DEFECTDOJO_API_KEY" \\
              -F "scan_type=Trivy Scan" \\
              -F "product_name=$BITBUCKET_REPO_SLUG" \\
              -F "engagement_name=Pipeline-$BITBUCKET_BUILD_NUMBER" \\
              -F "minimum_severity=High" \\
              -F "file=@trivy-results.json" \\
              || echo "Trivy import failed (non-blocking)" """)

    if "zap" in level["dast"]:
        imports.append("""\
          - |
            curl -sf -X POST "$DEFECTDOJO_URL/api/v2/import-scan/" \\
              -H "Authorization: Token $DEFECTDOJO_API_KEY" \\
              -F "scan_type=ZAP Scan" \\
              -F "product_name=$BITBUCKET_REPO_SLUG" \\
              -F "engagement_name=Pipeline-$BITBUCKET_BUILD_NUMBER" \\
              -F "minimum_severity=High" \\
              -F "file=@zap-reports/zap-report.json" \\
              || echo "ZAP import failed (non-blocking)" """)

    script_block = "\n".join(imports) if imports else "          - echo 'No findings to import'"

    return f"""\
    - step: &defectdojo-import
        name: "DefectDojo - Import All Findings"
        max-time: 10
        script:
{script_block}
"""


def _deploy_steps() -> str:
    return """\
    - step: &deploy-staging
        name: "Deploy to Staging"
        deployment: staging
        trigger: automatic
        max-time: 20
        script:
          - echo "Add staging deployment commands here"

    - step: &deploy-production
        name: "Deploy to Production"
        deployment: production
        trigger: manual
        max-time: 20
        script:
          - echo "Add production deployment commands here"
"""


def _pipelines_section(level: dict, has_container: bool, has_dast: bool) -> str:
    sast_tools = level["sast"]
    sca_tools = level["sca"]

    # PR parallel steps: SAST + primary SCA
    pr_steps = []
    if "sonarqube" in sast_tools:
        pr_steps.append("          - step: *sast-sonarqube")
    if "dependency-check" in sca_tools:
        pr_steps.append("          - step: *sca-dependency-check")
    elif "blackduck" in sca_tools:
        pr_steps.append("          - step: *sca-blackduck")

    # Main branch parallel steps: all SAST + all SCA + container
    main_steps = list(pr_steps)
    if "coverity" in sast_tools:
        main_steps.append("          - step: *sast-coverity")
    if "dependency-track" in sca_tools and "          - step: *sca-dependency-track" not in main_steps:
        main_steps.append("          - step: *sca-dependency-track")
    if "blackduck" in sca_tools and "          - step: *sca-blackduck" not in main_steps:
        main_steps.append("          - step: *sca-blackduck")
    if has_container:
        main_steps.append("          - step: *container-trivy")

    # Custom full-scan steps
    custom_steps = []
    if "sonarqube" in sast_tools:
        custom_steps.append("      - step: *sast-sonarqube")
    if "coverity" in sast_tools:
        custom_steps.append("      - step: *sast-coverity")
    if "dependency-check" in sca_tools:
        custom_steps.append("      - step: *sca-dependency-check")
    if "dependency-track" in sca_tools:
        custom_steps.append("      - step: *sca-dependency-track")
    if "blackduck" in sca_tools:
        custom_steps.append("      - step: *sca-blackduck")
    if has_container:
        custom_steps.append("      - step: *container-trivy")
    if has_dast:
        custom_steps.append("      - step: *dast-zap")
    custom_steps.append("      - step: *defectdojo-import")

    pr_parallel = "\n".join(pr_steps) if pr_steps else "          - step: *sast-sonarqube"
    main_parallel = "\n".join(main_steps) if main_steps else "          - step: *sast-sonarqube"
    custom_str = "\n".join(custom_steps)

    dast_block = ""
    if has_dast:
        dast_block = """
      - step: *dast-zap"""

    return f"""\
pipelines:
  # Runs on pushes to branches without a more-specific pipeline match
  default:
    - step: *build
    - step: *sast-sonarqube

  # Security gate on every pull request
  pull-requests:
    '**':
      - step: *build
      - parallel:
{pr_parallel}

  # Full pipeline on main: build → scan → deploy
  branches:
    main:
      - step: *build
      - parallel:
{main_parallel}
      - step: *deploy-staging{dast_block}
      - step: *defectdojo-import
      - step: *deploy-production

  # On-demand: run all security scans without deploying
  custom:
    security-full-scan:
{custom_str}
"""


# ── generate command ──────────────────────────────────────────────────────────

def cmd_generate(args) -> dict:
    cfg = PROJECT_CONFIGS[args.project_type]
    level = SECURITY_LEVELS[args.security_level]

    has_container = bool(level["container"])
    has_dast = bool(level["dast"])
    has_coverity = "coverity" in level["sast"]
    has_depcheck = "dependency-check" in level["sca"]
    has_deptrack = "dependency-track" in level["sca"]
    has_blackduck = "blackduck" in level["sca"]

    # --- definitions block ---
    cache_block = ""
    if cfg["cache_key"]:
        cache_block = f"\n  caches:\n    {cfg['cache_key']}: {cfg['cache_path']}"

    services_block = ""
    if has_container:
        services_block = "\n\n  services:\n    docker:\n      memory: 2048"

    # --- step definitions ---
    step_defs = _build_step(cfg)
    step_defs += "\n" + _sonarqube_step(cfg)
    if has_coverity:
        step_defs += "\n" + _coverity_step()
    if has_depcheck:
        step_defs += "\n" + _dependency_check_step(cfg)
    if has_deptrack:
        step_defs += "\n" + _dependency_track_step()
    if has_blackduck:
        step_defs += "\n" + _blackduck_step()
    if has_container:
        step_defs += "\n" + _trivy_step()
    if has_dast:
        step_defs += "\n" + _zap_step()
    step_defs += "\n" + _defectdojo_step(level)
    step_defs += "\n" + _deploy_steps()

    # --- required variables list ---
    required_vars = [
        "SONAR_TOKEN", "SONAR_HOST_URL", "SONAR_PROJECT_KEY",
        "DEFECTDOJO_URL", "DEFECTDOJO_API_KEY",
    ]
    if has_coverity:
        required_vars += ["COVERITY_HOST", "COVERITY_AUTH_KEY", "COVERITY_STREAM"]
    if has_depcheck:
        pass  # no external auth needed
    if has_deptrack:
        required_vars += ["DEPTRACK_URL", "DEPTRACK_API_KEY"]
    if has_blackduck:
        required_vars += ["BLACKDUCK_URL", "BLACKDUCK_API_TOKEN"]
    if has_dast:
        required_vars.append("APP_STAGING_URL")

    # --- full YAML ---
    pipeline_yaml = f"""\
# bitbucket-pipelines.yml
# Project : {args.pipeline_name}
# Type    : {args.project_type}
# Security: {args.security_level} — {level['description']}
#
# Required Bitbucket repository variables (Settings → Repository variables):
# Mark all credential variables as Secured.
{chr(10).join('# ' + v for v in required_vars)}
#
# Generated by Phantom / writing-bitbucket-pipelines skill

image: {cfg['image']}

definitions:{cache_block}{services_block}

  steps:
{step_defs}
{_pipelines_section(level, has_container, has_dast)}"""

    Path(args.output).write_text(pipeline_yaml)

    all_steps = (
        level["sast"]
        + level["sca"]
        + (["trivy"] if has_container else [])
        + (["owasp-zap"] if has_dast else [])
        + ["defectdojo"]
    )

    recommendations = [
        f"Set {v} as a secured Bitbucket repository variable" for v in required_vars
    ]
    recommendations += [
        "Configure 'staging' and 'production' environments under Settings → Deployments",
        "Create a SonarQube Quality Gate that blocks on new CRITICAL or HIGH findings",
        "Create a DefectDojo product matching '$BITBUCKET_REPO_SLUG' before the first pipeline run",
    ]
    if not has_dast:
        recommendations.append("Consider upgrading to 'full' to add OWASP ZAP DAST scanning against staging")
    if not has_coverity:
        recommendations.append("Consider Coverity for deep taint-analysis SAST on high-risk codebases")

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pipeline_name": args.pipeline_name,
        "project_type": args.project_type,
        "security_level": args.security_level,
        "security_level_description": level["description"],
        "security_steps_configured": all_steps,
        "output_file": args.output,
        "coverage": {
            "sast": level["sast"],
            "sca": level["sca"],
            "container_scan": level["container"],
            "dast": level["dast"],
            "aggregation": level["aggregation"],
        },
        "required_variables": required_vars,
        "recommendations": recommendations,
    }

    print(json.dumps(summary, indent=2))
    return summary


# ── audit command ─────────────────────────────────────────────────────────────

_SECRET_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[A-Za-z0-9!@#$%^&*()\-_]{6,}["\']?'), "password-like value"),
    (re.compile(r'(?i)(api[_-]?key|apikey|api[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{12,}["\']?'), "API key/token"),
    (re.compile(r'(?i)(secret|auth[_-]?token|bearer)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{12,}["\']?'), "secret/token"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS access key ID"),
    (re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9/+]{30,}["\']?'), "AWS secret key"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), "GitHub PAT"),
    (re.compile(r'(?i)sonar[_-]?token\s*[=:]\s*["\']?[A-Za-z0-9_]{8,}["\']?'), "SonarQube token"),
    (re.compile(r'(?i)blackduck[_-]?api[_-]?token\s*[=:]\s*["\']?[A-Za-z0-9_\-]{8,}["\']?'), "Black Duck token"),
    (re.compile(r'(?i)defectdojo[_-]?api[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9_]{8,}["\']?'), "DefectDojo API key"),
]

# Tools that must appear somewhere in the pipeline YAML, by security category
REQUIRED_TOOLS = {
    "SAST": {
        "keywords": ["sonarqube", "sonar-scanner", "sonar_token", "coverity", "cov-analyze", "cov-build"],
        "severity": "HIGH",
        "recommendation": "Add SonarQube (sonar-scanner) or Coverity SAST step",
    },
    "SCA": {
        "keywords": ["dependency-check", "owasp/dependency-check", "blackduck", "detect.synopsys", "dependency-track", "deptrack"],
        "severity": "HIGH",
        "recommendation": "Add OWASP Dependency-Check, Black Duck Detect, or Dependency Track SCA step",
    },
    "Container Scan": {
        "keywords": ["trivy", "aquasec/trivy", "grype", "clair", "docker-scout"],
        "severity": "MEDIUM",
        "recommendation": "Add Trivy container image scanning step before production deployment",
    },
    "DAST": {
        "keywords": ["zap", "zaproxy", "burp", "nuclei"],
        "severity": "MEDIUM",
        "recommendation": "Add OWASP ZAP baseline or Burp Suite Enterprise DAST step against staging",
    },
    "Finding Aggregation": {
        "keywords": ["defectdojo", "defect-dojo"],
        "severity": "LOW",
        "recommendation": "Add a DefectDojo import step to consolidate findings for triage and tracking",
    },
}


def _check_hardcoded_secrets(text: str) -> list:
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pattern, label in _SECRET_PATTERNS:
            m = pattern.search(line)
            if m and "$" not in m.group():
                findings.append({
                    "severity": "CRITICAL",
                    "category": "hardcoded-secret",
                    "description": f"Possible hardcoded {label}",
                    "line_hint": f"Line {lineno}: {stripped[:120]}",
                    "recommendation": "Move credential to a secured Bitbucket repository variable and reference as $VAR_NAME",
                })
                break  # one finding per line
    return findings


def _check_unpinned_images(text: str) -> list:
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped.startswith("image:"):
            continue
        img = stripped[len("image:"):].strip().strip('"').strip("'")
        if not img or img.startswith("$"):
            continue
        if img.endswith(":latest"):
            findings.append({
                "severity": "HIGH",
                "category": "unpinned-image",
                "description": f"Image '{img}' uses floating ':latest' tag",
                "line_hint": f"Line {lineno}: {stripped[:120]}",
                "recommendation": f"Pin to a specific version tag: {img.replace(':latest', ':X.Y.Z')}",
            })
        elif ":" not in img and "@" not in img:
            findings.append({
                "severity": "HIGH",
                "category": "unpinned-image",
                "description": f"Image '{img}' has no version tag or digest",
                "line_hint": f"Line {lineno}: {stripped[:120]}",
                "recommendation": f"Add a version tag: {img}:X.Y.Z",
            })
    return findings


def _check_missing_tools(text: str) -> list:
    findings = []
    text_lower = text.lower()
    for category, meta in REQUIRED_TOOLS.items():
        if not any(kw in text_lower for kw in meta["keywords"]):
            findings.append({
                "severity": meta["severity"],
                "category": "missing-security-tool",
                "description": f"No {category} tool detected ({', '.join(meta['keywords'][:4])}...)",
                "line_hint": "N/A",
                "recommendation": meta["recommendation"],
            })
    return findings


def _check_manual_gate(text: str) -> list:
    if "deployment: production" in text and "trigger: manual" not in text:
        return [{
            "severity": "HIGH",
            "category": "missing-manual-gate",
            "description": "Production deployment step lacks 'trigger: manual' approval gate",
            "line_hint": "Search for 'deployment: production'",
            "recommendation": "Add 'trigger: manual' to the production deployment step",
        }]
    return []


def _check_privileged_docker(text: str) -> list:
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if "privileged: true" in line.lower():
            findings.append({
                "severity": "MEDIUM",
                "category": "privileged-docker",
                "description": "Step uses Docker privileged mode",
                "line_hint": f"Line {lineno}: {line.strip()[:120]}",
                "recommendation": "Replace privileged mode with Docker BuildKit or Kaniko for image builds",
            })
    return findings


def _check_missing_max_time(text: str) -> list:
    step_count = len(re.findall(r'^\s+-\s+step:', text, re.MULTILINE))
    max_time_count = len(re.findall(r'max-time:', text))
    if step_count > 0 and max_time_count == 0:
        return [{
            "severity": "LOW",
            "category": "missing-max-time",
            "description": f"None of the {step_count} step(s) have a 'max-time' limit",
            "line_hint": "N/A",
            "recommendation": "Add 'max-time: N' (minutes) to each step to cap Bitbucket build-minute consumption",
        }]
    return []


def cmd_audit(args) -> dict:
    path = Path(args.pipeline)
    if not path.exists():
        print(f"[error] Pipeline file not found: {args.pipeline}", file=sys.stderr)
        sys.exit(1)

    text = path.read_text()
    raw_findings = (
        _check_hardcoded_secrets(text)
        + _check_unpinned_images(text)
        + _check_missing_tools(text)
        + _check_manual_gate(text)
        + _check_privileged_docker(text)
        + _check_missing_max_time(text)
    )

    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    raw_findings.sort(key=lambda x: sev_order.get(x["severity"], 0), reverse=True)

    findings = []
    for i, f in enumerate(raw_findings, 1):
        f["id"] = f"F-{i:03d}"
        findings.append(f)

    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        by_severity[f["severity"]] += 1

    overall_risk = (
        "CRITICAL" if by_severity["CRITICAL"] > 0
        else "HIGH" if by_severity["HIGH"] > 0
        else "MEDIUM" if by_severity["MEDIUM"] > 0
        else "LOW"
    )

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pipeline_file": args.pipeline,
        "findings": findings,
        "overall_risk": overall_risk,
        "summary": by_severity,
    }

    Path(args.output).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\n[*] Audit report saved to {args.output}", file=sys.stderr)
    return report


# ── report command ────────────────────────────────────────────────────────────

def cmd_report(args) -> dict:
    path = Path(args.audit)
    if not path.exists():
        print(f"[error] Audit file not found: {args.audit}", file=sys.stderr)
        sys.exit(1)

    audit = json.loads(path.read_text())
    findings = audit.get("findings", [])
    by_severity = audit.get("summary", {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
    overall_risk = audit.get("overall_risk", "LOW")

    by_category: dict[str, int] = {}
    for f in findings:
        cat = f.get("category", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1

    action_plan = []
    if by_severity.get("CRITICAL", 0) > 0:
        action_plan.append("IMMEDIATE: Remove all hardcoded credentials and rotate any exposed secrets now")
    if by_category.get("unpinned-image", 0) > 0:
        action_plan.append("Pin all Docker image references to specific version tags or SHA digests")
    if by_category.get("missing-security-tool", 0) > 0:
        action_plan.append("Add missing security tools — see individual findings for specific recommendations")
    if by_category.get("missing-manual-gate", 0) > 0:
        action_plan.append("Add 'trigger: manual' to all production deployment steps")
    if by_category.get("privileged-docker", 0) > 0:
        action_plan.append("Replace Docker privileged mode with BuildKit or Kaniko")
    if by_category.get("missing-max-time", 0) > 0:
        action_plan.append("Configure 'max-time' limits on all pipeline steps")

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pipeline_file": audit.get("pipeline_file", "unknown"),
        "overall_risk": overall_risk,
        "findings_count": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "top_findings": findings[:10],
        "action_plan": action_plan,
        "recommendation": (
            f"{len(findings)} finding(s): "
            f"{by_severity.get('CRITICAL',0)} CRITICAL, "
            f"{by_severity.get('HIGH',0)} HIGH, "
            f"{by_severity.get('MEDIUM',0)} MEDIUM, "
            f"{by_severity.get('LOW',0)} LOW. "
            + ("Immediate remediation required." if overall_risk in ("CRITICAL", "HIGH")
               else "Review and remediate at next sprint.")
        ),
    }

    Path(args.output).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\n[*] Security report saved to {args.output}", file=sys.stderr)

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)

    return report


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Bitbucket Pipelines Security Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    # generate
    p_gen = sub.add_parser("generate", help="Scaffold a secure bitbucket-pipelines.yml")
    p_gen.add_argument(
        "--project-type",
        choices=list(PROJECT_CONFIGS.keys()),
        default="python",
        help="Application language/runtime (default: python)",
    )
    p_gen.add_argument(
        "--security-level",
        choices=list(SECURITY_LEVELS.keys()),
        default="standard",
        help="Security depth: basic | standard | full (default: standard)",
    )
    p_gen.add_argument(
        "--pipeline-name",
        default="MyProject",
        help="Project name embedded in the YAML header comment",
    )
    p_gen.add_argument(
        "--output",
        default="bitbucket-pipelines.yml",
        help="Output file path (default: bitbucket-pipelines.yml)",
    )

    # audit
    p_audit = sub.add_parser("audit", help="Security-audit an existing bitbucket-pipelines.yml")
    p_audit.add_argument("--pipeline", required=True, help="Path to the YAML file to audit")
    p_audit.add_argument("--output", default="audit_report.json")

    # report
    p_report = sub.add_parser("report", help="Prioritized security report from an audit JSON")
    p_report.add_argument("--audit", required=True, help="Path to audit_report.json")
    p_report.add_argument("--output", default="pipeline_security_report.json")

    args = parser.parse_args()
    {
        "generate": cmd_generate,
        "audit": cmd_audit,
        "report": cmd_report,
    }[args.subcommand](args)


if __name__ == "__main__":
    main()
