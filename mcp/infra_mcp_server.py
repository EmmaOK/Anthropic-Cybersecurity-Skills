#!/usr/bin/env python3
"""
Phantom Infrastructure MCP Server
Exposes kubectl, AWS CLI, Terraform, and Helm to Claude/Phantom as MCP tools,
enabling Phantom to implement security fixes — not just find them.

All mutating operations (apply, delete, label) default to dry_run=True.
Set dry_run=False only after the user explicitly approves the change.

Tools:
  kubectl_get          — Read cluster resources (namespaces, pods, roles, etc.)
  kubectl_apply        — Apply a YAML manifest to the cluster
  kubectl_delete       — Delete a resource from the cluster
  kubectl_label        — Add/update labels on a resource
  kubectl_rollout      — Check rollout status or restart a deployment
  kubectl_run_command  — Run a safe, allowlisted kubectl command
  aws_run              — Run an allowlisted AWS CLI command
  aws_enable_guardduty — Enable GuardDuty in one or more regions
  aws_enable_security_hub — Enable Security Hub and standards in a region
  terraform_plan       — Run terraform plan and return the output
  terraform_apply      — Run terraform apply (requires explicit confirmation)
  helm_lint            — Lint a Helm chart for security issues
  helm_upgrade         — Install or upgrade a Helm release
  write_manifest       — Write a YAML/JSON manifest file to disk
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    print("MCP SDK not installed. Run: pip install mcp", file=sys.stderr)
    sys.exit(1)

# ── Safety allowlists ──────────────────────────────────────────────────────────

KUBECTL_SAFE_VERBS = {"get", "describe", "logs", "top", "version", "cluster-info",
                      "auth", "api-resources", "api-versions", "explain"}

KUBECTL_MUTATING_VERBS = {"apply", "delete", "label", "annotate", "patch",
                           "create", "replace", "rollout"}

AWS_ALLOWLIST = {
    # GuardDuty
    "guardduty": {"create-detector", "list-detectors", "get-detector", "update-detector",
                  "get-findings", "list-findings", "create-filter", "list-filters"},
    # Security Hub
    "securityhub": {"enable-security-hub", "get-enabled-standards", "batch-enable-standards",
                    "get-findings", "list-findings-aggregators", "describe-hub"},
    # S3
    "s3api": {"get-bucket-policy", "get-bucket-acl", "get-public-access-block",
              "put-public-access-block", "get-bucket-encryption", "put-bucket-encryption",
              "list-buckets", "get-bucket-logging", "put-bucket-logging",
              "get-bucket-versioning", "put-bucket-versioning"},
    # EC2 / Security Groups
    "ec2": {"describe-security-groups", "describe-instances", "describe-vpcs",
            "describe-subnets", "describe-network-acls", "describe-flow-logs",
            "revoke-security-group-ingress", "authorize-security-group-ingress",
            "create-flow-logs", "describe-regions"},
    # IAM (read-only)
    "iam": {"list-roles", "list-policies", "list-users", "list-groups",
            "get-role", "get-policy", "list-attached-role-policies",
            "list-role-policies", "get-account-password-policy",
            "list-access-keys", "generate-credential-report",
            "get-credential-report"},
    # Config
    "configservice": {"describe-config-rules", "describe-configuration-recorders",
                      "get-compliance-details-by-config-rule", "list-discovered-resources"},
    # CloudTrail
    "cloudtrail": {"describe-trails", "get-trail-status", "get-event-selectors",
                   "list-trails", "lookup-events"},
    # Inspector
    "inspector2": {"list-findings", "list-coverage", "batch-get-finding-details",
                   "enable", "disable", "list-account-permissions"},
}

server = Server("infra")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _run(cmd: list[str], cwd: str | None = None, timeout: int = 120) -> dict:
    """Run a subprocess and return {stdout, stderr, returncode}."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, cwd=cwd
        )
        return {
            "stdout":     result.stdout.strip(),
            "stderr":     result.stderr.strip(),
            "returncode": result.returncode,
            "success":    result.returncode == 0,
        }
    except FileNotFoundError:
        return {"stdout": "", "stderr": f"Command not found: {cmd[0]}", "returncode": 127, "success": False}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"Command timed out after {timeout}s", "returncode": -1, "success": False}


def _kubectl(*args, output_format: str = "json", timeout: int = 60) -> dict:
    cmd = ["kubectl"] + list(args)
    if output_format:
        cmd += ["-o", output_format]
    return _run(cmd, timeout=timeout)


def _has_tool(name: str) -> bool:
    return shutil.which(name) is not None


def _text(content) -> list[TextContent]:
    if not isinstance(content, str):
        content = json.dumps(content, indent=2)
    return [TextContent(type="text", text=content)]


# ── Tool definitions ───────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="kubectl_get",
            description=(
                "Read Kubernetes resources (namespaces, pods, deployments, services, "
                "roles, rolebindings, networkpolicies, etc.). Safe read-only operation. "
                "Returns JSON. Use resource='namespaces', 'pods', 'clusterroles', "
                "'networkpolicies', 'serviceaccounts', etc."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "resource":       {"type": "string", "description": "K8s resource type (e.g. namespaces, pods, clusterroles)"},
                    "name":           {"type": "string", "description": "Specific resource name (optional)"},
                    "namespace":      {"type": "string", "description": "Namespace (omit for cluster-scoped resources)"},
                    "all_namespaces": {"type": "boolean", "description": "Get across all namespaces", "default": False},
                    "label_selector": {"type": "string", "description": "Label selector filter (e.g. 'app=nginx')"},
                    "output":         {"type": "string", "description": "Output format: json (default) or yaml", "default": "json"},
                },
                "required": ["resource"],
            },
        ),
        Tool(
            name="kubectl_apply",
            description=(
                "Apply a YAML manifest to the Kubernetes cluster. Defaults to dry_run=True — "
                "set dry_run=False only after the user has reviewed and approved the manifest. "
                "Pass the full YAML content as manifest_yaml."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "manifest_yaml": {"type": "string", "description": "Full YAML manifest content to apply"},
                    "namespace":     {"type": "string", "description": "Target namespace (optional — can be in manifest)"},
                    "dry_run":       {"type": "boolean", "description": "If true, validate only (do not apply). Default: true", "default": True},
                },
                "required": ["manifest_yaml"],
            },
        ),
        Tool(
            name="kubectl_delete",
            description=(
                "Delete a Kubernetes resource. Defaults to dry_run=True — "
                "always confirm with the user before setting dry_run=False."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "resource":  {"type": "string", "description": "Resource type (e.g. pod, deployment, networkpolicy)"},
                    "name":      {"type": "string", "description": "Resource name"},
                    "namespace": {"type": "string", "description": "Namespace"},
                    "dry_run":   {"type": "boolean", "description": "If true, simulate only. Default: true", "default": True},
                },
                "required": ["resource", "name"],
            },
        ),
        Tool(
            name="kubectl_label",
            description=(
                "Add or update labels on a Kubernetes resource. Commonly used to apply "
                "Pod Security Standards labels to namespaces. Defaults to dry_run=True."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "resource":  {"type": "string", "description": "Resource type (e.g. namespace, pod, node)"},
                    "name":      {"type": "string", "description": "Resource name"},
                    "labels":    {"type": "object", "description": "Labels to apply as key-value pairs"},
                    "namespace": {"type": "string", "description": "Namespace (for namespaced resources)"},
                    "dry_run":   {"type": "boolean", "description": "If true, validate only. Default: true", "default": True},
                    "overwrite": {"type": "boolean", "description": "Overwrite existing labels. Default: true", "default": True},
                },
                "required": ["resource", "name", "labels"],
            },
        ),
        Tool(
            name="kubectl_rollout",
            description="Check rollout status or restart a Kubernetes deployment/daemonset/statefulset.",
            inputSchema={
                "type": "object",
                "properties": {
                    "action":    {"type": "string", "enum": ["status", "restart", "history", "undo"], "description": "Rollout action"},
                    "resource":  {"type": "string", "description": "Resource type: deployment, daemonset, statefulset"},
                    "name":      {"type": "string", "description": "Resource name"},
                    "namespace": {"type": "string", "description": "Namespace"},
                },
                "required": ["action", "resource", "name"],
            },
        ),
        Tool(
            name="aws_run",
            description=(
                "Run an allowlisted AWS CLI command. Only read and safe-write operations "
                "are permitted. Specify the AWS service, subcommand, and any additional args."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "service":    {"type": "string", "description": "AWS service (e.g. guardduty, s3api, ec2, iam, securityhub)"},
                    "command":    {"type": "string", "description": "AWS CLI subcommand (e.g. list-detectors, describe-security-groups)"},
                    "args":       {"type": "array",  "items": {"type": "string"}, "description": "Additional CLI arguments", "default": []},
                    "region":     {"type": "string", "description": "AWS region (uses default if omitted)"},
                    "profile":    {"type": "string", "description": "AWS CLI profile (uses default if omitted)"},
                },
                "required": ["service", "command"],
            },
        ),
        Tool(
            name="aws_enable_guardduty",
            description=(
                "Enable AWS GuardDuty in one or more regions. Creates a detector if none exists "
                "and enables S3, EKS, and Malware protection features."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "regions":       {"type": "array", "items": {"type": "string"}, "description": "AWS regions to enable GuardDuty in"},
                    "enable_s3":     {"type": "boolean", "description": "Enable S3 protection. Default: true", "default": True},
                    "enable_eks":    {"type": "boolean", "description": "Enable EKS protection. Default: true", "default": True},
                    "enable_malware":{"type": "boolean", "description": "Enable Malware protection. Default: true", "default": True},
                    "dry_run":       {"type": "boolean", "description": "Check current state only. Default: false", "default": False},
                },
                "required": ["regions"],
            },
        ),
        Tool(
            name="aws_enable_security_hub",
            description=(
                "Enable AWS Security Hub in a region and activate security standards "
                "(CIS, AWS Foundational, PCI DSS)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "region":               {"type": "string", "description": "AWS region"},
                    "enable_cis":           {"type": "boolean", "description": "Enable CIS AWS Foundations Benchmark. Default: true", "default": True},
                    "enable_aws_foundational": {"type": "boolean", "description": "Enable AWS Foundational Security Best Practices. Default: true", "default": True},
                    "enable_pci_dss":       {"type": "boolean", "description": "Enable PCI DSS standard. Default: false", "default": False},
                    "dry_run":              {"type": "boolean", "description": "Check current state only. Default: false", "default": False},
                },
                "required": ["region"],
            },
        ),
        Tool(
            name="terraform_plan",
            description="Run terraform plan in a directory and return the planned changes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "working_dir": {"type": "string", "description": "Path to the Terraform working directory"},
                    "var_file":    {"type": "string", "description": "Path to a .tfvars file (optional)"},
                    "target":      {"type": "string", "description": "Specific resource to plan (optional)"},
                },
                "required": ["working_dir"],
            },
        ),
        Tool(
            name="terraform_apply",
            description=(
                "Run terraform apply in a directory. Always confirm with the user before calling this. "
                "Use terraform_plan first to review changes."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "working_dir":    {"type": "string", "description": "Path to the Terraform working directory"},
                    "var_file":       {"type": "string", "description": "Path to a .tfvars file (optional)"},
                    "target":         {"type": "string", "description": "Specific resource to apply (optional)"},
                    "auto_approve":   {"type": "boolean", "description": "Skip interactive approval prompt. Default: false", "default": False},
                },
                "required": ["working_dir"],
            },
        ),
        Tool(
            name="helm_lint",
            description="Lint a Helm chart for misconfigurations and security issues.",
            inputSchema={
                "type": "object",
                "properties": {
                    "chart_path":  {"type": "string", "description": "Path to the Helm chart directory or package"},
                    "values_file": {"type": "string", "description": "Path to a values.yaml override file (optional)"},
                },
                "required": ["chart_path"],
            },
        ),
        Tool(
            name="helm_upgrade",
            description=(
                "Install or upgrade a Helm release. Defaults to dry_run=True. "
                "Set dry_run=False only after the user has reviewed the plan."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "release":     {"type": "string", "description": "Helm release name"},
                    "chart":       {"type": "string", "description": "Chart name or path (e.g. stable/nginx or ./my-chart)"},
                    "namespace":   {"type": "string", "description": "Target Kubernetes namespace"},
                    "values_file": {"type": "string", "description": "Path to values.yaml override (optional)"},
                    "values":      {"type": "object", "description": "Inline values to set (optional)"},
                    "version":     {"type": "string", "description": "Chart version to install (optional)"},
                    "dry_run":     {"type": "boolean", "description": "Simulate only. Default: true", "default": True},
                    "create_namespace": {"type": "boolean", "description": "Create namespace if missing. Default: true", "default": True},
                },
                "required": ["release", "chart", "namespace"],
            },
        ),
        Tool(
            name="write_manifest",
            description=(
                "Write a Kubernetes YAML manifest, Terraform file, or any config file to disk. "
                "Use this to stage files before applying them."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path":    {"type": "string", "description": "Absolute or relative file path to write"},
                    "content": {"type": "string", "description": "File content (YAML, JSON, HCL, etc.)"},
                    "mkdir":   {"type": "boolean", "description": "Create parent directories if needed. Default: true", "default": True},
                },
                "required": ["path", "content"],
            },
        ),
    ]


# ── Tool handlers ──────────────────────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "kubectl_get":
            return _kubectl_get(arguments)
        elif name == "kubectl_apply":
            return _kubectl_apply(arguments)
        elif name == "kubectl_delete":
            return _kubectl_delete(arguments)
        elif name == "kubectl_label":
            return _kubectl_label(arguments)
        elif name == "kubectl_rollout":
            return _kubectl_rollout(arguments)
        elif name == "aws_run":
            return _aws_run(arguments)
        elif name == "aws_enable_guardduty":
            return _aws_enable_guardduty(arguments)
        elif name == "aws_enable_security_hub":
            return _aws_enable_security_hub(arguments)
        elif name == "terraform_plan":
            return _terraform_plan(arguments)
        elif name == "terraform_apply":
            return _terraform_apply(arguments)
        elif name == "helm_lint":
            return _helm_lint(arguments)
        elif name == "helm_upgrade":
            return _helm_upgrade(arguments)
        elif name == "write_manifest":
            return _write_manifest(arguments)
        else:
            return _text({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return _text({"error": str(e), "tool": name})


# ── kubectl handlers ───────────────────────────────────────────────────────────

def _kubectl_get(args: dict) -> list[TextContent]:
    if not _has_tool("kubectl"):
        return _text({"error": "kubectl not found in PATH"})

    resource = args["resource"]
    cmd = ["kubectl", "get", resource]

    if args.get("name"):
        cmd.append(args["name"])
    if args.get("namespace"):
        cmd += ["-n", args["namespace"]]
    elif args.get("all_namespaces"):
        cmd.append("--all-namespaces")
    if args.get("label_selector"):
        cmd += ["-l", args["label_selector"]]

    fmt = args.get("output", "json")
    cmd += ["-o", fmt]

    result = _run(cmd)
    if result["success"] and fmt == "json":
        try:
            return _text(json.loads(result["stdout"]))
        except json.JSONDecodeError:
            pass
    return _text(result)


def _kubectl_apply(args: dict) -> list[TextContent]:
    if not _has_tool("kubectl"):
        return _text({"error": "kubectl not found in PATH"})

    manifest = args["manifest_yaml"]
    dry_run = args.get("dry_run", True)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(manifest)
        tmp = f.name

    try:
        cmd = ["kubectl", "apply", "-f", tmp]
        if args.get("namespace"):
            cmd += ["-n", args["namespace"]]
        if dry_run:
            cmd += ["--dry-run=client"]

        result = _run(cmd)
        result["dry_run"] = dry_run
        result["manifest_preview"] = manifest[:500] + ("..." if len(manifest) > 500 else "")
        return _text(result)
    finally:
        Path(tmp).unlink(missing_ok=True)


def _kubectl_delete(args: dict) -> list[TextContent]:
    if not _has_tool("kubectl"):
        return _text({"error": "kubectl not found in PATH"})

    dry_run = args.get("dry_run", True)
    cmd = ["kubectl", "delete", args["resource"], args["name"]]
    if args.get("namespace"):
        cmd += ["-n", args["namespace"]]
    if dry_run:
        cmd += ["--dry-run=client"]

    result = _run(cmd)
    result["dry_run"] = dry_run
    return _text(result)


def _kubectl_label(args: dict) -> list[TextContent]:
    if not _has_tool("kubectl"):
        return _text({"error": "kubectl not found in PATH"})

    labels = args.get("labels", {})
    label_args = [f"{k}={v}" for k, v in labels.items()]
    dry_run = args.get("dry_run", True)

    cmd = ["kubectl", "label", args["resource"], args["name"]] + label_args
    if args.get("namespace"):
        cmd += ["-n", args["namespace"]]
    if args.get("overwrite", True):
        cmd.append("--overwrite")
    if dry_run:
        cmd += ["--dry-run=client"]

    result = _run(cmd)
    result["dry_run"] = dry_run
    result["labels_applied"] = labels
    return _text(result)


def _kubectl_rollout(args: dict) -> list[TextContent]:
    if not _has_tool("kubectl"):
        return _text({"error": "kubectl not found in PATH"})

    action = args["action"]
    cmd = ["kubectl", "rollout", action,
           f"{args['resource']}/{args['name']}"]
    if args.get("namespace"):
        cmd += ["-n", args["namespace"]]

    result = _run(cmd, timeout=120)
    return _text(result)


# ── AWS handlers ───────────────────────────────────────────────────────────────

def _aws_run(args: dict) -> list[TextContent]:
    if not _has_tool("aws"):
        return _text({"error": "AWS CLI not found in PATH"})

    service = args["service"]
    command = args["command"]

    allowed = AWS_ALLOWLIST.get(service, set())
    if command not in allowed:
        return _text({
            "error": f"Command '{service} {command}' is not in the allowlist.",
            "allowed_commands": sorted(allowed),
            "tip": "If you need this command, request it to be added to the allowlist.",
        })

    cmd = ["aws", service, command] + args.get("args", [])
    if args.get("region"):
        cmd += ["--region", args["region"]]
    if args.get("profile"):
        cmd += ["--profile", args["profile"]]
    cmd.append("--output")
    cmd.append("json")

    result = _run(cmd, timeout=60)
    if result["success"]:
        try:
            return _text(json.loads(result["stdout"]))
        except json.JSONDecodeError:
            pass
    return _text(result)


def _aws_enable_guardduty(args: dict) -> list[TextContent]:
    if not _has_tool("aws"):
        return _text({"error": "AWS CLI not found in PATH"})

    regions = args["regions"]
    dry_run = args.get("dry_run", False)
    results = []

    for region in regions:
        region_result = {"region": region, "actions": []}

        # Check existing detectors
        check = _run(["aws", "guardduty", "list-detectors",
                      "--region", region, "--output", "json"])
        if not check["success"]:
            region_result["error"] = check["stderr"]
            results.append(region_result)
            continue

        try:
            detectors = json.loads(check["stdout"]).get("DetectorIds", [])
        except json.JSONDecodeError:
            detectors = []

        if detectors:
            detector_id = detectors[0]
            region_result["detector_id"] = detector_id
            region_result["actions"].append(f"Detector already exists: {detector_id}")
        elif not dry_run:
            # Create detector with data sources
            features = []
            if args.get("enable_s3", True):
                features += ["--features", "Name=S3_DATA_EVENTS,Status=ENABLED"]
            if args.get("enable_eks", True):
                features += ["--features", "Name=EKS_AUDIT_LOGS,Status=ENABLED"]
            if args.get("enable_malware", True):
                features += ["--features", "Name=EBS_MALWARE_PROTECTION,Status=ENABLED"]

            create = _run(["aws", "guardduty", "create-detector",
                           "--enable", "--region", region, "--output", "json"] + features)
            if create["success"]:
                try:
                    detector_id = json.loads(create["stdout"]).get("DetectorId", "")
                    region_result["detector_id"] = detector_id
                    region_result["actions"].append(f"Created detector: {detector_id}")
                except json.JSONDecodeError:
                    region_result["actions"].append("Detector created (ID parse failed)")
            else:
                region_result["error"] = create["stderr"]
        else:
            region_result["actions"].append("DRY RUN: would create GuardDuty detector")

        results.append(region_result)

    return _text({"guardduty_setup": results, "dry_run": dry_run,
                  "timestamp": datetime.now(timezone.utc).isoformat()})


def _aws_enable_security_hub(args: dict) -> list[TextContent]:
    if not _has_tool("aws"):
        return _text({"error": "AWS CLI not found in PATH"})

    region = args["region"]
    dry_run = args.get("dry_run", False)
    actions = []

    # ARNs for standards
    standard_arns = []
    if args.get("enable_cis", True):
        standard_arns.append(
            f"arn:aws:securityhub:{region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
        )
    if args.get("enable_aws_foundational", True):
        standard_arns.append(
            f"arn:aws:securityhub:{region}::standards/aws-foundational-security-best-practices/v/1.0.0"
        )
    if args.get("enable_pci_dss", False):
        standard_arns.append(
            f"arn:aws:securityhub:{region}::standards/pci-dss/v/3.2.1"
        )

    if dry_run:
        return _text({
            "dry_run": True,
            "region": region,
            "would_enable": ["Security Hub"] + standard_arns,
        })

    # Enable Security Hub
    enable = _run(["aws", "securityhub", "enable-security-hub",
                   "--region", region, "--output", "json"])
    if enable["success"]:
        actions.append("Security Hub enabled")
    elif "already enabled" in enable["stderr"].lower():
        actions.append("Security Hub already enabled")
    else:
        return _text({"error": enable["stderr"], "region": region})

    # Enable standards
    if standard_arns:
        sub_args = []
        for arn in standard_arns:
            sub_args += [f"StandardsArn={arn}"]
        enable_std = _run(["aws", "securityhub", "batch-enable-standards",
                           "--standards-subscription-requests"] + sub_args +
                          ["--region", region, "--output", "json"])
        if enable_std["success"]:
            actions.append(f"Enabled {len(standard_arns)} standards")
        else:
            actions.append(f"Standards warning: {enable_std['stderr'][:200]}")

    return _text({"security_hub": actions, "region": region,
                  "standards": standard_arns,
                  "timestamp": datetime.now(timezone.utc).isoformat()})


# ── Terraform handlers ─────────────────────────────────────────────────────────

def _terraform_plan(args: dict) -> list[TextContent]:
    if not _has_tool("terraform"):
        return _text({"error": "terraform not found in PATH"})

    working_dir = args["working_dir"]
    if not Path(working_dir).is_dir():
        return _text({"error": f"Directory not found: {working_dir}"})

    cmd = ["terraform", "plan", "-no-color"]
    if args.get("var_file"):
        cmd += [f"-var-file={args['var_file']}"]
    if args.get("target"):
        cmd += [f"-target={args['target']}"]

    result = _run(cmd, cwd=working_dir, timeout=300)
    return _text(result)


def _terraform_apply(args: dict) -> list[TextContent]:
    if not _has_tool("terraform"):
        return _text({"error": "terraform not found in PATH"})

    working_dir = args["working_dir"]
    if not Path(working_dir).is_dir():
        return _text({"error": f"Directory not found: {working_dir}"})

    cmd = ["terraform", "apply", "-no-color"]
    if args.get("var_file"):
        cmd += [f"-var-file={args['var_file']}"]
    if args.get("target"):
        cmd += [f"-target={args['target']}"]
    if args.get("auto_approve", False):
        cmd.append("-auto-approve")

    result = _run(cmd, cwd=working_dir, timeout=600)
    return _text(result)


# ── Helm handlers ──────────────────────────────────────────────────────────────

def _helm_lint(args: dict) -> list[TextContent]:
    if not _has_tool("helm"):
        return _text({"error": "helm not found in PATH"})

    cmd = ["helm", "lint", args["chart_path"]]
    if args.get("values_file"):
        cmd += ["-f", args["values_file"]]

    result = _run(cmd, timeout=60)
    return _text(result)


def _helm_upgrade(args: dict) -> list[TextContent]:
    if not _has_tool("helm"):
        return _text({"error": "helm not found in PATH"})

    dry_run = args.get("dry_run", True)
    cmd = [
        "helm", "upgrade", "--install",
        args["release"], args["chart"],
        "--namespace", args["namespace"],
    ]
    if args.get("create_namespace", True):
        cmd.append("--create-namespace")
    if args.get("values_file"):
        cmd += ["-f", args["values_file"]]
    if args.get("version"):
        cmd += ["--version", args["version"]]
    for k, v in (args.get("values") or {}).items():
        cmd += ["--set", f"{k}={v}"]
    if dry_run:
        cmd.append("--dry-run")

    result = _run(cmd, timeout=120)
    result["dry_run"] = dry_run
    return _text(result)


# ── File writer ────────────────────────────────────────────────────────────────

def _write_manifest(args: dict) -> list[TextContent]:
    path = Path(args["path"])
    if args.get("mkdir", True):
        path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(args["content"])
    return _text({
        "written": str(path.resolve()),
        "size_bytes": len(args["content"].encode()),
        "lines": args["content"].count("\n") + 1,
    })


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream,
                         server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
