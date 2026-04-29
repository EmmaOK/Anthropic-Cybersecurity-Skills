#!/usr/bin/env python3
"""
AI Workload Infrastructure Hardening Agent

Subcommands:
  scan     — Audit an AI infrastructure config JSON for security misconfigurations.
  scan-k8s — Parse a raw kubectl JSON export and check key deployment security fields.

Usage:
    agent.py scan     --config infra_config.json [--output infra_audit.json]
    agent.py scan-k8s --manifest deployment.json [--output k8s_audit.json]

To export a Kubernetes manifest for scan-k8s:
    kubectl get deployment <name> -o json > deployment.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

INFRA_CONTROLS: list[dict] = [
    {
        "id": "INFRA-001", "area": "container",
        "workload_field": "image_signed",
        "check": lambda v: v is True,
        "severity": "CRITICAL",
        "control": "Container image signing",
        "finding_template": "image_signed=false for workload '{name}' — unsigned images accepted without verification",
        "remediation": "Sign images with Cosign; configure admission controller (Kyverno/OPA) to reject unsigned images",
    },
    {
        "id": "INFRA-002", "area": "container",
        "workload_field": "image_scanned",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Container image vulnerability scanning",
        "finding_template": "image_scanned=false for workload '{name}' — no vulnerability scan before deployment",
        "remediation": "Integrate Trivy or Grype into CI pipeline; fail builds on CRITICAL/HIGH CVEs in container images",
    },
    {
        "id": "INFRA-003", "area": "container",
        "workload_field": "root_user",
        "check": lambda v: v is False,
        "severity": "CRITICAL",
        "control": "Non-root container execution",
        "finding_template": "root_user=true for workload '{name}' — container runs as root, enabling container escape",
        "remediation": "Set securityContext.runAsNonRoot=true and runAsUser to a non-zero UID in pod spec",
    },
    {
        "id": "INFRA-004", "area": "container",
        "workload_field": "privileged",
        "check": lambda v: v is False,
        "severity": "CRITICAL",
        "control": "No privileged containers",
        "finding_template": "privileged=true for workload '{name}' — privileged containers have full host access",
        "remediation": "Set securityContext.privileged=false; use specific capabilities if needed instead of privileged mode",
    },
    {
        "id": "INFRA-005", "area": "resources",
        "workload_check": lambda w: (
            w.get("resource_limits", {}).get("cpu") is not None and
            w.get("resource_limits", {}).get("memory") is not None
        ),
        "severity": "CRITICAL",
        "control": "Resource limits (anti-hijacking)",
        "finding_template": "No CPU/memory limits set for workload '{name}' — vulnerable to resource exhaustion and cryptomining",
        "remediation": "Set resources.limits.cpu and resources.limits.memory in pod spec; apply ResourceQuota at namespace level",
    },
    {
        "id": "INFRA-006", "area": "network",
        "workload_field": "network_policy",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Network policy enforcement",
        "finding_template": "network_policy=false for workload '{name}' — all pods can communicate freely (lateral movement risk)",
        "remediation": "Define NetworkPolicy restricting ingress/egress to only required services; deny-all default posture",
    },
    {
        "id": "INFRA-007", "area": "secrets",
        "workload_field": "secrets_as_env_vars",
        "check": lambda v: v is False,
        "severity": "HIGH",
        "control": "No secrets in environment variables",
        "finding_template": "secrets_as_env_vars=true for workload '{name}' — secrets visible in kubectl describe and process listings",
        "remediation": "Mount secrets as files via volume mounts or use Vault agent sidecar; avoid env var injection for credentials",
    },
    {
        "id": "INFRA-008", "area": "secrets",
        "workload_check": lambda w: w.get("service_account", "default") != "default",
        "severity": "HIGH",
        "control": "Dedicated service account (not default)",
        "finding_template": "Workload '{name}' uses 'default' service account — may have overprivileged token",
        "remediation": "Create a dedicated service account per workload; apply least-privilege RBAC roles",
    },
    {
        "id": "INFRA-009", "area": "rbac",
        "config_field": "rbac.least_privilege",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "RBAC least-privilege",
        "finding": "rbac.least_privilege=false — RBAC roles may be overprivileged for AI service accounts",
        "remediation": "Audit all RBAC roles bound to AI service accounts; remove unused verbs and resources",
    },
    {
        "id": "INFRA-010", "area": "rbac",
        "config_field": "rbac.service_account_automation",
        "check": lambda v: v is False,
        "severity": "MEDIUM",
        "control": "Service account token automount disabled",
        "finding": "service_account_automation=true — service account tokens auto-mounted in all pods",
        "remediation": "Set automountServiceAccountToken=false in pod specs that do not need API access",
    },
    {
        "id": "INFRA-011", "area": "admission",
        "config_field": "admission_controllers.pod_security_standards",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Pod Security Standards enforcement",
        "finding": "pod_security_standards=false — no admission-level enforcement of pod security baseline",
        "remediation": "Enable Pod Security Admission with 'baseline' or 'restricted' profile at namespace level",
    },
    {
        "id": "INFRA-012", "area": "admission",
        "config_field": "admission_controllers.image_policy_webhook",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Image policy admission webhook",
        "finding": "image_policy_webhook=false — no admission control to enforce image signing requirements",
        "remediation": "Deploy Kyverno or OPA Gatekeeper with policy requiring signed images from trusted registries",
    },
    {
        "id": "INFRA-013", "area": "network",
        "config_field": "network.agent_to_vectordb_isolated",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Agent-to-vector-DB network isolation",
        "finding": "agent_to_vectordb_isolated=false — vector DB reachable from any pod (embeddings exfiltration risk)",
        "remediation": "Apply NetworkPolicy restricting vector DB ingress to agent service pods only; use separate namespace",
    },
    {
        "id": "INFRA-014", "area": "network",
        "config_field": "network.agent_to_secret_store_isolated",
        "check": lambda v: v is True,
        "severity": "CRITICAL",
        "control": "Agent-to-secret-store network isolation",
        "finding": "agent_to_secret_store_isolated=false — secret store reachable broadly (lateral movement from agent pod)",
        "remediation": "Restrict Vault/Secrets Manager access to specific service account identities; deny pod-level network access",
    },
    {
        "id": "INFRA-015", "area": "network",
        "config_field": "network.egress_controlled",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Egress traffic control",
        "finding": "egress_controlled=false — AI agent pods can make arbitrary outbound connections (data exfiltration risk)",
        "remediation": "Apply egress NetworkPolicy; allowlist only required external endpoints (LLM API, tool backends)",
    },
    {
        "id": "INFRA-016", "area": "secrets",
        "config_field": "secrets_management.vault_integrated",
        "check": lambda v: v is True,
        "severity": "MEDIUM",
        "control": "Vault or secrets manager integration",
        "finding": "vault_integrated=false — using native Kubernetes secrets (base64, not encrypted by default)",
        "remediation": "Integrate HashiCorp Vault or AWS Secrets Manager; enable etcd encryption at rest for K8s secrets",
    },
]


def get_nested(obj: dict, path: str):
    for p in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(p)
    return obj


def set_nested(obj: dict, path: str, value) -> None:
    parts = path.split(".")
    for p in parts[:-1]:
        obj = obj.setdefault(p, {})
    obj[parts[-1]] = value


def cmd_scan(args) -> dict:
    path = Path(args.config)
    if not path.exists():
        print(f"[error] Config not found: {args.config}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        config = json.load(f)

    findings: list[dict] = []

    for ctrl in INFRA_CONTROLS:
        if "workload_field" in ctrl:
            for workload in config.get("workloads", []):
                val = workload.get(ctrl["workload_field"])
                if val is None or not ctrl["check"](val):
                    findings.append({
                        "id": ctrl["id"],
                        "severity": ctrl["severity"],
                        "control": ctrl["control"],
                        "finding": ctrl["finding_template"].format(name=workload.get("name", "unknown")),
                        "remediation": ctrl["remediation"],
                    })
        elif "workload_check" in ctrl:
            for workload in config.get("workloads", []):
                if not ctrl["workload_check"](workload):
                    findings.append({
                        "id": ctrl["id"],
                        "severity": ctrl["severity"],
                        "control": ctrl["control"],
                        "finding": ctrl["finding_template"].format(name=workload.get("name", "unknown")),
                        "remediation": ctrl["remediation"],
                    })
        elif "config_field" in ctrl:
            val = get_nested(config, ctrl["config_field"])
            if val is None or not ctrl["check"](val):
                findings.append({
                    "id": ctrl["id"],
                    "severity": ctrl["severity"],
                    "control": ctrl["control"],
                    "finding": ctrl["finding"],
                    "remediation": ctrl["remediation"],
                    "current_value": val,
                })

    return _build_report(config.get("system", "Unknown"), findings, args.output)


def cmd_scan_k8s(args) -> dict:
    path = Path(args.manifest)
    if not path.exists():
        print(f"[error] Manifest not found: {args.manifest}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        manifest = json.load(f)

    findings: list[dict] = []
    name = manifest.get("metadata", {}).get("name", "unknown")
    containers = (
        manifest.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("containers", [])
    )
    pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})

    for container in containers:
        cname = container.get("name", name)
        sec = container.get("securityContext", {})

        if not sec.get("runAsNonRoot"):
            findings.append({
                "id": "K8S-001", "severity": "CRITICAL",
                "control": "Non-root container execution",
                "finding": f"Container '{cname}' missing securityContext.runAsNonRoot=true",
                "remediation": "Set securityContext.runAsNonRoot=true and runAsUser to non-zero UID",
            })
        if sec.get("privileged"):
            findings.append({
                "id": "K8S-002", "severity": "CRITICAL",
                "control": "No privileged containers",
                "finding": f"Container '{cname}' has securityContext.privileged=true",
                "remediation": "Remove privileged=true; use specific capabilities only",
            })
        limits = container.get("resources", {}).get("limits", {})
        if not limits.get("cpu") or not limits.get("memory"):
            findings.append({
                "id": "K8S-003", "severity": "CRITICAL",
                "control": "Resource limits (anti-hijacking)",
                "finding": f"Container '{cname}' missing cpu/memory limits — cryptomining risk",
                "remediation": "Set resources.limits.cpu and resources.limits.memory",
            })
        env = container.get("env", [])
        secret_env = [e for e in env if e.get("valueFrom", {}).get("secretKeyRef")]
        if secret_env:
            findings.append({
                "id": "K8S-004", "severity": "HIGH",
                "control": "No secrets in environment variables",
                "finding": f"Container '{cname}' mounts {len(secret_env)} secret(s) as env vars — visible in pod description",
                "remediation": "Use volume mounts for secrets; prefer Vault agent sidecar injection",
            })

    if pod_spec.get("automountServiceAccountToken", True):
        findings.append({
            "id": "K8S-005", "severity": "MEDIUM",
            "control": "Service account token automount",
            "finding": f"Deployment '{name}' has automountServiceAccountToken=true (or unset default true)",
            "remediation": "Set automountServiceAccountToken=false if the pod does not need Kubernetes API access",
        })
    if pod_spec.get("serviceAccountName", "default") == "default":
        findings.append({
            "id": "K8S-006", "severity": "HIGH",
            "control": "Dedicated service account",
            "finding": f"Deployment '{name}' uses 'default' service account",
            "remediation": "Create a dedicated service account with least-privilege RBAC",
        })

    return _build_report(name, findings, args.output)


def _build_report(system: str, findings: list[dict], output_path: str) -> dict:
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        if sev in by_sev:
            by_sev[sev] += 1

    overall = (
        "CRITICAL" if by_sev["CRITICAL"] > 0 else
        "HIGH" if by_sev["HIGH"] > 0 else
        "MEDIUM" if by_sev["MEDIUM"] > 0 else "LOW"
    )

    report = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "system": system,
        "findings_count": len(findings),
        "by_severity": by_sev,
        "overall_risk": overall,
        "findings": findings,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] Infrastructure audit saved to {output_path}", file=sys.stderr)

    if overall in ("CRITICAL", "HIGH"):
        sys.exit(1)

    return report


import re as _re

# ── Remediation helpers ────────────────────────────────────────────────────

def _prompt(finding_id: str, severity: str, control: str, finding_text: str,
            proposed_lines: list[str]) -> str:
    print(f"\n{'─'*64}")
    print(f"[{finding_id}] {severity} — {control}")
    print(f"Finding  : {finding_text}")
    print("\nProposed fix:")
    for line in proposed_lines:
        print(f"  {line}")
    while True:
        try:
            ans = input("\nApply? [y]es / [n]o / [s]kip all / [a]ll remaining > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return "s"
        if ans and ans[0] in ("y", "n", "s", "a"):
            return ans[0]


_INFRA_PATCHES: dict[str, dict] = {
    "INFRA-001": {"kind": "workload", "field": "image_signed",  "value": True,
                  "desc": ["workload.image_signed = true",
                           "(enforce via Cosign + admission controller in the cluster)"]},
    "INFRA-002": {"kind": "workload", "field": "image_scanned", "value": True,
                  "desc": ["workload.image_scanned = true",
                           "(wire Trivy/Grype scan gate in your CI pipeline)"]},
    "INFRA-003": {"kind": "workload", "field": "root_user",     "value": False,
                  "desc": ["workload.root_user = false"]},
    "INFRA-004": {"kind": "workload", "field": "privileged",    "value": False,
                  "desc": ["workload.privileged = false"]},
    "INFRA-005": {"kind": "workload_limits",
                  "desc": ["workload.resource_limits.cpu = '500m'  (tune for your workload)",
                           "workload.resource_limits.memory = '512Mi'  (tune for your workload)"]},
    "INFRA-006": {"kind": "workload", "field": "network_policy", "value": True,
                  "desc": ["workload.network_policy = true",
                           "(create a NetworkPolicy manifest restricting ingress/egress)"]},
    "INFRA-007": {"kind": "workload", "field": "secrets_as_env_vars", "value": False,
                  "desc": ["workload.secrets_as_env_vars = false",
                           "(migrate secrets to volume mounts in the deployment manifest)"]},
    "INFRA-009": {"kind": "config", "field": "rbac.least_privilege", "value": True,
                  "desc": ["rbac.least_privilege = true",
                           "(audit RBAC ClusterRoles/Roles bound to AI service accounts)"]},
    "INFRA-010": {"kind": "config", "field": "rbac.service_account_automation", "value": False,
                  "desc": ["rbac.service_account_automation = false"]},
    "INFRA-011": {"kind": "config", "field": "admission_controllers.pod_security_standards", "value": True,
                  "desc": ["admission_controllers.pod_security_standards = true",
                           "(label namespace: kubectl label ns <ns> pod-security.kubernetes.io/enforce=restricted)"]},
    "INFRA-012": {"kind": "config", "field": "admission_controllers.image_policy_webhook", "value": True,
                  "desc": ["admission_controllers.image_policy_webhook = true",
                           "(deploy Kyverno or OPA Gatekeeper policy requiring signed images)"]},
    "INFRA-013": {"kind": "config", "field": "network.agent_to_vectordb_isolated", "value": True,
                  "desc": ["network.agent_to_vectordb_isolated = true",
                           "(create NetworkPolicy restricting vector DB ingress to agent pods only)"]},
    "INFRA-014": {"kind": "config", "field": "network.agent_to_secret_store_isolated", "value": True,
                  "desc": ["network.agent_to_secret_store_isolated = true",
                           "(restrict Vault/Secrets Manager to specific service account identities)"]},
    "INFRA-015": {"kind": "config", "field": "network.egress_controlled", "value": True,
                  "desc": ["network.egress_controlled = true",
                           "(create egress NetworkPolicy allowlisting LLM API + tool backends only)"]},
    "INFRA-016": {"kind": "config", "field": "secrets_management.vault_integrated", "value": True,
                  "desc": ["secrets_management.vault_integrated = true",
                           "(deploy Vault agent sidecar or switch to AWS Secrets Manager)"]},
}

_INFRA_MANUAL: dict[str, str] = {
    "INFRA-008": (
        "Create a dedicated service account per workload with least-privilege RBAC.\n"
        "  kubectl create serviceaccount <name> -n <namespace>\n"
        "  Then set serviceAccountName in pod spec."
    ),
}

_K8S_PATCHES: dict[str, list[str]] = {
    "K8S-001": ["securityContext.runAsNonRoot = true", "securityContext.runAsUser = 1000  (applied to all containers)"],
    "K8S-002": ["securityContext.privileged = false  (applied to all containers)"],
    "K8S-003": ["resources.limits.cpu = '500m'  (tune for workload)",
                "resources.limits.memory = '512Mi'  (tune for workload)"],
    "K8S-005": ["spec.template.spec.automountServiceAccountToken = false"],
}

_K8S_MANUAL: dict[str, str] = {
    "K8S-004": (
        "Convert secretKeyRef env vars to volume mounts in deployment YAML.\n"
        "  See: https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod\n"
        "  Or deploy a Vault agent sidecar for dynamic secret injection."
    ),
    "K8S-006": (
        "Create a dedicated service account:\n"
        "  kubectl create serviceaccount <name> -n <namespace>\n"
        "  Set spec.template.spec.serviceAccountName: <name> in the deployment."
    ),
}


def _apply_infra_patch(config: dict, finding_id: str, finding_text: str) -> bool:
    patch = _INFRA_PATCHES.get(finding_id)
    if not patch:
        return False
    kind = patch["kind"]
    if kind == "workload":
        m = _re.search(r"workload '([^']+)'", finding_text)
        wname = m.group(1) if m else None
        for w in config.get("workloads", []):
            if wname is None or w.get("name") == wname:
                w[patch["field"]] = patch["value"]
        return True
    if kind == "workload_limits":
        m = _re.search(r"workload '([^']+)'", finding_text)
        wname = m.group(1) if m else None
        for w in config.get("workloads", []):
            if wname is None or w.get("name") == wname:
                w.setdefault("resource_limits", {}).update({"cpu": "500m", "memory": "512Mi"})
        return True
    if kind == "config":
        set_nested(config, patch["field"], patch["value"])
        return True
    return False


def _apply_k8s_patch(manifest: dict, finding_id: str) -> bool:
    containers = (manifest.get("spec", {}).get("template", {})
                  .get("spec", {}).get("containers", []))
    pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})
    if finding_id == "K8S-001":
        for c in containers:
            c.setdefault("securityContext", {}).update({"runAsNonRoot": True, "runAsUser": 1000})
        return True
    if finding_id == "K8S-002":
        for c in containers:
            c.setdefault("securityContext", {})["privileged"] = False
        return True
    if finding_id == "K8S-003":
        for c in containers:
            c.setdefault("resources", {}).setdefault("limits", {}).update(
                {"cpu": "500m", "memory": "512Mi"})
        return True
    if finding_id == "K8S-005":
        pod_spec["automountServiceAccountToken"] = False
        return True
    return False


def cmd_remediate(args) -> dict:
    audit_path = Path(args.audit)
    if not audit_path.exists():
        print(f"[error] Audit file not found: {args.audit}", file=sys.stderr)
        sys.exit(1)
    with open(audit_path) as f:
        audit = json.load(f)

    findings = audit.get("findings", [])
    if not findings:
        print("[*] No findings in audit — nothing to remediate.")
        return {}

    is_k8s = any(f.get("id", "").startswith("K8S-") for f in findings)
    source_arg = args.manifest if is_k8s else args.config
    if not source_arg:
        flag = "--manifest" if is_k8s else "--config"
        print(f"[error] {flag} is required for this audit type", file=sys.stderr)
        sys.exit(1)

    source_path = Path(source_arg)
    if not source_path.exists():
        print(f"[error] Source file not found: {source_arg}", file=sys.stderr)
        sys.exit(1)
    with open(source_path) as f:
        source = json.load(f)

    stem = source_path.stem
    suffix = source_path.suffix or ".json"
    output_path = args.output or str(source_path.parent / f"{stem}.patched{suffix}")

    approved = skipped = manual = 0
    manual_items: list[dict] = []
    auto_approve = False

    for finding in findings:
        fid  = finding.get("id", "")
        fsev = finding.get("severity", "")
        fctl = finding.get("control", "")
        ftxt = finding.get("finding", "")

        manual_note = (_K8S_MANUAL if is_k8s else _INFRA_MANUAL).get(fid)
        if manual_note:
            print(f"\n{'─'*64}")
            print(f"[{fid}] {fsev} — {fctl}")
            print(f"Finding  : {ftxt}")
            print(f"\n[MANUAL REQUIRED]\n  {manual_note}")
            manual += 1
            manual_items.append({"id": fid, "severity": fsev, "finding": ftxt, "manual_steps": manual_note})
            continue

        proposed = (_K8S_PATCHES if is_k8s else {
            k: v["desc"] for k, v in _INFRA_PATCHES.items()
        }).get(fid, ["(no auto-patch available for this finding)"])

        if auto_approve:
            print(f"\n[auto-approved] [{fid}] {fctl}")
            decision = "y"
        else:
            decision = _prompt(fid, fsev, fctl, ftxt, proposed)

        if decision == "a":
            auto_approve = True
            decision = "y"
        if decision == "s":
            skipped += sum(
                1 for f in findings
                if f.get("id", "") not in (_K8S_MANUAL if is_k8s else _INFRA_MANUAL)
                and findings.index(f) > findings.index(finding)
            )
            break
        if decision == "n":
            skipped += 1
            continue

        applied = (_apply_k8s_patch(source, fid) if is_k8s
                   else _apply_infra_patch(source, fid, ftxt))
        if applied:
            approved += 1
            print("  [✓] Applied")
        else:
            skipped += 1

    with open(output_path, "w") as f:
        json.dump(source, f, indent=2)

    report = {
        "remediation_timestamp": datetime.now(timezone.utc).isoformat(),
        "source_file": str(source_path),
        "output_file": output_path,
        "findings_count": len(findings),
        "approved_and_applied": approved,
        "skipped": skipped,
        "manual_required": manual,
        "manual_items": manual_items,
    }
    print(f"\n{'═'*64}")
    print(json.dumps(report, indent=2))
    print(f"\n[*] Patched file written to {output_path}", file=sys.stderr)
    if is_k8s:
        print(f"[*] Review then apply: kubectl apply -f {output_path}", file=sys.stderr)
    print(f"[*] {manual} finding(s) require manual steps — see manual_items above", file=sys.stderr)
    return report


def main():
    parser = argparse.ArgumentParser(description="AI Workload Infrastructure Hardening Agent")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_scan = sub.add_parser("scan", help="Audit AI infra config JSON")
    p_scan.add_argument("--config", required=True, help="Infrastructure config JSON")
    p_scan.add_argument("--output", default="infra_audit.json")

    p_k8s = sub.add_parser("scan-k8s", help="Scan a kubectl deployment JSON export")
    p_k8s.add_argument("--manifest", required=True, help="kubectl deployment JSON (kubectl get deployment -o json)")
    p_k8s.add_argument("--output", default="k8s_audit.json")

    p_rem = sub.add_parser("remediate", help="Interactively apply fixes from scan or scan-k8s audit")
    p_rem.add_argument("--audit",    required=True, help="Audit JSON from scan or scan-k8s")
    p_rem.add_argument("--config",   default=None,  help="Original infra_config.json (for scan audits)")
    p_rem.add_argument("--manifest", default=None,  help="Original deployment.json (for scan-k8s audits)")
    p_rem.add_argument("--output",   default=None,  help="Output file (default: <source>.patched.json)")

    args = parser.parse_args()
    if args.subcommand == "scan":
        cmd_scan(args)
    elif args.subcommand == "scan-k8s":
        cmd_scan_k8s(args)
    elif args.subcommand == "remediate":
        cmd_remediate(args)


if __name__ == "__main__":
    main()
