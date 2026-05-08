#!/usr/bin/env python3
"""Kubernetes RBAC hardening audit agent.

Audits Kubernetes Role-Based Access Control configuration for security
weaknesses including overly permissive ClusterRoles, wildcard permissions,
privilege escalation paths, and service account misconfigurations.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def run_kubectl(args_list, timeout=60):
    """Execute kubectl and return parsed JSON."""
    cmd = ["kubectl"] + args_list + ["-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def audit_cluster_roles():
    """Audit ClusterRoles for dangerous permissions."""
    findings = []
    data = run_kubectl(["get", "clusterroles"])
    if not data:
        return findings

    dangerous_verbs = {"*", "create", "update", "patch", "delete"}
    dangerous_resources = {"secrets", "pods/exec", "clusterroles", "clusterrolebindings",
                           "roles", "rolebindings", "serviceaccounts", "nodes"}
    escalation_resources = {"clusterroles", "clusterrolebindings", "roles", "rolebindings"}

    for role in data.get("items", []):
        name = role.get("metadata", {}).get("name", "")
        if name.startswith("system:"):
            continue  # Skip system roles

        for rule in role.get("rules", []):
            verbs = set(rule.get("verbs", []))
            resources = set(rule.get("resources", []))
            api_groups = rule.get("apiGroups", [])

            # Wildcard everything
            if "*" in verbs and "*" in resources:
                findings.append({
                    "type": "wildcard_all", "role": name, "kind": "ClusterRole",
                    "severity": "CRITICAL",
                    "detail": "Full wildcard access (verbs: *, resources: *)",
                    "recommendation": "Replace with specific verbs and resources",
                })

            # Secrets access
            if resources & {"secrets", "*"} and verbs & {"get", "list", "watch", "*"}:
                findings.append({
                    "type": "secrets_access", "role": name, "kind": "ClusterRole",
                    "severity": "HIGH",
                    "detail": f"Can read secrets (verbs: {verbs & {'get', 'list', 'watch', '*'}})",
                })

            # Pod exec
            if "pods/exec" in resources or ("pods" in resources and "create" in verbs):
                findings.append({
                    "type": "pod_exec", "role": name, "kind": "ClusterRole",
                    "severity": "HIGH",
                    "detail": "Can exec into pods (container escape risk)",
                })

            # Privilege escalation via RBAC modification
            if resources & escalation_resources and verbs & {"create", "update", "patch", "*"}:
                findings.append({
                    "type": "rbac_escalation", "role": name, "kind": "ClusterRole",
                    "severity": "CRITICAL",
                    "detail": f"Can modify RBAC resources: {resources & escalation_resources}",
                })

            # Node access
            if "nodes" in resources and verbs & {"get", "list", "proxy", "*"}:
                findings.append({
                    "type": "node_access", "role": name, "kind": "ClusterRole",
                    "severity": "MEDIUM",
                    "detail": "Can access node resources",
                })

    return findings


def audit_cluster_role_bindings():
    """Audit ClusterRoleBindings for overly broad subject assignments."""
    findings = []
    data = run_kubectl(["get", "clusterrolebindings"])
    if not data:
        return findings

    for binding in data.get("items", []):
        name = binding.get("metadata", {}).get("name", "")
        if name.startswith("system:"):
            continue

        role_ref = binding.get("roleRef", {})
        role_name = role_ref.get("name", "")
        subjects = binding.get("subjects", [])

        for subject in subjects:
            kind = subject.get("kind", "")
            subj_name = subject.get("name", "")
            namespace = subject.get("namespace", "")

            # Cluster-admin binding
            if role_name == "cluster-admin":
                findings.append({
                    "type": "cluster_admin_binding",
                    "binding": name, "subject": f"{kind}/{subj_name}",
                    "severity": "CRITICAL",
                    "detail": f"cluster-admin bound to {kind} '{subj_name}'",
                })

            # Group bindings to all authenticated/unauthenticated
            if kind == "Group" and subj_name in ("system:authenticated", "system:unauthenticated"):
                findings.append({
                    "type": "broad_group_binding",
                    "binding": name, "subject": subj_name,
                    "severity": "CRITICAL" if subj_name == "system:unauthenticated" else "HIGH",
                    "detail": f"Role '{role_name}' bound to group '{subj_name}'",
                })

            # Default service account bindings
            if kind == "ServiceAccount" and subj_name == "default":
                findings.append({
                    "type": "default_sa_binding",
                    "binding": name, "subject": f"default SA in {namespace}",
                    "severity": "MEDIUM",
                    "detail": f"Role '{role_name}' bound to default service account",
                })

    return findings


def audit_service_accounts(namespace=None):
    """Audit service accounts for misconfigurations."""
    findings = []
    cmd = ["get", "serviceaccounts", "--all-namespaces"] if not namespace else ["get", "serviceaccounts", "-n", namespace]
    data = run_kubectl(cmd)
    if not data:
        return findings

    for sa in data.get("items", []):
        name = sa.get("metadata", {}).get("name", "")
        ns = sa.get("metadata", {}).get("namespace", "")
        automount = sa.get("automountServiceAccountToken", None)

        if name == "default" and automount is not False:
            findings.append({
                "type": "default_sa_automount",
                "namespace": ns, "service_account": name,
                "severity": "MEDIUM",
                "detail": f"Default SA in '{ns}' has automountServiceAccountToken enabled",
                "recommendation": "Set automountServiceAccountToken: false on default SA",
            })

        secrets = sa.get("secrets", [])
        if len(secrets) > 1:
            findings.append({
                "type": "sa_multiple_secrets",
                "namespace": ns, "service_account": name,
                "severity": "LOW",
                "detail": f"SA has {len(secrets)} token secrets",
            })

    return findings


def format_summary(role_findings, binding_findings, sa_findings):
    """Print RBAC audit summary."""
    all_findings = role_findings + binding_findings + sa_findings
    print(f"\n{'='*60}")
    print(f"  Kubernetes RBAC Hardening Audit")
    print(f"{'='*60}")
    print(f"  ClusterRole Issues    : {len(role_findings)}")
    print(f"  Binding Issues        : {len(binding_findings)}")
    print(f"  ServiceAccount Issues : {len(sa_findings)}")
    print(f"  Total Findings        : {len(all_findings)}")

    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"\n  By Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        if count:
            print(f"    {sev:10s}: {count}")

    if all_findings:
        print(f"\n  Top Findings:")
        for f in sorted(all_findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 9))[:15]:
            print(f"    [{f['severity']:8s}] {f['type']:25s} | {f.get('detail', '')[:50]}")

    return severity_counts


def generate_remediation_manifests(role_findings, binding_findings):
    """Generate YAML manifests to remediate RBAC findings."""
    manifests = []

    for f in role_findings:
        if f.get("type") == "wildcard_all":
            manifests.append({
                "finding": f,
                "action": "review_and_replace",
                "manifest": f"""# REMEDIATION: Replace wildcard ClusterRole '{f['role']}'
# Review what this role actually needs and replace wildcards with specific verbs/resources.
# Example least-privilege replacement:
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {f['role']}-hardened
rules:
- apiGroups: [""]
  resources: ["pods", "services"]   # Replace with actual resources needed
  verbs: ["get", "list", "watch"]   # Replace with actual verbs needed
""",
                "command": f"kubectl edit clusterrole {f['role']}",
            })

    for f in binding_findings:
        if f.get("type") == "cluster_admin_binding":
            subject = f.get("subject", {})
            manifests.append({
                "finding": f,
                "action": "remove_cluster_admin",
                "manifest": f"""# REMEDIATION: Remove cluster-admin from {subject.get('name', 'unknown')}
# Replace with a scoped role that grants only what is needed.
# To remove the binding:
# kubectl delete clusterrolebinding {f['binding']}
""",
                "command": f"kubectl delete clusterrolebinding {f['binding']}",
            })

    return manifests


def apply_remediation(manifests, dry_run=True):
    """Apply generated remediation commands."""
    results = []
    for item in manifests:
        cmd_str = item.get("command", "")
        if not cmd_str:
            continue
        parts = cmd_str.split()
        if dry_run:
            # Only run read-only equivalent
            results.append({"command": cmd_str, "dry_run": True,
                            "note": "Review manifest above and run command manually to apply"})
        else:
            result = subprocess.run(parts, capture_output=True, text=True, timeout=30)
            results.append({
                "command": cmd_str,
                "dry_run": False,
                "success": result.returncode == 0,
                "output": result.stdout.strip() or result.stderr.strip(),
            })
    return results


def main():
    parser = argparse.ArgumentParser(description="Kubernetes RBAC hardening audit and remediation agent")
    parser.add_argument("--namespace", "-n", help="Specific namespace to audit")
    parser.add_argument("--kubeconfig", help="Path to kubeconfig")
    parser.add_argument("--skip-roles", action="store_true")
    parser.add_argument("--skip-bindings", action="store_true")
    parser.add_argument("--skip-sa", action="store_true")
    parser.add_argument("--output", "-o", default="rbac_report.json", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--apply", action="store_true",
                        help="Generate and optionally apply remediation manifests")
    parser.add_argument("--no-dry-run", dest="dry_run", action="store_false",
                        help="Actually apply remediation (default: dry-run only)")
    parser.set_defaults(dry_run=True)
    args = parser.parse_args()

    if args.kubeconfig:
        os.environ["KUBECONFIG"] = args.kubeconfig

    role_findings = [] if args.skip_roles else audit_cluster_roles()
    binding_findings = [] if args.skip_bindings else audit_cluster_role_bindings()
    sa_findings = [] if args.skip_sa else audit_service_accounts(args.namespace)

    severity_counts = format_summary(role_findings, binding_findings, sa_findings)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "K8s RBAC Audit",
        "role_findings": role_findings,
        "binding_findings": binding_findings,
        "sa_findings": sa_findings,
        "severity_counts": severity_counts,
        "risk_level": (
            "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "MEDIUM" if severity_counts.get("MEDIUM", 0) > 0
            else "LOW"
        ),
    }

    if args.apply:
        manifests = generate_remediation_manifests(role_findings, binding_findings)
        report["remediation_manifests"] = manifests
        if manifests:
            print(f"\n[+] Generated {len(manifests)} remediation manifests")
            for m in manifests:
                print(f"\n{'='*60}")
                print(m["manifest"])
            apply_results = apply_remediation(manifests, dry_run=args.dry_run)
            report["apply_results"] = apply_results
            mode = "DRY RUN" if args.dry_run else "APPLIED"
            print(f"\n[{mode}] {len(apply_results)} remediation actions")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Report saved to {args.output}")

    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)
    if critical > 0 or high > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
