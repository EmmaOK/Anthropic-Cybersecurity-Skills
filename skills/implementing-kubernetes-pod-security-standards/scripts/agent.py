#!/usr/bin/env python3
"""Agent for auditing and implementing Kubernetes Pod Security Standards enforcement."""

import json
import argparse
import subprocess
import sys
from datetime import datetime
from collections import Counter


PSS_LEVELS = {
    "privileged": {"order": 0, "description": "Unrestricted, for system workloads"},
    "baseline": {"order": 1, "description": "Minimally restrictive, prevents known escalations"},
    "restricted": {"order": 2, "description": "Heavily restricted, hardened best practices"},
}

BASELINE_VIOLATIONS = [
    "hostNetwork", "hostPID", "hostIPC", "hostPorts",
    "privileged", "allowPrivilegeEscalation",
    "capabilities.add (non-default)", "seccomp (unconfined)",
]

RESTRICTED_VIOLATIONS = BASELINE_VIOLATIONS + [
    "runAsNonRoot not set", "runAsUser=0",
    "seccompProfile not RuntimeDefault/Localhost",
    "capabilities.drop not ALL", "readOnlyRootFilesystem not set",
]


def kubectl_json(args_list):
    """Run kubectl and return JSON."""
    cmd = ["kubectl"] + args_list + ["-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        return {"error": result.stderr.strip()}
    return json.loads(result.stdout) if result.stdout.strip() else {}


def audit_namespace_labels():
    """Audit PSA labels on all namespaces."""
    ns_data = kubectl_json(["get", "namespaces"])
    if "error" in ns_data:
        return ns_data
    results = []
    for ns in ns_data.get("items", []):
        name = ns["metadata"]["name"]
        labels = ns["metadata"].get("labels", {})
        enforce = labels.get("pod-security.kubernetes.io/enforce", "")
        audit = labels.get("pod-security.kubernetes.io/audit", "")
        warn = labels.get("pod-security.kubernetes.io/warn", "")
        system = name in ("kube-system", "kube-public", "kube-node-lease")
        results.append({
            "namespace": name, "system": system,
            "enforce": enforce, "audit": audit, "warn": warn,
            "protected": bool(enforce),
            "severity": "INFO" if enforce or system else "HIGH",
        })
    return results


def audit_pod_security(pods_path):
    """Audit pods against Pod Security Standards."""
    with open(pods_path) as f:
        data = json.load(f)
    pods = data if isinstance(data, list) else data.get("items", [])
    findings = []

    for pod in pods:
        metadata = pod.get("metadata", {})
        spec = pod.get("spec", {})
        pod_name = metadata.get("name", "")
        ns = metadata.get("namespace", "default")

        if spec.get("hostNetwork"):
            findings.append({"pod": pod_name, "ns": ns, "violation": "hostNetwork",
                             "level": "baseline", "severity": "HIGH"})
        if spec.get("hostPID"):
            findings.append({"pod": pod_name, "ns": ns, "violation": "hostPID",
                             "level": "baseline", "severity": "HIGH"})

        for container in spec.get("containers", []) + spec.get("initContainers", []):
            sc = container.get("securityContext", {})
            c_name = container.get("name", "")

            if sc.get("privileged"):
                findings.append({"pod": pod_name, "container": c_name, "ns": ns,
                                 "violation": "privileged", "level": "baseline",
                                 "severity": "CRITICAL"})

            if sc.get("allowPrivilegeEscalation", True):
                findings.append({"pod": pod_name, "container": c_name, "ns": ns,
                                 "violation": "allowPrivilegeEscalation",
                                 "level": "restricted", "severity": "MEDIUM"})

            if not sc.get("runAsNonRoot"):
                findings.append({"pod": pod_name, "container": c_name, "ns": ns,
                                 "violation": "runAsNonRoot not set",
                                 "level": "restricted", "severity": "MEDIUM"})

            caps = sc.get("capabilities", {})
            added = caps.get("add", [])
            if added and any(c not in ("NET_BIND_SERVICE",) for c in added):
                findings.append({"pod": pod_name, "container": c_name, "ns": ns,
                                 "violation": f"capabilities.add: {added}",
                                 "level": "baseline", "severity": "HIGH"})

            dropped = caps.get("drop", [])
            if "ALL" not in dropped:
                findings.append({"pod": pod_name, "container": c_name, "ns": ns,
                                 "violation": "capabilities.drop not ALL",
                                 "level": "restricted", "severity": "MEDIUM"})

    return findings


def generate_namespace_labels(namespace, level="restricted"):
    """Generate PSA label patch for a namespace."""
    labels = {
        f"pod-security.kubernetes.io/enforce": level,
        f"pod-security.kubernetes.io/audit": level,
        f"pod-security.kubernetes.io/warn": level,
    }
    return {
        "command": f'kubectl label namespace {namespace} '
                   f'pod-security.kubernetes.io/enforce={level} '
                   f'pod-security.kubernetes.io/audit={level} '
                   f'pod-security.kubernetes.io/warn={level} --overwrite',
        "labels": labels,
    }


def generate_compliance_report(findings):
    """Generate PSS compliance summary."""
    by_level = Counter(f.get("level", "unknown") for f in findings)
    by_severity = Counter(f.get("severity", "unknown") for f in findings)
    by_violation = Counter(f.get("violation", "unknown") for f in findings)
    return {
        "total_violations": len(findings),
        "by_level": dict(by_level),
        "by_severity": dict(by_severity),
        "top_violations": dict(by_violation.most_common(10)),
        "baseline_violations": by_level.get("baseline", 0),
        "restricted_violations": by_level.get("restricted", 0),
    }


def apply_namespace_labels(namespace, level="restricted", dry_run=True):
    """Apply PSS labels to a namespace via kubectl label."""
    cmd = [
        "kubectl", "label", "namespace", namespace,
        f"pod-security.kubernetes.io/enforce={level}",
        f"pod-security.kubernetes.io/audit={level}",
        f"pod-security.kubernetes.io/warn={level}",
        "--overwrite",
    ]
    if dry_run:
        cmd += ["--dry-run=client"]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return {
        "namespace": namespace,
        "level": level,
        "dry_run": dry_run,
        "success": result.returncode == 0,
        "output": result.stdout.strip() or result.stderr.strip(),
    }


def apply_all_unprotected(ns_audit, level="baseline", dry_run=True, skip_system=True):
    """Apply PSS labels to all unprotected namespaces."""
    results = []
    for ns in ns_audit:
        if ns.get("protected"):
            continue
        if skip_system and ns.get("system"):
            continue
        results.append(apply_namespace_labels(ns["namespace"], level, dry_run))
    return results


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Pod Security Standards Agent")
    parser.add_argument("--pods", help="Pods JSON to audit")
    parser.add_argument("--namespace", help="Specific namespace to label (or 'all' for all unprotected)")
    parser.add_argument("--level", choices=["privileged", "baseline", "restricted"],
                        default="baseline")
    parser.add_argument("--action", choices=["audit-ns", "audit-pods", "generate", "full"],
                        default="full")
    parser.add_argument("--apply", action="store_true",
                        help="Apply PSS labels to unprotected namespaces (requires kubectl access)")
    parser.add_argument("--dry-run", action="store_true", default=True,
                        help="Simulate apply without making changes (default: true)")
    parser.add_argument("--no-dry-run", dest="dry_run", action="store_false",
                        help="Actually apply changes to the cluster")
    parser.add_argument("--output", default="pss_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}
    exit_code = 0

    if args.action in ("audit-ns", "full"):
        ns_audit = audit_namespace_labels()
        report["results"]["namespace_audit"] = ns_audit
        if isinstance(ns_audit, list):
            unprotected = [n for n in ns_audit if not n["protected"] and not n["system"]]
            print(f"[+] Namespaces: {len(unprotected)} unprotected (non-system)")
            if unprotected:
                exit_code = 1
                for ns in unprotected:
                    print(f"    ✗ {ns['namespace']} — no PSS enforce label")

            if args.apply:
                dry_run = args.dry_run
                mode = "DRY RUN" if dry_run else "APPLYING"
                print(f"\n[{mode}] Setting level={args.level} on {len(unprotected)} namespaces")
                if args.namespace and args.namespace != "all":
                    apply_results = [apply_namespace_labels(args.namespace, args.level, dry_run)]
                else:
                    apply_results = apply_all_unprotected(ns_audit, args.level, dry_run)
                report["results"]["apply_results"] = apply_results
                for r in apply_results:
                    status = "✓" if r["success"] else "✗"
                    print(f"    {status} {r['namespace']} → {r['level']} {'(dry-run)' if dry_run else '(applied)'}")

    if args.action in ("audit-pods", "full") and args.pods:
        findings = audit_pod_security(args.pods)
        summary = generate_compliance_report(findings)
        report["results"]["pod_audit"] = findings
        report["results"]["summary"] = summary
        print(f"[+] Pod violations: {summary['total_violations']}")
        if summary["total_violations"]:
            exit_code = 1

    if args.action in ("generate", "full") and args.namespace and not args.apply:
        labels = generate_namespace_labels(args.namespace, args.level)
        report["results"]["generated"] = labels
        print(f"[+] Remediation command for {args.namespace}:\n    {labels['command']}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[+] Report saved to {args.output}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
