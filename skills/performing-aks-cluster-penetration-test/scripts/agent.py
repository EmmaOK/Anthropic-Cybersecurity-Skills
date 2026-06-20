#!/usr/bin/env python3
"""
AKS Cluster Penetration Test Agent
Performs authorized security assessment of Azure Kubernetes Service clusters
against kubectl JSON exports or a live cluster.

Subcommands:
  collect          Print kubectl collection commands to run on the cluster
  audit            Run all audit modules against a directory of kubectl JSON exports
  audit-rbac       RBAC privilege escalation analysis only
  audit-secrets    Credential and secret exposure analysis only
  audit-network    Network segmentation analysis only
  audit-pods       Pod and container security analysis only
  audit-components Component CVE correlation only
  kill-chain       Synthesize findings into an end-to-end attack chain
  report           Format findings as markdown or JSON report

Usage:
  python3 agent.py collect [--namespace NS] [--output-dir DIR]
  python3 agent.py audit --dir EXPORTS_DIR [--namespace NS] [--output FILE]
  python3 agent.py audit-rbac --dir EXPORTS_DIR
  python3 agent.py audit-secrets --dir EXPORTS_DIR
  python3 agent.py audit-network --dir EXPORTS_DIR
  python3 agent.py audit-pods --dir EXPORTS_DIR
  python3 agent.py audit-components --dir EXPORTS_DIR
  python3 agent.py kill-chain --findings FILE [--web-findings FILE]
  python3 agent.py report --findings FILE [--format md|json] [--output FILE]

No external dependencies. Python 3.8+ stdlib only.
"""

import argparse
import base64
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# CVE database for known vulnerable component versions
# ---------------------------------------------------------------------------
CVE_DB = [
    {
        "component": "argo-workflows",
        "image_patterns": ["argoproj/argocli", "argoproj/workflow-controller", "argocli"],
        "cve": "CVE-2024-53862",
        "cvss": 7.5,
        "severity": "HIGH",
        "description": "Authentication bypass on archived workflow endpoint — forged token accepted",
        "affected_below": (3, 5, 13),
        "fixed_in": "v3.5.13 / v3.6.2",
        "epss": 0.0033,
    },
    {
        "component": "kafka-ui",
        "image_patterns": ["provectuslabs/kafka-ui"],
        "cve": "CVE-2023-52251",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "description": "Remote code execution via Groovy script execution in the UI",
        "affected_below": (0, 7, 2),
        "fixed_in": "v0.7.2",
        "epss": 0.9401,
    },
    {
        "component": "kafka-ui",
        "image_patterns": ["provectuslabs/kafka-ui"],
        "cve": "CVE-2024-32030",
        "cvss": 7.5,
        "severity": "HIGH",
        "description": "RMI deserialization leading to remote code execution",
        "affected_below": (0, 7, 2),
        "fixed_in": "v0.7.2",
        "epss": 0.8172,
    },
    {
        "component": "ingress-nginx",
        "image_patterns": ["ingress-nginx/controller", "nginx-ingress-controller"],
        "cve": "CVE-2024-7646",
        "cvss": 8.8,
        "severity": "HIGH",
        "description": "Annotation injection allowing arbitrary nginx config and potential cluster secret disclosure",
        "affected_below": (1, 9, 6),
        "fixed_in": "v1.9.6",
        "epss": 0.0041,
    },
]

# Credential patterns to flag in env vars and secret keys
CREDENTIAL_PATTERNS = re.compile(
    r"(password|passwd|secret|_key|api_key|token|credential|auth|access_key|private_key|"
    r"client_secret|admin_pass|bootstrap|storage_key|connection_string)",
    re.IGNORECASE,
)

# Placeholder / weak values that indicate the credential was never properly set
WEAK_VALUES = {
    "password", "Password", "PASSWORD",
    "secret", "Secret", "SECRET",
    "admin", "Admin", "ADMIN",
    "test", "Test", "TEST",
    "changeme", "ChangeMe",
    "default", "Default",
    "123456", "12345678",
    "metacell", "Metacell",
}

# Django insecure key prefix
DJANGO_INSECURE_PREFIX = "django-insecure-"

# Dangerous RBAC roles (name → severity)
DANGEROUS_ROLES = {
    "cluster-admin": "CRITICAL",
    "admin": "HIGH",
    "edit": "MEDIUM",
}

# Dangerous hostPath mounts
DANGEROUS_HOST_PATHS = ["/", "/etc", "/proc", "/sys", "/root", "/var/run/docker.sock",
                         "/run/containerd", "/var/lib/kubelet"]

SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_json(path: Path) -> dict | None:
    """Load a kubectl JSON export, handling UTF-16 BOM from Windows PowerShell."""
    if not path.exists():
        return None
    raw = path.read_bytes()
    # Detect UTF-16 BOM (FF FE or FE FF)
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    elif raw[:3] == b"\xef\xbb\xbf":
        text = raw.decode("utf-8-sig")
    else:
        text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        print(f"  [WARN] Failed to parse {path.name}: {e}", file=sys.stderr)
        return None


def load_exports(exports_dir: str, namespace_filter: str | None = None) -> dict:
    """Load all kubectl JSON exports from a directory."""
    d = Path(exports_dir)
    files = {
        "pods": None, "deployments": None, "crb": None, "cr": None,
        "rb": None, "sa": None, "secrets": None, "netpol": None,
        "namespaces": None, "services": None, "configmaps": None, "ingress": None,
    }
    # Try both raw and _clean suffix variants
    name_map = {
        "pods": ["aks_pods", "aks_pods_clean"],
        "deployments": ["aks_deployments", "aks_deployments_clean"],
        "crb": ["aks_crb", "aks_crb_clean"],
        "cr": ["aks_cr", "aks_cr_clean"],
        "rb": ["aks_rb", "aks_rb_clean"],
        "sa": ["aks_sa", "aks_sa_clean"],
        "secrets": ["aks_secrets", "aks_secrets_clean"],
        "netpol": ["aks_netpol", "aks_netpol_clean"],
        "namespaces": ["aks_namespaces", "aks_namespaces_clean"],
        "services": ["aks_services", "aks_services_clean"],
        "configmaps": ["aks_configmaps", "aks_configmaps_clean"],
        "ingress": ["aks_ingress", "aks_ingress_clean"],
    }
    for key, candidates in name_map.items():
        for candidate in candidates:
            p = d / f"{candidate}.json"
            if p.exists():
                files[key] = load_json(p)
                break

    if namespace_filter:
        for key in ["pods", "deployments", "rb", "sa", "secrets", "netpol",
                    "services", "configmaps", "ingress"]:
            if files[key] and "items" in files[key]:
                files[key]["items"] = [
                    i for i in files[key]["items"]
                    if i.get("metadata", {}).get("namespace") == namespace_filter
                ]
    return files


def severity_color(severity: str) -> str:
    colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}
    return colors.get(severity, "⚪")


def finding(fid, severity, cvss, title, description, evidence, remediation,
            mitre=None, cwe=None, references=None) -> dict:
    return {
        "id": fid,
        "severity": severity,
        "cvss": cvss,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "mitre": mitre or [],
        "cwe": cwe or [],
        "references": references or [],
    }


# ---------------------------------------------------------------------------
# collect subcommand
# ---------------------------------------------------------------------------

def cmd_collect(args):
    ns = f"-n {args.namespace}" if args.namespace else "-A"
    out = args.output_dir or "/tmp/aks_audit"

    print("=" * 70)
    print("AKS PENETRATION TEST — COLLECTION COMMANDS")
    print("Run these commands on a system with kubectl access to the cluster.")
    print(f"Output directory: {out}")
    print("=" * 70)

    commands = [
        ("Pods (all namespaces)", f"kubectl get pods {ns} -o json > {out}/aks_pods.json"),
        ("Deployments", f"kubectl get deployments {ns} -o json > {out}/aks_deployments.json"),
        ("StatefulSets", f"kubectl get statefulsets {ns} -o json > {out}/aks_statefulsets.json"),
        ("ClusterRoleBindings", f"kubectl get clusterrolebindings -o json > {out}/aks_crb.json"),
        ("ClusterRoles", f"kubectl get clusterroles -o json > {out}/aks_cr.json"),
        ("RoleBindings", f"kubectl get rolebindings {ns} -o json > {out}/aks_rb.json"),
        ("ServiceAccounts", f"kubectl get serviceaccounts {ns} -o json > {out}/aks_sa.json"),
        ("Secrets", f"kubectl get secrets {ns} -o json > {out}/aks_secrets.json"),
        ("NetworkPolicies", f"kubectl get networkpolicies {ns} -o json > {out}/aks_netpol.json"),
        ("Namespaces", f"kubectl get namespaces -o json > {out}/aks_namespaces.json"),
        ("Services", f"kubectl get services {ns} -o json > {out}/aks_services.json"),
        ("ConfigMaps", f"kubectl get configmaps {ns} -o json > {out}/aks_configmaps.json"),
        ("Ingress", f"kubectl get ingress {ns} -o json > {out}/aks_ingress.json"),
        ("Privileged pods", f"kubectl get pods {ns} -o json | python3 -c \""
            "import json,sys\n[print(p['metadata']['namespace']+'/'+p['metadata']['name']+'/'+c['name']+': PRIVILEGED')"
            " for p in json.load(sys.stdin)['items']"
            " for c in p['spec'].get('containers',[])"
            " if c.get('securityContext',{}).get('privileged')]\" > {out}/aks_priv_pods.txt"),
        ("Kube-system pods", f"kubectl get pods -n kube-system -o wide > {out}/aks_kube_system_pods.txt"),
    ]

    print(f"\nmkdir -p {out}\n")
    for label, cmd in commands:
        print(f"# {label}")
        print(cmd)
        print()

    print("# Bundle for transfer (if needed):")
    print(f"tar -czf aks_audit_dump.tar.gz -C $(dirname {out}) $(basename {out})")
    print()
    print("# If files are UTF-16 (Windows/PowerShell), convert before analysis:")
    print(f"python3 -c \"")
    print(f"import os, glob")
    print(f"for f in glob.glob('{out}/*.json'):")
    print(f"    raw = open(f,'rb').read()")
    print(f"    if raw[:2] in (b'\\xff\\xfe', b'\\xfe\\xff'):")
    print(f"        text = raw.decode('utf-16')")
    print(f"        out_f = f.replace('.json','_clean.json')")
    print(f"        open(out_f,'w').write(text)")
    print(f"        print(f'Converted: {{out_f}}')")
    print("\"")


# ---------------------------------------------------------------------------
# audit-rbac
# ---------------------------------------------------------------------------

def audit_rbac(data: dict) -> list:
    findings = []
    crb_data = data.get("crb") or {}
    cr_data = data.get("cr") or {}
    pods_data = data.get("pods") or {}

    # Build a map of role name → rules for custom role analysis
    role_rules = {}
    for role in (cr_data.get("items") or []):
        role_rules[role["metadata"]["name"]] = role.get("rules", [])

    dangerous_bindings = []
    for item in (crb_data.get("items") or []):
        role_name = item.get("roleRef", {}).get("name", "")
        binding_name = item["metadata"]["name"]
        subjects = item.get("subjects") or []

        if role_name in DANGEROUS_ROLES:
            sev = DANGEROUS_ROLES[role_name]
            for subj in subjects:
                dangerous_bindings.append({
                    "binding": binding_name,
                    "role": role_name,
                    "severity": sev,
                    "subject_kind": subj.get("kind"),
                    "subject_name": subj.get("name"),
                    "subject_namespace": subj.get("namespace", ""),
                })

    # Group by role for reporting
    cluster_admin_bindings = [b for b in dangerous_bindings if b["role"] == "cluster-admin"]

    if cluster_admin_bindings:
        default_sa_bindings = [b for b in cluster_admin_bindings
                                if b["subject_name"] == "default" and b["subject_kind"] == "ServiceAccount"]

        if default_sa_bindings:
            # Find which pods are affected
            affected_pods = []
            for pod in (pods_data.get("items") or []):
                ns = pod["metadata"]["namespace"]
                if ns in SYSTEM_NAMESPACES:
                    continue
                sa = pod["spec"].get("serviceAccountName", "default")
                if sa == "default":
                    affected_pods.append(f"{ns}/{pod['metadata']['name']}")

            # Also check automountServiceAccountToken
            auto_mount_pods = []
            for pod in (pods_data.get("items") or []):
                if pod["metadata"]["namespace"] in SYSTEM_NAMESPACES:
                    continue
                if pod["spec"].get("automountServiceAccountToken", True):
                    auto_mount_pods.append(f"{pod['metadata']['namespace']}/{pod['metadata']['name']}")

            binding_names = [b["binding"] for b in default_sa_bindings]
            ns_list = list({b["subject_namespace"] for b in default_sa_bindings})

            findings.append(finding(
                fid="AKSPT-001",
                severity="CRITICAL",
                cvss=9.8,
                title=f"default Service Account bound to cluster-admin — {len(affected_pods)} pods inherit full cluster control",
                description=(
                    f"The default service account in namespace(s) {ns_list} is bound to cluster-admin "
                    f"via ClusterRoleBinding(s): {binding_names}. In Kubernetes, any pod that does not "
                    f"explicitly declare serviceAccountName automatically uses the default service account. "
                    f"{len(affected_pods)} application pods inherit cluster-admin. Kubernetes automounts "
                    f"the service account token at /var/run/secrets/kubernetes.io/serviceaccount/token — "
                    f"any code execution inside these pods immediately yields full cluster control."
                ),
                evidence={
                    "bindings": binding_names,
                    "affected_pods": affected_pods,
                    "auto_mount_pods": len(auto_mount_pods),
                },
                remediation=(
                    f"IMMEDIATE (zero downtime): kubectl delete clusterrolebinding {' '.join(binding_names)}\n"
                    "Then create a namespace-scoped Role with only the permissions the workload needs.\n"
                    "Set automountServiceAccountToken: false on all pods that don't call the K8s API.\n"
                    "Assign explicit named service accounts to every Deployment."
                ),
                mitre=["T1548.005"],
                cwe=["CWE-269"],
            ))

        # Non-default SA with cluster-admin
        non_default = [b for b in cluster_admin_bindings
                       if not (b["subject_name"] == "default" and b["subject_kind"] == "ServiceAccount")]
        for b in non_default:
            findings.append(finding(
                fid=f"AKSPT-001b",
                severity="CRITICAL",
                cvss=9.1,
                title=f"{b['subject_kind']}/{b['subject_name']} bound to cluster-admin via {b['binding']}",
                description=(
                    f"Service account {b['subject_namespace']}/{b['subject_name']} has cluster-admin "
                    f"via {b['binding']}. Any workload running as this service account has unrestricted "
                    f"cluster access. If this is a workflow engine (e.g., Argo), any submitted workflow "
                    f"step inherits these privileges."
                ),
                evidence={"binding": b["binding"], "subject": f"{b['subject_namespace']}/{b['subject_name']}"},
                remediation=(
                    f"kubectl delete clusterrolebinding {b['binding']}\n"
                    "Create a namespace-scoped Role with only the resources the workload requires."
                ),
                mitre=["T1548.005", "T1610"],
                cwe=["CWE-269"],
            ))

    # Wildcard permissions in custom roles
    wildcard_roles = []
    for role_name, rules in role_rules.items():
        if role_name.startswith("system:"):
            continue
        for rule in rules:
            verbs = rule.get("verbs", [])
            resources = rule.get("resources", [])
            if "*" in verbs or "*" in resources:
                wildcard_roles.append({"role": role_name, "verbs": verbs, "resources": resources})

    if wildcard_roles:
        findings.append(finding(
            fid="AKSPT-002",
            severity="HIGH",
            cvss=8.0,
            title=f"Wildcard permissions in {len(wildcard_roles)} custom ClusterRole(s)",
            description=(
                f"{len(wildcard_roles)} custom ClusterRole(s) use wildcard (*) verbs or resources, "
                "granting broader access than intended. Wildcard roles violate the principle of "
                "least privilege and may grant unintended capabilities as new resource types are added."
            ),
            evidence={"wildcard_roles": wildcard_roles},
            remediation=(
                "Replace wildcard rules with explicit verb+resource combinations. "
                "Use kubectl auth can-i --list --as system:serviceaccount:<ns>:<sa> to enumerate "
                "effective permissions and reduce to the minimum required set."
            ),
            mitre=["T1548.005"],
            cwe=["CWE-732"],
        ))

    return findings


# ---------------------------------------------------------------------------
# audit-secrets
# ---------------------------------------------------------------------------

def audit_secrets(data: dict) -> list:
    findings = []
    pods_data = data.get("pods") or {}
    secrets_data = data.get("secrets") or {}

    # Plaintext credentials in pod env vars
    plaintext_creds = []
    shared_values = defaultdict(list)

    for pod in (pods_data.get("items") or []):
        ns = pod["metadata"]["namespace"]
        pname = pod["metadata"]["name"]
        for c in pod["spec"].get("containers", []):
            cname = c["name"]
            for e in c.get("env", []):
                var_name = e.get("name", "")
                if not CREDENTIAL_PATTERNS.search(var_name):
                    continue
                if "value" not in e:
                    continue  # valueFrom is fine — it's from a Secret/ConfigMap
                val = e["value"]

                # Check for weak/placeholder values
                weak = val in WEAK_VALUES or val.startswith(DJANGO_INSECURE_PREFIX)
                location = f"{ns}/{pname}/{cname}"
                plaintext_creds.append({
                    "location": location,
                    "var": var_name,
                    "value_preview": val[:60],
                    "is_weak": weak,
                    "is_placeholder": val.startswith(DJANGO_INSECURE_PREFIX),
                })
                # Track for shared-secret detection
                if len(val) > 8:
                    shared_values[val].append(f"{location}.{var_name}")

    if plaintext_creds:
        critical = [c for c in plaintext_creds if c["is_weak"] or c["is_placeholder"]]
        findings.append(finding(
            fid="AKSPT-003",
            severity="CRITICAL" if critical else "HIGH",
            cvss=9.1 if critical else 8.1,
            title=f"{len(plaintext_creds)} plaintext credential(s) in pod environment variables",
            description=(
                f"{len(plaintext_creds)} sensitive environment variables contain plaintext values "
                f"directly in the pod spec (not via secretKeyRef/valueFrom). "
                f"{len(critical)} are weak or placeholder values. "
                "Pod environment variables are visible to any user with kubectl describe pod access "
                "and to any process running inside the container."
            ),
            evidence={"plaintext_credentials": plaintext_creds},
            remediation=(
                "Move all credentials to Azure Key Vault and inject via Secrets Store CSI driver.\n"
                "Replace env.value with env.valueFrom.secretKeyRef.\n"
                "Immediately rotate any credentials that have been exposed — treat them as compromised.\n"
                "For Django: generate a production SECRET_KEY: python3 -c \"import secrets; print(secrets.token_urlsafe(50))\""
            ),
            mitre=["T1552.007"],
            cwe=["CWE-798", "CWE-312"],
        ))

    # Shared secrets across multiple services
    shared = {val: locs for val, locs in shared_values.items() if len(locs) > 1}
    if shared:
        findings.append(finding(
            fid="AKSPT-004",
            severity="HIGH",
            cvss=7.8,
            title=f"Shared credential value used across {len(shared)} service(s)",
            description=(
                f"{len(shared)} distinct credential values each appear in multiple pod environments. "
                "A single shared secret means Keycloak/the IdP cannot distinguish which service is "
                "making an API call. Compromising one service exposes credentials for all services "
                "that share the same value simultaneously."
            ),
            evidence={"shared_credentials": {v[:20] + "...": locs for v, locs in shared.items()}},
            remediation=(
                "Register a unique OAuth client in the IdP for each backend service.\n"
                "Issue a unique client_secret per service and store in Azure Key Vault.\n"
                "Rotate the shared credential after unique secrets are in place."
            ),
            mitre=["T1552.007"],
            cwe=["CWE-798"],
        ))

    # High-value keys in Kubernetes Secrets
    high_value_secrets = []
    storage_key_pattern = re.compile(r"(storage.*key|account.*key|azure.*key|blob.*key)", re.IGNORECASE)
    for s in (secrets_data.get("items") or []):
        ns = s["metadata"]["namespace"]
        sname = s["metadata"]["name"]
        for k, v in (s.get("data") or {}).items():
            if storage_key_pattern.search(k) or storage_key_pattern.search(sname):
                try:
                    decoded = base64.b64decode(v).decode(errors="ignore")
                    if len(decoded) > 30:  # looks like a real key
                        high_value_secrets.append({
                            "location": f"{ns}/{sname}",
                            "key": k,
                            "length": len(decoded),
                            "preview": decoded[:20] + "...",
                        })
                except Exception:
                    pass

    if high_value_secrets:
        findings.append(finding(
            fid="AKSPT-005",
            severity="HIGH",
            cvss=8.1,
            title=f"Azure Storage Account key or high-value cloud credential in Kubernetes Secret",
            description=(
                f"{len(high_value_secrets)} Kubernetes Secret(s) contain what appear to be Azure "
                "Storage Account keys or other long-lived cloud credentials. Kubernetes Secrets are "
                "base64-encoded (not encrypted) by default. Any service account with 'list secrets' "
                "permission — or cluster-admin — can retrieve these in plaintext. "
                "A Storage Account key grants full read/write/delete access to all Blob containers."
            ),
            evidence={"high_value_secrets": high_value_secrets},
            remediation=(
                "IMMEDIATE: Rotate the Azure Storage Account key via Azure Portal → Storage → Access Keys → Rotate.\n"
                "Replace static keys with Azure Workload Identity (Managed Identity + OIDC federation):\n"
                "  az aks update --enable-oidc-issuer --enable-workload-identity -g <rg> -n <cluster>\n"
                "Application code: replace BlobServiceClient(credential=key) with "
                "BlobServiceClient(credential=DefaultAzureCredential())"
            ),
            mitre=["T1552.007"],
            cwe=["CWE-312"],
            references=["https://azure.github.io/azure-workload-identity/docs/"],
        ))

    return findings


# ---------------------------------------------------------------------------
# audit-network
# ---------------------------------------------------------------------------

def audit_network(data: dict) -> list:
    findings = []
    netpol_data = data.get("netpol") or {}
    ns_data = data.get("namespaces") or {}
    pods_data = data.get("pods") or {}

    # Which namespaces have NetworkPolicies?
    covered_ns = set()
    empty_selector_policies = []

    for np in (netpol_data.get("items") or []):
        ns = np["metadata"]["namespace"]
        covered_ns.add(ns)
        np_name = np["metadata"]["name"]

        # Check for empty podSelector in ingress/egress from/to peers
        for direction in ["ingress", "egress"]:
            for rule in (np["spec"].get(direction) or []):
                peer_key = "from" if direction == "ingress" else "to"
                for peer in (rule.get(peer_key) or []):
                    ps = peer.get("podSelector")
                    if ps == {}:
                        empty_selector_policies.append(
                            f"{ns}/{np_name} ({direction}) — podSelector: {{}} allows ALL pods"
                        )

    # All application namespaces
    all_ns = set()
    for ns in (ns_data.get("items") or []):
        name = ns["metadata"]["name"]
        if name not in SYSTEM_NAMESPACES:
            all_ns.add(name)

    uncovered = all_ns - covered_ns
    if uncovered:
        findings.append(finding(
            fid="AKSPT-006",
            severity="MEDIUM",
            cvss=5.3,
            title=f"{len(uncovered)} namespace(s) have no NetworkPolicies — unrestricted pod-to-pod traffic",
            description=(
                f"Namespaces without any NetworkPolicy: {sorted(uncovered)}. "
                "In Kubernetes, the default is to allow all pod-to-pod traffic. Without a NetworkPolicy, "
                "any pod in the cluster can communicate with any other pod — including sensitive services "
                "like certificate authorities, policy engines, and databases."
            ),
            evidence={"uncovered_namespaces": sorted(uncovered), "covered_namespaces": sorted(covered_ns)},
            remediation=(
                "Apply a default-deny NetworkPolicy to each uncovered namespace, then add specific allow rules:\n\n"
                "apiVersion: networking.k8s.io/v1\n"
                "kind: NetworkPolicy\nmetadata:\n  name: default-deny\nspec:\n"
                "  podSelector: {}\n  policyTypes: [Ingress, Egress]"
            ),
            mitre=["T1210"],
            cwe=["CWE-923"],
        ))

    if empty_selector_policies:
        findings.append(finding(
            fid="AKSPT-007",
            severity="HIGH",
            cvss=7.8,
            title=f"NetworkPolicy ingress/egress rules use empty podSelector — allows all pods",
            description=(
                f"{len(empty_selector_policies)} NetworkPolicy rule(s) use 'podSelector: {{}}' in their "
                "ingress from / egress to peer selectors. An empty podSelector matches ALL pods in the "
                "namespace — not just the intended service. This is commonly seen on database NetworkPolicies "
                "where the intent was to restrict access to specific application pods."
            ),
            evidence={"policies_with_empty_selector": empty_selector_policies},
            remediation=(
                "Replace empty podSelector: {} with explicit app label selectors:\n\n"
                "ingress:\n- from:\n  - podSelector:\n      matchLabels:\n        app: your-app-name\n\n"
                "Use: kubectl get pods -n <ns> --show-labels to find the correct label values."
            ),
            mitre=["T1557"],
            cwe=["CWE-923"],
        ))

    # Check for service mesh
    mesh_found = False
    for pod in (pods_data.get("items") or []):
        for c in pod["spec"].get("containers", []):
            img = c.get("image", "").lower()
            if any(x in img for x in ["istio", "linkerd2-proxy", "envoy", "cilium"]):
                mesh_found = True
                break
        if mesh_found:
            break

    if not mesh_found:
        findings.append(finding(
            fid="AKSPT-008",
            severity="HIGH",
            cvss=7.8,
            title="No service mesh detected — all inter-pod traffic is unencrypted and unauthenticated",
            description=(
                "No service mesh (Istio, Linkerd, Cilium) is installed. All communication between "
                "pods travels in plaintext over the cluster network. There is no cryptographic service "
                "identity — any pod can impersonate any other service. An attacker with network access "
                "inside the cluster can eavesdrop on inter-service traffic and capture tokens, session "
                "data, or patient records in transit."
            ),
            evidence={"mesh_detected": False},
            remediation=(
                "Deploy Linkerd (recommended for simplicity) or Istio for automatic mTLS:\n\n"
                "  linkerd install | kubectl apply -f -\n"
                "  kubectl annotate namespace <app-ns> linkerd.io/inject=enabled\n"
                "  kubectl rollout restart deployment -n <app-ns>\n\n"
                "For Argo Workflows compatibility add: config.linkerd.io/proxy-await=true\n"
                "Note: Install resource limits (AKSPT-011) before sidecar injection."
            ),
            mitre=["T1557", "T1040"],
            cwe=["CWE-306"],
            references=["https://linkerd.io/2.14/tasks/adding-your-service/"],
        ))

    return findings


# ---------------------------------------------------------------------------
# audit-pods
# ---------------------------------------------------------------------------

def audit_pods(data: dict) -> list:
    findings = []
    pods_data = data.get("pods") or {}
    ns_data = data.get("namespaces") or {}

    privileged_pods = []
    root_pods = []
    no_limits = []
    dangerous_mounts = []
    auto_mount_pods = []

    for pod in (pods_data.get("items") or []):
        ns = pod["metadata"]["namespace"]
        pname = pod["metadata"]["name"]
        is_system = ns in SYSTEM_NAMESPACES

        for c in pod["spec"].get("containers", []):
            cname = c["name"]
            sc = c.get("securityContext", {})
            res = c.get("resources", {})
            label = f"{ns}/{pname}/{cname}"

            if sc.get("privileged") and not is_system:
                privileged_pods.append(label)

            if (sc.get("runAsUser") == 0 or sc.get("runAsNonRoot") is False) and not is_system:
                root_pods.append(label)

            if not res.get("limits"):
                no_limits.append(label)

        for v in pod["spec"].get("volumes", []):
            hp = v.get("hostPath", {}).get("path", "")
            if hp and not is_system and any(hp.startswith(d) for d in DANGEROUS_HOST_PATHS):
                dangerous_mounts.append(f"{ns}/{pname} → {hp}")

        if pod["spec"].get("automountServiceAccountToken", True) and not is_system:
            auto_mount_pods.append(f"{ns}/{pname}")

    # PSA labels check
    ns_without_psa = []
    for ns in (ns_data.get("items") or []):
        name = ns["metadata"]["name"]
        labels = ns["metadata"].get("labels", {})
        psa_labels = {k: v for k, v in labels.items() if "pod-security" in k}
        if not psa_labels:
            ns_without_psa.append(name)

    if ns_without_psa:
        findings.append(finding(
            fid="AKSPT-009",
            severity="HIGH",
            cvss=8.0,
            title=f"No Pod Security Admission labels on {len(ns_without_psa)} namespace(s)",
            description=(
                f"Namespaces without PSA labels: {ns_without_psa}. "
                "Pod Security Admission is the Kubernetes built-in mechanism that blocks pods from "
                "requesting dangerous privileges. Without PSA labels, any deployment can request "
                "privileged: true, hostPID: true, or hostNetwork: true unconditionally."
            ),
            evidence={"namespaces_without_psa": ns_without_psa},
            remediation=(
                "Phase 1 — warn mode (audit without blocking):\n"
                "  kubectl label namespace <ns> pod-security.kubernetes.io/warn=restricted\n\n"
                "Phase 2 — after fixing all warnings, enforce:\n"
                "  kubectl label namespace <ns> pod-security.kubernetes.io/enforce=restricted\n\n"
                "System namespaces: use 'privileged' for kube-system, 'baseline' for cert-manager/gatekeeper."
            ),
            mitre=["T1611"],
            cwe=["CWE-732"],
            references=["https://kubernetes.io/docs/concepts/security/pod-security-admission/"],
        ))

    if privileged_pods:
        findings.append(finding(
            fid="AKSPT-010",
            severity="HIGH",
            cvss=8.0,
            title=f"{len(privileged_pods)} privileged container(s) outside kube-system",
            description=(
                f"Containers running with privileged: true outside kube-system: {privileged_pods}. "
                "A privileged container has nearly all Linux capabilities and can access the host node's "
                "devices, bypass namespacing, and escape the container boundary."
            ),
            evidence={"privileged_containers": privileged_pods},
            remediation=(
                "Remove privileged: true from all application containers.\n"
                "If specific Linux capabilities are needed, grant only the minimum required:\n"
                "  securityContext:\n    capabilities:\n      add: [NET_BIND_SERVICE]  # example\n"
                "      drop: [ALL]"
            ),
            mitre=["T1611"],
            cwe=["CWE-732"],
        ))

    if no_limits:
        app_no_limits = [c for c in no_limits if not any(
            c.startswith(ns + "/") for ns in SYSTEM_NAMESPACES
        )]
        if app_no_limits:
            findings.append(finding(
                fid="AKSPT-011",
                severity="MEDIUM",
                cvss=5.3,
                title=f"{len(app_no_limits)} application container(s) have no resource limits",
                description=(
                    f"{len(app_no_limits)} containers lack CPU/memory limits. "
                    "Without limits, a single misbehaving container can consume all available node "
                    "resources, causing the Kubernetes kubelet to OOMKill neighbouring pods. "
                    "This is also a prerequisite risk for service mesh deployment — sidecar proxies "
                    "added to unlimited pods can starve nodes."
                ),
                evidence={"containers_without_limits": app_no_limits[:20]},
                remediation=(
                    "1. Profile actual usage: kubectl top pods --containers -n <ns>\n"
                    "2. Set limits at 2x the 95th percentile observed:\n"
                    "   resources:\n     requests: {cpu: 100m, memory: 256Mi}\n"
                    "     limits: {cpu: 500m, memory: 512Mi}\n"
                    "3. Apply a LimitRange as a namespace-wide safety net."
                ),
                mitre=["T1499.004"],
                cwe=["CWE-400"],
            ))

    if dangerous_mounts:
        findings.append(finding(
            fid="AKSPT-012",
            severity="HIGH",
            cvss=8.5,
            title=f"{len(dangerous_mounts)} dangerous hostPath volume mount(s) in application pods",
            description=(
                f"Application pods mount sensitive host paths: {dangerous_mounts}. "
                "A hostPath mount of sensitive directories (/etc, /proc, /root, /var/run/docker.sock) "
                "gives the container read or write access to the underlying node's filesystem, "
                "effectively breaking container isolation."
            ),
            evidence={"dangerous_mounts": dangerous_mounts},
            remediation=(
                "Replace hostPath mounts with PersistentVolumeClaims or ConfigMaps.\n"
                "If hostPath is genuinely required (e.g., CSI drivers), restrict to specific "
                "non-sensitive paths and add PSA labels to enforce the restriction."
            ),
            mitre=["T1611"],
            cwe=["CWE-732"],
        ))

    return findings


# ---------------------------------------------------------------------------
# audit-components
# ---------------------------------------------------------------------------

def audit_components(data: dict) -> list:
    findings = []
    pods_data = data.get("pods") or {}

    # Extract all unique images
    images = {}
    for pod in (pods_data.get("items") or []):
        ns = pod["metadata"]["namespace"]
        pname = pod["metadata"]["name"]
        for c in pod["spec"].get("containers", []):
            img = c.get("image", "")
            if img not in images:
                images[img] = []
            images[img].append(f"{ns}/{pname}/{c['name']}")

    for img, locations in images.items():
        img_lower = img.lower()
        # Extract version from image tag
        ver_match = re.search(r":v?(\d+\.\d+\.\d+)", img)
        if not ver_match:
            continue
        ver_str = ver_match.group(1)
        ver_parts = tuple(int(x) for x in ver_str.split("."))

        for entry in CVE_DB:
            if not any(p.lower() in img_lower for p in entry["image_patterns"]):
                continue

            affected_below = entry["affected_below"]
            if ver_parts < affected_below:
                findings.append(finding(
                    fid=f"AKSPT-CVE-{entry['cve'].replace('-', '')}",
                    severity=entry["severity"],
                    cvss=entry["cvss"],
                    title=f"{entry['component']} {ver_str} — {entry['cve']} (CVSS {entry['cvss']})",
                    description=(
                        f"Running version {ver_str} is affected by {entry['cve']}: "
                        f"{entry['description']}. "
                        f"Fixed in {entry['fixed_in']}. EPSS: {entry['epss']*100:.2f}%."
                    ),
                    evidence={"image": img, "version": ver_str, "locations": locations},
                    remediation=(
                        f"Upgrade to {entry['fixed_in']} or later.\n"
                        f"helm upgrade <release> <chart> --set image.tag={entry['fixed_in']}"
                    ),
                    mitre=["T1190"],
                    cwe=["CWE-1104"],
                    references=[f"https://nvd.nist.gov/vuln/detail/{entry['cve']}"],
                ))

    # Flag any component with 'latest' tag
    latest_images = [img for img in images if img.endswith(":latest")]
    if latest_images:
        findings.append(finding(
            fid="AKSPT-013",
            severity="MEDIUM",
            cvss=5.0,
            title=f"{len(latest_images)} container image(s) using 'latest' tag",
            description=(
                "Images using the 'latest' tag are non-deterministic — a node pull can silently "
                "introduce a new version with breaking changes or security regressions. "
                "This also prevents accurate CVE scanning."
            ),
            evidence={"latest_images": latest_images},
            remediation="Pin all images to a specific version tag and enforce with OPA Gatekeeper policy.",
            mitre=["T1195"],
            cwe=["CWE-1104"],
        ))

    return findings


# ---------------------------------------------------------------------------
# kill-chain
# ---------------------------------------------------------------------------

def cmd_kill_chain(args):
    findings_path = Path(args.findings)
    if not findings_path.exists():
        print(f"[ERROR] Findings file not found: {args.findings}")
        sys.exit(1)

    all_findings = json.loads(findings_path.read_text())["findings"]

    # Severity index
    by_id = {f["id"]: f for f in all_findings}
    critical = [f for f in all_findings if f["severity"] == "CRITICAL"]
    high = [f for f in all_findings if f["severity"] == "HIGH"]

    print("=" * 70)
    print("AKS KILL CHAIN ANALYSIS")
    print("=" * 70)

    # Look for the key chain components
    has_rbac_escalation = any("cluster-admin" in f["title"].lower() for f in critical + high)
    has_secret_exposure = any("plaintext" in f["title"].lower() or "storage" in f["title"].lower()
                               for f in all_findings)
    has_no_mesh = any("service mesh" in f["title"].lower() for f in all_findings)

    chain_steps = []

    chain_steps.append({
        "step": 1,
        "phase": "INITIAL ACCESS",
        "finding": "External — web application vulnerability or exposed service (see Phase 1 report)",
        "method": "Credential stuffing (no rate limit), XSS token theft, or SSRF to cloud metadata",
        "result": "Valid session token or code execution entry point",
        "mitre": "TA0001",
    })

    chain_steps.append({
        "step": 2,
        "phase": "EXECUTION",
        "finding": "Web application code execution (XSS, file upload, SSRF) or vulnerable cluster component",
        "method": "Stored XSS → session token exfiltration; or exploit Argo Workflows API",
        "result": "Code execution inside a pod in the target namespace",
        "mitre": "TA0002",
    })

    if has_rbac_escalation:
        chain_steps.append({
            "step": 3,
            "phase": "PRIVILEGE ESCALATION",
            "finding": "AKSPT-001 — default SA bound to cluster-admin",
            "method": (
                "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\n"
                "curl -sk -H \"Authorization: Bearer $TOKEN\" "
                "https://kubernetes.default.svc/api/v1/secrets"
            ),
            "result": "cluster-admin access — read ALL secrets in ALL namespaces",
            "mitre": "T1548.005",
        })

    if has_secret_exposure:
        chain_steps.append({
            "step": 4,
            "phase": "CREDENTIAL HARVEST",
            "finding": "AKSPT-003 + AKSPT-005 — plaintext credentials and storage key",
            "method": "Parse K8s Secret dump for storage keys, DB passwords, OAuth secrets",
            "result": "Azure Storage Account key, database passwords, IdP admin password",
            "mitre": "T1552.007",
        })

    chain_steps.append({
        "step": 5,
        "phase": "EXFILTRATION",
        "finding": "AKSPT-005 — Azure Storage key",
        "method": (
            "az storage blob download-batch \\\n"
            "  --account-key <harvested-key> \\\n"
            "  --source <container> --destination ./exfil/"
        ),
        "result": "Full dataset downloaded from Azure Blob Storage — HIPAA/GDPR reportable breach",
        "mitre": "TA0010",
    })

    for step in chain_steps:
        print(f"\n{'─'*60}")
        print(f"STEP {step['step']} — {step['phase']} [{step['mitre']}]")
        print(f"Finding:  {step['finding']}")
        print(f"Method:   {step['method']}")
        print(f"Result:   {step['result']}")

    print(f"\n{'='*70}")
    print("CHAIN BREAK ANALYSIS")
    print(f"{'='*70}")
    print("Breaking any link breaks the chain. Highest-impact breaks first:")
    print()
    if has_rbac_escalation:
        print("1. [IMMEDIATE] Delete cluster-admin ClusterRoleBinding (AKSPT-001)")
        print("   → Breaks Step 3 — attacker gets pod exec but cannot escalate")
        print("   → Single kubectl command, zero downtime")
    print()
    print("2. [SAME DAY] Rotate Azure Storage Account key (AKSPT-005)")
    print("   → Breaks Step 5 — exfiltrated key is immediately invalidated")
    print()
    print("3. [SAME DAY] Disable ROPC grant in Keycloak (Phase 1 finding)")
    print("   → Breaks Step 1 — credential stuffing entry point eliminated")
    print()
    print(f"ZERO-DAYS REQUIRED: 0")
    print(f"TOTAL FINDINGS USED IN CHAIN: {len(chain_steps)} steps")


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def cmd_report(args):
    findings_path = Path(args.findings)
    if not findings_path.exists():
        print(f"[ERROR] Findings file not found: {args.findings}")
        sys.exit(1)

    data = json.loads(findings_path.read_text())
    all_findings = data.get("findings", [])
    metadata = data.get("metadata", {})

    if args.format == "json":
        output = json.dumps(data, indent=2)
    else:
        output = _render_markdown(all_findings, metadata)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Report written to: {args.output}")
    else:
        print(output)


def _render_markdown(findings: list, metadata: dict) -> str:
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f["severity"], 9))

    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1

    lines = [
        "# AKS Penetration Test — Findings Report",
        f"\n**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Total Findings:** {len(findings)}",
        "",
        "## Risk Distribution",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        lines.append(f"| {severity_color(sev)} {sev} | {counts.get(sev, 0)} |")

    lines += ["", "## Findings Index", "", "| ID | Severity | CVSS | Title |",
              "|----|----------|------|-------|"]
    for f in sorted_findings:
        lines.append(f"| {f['id']} | {severity_color(f['severity'])} {f['severity']} | {f['cvss']} | {f['title']} |")

    lines += ["", "---", "", "## Detailed Findings", ""]
    for f in sorted_findings:
        lines += [
            f"### {f['id']} · CVSS {f['cvss']}",
            f"**{f['title']}**",
            "",
            f"**Severity:** {severity_color(f['severity'])} {f['severity']}  ",
            f"**MITRE ATT&CK:** {', '.join(f.get('mitre', []))}  ",
            f"**CWE:** {', '.join(f.get('cwe', []))}",
            "",
            "**Description**",
            "",
            f.get("description", ""),
            "",
            "**Evidence**",
            "",
            f"```json\n{json.dumps(f.get('evidence', {}), indent=2)}\n```",
            "",
            "**Remediation**",
            "",
            f"```\n{f.get('remediation', '')}\n```",
            "",
            "---",
            "",
        ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Full audit runner
# ---------------------------------------------------------------------------

def cmd_audit(args):
    print(f"[*] Loading exports from: {args.dir}")
    data = load_exports(args.dir, getattr(args, "namespace", None))

    loaded = [k for k, v in data.items() if v is not None]
    missing = [k for k, v in data.items() if v is None]
    print(f"[*] Loaded: {loaded}")
    if missing:
        print(f"[!] Missing (will skip): {missing}")

    all_findings = []
    modules = [
        ("RBAC", audit_rbac),
        ("Secrets", audit_secrets),
        ("Network", audit_network),
        ("Pods", audit_pods),
        ("Components", audit_components),
    ]

    for name, fn in modules:
        print(f"[*] Running audit-{name.lower()}...")
        results = fn(data)
        print(f"    → {len(results)} finding(s)")
        all_findings.extend(results)

    counts = defaultdict(int)
    for f in all_findings:
        counts[f["severity"]] += 1

    print()
    print("=" * 60)
    print("AUDIT COMPLETE")
    print("=" * 60)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[sev]:
            print(f"  {severity_color(sev)} {sev}: {counts[sev]}")
    print(f"  Total: {len(all_findings)}")

    output_data = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "exports_dir": str(args.dir),
            "namespace_filter": getattr(args, "namespace", None),
        },
        "findings": all_findings,
    }

    if getattr(args, "output", None):
        Path(args.output).write_text(json.dumps(output_data, indent=2))
        print(f"\n[*] Findings saved to: {args.output}")
    else:
        print(json.dumps(output_data, indent=2))


def cmd_audit_module(args, module_fn):
    print(f"[*] Loading exports from: {args.dir}")
    data = load_exports(args.dir, getattr(args, "namespace", None))
    results = module_fn(data)
    for f in results:
        print(f"\n{severity_color(f['severity'])} {f['id']} [{f['severity']} CVSS {f['cvss']}]")
        print(f"  {f['title']}")
        print(f"  Remediation: {f['remediation'].splitlines()[0]}")
    print(f"\n{len(results)} finding(s)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="AKS Cluster Penetration Test Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # collect
    p_collect = sub.add_parser("collect", help="Print kubectl collection commands")
    p_collect.add_argument("--namespace", "-n", help="Scope to a specific namespace")
    p_collect.add_argument("--output-dir", default="/tmp/aks_audit")

    # audit
    p_audit = sub.add_parser("audit", help="Run all audit modules")
    p_audit.add_argument("--dir", required=True, help="Directory containing kubectl JSON exports")
    p_audit.add_argument("--namespace", "-n", help="Filter to a specific namespace")
    p_audit.add_argument("--output", "-o", help="Write findings JSON to file")

    # audit-rbac
    p_rbac = sub.add_parser("audit-rbac", help="RBAC analysis only")
    p_rbac.add_argument("--dir", required=True)
    p_rbac.add_argument("--namespace", "-n")

    # audit-secrets
    p_secrets = sub.add_parser("audit-secrets", help="Credential exposure analysis only")
    p_secrets.add_argument("--dir", required=True)
    p_secrets.add_argument("--namespace", "-n")

    # audit-network
    p_network = sub.add_parser("audit-network", help="Network segmentation analysis only")
    p_network.add_argument("--dir", required=True)
    p_network.add_argument("--namespace", "-n")

    # audit-pods
    p_pods = sub.add_parser("audit-pods", help="Pod security analysis only")
    p_pods.add_argument("--dir", required=True)
    p_pods.add_argument("--namespace", "-n")

    # audit-components
    p_comp = sub.add_parser("audit-components", help="Component CVE analysis only")
    p_comp.add_argument("--dir", required=True)
    p_comp.add_argument("--namespace", "-n")

    # kill-chain
    p_kc = sub.add_parser("kill-chain", help="Synthesize kill chain from findings")
    p_kc.add_argument("--findings", required=True, help="Path to findings JSON")
    p_kc.add_argument("--web-findings", help="Path to Phase 1 web app findings JSON (optional)")

    # report
    p_report = sub.add_parser("report", help="Generate findings report")
    p_report.add_argument("--findings", required=True)
    p_report.add_argument("--format", choices=["md", "json"], default="md")
    p_report.add_argument("--output", "-o")

    args = parser.parse_args()

    dispatch = {
        "collect": cmd_collect,
        "audit": cmd_audit,
        "audit-rbac": lambda a: cmd_audit_module(a, audit_rbac),
        "audit-secrets": lambda a: cmd_audit_module(a, audit_secrets),
        "audit-network": lambda a: cmd_audit_module(a, audit_network),
        "audit-pods": lambda a: cmd_audit_module(a, audit_pods),
        "audit-components": lambda a: cmd_audit_module(a, audit_components),
        "kill-chain": cmd_kill_chain,
        "report": cmd_report,
    }

    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
