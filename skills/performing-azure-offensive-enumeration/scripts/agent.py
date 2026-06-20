#!/usr/bin/env python3
"""
Azure Offensive Enumeration Agent
Performs authorized offensive enumeration of Azure tenants and subscriptions.

Subcommands:
  auth             Verify authentication and show current context
  enumerate        Run all enumeration modules
  enum-identity    Entra ID / Azure AD identity enumeration
  enum-resources   Subscription, resource groups, and RBAC enumeration
  enum-storage     Storage account exposure analysis
  enum-compute     VMs, AKS, ACR, and Function Apps
  enum-network     NSGs, public IPs, VNet peering
  enum-keyvault    Key Vault access and configuration
  escalation       Privilege escalation path analysis
  imds             Azure IMDS exploitation (run from inside Azure VM)
  report           Generate markdown or JSON report

Requires: az CLI authenticated (az login). No pip dependencies.
For IMDS subcommand: no az login needed — runs from inside Azure VM.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HIGH_PRIV_ROLES = {
    "Owner": "Can grant any role — full subscription takeover",
    "Contributor": "Full resource control — can deploy Automation Accounts for code execution",
    "User Access Administrator": "Can grant Owner role — full subscription takeover",
    "Role Based Access Control Administrator": "Can assign roles to any principal",
    "Application Administrator": "Can manage all app registrations and service principal credentials",
    "Global Administrator": "Full Entra ID and Azure control",
    "Privileged Role Administrator": "Can assign all Entra ID roles including Global Admin",
    "Cloud Application Administrator": "Can manage app registrations and consent",
}

MGMT_PORTS = {
    "22": "SSH", "3389": "RDP", "5985": "WinRM-HTTP",
    "5986": "WinRM-HTTPS", "445": "SMB", "1433": "MSSQL",
    "3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis",
    "27017": "MongoDB", "9200": "Elasticsearch", "8080": "HTTP-alt",
}

DANGEROUS_GRAPH_PERMISSIONS = {
    "Application.ReadWrite.All": "Can create app credentials and backdoor service principals",
    "Directory.ReadWrite.All": "Full Entra ID write — can modify any object",
    "RoleManagement.ReadWrite.Directory": "Can assign Global Admin and other privileged roles",
    "AppRoleAssignment.ReadWrite.All": "Can grant admin consent to any app",
    "User.ReadWrite.All": "Can reset any user password",
    "GroupMember.ReadWrite.All": "Can add self to any group including privileged ones",
    "ServicePrincipalEndpoint.ReadWrite.All": "Can modify service principal endpoints",
    "Policy.ReadWrite.ConditionalAccess": "Can disable conditional access policies",
}

IMDS_URL = "http://169.254.169.254"
IMDS_HEADERS = {"Metadata": "true"}


# ---------------------------------------------------------------------------
# az CLI wrapper
# ---------------------------------------------------------------------------

def az(args: list, *, suppress_errors: bool = False) -> dict | list | None:
    """Run an az CLI command and return parsed JSON output."""
    cmd = ["az"] + args + ["--output", "json"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            if not suppress_errors:
                err = result.stderr.strip()
                if "az login" in err or "not logged in" in err.lower():
                    print("[ERROR] Not authenticated. Run: az login", file=sys.stderr)
                elif err:
                    print(f"[WARN] az {' '.join(args[:3])}: {err[:200]}", file=sys.stderr)
            return None
        if not result.stdout.strip():
            return []
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        print(f"[WARN] Timeout: az {' '.join(args[:3])}", file=sys.stderr)
        return None
    except json.JSONDecodeError:
        return None
    except FileNotFoundError:
        print("[ERROR] az CLI not found. Install: https://aka.ms/installazurecliwindows", file=sys.stderr)
        sys.exit(1)


def az_rest(url: str, method: str = "GET") -> dict | None:
    """Call Azure REST API via az rest."""
    result = az(["rest", "--method", method, "--url", url], suppress_errors=True)
    return result


def imds_get(path: str) -> dict | None:
    """Call IMDS endpoint via curl subprocess."""
    url = f"{IMDS_URL}{path}"
    try:
        result = subprocess.run(
            ["curl", "-s", "-f", "--connect-timeout", "3",
             "-H", "Metadata: true", url],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return None


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------

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


def severity_icon(s: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(s, "⚪")


# ---------------------------------------------------------------------------
# auth subcommand
# ---------------------------------------------------------------------------

def cmd_auth(args):
    print("[*] Checking Azure authentication...")
    account = az(["account", "show"])
    if not account:
        print("[ERROR] Not authenticated. Run: az login")
        sys.exit(1)

    user = account.get("user", {})
    print(f"\n  Tenant:       {account.get('tenantId')}")
    print(f"  Subscription: {account.get('id')} ({account.get('name')})")
    print(f"  Principal:    {user.get('name')} ({user.get('type')})")
    print(f"  State:        {account.get('state')}")

    # List all accessible subscriptions
    all_subs = az(["account", "list"]) or []
    if len(all_subs) > 1:
        print(f"\n  [{len(all_subs)} subscriptions accessible]")
        for sub in all_subs:
            marker = "→" if sub["isDefault"] else " "
            print(f"  {marker} {sub['id']} | {sub['name']} | {sub['state']}")

    # Current user's directory roles
    print("\n[*] Checking directory role memberships...")
    me = az(["ad", "signed-in-user", "show"], suppress_errors=True)
    if me:
        member_of = az_rest("https://graph.microsoft.com/v1.0/me/memberOf") or {}
        roles = [v for v in member_of.get("value", [])
                 if v.get("@odata.type") == "#microsoft.graph.directoryRole"]
        if roles:
            print(f"  Directory roles held:")
            for r in roles:
                role_name = r.get("displayName", "")
                print(f"    {severity_icon('HIGH') if role_name in HIGH_PRIV_ROLES else '  '} {role_name}")
        else:
            print("  No directory roles (or insufficient permissions to query)")

    print()


# ---------------------------------------------------------------------------
# enum-identity
# ---------------------------------------------------------------------------

def enum_identity(args=None) -> list:
    findings = []
    print("[*] Enumerating Entra ID identities...")

    # Service principals with high-privilege Azure RBAC
    print("    Checking high-privilege role assignments...")
    role_assignments = az(["role", "assignment", "list", "--all"], suppress_errors=True) or []

    sp_high_roles = defaultdict(list)
    for ra in role_assignments:
        role_name = ra.get("roleDefinitionName", "")
        principal_type = ra.get("principalType", "")
        principal_name = ra.get("principalName") or ra.get("principalId", "")
        scope = ra.get("scope", "")

        if role_name in HIGH_PRIV_ROLES and principal_type == "ServicePrincipal":
            sp_high_roles[principal_name].append({
                "role": role_name,
                "scope": scope,
                "impact": HIGH_PRIV_ROLES[role_name],
            })

    if sp_high_roles:
        findings.append(finding(
            fid="AZEPT-001",
            severity="CRITICAL",
            cvss=9.8,
            title=f"{len(sp_high_roles)} service principal(s) with high-privilege Azure RBAC roles",
            description=(
                f"{len(sp_high_roles)} service principals hold high-privilege roles (Owner, Contributor, "
                "User Access Administrator). A compromised service principal credential at subscription "
                "scope grants full resource control — including the ability to read all Key Vault secrets, "
                "enumerate all storage accounts, and create backdoor resources."
            ),
            evidence={"high_privilege_service_principals": dict(sp_high_roles)},
            remediation=(
                "Apply the principle of least privilege — assign only the specific roles each SP requires.\n"
                "Audit each SP's purpose and remove assignments that are not actively needed.\n"
                "Enable Microsoft Defender for Cloud to alert on overly-permissive role assignments.\n"
                "Rotate credentials for any SP with Owner/Contributor at subscription scope."
            ),
            mitre=["T1098", "T1078.004"],
            cwe=["CWE-269"],
            references=["https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices"],
        ))

    # App registrations with dangerous Graph permissions
    print("    Checking app registration permissions...")
    apps = az(["ad", "app", "list", "--all"], suppress_errors=True) or []
    dangerous_apps = []

    # Map Graph API app role IDs to permission names (common ones)
    # These IDs are stable across all tenants
    GRAPH_ROLE_IDS = {
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
        "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
        "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
        "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
        "dbaae8cf-10b5-4b86-a4a1-f871c94c6695": "GroupMember.ReadWrite.All",
        "4e46008b-f24c-477d-8fff-7bb4ec7aafe0": "Policy.ReadWrite.ConditionalAccess",
    }

    for app in apps:
        for req in (app.get("requiredResourceAccess") or []):
            for r in req.get("resourceAccess", []):
                if r.get("type") == "Role":
                    perm_name = GRAPH_ROLE_IDS.get(r.get("id", ""), r.get("id", "unknown"))
                    if perm_name in DANGEROUS_GRAPH_PERMISSIONS:
                        dangerous_apps.append({
                            "app": app.get("displayName"),
                            "appId": app.get("appId"),
                            "permission": perm_name,
                            "impact": DANGEROUS_GRAPH_PERMISSIONS[perm_name],
                        })

    if dangerous_apps:
        findings.append(finding(
            fid="AZEPT-002",
            severity="HIGH",
            cvss=8.5,
            title=f"{len(dangerous_apps)} app registration(s) with dangerous Graph API application permissions",
            description=(
                f"{len(dangerous_apps)} app registrations hold dangerous Microsoft Graph API application "
                "permissions (type: Role, not delegated). These permissions act without a signed-in user. "
                "If an attacker compromises the app's client secret or certificate, they inherit these "
                "permissions — potentially enabling Global Admin takeover."
            ),
            evidence={"dangerous_apps": dangerous_apps},
            remediation=(
                "Review whether each permission is genuinely required.\n"
                "Replace application permissions with delegated permissions where possible.\n"
                "Implement certificate-based authentication instead of client secrets.\n"
                "Monitor consent grants via Microsoft Entra audit logs."
            ),
            mitre=["T1098", "T1528"],
            cwe=["CWE-269"],
            references=["https://learn.microsoft.com/en-us/azure/active-directory/develop/permissions-consent-overview"],
        ))

    return findings


# ---------------------------------------------------------------------------
# enum-resources
# ---------------------------------------------------------------------------

def enum_resources(args=None) -> list:
    findings = []
    print("[*] Enumerating subscriptions and RBAC...")

    subs = az(["account", "list"]) or []
    print(f"    {len(subs)} subscription(s) accessible")

    role_assignments = az(["role", "assignment", "list", "--all"], suppress_errors=True) or []

    # Subscription-scope Owner/Contributor for any principal
    sub_scope_high = []
    for ra in role_assignments:
        role_name = ra.get("roleDefinitionName", "")
        scope = ra.get("scope", "")
        principal_type = ra.get("principalType", "")
        principal_name = ra.get("principalName") or ra.get("principalId", "")

        # Subscription-level scope looks like /subscriptions/<guid>
        is_sub_scope = re.match(r"^/subscriptions/[^/]+$", scope) is not None
        if is_sub_scope and role_name in ("Owner", "User Access Administrator",
                                           "Role Based Access Control Administrator"):
            sub_scope_high.append({
                "role": role_name,
                "principal": principal_name,
                "type": principal_type,
                "scope": scope,
            })

    if sub_scope_high:
        findings.append(finding(
            fid="AZEPT-003",
            severity="CRITICAL",
            cvss=9.5,
            title=f"{len(sub_scope_high)} subscription-scope Owner/UAA role assignment(s)",
            description=(
                f"{len(sub_scope_high)} principal(s) hold Owner, User Access Administrator, or RBAC "
                "Administrator at the subscription root. This grants the ability to assign any role "
                "to any principal — a single compromised credential here results in full subscription "
                "takeover and can pivot to other subscriptions via management group inheritance."
            ),
            evidence={"subscription_scope_assignments": sub_scope_high},
            remediation=(
                "Remove subscription-scope Owner assignments and replace with scoped Contributor/Reader.\n"
                "Use Privileged Identity Management (PIM) for just-in-time Owner access.\n"
                "Require MFA and Conditional Access for any principal with Owner.\n"
                "Alert on any new subscription-scope role assignments via Azure Monitor."
            ),
            mitre=["T1098", "T1484.002"],
            cwe=["CWE-269"],
        ))

    # Custom roles with wildcard actions
    print("    Checking custom role definitions...")
    custom_roles = az(["role", "definition", "list", "--custom-role-only"], suppress_errors=True) or []
    wildcard_roles = []
    for role in custom_roles:
        for perm in role.get("permissions", []):
            actions = perm.get("actions", [])
            for action in actions:
                if action in ("*", "*/write", "*/delete") or \
                   "Microsoft.Authorization" in action and "Write" in action:
                    wildcard_roles.append({
                        "role": role.get("roleName"),
                        "action": action,
                        "description": role.get("description", ""),
                    })
                    break

    if wildcard_roles:
        findings.append(finding(
            fid="AZEPT-004",
            severity="HIGH",
            cvss=7.8,
            title=f"{len(wildcard_roles)} custom role(s) with wildcard or over-broad actions",
            description=(
                f"{len(wildcard_roles)} custom RBAC role definition(s) contain wildcard (*) or "
                "overly broad action patterns. Wildcard actions grant unintended capabilities as "
                "new Azure resource types and APIs are added."
            ),
            evidence={"wildcard_custom_roles": wildcard_roles},
            remediation=(
                "Replace wildcard actions with explicit resource provider actions.\n"
                "Use az role definition update to tighten the action list.\n"
                "Review using: az role definition list --custom-role-only -o json"
            ),
            mitre=["T1548"],
            cwe=["CWE-732"],
        ))

    return findings


# ---------------------------------------------------------------------------
# enum-storage
# ---------------------------------------------------------------------------

def enum_storage(args=None) -> list:
    findings = []
    print("[*] Enumerating storage accounts...")

    storage_accounts = az(["storage", "account", "list"]) or []
    if not storage_accounts:
        print("    No storage accounts found or insufficient permissions")
        return findings

    print(f"    {len(storage_accounts)} storage account(s) found")

    public_access_accounts = []
    shared_key_accounts = []
    no_https_accounts = []
    weak_tls_accounts = []

    for sa in storage_accounts:
        name = sa.get("name", "")
        rg = sa.get("resourceGroup", "")
        pub = sa.get("allowBlobPublicAccess")
        shared_key = sa.get("allowSharedKeyAccess", True)
        https_only = sa.get("enableHttpsTrafficOnly", True)
        tls_ver = sa.get("minimumTlsVersion", "TLS1_0")

        if pub is True or pub is None:
            public_access_accounts.append({"name": name, "resourceGroup": rg})

        if shared_key is True or shared_key is None:
            shared_key_accounts.append({"name": name, "resourceGroup": rg})

        if not https_only:
            no_https_accounts.append(name)

        if tls_ver in ("TLS1_0", "TLS1_1"):
            weak_tls_accounts.append({"name": name, "tls": tls_ver})

    if public_access_accounts:
        # Try to enumerate containers for public accounts
        public_containers = []
        for sa in public_access_accounts[:5]:  # limit API calls
            containers = az(
                ["storage", "container", "list",
                 "--account-name", sa["name"], "--auth-mode", "login"],
                suppress_errors=True
            ) or []
            for c in containers:
                pub_access = c.get("properties", {}).get("publicAccess")
                if pub_access in ("blob", "container"):
                    public_containers.append({
                        "storage_account": sa["name"],
                        "container": c.get("name"),
                        "public_access": pub_access,
                        "url": f"https://{sa['name']}.blob.core.windows.net/{c.get('name')}",
                    })

        sev = "CRITICAL" if public_containers else "HIGH"
        cvss = 9.1 if public_containers else 7.5

        findings.append(finding(
            fid="AZEPT-005",
            severity=sev,
            cvss=cvss,
            title=f"{len(public_access_accounts)} storage account(s) allow public blob access"
                  + (f" — {len(public_containers)} public container(s) confirmed" if public_containers else ""),
            description=(
                f"{len(public_access_accounts)} storage accounts have allowBlobPublicAccess enabled. "
                + (f"{len(public_containers)} containers are publicly readable without authentication. " if public_containers else "")
                + "Public blob access allows unauthenticated download of any file in the container — "
                "including database backups, configuration files, private keys, and patient data."
            ),
            evidence={
                "public_access_accounts": public_access_accounts,
                "confirmed_public_containers": public_containers,
            },
            remediation=(
                "Disable public blob access at the storage account level:\n"
                "  az storage account update --name <name> --resource-group <rg> --allow-blob-public-access false\n\n"
                "Rotate any credentials that may have been exposed in public containers.\n"
                "Enable Microsoft Defender for Storage to alert on anomalous access."
            ),
            mitre=["T1530"],
            cwe=["CWE-284"],
            references=["https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent"],
        ))

    if shared_key_accounts:
        findings.append(finding(
            fid="AZEPT-006",
            severity="MEDIUM",
            cvss=6.5,
            title=f"{len(shared_key_accounts)} storage account(s) permit shared key (account key) authentication",
            description=(
                f"{len(shared_key_accounts)} storage accounts allow authentication via the 512-bit "
                "account key. This key grants full read/write/delete access to all containers. "
                "Unlike Entra ID tokens (which expire in 1 hour), a stolen account key is valid "
                "indefinitely until manually rotated."
            ),
            evidence={"shared_key_enabled_accounts": [sa["name"] for sa in shared_key_accounts]},
            remediation=(
                "Disable shared key access where possible:\n"
                "  az storage account update --name <name> --resource-group <rg> --allow-shared-key-access false\n\n"
                "Use Azure Workload Identity or SAS tokens with short expiry instead.\n"
                "Enable key rotation reminders via Key Vault."
            ),
            mitre=["T1552.008"],
            cwe=["CWE-312"],
        ))

    if no_https_accounts or weak_tls_accounts:
        all_weak = no_https_accounts + [sa["name"] for sa in weak_tls_accounts]
        findings.append(finding(
            fid="AZEPT-007",
            severity="MEDIUM",
            cvss=5.9,
            title=f"{len(all_weak)} storage account(s) with insecure transport configuration",
            description=(
                f"Storage accounts with HTTPS-only disabled or TLS < 1.2: {all_weak}. "
                "HTTP access to storage enables plaintext credential and data interception."
            ),
            evidence={"no_https": no_https_accounts, "weak_tls": weak_tls_accounts},
            remediation=(
                "az storage account update --name <name> --resource-group <rg> --https-only true\n"
                "az storage account update --name <name> --resource-group <rg> --min-tls-version TLS1_2"
            ),
            mitre=["T1040"],
            cwe=["CWE-319"],
        ))

    return findings


# ---------------------------------------------------------------------------
# enum-compute
# ---------------------------------------------------------------------------

def enum_compute(args=None) -> list:
    findings = []
    print("[*] Enumerating compute resources...")

    # VMs with public IPs
    print("    Checking VMs...")
    vms = az(["vm", "list", "--show-details"], suppress_errors=True) or []
    vms_with_public_ip = []
    for vm in vms:
        pub_ip = vm.get("publicIps", "")
        if pub_ip:
            vms_with_public_ip.append({
                "name": vm.get("name"),
                "resourceGroup": vm.get("resourceGroup"),
                "publicIp": pub_ip,
                "os": vm.get("storageProfile", {}).get("osDisk", {}).get("osType", ""),
                "powerState": vm.get("powerState", ""),
            })

    if vms_with_public_ip:
        findings.append(finding(
            fid="AZEPT-008",
            severity="MEDIUM",
            cvss=5.3,
            title=f"{len(vms_with_public_ip)} VM(s) with public IP addresses",
            description=(
                f"{len(vms_with_public_ip)} virtual machines are directly reachable from the internet. "
                "Public IPs expand the attack surface for brute force, vulnerability exploitation, "
                "and port scanning. Combine with NSG findings to determine which management ports are exposed."
            ),
            evidence={"vms_with_public_ip": vms_with_public_ip},
            remediation=(
                "Remove public IPs and use Azure Bastion for secure VM access.\n"
                "If public IP is required, restrict NSG inbound rules to specific source IP ranges.\n"
                "Enable Microsoft Defender for Servers for runtime threat detection."
            ),
            mitre=["T1580"],
            cwe=["CWE-284"],
        ))

    # ACR with admin user
    print("    Checking container registries...")
    acrs = az(["acr", "list"], suppress_errors=True) or []
    admin_acrs = [a for a in acrs if a.get("adminUserEnabled")]
    if admin_acrs:
        creds_info = []
        for acr in admin_acrs[:3]:
            creds = az(
                ["acr", "credential", "show", "--name", acr["name"]],
                suppress_errors=True
            ) or {}
            creds_info.append({
                "registry": acr["name"],
                "loginServer": acr.get("loginServer"),
                "username": creds.get("username", "admin"),
                "password_accessible": bool(creds.get("passwords")),
            })

        findings.append(finding(
            fid="AZEPT-009",
            severity="HIGH",
            cvss=8.1,
            title=f"{len(admin_acrs)} Azure Container Registry/ies with admin user enabled",
            description=(
                f"{len(admin_acrs)} ACR instance(s) have the admin user enabled. "
                "The admin account uses static username/password credentials that "
                "never expire and grant full pull/push/delete access to all images. "
                "A compromised admin credential enables supply chain attacks by replacing "
                "production container images with backdoored versions."
            ),
            evidence={"admin_enabled_registries": creds_info},
            remediation=(
                "Disable the admin user on all production registries:\n"
                "  az acr update --name <name> --admin-enabled false\n\n"
                "Use Entra ID-backed authentication instead:\n"
                "  az acr login --name <name>  # uses current az login identity\n"
                "Assign AcrPull/AcrPush roles to specific service principals or managed identities."
            ),
            mitre=["T1078.004", "T1195.002"],
            cwe=["CWE-798"],
        ))

    # AKS clusters
    print("    Checking AKS clusters...")
    aks_clusters = az(["aks", "list"], suppress_errors=True) or []
    exposed_aks = []
    for cluster in aks_clusters:
        api_profile = cluster.get("apiServerAccessProfile", {})
        authorized_ranges = api_profile.get("authorizedIpRanges")
        if not authorized_ranges:
            exposed_aks.append({
                "name": cluster.get("name"),
                "resourceGroup": cluster.get("resourceGroup"),
                "k8sVersion": cluster.get("kubernetesVersion"),
                "enableRbac": cluster.get("enableRbac", True),
            })

    if exposed_aks:
        findings.append(finding(
            fid="AZEPT-010",
            severity="HIGH",
            cvss=7.5,
            title=f"{len(exposed_aks)} AKS cluster(s) with API server accessible from all IPs",
            description=(
                f"{len(exposed_aks)} AKS cluster(s) have no authorized IP ranges configured — "
                "the Kubernetes API server (port 6443) is accessible from any internet address. "
                "Combined with any valid kubeconfig or weak RBAC, this enables direct cluster access. "
                "For each cluster, run the performing-aks-cluster-penetration-test skill."
            ),
            evidence={"exposed_aks_clusters": exposed_aks},
            remediation=(
                "Restrict API server access to specific IP ranges:\n"
                "  az aks update --name <name> --resource-group <rg> \\\n"
                "    --api-server-authorized-ip-ranges <ip-range>\n\n"
                "For internal-only clusters, enable private cluster mode:\n"
                "  az aks update --name <name> --resource-group <rg> --enable-private-cluster"
            ),
            mitre=["T1580"],
            cwe=["CWE-284"],
            references=["See skill: performing-aks-cluster-penetration-test"],
        ))

    return findings


# ---------------------------------------------------------------------------
# enum-network
# ---------------------------------------------------------------------------

def enum_network(args=None) -> list:
    findings = []
    print("[*] Enumerating network configuration...")

    # NSG rules
    print("    Checking NSG rules...")
    nsgs = az(["network", "nsg", "list"], suppress_errors=True) or []
    wildcard_rules = []
    exposed_mgmt = []

    for nsg in nsgs:
        nsg_name = nsg.get("name", "")
        rg = nsg.get("resourceGroup", "")
        for rule in (nsg.get("securityRules") or []):
            if rule.get("access") != "Allow" or rule.get("direction") != "Inbound":
                continue
            src = rule.get("sourceAddressPrefix", "")
            dest_port = rule.get("destinationPortRange", "")
            dest_port_ranges = rule.get("destinationPortRanges", [])
            priority = rule.get("priority", 9999)
            rule_name = rule.get("name", "")

            is_open = src in ("*", "0.0.0.0/0", "Internet", "Any")
            if not is_open:
                continue

            # Check for management port exposure
            ports_to_check = [dest_port] + dest_port_ranges
            for p in ports_to_check:
                if p in MGMT_PORTS:
                    exposed_mgmt.append({
                        "nsg": nsg_name,
                        "rule": rule_name,
                        "port": p,
                        "service": MGMT_PORTS[p],
                        "source": src,
                        "priority": priority,
                        "resourceGroup": rg,
                    })
                elif p == "*":
                    wildcard_rules.append({
                        "nsg": nsg_name,
                        "rule": rule_name,
                        "priority": priority,
                        "resourceGroup": rg,
                    })

    if exposed_mgmt:
        ssh_rdp = [r for r in exposed_mgmt if r["port"] in ("22", "3389")]
        findings.append(finding(
            fid="AZEPT-011",
            severity="HIGH" if ssh_rdp else "MEDIUM",
            cvss=8.0 if ssh_rdp else 6.5,
            title=f"{len(exposed_mgmt)} NSG rule(s) expose management ports to the internet",
            description=(
                f"{len(exposed_mgmt)} NSG inbound rules allow traffic from any source (*) "
                f"to management ports. {len(ssh_rdp)} SSH/RDP rules found. "
                "Internet-exposed management ports are a primary target for brute force, "
                "credential stuffing, and exploitation of known vulnerabilities."
            ),
            evidence={"exposed_management_ports": exposed_mgmt},
            remediation=(
                "Remove internet-facing management port rules.\n"
                "For SSH/RDP: use Azure Bastion (managed jump host with no public IP):\n"
                "  az network bastion create --name <name> --resource-group <rg> --vnet-name <vnet>\n\n"
                "If direct access is required, restrict source to specific IPs:\n"
                "  az network nsg rule update --nsg-name <nsg> --name <rule> \\\n"
                "    --source-address-prefixes <your-ip>/32"
            ),
            mitre=["T1021.022", "T1190"],
            cwe=["CWE-284"],
        ))

    if wildcard_rules:
        findings.append(finding(
            fid="AZEPT-012",
            severity="HIGH",
            cvss=8.5,
            title=f"{len(wildcard_rules)} NSG rule(s) allow ALL inbound ports from the internet",
            description=(
                f"{len(wildcard_rules)} NSG rule(s) use destinationPortRange: * combined with "
                "an internet source. This exposes every TCP/UDP port on associated resources — "
                "effectively disabling the firewall."
            ),
            evidence={"wildcard_inbound_rules": wildcard_rules},
            remediation=(
                "Immediately restrict or delete wildcard inbound NSG rules.\n"
                "Replace with explicit port rules for only the required services.\n"
                "Enable Microsoft Defender for Cloud Network recommendations."
            ),
            mitre=["T1190"],
            cwe=["CWE-284"],
        ))

    return findings


# ---------------------------------------------------------------------------
# enum-keyvault
# ---------------------------------------------------------------------------

def enum_keyvault(args=None) -> list:
    findings = []
    print("[*] Enumerating Key Vaults...")

    kvs = az(["keyvault", "list"], suppress_errors=True) or []
    if not kvs:
        print("    No Key Vaults found or insufficient permissions")
        return findings

    print(f"    {len(kvs)} Key Vault(s) found")

    public_kvs = []
    no_purge_protection = []
    accessible_secrets = []

    for kv in kvs:
        name = kv.get("name", "")
        rg = kv.get("resourceGroup", "")
        props = kv.get("properties", {})
        net_acls = props.get("networkAcls", {})
        default_action = net_acls.get("defaultAction", "Allow")
        purge_prot = props.get("enablePurgeProtection", False)

        if default_action == "Allow":
            public_kvs.append({"name": name, "resourceGroup": rg})

        if not purge_prot:
            no_purge_protection.append(name)

        # Attempt to list secrets (succeeds only if current principal has access)
        secrets = az(
            ["keyvault", "secret", "list", "--vault-name", name],
            suppress_errors=True
        )
        if secrets:
            accessible_secrets.append({
                "vault": name,
                "secret_count": len(secrets),
                "secret_names": [s.get("name") for s in secrets[:10]],
            })

    if accessible_secrets:
        findings.append(finding(
            fid="AZEPT-013",
            severity="HIGH",
            cvss=8.5,
            title=f"Current principal can list secrets in {len(accessible_secrets)} Key Vault(s)",
            description=(
                f"The current authenticated principal has List permission on secrets in "
                f"{len(accessible_secrets)} Key Vault(s). Secret names often reveal the purpose "
                "of stored credentials and provide a roadmap for further exploitation. "
                "Combined with Get permission, the actual secret values are retrievable."
            ),
            evidence={
                "accessible_vaults": accessible_secrets,
                "note": "Run: az keyvault secret show --vault-name <vault> --name <secret> to retrieve values",
            },
            remediation=(
                "Review and tighten Key Vault access policies — apply least privilege.\n"
                "Migrate from access policies to Azure RBAC for Key Vault:\n"
                "  az keyvault update --name <name> --enable-rbac-authorization true\n"
                "Enable Key Vault audit logging and alert on unusual access patterns."
            ),
            mitre=["T1555"],
            cwe=["CWE-284"],
        ))

    if public_kvs:
        findings.append(finding(
            fid="AZEPT-014",
            severity="MEDIUM",
            cvss=6.0,
            title=f"{len(public_kvs)} Key Vault(s) with public network access (no IP restrictions)",
            description=(
                f"{len(public_kvs)} Key Vault(s) have networkAcls.defaultAction=Allow — accessible "
                "from any network. While access still requires authentication, public exposure "
                "increases the attack surface for token theft and credential replay."
            ),
            evidence={"public_key_vaults": public_kvs},
            remediation=(
                "Restrict Key Vault to specific VNets or IP ranges:\n"
                "  az keyvault network-rule add --name <kv> --ip-address <cidr>\n"
                "  az keyvault update --name <kv> --default-action Deny"
            ),
            mitre=["T1555"],
            cwe=["CWE-284"],
        ))

    return findings


# ---------------------------------------------------------------------------
# escalation
# ---------------------------------------------------------------------------

def enum_escalation(args=None) -> list:
    findings = []
    print("[*] Analysing privilege escalation paths...")

    # Automation Accounts (code execution path)
    print("    Checking Automation Accounts...")
    automation_accounts = az(["automation", "account", "list"], suppress_errors=True) or []

    if automation_accounts:
        aa_details = []
        for aa in automation_accounts:
            name = aa.get("name", "")
            rg = aa.get("resourceGroup", "")
            runbooks = az(
                ["automation", "runbook", "list",
                 "--automation-account-name", name, "--resource-group", rg],
                suppress_errors=True
            ) or []
            aa_details.append({
                "name": name,
                "resourceGroup": rg,
                "runbook_count": len(runbooks),
                "runbooks": [r.get("name") for r in runbooks[:5]],
            })

        findings.append(finding(
            fid="AZEPT-015",
            severity="HIGH",
            cvss=8.0,
            title=f"{len(automation_accounts)} Azure Automation Account(s) — potential code execution path",
            description=(
                f"{len(automation_accounts)} Automation Account(s) found. If the current principal "
                "has Microsoft.Automation/automationAccounts/runbooks/write permission, it can create "
                "or modify runbooks that execute as the Automation Account's RunAs service principal. "
                "If that RunAs SP has Contributor or higher, this is a full privilege escalation path."
            ),
            evidence={"automation_accounts": aa_details},
            remediation=(
                "Audit Automation Account RunAs principal RBAC assignments:\n"
                "  az role assignment list --assignee <RunAs-SP-id> --all\n\n"
                "Restrict runbook creation/modification to authorized principals only.\n"
                "Migrate from RunAs accounts to Managed Identity (more auditable):\n"
                "  az automation account update --name <aa> --resource-group <rg> \\\n"
                "    --set identity.type=SystemAssigned"
            ),
            mitre=["T1098", "T1059"],
            cwe=["CWE-269"],
        ))

    # Logic Apps
    print("    Checking Logic Apps...")
    logic_apps = az(["logic", "workflow", "list"], suppress_errors=True) or []
    if logic_apps:
        running = [la for la in logic_apps if la.get("state") == "Enabled"]
        findings.append(finding(
            fid="AZEPT-016",
            severity="MEDIUM",
            cvss=6.0,
            title=f"{len(running)} enabled Logic App(s) — review trigger authorization",
            description=(
                f"{len(running)} Logic Apps are enabled. Logic App HTTP triggers that lack "
                "authentication allow unauthenticated invocation. If a Logic App performs actions "
                "as a high-privilege managed identity (storage access, email sending, database calls), "
                "this is an unauthenticated action execution path."
            ),
            evidence={
                "total_logic_apps": len(logic_apps),
                "enabled": len(running),
                "names": [la.get("name") for la in running[:10]],
            },
            remediation=(
                "Audit Logic App HTTP trigger access keys and restrict to specific IPs.\n"
                "Require OAuth authentication on all public HTTP triggers.\n"
                "Review the managed identity assigned to each Logic App and its RBAC roles."
            ),
            mitre=["T1059", "T1098"],
            cwe=["CWE-306"],
        ))

    return findings


# ---------------------------------------------------------------------------
# imds subcommand
# ---------------------------------------------------------------------------

def cmd_imds(args):
    print("[*] Probing Azure Instance Metadata Service (IMDS)...")
    print("    IMDS is accessible from inside Azure VMs only — no authentication required")
    print()

    # Basic connectivity check
    instance = imds_get("/metadata/instance?api-version=2021-02-01")
    if not instance:
        print("[!] IMDS not reachable — this machine may not be an Azure VM, or IMDS is blocked")
        print("    If you are inside an Azure VM, ensure curl is installed and 169.254.169.254 is routable")
        return

    compute = instance.get("compute", {})
    network = instance.get("network", {})

    print(f"[+] IMDS REACHABLE — running on Azure VM")
    print()
    print("=== INSTANCE METADATA ===")
    print(f"  VM Name:        {compute.get('name')}")
    print(f"  Resource Group: {compute.get('resourceGroupName')}")
    print(f"  Subscription:   {compute.get('subscriptionId')}")
    print(f"  Location:       {compute.get('location')}")
    print(f"  VM Size:        {compute.get('vmSize')}")
    print(f"  OS:             {compute.get('osType')} / {compute.get('offer')} {compute.get('version')}")

    # Tags — sometimes contain secrets
    tags = compute.get("tags", {})
    if tags:
        print(f"\n  Tags (check for sensitive values):")
        for k, v in tags.items():
            print(f"    {k} = {v}")

    # Managed identity check
    mi = compute.get("managedIdentity", {})
    user_assigned = mi if isinstance(mi, dict) else {}
    print(f"\n  Managed Identity: {'YES' if mi else 'NOT configured'}")

    print()
    print("=== TOKEN ACQUISITION ===")

    # Try to get a management token
    mgmt_token_data = imds_get(
        "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
    )

    if mgmt_token_data and mgmt_token_data.get("access_token"):
        token = mgmt_token_data["access_token"]
        expires = mgmt_token_data.get("expires_on", "unknown")
        print(f"[+] Azure Management API token acquired (expires: {expires})")
        print(f"    Token preview: {token[:40]}...")
        print()
        print("  Use this token to enumerate Azure resources:")
        print(f"  TOKEN=\"{token[:40]}...\"")
        print(f"  curl -H \"Authorization: Bearer $TOKEN\" \\")
        print(f"    \"https://management.azure.com/subscriptions?api-version=2020-01-01\"")
        print()

        # Try to determine subscription ID
        sub_id = compute.get("subscriptionId", "")
        if sub_id:
            print(f"  Enumerate resources in subscription {sub_id}:")
            print(f"  curl -H \"Authorization: Bearer $TOKEN\" \\")
            print(f"    \"https://management.azure.com/subscriptions/{sub_id}/resources?api-version=2021-04-01\"")
    else:
        print("[!] Management token not available — no managed identity configured on this VM")
        print("    Or the managed identity does not have access to management.azure.com")

    # Try Key Vault token
    kv_token_data = imds_get(
        "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/"
    )
    if kv_token_data and kv_token_data.get("access_token"):
        print(f"[+] Key Vault token acquired — this identity may have Key Vault access")
        print(f"    Check: az keyvault list --output json")
    else:
        print("[!] Key Vault token not available")

    # Try storage token
    storage_token_data = imds_get(
        "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"
    )
    if storage_token_data and storage_token_data.get("access_token"):
        print(f"[+] Storage token acquired — this identity has storage access")

    print()
    print("=== NETWORK INTERFACES ===")
    ifaces = network.get("interface", [])
    for iface in ifaces:
        for addr in iface.get("ipv4", {}).get("ipAddress", []):
            priv = addr.get("privateIpAddress", "")
            pub = addr.get("publicIpAddress", "")
            print(f"  Private: {priv}  Public: {pub or 'none'}")


# ---------------------------------------------------------------------------
# Full enumerate runner
# ---------------------------------------------------------------------------

def cmd_enumerate(args):
    all_findings = []
    modules = [
        ("Identity", enum_identity),
        ("Resources", enum_resources),
        ("Storage", enum_storage),
        ("Compute", enum_compute),
        ("Network", enum_network),
        ("KeyVault", enum_keyvault),
        ("Escalation", enum_escalation),
    ]

    for name, fn in modules:
        results = fn()
        print(f"    → {len(results)} finding(s)")
        all_findings.extend(results)

    counts = defaultdict(int)
    for f in all_findings:
        counts[f["severity"]] += 1

    print()
    print("=" * 60)
    print("AZURE ENUMERATION COMPLETE")
    print("=" * 60)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[sev]:
            print(f"  {severity_icon(sev)} {sev}: {counts[sev]}")
    print(f"  Total: {len(all_findings)}")

    output_data = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": "performing-azure-offensive-enumeration",
        },
        "findings": all_findings,
    }

    if getattr(args, "output", None):
        Path(args.output).write_text(json.dumps(output_data, indent=2))
        print(f"\n[*] Findings saved to: {args.output}")
    else:
        print(json.dumps(output_data, indent=2))


def cmd_module(fn, args):
    results = fn()
    for f in results:
        print(f"\n{severity_icon(f['severity'])} {f['id']} [{f['severity']} CVSS {f['cvss']}]")
        print(f"  {f['title']}")
        if f.get("evidence"):
            first_key = next(iter(f["evidence"]))
            print(f"  Evidence ({first_key}): {str(f['evidence'][first_key])[:120]}")
    print(f"\n{len(results)} finding(s)")


# ---------------------------------------------------------------------------
# report subcommand
# ---------------------------------------------------------------------------

def cmd_report(args):
    findings_path = Path(args.findings)
    if not findings_path.exists():
        print(f"[ERROR] Findings file not found: {args.findings}")
        sys.exit(1)

    data = json.loads(findings_path.read_text())
    all_findings = data.get("findings", [])

    if args.format == "json":
        output = json.dumps(data, indent=2)
    else:
        output = _render_markdown(all_findings)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Report written to: {args.output}")
    else:
        print(output)


def _render_markdown(findings: list) -> str:
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_f = sorted(findings, key=lambda x: sev_order.get(x["severity"], 9))
    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1

    lines = [
        "# Azure Offensive Enumeration — Findings Report",
        f"\n**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Total Findings:** {len(findings)}",
        "",
        "## Risk Distribution",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        lines.append(f"| {severity_icon(sev)} {sev} | {counts.get(sev, 0)} |")

    lines += ["", "## Findings Index", "", "| ID | Severity | CVSS | Title |",
              "|----|----------|------|-------|"]
    for f in sorted_f:
        lines.append(f"| {f['id']} | {severity_icon(f['severity'])} {f['severity']} | {f['cvss']} | {f['title']} |")

    lines += ["", "---", ""]
    for f in sorted_f:
        lines += [
            f"### {f['id']} · CVSS {f['cvss']}",
            f"**{f['title']}**",
            "",
            f"**Severity:** {severity_icon(f['severity'])} {f['severity']}  ",
            f"**MITRE:** {', '.join(f.get('mitre', []))}  ",
            f"**CWE:** {', '.join(f.get('cwe', []))}",
            "",
            f.get("description", ""),
            "",
            "**Evidence**",
            f"```json\n{json.dumps(f.get('evidence', {}), indent=2)}\n```",
            "",
            "**Remediation**",
            f"```\n{f.get('remediation', '')}\n```",
            "",
            "---",
            "",
        ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Azure Offensive Enumeration Agent — authorized Azure tenant assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("auth", help="Verify authentication and show current context")

    p_enum = sub.add_parser("enumerate", help="Run all enumeration modules")
    p_enum.add_argument("--subscription", "-s", help="Scope to specific subscription ID")
    p_enum.add_argument("--output", "-o", help="Write findings JSON to file")

    for name in ["enum-identity", "enum-resources", "enum-storage",
                 "enum-compute", "enum-network", "enum-keyvault", "escalation"]:
        p = sub.add_parser(name, help=f"Run {name} module only")
        p.add_argument("--subscription", "-s")
        p.add_argument("--output", "-o")

    sub.add_parser("imds", help="IMDS exploitation — run from inside Azure VM")

    p_report = sub.add_parser("report", help="Generate findings report")
    p_report.add_argument("--findings", required=True)
    p_report.add_argument("--format", choices=["md", "json"], default="md")
    p_report.add_argument("--output", "-o")

    args = parser.parse_args()

    module_map = {
        "enum-identity": enum_identity,
        "enum-resources": enum_resources,
        "enum-storage": enum_storage,
        "enum-compute": enum_compute,
        "enum-network": enum_network,
        "enum-keyvault": enum_keyvault,
        "escalation": enum_escalation,
    }

    if args.cmd == "auth":
        cmd_auth(args)
    elif args.cmd == "enumerate":
        cmd_enumerate(args)
    elif args.cmd in module_map:
        cmd_module(module_map[args.cmd], args)
    elif args.cmd == "imds":
        cmd_imds(args)
    elif args.cmd == "report":
        cmd_report(args)


if __name__ == "__main__":
    main()
