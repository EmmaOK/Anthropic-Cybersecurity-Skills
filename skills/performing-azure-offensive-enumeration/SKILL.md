---
name: performing-azure-offensive-enumeration
description: >-
  Offensive enumeration of Azure / Entra ID environments — identities, service
  principals, managed identities, RBAC, storage, compute, network, and Key Vault,
  including IMDS exploitation. Mapped to MITRE ATT&CK Cloud and the CIS Azure Benchmark.
domain: cybersecurity
subdomain: cloud-security
tags:
  - azure
  - entra-id
  - azure-ad
  - offensive-security
  - enumeration
  - privilege-escalation
  - service-principal
  - managed-identity
  - imds
  - roadtools
  - microburst
  - rbac
  - storage-enumeration
  - cloud-pentest
  - red-team
  - T1526
  - T1087.004
  - T1078.004
  - T1552.008
  - T1530
  - T1580
  - T1098
  - T1484.002
  - T1069.003
  - T1555
version: '1.0'
author: emmanuelokonkwo
license: Apache-2.0
---

# Performing Azure Offensive Enumeration

## Metadata
- **Subdomain:** cloud-security
- **Tags:** `azure` `entra-id` `azure-ad` `offensive-security` `enumeration` `privilege-escalation` `service-principal` `managed-identity` `imds` `roadtools` `microburst` `rbac` `storage-enumeration` `cloud-pentest` `red-team`
- **Has Script:** true
- **Script Subcommands:** `auth` · `enumerate` · `enum-identity` · `enum-resources` · `enum-storage` · `enum-compute` · `enum-network` · `enum-keyvault` · `escalation` · `imds` · `report`
- **MITRE ATT&CK:** T1526, T1087.004, T1078.004, T1552.008, T1530, T1580, T1098, T1484.002
- **Frameworks:** MITRE ATT&CK Cloud · CIS Azure Benchmark v2.0 · NIST SP 800-207 · Microsoft Security Benchmark

---

## Overview

This skill covers the offensive enumeration phase of an authorized Azure penetration test — mapping the full attack surface of an Azure tenant before attempting exploitation. It covers eight attack surfaces: Entra ID (Azure AD) identity, subscription and RBAC structure, storage account exposure, compute and container workloads, network configuration, Key Vault access, automation-based code execution, and Azure Instance Metadata Service (IMDS) exploitation from within Azure VMs.

**Primary toolchain:** `az` CLI (all subcommands), ROADtools (Entra ID deep-dive), MicroBurst (PowerShell), AzureHound (BloodHound for Azure), Microsoft Graph API.

The included `agent.py` automates enumeration using the `az` CLI — no additional pip installs required. It produces structured JSON findings that feed directly into a pentest report.

**Relationship to AKS assessment:** Azure enumeration is the pre-cluster phase. If AKS clusters are discovered during this enumeration, feed the cluster name and resource group into the `performing-aks-cluster-penetration-test` skill.

---

## Authorization Requirements

Before running this assessment:

1. Written authorization from the **Azure subscription owner** or **Entra ID Global Administrator** covering:
   - The specific subscription(s) and tenant ID in scope
   - Whether Entra ID (Azure AD) directory enumeration is in scope
   - Whether active exploitation (token theft, privilege escalation attempts) is authorized
2. For IMDS exploitation: confirm the specific VM(s) authorized for testing
3. Document the authorization reference number in all output files

> **Never run this skill against a tenant you do not have explicit written authorization to assess.**

---

## Prerequisites

### Tools
```bash
# Azure CLI (required for all az-based subcommands)
brew install azure-cli          # macOS
apt-get install azure-cli       # Debian/Ubuntu

# ROADtools (deep Entra ID enumeration — optional but strongly recommended)
pip install roadtools roadtx

# AzureHound (BloodHound data collector for Azure — optional)
# Download binary from: https://github.com/BloodHoundAD/AzureHound/releases

# MicroBurst (PowerShell — optional, Windows/macOS with pwsh)
Install-Module -Name MicroBurst -Scope CurrentUser
```

### Authentication Options

The script supports four authentication modes. The current mode is auto-detected from the az CLI context.

**Option 1 — Interactive Browser Login (recommended for user-context assessment)**
```bash
az login
az account set --subscription <subscription-id>
```

**Option 2 — Service Principal (for automated / CI assessment)**
```bash
az login --service-principal \
  --username <client-id> \
  --password <client-secret> \
  --tenant <tenant-id>
```

**Option 3 — Device Code (for restricted environments)**
```bash
az login --use-device-code
```

**Option 4 — Managed Identity (from inside an Azure VM or container)**
```bash
az login --identity
# Or: use the IMDS subcommand directly — no az login needed
```

### Permission Requirements by Phase

| Phase | Minimum Permission | Notes |
|-------|-------------------|-------|
| Identity enumeration | Directory Reader | Or: Global Reader |
| Subscription resources | Reader on subscription | Lists all resources |
| Storage contents | Storage Blob Data Reader | Required to list blobs |
| Key Vault secrets | Key Vault Reader | Lists vaults; secrets need Get permission |
| RBAC analysis | Reader on subscription | Lists all role assignments |
| Privilege escalation | Varies | See Phase 7 |

---

## Assessment Workflow

### Phase 1 — Authentication & Context

**Objective:** Confirm who you are, what tenants and subscriptions are accessible, and what your current permissions are.

```bash
# Verify current authentication:
python3 agent.py auth

# Manual verification:
az account show --output json
az account list --output json  # All accessible subscriptions
az ad signed-in-user show --output json  # Your user object
```

**Key questions:**
- What tenant ID and display name are we in?
- How many subscriptions are accessible?
- What directory roles does the current principal hold?
- Is this a user, service principal, or managed identity?

---

### Phase 2 — Entra ID (Azure AD) Identity Enumeration

**Objective:** Map all identities — users, service principals, app registrations, and their permissions.

**MITRE:** T1087.004 — Account Discovery: Cloud Account

#### 2.1 — Enumerate users

```bash
# All users in the tenant:
az ad user list --output json | python3 -c "
import json, sys
users = json.load(sys.stdin)
print(f'{len(users)} users found')
for u in users[:20]:
    print(f\"  {u['userPrincipalName']} | {u.get('jobTitle','')} | {'ADMIN' if u.get('accountEnabled') else 'disabled'}\")
"
```

**High-value targets:** Global Administrators, Privileged Role Administrators, Application Administrators, break-glass accounts.

#### 2.2 — Enumerate service principals

Service principals are non-human identities used by applications and automation. They are the highest-value targets in Azure — a compromised service principal with Contributor on a subscription grants full resource control.

```bash
az ad sp list --all --output json | python3 -c "
import json, sys
sps = json.load(sys.stdin)
print(f'{len(sps)} service principals found')
for sp in sps:
    tags = sp.get('tags', [])
    if any('WindowsAzureActiveDirectoryIntegratedApp' not in t for t in tags):
        print(f\"  {sp['displayName']} | AppId: {sp['appId']} | Type: {sp.get('servicePrincipalType')}\")
" 2>/dev/null | head -40
```

#### 2.3 — Enumerate app registrations and their permissions

```bash
# App registrations with admin-consented Graph API permissions:
az ad app list --all --output json | python3 -c "
import json, sys
apps = json.load(sys.stdin)
high_perms = ['Application.ReadWrite.All', 'Directory.ReadWrite.All',
              'RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All',
              'User.ReadWrite.All', 'GroupMember.ReadWrite.All']
for app in apps:
    reqs = app.get('requiredResourceAccess', [])
    for req in reqs:
        for r in req.get('resourceAccess', []):
            # type 'Role' = application permission (more dangerous than 'Scope'/delegated)
            if r.get('type') == 'Role':
                print(f\"  {app['displayName']}: AppRole {r['id']}\")
"
```

#### 2.4 — ROADtools deep enumeration (highly recommended)

ROADtools dumps the entire Entra ID directory into a local SQLite database, enabling offline analysis of the full identity graph.

```bash
# Authenticate ROADtools using existing az credentials:
roadrecon auth --access-token "$(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)"

# Dump all directory objects:
roadrecon gather

# Query the local database for high-privilege service principals:
roadrecon plugin policies     # Conditional access policies
roadrecon plugin bloodhound   # Export to BloodHound format

# Query the SQLite database directly:
sqlite3 roadrecon.db "
SELECT displayName, appId, servicePrincipalType
FROM ServicePrincipals
WHERE servicePrincipalType = 'Application'
ORDER BY createdDateTime DESC LIMIT 20;
"
```

#### 2.5 — Enumerate directory roles and members

```bash
# Who is in Global Administrator?
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/directoryRoles" \
  --headers "Content-Type=application/json" \
  --query "value[].{name:displayName, id:id}" --output json

# Members of a specific role (replace with role ID from above):
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/directoryRoles/<role-id>/members" \
  --query "value[].{name:displayName, upn:userPrincipalName, type:\"@odata.type\"}" --output json
```

---

### Phase 3 — Subscription & RBAC Enumeration

**Objective:** Map Azure resource structure and identify over-privileged role assignments.

**MITRE:** T1526 — Cloud Service Discovery · T1069.003 — Permission Groups Discovery: Cloud Groups

#### 3.1 — List all subscriptions and management groups

```bash
az account list --output json | python3 -c "
import json, sys
for sub in json.load(sys.stdin):
    print(f\"{sub['id']} | {sub['name']} | {sub['state']} | Tenant: {sub['tenantId']}\")
"

# Management group hierarchy:
az account management-group list --output json 2>/dev/null
```

#### 3.2 — Enumerate all resource groups and resources

```bash
# Resource groups:
az group list --output json | python3 -c "
import json, sys
for rg in json.load(sys.stdin):
    print(f\"{rg['name']} | {rg['location']}\")
"

# All resources in subscription:
az resource list --output json | python3 -c "
import json, sys, collections
resources = json.load(sys.stdin)
type_counts = collections.Counter(r['type'] for r in resources)
print(f'Total resources: {len(resources)}')
for rtype, count in type_counts.most_common(20):
    print(f'  {count:4d}  {rtype}')
"
```

#### 3.3 — Enumerate all RBAC role assignments (critical step)

```bash
# All role assignments across the subscription:
az role assignment list --all --output json | python3 -c "
import json, sys
assignments = json.load(sys.stdin)
HIGH_ROLES = {'Owner', 'Contributor', 'User Access Administrator',
              'Role Based Access Control Administrator'}
print(f'{len(assignments)} total role assignments')
for a in assignments:
    role = a.get('roleDefinitionName','')
    if role in HIGH_ROLES:
        principal = a.get('principalName') or a.get('principalId')
        ptype = a.get('principalType','')
        scope = a.get('scope','')
        print(f'  [HIGH] {role} → {ptype}/{principal} @ {scope}')
"
```

**Critical finding pattern:** Service principals with Owner or Contributor at the subscription scope — these can create resources, read all secrets, and escalate to Global Admin via federation attacks.

#### 3.4 — Check for custom role definitions with dangerous actions

```bash
az role definition list --custom-role-only --output json | python3 -c "
import json, sys
DANGEROUS = ['*', '*/write', '*/delete', 'Microsoft.Authorization/*/Write',
             'Microsoft.Authorization/elevateAccess/Action']
for role in json.load(sys.stdin):
    perms = role.get('permissions', [{}])
    for p in perms:
        for action in p.get('actions', []):
            if any(d in action for d in DANGEROUS):
                print(f\"DANGEROUS CUSTOM ROLE: {role['roleName']} — {action}\")
"
```

---

### Phase 4 — Storage Account Enumeration

**Objective:** Find publicly accessible blobs, weak SAS tokens, and storage accounts with overly permissive configuration.

**MITRE:** T1530 — Data from Cloud Storage · T1552.008 — Unsecured Credentials: Cloud Instance Metadata API

#### 4.1 — Enumerate all storage accounts

```bash
az storage account list --output json | python3 -c "
import json, sys
for sa in json.load(sys.stdin):
    name = sa['name']
    pub = sa.get('allowBlobPublicAccess')
    https_only = sa.get('enableHttpsTrafficOnly', True)
    tls = sa.get('minimumTlsVersion','')
    tier = sa.get('sku',{}).get('name','')
    print(f'{name}: public={pub} https_only={https_only} min_tls={tls} tier={tier}')
"
```

#### 4.2 — Check for public blob containers

```bash
# For each storage account with allowBlobPublicAccess=true:
SA_NAME="<target-storage-account>"

# List containers:
az storage container list \
  --account-name $SA_NAME \
  --auth-mode login \
  --output json | python3 -c "
import json, sys
for c in json.load(sys.stdin):
    pub = c.get('properties',{}).get('publicAccess','None')
    print(f\"{c['name']} | publicAccess={pub}\")
"

# Enumerate blobs in a public container (no auth needed):
az storage blob list \
  --account-name $SA_NAME \
  --container-name <container> \
  --auth-mode login \
  --output json | python3 -c "
import json, sys
blobs = json.load(sys.stdin)
for b in blobs[:20]:
    print(f\"{b['name']} | {b.get('properties',{}).get('contentLength',0)} bytes\")
"
```

#### 4.3 — Check for SAS tokens in configuration or environment

```bash
# Scan App Service configuration for SAS tokens:
az webapp list --output json | python3 -c "
import json, sys
for app in json.load(sys.stdin):
    print(app['name'], app['resourceGroup'])
" | while read name rg; do
  az webapp config appsettings list \
    --name $name --resource-group $rg --output json 2>/dev/null | \
    python3 -c "
import json, sys, re
SAS_PAT = re.compile(r'(sv=|sig=|se=|sp=|sr=)')
for s in json.load(sys.stdin):
    if SAS_PAT.search(str(s.get('value',''))):
        print(f'SAS TOKEN IN APP SETTINGS: {s[\"name\"]}')
"
done
```

#### 4.4 — Test unauthenticated blob access (no credentials needed)

```bash
# Attempt to access a storage account endpoint without auth:
SA_NAME="<target>"
curl -s "https://${SA_NAME}.blob.core.windows.net/?comp=list" | python3 -c "
import sys, xml.etree.ElementTree as ET
data = sys.stdin.read()
if '<EnumerationResults' in data:
    root = ET.fromstring(data)
    for c in root.iter('Container'):
        print('PUBLIC CONTAINER:', c.find('Name').text)
elif 'AuthenticationFailed' in data:
    print('NOT public — authentication required')
elif 'ResourceNotFound' in data:
    print('Storage account not found')
"
```

---

### Phase 5 — Compute & Container Enumeration

**Objective:** Identify VMs with exposed management interfaces, accessible container registries, and misconfigured AKS clusters.

**MITRE:** T1580 — Cloud Infrastructure Discovery

#### 5.1 — Virtual machines

```bash
az vm list --show-details --output json | python3 -c "
import json, sys
vms = json.load(sys.stdin)
print(f'{len(vms)} VMs found')
for vm in vms:
    name = vm['name']
    rg = vm['resourceGroup']
    pub_ip = vm.get('publicIps','')
    state = vm.get('powerState','')
    os_type = vm.get('storageProfile',{}).get('osDisk',{}).get('osType','')
    print(f'  {name} | {os_type} | {state} | PublicIP: {pub_ip or \"none\"} | RG: {rg}')
"
```

#### 5.2 — Check NSG rules for exposed management ports

```bash
az network nsg list --output json | python3 -c "
import json, sys
MGMT_PORTS = {'22': 'SSH', '3389': 'RDP', '5985': 'WinRM-HTTP',
              '5986': 'WinRM-HTTPS', '445': 'SMB', '1433': 'MSSQL'}
for nsg in json.load(sys.stdin):
    for rule in nsg.get('securityRules', []):
        if rule.get('access') != 'Allow' or rule.get('direction') != 'Inbound':
            continue
        src = rule.get('sourceAddressPrefix','')
        dest_port = rule.get('destinationPortRange','')
        if src in ('*', '0.0.0.0/0', 'Internet', 'Any') and dest_port in MGMT_PORTS:
            print(f\"EXPOSED MGMT PORT: {nsg['name']} — {dest_port} ({MGMT_PORTS[dest_port]}) from {src}\")
        elif src in ('*', '0.0.0.0/0', 'Internet', 'Any') and dest_port == '*':
            print(f\"WILDCARD INBOUND: {nsg['name']} — ALL PORTS from {src}\")
"
```

#### 5.3 — Azure Container Registry

```bash
# List ACR registries:
az acr list --output json | python3 -c "
import json, sys
for acr in json.load(sys.stdin):
    name = acr['name']
    admin_enabled = acr.get('adminUserEnabled', False)
    public_access = acr.get('publicNetworkAccess','Enabled')
    sku = acr.get('sku',{}).get('name','')
    print(f'{name} | SKU={sku} | admin_user={admin_enabled} | public_access={public_access}')
    if admin_enabled:
        print(f'  [!] Admin user enabled — retrieve creds:')
        print(f'  az acr credential show --name {name}')
"
```

#### 5.4 — AKS clusters

```bash
az aks list --output json | python3 -c "
import json, sys
for cluster in json.load(sys.stdin):
    name = cluster['name']
    rg = cluster['resourceGroup']
    k8s_ver = cluster.get('kubernetesVersion','')
    api_server_authorized = cluster.get('apiServerAccessProfile',{}).get('authorizedIpRanges')
    rbac = cluster.get('enableRbac', True)
    print(f'{name} ({rg}) | k8s {k8s_ver} | RBAC={rbac}')
    if not api_server_authorized:
        print(f'  [!] API server accessible from ALL IPs — no authorized IP ranges set')
"
# For each AKS cluster found, proceed with: performing-aks-cluster-penetration-test
```

#### 5.5 — Azure Functions and App Services (potential code execution)

```bash
az functionapp list --output json | python3 -c "
import json, sys
for app in json.load(sys.stdin):
    name = app['name']
    state = app.get('state','')
    pub_url = app.get('defaultHostName','')
    https_only = app.get('httpsOnly', False)
    print(f'{name} | {state} | https_only={https_only} | {pub_url}')
"
```

---

### Phase 6 — Network & Exposure Enumeration

**Objective:** Map publicly reachable attack surface — exposed IPs, open management ports, and unprotected subnets.

#### 6.1 — Public IP addresses

```bash
az network public-ip list --output json | python3 -c "
import json, sys
for pip in json.load(sys.stdin):
    ip = pip.get('ipAddress','unassigned')
    assoc = pip.get('ipConfiguration',{}).get('id','unassigned')
    sku = pip.get('sku',{}).get('name','')
    print(f'{ip} | SKU={sku} | Associated: {assoc.split(\"/\")[-1] if assoc != \"unassigned\" else \"none\"}')
"
```

#### 6.2 — Full NSG rule audit

```bash
az network nsg list --output json | python3 -c "
import json, sys
for nsg in json.load(sys.stdin):
    name = nsg['name']
    rg = nsg['resourceGroup']
    for rule in nsg.get('securityRules',[]):
        if rule['access'] == 'Allow' and rule['direction'] == 'Inbound':
            src = rule.get('sourceAddressPrefix','')
            port = rule.get('destinationPortRange','')
            priority = rule.get('priority',9999)
            if src in ('*', '0.0.0.0/0', 'Internet', 'Any'):
                print(f'  ALLOW INBOUND: {name} P={priority} port={port} from {src}')
"
```

#### 6.3 — VNet peering (lateral movement between VNets)

```bash
az network vnet list --output json | python3 -c "
import json, sys
for vnet in json.load(sys.stdin):
    peers = vnet.get('virtualNetworkPeerings', [])
    if peers:
        print(f\"{vnet['name']} has {len(peers)} peering(s):\")
        for p in peers:
            remote = p.get('remoteVirtualNetwork',{}).get('id','')
            state = p.get('peeringState','')
            allows_gw = p.get('allowGatewayTransit', False)
            print(f\"  → {remote.split('/')[-1]} | state={state} | gateway_transit={allows_gw}\")
"
```

---

### Phase 7 — Key Vault Enumeration

**Objective:** Identify accessible Key Vaults, misconfigured network access, and readable secrets.

**MITRE:** T1555 — Credentials from Password Stores

#### 7.1 — List all Key Vaults

```bash
az keyvault list --output json | python3 -c "
import json, sys
for kv in json.load(sys.stdin):
    name = kv['name']
    rg = kv.get('resourceGroup','')
    # Check network rules:
    props = kv.get('properties',{})
    net_acls = props.get('networkAcls',{})
    default_action = net_acls.get('defaultAction','Allow')
    bypass = net_acls.get('bypass','None')
    soft_delete = props.get('enableSoftDelete', True)
    purge_prot = props.get('enablePurgeProtection', False)
    print(f'{name} ({rg})')
    print(f'  Network: defaultAction={default_action} bypass={bypass}')
    print(f'  SoftDelete={soft_delete} PurgeProtection={purge_prot}')
    if default_action == 'Allow':
        print(f'  [!] PUBLIC NETWORK ACCESS — no IP restrictions')
"
```

#### 7.2 — Attempt to list secrets (if permissions allow)

```bash
KV_NAME="<target-key-vault>"

# List secret names (requires list permission on secrets):
az keyvault secret list --vault-name $KV_NAME --output json | python3 -c "
import json, sys
secrets = json.load(sys.stdin)
print(f'{len(secrets)} secrets accessible:')
for s in secrets:
    name = s['name']
    enabled = s.get('attributes',{}).get('enabled',True)
    exp = s.get('attributes',{}).get('expires','no expiry')
    print(f'  {name} | enabled={enabled} | expires={exp}')
"

# Read a specific secret (requires get permission):
az keyvault secret show --vault-name $KV_NAME --name <secret-name> \
  --query value --output tsv
```

#### 7.3 — Key Vault access policy audit

```bash
az keyvault show --name $KV_NAME --output json | python3 -c "
import json, sys
kv = json.load(sys.stdin)
policies = kv.get('properties',{}).get('accessPolicies',[])
HIGH_PERMS = {'all', 'purge', 'backup', 'restore'}
for p in policies:
    object_id = p['objectId']
    secret_perms = set(p.get('permissions',{}).get('secrets',[]))
    key_perms = set(p.get('permissions',{}).get('keys',[]))
    if HIGH_PERMS & secret_perms or HIGH_PERMS & key_perms:
        print(f'HIGH-PERM POLICY: {object_id}')
        print(f'  secrets: {secret_perms}')
        print(f'  keys: {key_perms}')
"
```

---

### Phase 8 — Privilege Escalation Path Analysis

**Objective:** Identify paths from the current principal to higher privilege — subscription Owner, Global Admin, or code execution on compute.

**MITRE:** T1098 — Account Manipulation · T1484.002 — Domain or Tenant Policy Modification

#### 8.1 — Service principal → subscription escalation

A service principal with `Microsoft.Authorization/roleAssignments/write` permission on any scope can grant itself or another principal a higher role.

```bash
# Check current principal's effective permissions:
az role assignment list \
  --assignee "$(az account show --query user.name -o tsv)" \
  --all --output json | python3 -c "
import json, sys
ESCALATION_ROLES = {
    'Owner': 'Can grant any role — full subscription takeover',
    'User Access Administrator': 'Can grant Owner — full subscription takeover',
    'Contributor': 'Can create Automation Accounts and execute runbooks',
    'Role Based Access Control Administrator': 'Can grant roles without Owner'
}
for a in json.load(sys.stdin):
    role = a.get('roleDefinitionName','')
    if role in ESCALATION_ROLES:
        print(f'ESCALATION PATH: {role} at {a[\"scope\"]}')
        print(f'  Impact: {ESCALATION_ROLES[role]}')
"
```

#### 8.2 — Automation Account escalation (code execution)

Azure Automation Accounts execute runbooks as a RunAs service principal. If the RunAs principal has Contributor or higher, and the current principal can create/modify runbooks, this is a code execution → privilege escalation path.

```bash
az automation account list --output json 2>/dev/null | python3 -c "
import json, sys
for aa in json.load(sys.stdin):
    name = aa['name']
    rg = aa['resourceGroup']
    print(f'AUTOMATION ACCOUNT: {name} ({rg})')
    print(f'  Check: can current principal create/run runbooks?')
    print(f'  az automation runbook list --automation-account-name {name} --resource-group {rg}')
"
```

#### 8.3 — Managed identity enumeration and abuse

Managed identities assigned to VMs, containers, or functions can be retrieved via IMDS and used to call Azure APIs without credentials.

```bash
# List managed identities:
az identity list --output json | python3 -c "
import json, sys
for mi in json.load(sys.stdin):
    name = mi['name']
    client_id = mi.get('clientId','')
    principal_id = mi.get('principalId','')
    print(f'{name} | clientId={client_id} | principalId={principal_id}')
"

# Check what roles each managed identity holds:
for PRINCIPAL_ID in $(az identity list --query '[].principalId' -o tsv); do
  az role assignment list --assignee $PRINCIPAL_ID --all --output json | \
    python3 -c "
import json,sys
for a in json.load(sys.stdin):
    print(f\"MI ROLE: {a['roleDefinitionName']} @ {a['scope']}\")
"
done
```

#### 8.4 — Global Admin via application permission grant

If the current principal can consent to `RoleManagement.ReadWrite.Directory` for an app, it can grant Global Admin roles:

```bash
# Check if current user is Application Administrator:
az ad signed-in-user show --query "userPrincipalName" -o tsv
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/me/memberOf" \
  --query "value[].displayName" --output json
```

---

### Phase 9 — IMDS Exploitation (from inside Azure VM)

**Objective:** Extract instance metadata and OAuth tokens from the Azure Instance Metadata Service — accessible from any Azure VM/container at 169.254.169.254 with no credentials.

**MITRE:** T1552.008 — Unsecured Credentials: Cloud Instance Metadata API

#### 9.1 — Retrieve instance metadata

```bash
# No authentication needed — IMDS is accessible from inside the VM only
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | \
  python3 -m json.tool
```

**Key fields to extract:** `subscriptionId`, `resourceGroupName`, `name` (VM name), `location`, `tags` (may contain secrets), `userAssignedIdentities`.

#### 9.2 — Retrieve managed identity token

```bash
# Get OAuth token for the Azure Management API:
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
token = data.get('access_token','')
expires = data.get('expires_on','')
print(f'Token acquired (expires {expires}):')
print(f'{token[:80]}...')
"
```

#### 9.3 — Use token to enumerate Azure resources

```bash
# Store the token:
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | \
  python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

# List subscriptions accessible to this identity:
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01" | \
  python3 -m json.tool

# List all resources in a subscription:
SUB_ID="<subscription-id-from-instance-metadata>"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resources?api-version=2021-04-01" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data.get('value', []):
    print(f\"{r['type']}: {r['name']}\")
"
```

#### 9.4 — Attempt Key Vault token

```bash
# Get token for Key Vault:
KV_TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/" | \
  python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))")

if [ -n "$KV_TOKEN" ]; then
  KV_NAME="<vault-name>"
  curl -s -H "Authorization: Bearer $KV_TOKEN" \
    "https://${KV_NAME}.vault.azure.net/secrets?api-version=7.4" | python3 -m json.tool
fi
```

---

## Automated Assessment with agent.py

```bash
# Check authentication:
python3 agent.py auth

# Full enumeration (all modules):
python3 agent.py enumerate --output findings.json

# Targeted enumeration:
python3 agent.py enum-identity   --output identity_findings.json
python3 agent.py enum-resources  --subscription <sub-id>
python3 agent.py enum-storage    --output storage_findings.json
python3 agent.py enum-compute
python3 agent.py enum-network
python3 agent.py enum-keyvault
python3 agent.py escalation      --output escalation_findings.json

# IMDS (from inside Azure VM — no az login needed):
python3 agent.py imds

# Report:
python3 agent.py report --findings findings.json --format md --output azure_enum_report.md
```

---

## High-Value Finding Patterns

| Pattern | Typical CVSS | Where Found |
|---------|-------------|-------------|
| Service principal with Owner at subscription scope | 9.8 | RBAC role assignments |
| Public blob container with sensitive data | 9.1 | Storage accounts |
| ACR with admin user enabled | 8.5 | Container Registry |
| VM with public IP + RDP/SSH open from * | 8.0 | NSG rules |
| Automation Account with Contributor RunAs | 8.0 | Automation Accounts |
| Key Vault with public network access | 7.5 | Key Vault config |
| App registration with Directory.ReadWrite.All | 7.5 | App registrations |
| IMDS token accessible from compromised VM | 7.0 | IMDS endpoint |
| Storage account with shared key access | 6.5 | Storage account config |
| Custom role with wildcard actions | 6.5 | Custom role definitions |

---

## References

- [ROADtools documentation](https://github.com/dirkjanm/ROADtools)
- [MicroBurst](https://github.com/NetSPI/MicroBurst)
- [AzureHound](https://github.com/BloodHoundAD/AzureHound)
- [Hacking the Cloud — Azure](https://hackingthe.cloud/azure/)
- [Azure privilege escalation paths (Andy Robbins)](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [CIS Microsoft Azure Foundations Benchmark v2.0](https://www.cisecurity.org/benchmark/azure)
- [Microsoft Identity Platform — service principals](https://learn.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
