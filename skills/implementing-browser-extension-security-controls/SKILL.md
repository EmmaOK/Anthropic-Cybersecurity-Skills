---
name: implementing-browser-extension-security-controls
description: >-
  Audit, control, and enforce browser extension security for a 400+ remote
  workforce where unmanaged extensions represent a significant data theft,
  credential harvesting, and supply chain risk. Covers extension inventory
  and risk assessment, allowlist-only enforcement via Chrome CBCM and Edge
  Intune policy, automated detection of malicious or overly permissive
  extensions, permission-based risk scoring, and response workflows for
  when a published extension is compromised or turns malicious post-install.
domain: cybersecurity
subdomain: endpoint-security
tags:
  - browser-extensions
  - browser-security
  - chrome-enterprise
  - microsoft-edge
  - supply-chain
  - endpoint-security
  - remote-workforce
  - data-loss-prevention
version: '1.0'
author: emmanuelokonkwo
license: Apache-2.0
nist_csf:
  - PR.PS-01
  - PR.PS-04
  - DE.CM-01
  - ID.RA-01
d3fend_techniques:
  - Executable Denylisting
  - Platform Hardening
---

# Implementing Browser Extension Security Controls

## When to Use

- When remote employees have dozens of unvetted extensions installed that can read and modify all web traffic
- When a browser extension supply chain attack (malicious update to a previously trusted extension) could silently exfiltrate session tokens and credentials
- When DLP controls are undermined by extensions with `<all_urls>` permission that can read clipboard contents and form data
- When compliance audits require demonstrating control over software installed in the browser context
- When shadow IT review reveals extensions designed to harvest credentials, bypass SSO, or exfiltrate data

**Do not use** as a blanket "block everything" policy without first inventorying and allowlisting legitimate productivity tools — this creates immediate friction for 400 remote workers and will be bypassed.

## Prerequisites

- Chrome Browser Cloud Management (CBCM) or Microsoft Intune for Edge policy deployment
- Browser management baseline in place (see `implementing-enterprise-browser-management`)
- Access to Chrome Web Store developer API or crxcavator.io for extension risk analysis
- Process for employees to request extension approval (IT helpdesk ticket or self-service form)

## Workflow

### Step 1: Inventory All Installed Extensions Across the Fleet

Before enforcing allowlists, understand what is currently installed — blocking without inventory creates support ticket storms.

```python
# scripts/extension_inventory.py — pull extension data from Chrome CBCM API
import requests, json, os
from google.oauth2 import service_account
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/admin.directory.device.chromebrowsers.readonly']
credentials = service_account.Credentials.from_service_account_file(
    'service_account.json', scopes=SCOPES
)
service = build('admin', 'directory_v1', credentials=credentials)

def get_all_extensions():
    extensions = {}
    page_token = None
    while True:
        result = service.chromeosdevices().list(
            customerId='my_customer',
            pageToken=page_token,
            projection='FULL'
        ).execute()
        for device in result.get('chromeosdevices', []):
            for ext in device.get('activeTimeRanges', []):
                ext_id = ext.get('extensionId', '')
                if ext_id not in extensions:
                    extensions[ext_id] = {
                        'id': ext_id,
                        'name': ext.get('name', 'Unknown'),
                        'version': ext.get('version', ''),
                        'users': []
                    }
                extensions[ext_id]['users'].append(device.get('annotatedUser', ''))
        page_token = result.get('nextPageToken')
        if not page_token:
            break
    return list(extensions.values())

extensions = get_all_extensions()
# Sort by user count to identify most-used extensions
extensions.sort(key=lambda x: len(x['users']), reverse=True)
print(json.dumps(extensions[:50], indent=2))
print(f"\nTotal unique extensions: {len(extensions)}")
print(f"Total installs: {sum(len(e['users']) for e in extensions)}")
```

### Step 2: Risk-Score Extensions by Permission Profile

Browser extensions are granted permissions at install time. The permission set is the primary risk indicator.

```python
# scripts/score_extension_risk.py — score extensions based on permission risk
import requests, json

# Permission risk weights
PERMISSION_RISK = {
    # CRITICAL — can read and modify all web traffic / credentials
    "<all_urls>": 10,
    "http://*/*": 10,
    "https://*/*": 10,
    "webRequest": 9,
    "webRequestBlocking": 10,
    "cookies": 8,
    "tabs": 6,
    "history": 7,
    "bookmarks": 4,
    "clipboardRead": 8,
    "clipboardWrite": 6,
    "nativeMessaging": 9,     # can communicate with native OS apps
    "desktopCapture": 8,
    "debugger": 10,           # can intercept all browser activity
    "proxy": 10,              # can route all traffic through attacker proxy
    "privacy": 7,
    "management": 9,          # can install/remove other extensions
    "downloads": 5,
    "storage": 3,
    "notifications": 2,
    "contextMenus": 1,
}

def score_extension(extension_id):
    """Fetch extension manifest from Chrome Web Store and calculate risk score"""
    try:
        resp = requests.get(
            f"https://chrome.google.com/webstore/detail/{extension_id}",
            timeout=10
        )
        # Also check crxcavator.io for deep analysis
        cavator = requests.get(
            f"https://api.crxcavator.io/v1/report/{extension_id}",
            timeout=10
        ).json()
        risk_score = cavator.get('data', {}).get('risk', {}).get('total', 0)
        permissions = cavator.get('data', {}).get('manifest', {}).get('permissions', [])
        permission_score = sum(PERMISSION_RISK.get(p, 0) for p in permissions)
        return {
            "extension_id": extension_id,
            "crxcavator_risk": risk_score,
            "permission_score": permission_score,
            "permissions": permissions,
            "risk_level": "CRITICAL" if permission_score >= 20 else
                          "HIGH" if permission_score >= 12 else
                          "MEDIUM" if permission_score >= 6 else "LOW"
        }
    except Exception as e:
        return {"extension_id": extension_id, "error": str(e)}

# Score all discovered extensions
EXTENSION_IDS = ["extension_id_1", "extension_id_2"]  # from inventory step
report = [score_extension(eid) for eid in EXTENSION_IDS]
report.sort(key=lambda x: x.get('permission_score', 0), reverse=True)
print(json.dumps(report, indent=2))
```

### Step 3: Enforce Extension Allowlist via Chrome CBCM

After inventorying and vetting extensions, enforce an allowlist — only approved extensions can install.

```json
// Chrome policy: allowlist-only extension installation
{
  // Block all extensions by default
  "ExtensionInstallBlocklist": ["*"],

  // Allow only vetted extensions (by extension ID)
  "ExtensionInstallAllowlist": [
    "aapbdbdomjkkjkaonfhkkikfgjllcleb",   // Google Translate
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi",   // Google Docs Offline
    "efaidnbmnnnibpcajpcglclefindmkaj",   // Adobe Acrobat (PDF)
    "cjpalhdlnbpafiamejdnhcphjbkeiagm",   // 1Password (corporate password manager)
    "aeblfdkhhhdcdjpifhhbdiojplfjncoa",   // 1Password alternative
    "ndjpnladcallmjemlbaebfadecfhkepb",   // Zoom
    "kbfnbcaeplbcioakkpcpgfkobkghlhen",   // Grammarly (if approved)
    "LOOM_EXTENSION_ID",                   // Loom (if approved)
    "SLACK_EXTENSION_ID"                   // Slack
  ],

  // Force-install required extensions (cannot be removed by user)
  "ExtensionInstallForcelist": [
    "cjpalhdlnbpafiamejdnhcphjbkeiagm;https://clients2.google.com/service/update2/crx"  // 1Password
  ],

  // Allow enterprise extensions from your own web store / private URL
  "ExtensionInstallSources": [
    "https://extensions.yourcompany.com/*"
  ]
}
```

```bash
# Verify extension policy compliance via CBCM
# Admin Console → Devices → Chrome → Managed browsers → Extensions
# Filter: Status = Blocked (extensions employees tried to install but were blocked)
# This list reveals demand — use it to prioritize approval requests
```

### Step 4: Edge Extension Control via Intune

```json
// Edge Intune policy: control extension installation
{
  // Block all extensions by default
  "ExtensionInstallBlocklist": ["*"],

  // Allowlist approved extension IDs (Edge uses same IDs as Chrome for cross-store)
  "ExtensionInstallAllowlist": [
    "approved-extension-id-1",
    "approved-extension-id-2"
  ],

  // Force-install security-required extensions
  "ExtensionInstallForcelist": [
    "approved-extension-id;https://edge.microsoft.com/extensionwebstorebase/v1/crx"
  ],

  // Prevent extensions from using developer mode (bypass for sideloaded extensions)
  "DeveloperToolsAvailability": 2,

  // Block sideloading unpacked extensions
  "AllowedDomainsForApps": ["yourcompany.com"]
}
```

### Step 5: Detect Malicious Extension Behaviour at Runtime

Policy-based allowlisting protects against unauthorized installs but not against trusted extensions that turn malicious via an update. Monitor for behavioural anomalies.

```kql
// Sentinel/MDE: detect extension making unusual outbound connections
// Chrome/Edge process making connections to unexpected external IPs
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe")
| where RemotePort in (80, 443, 8080, 8443)
| where RemoteIPType == "Public"
// Filter out known Google/Microsoft infrastructure
| where not(RemoteUrl has_any ("google.com", "googleapis.com", "microsoft.com", "windows.net",
                                "akamai.net", "cloudflare.com", "fastly.net"))
| summarize ConnectionCount=count(), UniqueIPs=dcount(RemoteIP),
            Domains=make_set(RemoteUrl, 10)
            by DeviceName, InitiatingProcessAccountUpn, bin(TimeGenerated, 1h)
| where UniqueIPs > 20  // unusual fan-out = extension beaconing or data exfil
| sort by ConnectionCount desc
```

```kql
// Detect extension reading clipboard data at high frequency
DeviceEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ClipboardEventTriggered"
| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe")
| summarize ClipboardReads=count() by DeviceName, InitiatingProcessAccountUpn, bin(TimeGenerated, 1h)
| where ClipboardReads > 50  // unusually high clipboard access by browser
| sort by ClipboardReads desc
```

### Step 6: Extension Compromise Response Playbook

When a trusted extension in your allowlist is compromised (malicious update published to Chrome Web Store), you need to remove it from all 400 devices within minutes.

```bash
# Immediate response when a compromised extension is discovered:

# Step 1: Block the extension immediately in Chrome policy (even if it was allowlisted)
# Admin Console → Devices → Chrome → Apps and Extensions → Add extension to blocklist
# Or via API: add to ExtensionInstallBlocklist with forced policy push

# Step 2: Force-remove from all managed browsers
# Update Chrome policy:
#   "ExtensionInstallBlocklist": ["COMPROMISED_EXTENSION_ID"],
#   "ExtensionInstallAllowlist": [<remove compromised ID>]
# Chrome browsers pick up new policies within ~15 minutes on next policy sync

# Step 3: Force immediate policy refresh on all endpoints
# Intune: create a script to force Chrome policy refresh
$script = @"
# Force Chrome policy update on Windows endpoints
$chromeProcess = Get-Process chrome -ErrorAction SilentlyContinue
if ($chromeProcess) { Stop-Process -Name chrome -Force }
Start-Process "C:\Program Files\Google\Chrome\Application\chrome.exe" `
  --args "--no-startup-window"
"@
# Deploy via Intune → Devices → Scripts → PowerShell scripts

# Step 4: Query which devices had the extension installed
python3 scripts/extension_inventory.py | jq ".[] | select(.id == \"COMPROMISED_ID\")"

# Step 5: Investigate affected devices for credential theft
# Pull browser history, cookie access logs, network connections from those devices
```

## Key Concepts

| Term | Definition |
|---|---|
| Extension allowlist | Chrome/Edge policy that blocks all extensions by default and permits only explicitly listed extension IDs — the strongest control for preventing unauthorized extension installation |
| `<all_urls>` permission | Browser extension permission granting access to read and modify HTTP/HTTPS traffic on every website — the highest-risk permission, equivalent to a full MITM proxy |
| crxcavator.io | Open-source tool and API by Duo Security that analyzes Chrome extension manifests, permissions, and external call patterns to generate a composite risk score |
| Force-install | Chrome/Edge policy that installs an extension automatically on all managed devices without user interaction and prevents the user from removing it |
| Extension sideloading | Installing an unpacked extension directly from the filesystem (Developer Mode) bypassing the Chrome Web Store — common technique for policy bypass |
| Malicious extension update | Supply chain attack where an attacker purchases or compromises a previously legitimate extension account and publishes a malicious update that reaches all users who have the extension installed |
| webRequestBlocking | Chrome extension permission that allows the extension to intercept and modify or cancel HTTP requests before they are sent — the most dangerous network permission |

## Tools & Systems

- **Chrome Browser Cloud Management**: Primary management plane for Chrome extension policy deployment and fleet-wide extension inventory
- **Microsoft Intune**: Extension policy enforcement for Edge (and Chrome on Intune-managed devices via OMA-URI)
- **crxcavator.io**: Extension risk scoring API — use in the extension approval workflow before adding any extension to the allowlist
- **Chrome Web Store Developer API**: Programmatic access to extension metadata for automated inventory and monitoring
- **Microsoft Defender for Endpoint**: Provides process-level network telemetry for detecting anomalous browser extension behaviour at runtime

## Common Scenarios

### Scenario: Popular PDF Extension Publishes Malicious Update

**Context**: A widely-used PDF extension on your allowlist with 380 installs is acquired by a new owner who publishes an update that exfiltrates session cookies to an external server.

**Approach**:
1. Sentinel alert fires — the network telemetry KQL rule detects Chrome.exe making high-frequency connections to an unfamiliar domain
2. The SOC identifies the connection pattern as consistent with the compromised extension (all affected devices ran the update in the past 6 hours)
3. The extension ID is added to the CBCM blocklist — all 380 installs are force-removed within 15 minutes
4. All potentially-affected users' sessions are invalidated in Entra ID — passwords and MFA tokens reset
5. The extension is removed from the allowlist; a replacement PDF tool is evaluated and added

### Scenario: Remote Employee Tries to Install Password-Harvesting Extension

**Context**: An employee searches for "autofill helper" on the Chrome Web Store and clicks Install on an extension that is actually credential-harvesting malware (4.8 stars, 10,000+ installs — fake reviews).

**Approach**:
1. CBCM policy blocks the install — the extension ID is not in the allowlist
2. The employee sees: "Your administrator has blocked installation of extensions not on the approved list. Submit a request at helpdesk.yourcompany.com/extension-request"
3. The request comes in; IT runs the extension ID through crxcavator.io
4. crxcavator scores it CRITICAL (risk score 892/1000) — `<all_urls>`, `webRequestBlocking`, `nativeMessaging` permissions
5. The request is denied; the employee is offered an approved password manager from the allowlist

## Output Format

```json
{
  "extension_fleet_report": {
    "report_date": "2026-06-06",
    "managed_browsers": 423,
    "total_unique_extensions": 847,
    "allowlisted": 23,
    "blocked_install_attempts_7d": 312
  },
  "risk_distribution": {
    "CRITICAL": 4,
    "HIGH": 38,
    "MEDIUM": 112,
    "LOW": 693
  },
  "top_blocked_extensions": [
    {"name": "Free VPN", "id": "ext123", "block_attempts": 47, "risk": "CRITICAL"},
    {"name": "PDF Converter Pro", "id": "ext456", "block_attempts": 31, "risk": "HIGH"}
  ],
  "force_installed": [
    {"name": "1Password", "id": "cjpalhdlnbpafiamejdnhcphjbkeiagm", "installs": 421}
  ],
  "anomalous_behaviour_alerts_7d": 2
}
```
