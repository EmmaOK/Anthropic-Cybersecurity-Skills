---
name: detecting-browser-credential-theft-and-infostealers
description: >-
  Detect and respond to infostealer malware targeting browser credential stores,
  session cookies, and saved passwords on remote workforce endpoints. Covers
  endpoint telemetry-based detection of browser database access (Chrome Login
  Data, Cookies SQLite files), infostealer process behaviour patterns, cookie
  theft and session hijacking indicators, post-compromise credential rotation
  workflows, and hardening controls that reduce the attack surface of browser
  credential storage for a 400+ remote workforce.
domain: cybersecurity
subdomain: endpoint-security
tags:
  - infostealer
  - credential-theft
  - browser-security
  - session-hijacking
  - endpoint-detection
  - remote-workforce
  - T1555.003
  - T1539
version: '1.0'
author: emmanuelokonkwo
license: Apache-2.0
nist_csf:
  - DE.CM-01
  - DE.AE-02
  - RS.AN-01
  - RS.MI-01
d3fend_techniques:
  - Credential Hardening
  - Process Lineage Analysis
  - File Access Pattern Analysis
---

# Detecting Browser Credential Theft and Infostealers

## When to Use

- When remote workforce endpoints are targeted by commodity infostealer malware (Redline, Vidar, Raccoon, Lumma, Stealc) that harvests browser-stored credentials
- When session cookie theft is enabling account takeover bypassing MFA — attackers use stolen cookies to replay authenticated sessions
- When threat intelligence reports indicate your industry sector is being targeted by infostealer campaigns
- When investigating an account takeover and needing to determine whether credentials were stolen from a browser store vs. phishing
- When hardening remote worker endpoints against the most common initial access vector in ransomware incidents

**Do not use** as a replacement for EDR (CrowdStrike, SentinelOne, Defender for Endpoint) — this skill provides detection logic and hardening procedures that complement EDR, not replace it.

## Prerequisites

- Microsoft Defender for Endpoint or equivalent EDR on all remote Windows/macOS endpoints
- Microsoft Sentinel or Splunk for detection rule deployment
- Sysmon deployed on Windows endpoints for high-fidelity process and file access telemetry
- Chrome/Edge browser management in place (see `implementing-enterprise-browser-management`)
- Entra ID Continuous Access Evaluation (CAE) for rapid session revocation post-compromise

## Workflow

### Step 1: Understand the Browser Credential Attack Surface

Remote endpoints store sensitive credential material in predictable filesystem locations that infostealers target first.

```
Browser Credential Store Locations (Windows):
──────────────────────────────────────────────
Chrome Login Data (passwords):
  %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
  %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data-journal

Chrome Cookies (session tokens):
  %LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies

Chrome Local State (AES encryption key for DPAPI):
  %LOCALAPPDATA%\Google\Chrome\User Data\Local State

Edge Login Data:
  %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data

Edge Cookies:
  %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Network\Cookies

Firefox Logins (NSS-encrypted):
  %APPDATA%\Mozilla\Firefox\Profiles\*.default-release\logins.json
  %APPDATA%\Mozilla\Firefox\Profiles\*.default-release\key4.db

macOS Chrome Keychain integration:
  ~/Library/Application Support/Google/Chrome/Default/Login Data
  Encryption key stored in macOS Keychain: "Chrome Safe Storage"
```

```
Common Infostealer Behaviour Pattern:
──────────────────────────────────────
1. Process spawns (often from browser, Office, or download)
2. Reads CryptUnprotectData / queries DPAPI (to decrypt Chrome master key)
3. Opens Login Data SQLite (copies to TEMP to avoid lock)
4. Opens Cookies SQLite (copies to TEMP)
5. Reads Local State JSON (to extract AES key)
6. Decrypts credentials using retrieved key
7. Exfiltrates to C2 over HTTPS (often Telegram bot API or Discord webhooks)
8. Deletes temp files
```

### Step 2: Deploy Infostealer Detection Rules in Sentinel / Splunk

```kql
// Detection 1: Process reading Chrome/Edge credential database (T1555.003)
// High-fidelity: non-browser process opening Login Data SQLite
DeviceFileEvents
| where TimeGenerated > ago(1h)
| where FolderPath has_any (
    @"\Google\Chrome\User Data\Default\Login Data",
    @"\Microsoft\Edge\User Data\Default\Login Data",
    @"\Mozilla\Firefox\Profiles\",
    @"\Chromium\User Data\Default\Login Data"
  )
| where ActionType in ("FileRead", "FileCreated")
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe",
    "SearchIndexer.exe", "MsMpEng.exe",  // Windows Defender indexing
    "OneDrive.exe", "backup.exe"         // legitimate backup
  )
| project TimeGenerated, DeviceName, InitiatingProcessAccountUpn,
          InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| sort by TimeGenerated desc
```

```kql
// Detection 2: DPAPI CryptUnprotectData called by suspicious process (Chrome key decryption)
DeviceEvents
| where TimeGenerated > ago(1h)
| where ActionType == "DpapiAccessed"
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "lsass.exe", "svchost.exe",
    "MicrosoftEdgeUpdate.exe", "GoogleUpdate.exe"
  )
| where AdditionalFields has "CHROME"  // DPAPI entropy value used by Chrome
| project TimeGenerated, DeviceName, InitiatingProcessAccountUpn,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

```kql
// Detection 3: Browser credential file copied to TEMP then deleted (infostealer staging)
let suspiciousCopies = DeviceFileEvents
| where TimeGenerated > ago(1h)
| where FolderPath has "Login Data" or FolderPath has "Cookies"
| where ActionType == "FileCreated"
| where FolderPath has_any (@"\Temp\", @"\AppData\Local\Temp\", @"\Windows\Temp\")
| project CopyTime=TimeGenerated, DeviceName, TempFile=FolderPath,
          Process=InitiatingProcessFileName, CmdLine=InitiatingProcessCommandLine;
let deletions = DeviceFileEvents
| where TimeGenerated > ago(1h)
| where ActionType == "FileDeleted"
| where FolderPath has_any (@"\Temp\", @"\AppData\Local\Temp\");
suspiciousCopies
| join kind=inner deletions on DeviceName
| where deletions.TimeGenerated > CopyTime
| project CopyTime, DeviceName, TempFile, Process, CmdLine
```

```kql
// Detection 4: Cookie theft — large outbound HTTPS POST to rare domain after file access
// Correlates credential file access with subsequent data exfiltration
let credentialAccess = DeviceFileEvents
| where TimeGenerated > ago(2h)
| where FolderPath has "Login Data" or FolderPath has "Cookies"
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe")
| project FileName=InitiatingProcessFileName, DeviceName, AccessTime=TimeGenerated;
DeviceNetworkEvents
| where TimeGenerated > ago(2h)
| where RemotePort == 443
| where SentBytes > 102400  // > 100KB outbound = suspicious for a background process
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","onedrive.exe","teams.exe")
| join kind=inner credentialAccess on DeviceName
| where TimeGenerated > AccessTime  // network event AFTER file access
| project TimeGenerated, DeviceName, InitiatingProcessAccountUpn,
          InitiatingProcessFileName, RemoteUrl, SentMB=SentBytes/1048576
```

```kql
// Detection 5: Telegram/Discord exfiltration (common infostealer C2 channels)
DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| where RemoteUrl has_any ("api.telegram.org", "discord.com/api", "discord.gg")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe",
                                         "Discord.exe", "Telegram.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl, SentBytes
```

### Step 3: Harden Browser Credential Storage

Reduce the attack surface so that even if malware reaches the endpoint, credential theft is harder.

```json
// Chrome policy: disable saving passwords in browser (use corporate password manager instead)
{
  "PasswordManagerEnabled": false,
  "AutofillAddressEnabled": false,
  "AutofillCreditCardEnabled": false,

  // Prevent cookies from persisting beyond the session for high-risk sites
  // (reduces cookie theft window)
  "CookiesSessionOnlyForUrls": [
    "https://[*.]yourbanking-portal.com",
    "https://[*.]financial-system.com"
  ],

  // Clear cookies and site data on exit (for high-sensitivity roles)
  // Note: this logs users out of all sites on browser close — balance with UX
  "DefaultCookiesSetting": 1,   // 1=allow, 2=block all, 4=session only
  "ClearBrowsingDataOnExitList": ["cookies_and_other_site_data"]
}
```

```powershell
# Windows: restrict access to Chrome credential files via NTFS ACLs
# Only chrome.exe and the user account should access Login Data

$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
$loginData = Join-Path $chromePath "Login Data"

# Audit current permissions
Get-Acl $loginData | Format-List

# Add SACL to audit all reads of Login Data (generates Event ID 4663)
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "ReadData",
    "Failure,Success"
)
$acl = Get-Acl $loginData
$acl.AddAuditRule($auditRule)
Set-Acl -Path $loginData -AclObject $acl

# Monitor Event ID 4663 in Windows Security log for unauthorized Login Data reads
```

```bash
# macOS: audit Chrome Keychain access (requires TCC / Endpoint Security Framework)
# Monitor: "Chrome Safe Storage" Keychain item access by non-Chrome processes
# Deploy via MDM profile: Privacy Preferences Policy Control → restrict keychain access
```

### Step 4: Enable Continuous Access Evaluation for Rapid Session Revocation

Stolen session cookies are valuable because they bypass MFA. CAE ensures that revoked sessions are invalidated within minutes rather than hours.

```bash
# Enable Continuous Access Evaluation in Entra ID
az ad sp show --id "00000003-0000-0000-c000-000000000000"  # Microsoft Graph

# Enable CAE policy (requires Entra ID P1)
# Entra ID → Security → Conditional Access → Continuous Access Evaluation
# Enable for: All cloud apps
# Strict enforcement: Yes (tokens become invalid within 15 minutes of revocation)

# When a credential theft is detected — immediately revoke all sessions
USER_UPN="compromised.user@yourcompany.com"

# Revoke all refresh tokens (user must re-authenticate at next app launch)
az ad user revoke-sign-in-sessions --id $USER_UPN

# Reset password to invalidate password-based tokens
az ad user update --id $USER_UPN --password "$(openssl rand -base64 24)" --force-change-password-next-login true

# Force MFA re-registration (in case TOTP seed was also stolen)
# Entra ID → Users → select user → Authentication methods → Require re-register MFA
```

### Step 5: Infostealer Incident Response Playbook

```python
# scripts/infostealer_response.py — automated initial response to infostealer detection
import subprocess, json, os, sys
from datetime import datetime
import requests

def isolate_device_mde(device_id, machine_id):
    """Isolate device via Microsoft Defender for Endpoint API"""
    token = os.environ["MDE_TOKEN"]
    resp = requests.post(
        f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/isolate",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"Comment": f"Infostealer detected - auto-isolated {datetime.utcnow().isoformat()}",
              "IsolationType": "Full"}
    )
    return resp.status_code == 201

def revoke_user_sessions(user_upn):
    """Revoke all Entra ID sessions for compromised user"""
    result = subprocess.run(
        ["az", "ad", "user", "revoke-sign-in-sessions", "--id", user_upn],
        capture_output=True, text=True
    )
    return result.returncode == 0

def collect_forensic_triage(device_name):
    """Trigger MDE live response for forensic collection"""
    token = os.environ["MDE_TOKEN"]
    resp = requests.post(
        "https://api.securitycenter.microsoft.com/api/liveresponse/sessions",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"machineName": device_name, "comment": "Infostealer forensic triage"}
    )
    return resp.json()

def run_response(device_id, machine_id, user_upn, device_name):
    print(json.dumps({
        "action": "INFOSTEALER_RESPONSE_STARTED",
        "device": device_name,
        "user": user_upn,
        "timestamp": datetime.utcnow().isoformat()
    }))
    results = {
        "device_isolated": isolate_device_mde(device_id, machine_id),
        "sessions_revoked": revoke_user_sessions(user_upn),
        "forensic_session": collect_forensic_triage(device_name)
    }
    print(json.dumps(results, indent=2))
    return results

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--machine-id", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--device-name", required=True)
    args = parser.parse_args()
    run_response(args.device_id, args.machine_id, args.user, args.device_name)
```

### Step 6: Post-Compromise Credential Reset Scope

After an infostealer incident, the credential reset scope must match the browser's stored credential scope.

```bash
# Query which credentials were stored in the victim's browser
# (requires forensic access to the device or EDR telemetry)

# Check Chrome stored passwords via DPAPI decryption (forensic tool)
# SharpChrome, HarvestBrowserPasswords, or MDE Advanced Hunting

# Typically reset the following for any confirmed infostealer:
RESET_SCOPE=(
  "Entra ID password + revoke all sessions"
  "MFA device registration (re-register)"
  "Corporate email app password"
  "VPN credentials / certificates"
  "Any SaaS apps the user accesses via browser (identified from browser history)"
  "Corporate password manager master password"
  "AWS/Azure/GCP console credentials if browser-accessed"
  "GitHub/GitLab tokens if stored in browser"
)

# Notify user of what to reset on personal accounts (bank, personal email)
# if personal browsing occurred on the compromised device
```

## Key Concepts

| Term | Definition |
|---|---|
| Infostealer | Commodity malware specifically designed to harvest browser-stored credentials, session cookies, autofill data, and crypto wallets from infected endpoints |
| Login Data (SQLite) | Chrome and Edge's local SQLite database storing saved usernames, passwords (DPAPI-encrypted), and associated URLs — the primary infostealer target on Windows |
| DPAPI | Windows Data Protection API — the encryption mechanism Chrome uses to protect the Login Data AES key; infostealers call `CryptUnprotectData` to retrieve it |
| Session cookie theft | Stealing authenticated browser cookies to replay HTTP sessions without knowing the password or MFA code — allows account takeover that bypasses MFA |
| Continuous Access Evaluation (CAE) | Microsoft Entra ID feature that shortens access token lifetimes and enables near-real-time session revocation so stolen tokens expire within minutes |
| T1555.003 | MITRE ATT&CK technique: Credentials from Password Stores — Credentials from Web Browsers — the primary technique used by all commodity infostealers |
| T1539 | MITRE ATT&CK technique: Steal Web Session Cookie — stealing browser cookies to hijack authenticated sessions |
| Credential canary | A fake credential stored in the browser password manager that, when used, triggers a detection — useful for identifying infostealer activity in a test environment |

## Tools & Systems

- **Microsoft Defender for Endpoint**: Primary EDR providing DeviceFileEvents, DeviceNetworkEvents, and DpapiAccessed telemetry for infostealer detection
- **Microsoft Sentinel**: SIEM for correlating multi-signal infostealer detection rules and triggering automated response playbooks
- **Sysmon**: Windows System Monitor providing high-fidelity file access and process telemetry when MDE is not available
- **Microsoft Entra ID CAE**: Near-real-time session revocation mechanism — critical for limiting the window of stolen cookie usability
- **MDE Live Response**: Remote forensic shell allowing analysts to collect evidence from isolated infected endpoints without physical access
- **SharpChrome / HarvestBrowserPasswords**: Forensic tools for extracting and inventorying browser-stored credentials during incident response

## Common Scenarios

### Scenario: Redline Infostealer Delivered via Malicious Download

**Context**: A remote employee downloads a cracked software installer from a file-sharing site. The installer drops Redline Stealer, which exfiltrates all browser-stored credentials within 90 seconds.

**Approach**:
1. Sentinel detection 1 fires — a non-browser process (`setup.exe`) opens Chrome's Login Data SQLite
2. Detection 4 correlates file access with a 2.3MB HTTPS POST to a Telegram bot API endpoint
3. The automated Logic App runs `infostealer_response.py` — device is network-isolated, user sessions revoked in Entra ID
4. MDE Live Response collects the malware binary and Chrome credential database copy from TEMP
5. Full credential reset: Entra ID password, MFA re-registration, all SaaS apps the user accessed
6. Browser history is analysed to determine which credentials were stored and need rotation

### Scenario: Session Cookie Theft Bypasses MFA

**Context**: An employee's laptop is infected by a cookie-focused infostealer. The attacker uses stolen M365 session cookies to access SharePoint and export confidential documents — no password or MFA prompt appears.

**Approach**:
1. Entra ID sign-in logs show successful access from an unfamiliar IP in a different country — impossible travel alert fires in Sentinel
2. Conditional Access triggers a CAE event — the token is invalidated within 15 minutes
3. SharePoint access logs show 847 files viewed/downloaded in a 12-minute window before the session was revoked
4. The compromised endpoint is identified via the DeviceName in the MDE alert and isolated
5. DLP audit confirms what files were accessed; data breach notification assessment is initiated

## Output Format

```json
{
  "infostealer_detection_summary": {
    "report_date": "2026-06-06",
    "endpoints_monitored": 423
  },
  "detections_7d": {
    "credential_db_access_by_non_browser": 3,
    "dpapi_access_suspicious_process": 1,
    "credential_file_copy_to_temp": 2,
    "telegram_discord_exfil_attempts": 1,
    "confirmed_infostealer_incidents": 1
  },
  "incident_response": {
    "devices_isolated": 1,
    "users_sessions_revoked": 1,
    "credentials_rotated": 47,
    "forensic_collections": 1,
    "mean_time_to_isolate_minutes": 4
  },
  "hardening_status": {
    "password_manager_in_browser_disabled": true,
    "corporate_password_manager_deployed": true,
    "cae_enabled": true,
    "login_data_access_auditing": true
  }
}
```
