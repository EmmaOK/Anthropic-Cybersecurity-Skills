#!/usr/bin/env python3
"""
Securonix SIEM Operations Agent

Three subcommands:
  query   — Generate ready-to-use SPOTTER queries for common attack scenarios.
  convert — Convert a Splunk SPL query or Sigma rule to Securonix SPOTTER syntax.
  triage  — Generate a structured triage checklist for a given alert/violation type.

Usage:
    agent.py query   --use-case brute-force --output queries.json
    agent.py query   --list-cases
    agent.py convert --spl "index=auth EventCode=4625 | stats count by src_ip | where count > 10"
    agent.py convert --sigma dcsync.yml --output spotter.txt
    agent.py triage  --alert-type lateral-movement --output checklist.json

No API key required — all operations are rule-based and run locally.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── SPOTTER query library ─────────────────────────────────────────────────────

QUERY_LIBRARY: dict[str, list[dict]] = {
    "brute-force": [
        {
            "name": "Failed authentication spike per user (brute force)",
            "description": "Detects single user being targeted with >10 failed logins",
            "query": (
                'index = activity AND rg_category = "Authentication" AND action = "failed"\n'
                '  | stats count by employeeid, ipaddress, resourcename\n'
                '  | where count > 10\n'
                '  | sort -count\n'
                '  | head 50'
            ),
            "technique": "T1110.001",
            "threshold": "count > 10",
            "tuning_notes": "Raise threshold if helpdesk password resets generate false positives",
        },
        {
            "name": "Password spray — many users, few failures, same source IP",
            "description": "Detects spray pattern: one IP targeting many accounts with few failures each",
            "query": (
                'index = activity AND rg_category = "Authentication" AND action = "failed"\n'
                '  | stats count as failure_count, dc(employeeid) as unique_users by ipaddress\n'
                '  | where unique_users > 20 AND failure_count < unique_users * 3\n'
                '  | sort -unique_users'
            ),
            "technique": "T1110.003",
            "threshold": "unique_users > 20",
            "tuning_notes": "Lower unique_users threshold for small orgs; increase for large shared IPs (NAT)",
        },
        {
            "name": "Successful login after multiple failures (credential stuffing hit)",
            "description": "Flags accounts with >5 failures followed by a success — likely stuffing hit",
            "query": (
                'index = activity AND rg_category = "Authentication"\n'
                '  | stats\n'
                '      sum(eval(if(action="failed",1,0))) as failures,\n'
                '      sum(eval(if(action="success",1,0))) as successes\n'
                '    by employeeid, ipaddress\n'
                '  | where failures > 5 AND successes > 0\n'
                '  | sort -failures'
            ),
            "technique": "T1110.004",
            "threshold": "failures > 5 AND successes > 0",
            "tuning_notes": "Combine with geolocation enrichment to catch impossible travel logins",
        },
    ],
    "lateral-movement": [
        {
            "name": "Abnormal internal RDP/SMB connections",
            "description": "User connecting to an unusual number of internal hosts via RDP or SMB",
            "query": (
                'index = activity AND rg_category = "Network"\n'
                '  AND (destinationport = "3389" OR destinationport = "445")\n'
                '  | stats dc(destinationaddress) as unique_targets, count by employeeid, ipaddress\n'
                '  | where unique_targets > 5\n'
                '  | sort -unique_targets'
            ),
            "technique": "T1021.001",
            "threshold": "unique_targets > 5",
            "tuning_notes": "Exclude IT admin accounts; baseline normal admin activity first",
        },
        {
            "name": "Admin share access sweep (T1021.002)",
            "description": "User accessing admin shares (C$, ADMIN$, IPC$) across multiple hosts",
            "query": (
                'index = activity AND rg_category = "Endpoint"\n'
                '  AND resourcename matches ".*\\\\\\$"\n'
                '  AND action = "success"\n'
                '  | stats count, dc(resourcename) as shares_accessed by employeeid, ipaddress\n'
                '  | where shares_accessed > 3\n'
                '  | sort -shares_accessed'
            ),
            "technique": "T1021.002",
            "threshold": "shares_accessed > 3",
            "tuning_notes": "Whitelist backup service accounts and domain controllers",
        },
        {
            "name": "NTLM authentication to multiple targets (pass-the-hash indicator)",
            "description": "NTLM success events from a single account to many destinations — PtH pattern",
            "query": (
                'index = activity AND rg_category = "Authentication"\n'
                '  AND message contains "NTLM" AND action = "success"\n'
                '  | stats dc(resourcename) as targets, count by employeeid, ipaddress\n'
                '  | where targets > 3\n'
                '  | sort -targets'
            ),
            "technique": "T1550.002",
            "threshold": "targets > 3",
            "tuning_notes": "NTLM is expected in some legacy environments — baseline first",
        },
        {
            "name": "New remote PowerShell sessions",
            "description": "WinRM / remote PS sessions to hosts not previously accessed by this user",
            "query": (
                'index = activity AND rg_category = "Endpoint"\n'
                '  AND (message contains "WSMan" OR message contains "WinRM"\n'
                '       OR message contains "Enter-PSSession")\n'
                '  | stats dc(destinationaddress) as remote_hosts, count by employeeid\n'
                '  | where remote_hosts > 2\n'
                '  | sort -remote_hosts'
            ),
            "technique": "T1021.006",
            "threshold": "remote_hosts > 2",
            "tuning_notes": "Exclude known automation service accounts",
        },
    ],
    "data-exfiltration": [
        {
            "name": "Large data transfer to external destination",
            "description": "DLP events showing > 100MB sent to external IPs",
            "query": (
                'index = activity AND rg_category = "DLP"\n'
                '  | stats sum(transactionstring1) as bytes_sent by employeeid, destinationaddress\n'
                '  | where bytes_sent > 104857600\n'
                '  | eval mb_sent = round(bytes_sent / 1048576, 2)\n'
                '  | sort -bytes_sent\n'
                '  | table employeeid, destinationaddress, mb_sent'
            ),
            "technique": "T1041",
            "threshold": "bytes_sent > 104857600 (100MB)",
            "tuning_notes": "Adjust threshold based on business context; exclude known backup destinations",
        },
        {
            "name": "Anomalous outbound email with attachments",
            "description": "User sending unusually high number of emails with attachments",
            "query": (
                'index = activity AND rg_category = "Email"\n'
                '  AND action = "sent" AND transactionstring2 = "attachment"\n'
                '  | stats count as emails_with_attachments by employeeid\n'
                '  | where emails_with_attachments > 50\n'
                '  | sort -emails_with_attachments'
            ),
            "technique": "T1048.003",
            "threshold": "emails_with_attachments > 50",
            "tuning_notes": "Baseline per department — marketing/sales have higher normal volumes",
        },
        {
            "name": "USB / removable media write activity",
            "description": "Data written to removable media — potential staging for physical exfiltration",
            "query": (
                'index = activity AND rg_category = "Endpoint"\n'
                '  AND categorybehavior = "Removable Media" AND action = "write"\n'
                '  | stats sum(transactionstring1) as bytes_written, count by employeeid, resourcename\n'
                '  | sort -bytes_written'
            ),
            "technique": "T1052.001",
            "threshold": "any write event",
            "tuning_notes": "Consider blocking removable media org-wide if not a business requirement",
        },
        {
            "name": "Cloud storage upload spike",
            "description": "Unusual upload volume to cloud storage services (S3, OneDrive, Dropbox)",
            "query": (
                'index = activity AND rg_category = "Web"\n'
                '  AND (destinationaddress contains "s3.amazonaws.com"\n'
                '       OR destinationaddress contains "onedrive.live.com"\n'
                '       OR destinationaddress contains "dropbox.com"\n'
                '       OR destinationaddress contains "box.com")\n'
                '  AND action = "upload"\n'
                '  | stats sum(transactionstring1) as bytes_uploaded, count by employeeid\n'
                '  | where bytes_uploaded > 52428800\n'
                '  | eval mb_uploaded = round(bytes_uploaded / 1048576, 2)\n'
                '  | sort -bytes_uploaded'
            ),
            "technique": "T1567.002",
            "threshold": "bytes_uploaded > 52428800 (50MB)",
            "tuning_notes": "Whitelist approved cloud storage destinations for your org",
        },
    ],
    "insider-threat": [
        {
            "name": "Off-hours system access",
            "description": "Successful logins outside business hours (before 7am or after 8pm, weekends)",
            "query": (
                'index = activity AND rg_category = "Authentication" AND action = "success"\n'
                '  | eval hour = tonumber(strftime(eventtime, "%H"))\n'
                '  | eval day = strftime(eventtime, "%A")\n'
                '  | where (hour < 7 OR hour > 20) OR (day = "Saturday" OR day = "Sunday")\n'
                '  | stats count, dc(resourcename) as systems_accessed by employeeid\n'
                '  | where count > 5\n'
                '  | sort -count'
            ),
            "technique": "T1078",
            "threshold": "count > 5 off-hours events",
            "tuning_notes": "Exclude on-call staff, global remote workers, and service accounts",
        },
        {
            "name": "Mass file read / staging before departure",
            "description": "User reading large numbers of files — potential pre-exfil staging",
            "query": (
                'index = activity AND rg_category = "Endpoint"\n'
                '  AND action = "read" AND transactionstring3 = "file"\n'
                '  | stats count as file_reads, dc(transactionstring4) as unique_files by employeeid\n'
                '  | where file_reads > 200\n'
                '  | sort -file_reads'
            ),
            "technique": "T1005",
            "threshold": "file_reads > 200",
            "tuning_notes": "Cross-reference with departing employees watchlist for prioritization",
        },
        {
            "name": "Access to sensitive systems not previously accessed",
            "description": "First-ever access to high-value systems — possible privilege abuse",
            "query": (
                'index = activity AND rg_category = "Authentication" AND action = "success"\n'
                '  AND (resourcename contains "FINSVR" OR resourcename contains "HR"\n'
                '       OR resourcename contains "PAYROLL" OR resourcename contains "EXEC")\n'
                '  | stats min(eventtime) as first_access by employeeid, resourcename\n'
                '  | where first_access > relative_time(now(), "-7d")\n'
                '  | sort -first_access'
            ),
            "technique": "T1078.002",
            "threshold": "first access within last 7 days",
            "tuning_notes": "Update resourcename patterns to match your sensitive server naming convention",
        },
    ],
    "cloud-abuse": [
        {
            "name": "Impossible travel — login from two distant IPs in short timeframe",
            "description": "User authenticated from multiple IPs in a short window — may indicate compromise",
            "query": (
                'index = activity AND rg_category = "Cloud" AND action = "success"\n'
                '  | stats\n'
                '      dc(ipaddress) as unique_ips,\n'
                '      values(ipaddress) as ip_list,\n'
                '      min(eventtime) as first_login,\n'
                '      max(eventtime) as last_login\n'
                '    by employeeid\n'
                '  | where unique_ips > 2\n'
                '  | sort -unique_ips'
            ),
            "technique": "T1078.004",
            "threshold": "unique_ips > 2",
            "tuning_notes": "Pair with GeoIP enrichment to flag cross-country logins within minutes",
        },
        {
            "name": "Cloud privilege escalation (IAM policy changes)",
            "description": "IAM role/policy modifications that could grant elevated access",
            "query": (
                'index = activity AND rg_category = "Cloud"\n'
                '  AND (message contains "AttachRolePolicy"\n'
                '       OR message contains "CreateAdminUser"\n'
                '       OR message contains "AddUserToGroup"\n'
                '       OR message contains "PutUserPolicy"\n'
                '       OR message contains "UpdateAssumeRolePolicy")\n'
                '  | stats count by employeeid, ipaddress, message\n'
                '  | sort -count'
            ),
            "technique": "T1078.004",
            "threshold": "any IAM change event",
            "tuning_notes": "Whitelist approved CI/CD service accounts performing automated deployments",
        },
        {
            "name": "Dormant cloud account first login",
            "description": "Account that has never logged in (or not in 180 days) suddenly active",
            "query": (
                'index = activity AND rg_category = "Cloud" AND action = "success"\n'
                '  | stats min(eventtime) as first_seen, count by employeeid\n'
                '  | where first_seen > relative_time(now(), "-7d")\n'
                '  | sort -first_seen'
            ),
            "technique": "T1078",
            "threshold": "first activity in last 7 days",
            "tuning_notes": "Cross-reference against HR system — new joiners vs truly dormant accounts",
        },
    ],
    "ransomware": [
        {
            "name": "Mass file rename / extension change (encryption indicator)",
            "description": "Large number of file renames in a short period — ransomware encryption pattern",
            "query": (
                'index = activity AND rg_category = "Endpoint"\n'
                '  AND (categorybehavior = "File Rename" OR action = "rename")\n'
                '  | stats count as renames by employeeid, resourcename\n'
                '  | where renames > 100\n'
                '  | sort -renames'
            ),
            "technique": "T1486",
            "threshold": "renames > 100",
            "tuning_notes": "Lower threshold to 50 for faster detection; some build systems rename files in bulk",
        },
        {
            "name": "Shadow copy deletion (T1490)",
            "description": "vssadmin or wmic commands deleting volume shadow copies",
            "query": (
                'index = activity AND rg_category = "Endpoint"\n'
                '  AND (message contains "vssadmin delete shadows"\n'
                '       OR message contains "wmic shadowcopy delete"\n'
                '       OR message contains "bcdedit /set recoveryenabled no")\n'
                '  | table eventtime, resourcename, employeeid, message\n'
                '  | sort -eventtime'
            ),
            "technique": "T1490",
            "threshold": "any match",
            "tuning_notes": "Zero tolerance — any hit should be treated as critical and investigated immediately",
        },
        {
            "name": "Rapid outbound connections to many external IPs (C2 beacon)",
            "description": "Host beaconing to many external IPs — possible C2 communication",
            "query": (
                'index = activity AND rg_category = "Network"\n'
                '  AND action = "allowed"\n'
                '  | stats dc(destinationaddress) as unique_ext_ips, count by ipaddress, resourcename\n'
                '  | where unique_ext_ips > 20\n'
                '  | sort -unique_ext_ips'
            ),
            "technique": "T1071.001",
            "threshold": "unique_ext_ips > 20",
            "tuning_notes": "Exclude known CDN IPs and browser traffic — focus on non-web ports",
        },
    ],
}

TRIAGE_CHECKLISTS: dict[str, dict] = {
    "brute-force": {
        "title": "Brute Force / Password Spray Triage Checklist",
        "severity_indicators": [
            "Source IP is external (internet-facing)",
            "Failures distributed across many usernames (spray vs brute)",
            "Failures followed by at least one success",
            "Target accounts include privileged/admin accounts",
            "Source IP has no prior access history",
        ],
        "investigation_steps": [
            "Identify source IP — is it internal, VPN, or external?",
            "Check if the IP appears on threat intelligence feeds (VirusTotal, AbuseIPDB)",
            "Determine if any accounts successfully authenticated after failures",
            "For successful logins: check what actions were taken post-authentication",
            "Determine if MFA was used or bypassed on successful logins",
            "Check the time window — sustained attack or short burst?",
            "Look for other violations on the same source IP or targeted accounts",
        ],
        "escalation_criteria": [
            "Any account successfully authenticated after >5 failures → ESCALATE",
            "Privileged/admin account targeted → ESCALATE",
            "External IP with no prior access history → ESCALATE",
            "Attack spans >1 hour with no blocking → ESCALATE",
        ],
        "closure_criteria": [
            "All failures, no successes, source IP blocked at perimeter → CLOSE",
            "Source IP is known authorized scanner/penetration test → CLOSE with note",
            "Internal helpdesk tool causing lockout noise → TUNE policy + CLOSE",
        ],
        "containment_actions": [
            "Block source IP at firewall/proxy if external and malicious",
            "Lock targeted accounts pending investigation",
            "Reset credentials for any successfully authenticated accounts",
            "Enable MFA if not already active on affected accounts",
            "Add source IP to threat intelligence blocklist",
        ],
        "spotter_pivot_queries": [
            'index = activity AND rg_category = "Authentication" AND ipaddress = "<src_ip>"',
            'index = activity AND employeeid = "<affected_user>" | sort -eventtime | head 50',
            'index = violation AND employeeid = "<affected_user>"',
        ],
    },
    "lateral-movement": {
        "title": "Lateral Movement Triage Checklist",
        "severity_indicators": [
            "User accessing hosts not in their normal access pattern",
            "Admin share (C$, ADMIN$) access to multiple hosts",
            "NTLM authentication to many destinations",
            "Access coincides with or follows a suspicious login",
            "User account was recently compromised (prior brute force violation)",
        ],
        "investigation_steps": [
            "Establish the user's normal access baseline — which hosts do they usually access?",
            "Map the sequence of host accesses — does it follow a network topology (subnet sweep)?",
            "Check for privilege escalation events on the target hosts",
            "Look for process creation events (cmd.exe, PowerShell) on accessed hosts",
            "Check if the user's credentials were recently targeted by brute force",
            "Determine if the activity is from the user's normal workstation or a different host",
            "Look for data staging or exfiltration events following the lateral movement",
        ],
        "escalation_criteria": [
            "Access to domain controller or critical server → ESCALATE IMMEDIATELY",
            "Credential dumping tools (mimikatz, secretsdump) detected → ESCALATE",
            "Movement pattern consistent with known threat actor TTP → ESCALATE",
            "User is on departing employees watchlist → ESCALATE",
        ],
        "closure_criteria": [
            "IT admin performing documented maintenance across hosts → CLOSE with note",
            "Automated backup/patching tool causing activity → TUNE + CLOSE",
            "Pentest/red team activity within authorized scope → CLOSE with reference",
        ],
        "containment_actions": [
            "Isolate the source workstation from the network",
            "Disable the user account pending investigation",
            "Reset all credentials used by the account",
            "Block the source IP at the network layer",
            "Initiate forensic collection on source and target hosts",
        ],
        "spotter_pivot_queries": [
            'index = activity AND employeeid = "<user>" AND rg_category = "Endpoint" | sort -eventtime',
            'index = activity AND ipaddress = "<source_ip>" | sort -eventtime | head 100',
            'index = violation AND employeeid = "<user>" | sort -eventtime',
            'index = activity AND rg_category = "Authentication" AND employeeid = "<user>" AND action = "success" | stats dc(resourcename) as targets by ipaddress',
        ],
    },
    "data-exfiltration": {
        "title": "Data Exfiltration Triage Checklist",
        "severity_indicators": [
            "Destination is external / not a known business partner",
            "Transfer volume significantly above user baseline",
            "Transfer occurs outside business hours",
            "User is on departing employees or investigation watchlist",
            "Transfer followed by USB write or cloud upload",
            "Sensitive data classification tags on transferred files",
        ],
        "investigation_steps": [
            "Identify the destination — is it a known business partner, cloud service, or unknown external?",
            "Determine what data was transferred — file names, extensions, classification labels",
            "Establish the user's normal transfer baseline for this destination",
            "Check if the transfer was authorized (check with manager/data owner)",
            "Look for prior access events to the files/folders that were transferred",
            "Check for DLP policy violations or email gateway alerts on the same timeframe",
            "Determine if data was compressed or encrypted before transfer",
        ],
        "escalation_criteria": [
            "Data contains PII, financial records, or IP → ESCALATE",
            "Destination is a competitor or unknown external party → ESCALATE",
            "User is under active investigation or on departing watchlist → ESCALATE",
            "Transfer volume > 1GB to external destination → ESCALATE",
        ],
        "closure_criteria": [
            "Transfer to approved cloud backup destination, within normal volume → CLOSE",
            "Authorized transfer confirmed by manager and data owner → CLOSE with approval record",
            "DLP false positive on file type/content → TUNE policy + CLOSE",
        ],
        "containment_actions": [
            "Block the destination IP/domain at the proxy/firewall",
            "Quarantine the source workstation",
            "Suspend user access pending investigation",
            "Notify data owner and legal/compliance team",
            "Preserve logs and initiate legal hold if breach confirmed",
        ],
        "spotter_pivot_queries": [
            'index = activity AND employeeid = "<user>" AND rg_category = "DLP" | sort -eventtime',
            'index = activity AND employeeid = "<user>" AND rg_category = "Email" AND action = "sent" | sort -eventtime',
            'index = activity AND destinationaddress = "<dest_ip>" | stats dc(employeeid) as users by destinationaddress',
        ],
    },
    "insider-threat": {
        "title": "Insider Threat Triage Checklist",
        "severity_indicators": [
            "User on departing employees or HR investigation watchlist",
            "Activity outside normal working hours and location",
            "Access to data or systems outside their job function",
            "Multiple minor anomalies clustering in a short period",
            "Sudden increase in data access or download volume",
            "Attempts to disable or tamper with monitoring tools",
        ],
        "investigation_steps": [
            "Review the full entity risk timeline — look for a pattern of escalating violations",
            "Correlate with HR data — any recent performance issues, termination notice, or disciplinary action?",
            "Identify which specific data or systems were accessed",
            "Determine if the access is within the scope of the user's role",
            "Check for any data egress (email, USB, cloud upload) following the access",
            "Review badge access / physical security logs if available",
            "Check if the user attempted to cover tracks (log deletion, tool installation)",
        ],
        "escalation_criteria": [
            "User on active HR investigation → ESCALATE to HR and Legal",
            "Evidence of data egress combined with unusual access → ESCALATE",
            "User has given notice and accessing sensitive systems → ESCALATE",
            "Access to executive communications, legal files, or M&A data → ESCALATE",
        ],
        "closure_criteria": [
            "Off-hours access explained by time zone difference (remote worker) → CLOSE",
            "Access within role scope, no egress detected → CLOSE with monitoring note",
            "Activity matches approved project requiring sensitive data access → CLOSE",
        ],
        "containment_actions": [
            "Add user to enhanced monitoring watchlist",
            "Coordinate with HR before any visible action to protect investigation",
            "Preserve all log data and initiate legal hold",
            "Restrict access to sensitive systems on a need-to-know basis",
            "Prepare for account disable on termination date",
        ],
        "spotter_pivot_queries": [
            'index = violation AND employeeid = "<user>" | sort -eventtime',
            'index = activity AND employeeid = "<user>" | sort -eventtime | head 200',
            'index = riskscore AND employeeid = "<user>" | timechart span=1d max(riskscore)',
            'index = activity AND employeeid = "<user>" AND rg_category = "DLP" | sort -eventtime',
        ],
    },
}

# ── SPL → SPOTTER field mapping ───────────────────────────────────────────────

FIELD_MAP = {
    "src_ip":        "ipaddress",
    "src":           "ipaddress",
    "source":        "ipaddress",
    "dest_ip":       "destinationaddress",
    "dest":          "destinationaddress",
    "destination":   "destinationaddress",
    "user":          "employeeid",
    "username":      "employeeid",
    "src_user":      "employeeid",
    "host":          "resourcename",
    "hostname":      "resourcename",
    "Computer":      "resourcename",
    "EventCode":     'message contains',
    "sourcetype":    "rg_category",
    "_time":         "eventtime",
    "earliest":      None,   # handled by time picker
    "latest":        None,
    "index":         None,   # replaced with index = activity
}

SOURCETYPE_TO_RG = {
    "wineventlog":          "Authentication",
    "WinEventLog:Security": "Authentication",
    "linux_audit":          "Endpoint",
    "cisco:asa":            "Network",
    "pan:traffic":          "Network",
    "pan:threat":           "Network",
    "proxy":                "Web",
    "bluecoat:proxysg":     "Web",
    "stream:smtp":          "Email",
    "office365":            "Cloud",
    "aws:cloudtrail":       "Cloud",
    "okta:im2":             "Authentication",
}

COMMAND_MAP = {
    "stats":     "| stats",
    "timechart": "| timechart",
    "eval":      "| eval",
    "where":     "| where",
    "sort":      "| sort",
    "head":      "| head",
    "tail":      "| tail",
    "table":     "| table",
    "rename":    "| rename",
    "dedup":     "| dedup",
    "rex":       "-- NOTE: SPOTTER has no rex; use message contains or pre-parsed fields",
    "lookup":    "| lookup",
}


def translate_spl(spl: str) -> str:
    lines = [l.strip() for l in spl.strip().split("|")]
    spotter_lines = []

    for i, line in enumerate(lines):
        if i == 0:
            # Base search line
            spotter = _translate_base_search(line)
            spotter_lines.append(spotter)
        else:
            spotter_lines.append(_translate_command(line))

    return "\n  ".join(spotter_lines)


def _translate_base_search(line: str) -> str:
    # Remove index= and sourcetype= tokens, translate fields
    parts = []
    rg_category = None

    tokens = re.split(r'\s+AND\s+|\s+OR\s+|\s+', line, flags=re.IGNORECASE)
    for token in tokens:
        if "=" in token:
            k, v = token.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")

            if k.lower() == "index":
                continue
            if k.lower() in ("sourcetype",):
                mapped = SOURCETYPE_TO_RG.get(v, v.title())
                rg_category = mapped
                continue
            mapped_key = FIELD_MAP.get(k, k)
            if mapped_key is None:
                continue
            if mapped_key == 'message contains':
                parts.append(f'message contains "{v}"')
            else:
                parts.append(f'{mapped_key} = "{v}"')
        elif token.upper() in ("AND", "OR", "NOT"):
            parts.append(token.upper())
        elif token.strip():
            # free-text search term
            parts.append(f'message contains "{token}"')

    base = "index = activity"
    if rg_category:
        base += f' AND rg_category = "{rg_category}"'
    if parts:
        joined = " ".join(p for p in parts if p not in ("AND", "OR", "NOT"))
        base += " AND " + joined

    return base


def _translate_command(cmd: str) -> str:
    cmd = cmd.strip()

    # Translate field names in the command
    for spl_field, spotter_field in FIELD_MAP.items():
        if spotter_field and spotter_field != 'message contains':
            cmd = re.sub(rf'\b{re.escape(spl_field)}\b', spotter_field, cmd)

    # Map command keywords
    first_word = cmd.split()[0].lower() if cmd.split() else ""
    if first_word in COMMAND_MAP:
        translated = COMMAND_MAP[first_word]
        if translated.startswith("--"):
            return f"{translated}"
        rest = cmd[len(first_word):].strip()
        return f"{translated} {rest}"

    return f"| {cmd}"


def cmd_query(args) -> dict:
    if args.list_cases:
        print("Available use cases:")
        for case in sorted(QUERY_LIBRARY.keys()):
            count = len(QUERY_LIBRARY[case])
            print(f"  {case:<25} ({count} queries)")
        return {}

    use_case = args.use_case
    if use_case not in QUERY_LIBRARY:
        print(f"[error] Unknown use case '{use_case}'. Run --list-cases to see options.", file=sys.stderr)
        sys.exit(1)

    queries = QUERY_LIBRARY[use_case]
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "use_case": use_case,
        "query_count": len(queries),
        "spotter_queries": queries,
    }

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))
    print(f"\n[*] {len(queries)} SPOTTER queries written to {args.output}")
    return result


def cmd_convert(args) -> dict:
    if args.sigma:
        path = Path(args.sigma)
        if not path.exists():
            print(f"[error] Sigma file not found: {args.sigma}", file=sys.stderr)
            sys.exit(1)
        raw = path.read_text()
        result = _convert_sigma(raw, args.output)
    elif args.spl:
        spotter = translate_spl(args.spl)
        result = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": "spl",
            "original": args.spl,
            "spotter": spotter,
            "notes": [
                "Review field name mappings — adjust rg_category and custom fields to match your data",
                "SPOTTER uses the Spotter time picker for time ranges — remove earliest/latest if present",
                "Test the query in Spotter before creating a policy",
            ],
        }
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"Original SPL:\n  {args.spl}\n")
        print(f"SPOTTER equivalent:\n  {spotter}\n")
        print(f"[*] Written to {args.output}")

    return result


def _convert_sigma(sigma_text: str, output_path: str) -> dict:
    # Basic Sigma YAML field extraction
    title = re.search(r'^title:\s*(.+)$', sigma_text, re.MULTILINE)
    detection = re.search(r'detection:(.*?)(?=^\w|\Z)', sigma_text, re.MULTILINE | re.DOTALL)
    logsource = re.search(r'logsource:(.*?)(?=^\w|\Z)', sigma_text, re.MULTILINE | re.DOTALL)

    notes = [
        "Sigma→SPOTTER conversion is approximate — review field mappings carefully",
        "Replace placeholder field names with your actual Securonix field names",
        "Test in Spotter before deploying as a policy",
    ]

    spotter = "index = activity"

    if logsource:
        ls = logsource.group(1)
        cat = re.search(r'category:\s*(.+)', ls)
        product = re.search(r'product:\s*(.+)', ls)
        if product:
            prod = product.group(1).strip().lower()
            rg = {"windows": "Authentication", "linux": "Endpoint",
                  "aws": "Cloud", "azure": "Cloud", "okta": "Authentication"}.get(prod, "Endpoint")
            spotter += f'\n  AND rg_category = "{rg}"'

    if detection:
        det = detection.group(1)
        keywords = re.findall(r"'([^']+)'", det)
        conditions = re.findall(r'(\w+):\s*(.+)', det)
        for field, value in conditions:
            field = field.strip()
            value = value.strip().strip("'\"")
            mapped = FIELD_MAP.get(field, field)
            if mapped and mapped != 'message contains' and field != "condition":
                spotter += f'\n  AND {mapped} = "{value}"'
            elif field not in ("condition",):
                spotter += f'\n  AND message contains "{value}"'

    spotter += "\n  | table eventtime, employeeid, ipaddress, resourcename, message"
    spotter += "\n  | sort -eventtime"

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "sigma",
        "sigma_title": title.group(1).strip() if title else "Unknown",
        "spotter": spotter,
        "notes": notes,
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Sigma rule: {result['sigma_title']}")
    print(f"\nSPOTTER equivalent:\n{spotter}\n")
    print(f"[*] Written to {output_path}")
    return result


def cmd_triage(args) -> dict:
    alert_type = args.alert_type
    if alert_type not in TRIAGE_CHECKLISTS:
        print(f"[error] Unknown alert type '{alert_type}'.", file=sys.stderr)
        print(f"Available types: {', '.join(sorted(TRIAGE_CHECKLISTS.keys()))}")
        sys.exit(1)

    checklist = TRIAGE_CHECKLISTS[alert_type]
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alert_type": alert_type,
        **checklist,
    }

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))
    print(f"\n[*] Triage checklist written to {args.output}")
    return result


def main():
    parser = argparse.ArgumentParser(description="Securonix SIEM Operations Agent")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_query = sub.add_parser("query", help="Generate SPOTTER queries for a use case")
    p_query.add_argument("--use-case", help="Attack scenario use case name")
    p_query.add_argument("--list-cases", action="store_true", help="List all available use cases")
    p_query.add_argument("--output", default="spotter_queries.json")

    p_convert = sub.add_parser("convert", help="Convert SPL or Sigma rule to SPOTTER")
    p_convert_src = p_convert.add_mutually_exclusive_group(required=True)
    p_convert_src.add_argument("--spl", help="Splunk SPL query string to convert")
    p_convert_src.add_argument("--sigma", help="Path to Sigma YAML rule file")
    p_convert.add_argument("--output", default="spotter_converted.json")

    p_triage = sub.add_parser("triage", help="Generate triage checklist for an alert type")
    p_triage.add_argument("--alert-type", required=True,
                          choices=list(TRIAGE_CHECKLISTS.keys()))
    p_triage.add_argument("--output", default="triage_checklist.json")

    args = parser.parse_args()
    if args.subcommand == "query":
        cmd_query(args)
    elif args.subcommand == "convert":
        cmd_convert(args)
    elif args.subcommand == "triage":
        cmd_triage(args)


if __name__ == "__main__":
    main()
