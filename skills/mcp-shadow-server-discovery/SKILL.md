---
name: mcp-shadow-server-discovery
description: >-
  Discovers and governs unapproved Model Context Protocol server deployments operating outside
  formal security governance — the AI-age equivalent of shadow IT. Covers network scanning for
  unauthorized MCP instances, default-credential detection, configuration weakness enumeration,
  and integration of discovered servers into formal governance processes. Based on OWASP MCP
  Top 10 (MCP09:2025 Shadow MCP Servers). Activates when auditing AI infrastructure for
  unauthorized MCP deployments, conducting asset discovery in environments with rapid AI tool
  adoption, or responding to incidents traced to an unapproved MCP server.
domain: cybersecurity
subdomain: ai-security
tags:
- mcp-security
- shadow-it
- asset-discovery
- OWASP-MCP-Top10
- network-scanning
- AI-governance
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0088
nist_ai_rmf:
- GOVERN-1.7
- GOVERN-4.2
- MEASURE-2.5
d3fend_techniques:
- Network Mapping
- Asset Inventory
nist_csf:
- ID.AM-01
- ID.AM-02
- DE.CM-01
---
# MCP Shadow Server Discovery

## When to Use

- Auditing an organization's network for unauthorized MCP server deployments set up by developers or teams without security review
- Conducting AI asset discovery as part of a broader IT asset inventory exercise
- Detecting MCP servers started locally by developers that have been accidentally exposed to the network
- Investigating an incident where malicious activity was traced to an unknown MCP endpoint
- Establishing an approved MCP server registry and identifying services that need to be onboarded or shut down

**Do not use** on networks where you do not have explicit authorization to conduct scanning — unauthorized scanning is illegal and may constitute a computer crime.

## Prerequisites

- Written authorization to scan the target network range
- `nmap` 7.80+: `brew install nmap` or package manager
- `netcat` (`nc`) for banner grabbing
- Python 3.10+ with `httpx`, `asyncio` for async probing
- Access to DHCP/DNS records and cloud resource inventories (AWS Config, Azure Resource Graph) for cross-validation
- An approved MCP server registry (CMDB entry or spreadsheet) to compare against discoveries

## Workflow

### Step 1: Identify MCP Server Candidate Ports

MCP servers typically run on ports 3000, 8080, 8443, or custom ports. Scan the internal network:

```bash
# Quick scan for common MCP server ports on internal subnet
nmap -sV -p 3000,3001,8000,8080,8443,9000 \
  --open --version-intensity 5 \
  -oA mcp-port-scan 10.0.0.0/16

# Broader scan for all HTTP/HTTPS services that might be MCP
nmap -sV -p 80,443,3000-3010,8000-8100,9000-9010 \
  --open -oA mcp-broad-scan 10.0.0.0/16

# Parse results for candidate hosts
cat mcp-port-scan.xml | python3 -c "
import xml.etree.ElementTree as ET, sys, json
tree = ET.parse(sys.stdin)
hosts = []
for host in tree.findall('host'):
  addr = host.find('address').get('addr')
  ports = [p.get('portid') for p in host.findall('ports/port') if p.find('state').get('state') == 'open']
  if ports:
    hosts.append({'ip': addr, 'open_ports': ports})
print(json.dumps(hosts, indent=2))
"
```

### Step 2: Fingerprint MCP Servers

Probe candidate hosts for MCP-specific endpoints:

```python
import httpx, asyncio, json

MCP_FINGERPRINT_PATHS = [
    "/",
    "/tools",
    "/health",
    "/.well-known/mcp",
    "/mcp/v1/tools",
    "/api/tools",
    "/capabilities",
]

MCP_INDICATORS = [
    "mcp", "model-context-protocol", "tool_list", "inputSchema",
    '"tools":', '"capabilities":', "anthropic", "claude"
]

async def fingerprint_host(client: httpx.AsyncClient, host: str, port: int) -> dict:
    found_paths = []
    for path in MCP_FINGERPRINT_PATHS:
        for scheme in ("http", "https"):
            url = f"{scheme}://{host}:{port}{path}"
            try:
                r = await client.get(url, timeout=3.0, follow_redirects=True)
                body = r.text.lower()
                if any(ind in body for ind in MCP_INDICATORS):
                    found_paths.append({
                        "url": url,
                        "status": r.status_code,
                        "indicators": [i for i in MCP_INDICATORS if i in body],
                        "authenticated": r.status_code in (401, 403)
                    })
            except Exception:
                pass
    return {"host": host, "port": port, "mcp_paths": found_paths,
            "likely_mcp": bool(found_paths)}

async def scan_hosts(targets: list[tuple[str, int]]) -> list[dict]:
    async with httpx.AsyncClient(verify=False) as client:
        return await asyncio.gather(*[fingerprint_host(client, h, p) for h, p in targets])

targets = [("10.0.1.42", 3000), ("10.0.1.55", 8080)]
results = asyncio.run(scan_hosts(targets))
print(json.dumps([r for r in results if r["likely_mcp"]], indent=2))
```

### Step 3: Test for Default Credentials and Open Access

```bash
# Test common default credentials on discovered MCP servers
for host in $(cat mcp-candidates.txt); do
  for cred in "admin:admin" "admin:password" "mcp:mcp" ":"; do
    user=$(echo $cred | cut -d: -f1)
    pass=$(echo $cred | cut -d: -f2)
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      -u "$user:$pass" "http://$host/admin/")
    if [ "$HTTP_CODE" -eq "200" ]; then
      echo "DEFAULT CREDS WORK: $host — $cred"
    fi
  done

  # Test unauthenticated tool listing
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://$host/tools")
  if [ "$HTTP_CODE" -eq "200" ]; then
    echo "UNAUTH ACCESS: $host/tools returns 200 — no authentication required"
  fi
done
```

### Step 4: Cross-Reference Against Approved Registry

```python
import json

def find_shadow_servers(discovered: list[dict], approved_registry: list[str]) -> dict:
    approved_set = set(f"{s['ip']}:{s['port']}" for s in approved_registry)
    shadow = []
    approved = []

    for server in discovered:
        if not server["likely_mcp"]:
            continue
        key = f"{server['host']}:{server['port']}"
        if key not in approved_set:
            shadow.append({
                "host": server["host"],
                "port": server["port"],
                "paths": server["mcp_paths"],
                "risk": "SHADOW — not in approved registry",
                "action_required": "investigate and either register or decommission"
            })
        else:
            approved.append(key)

    return {
        "shadow_servers": shadow,
        "approved_servers_found": approved,
        "shadow_count": len(shadow)
    }
```

### Step 5: Remediate and Register

```bash
# For each shadow MCP server found:
# 1. Notify the owner (look up IP in DHCP/CMDB)
# 2. Block access at the network layer if unapproved
iptables -I FORWARD -d 10.0.1.42 -p tcp --dport 3000 -j DROP

# 3. Add to approved registry if legitimate
cat >> approved-mcp-registry.json << 'EOF'
{"ip": "10.0.1.42", "port": 3000, "owner": "data-team",
 "approved_date": "2026-04-26", "security_review": "pending"}
EOF

# 4. Schedule follow-up security review within 14 days
echo "MCP server 10.0.1.42:3000 — security review due 2026-05-10" >> review-queue.txt
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Shadow IT** | Technology infrastructure deployed by employees or teams without the knowledge or approval of the central IT/security organization |
| **Shadow MCP Server** | An MCP server instance running outside formal governance, often with default credentials and permissive configurations |
| **MCP Fingerprinting** | Probing an HTTP/HTTPS endpoint for MCP-specific response patterns to confirm it is an MCP server |
| **Default Credentials** | Factory-default username/password combinations left unchanged in a deployment; a frequent initial-access vector |
| **Asset Registry** | Centralized inventory of approved technology assets, used to identify shadow deployments by exclusion |
| **Network Port Scan** | Probing a range of IP addresses and ports to identify listening services, revealing unapproved deployments |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **nmap** | Network port scanner for discovering hosts and open ports across IP ranges |
| **httpx (Python)** | Async HTTP client used for fast parallel probing of discovered hosts for MCP fingerprints |
| **AWS Config / Azure Resource Graph** | Cloud-native asset inventory services that can reveal MCP server deployments in cloud environments |
| **Shodan** | Internet-wide scan database for discovering internet-exposed MCP endpoints (authorized use only) |
| **Tenable / Qualys** | Enterprise vulnerability scanners that include asset discovery and can detect new services on the network |

## Common Scenarios

- **Developer-started local MCP server**: A developer runs `npx @modelcontextprotocol/server-filesystem` for local testing and leaves it running, inadvertently binding to `0.0.0.0:3000`. Network scan discovers it; no authentication is configured. Server is shut down; developer adds a firewall rule for future local testing.
- **Team-deployed MCP server without security review**: The data team deploys a custom MCP server with database access on an EC2 instance. AWS Config asset inventory reveals an EC2 instance not in the CMDB. Network scan confirms it's running an MCP server on port 8080 with default credentials. Security review is initiated.
- **Rogue MCP server by malicious insider**: An attacker deploys a shadow MCP server to harvest credentials from agents that are redirected to it. Network anomaly detection and port scan discovery surface it; comparison against the approved registry confirms it is unauthorized.

## Output Format

```json
{
  "scan_timestamp": "2026-04-26T14:00:00Z",
  "network_range": "10.0.0.0/16",
  "hosts_scanned": 65536,
  "mcp_candidates_found": 4,
  "shadow_servers": [
    {
      "host": "10.0.1.42",
      "port": 3000,
      "paths_found": ["/tools", "/health"],
      "authenticated": false,
      "default_creds_work": false,
      "risk": "SHADOW — unauthenticated tool listing exposed",
      "owner_lookup": "DHCP: hostname=dev-laptop-jenkins",
      "action": "block_and_notify_owner"
    }
  ],
  "approved_servers_confirmed": 2,
  "shadow_count": 1
}
```
