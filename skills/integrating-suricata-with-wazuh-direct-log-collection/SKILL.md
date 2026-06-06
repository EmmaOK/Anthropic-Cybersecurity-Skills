---
name: integrating-suricata-with-wazuh-direct-log-collection
description: >-
  Integrate Suricata IDS with Wazuh SIEM by mounting the Suricata log volume
  directly into the Wazuh manager container, bypassing Filebeat. Covers the
  Filebeat 8.x/OpenSearch incompatibility, Wazuh's JSON field limit for EVE
  logs, creating a minimal wazuh-alerts.json output, and fixing Docker
  checksum offloading issues.
domain: cybersecurity
subdomain: soc-operations
tags:
- suricata
- wazuh
- siem
- docker
- log-collection
- eve-json
- filebeat
- opensearch
- T1041
- T1071
version: '1.0'
author: fortark
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- RS.AN-01
nist_ai_rmf:
- MEASURE-2.7
- MANAGE-3.1
---
# Integrating Suricata with Wazuh via Direct Log Collection

## When to Use

- When Filebeat fails to ship Suricata EVE logs to OpenSearch (common with Filebeat 8.x)
- When Suricata alerts are not appearing in Wazuh despite Filebeat running
- When deploying Suricata and Wazuh together in Docker Compose
- When Wazuh reports "Too many fields for JSON decoder" on Suricata events
- When Suricata alerts fire in logs but never reach the SIEM

**Do not use** Filebeat 8.x with OpenSearch — it calls `GET /_license` on startup which OpenSearch rejects with 400, causing an infinite reconnect loop. Use direct volume mounting instead.

## Prerequisites

- Docker Compose with a named volume shared between the Suricata and Wazuh manager containers
- Suricata 7.x configured with EVE JSON output
- Wazuh Manager 4.x with logcollector enabled
- Understanding of Docker volume mounts and Wazuh ossec.conf syntax

## Workflow

### Step 1: Identify the Filebeat Incompatibility

Filebeat 8.x calls `GET /_license` on every connection to OpenSearch. OpenSearch rejects this with HTTP 400, causing Filebeat to retry indefinitely. Check Filebeat logs:

```bash
docker logs soc-filebeat 2>&1 | grep -i "license\|error\|failed" | tail -20
# Look for: "Failed to perform any bulk index operations: ... 400 Bad Request"
# Or:       "Request to /_license failed"
```

If you see thousands of failed reconnects, Filebeat is non-functional. The fix is to bypass it entirely.

### Step 2: Create a Minimal Suricata Output for Wazuh

Wazuh's JSON decoder has a hardcoded field limit (~128 fields). Full EVE JSON events from Suricata exceed this limit, causing the error "Too many fields for JSON decoder" and silently dropping alerts.

Add a second, minimal EVE output to `suricata.yaml` **before** the full eve.json output:

```yaml
outputs:
  # Minimal output for Wazuh — stays within the ~128 field JSON decoder limit
  - eve-log:
      enabled: yes
      filetype: regular
      filename: wazuh-alerts.json
      community-id: true
      community-id-seed: 0
      types:
        - alert:
            payload: no
            packet: no
            metadata: no
            http-body: no
            tagged-packets: no
        - http: {}
        - dns:
            version: 2
        - tls: {}

  # Full output for forensics/dashboards — not read by Wazuh
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      community-id: true
      types:
        - alert:
            payload: yes
            packet: yes
            metadata: yes
            http-body: yes
```

### Step 3: Fix Docker Checksum Offloading

Docker uses checksum offloading, which causes Suricata to log `SURICATA TCPv4 invalid checksum` and drop packets. Disable checksum validation in the af-packet section:

```yaml
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    block-size: 131072
    checksum-checks: no   # Required in Docker — offloading causes false invalid checksums
```

For macOS Docker Desktop (pcap mode instead of af-packet):

```yaml
# suricata.mac.yaml override
pcap:
  - interface: eth0
    checksum-checks: no
```

### Step 4: Share the Suricata Log Volume with Wazuh

In `docker-compose.yml`, declare a named volume and mount it into both containers:

```yaml
volumes:
  suricata-logs:   # named volume shared between suricata and wazuh-manager

services:
  suricata:
    volumes:
      - suricata-logs:/var/log/suricata

  wazuh-manager:
    volumes:
      - suricata-logs:/var/log/suricata:ro   # read-only — Wazuh only reads
```

### Step 5: Configure Wazuh to Read the Minimal Output

Add a `<localfile>` entry to `ossec.conf`. Use `json` format (not `syslog`) and point to `wazuh-alerts.json`:

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/wazuh-alerts.json</location>
  </localfile>
</ossec_config>
```

**Important:** After adding a new `<localfile>`, `wazuh-control reload` only restarts analysisd — logcollector does not pick up the new entry. A full restart is required:

```bash
docker exec soc-wazuh-manager /var/ossec/bin/wazuh-control restart
```

### Step 6: Verify the Pipeline

```bash
# 1. Confirm Suricata is writing the minimal output
docker exec soc-suricata tail -5 /var/log/suricata/wazuh-alerts.json | python3 -m json.tool | head -20

# 2. Confirm Wazuh logcollector is tailing the file
docker exec soc-wazuh-manager grep -i "suricata\|wazuh-alerts" /var/ossec/logs/ossec.log | tail -10

# 3. Trigger a test alert — curl a known-signature URL
docker exec soc-suricata curl -s http://testmynids.org/uid/index.html

# 4. Check Wazuh alerts for Suricata events
docker exec soc-wazuh-manager grep -l "suricata" /var/ossec/logs/alerts/ 2>/dev/null | head -5

# 5. In OpenSearch/Wazuh dashboard, filter:
#    rule.groups: suricata
#    OR data.alert.signature_id: <your SID>
```

### Step 7: Write Effective Suricata Detection Rules

Custom rules for lab simulation or specific detections go in `local.rules`. Key patterns:

```suricata
# Detect outbound HTTP POST to a specific host (data exfiltration sim)
# NOTE: Suricata cannot inspect HTTPS — use http:// in test URLs
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Data exfiltration POST to external host";
  flow:established,to_server;
  http.method; content:"POST";
  http.host; content:"target.example.com";
  classtype:data-loss;
  sid:9000010; rev:1;
)

# Detect outbound connections to common C2 ports
alert tcp $HOME_NET any -> $EXTERNAL_NET [4444,5555,6666,31337] (
  msg:"Outbound connection to common C2 port";
  flow:established,to_server;
  classtype:trojan-activity;
  sid:9000002; rev:1;
)
```

**Critical:** Suricata only inspects plaintext traffic. For exfiltration simulation rules to fire, the sim script must use `http://` not `https://`. HTTPS traffic appears as TLS handshake metadata only — the POST body and Host header are not visible to Suricata rules.

## Key Concepts

| Term | Definition |
|------|------------|
| **EVE JSON** | Suricata's structured JSON log format; full events can exceed 128 fields, hitting Wazuh's JSON decoder limit |
| **Wazuh logcollector** | Wazuh process that reads `<localfile>` entries and feeds them to analysisd; only picks up new entries after a full `wazuh-control restart` |
| **wazuh-alerts.json** | Minimal Suricata EVE output with payload/packet/metadata disabled; stays within Wazuh's field limit |
| **checksum-checks: no** | Disables Suricata's TCP/IP checksum validation; required in Docker because the host offloads checksums, causing Suricata to see "invalid" packets |
| **ET.formdata flowbit** | Suricata flowbit indicating a multipart form-data POST body (file upload); set by Emerging Threats rules when data exfiltration pattern matches |
| **community-id** | Standardized flow hash for correlating the same connection across multiple tools |

## Tools & Systems

- **Suricata 7.x**: Open-source network IDS; outputs EVE JSON logs
- **Wazuh Manager 4.x**: SIEM that reads log files via logcollector; has a ~128-field JSON decoder limit
- **Filebeat 8.x**: Incompatible with OpenSearch — calls `GET /_license` which OpenSearch rejects; avoid for this pipeline
- **Docker named volumes**: Used to share the Suricata log directory between containers without Filebeat

## Common Scenarios

### Scenario: Suricata Alerts Not Appearing in OpenSearch After Days of Running

**Symptoms**: Suricata rules fire (visible in `eve.json`), Filebeat shows as running, but zero Suricata events appear in OpenSearch.

**Diagnosis**:
```bash
docker logs soc-filebeat 2>&1 | grep -c "failed\|error"
# Returns 3000+ — Filebeat has been failing since startup
```

**Root Cause**: Filebeat 8.x calls `GET /_license` on every connection. OpenSearch (which is not Elasticsearch) does not implement this API and returns 400. Filebeat enters an infinite reconnect loop and never ships a single event.

**Fix**:
1. Remove Filebeat from the pipeline
2. Add `suricata-logs` named volume to both Suricata and Wazuh manager containers
3. Add `<localfile>` pointing to `wazuh-alerts.json` in ossec.conf
4. Do a full `wazuh-control restart`

### Scenario: "Too Many Fields" — Suricata Alerts Decoded as Empty

**Symptoms**: Wazuh sees Suricata events but they decode as empty or trigger rule 1002 (unknown format) instead of the Suricata rules.

**Root Cause**: Full EVE JSON events (with payload, packet, metadata) contain 150-200+ fields. Wazuh's JSON decoder silently truncates at ~128 fields, losing the alert information.

**Fix**: Add a second Suricata EVE output (`wazuh-alerts.json`) with all heavy fields disabled. Wazuh reads this file; the full `eve.json` is kept for forensics dashboards.

## Output Format

Suricata alert events in `wazuh-alerts.json` (minimal format readable by Wazuh):

```json
{
  "timestamp": "2026-06-01T13:51:42.123456+0000",
  "flow_id": 1234567890,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "172.20.0.50",
  "src_port": 54321,
  "dest_ip": "52.2.50.46",
  "dest_port": 80,
  "proto": "TCP",
  "community_id": "1:abc123==",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 9000010,
    "rev": 1,
    "signature": "Lab2 Sim: Data exfiltration POST to httpbin.org",
    "category": "Data Loss",
    "severity": 1
  },
  "app_proto": "http",
  "direction": "to_server"
}
```

In Wazuh/OpenSearch, filter with:
- `data.alert.signature_id: 9000010` — specific rule SID
- `rule.groups: suricata` — all Suricata events
