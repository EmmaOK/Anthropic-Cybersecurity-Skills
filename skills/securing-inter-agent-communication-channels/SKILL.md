---
name: securing-inter-agent-communication-channels
description: >-
  Secures communication between agents in multi-agent systems against man-in-the-middle
  attacks, message spoofing, replay attacks, and protocol downgrade attacks. Implements
  mutual TLS for agent-to-agent channels, message signing with HMAC or asymmetric keys,
  agent authentication via JWT, and schema validation of inter-agent messages. Covers
  both direct agent-to-agent APIs and message-queue-based coordination channels.
  Based on OWASP Top 10 for Agentic Applications (ASI07:2026 Insecure Inter-Agent
  Communication). Activates when designing multi-agent communication architectures,
  auditing inter-agent channels for spoofing vulnerabilities, or investigating incidents
  where agents acted on forged or replayed instructions.
domain: cybersecurity
subdomain: ai-security
tags:
- agentic-security
- inter-agent-communication
- mTLS
- OWASP-Agentic-Top10
- ASI07
- message-signing
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0088
nist_ai_rmf:
- GOVERN-1.1
- MEASURE-2.5
- MANAGE-3.1
d3fend_techniques:
- Network Traffic Filtering
- Multi-factor Authentication
nist_csf:
- PR.DS-02
- PR.DS-05
- DE.CM-01
---
# Securing Inter-Agent Communication Channels

## When to Use

- Designing the communication model for a multi-agent system where agents delegate tasks, share results, or coordinate actions
- Auditing existing inter-agent API calls for missing authentication, unencrypted channels, or absence of message integrity checks
- Detecting agent impersonation — where a rogue agent registers with a cloned schema and intercepts coordination traffic
- Implementing replay-attack prevention for message queues used in agent orchestration (RabbitMQ, Kafka, Redis Pub/Sub)
- Investigating an incident where an agent acted on instructions that originated from an unverified or spoofed source

**Do not use** this skill for external MCP server authentication — that is covered by `mcp-authentication-and-authorization-hardening`.

## Prerequisites

- Python 3.10+ with `cryptography`, `PyJWT`, `httpx`, `pydantic`
- OpenSSL for generating mTLS certificates: `brew install openssl`
- Message queue access (RabbitMQ, Kafka, or Redis) for queue-based agent coordination
- A shared or asymmetric key infrastructure for message signing
- `nmap` or `sslyze` for auditing TLS configuration on agent endpoints

## Workflow

### Step 1: Audit Inter-Agent Endpoint TLS Configuration

```bash
# Check TLS version and cipher strength on all agent endpoints
sslyze --regular agent-01:8443 agent-02:8443 orchestrator:8443 2>/dev/null | \
  grep -E "(TLSv|SSLv|Cipher|Certificate)"

# Test for TLS downgrade (should refuse SSLv3 and TLSv1.0/1.1)
openssl s_client -connect agent-01:8443 -ssl3 2>&1 | grep -c "handshake failure"
openssl s_client -connect agent-01:8443 -tls1 2>&1 | grep -c "handshake failure"
openssl s_client -connect agent-01:8443 -tls1_1 2>&1 | grep -c "handshake failure"

# Verify mutual TLS is enforced (server rejects clients without cert)
openssl s_client -connect agent-01:8443 2>&1 | grep "Verify return code"
# Should NOT be "0 (ok)" — should require client cert
```

### Step 2: Implement Signed Inter-Agent Messages

```python
import hmac, hashlib, json, time, uuid
from cryptography.hazmat.primitives.asymmetric import ed25519

# Ed25519 keys for message signing (faster and smaller than RSA)
def generate_agent_signing_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

@dataclass
class AgentMessage:
    message_id: str
    sender_id: str
    recipient_id: str
    message_type: str
    payload: dict
    timestamp: float
    nonce: str
    signature: str | None = None

def sign_message(msg: AgentMessage, private_key) -> AgentMessage:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    canonical = json.dumps({
        "message_id": msg.message_id,
        "sender_id": msg.sender_id,
        "recipient_id": msg.recipient_id,
        "message_type": msg.message_type,
        "payload": msg.payload,
        "timestamp": msg.timestamp,
        "nonce": msg.nonce,
    }, sort_keys=True).encode()

    signature = private_key.sign(canonical)
    return dataclasses.replace(msg, signature=signature.hex())

def verify_message(msg: AgentMessage, sender_public_key) -> bool:
    canonical = json.dumps({
        "message_id": msg.message_id,
        "sender_id": msg.sender_id,
        "recipient_id": msg.recipient_id,
        "message_type": msg.message_type,
        "payload": msg.payload,
        "timestamp": msg.timestamp,
        "nonce": msg.nonce,
    }, sort_keys=True).encode()

    try:
        sig_bytes = bytes.fromhex(msg.signature)
        sender_public_key.verify(sig_bytes, canonical)
        return True
    except Exception:
        return False
```

### Step 3: Prevent Replay Attacks

```python
import time

class NonceStore:
    def __init__(self, ttl_seconds: int = 300):
        self._seen: dict[str, float] = {}
        self._ttl = ttl_seconds

    def check_and_record(self, nonce: str, msg_timestamp: float) -> tuple[bool, str]:
        now = time.time()

        # Reject expired messages (clock skew tolerance: 60 seconds)
        if abs(now - msg_timestamp) > self._ttl:
            return False, f"Message timestamp too old/future: {msg_timestamp}"

        # Clean up expired nonces
        self._seen = {n: ts for n, ts in self._seen.items() if now - ts < self._ttl}

        # Reject replayed nonces
        if nonce in self._seen:
            return False, f"Replay detected: nonce '{nonce}' already seen"

        self._seen[nonce] = now
        return True, "ok"

nonce_store = NonceStore()

def validate_incoming_message(msg: AgentMessage,
                               sender_public_key) -> tuple[bool, str]:
    # 1. Verify signature
    if not verify_message(msg, sender_public_key):
        return False, "Invalid message signature — possible spoofing"

    # 2. Replay prevention
    valid, reason = nonce_store.check_and_record(msg.nonce, msg.timestamp)
    if not valid:
        return False, reason

    # 3. Recipient check
    if msg.recipient_id != MY_AGENT_ID:
        return False, f"Message not addressed to this agent: {msg.recipient_id}"

    return True, "ok"
```

### Step 4: Verify Agent Registration Schema

```python
import jsonschema

AGENT_REGISTRATION_SCHEMA = {
    "type": "object",
    "required": ["agent_id", "agent_name", "capabilities", "public_key", "registration_token"],
    "properties": {
        "agent_id": {"type": "string", "pattern": "^agent-[a-z0-9-]{8,32}$"},
        "agent_name": {"type": "string", "maxLength": 64},
        "capabilities": {"type": "array", "items": {"type": "string"}, "maxItems": 20},
        "public_key": {"type": "string", "minLength": 64},
        "registration_token": {"type": "string"},
    },
    "additionalProperties": False,
}

def register_agent(registration_data: dict, orchestrator_jwt_secret: str) -> dict:
    try:
        jsonschema.validate(registration_data, AGENT_REGISTRATION_SCHEMA)
    except jsonschema.ValidationError as e:
        return {"registered": False, "reason": f"Schema validation failed: {e.message}"}

    # Verify registration token was issued by the orchestrator
    try:
        jwt.decode(registration_data["registration_token"],
                   orchestrator_jwt_secret, algorithms=["HS256"])
    except jwt.InvalidTokenError as e:
        return {"registered": False, "reason": f"Invalid registration token: {e}"}

    # Store agent's public key in the registry
    AGENT_REGISTRY[registration_data["agent_id"]] = registration_data["public_key"]
    return {"registered": True, "agent_id": registration_data["agent_id"]}
```

### Step 5: Monitor Inter-Agent Traffic for Anomalies

```bash
# Monitor for unencrypted inter-agent traffic (should be zero)
tcpdump -i eth0 -A 'port 8080 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 or
  tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)' 2>/dev/null | \
  grep -c "HTTP/" | \
  awk '{if ($1 > 0) print "ALERT: Unencrypted inter-agent HTTP detected:", $1, "requests"}'

# Check for agents communicating with unknown peers
ss -tnp | grep <agent_pid> | awk '{print $5}' | \
  sort -u > current-connections.txt
comm -23 <(sort current-connections.txt) <(sort approved-peers.txt) > unknown-peers.txt
if [ -s unknown-peers.txt ]; then
  echo "ALERT: agent communicating with unknown peers:"
  cat unknown-peers.txt
fi
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Agent Impersonation** | An attack where a rogue agent registers with a cloned identity or schema and receives messages intended for a legitimate agent |
| **Replay Attack** | An attacker captures a valid signed message and re-sends it later to trigger the same action again |
| **Protocol Downgrade** | Forcing communication to use an older, weaker protocol (e.g., HTTP instead of HTTPS) to enable MITM interception |
| **Message Signing** | Using an asymmetric key (Ed25519, RSA) to prove that a message was authored by a specific agent and has not been altered |
| **Nonce** | A one-time random value included in each message to prevent replay attacks — servers reject messages reusing a seen nonce |
| **Registration Token** | A short-lived credential issued by the orchestrator that an agent must present when registering, preventing unauthorized agent registration |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **sslyze** | TLS configuration analyzer for auditing agent endpoint cipher suites, protocol versions, and certificate validity |
| **cryptography (Python)** | Ed25519 and RSA signing/verification library for implementing message-level integrity in agent communication |
| **RabbitMQ TLS** | Configuring RabbitMQ message broker with TLS and per-agent client certificate authentication |
| **SPIFFE/SPIRE** | Workload identity system that issues short-lived SVIDs (X.509 certificates) to agents for mTLS in dynamic environments |

## Common Scenarios

- **Protocol downgrade MITM**: An attacker on the network forces agent-to-agent communication to downgrade from HTTPS to HTTP, injecting malicious instructions. TLS enforcement (minimum TLSv1.3) and HSTS headers prevent the downgrade.
- **Fake agent registration**: An attacker registers a rogue agent with a schema identical to the legitimate `data-retrieval-agent`, intercepting its task messages. Schema validation and registration token verification block the rogue registration.
- **Replay of approval message**: An attacker captures a signed `{approve: true}` message for a $10K transaction and replays it for a $500K transaction. Nonce store rejects the replayed message; the transaction is blocked.

## Output Format

```json
{
  "audit_timestamp": "2026-04-26T22:00:00Z",
  "agents_audited": 6,
  "tls_findings": [
    {
      "agent": "research-agent-01:8443",
      "finding": "TLSv1.1 accepted",
      "severity": "HIGH",
      "remediation": "disable TLSv1.0 and TLSv1.1 in agent TLS config"
    }
  ],
  "message_security_events": [
    {
      "type": "REPLAY_DETECTED",
      "nonce": "abc123xyz",
      "sender": "agent-04",
      "severity": "CRITICAL",
      "action": "message_rejected"
    }
  ],
  "unknown_peer_connections": 0,
  "unencrypted_connections": 0
}
```
