---
name: agentic-cascading-failure-prevention
description: >-
  Prevents single-agent faults from propagating across multi-agent pipelines and amplifying
  into system-wide failures. A poisoned upstream agent, logic error, or resource exhaustion
  can cascade through downstream dependencies to cause large-scale impact — including financial
  losses, cloud cost explosions, or mass data corruption. Implements circuit breakers, output
  validation at pipeline stage boundaries, operational isolation, resource quotas, and rollback
  mechanisms. Based on OWASP Top 10 for Agentic Applications (ASI08:2026 Cascading Failures).
  Activates when designing fault-tolerant multi-agent architectures, investigating cascade
  incidents in production agent pipelines, or auditing agent system resilience.
domain: cybersecurity
subdomain: ai-security
tags:
- agentic-security
- cascading-failures
- circuit-breaker
- OWASP-Agentic-Top10
- ASI08
- resilience
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0088
nist_ai_rmf:
- GOVERN-6.1
- MANAGE-2.2
- MEASURE-3.1
d3fend_techniques:
- System Call Analysis
- Network Traffic Filtering
nist_csf:
- RS.MI-01
- RS.MI-02
- DE.CM-09
---
# Agentic Cascading Failure Prevention

## When to Use

- Designing a multi-agent pipeline where agents feed outputs to downstream agents — and a fault in one could propagate
- Auditing an existing agent system for missing circuit breakers, absent output validation, or no rollback capability
- Responding to a cascading failure incident in a production multi-agent system (financial trades, cloud provisioning, data processing)
- Implementing resource quotas to prevent one misbehaving agent from exhausting shared compute, API, or database resources
- Building agent system health dashboards that aggregate behavior across the pipeline to detect cascade onset early

**Do not use** this skill for single-agent systems — the overhead of circuit breakers and cross-agent validation is only justified in multi-agent pipelines.

## Prerequisites

- Python 3.10+ with `pydantic` for output schema validation
- A shared metrics/state store (Redis) for circuit breaker state
- Observability stack (Prometheus + Grafana or similar) for cascade detection
- Agent orchestration framework with stage-level hooks (LangChain, CrewAI, custom)
- Defined rollback procedures for each pipeline stage

## Workflow

### Step 1: Implement a Circuit Breaker for Each Agent

```python
import time, redis
from enum import Enum

class CircuitState(Enum):
    CLOSED = "closed"       # normal operation
    OPEN = "open"           # blocking calls after failures
    HALF_OPEN = "half_open" # testing recovery

class AgentCircuitBreaker:
    def __init__(self, agent_id: str, failure_threshold: int = 5,
                 recovery_timeout: int = 60, redis_client=None):
        self._agent_id = agent_id
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._redis = redis_client or redis.Redis()

    def _key(self, suffix: str) -> str:
        return f"cb:{self._agent_id}:{suffix}"

    def get_state(self) -> CircuitState:
        state = self._redis.get(self._key("state"))
        if state is None:
            return CircuitState.CLOSED
        state_str = state.decode()
        if state_str == "open":
            open_at = float(self._redis.get(self._key("opened_at")) or 0)
            if time.time() - open_at > self._recovery_timeout:
                return CircuitState.HALF_OPEN
        return CircuitState(state_str)

    def record_success(self):
        self._redis.delete(self._key("failures"))
        self._redis.set(self._key("state"), "closed")

    def record_failure(self):
        failures = self._redis.incr(self._key("failures"))
        self._redis.expire(self._key("failures"), 300)
        if failures >= self._failure_threshold:
            self._redis.set(self._key("state"), "open")
            self._redis.set(self._key("opened_at"), str(time.time()))

    def call_allowed(self) -> bool:
        state = self.get_state()
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.HALF_OPEN:
            return True  # allow one test call
        return False  # OPEN — block
```

### Step 2: Validate Agent Outputs at Pipeline Stage Boundaries

```python
from pydantic import BaseModel, validator
from typing import Any

class MarketAnalysisOutput(BaseModel):
    risk_score: float
    recommended_position_size: float
    confidence: float
    reasoning: str

    @validator("risk_score")
    def risk_in_range(cls, v):
        assert 0.0 <= v <= 1.0, f"risk_score {v} out of bounds [0,1]"
        return v

    @validator("recommended_position_size")
    def position_reasonable(cls, v):
        assert v <= 100_000, f"position size {v} exceeds maximum 100,000 — possible poisoning"
        return v

    @validator("confidence")
    def confidence_in_range(cls, v):
        assert 0.0 <= v <= 1.0
        return v

def validate_stage_output(raw_output: Any, output_model: type[BaseModel],
                            stage_name: str) -> tuple[bool, Any]:
    try:
        validated = output_model(**raw_output)
        return True, validated
    except (ValueError, AssertionError) as e:
        return False, {
            "stage": stage_name,
            "error": str(e),
            "raw_output": str(raw_output)[:200],
            "action": "pipeline_halted"
        }
```

### Step 3: Isolate Agents Operationally with Resource Quotas

```python
import resource, os

def apply_agent_resource_limits(agent_name: str, limits: dict):
    cpu_seconds = limits.get("cpu_seconds", 60)
    memory_mb = limits.get("memory_mb", 512)
    max_processes = limits.get("max_processes", 10)
    max_open_files = limits.get("max_open_files", 64)

    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    resource.setrlimit(resource.RLIMIT_AS,
                        (memory_mb * 1024 * 1024, memory_mb * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NPROC, (max_processes, max_processes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (max_open_files, max_open_files))
    print(f"[{agent_name}] Resource limits applied: {limits}")

AGENT_RESOURCE_PROFILES = {
    "market-analysis-agent":  {"cpu_seconds": 30, "memory_mb": 256},
    "position-sizing-agent":  {"cpu_seconds": 10, "memory_mb": 128},
    "execution-agent":        {"cpu_seconds": 5,  "memory_mb": 64},
    "cloud-provisioner":      {"cpu_seconds": 120, "memory_mb": 512},
}
```

### Step 4: Implement Pipeline Rollback Mechanisms

```python
from contextlib import contextmanager
from dataclasses import dataclass, field

@dataclass
class PipelineCheckpoint:
    stage_name: str
    timestamp: float
    state_snapshot: dict
    rollback_fn: callable
    committed: bool = False

class PipelineRollbackManager:
    def __init__(self):
        self._checkpoints: list[PipelineCheckpoint] = []

    def add_checkpoint(self, stage_name: str, state: dict, rollback_fn):
        self._checkpoints.append(PipelineCheckpoint(
            stage_name=stage_name,
            timestamp=time.time(),
            state_snapshot=state,
            rollback_fn=rollback_fn,
        ))

    def rollback_to(self, stage_name: str) -> list[str]:
        rolled_back = []
        for checkpoint in reversed(self._checkpoints):
            if checkpoint.stage_name == stage_name:
                break
            if not checkpoint.committed:
                checkpoint.rollback_fn(checkpoint.state_snapshot)
                rolled_back.append(checkpoint.stage_name)
        return rolled_back

@contextmanager
def pipeline_stage(manager: PipelineRollbackManager, name: str,
                    state: dict, rollback_fn, circuit_breaker: AgentCircuitBreaker):
    if not circuit_breaker.call_allowed():
        raise RuntimeError(f"Circuit breaker OPEN for stage '{name}' — pipeline halted")

    manager.add_checkpoint(name, state, rollback_fn)
    try:
        yield
        circuit_breaker.record_success()
        manager._checkpoints[-1].committed = True
    except Exception as e:
        circuit_breaker.record_failure()
        raise
```

### Step 5: Monitor Aggregate Pipeline Health

```bash
# Prometheus metrics for cascade detection
# Alert when >2 circuit breakers are open simultaneously
cat > /etc/prometheus/alerts/agent-cascade.yml << 'EOF'
groups:
- name: agent_cascade
  rules:
  - alert: MultipleBreakersTrippped
    expr: count(agent_circuit_breaker_state == 2) > 2
    for: 1m
    annotations:
      summary: "CASCADING FAILURE: {{ $value }} circuit breakers open simultaneously"

  - alert: PipelineStageFailureRate
    expr: rate(agent_stage_failures_total[5m]) > 0.5
    for: 2m
    annotations:
      summary: "High failure rate in agent pipeline stage {{ $labels.stage }}"
EOF

# Check current circuit breaker states in Redis
redis-cli --scan --pattern "cb:*:state" | while read key; do
  agent=$(echo $key | cut -d: -f2)
  state=$(redis-cli GET $key)
  echo "$agent: $state"
done
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Circuit Breaker** | A fault-tolerance pattern that stops sending requests to a failing service after a threshold is exceeded, allowing recovery without cascading |
| **Cascading Failure** | A failure that propagates from one component to dependent components, amplifying as it travels through the system |
| **Stage Boundary Validation** | Checking that each agent's output conforms to its schema before passing it to the next pipeline stage |
| **Operational Isolation** | Running each agent in its own process or container with resource limits so a runaway agent cannot exhaust shared resources |
| **Rollback Mechanism** | The ability to undo the effects of pipeline stages up to a known-good checkpoint when a failure is detected |
| **Half-Open State** | A circuit breaker state where one test call is allowed through to check if the failing agent has recovered |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Redis** | Shared state store for circuit breaker counters and state across distributed agent processes |
| **Pydantic** | Python data validation library for enforcing strict output schemas at each pipeline stage boundary |
| **Prometheus + Grafana** | Metrics collection and visualization for aggregate pipeline health and cascade detection dashboards |
| **CrewAI / LangGraph** | Agent orchestration frameworks with built-in stage management that can be extended with circuit breaker hooks |

## Common Scenarios

- **Financial cascade**: A market analysis agent is poisoned to report inflated risk limits. The position sizing agent accepts these limits and recommends oversized trades. Stage-boundary validation catches `recommended_position_size > 100,000` and halts the pipeline before the execution agent acts.
- **Cloud cost explosion**: A resource planning agent with a bug begins provisioning 100× the intended cloud resources. Per-agent resource quotas limit its API call rate; circuit breaker opens after 5 API errors; pipeline is halted.
- **Logic error amplification**: A data processing agent outputs malformed dates that cause every downstream agent to fail. The first failure increments the circuit breaker counter; after 5 failures the breaker opens, preventing the malformed data from continuing down the pipeline.

## Output Format

```json
{
  "pipeline_health_timestamp": "2026-04-26T23:00:00Z",
  "circuit_breakers": [
    {"agent": "market-analysis-agent", "state": "open", "failures": 5, "opened_at": "23:01:00"},
    {"agent": "position-sizing-agent", "state": "closed", "failures": 0}
  ],
  "cascade_event": {
    "detected": true,
    "origin_stage": "market-analysis-agent",
    "affected_stages": ["position-sizing-agent", "execution-agent"],
    "validation_failure": "recommended_position_size 450000 exceeds maximum 100000",
    "rollback_triggered": true,
    "stages_rolled_back": ["position-sizing-agent"]
  }
}
```
