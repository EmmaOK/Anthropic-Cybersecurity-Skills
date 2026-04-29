---
name: llm-resource-consumption-and-dos-prevention
description: >-
  Prevents unbounded resource consumption in LLM-powered applications through rate
  limiting, token budget enforcement, and detection of adversarial inputs designed to
  exhaust inference compute. Unbounded consumption allows adversaries to cause denial of
  service, run up cloud inference costs, or degrade quality for other users through
  carefully crafted long prompts, recursive tool calls, or algorithmic complexity attacks.
  Covers per-user token budgets, input length limits, prompt complexity scoring, queue
  fairness policies, cost monitoring with automatic cutoffs, and canary token attacks that
  force expensive re-generation. Based on OWASP LLM Top 10 (LLM10:2025 Unbounded
  Consumption). Activates when deploying a public-facing LLM endpoint, detecting anomalous
  inference cost spikes, or designing resource governance for a multi-tenant LLM service.
domain: cybersecurity
subdomain: ai-security
tags:
- LLM-security
- OWASP-LLM-Top10
- LLM10
- rate-limiting
- DoS-prevention
- token-budget
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0088
- AML.T0057
nist_ai_rmf:
- GOVERN-6.1
- MEASURE-3.1
- MANAGE-2.2
d3fend_techniques:
- Network Traffic Filtering
- Resource Restriction
nist_csf:
- PR.PS-04
- DE.CM-01
- RS.MI-01
---
# LLM Resource Consumption and DoS Prevention

## When to Use

- Deploying a public-facing LLM API endpoint and need to enforce per-user token and cost budgets
- Detecting adversarial inputs designed to maximize inference time (long prompts, repetitive patterns, algorithmic complexity attacks)
- Implementing queue fairness controls in a multi-tenant LLM service to prevent one tenant from monopolizing compute
- Monitoring for inference cost anomalies that may indicate adversarial resource exhaustion or billing abuse
- Designing automatic circuit breakers that halt inference when cost or token budgets are exceeded

**Do not use** input length limits alone as the only defense — measure actual token cost and complexity, not just character count.

## Prerequisites

- Python 3.10+ with `anthropic`, `redis`, `tiktoken`, `fastapi`, `prometheus-client`
- `redis`: `pip install redis` for distributed rate limiting and token budget tracking
- `tiktoken`: `pip install tiktoken` for accurate token counting before inference
- `fastapi`: `pip install fastapi` for middleware implementation
- `prometheus-client`: `pip install prometheus-client` for cost and usage telemetry

## Workflow

### Step 1: Count Tokens and Enforce Input Limits Before Inference

```python
import tiktoken
import re

def count_tokens(text: str, model: str = "claude-sonnet-4-6") -> int:
    # Use cl100k_base as proxy for Claude tokenization (within ~5% accuracy)
    enc = tiktoken.get_encoding("cl100k_base")
    return len(enc.encode(text))

def validate_input_budget(
    user_message: str,
    system_prompt: str,
    user_id: str,
    max_input_tokens: int = 4000,
    max_input_chars: int = 16000
) -> dict:
    issues = []

    if len(user_message) > max_input_chars:
        issues.append({
            "check": "MAX_CHAR_LENGTH",
            "value": len(user_message),
            "limit": max_input_chars,
            "severity": "HIGH"
        })

    total_tokens = count_tokens(system_prompt + "\n\n" + user_message)
    if total_tokens > max_input_tokens:
        issues.append({
            "check": "MAX_TOKEN_LENGTH",
            "value": total_tokens,
            "limit": max_input_tokens,
            "severity": "HIGH"
        })

    # Detect token-multiplying patterns (repetition attacks)
    repeat_ratio = detect_repetition_ratio(user_message)
    if repeat_ratio > 0.7:
        issues.append({
            "check": "REPETITION_ATTACK",
            "repeat_ratio": round(repeat_ratio, 3),
            "severity": "HIGH",
            "detail": "High repetition ratio suggests token-multiplying DoS attempt"
        })

    return {
        "user_id": user_id,
        "input_tokens": total_tokens,
        "input_chars": len(user_message),
        "issues": issues,
        "allowed": not bool(issues)
    }

def detect_repetition_ratio(text: str) -> float:
    """Measure ratio of repeated n-grams — high ratio indicates padding/flooding."""
    words = text.lower().split()
    if len(words) < 20:
        return 0.0
    trigrams = [tuple(words[i:i+3]) for i in range(len(words) - 2)]
    unique = len(set(trigrams))
    return 1.0 - (unique / len(trigrams)) if trigrams else 0.0
```

### Step 2: Enforce Per-User Token Budgets with Redis

```python
import redis
import time

r = redis.Redis(host="localhost", port=6379, decode_responses=True)

DAILY_TOKEN_BUDGET = 100_000    # tokens per user per day
HOURLY_TOKEN_BUDGET = 20_000    # tokens per user per hour
COST_PER_1K_INPUT_TOKENS = 0.003   # USD — update per provider pricing
COST_PER_1K_OUTPUT_TOKENS = 0.015

def check_and_deduct_token_budget(user_id: str,
                                   input_tokens: int,
                                   output_tokens: int) -> dict:
    day_key = f"budget:day:{user_id}:{time.strftime('%Y%m%d')}"
    hour_key = f"budget:hour:{user_id}:{time.strftime('%Y%m%d%H')}"

    pipe = r.pipeline()
    pipe.get(day_key)
    pipe.get(hour_key)
    day_used, hour_used = pipe.execute()

    day_used = int(day_used or 0)
    hour_used = int(hour_used or 0)
    total_tokens = input_tokens + output_tokens

    if day_used + total_tokens > DAILY_TOKEN_BUDGET:
        return {
            "allowed": False,
            "reason": "DAILY_BUDGET_EXCEEDED",
            "day_used": day_used,
            "day_limit": DAILY_TOKEN_BUDGET,
            "retry_after": "next UTC day"
        }

    if hour_used + total_tokens > HOURLY_TOKEN_BUDGET:
        return {
            "allowed": False,
            "reason": "HOURLY_BUDGET_EXCEEDED",
            "hour_used": hour_used,
            "hour_limit": HOURLY_TOKEN_BUDGET,
            "retry_after": "next UTC hour"
        }

    # Deduct tokens and set expiry
    pipe = r.pipeline()
    pipe.incrby(day_key, total_tokens)
    pipe.expire(day_key, 86400)
    pipe.incrby(hour_key, total_tokens)
    pipe.expire(hour_key, 3600)
    pipe.execute()

    cost = (input_tokens / 1000 * COST_PER_1K_INPUT_TOKENS +
            output_tokens / 1000 * COST_PER_1K_OUTPUT_TOKENS)

    return {
        "allowed": True,
        "day_used": day_used + total_tokens,
        "hour_used": hour_used + total_tokens,
        "estimated_cost_usd": round(cost, 6)
    }
```

### Step 3: Detect Adversarial Prompt Complexity Attacks

```python
import re, math

def score_prompt_complexity(text: str) -> dict:
    """Score a prompt for patterns designed to maximize LLM inference cost."""
    scores = {}

    # Recursive or self-referential patterns force deep reasoning
    recursive_patterns = [
        r"(?i)(repeat|restate|rewrite|paraphrase).{0,50}(again|more time|once more)",
        r"(?i)(for each|for every|iterate|enumerate).{0,30}(\d{3,}|\bmany\b|\ball\b)",
        r"(?i)(expand|elaborate|detail).{0,30}(every|each|all|comprehensive)",
    ]
    recursive_score = sum(
        len(re.findall(pat, text)) for pat in recursive_patterns
    )
    scores["recursive_instruction_count"] = recursive_score

    # Excessively long nested structures
    bracket_depth = max(
        (text.count("(") + text.count("[") + text.count("{")),
        0
    )
    scores["nesting_depth_proxy"] = bracket_depth

    # Mathematical/algorithmic complexity requests
    algo_patterns = [
        r"(?i)(generate|list|enumerate|output).{0,30}(all|every).{0,20}(prime|fibonacci|permut|combin)",
        r"(?i)(\d{4,})-?step",  # requests for thousands of steps
    ]
    scores["algorithmic_complexity_signals"] = sum(
        len(re.findall(pat, text)) for pat in algo_patterns
    )

    # Entropy — low entropy indicates padding/repetition flooding
    words = text.lower().split()
    freq = {}
    for w in words:
        freq[w] = freq.get(w, 0) + 1
    entropy = -sum((c/len(words)) * math.log2(c/len(words))
                   for c in freq.values()) if words else 0
    scores["token_entropy"] = round(entropy, 3)

    overall_risk = "HIGH" if (
        recursive_score > 2 or
        scores["algorithmic_complexity_signals"] > 0 or
        (entropy < 2.0 and len(words) > 100)
    ) else "MEDIUM" if recursive_score > 0 else "LOW"

    return {
        "scores": scores,
        "overall_risk": overall_risk,
        "blocked": overall_risk == "HIGH"
    }
```

### Step 4: Implement Request Queue Fairness and Rate Limiting

```python
import time

def rate_limit_check(user_id: str,
                     requests_per_minute: int = 10,
                     burst_limit: int = 20) -> dict:
    """Sliding window rate limiter using Redis sorted sets."""
    now = time.time()
    window_start = now - 60  # 1-minute window
    key = f"ratelimit:{user_id}"

    pipe = r.pipeline()
    pipe.zremrangebyscore(key, 0, window_start)  # remove old requests
    pipe.zcard(key)                               # count recent requests
    pipe.zadd(key, {str(now): now})              # add current request
    pipe.expire(key, 120)
    _, count_before, _, _ = pipe.execute()

    if count_before >= burst_limit:
        return {
            "allowed": False,
            "reason": "BURST_LIMIT_EXCEEDED",
            "requests_in_window": count_before,
            "limit": burst_limit,
            "retry_after_seconds": 60
        }

    if count_before >= requests_per_minute:
        return {
            "allowed": False,
            "reason": "RATE_LIMIT_EXCEEDED",
            "requests_in_window": count_before,
            "limit": requests_per_minute,
            "retry_after_seconds": 30
        }

    return {"allowed": True, "requests_in_window": count_before + 1}

def enforce_max_tokens_output(max_output_tokens: int = 2000) -> dict:
    """Return parameter constraint to pass to the LLM API."""
    return {
        "max_tokens": max_output_tokens,
        "note": "Hard-cap output tokens to prevent runaway generation costs"
    }
```

### Step 5: Monitor and Alert on Cost Anomalies

```python
import datetime
from prometheus_client import Counter, Histogram, Gauge, push_to_gateway

token_counter = Counter("llm_tokens_total", "Total tokens consumed", ["user_id", "type"])
cost_gauge = Gauge("llm_cost_usd_daily", "Daily cost in USD", ["user_id"])
latency_histogram = Histogram("llm_inference_latency_seconds", "Inference latency")

COST_ALERT_THRESHOLD_USD = 50.0  # alert if daily cost exceeds $50

def record_inference_metrics(user_id: str, input_tokens: int,
                              output_tokens: int, latency_s: float):
    token_counter.labels(user_id=user_id, type="input").inc(input_tokens)
    token_counter.labels(user_id=user_id, type="output").inc(output_tokens)
    latency_histogram.observe(latency_s)

    cost = (input_tokens / 1000 * COST_PER_1K_INPUT_TOKENS +
            output_tokens / 1000 * COST_PER_1K_OUTPUT_TOKENS)
    cost_key = f"cost:day:{user_id}:{datetime.date.today().isoformat()}"
    new_total = r.incrbyfloat(cost_key, cost)
    r.expire(cost_key, 86400)
    cost_gauge.labels(user_id=user_id).set(new_total)

    if new_total > COST_ALERT_THRESHOLD_USD:
        return {
            "alert": True,
            "alert_type": "COST_THRESHOLD_EXCEEDED",
            "user_id": user_id,
            "daily_cost_usd": round(new_total, 4),
            "threshold_usd": COST_ALERT_THRESHOLD_USD,
            "severity": "HIGH",
            "action": "throttle or suspend user inference"
        }

    return {"alert": False, "daily_cost_usd": round(new_total, 4)}
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Unbounded Consumption** | An attack or design flaw where adversarial inputs or unrestricted usage causes an LLM application to consume disproportionate compute, memory, or API cost |
| **Token Budget** | A per-user or per-session cap on the number of tokens that can be consumed over a time window, enforced before inference begins |
| **Repetition Attack** | Flooding a prompt with repeated text or patterns to exhaust context windows and force expensive re-processing |
| **Algorithmic Complexity Attack** | Prompting an LLM to perform compute-intensive operations (enumerate all primes, generate every permutation) that exhaust server resources |
| **Sliding Window Rate Limiter** | A rate-limiting algorithm that tracks requests within a rolling time window rather than fixed intervals, preventing burst-through attacks |
| **Inference Cost Anomaly** | An unexpected spike in token consumption or billing that may indicate adversarial abuse, misconfiguration, or runaway agent loops |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **tiktoken** | OpenAI's tokenizer library (cl100k_base); provides accurate token counts before inference for budget enforcement |
| **Redis** | In-memory data store for distributed rate limiting, per-user token budgets, and sliding window counters |
| **Prometheus + Grafana** | Metrics collection and dashboarding for LLM inference cost, token usage, and latency anomaly detection |
| **FastAPI middleware** | Request interception layer for applying rate limits, input validation, and token budget checks before routing to the LLM |
| **Anthropic API (max_tokens)** | Hard-cap on output generation length; always set `max_tokens` to prevent runaway generation in the API call |

## Common Scenarios

- **Repetition flooding attack**: An adversarial user submits a 15,000-character prompt consisting of repeated phrases. The repetition ratio detector scores 0.89 (>0.7 threshold) and blocks the request before inference.
- **Recursive instruction exhaustion**: A prompt asks the LLM to "expand each of the following 500 items in detail." Complexity scoring detects the algorithmic expansion pattern and flags it as HIGH risk; the request is rate-limited.
- **Cost spike from runaway agent loop**: An autonomous agent enters an infinite tool-call loop, accumulating $200 in inference costs within an hour. The cost monitoring alert fires at the $50 threshold; the agent session is suspended and the user is notified.

## Output Format

```json
{
  "request_timestamp": "2026-04-27T17:00:00Z",
  "user_id": "user-8821",
  "input_validation": {
    "input_tokens": 8200,
    "limit": 4000,
    "allowed": false,
    "issues": [{"check": "MAX_TOKEN_LENGTH", "severity": "HIGH"}]
  },
  "rate_limit": {
    "allowed": false,
    "reason": "BURST_LIMIT_EXCEEDED",
    "requests_in_window": 22,
    "limit": 20,
    "retry_after_seconds": 60
  },
  "complexity_check": {
    "overall_risk": "HIGH",
    "blocked": true,
    "scores": {"recursive_instruction_count": 3, "token_entropy": 1.8}
  },
  "cost_alert": {
    "alert": true,
    "daily_cost_usd": 54.21,
    "action": "throttle or suspend user inference"
  },
  "action": "request_blocked"
}
```
