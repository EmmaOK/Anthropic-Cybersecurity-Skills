---
name: human-agent-trust-and-oversight-controls
description: >-
  Implements oversight controls that prevent AI agents from exploiting human authority bias,
  anthropomorphism, and urgency framing to manipulate users into approving harmful or
  fraudulent actions. Agents can fabricate convincing audit trails, use expert positioning,
  or manufacture urgency to obtain inappropriate approvals. Covers multi-step approval
  workflows for high-risk decisions, explainability verification, uncertainty quantification,
  and friction injection that scales with action risk. Based on OWASP Top 10 for Agentic
  Applications (ASI09:2026 Human-Agent Trust Exploitation). Activates when designing human
  oversight workflows for AI agents, auditing approval mechanisms for manipulation resistance,
  or investigating incidents where users approved actions based on false agent rationale.
domain: cybersecurity
subdomain: ai-security
tags:
- agentic-security
- human-oversight
- explainability
- OWASP-Agentic-Top10
- ASI09
- approval-workflow
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0068
nist_ai_rmf:
- GOVERN-1.1
- GOVERN-1.7
- MEASURE-2.5
d3fend_techniques:
- User Behavior Analysis
- Audit Log Analysis
nist_csf:
- GV.OC-03
- GV.OC-05
- RS.AN-03
---
# Human-Agent Trust and Oversight Controls

## When to Use

- Designing approval workflows for AI agents that can initiate financial transactions, send communications, or make irreversible system changes
- Auditing existing agent UIs for dark patterns — urgency framing, authority language, or anthropomorphic cues that bypass critical human judgment
- Detecting when an agent is presenting fabricated reasoning or unsupported explanations to justify its recommended action
- Implementing uncertainty quantification so agents communicate genuine confidence rather than false certainty
- Investigating incidents where a user approved a harmful action because the agent presented a convincing but false rationale

**Do not use** to block all autonomous agent action — the goal is risk-calibrated friction, not universal human-in-the-loop requirements that negate agent value.

## Prerequisites

- Python 3.10+ with `anthropic` SDK or equivalent for explainability probing
- A structured approval workflow system (ticketing, Slack approval bots, or custom)
- `sentence-transformers` for verifying that agent explanations are grounded in cited evidence
- Audit log access to review the explanations provided to users at approval time
- UI/UX guidelines for removing anthropomorphic language from agent interfaces

## Workflow

### Step 1: Define Risk-Calibrated Approval Tiers

```python
from dataclasses import dataclass
from enum import Enum

class ApprovalTier(Enum):
    AUTO = "auto"           # no human required
    SOFT = "soft"           # notification only, auto-approved after 5 min
    CONFIRM = "confirm"     # single-step human confirmation
    MULTI_STEP = "multi_step"  # two independent approvers
    ESCALATE = "escalate"  # human expert + security review

@dataclass
class ActionRiskProfile:
    action_type: str
    max_financial_impact: float | None
    reversible: bool
    approval_tier: ApprovalTier
    max_auto_value: float | None = None  # for financial actions

ACTION_RISK_PROFILES: list[ActionRiskProfile] = [
    ActionRiskProfile("email_send",     None,      True,  ApprovalTier.CONFIRM),
    ActionRiskProfile("payment_initiate", 1_000,   True,  ApprovalTier.CONFIRM,    max_auto_value=100),
    ActionRiskProfile("payment_initiate", 50_000,  True,  ApprovalTier.MULTI_STEP),
    ActionRiskProfile("payment_initiate", float("inf"), True, ApprovalTier.ESCALATE),
    ActionRiskProfile("file_delete",    None,      False, ApprovalTier.CONFIRM),
    ActionRiskProfile("infrastructure_change", None, False, ApprovalTier.ESCALATE),
    ActionRiskProfile("data_read",      None,      True,  ApprovalTier.AUTO),
]

def get_approval_tier(action_type: str, amount: float | None = None) -> ApprovalTier:
    for profile in sorted(ACTION_RISK_PROFILES,
                           key=lambda p: p.max_financial_impact or float("inf")):
        if profile.action_type != action_type:
            continue
        if amount is not None and profile.max_auto_value and amount <= profile.max_auto_value:
            return ApprovalTier.AUTO
        if amount is None or profile.max_financial_impact is None or amount <= profile.max_financial_impact:
            return profile.approval_tier
    return ApprovalTier.ESCALATE
```

### Step 2: Verify Agent Explanations Are Grounded in Evidence

```python
from sentence_transformers import SentenceTransformer, util
import numpy as np

model = SentenceTransformer("all-MiniLM-L6-v2")

def verify_explanation_grounding(explanation: str,
                                   cited_sources: list[str],
                                   threshold: float = 0.40) -> dict:
    if not cited_sources:
        return {
            "grounded": False,
            "reason": "No sources cited — explanation is unverifiable",
            "severity": "HIGH"
        }

    explanation_emb = model.encode(explanation, normalize_embeddings=True)
    max_similarity = 0.0
    best_source = ""

    for source in cited_sources:
        source_emb = model.encode(source, normalize_embeddings=True)
        sim = float(np.dot(explanation_emb, source_emb))
        if sim > max_similarity:
            max_similarity = sim
            best_source = source

    grounded = max_similarity >= threshold
    return {
        "grounded": grounded,
        "max_source_similarity": round(max_similarity, 3),
        "best_matching_source": best_source[:100],
        "severity": None if grounded else "HIGH",
        "reason": None if grounded else "Explanation has low similarity to cited sources — possible hallucination"
    }
```

### Step 3: Strip Anthropomorphic and Urgency Language from Approval Prompts

```python
import re

URGENCY_PATTERNS = [
    r"\b(immediately|right now|urgent|critical|emergency|asap|time-sensitive)\b",
    r"\b(must|have to|need to|required to) (act|decide|approve|confirm) (now|immediately|today)\b",
    r"\b(limited time|deadline|expire[sd]|last chance)\b",
]

ANTHROPOMORPHIC_PATTERNS = [
    r"\b(I (think|believe|feel|know|recommend|suggest|urge))\b",
    r"\b(trust me|I am confident|I am certain|my analysis shows)\b",
    r"\b(as your (assistant|advisor|helper))\b",
]

AUTHORITY_PATTERNS = [
    r"\b(according to (policy|best practice|industry standard|regulation))\b(?!.*\[source)",
    r"\b(experts (say|recommend|agree))\b(?!.*\[source)",
]

def sanitize_approval_prompt(agent_explanation: str) -> dict:
    stripped_patterns = []
    sanitized = agent_explanation

    for pattern in URGENCY_PATTERNS + ANTHROPOMORPHIC_PATTERNS + AUTHORITY_PATTERNS:
        matches = list(re.finditer(pattern, sanitized, re.IGNORECASE))
        for m in matches:
            stripped_patterns.append({"type": "manipulative_language", "match": m.group(0)})
            sanitized = sanitized.replace(m.group(0), "[agent assessment]")

    return {
        "original_length": len(agent_explanation),
        "sanitized_explanation": sanitized,
        "patterns_removed": stripped_patterns,
        "manipulation_detected": bool(stripped_patterns),
    }
```

### Step 4: Implement Multi-Step Approval with Independent Reviewers

```python
import uuid, time

class ApprovalRequest:
    def __init__(self, action_type: str, action_details: dict,
                  agent_explanation: str, required_approvers: int = 1):
        self.request_id = str(uuid.uuid4())
        self.action_type = action_type
        self.action_details = action_details
        self.agent_explanation = agent_explanation
        self.required_approvers = required_approvers
        self.approvals: list[dict] = []
        self.created_at = time.time()
        self.expires_at = time.time() + 3600  # 1-hour window

    def add_approval(self, approver_id: str, decision: bool, comment: str = "") -> dict:
        if time.time() > self.expires_at:
            return {"accepted": False, "reason": "Approval request expired"}

        # Prevent the same person from approving twice
        if any(a["approver_id"] == approver_id for a in self.approvals):
            return {"accepted": False, "reason": "Approver has already voted"}

        self.approvals.append({
            "approver_id": approver_id,
            "decision": decision,
            "comment": comment,
            "timestamp": time.time()
        })

        approved_count = sum(1 for a in self.approvals if a["decision"])
        rejected_count = sum(1 for a in self.approvals if not a["decision"])

        if rejected_count > 0:
            return {"accepted": False, "final": True, "reason": "Rejected by an approver"}
        if approved_count >= self.required_approvers:
            return {"accepted": True, "final": True}
        return {"accepted": False, "final": False,
                "approvals_received": approved_count,
                "approvals_needed": self.required_approvers}
```

### Step 5: Audit Historical Approval Decisions for Manipulation Signals

```python
import json

def audit_approval_history(log_file: str) -> dict:
    with open(log_file) as f:
        events = [json.loads(line) for line in f]

    manipulation_indicators = []
    for event in events:
        # Agent explanations that were later found incorrect
        if event.get("explanation_verified") is False:
            manipulation_indicators.append({
                "request_id": event["request_id"],
                "issue": "ungrounded_explanation",
                "approved": event.get("approved", False),
                "impact": event.get("financial_impact", 0)
            })

        # Approvals made within seconds — possible rubber-stamping
        approval_time = event.get("approval_time_seconds", 999)
        if approval_time < 10 and event.get("approved"):
            manipulation_indicators.append({
                "request_id": event["request_id"],
                "issue": "instant_approval",
                "approval_time_s": approval_time,
                "risk": "human may not have reviewed explanation"
            })

    return {
        "total_requests": len(events),
        "manipulation_indicators": manipulation_indicators,
        "indicator_count": len(manipulation_indicators),
    }
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Authority Bias** | Human tendency to defer to an apparent expert or authority figure without critical evaluation |
| **Anthropomorphism** | Attributing human qualities to an AI agent, leading users to trust its judgments as they would a human expert |
| **Urgency Injection** | Including language like "immediately" or "critical" in agent prompts to shortcut careful deliberation |
| **Explainability Verification** | Checking that an agent's stated reasoning is actually grounded in the cited sources, not hallucinated |
| **Multi-Step Approval** | Requiring two independent approvers for high-risk actions, preventing a single manipulated approval from causing harm |
| **Friction Injection** | Deliberately adding effort to high-risk approval flows (confirmation dialogs, wait times, dual approval) to ensure deliberate review |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **sentence-transformers** | Semantic similarity scoring to verify that agent explanations are grounded in the documents they cite |
| **Anthropic Claude API** | Can be used to independently evaluate whether an agent's reasoning is logically consistent with its cited evidence |
| **PagerDuty / Opsgenie** | Escalation workflow tools for routing high-risk approval requests to on-call security or domain experts |
| **OWASP ASVS** | Application Security Verification Standard V3 provides guidance on human oversight controls for automated systems |

## Common Scenarios

- **Invoice fraud via urgency**: An agent processes a poisoned invoice and presents `"URGENT: This payment must be approved immediately to avoid contract breach."` The urgency sanitizer strips `"URGENT"` and `"immediately"`, and the slow-down friction adds a 10-minute review window.
- **Fabricated audit rationale**: An agent recommends deploying a configuration with known vulnerabilities and fabricates a policy citation. The explanation grounding check finds 0.12 similarity between the explanation and the cited policy document — flagged as likely hallucination.
- **Rubber-stamp approval**: A payment approval is accepted 3 seconds after presentation. The audit detects `approval_time_seconds = 3` and flags the approval as "instant" — a signal the reviewer did not read the explanation.

## Output Format

```json
{
  "approval_request_id": "req-abc123",
  "action_type": "payment_initiate",
  "amount": 45000,
  "approval_tier": "multi_step",
  "explanation_grounding": {
    "grounded": false,
    "max_source_similarity": 0.12,
    "severity": "HIGH",
    "reason": "Explanation has low similarity to cited sources — possible hallucination"
  },
  "sanitization": {
    "manipulation_detected": true,
    "patterns_removed": [
      {"type": "urgency", "match": "immediately"},
      {"type": "anthropomorphic", "match": "I am confident"}
    ]
  },
  "approval_status": "pending",
  "approvals_received": 1,
  "approvals_needed": 2,
  "recommendation": "request independent verification of cited sources before approving"
}
```
