"""
orchestrator.py — Multi-agent coordinator for Phantom.

Architecture:
  PhantomOrchestrator (coordinator) dispatches tasks to specialist agents:
    recon | webapp | ad | cloud | exploit | reporting

Each agent runs in its own thread with its own Claude context and Kali access.
Agents can self-spawn sub-agents (triggers: new target, HIGH finding,
parallel workload, report generation). Max depth = 3.

Usage:
    orch = PhantomOrchestrator()
    agent_id = orch.spawn_agent("recon", "Scan 10.10.10.0/24", targets=["10.10.10.0/24"])
    results  = orch.wait_for_all()
"""

import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

try:
    import anthropic
except ImportError:
    raise ImportError("pip install anthropic")

MODEL = "claude-opus-4-6"
MAX_TOKENS = 4096
MAX_DEPTH = 3
MAX_PARALLEL_AGENTS = 8

# ---------------------------------------------------------------------------
# Specialist personas
# ---------------------------------------------------------------------------

SPECIALIST_PERSONAS: dict[str, str] = {
    "coordinator": (
        "You are Phantom Coordinator, master orchestrator of a multi-agent cybersecurity team. "
        "Analyse the engagement scope, break it into parallel tasks, and dispatch specialist agents "
        "using spawn_agent. Available specialists: recon, webapp, ad, cloud, exploit, reporting. "
        "Rules: (1) Always confirm scope and targets before spawning. "
        "(2) Spawn recon agents first, then assessment agents based on what recon finds. "
        "(3) Escalate every HIGH/CRITICAL finding to an exploit agent for validation. "
        "(4) When all work is done, spawn one reporting agent to aggregate everything. "
        "Use get_agent_results to poll agent status. Synthesise findings across all agents in your final answer. "
        "Authorized lab environments only."
    ),
    "recon": (
        "You are a Phantom Recon Agent. Perform reconnaissance and discovery autonomously. "
        "Tools: nmap (port/service/OS), masscan (fast sweep), amass/subfinder/dnsx (subdomains), "
        "httpx (HTTP probing), whatweb/wafw00f (fingerprinting), arp-scan/netdiscover (host discovery). "
        "Use kali_exec or kali_docker_exec for every tool. "
        "When you find new hosts → spawn a recon agent per host. "
        "When you find web services → spawn a webapp agent. "
        "When you find SMB/LDAP/WinRM → spawn an ad agent. "
        "When you find cloud metadata endpoints → spawn a cloud agent. "
        "Output structured JSON: {hosts, services, open_ports, subdomains, notes}."
    ),
    "webapp": (
        "You are a Phantom WebApp Agent. Perform web application security testing autonomously. "
        "Tools: gobuster/feroxbuster/ffuf (fuzzing), nuclei (CVE templates), nikto (misconfig), "
        "sqlmap (SQLi), commix (command injection), wfuzz (parameter fuzzing), hydra (auth brute-force). "
        "Use kali_exec or kali_docker_exec for every tool. "
        "Spawn an exploit agent for every HIGH or CRITICAL finding. "
        "Output structured JSON: {findings: [{title, severity, url, evidence, cve, remediation}]}."
    ),
    "ad": (
        "You are a Phantom Active Directory Agent. Perform AD enumeration and attack path analysis. "
        "Tools: bloodhound-python (graph collection), netexec (SMB/LDAP/WinRM enum + spraying), "
        "ldapsearch (raw queries), impacket-secretsdump/psexec (credential extraction), "
        "evil-winrm (shell), certipy-ad (ADCS attacks), responder (LLMNR poisoning), hashcat (cracking). "
        "Use kali_exec or kali_docker_exec for every tool. "
        "Spawn an exploit agent when you find a privilege escalation path or valid credentials. "
        "Output structured JSON with ATT&CK technique IDs: {findings, attack_paths, credentials_obtained}."
    ),
    "cloud": (
        "You are a Phantom Cloud Agent. Perform cloud security assessment autonomously. "
        "Tools: aws (IAM enum, S3 exposure, EC2/Lambda recon), pacu (AWS exploitation framework). "
        "Use kali_exec or kali_docker_exec for every tool. "
        "Spawn an exploit agent for exposed credentials or privilege escalation paths. "
        "Output structured JSON: {provider, findings, misconfigured_resources, iam_risks}."
    ),
    "exploit": (
        "You are a Phantom Exploit Agent. Validate and exploit specific findings. "
        "Tools: searchsploit (CVE lookup), msfconsole/msfvenom (exploitation + payloads), "
        "manual techniques as appropriate. "
        "Only target systems you are explicitly authorized to test. "
        "Use kali_exec or kali_docker_exec for every tool. "
        "Document PoC steps, impact, CVSS score, and remediation for each finding. "
        "Output structured JSON: {exploited_findings: [{title, severity, poc_steps, impact, remediation}]}."
    ),
    "ai": (
        "You are a Phantom AI Security Agent. Test AI/LLM systems, agentic pipelines, and MCP servers "
        "for OWASP LLM Top 10 2025, OWASP Top 10 for Agentic Applications 2026, and OWASP MCP Top 10 v0.1 vulnerabilities. "
        "Execute tests using run_skill_agent for each applicable skill script: "
        "LLM01→detecting-ai-model-prompt-injection-attacks, "
        "LLM02→llm-output-validation-and-sanitization, "
        "LLM03→llm-data-and-model-poisoning-defense, "
        "LLM06→llm-sensitive-information-disclosure-prevention, "
        "LLM07→llm-system-prompt-leakage-prevention, "
        "LLM08→llm-excessive-agency-prevention, "
        "ASI01→agent-goal-hijacking-detection, "
        "ASI02→rogue-agent-detection-and-containment, "
        "ASI03→agent-memory-poisoning-detection-and-defense, "
        "ASI04→agentic-tool-misuse-detection-and-control, "
        "ASI05→agent-identity-and-privilege-governance, "
        "ASI06→agent-code-execution-sandboxing, "
        "ASI07→human-agent-trust-and-oversight-controls, "
        "ASI08→agentic-supply-chain-integrity-verification, "
        "ASI09→agentic-cascading-failure-prevention, "
        "MCP01→mcp-tool-poisoning-detection-and-defense, "
        "MCP02→mcp-authentication-and-authorization-hardening, "
        "MCP03→mcp-privilege-scope-enforcement, "
        "MCP04→mcp-context-injection-prevention, "
        "MCP05→mcp-shadow-server-discovery, "
        "MCP06→mcp-command-injection-prevention, "
        "MCP07→mcp-token-management-and-secret-protection, "
        "MCP08→mcp-intent-flow-subversion-detection, "
        "MCP09→mcp-audit-logging-and-telemetry-setup, "
        "MCP10→mcp-supply-chain-security-assessment. "
        "For broad LLM probe testing use kali_exec to run: "
        "python phantom/garak_runner.py --model-type anthropic --model-name claude-sonnet-4-6 --risks LLM01,LLM02,LLM06,LLM07. "
        "Output structured JSON findings mapped to OWASP risk IDs."
    ),
    "reporting": (
        "You are a Phantom Reporting Agent. Aggregate findings from all specialist agents "
        "into a structured security assessment report. "
        "Use get_agent_results to collect all agent output before writing. "
        "Report sections: executive summary, scope, methodology, findings by severity "
        "(CRITICAL / HIGH / MEDIUM / LOW / INFO), ATT&CK technique coverage heatmap, "
        "remediation priorities (quick wins first), risk score, appendices. "
        "Use write_file to save both JSON (machine-readable) and Markdown (human-readable) formats. "
        "Be precise, evidence-based, and remediation-focused."
    ),
}

# ---------------------------------------------------------------------------
# Agent result container
# ---------------------------------------------------------------------------

class AgentResult:
    def __init__(self, agent_id: str, agent_type: str, task: str, depth: int):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.task = task
        self.depth = depth
        self.status = "pending"   # pending | running | done | error
        self.result: str | None = None
        self.spawned: list[str] = []
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.finished_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "task": self.task,
            "depth": self.depth,
            "status": self.status,
            "result": self.result,
            "spawned_agents": self.spawned,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }

# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class PhantomOrchestrator:
    """
    Manages a pool of specialist agents that run in parallel threads
    and can self-spawn sub-agents up to MAX_DEPTH levels deep.
    """

    def __init__(self, api_key: str | None = None):
        self._client = anthropic.Anthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        )
        self._agents: dict[str, AgentResult] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=MAX_PARALLEL_AGENTS, thread_name_prefix="phantom-agent")

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def spawn_agent(
        self,
        agent_type: str,
        task: str,
        targets: list[str] | None = None,
        context: str | None = None,
        depth: int = 0,
        parent_id: str | None = None,
    ) -> str:
        """
        Spawn a specialist agent in a background thread.
        Returns agent_id immediately; poll with get_result().
        """
        if depth >= MAX_DEPTH:
            msg = f"[Orchestrator] Max depth {MAX_DEPTH} reached — cannot spawn {agent_type}"
            print(msg)
            return msg
        if agent_type not in SPECIALIST_PERSONAS:
            return f"[Error] Unknown agent type '{agent_type}'. Valid: {sorted(SPECIALIST_PERSONAS)}"

        agent_id = f"{agent_type[:4]}-{uuid.uuid4().hex[:6]}"
        ar = AgentResult(agent_id, agent_type, task, depth)

        with self._lock:
            self._agents[agent_id] = ar
            if parent_id and parent_id in self._agents:
                self._agents[parent_id].spawned.append(agent_id)

        print(f"\n[Orchestrator] + {agent_id}  type={agent_type}  depth={depth}")
        if targets:
            print(f"               targets={targets}")

        self._pool.submit(self._run_agent, agent_id, agent_type, task,
                          targets or [], context or "", depth)
        return agent_id

    def get_result(self, agent_id: str) -> dict:
        with self._lock:
            if agent_id not in self._agents:
                return {"error": f"Unknown agent: {agent_id}"}
            return self._agents[agent_id].to_dict()

    def get_all_results(self) -> dict:
        with self._lock:
            return {aid: a.to_dict() for aid, a in self._agents.items()}

    def wait_for_all(self, timeout: int = 1800) -> dict:
        """Block until all agents complete or timeout expires."""
        self._pool.shutdown(wait=True, cancel_futures=False)
        return self.get_all_results()

    def summary(self) -> str:
        with self._lock:
            agents = list(self._agents.values())
        if not agents:
            return "[Orchestrator] No agents spawned yet."
        lines = [f"[Orchestrator] {len(agents)} agent(s):"]
        for a in agents:
            indent = "  " + "  " * a.depth
            lines.append(
                f"{indent}{a.agent_id:22s} [{a.status:8s}]  {a.task[:55]}"
            )
        return "\n".join(lines)

    def reset(self):
        """Clear all agent state — call between engagements."""
        with self._lock:
            self._agents.clear()
        self._pool = ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_AGENTS, thread_name_prefix="phantom-agent"
        )

    # ------------------------------------------------------------------ #
    # Internal agent loop                                                  #
    # ------------------------------------------------------------------ #

    def _run_agent(
        self,
        agent_id: str,
        agent_type: str,
        task: str,
        targets: list[str],
        context: str,
        depth: int,
    ):
        self._set_status(agent_id, "running")
        try:
            result = self._agent_loop(agent_id, agent_type, task, targets, context, depth)
            self._set_status(agent_id, "done", result)
            print(f"\n[Orchestrator] ✓ {agent_id} done.")
        except Exception as e:
            self._set_status(agent_id, "error", str(e))
            print(f"\n[Orchestrator] ✗ {agent_id} error: {e}")

    def _agent_loop(
        self,
        agent_id: str,
        agent_type: str,
        task: str,
        targets: list[str],
        context: str,
        depth: int,
    ) -> str:
        from tools import TOOLS
        from main import dispatch_tool

        agent_tools = TOOLS + [spawn_agent_tool_def(), get_agent_results_tool_def()]
        system = SPECIALIST_PERSONAS[agent_type]
        target_str = ", ".join(targets) if targets else "see task"
        messages = [{
            "role": "user",
            "content": (
                f"Agent ID: {agent_id}  |  Type: {agent_type}  |  Depth: {depth}/{MAX_DEPTH}\n"
                f"Task: {task}\n"
                f"Targets: {target_str}\n"
                f"Context from parent: {context or 'none'}\n\n"
                "Execute your task autonomously. Use kali_exec or kali_docker_exec for all tool "
                "execution. Spawn sub-agents for parallel work where appropriate. "
                "Output structured JSON findings when complete."
            ),
        }]

        while True:
            response = self._client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=system,
                tools=agent_tools,
                messages=messages,
            )

            text_parts = [b.text for b in response.content if b.type == "text"]

            if response.stop_reason == "end_turn":
                return "\n".join(text_parts)

            if response.stop_reason == "tool_use":
                # Build assistant message
                assistant_blocks = []
                for b in response.content:
                    if b.type == "tool_use":
                        assistant_blocks.append({
                            "type": "tool_use", "id": b.id,
                            "name": b.name, "input": b.input,
                        })
                    else:
                        assistant_blocks.append({"type": "text", "text": getattr(b, "text", "")})
                messages.append({"role": "assistant", "content": assistant_blocks})

                # Execute tools
                tool_results = []
                for block in response.content:
                    if block.type != "tool_use":
                        continue
                    name, inp = block.name, block.input
                    print(f"  [{agent_id}] tool: {name}")

                    if name == "spawn_agent":
                        result = self.spawn_agent(
                            agent_type=inp.get("agent_type", "recon"),
                            task=inp.get("task", ""),
                            targets=inp.get("targets", []),
                            context=inp.get("context", ""),
                            depth=depth + 1,
                            parent_id=agent_id,
                        )
                    elif name == "get_agent_results":
                        req = inp.get("agent_id")
                        result = json.dumps(
                            self.get_result(req) if req else self.get_all_results(),
                            indent=2,
                        )
                    else:
                        result = dispatch_tool(name, inp)

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": str(result),
                    })

                messages.append({"role": "user", "content": tool_results})
                continue

            return "\n".join(text_parts) if text_parts else "[No output]"

    def _set_status(self, agent_id: str, status: str, result: str | None = None):
        with self._lock:
            if agent_id not in self._agents:
                return
            self._agents[agent_id].status = status
            if result is not None:
                self._agents[agent_id].result = result
            if status in ("done", "error"):
                self._agents[agent_id].finished_at = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Orchestration tool definitions (injected into every agent's tool list)
# ---------------------------------------------------------------------------

def spawn_agent_tool_def() -> dict:
    return {
        "name": "spawn_agent",
        "description": (
            "Spawn a specialist sub-agent to work on a task in parallel. "
            "Trigger when: a new host/service is discovered (recon/webapp/ad/cloud), "
            "a HIGH or CRITICAL finding needs validation (exploit), "
            "the scope is too large for one agent (parallel recon), "
            "or all work is done and a report is needed (reporting). "
            "Returns agent_id immediately — agent runs in background. "
            "Use get_agent_results to poll status and retrieve output."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_type": {
                    "type": "string",
                    "enum": ["recon", "webapp", "ad", "cloud", "exploit", "reporting"],
                },
                "task": {"type": "string", "description": "Specific task for this agent."},
                "targets": {
                    "type": "array", "items": {"type": "string"},
                    "description": "IPs, hostnames, or URLs for this agent.",
                },
                "context": {
                    "type": "string",
                    "description": "Findings or context from parent agent to share.",
                },
            },
            "required": ["agent_type", "task"],
        },
    }


def get_agent_results_tool_def() -> dict:
    return {
        "name": "get_agent_results",
        "description": (
            "Retrieve the current status and output of a spawned agent. "
            "Pass agent_id for one agent, or omit to get all agents."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Specific agent ID to query. Omit for all agents.",
                },
            },
            "required": [],
        },
    }
