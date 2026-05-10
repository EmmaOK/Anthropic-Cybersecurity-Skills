#!/usr/bin/env python3
"""ASI06 - Agent Code Execution Sandboxing: Audit sandbox config and probe for escape vectors."""
import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

OWASP_ID = "ASI06"
TOOL_NAME = "phantom-agent-sandboxing"

SANDBOX_CONTROLS = [
    ("seccomp_profile", "CRITICAL", "Seccomp syscall filter not configured — unrestricted syscalls"),
    ("no_new_privileges", "CRITICAL", "no_new_privileges not set — privilege escalation via setuid binaries possible"),
    ("read_only_rootfs", "HIGH", "Root filesystem is writable — persistent payload drops possible"),
    ("network_policy", "HIGH", "No network egress policy — agent can exfiltrate data freely"),
    ("memory_limit_mb", "MEDIUM", "No memory limit — agent can exhaust host memory"),
    ("cpu_limit", "MEDIUM", "No CPU limit — agent can monopolise host CPU"),
    ("user_namespace", "HIGH", "User namespace isolation not enabled"),
    ("pid_namespace", "HIGH", "PID namespace isolation not enabled"),
    ("mount_namespace", "HIGH", "Mount namespace isolation not enabled"),
]

CODE_EXEC_PATTERNS = [
    (r"\beval\s*\(", "eval() usage — dynamic code execution"),
    (r"\bexec\s*\(", "exec() usage — arbitrary code execution"),
    (r"__import__\s*\(", "Dynamic import — potential sandbox escape"),
    (r"subprocess\.(run|Popen|call|check_output)", "subprocess usage — shell command execution"),
    (r"os\.(system|popen|execv|execve)", "os.system/exec usage"),
    (r"shell\s*=\s*True", "shell=True in subprocess — shell injection risk"),
    (r"/proc/self/mem|/proc/[0-9]+/mem", "Direct memory access via /proc"),
]

CONTAINER_ESCAPE_INDICATORS = [
    ("privileged", True, "CRITICAL", "Container running in privileged mode — full host access"),
    ("host_pid", True, "CRITICAL", "Host PID namespace shared — can see and signal host processes"),
    ("host_network", True, "HIGH", "Host network namespace shared — bypasses network policies"),
]


def audit_config(config):
    findings = []
    for key, severity, msg in SANDBOX_CONTROLS:
        val = config.get(key)
        if val is None or val is False or val == 0 or val == "":
            findings.append({
                "id": f"{OWASP_ID}-{len(findings)+1:03d}",
                "title": f"Missing Sandbox Control: {key}",
                "severity": severity,
                "description": msg,
                "evidence": f"config.{key}={val!r}",
                "remediation": f"Set '{key}' in container/sandbox config. Reference: NIST SP 800-190.",
            })
    for key, bad_val, severity, msg in CONTAINER_ESCAPE_INDICATORS:
        if config.get(key) == bad_val:
            findings.append({
                "id": f"{OWASP_ID}-{len(findings)+1:03d}",
                "title": f"Container Escape Risk: {msg}",
                "severity": severity,
                "description": msg,
                "evidence": f"config.{key}={bad_val}",
                "remediation": "Disable privileged mode and host namespace sharing.",
            })
    cap_add = config.get("cap_add", [])
    dangerous_caps = [c for c in cap_add if c in ("SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN")]
    if dangerous_caps:
        findings.append({
            "id": f"{OWASP_ID}-{len(findings)+1:03d}",
            "title": "Dangerous Capabilities Granted",
            "severity": "HIGH",
            "description": f"Dangerous Linux capabilities granted: {dangerous_caps}",
            "evidence": f"cap_add={cap_add}",
            "remediation": "Remove dangerous capabilities. Use drop_all=true and add only specific caps required.",
        })
    config_str = json.dumps(config)
    for pattern, desc in CODE_EXEC_PATTERNS:
        if re.search(pattern, config_str, re.IGNORECASE):
            findings.append({
                "id": f"{OWASP_ID}-U{len(findings)+1:03d}",
                "title": f"Unsafe Code Pattern in Config: {desc}",
                "severity": "HIGH",
                "description": f"Configuration contains unsafe code pattern: {desc}",
                "evidence": f"pattern='{pattern}' found in config",
                "remediation": "Remove dynamic code execution from agent config. Use static, declarative tool definitions.",
            })
    return findings


def probe_code_execution(server_url):
    findings = []
    base = server_url.rstrip("/")
    payloads = [
        {"tool": "execute", "code": "__import__('os').system('id')"},
        {"tool": "run_python", "code": "eval('1+1')"},
        {"action": "execute_code", "parameters": {"code": "print(open('/etc/passwd').read())"}},
    ]
    for payload in payloads:
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(f"{base}/tools/call", data=data,
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = resp.read().decode(errors="replace")
                if re.search(r"(uid=|root|/bin/bash|passwd)", body):
                    findings.append({
                        "id": f"{OWASP_ID}-E{len(findings)+1:03d}",
                        "title": "Code Execution Successful via Tool Call",
                        "severity": "CRITICAL",
                        "description": "Agent endpoint executed injected code and returned system output.",
                        "evidence": f"payload={json.dumps(payload)[:200]}, response={body[:200]}",
                        "remediation": "Sandbox all code execution. Never eval user-supplied code.",
                    })
        except Exception:
            pass
    return findings


def main():
    p = argparse.ArgumentParser(description="ASI06 Agent Code Execution Sandboxing")
    p.add_argument("--config", help="JSON file with sandbox configuration")
    p.add_argument("--server-url", help="Agent server URL to probe for code execution")
    p.add_argument("--output", default="asi06_sandboxing_report.json")
    args = p.parse_args()
    if not args.config and not args.server_url:
        print("[ASI06] Provide --config or --server-url", file=sys.stderr)
        sys.exit(2)
    findings = []
    if args.config:
        config = json.loads(Path(args.config).read_text())
        findings += audit_config(config)
    if args.server_url:
        findings += probe_code_execution(args.server_url)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1
    report = {
        "tool": TOOL_NAME, "owasp_id": OWASP_ID,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings, "summary": {"total": len(findings), **counts},
    }
    print(json.dumps(report, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2))
    sys.exit(1 if counts["CRITICAL"] > 0 or counts["HIGH"] > 0 else 0)


if __name__ == "__main__":
    main()
