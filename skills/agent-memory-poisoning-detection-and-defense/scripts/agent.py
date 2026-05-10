#!/usr/bin/env python3
"""
ASI03 - Agent Memory Poisoning Detection and Defense
Audits agent memory stores and conversation logs for injected malicious content.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

INJECTION_PATTERNS = [
    (r"ignore (previous|all|above|prior) instructions?", "CRITICAL", "Direct instruction override attempt"),
    (r"(you are now|act as|pretend (you are|to be)|roleplay as)", "HIGH", "Persona hijacking pattern"),
    (r"(system prompt|system message|your instructions).{0,50}(forget|ignore|override|replace)", "CRITICAL", "System prompt manipulation"),
    (r"<(system|instruction|admin|root)>", "HIGH", "Pseudo-system tag injection"),
    (r"(execute|run|eval|os\.system|subprocess)\s*\(", "CRITICAL", "Code execution injection"),
    (r"(exfiltrate|send|transmit|upload).{0,50}(data|credentials|keys|secrets)", "HIGH", "Data exfiltration instruction"),
    (r"(disable|bypass|skip|remove).{0,50}(safety|filter|guardrail|restriction|check)", "HIGH", "Safety bypass attempt"),
    (r"\[INST\]|\[\/INST\]|<<SYS>>|<</SYS>>", "HIGH", "LLM control token injection"),
    (r"(remember|store|memorize|save).{0,50}(this instruction|following|always)", "MEDIUM", "Persistent instruction implant"),
    (r"when (asked|queried|prompted).{0,100}(respond|say|output|return)", "MEDIUM", "Conditional behaviour implant"),
]

CROSS_SESSION_PATTERNS = [
    r"user_id\s*[:=]\s*['\"]?\w+['\"]?",
    r"session_id\s*[:=]\s*['\"]?\w+['\"]?",
]


def scan_log_file(log_path: str) -> list[dict]:
    findings = []
    path = Path(log_path)
    if not path.exists():
        return [{"id": "ASI03-E001", "title": "Log file not found", "severity": "MEDIUM",
                 "description": f"Log file {log_path} does not exist.",
                 "evidence": log_path, "remediation": "Ensure agent conversation logs are persisted and accessible."}]

    content = path.read_text(errors="replace")
    lines = content.splitlines()

    # Parse JSONL or plain text
    entries = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            entries.append({"raw": line})

    # Scan each entry for injection patterns
    seen_sessions = set()
    memory_recall_count = 0

    for i, entry in enumerate(entries):
        text = json.dumps(entry) if isinstance(entry, dict) else str(entry)

        for pattern, severity, desc in INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append({
                    "id": f"ASI03-{len(findings)+1:03d}",
                    "title": f"Memory Injection: {desc}",
                    "severity": severity,
                    "description": f"Injection pattern detected in memory entry {i}: {desc}",
                    "evidence": text[:300],
                    "remediation": "Sanitise all content before storing in agent memory. Apply injection detection classifier at memory write time.",
                })

        # Track cross-session indicators
        for pattern in CROSS_SESSION_PATTERNS:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                seen_sessions.add(m.group(0))

        # Count memory recall events
        if re.search(r"(recall|retrieve|fetch|lookup|remember|memory)", text, re.IGNORECASE):
            memory_recall_count += 1

    # Flag unusual memory recall volume
    if memory_recall_count > len(entries) * 0.5 and len(entries) > 10:
        findings.append({
            "id": f"ASI03-{len(findings)+1:03d}",
            "title": "Anomalous Memory Recall Frequency",
            "severity": "MEDIUM",
            "description": f"Memory recall events ({memory_recall_count}) exceed 50% of total log entries ({len(entries)}). Possible memory probing.",
            "evidence": f"memory_recall_count={memory_recall_count}, total_entries={len(entries)}",
            "remediation": "Implement rate limiting on memory retrieval operations and alert on unusual recall patterns.",
        })

    # Cross-session contamination check
    if len(seen_sessions) > 1:
        findings.append({
            "id": f"ASI03-{len(findings)+1:03d}",
            "title": "Potential Cross-Session Memory Contamination",
            "severity": "HIGH",
            "description": f"Multiple session identifiers found in a single memory log: {list(seen_sessions)[:5]}",
            "evidence": str(list(seen_sessions)[:5]),
            "remediation": "Enforce strict session isolation in memory stores. Use namespace-based separation per user/session.",
        })

    return findings


def probe_memory_store(url: str) -> list[dict]:
    findings = []
    try:
        import urllib.request
        import urllib.error

        # Probe 1: Unauthenticated access
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    findings.append({
                        "id": f"ASI03-M001",
                        "title": "Memory Store: Unauthenticated Access",
                        "severity": "CRITICAL",
                        "description": "Vector/memory store accessible without authentication.",
                        "evidence": f"GET {url} returned HTTP 200",
                        "remediation": "Enforce authentication on all memory store endpoints. Use API keys or mTLS.",
                    })
        except urllib.error.HTTPError as e:
            if e.code in (200, 201):
                pass  # Already found
        except Exception:
            pass

        # Probe 2: Namespace enumeration
        for ns_path in ["/namespaces", "/collections", "/indexes", "/_cat/indices"]:
            try:
                test_url = url.rstrip("/") + ns_path
                req = urllib.request.Request(test_url)
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status == 200:
                        findings.append({
                            "id": f"ASI03-M002",
                            "title": "Memory Store: Namespace Enumeration Possible",
                            "severity": "HIGH",
                            "description": f"Memory store namespaces/collections can be enumerated via {ns_path}",
                            "evidence": f"GET {test_url} → HTTP 200",
                            "remediation": "Restrict namespace listing to admin roles only.",
                        })
            except Exception:
                pass

    except ImportError:
        pass

    return findings


def main():
    p = argparse.ArgumentParser(description="ASI03 Memory Poisoning Detection")
    p.add_argument("--memory-store-url", help="Vector DB / memory store endpoint URL")
    p.add_argument("--log-file", help="Agent conversation log (JSON/JSONL/text)")
    p.add_argument("--output", default="asi03_memory_poisoning_report.json")
    args = p.parse_args()

    if not args.memory_store_url and not args.log_file:
        print("[ASI03] Provide --memory-store-url or --log-file", file=sys.stderr)
        sys.exit(2)

    findings = []
    if args.log_file:
        findings += scan_log_file(args.log_file)
    if args.memory_store_url:
        findings += probe_memory_store(args.memory_store_url)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    report = {
        "tool": "phantom-agentic-memory-poisoning",
        "owasp_id": "ASI03",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "summary": {"total": len(findings), "critical": counts["CRITICAL"],
                    "high": counts["HIGH"], "medium": counts["MEDIUM"],
                    "low": counts["LOW"]},
    }

    out = json.dumps(report, indent=2)
    print(out)
    if args.output:
        Path(args.output).write_text(out)

    if counts["CRITICAL"] > 0 or counts["HIGH"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
