# DVMCP Testing Reference

Scripts for testing skills against [DVMCP (Damn Vulnerable MCP Server)](https://github.com/halencarjunior/dvmcp) live in `examples/dvmcp/`:

- `detect_challenge2.py` — implements the `mcp-tool-poisoning-detection-and-defense` workflow against Challenge 2 (port 9002)
- `mcp_command_injection_audit.py` — implements the `mcp-command-injection-prevention` workflow: static regex scan + 8 live injection probes

**Start DVMCP:** `docker compose up -d` from the DVMCP repo root (challenges on ports 9001–9010).

## Challenge 2 vulnerabilities confirmed
- **Command injection via `\n` newline bypass:** `split()[0]` treats newline as whitespace, so `"ls\nid"` passes the allowlist check while injecting `id` when `shell=True`.
- **Path traversal via `startswith('/tmp/safe/')` without `Path.resolve()`:** `/tmp/safe/../../etc/passwd` passes the check.
