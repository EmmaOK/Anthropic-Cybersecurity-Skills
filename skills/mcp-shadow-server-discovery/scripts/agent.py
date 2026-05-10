#!/usr/bin/env python3
"""MCP05 - Shadow Server Discovery: Scan for undisclosed MCP servers on common ports."""
import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    import urllib.request
    HAS_HTTPX = False

OWASP_ID = "MCP05"
TOOL_NAME = "phantom-mcp-shadow-discovery"

DEFAULT_PORTS = [3000, 8080, 8443, 9000, 9001, 9002, 4000, 5000, 6000, 7000]
MCP_PATHS = ["/", "/mcp", "/api/mcp", "/v1", "/rpc", "/jsonrpc"]
MCP_PROBE = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode()


def check_port(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def probe_mcp_endpoint(host, port, path, timeout=5):
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}{path}"
    h = {"Content-Type": "application/json"}
    try:
        if HAS_HTTPX:
            r = httpx.post(url, content=MCP_PROBE, headers=h, timeout=timeout, verify=False)
            status, body = r.status_code, r.text
        else:
            req = urllib.request.Request(url, data=MCP_PROBE, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status, body = resp.status, resp.read().decode()
        is_mcp = ('"jsonrpc"' in body or '"result"' in body) and '"tools"' in body
        return url, status, is_mcp, body[:300]
    except Exception as e:
        return url, None, False, str(e)


def expand_target(target):
    """Return list of hosts from a single IP, hostname, or simple x.x.x.0/24 CIDR."""
    if "/" in target:
        parts = target.split("/")
        try:
            prefix = int(parts[1])
            base = parts[0].rsplit(".", 1)
            if prefix == 24:
                return [f"{base[0]}.{i}" for i in range(1, 255)]
        except Exception:
            pass
    return [target]


def scan_host(host, ports, timeout):
    findings = []
    for port in ports:
        if not check_port(host, port, timeout=2):
            continue
        for path in MCP_PATHS:
            url, status, is_mcp, body = probe_mcp_endpoint(host, port, path, timeout)
            if is_mcp:
                findings.append({
                    "id": f"{OWASP_ID}-{host}:{port}",
                    "title": f"Shadow MCP Server Discovered: {host}:{port}{path}",
                    "severity": "HIGH",
                    "description": (
                        f"An undisclosed MCP server is running at {host}:{port}{path}. "
                        f"Shadow servers may be unpatched, misconfigured, or used for exfiltration."
                    ),
                    "evidence": f"URL: {url}\nHTTP {status}\nResponse: {body}",
                    "remediation": (
                        "Inventory all MCP servers in your environment. "
                        "Enforce network segmentation to restrict MCP port access. "
                        "Use a service registry and reject connections from unregistered servers."
                    ),
                })
                break  # Found MCP on this port, move on
        else:
            # Port open but no MCP found — flag as unknown service
            pass
    return findings


def main():
    p = argparse.ArgumentParser(description="MCP05 Shadow Server Discovery")
    p.add_argument("--target", required=True, help="Host, IP, or x.x.x.0/24 CIDR")
    p.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                   help=f"Comma-separated ports (default: {','.join(map(str, DEFAULT_PORTS))})")
    p.add_argument("--timeout", type=int, default=5)
    p.add_argument("--output", default="mcp05_report.json")
    args = p.parse_args()

    ports = [int(p) for p in args.ports.split(",")]
    hosts = expand_target(args.target)
    print(f"[{OWASP_ID}] Scanning {len(hosts)} host(s) × {len(ports)} ports...", file=sys.stderr)

    all_findings = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(scan_host, h, ports, args.timeout): h for h in hosts}
        for fut in as_completed(futs):
            all_findings.extend(fut.result())

    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1

    report = {
        "tool": TOOL_NAME, "target": args.target, "owasp_id": OWASP_ID,
        "hosts_scanned": len(hosts), "ports_scanned": ports,
        "findings": all_findings, "summary": {"total": len(all_findings), **sev},
    }
    print(json.dumps(report, indent=2))
    if args.output:
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)

    sys.exit(1 if sev["CRITICAL"] > 0 or sev["HIGH"] > 0 else 0)


if __name__ == "__main__":
    main()
