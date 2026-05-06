# Phantom Burp Extension

Jython extension that turns Burp Suite Professional into a live pentest backend
for Phantom. Once loaded, Phantom gains access to your proxy history, can replay
and modify requests, fuzz parameters, decode values, and read scanner issues —
all from natural language in Claude Code.

## Prerequisites

- Burp Suite Professional (any recent version)
- Jython standalone JAR — download from https://www.jython.org/download

## Installation (5 minutes)

### Step 1 — Configure Jython in Burp

1. Open Burp Suite Professional
2. Go to **Extender → Options → Python Environment**
3. Click **Select file** next to "Location of Jython standalone JAR"
4. Choose your downloaded `jython-standalone-*.jar`

### Step 2 — Load the extension

1. Go to **Extender → Extensions → Add**
2. Extension type: **Python**
3. Extension file: select `phantom_burp_extension.py` (this directory)
4. Click **Next**

The Output tab will show:
```
[Phantom] Starting MCP bridge on port 9877...
[Phantom] MCP bridge running at http://127.0.0.1:9877
[Phantom] Register burp_pentest_mcp_server.py in .mcp.json to connect Phantom.
```

### Step 3 — Verify in Claude Code

The `burp-pentest` MCP server is already registered in `.mcp.json`.
In Claude Code, ask Phantom:

```
check burp status
```

Phantom calls `burp_status` and confirms the bridge is running.

## Port configuration

Default port is **9877**. Override with the `PHANTOM_BURP_PORT` environment variable
before launching Burp, or set `PHANTOM_BURP_URL` in `.mcp.json` to match.

## What Phantom can do once connected

| Command to Phantom | What happens |
|---|---|
| "show me recent proxy history for api.example.com" | `burp_proxy_history(host="api.example.com")` |
| "analyze this request for vulnerabilities" + paste request | `burp_analyze_request` — identifies IDOR, SSRF, JWT issues, mass assignment |
| "replay that request with id=2 instead of id=1" | `burp_send_request` with modified body |
| "fuzz the id parameter with SQLi payloads" | `burp_generate_payloads(sqli)` → `burp_fuzz` |
| "what has Burp's scanner found so far?" | `burp_scanner_issues` |
| "show me the site map for app.example.com" | `burp_site_map` |
| "decode this base64 value" | `burp_decode` |
| "what cookies does Burp have for this host?" | `burp_get_cookies` |

## Automated scanning (separate from manual tools)

The `dast` MCP server (also in `.mcp.json`) handles ZAP and Burp's automated
REST API scanning:

| Command to Phantom | What happens |
|---|---|
| "scan https://staging.example.com with ZAP" | `dast_start_scan` via ZAP daemon |
| "start a Burp scan on https://api.example.com" | `burp_start_scan` via Burp REST API |
| "what's the scan progress?" | `dast_scan_status` |
| "show me all HIGH findings" | `dast_get_findings(min_severity=HIGH)` |

## ZAP daemon setup (for dast MCP server)

```bash
# macOS (Homebrew)
brew install --cask owasp-zap

# Start daemon
/Applications/ZAP.app/Contents/Java/zap.sh \
  -daemon -port 8080 -config api.key=phantom

# Or Docker (no install needed)
docker run -d -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.key=phantom
```

Set `ZAP_API_KEY` in `.mcp.json` env to match.
