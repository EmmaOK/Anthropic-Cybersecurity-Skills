# -*- coding: utf-8 -*-
"""
Phantom Burp Extension
======================
Jython extension for Burp Suite Professional that starts an HTTP server
inside Burp and exposes proxy history, site map, request sending, scanner
issues, and Intruder-style fuzzing to the Phantom MCP server.

Installation
------------
1. Open Burp Suite Professional
2. Go to Extender > Options > Python Environment
3. Set the path to jython-standalone-*.jar  (download from jython.org)
4. Go to Extender > Extensions > Add
5. Extension type: Python
6. Extension file: this file (phantom_burp_extension.py)

The extension starts an HTTP server on port 9877 (configurable via
PHANTOM_BURP_PORT env var). The Phantom MCP server (burp_pentest_mcp_server.py)
connects to it.

Endpoints
---------
GET  /status                        — Health check, returns Burp version
GET  /proxy/history?host=&path=&limit=100&offset=0
POST /request                       — Send arbitrary HTTP request via Burp engine
                                      Body: {host, port, https, request_b64}
GET  /sitemap?host=                 — Burp site map for a host
GET  /issues?url=                   — Scanner issues for a URL
POST /scan                          — Trigger active scan
                                      Body: {host, port, https, request_b64}
POST /intruder                      — Fuzz a request
                                      Body: {host, port, https, request_b64,
                                             positions: [[start,end]], payloads: []}
GET  /decode?value=&encoding=       — Decode/encode (base64|url|html|hex)
GET  /cookies?host=                 — Cookies in the Burp cookie jar for a host
"""

import base64
import json
import re
import sys
import threading

# Python 2/3 compatibility (Jython is Python 2.7)
try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse, parse_qs, unquote
except ImportError:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from urlparse import urlparse, parse_qs
    from urllib import unquote

try:
    from burp import IBurpExtender, ITab
    from java.lang import System
    BURP_PORT = int(System.getenv("PHANTOM_BURP_PORT") or "9877")
except ImportError:
    # Running outside Burp for testing
    BURP_PORT = 9877

EXTENSION_NAME = "Phantom MCP"
_callbacks = None
_helpers   = None


# ── Request handler ────────────────────────────────────────────────────────────

class PhantomHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # silence access log

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            raw = self.rfile.read(length)
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception:
                return {}
        return {}

    def _qs(self):
        parsed = urlparse(self.path)
        return parse_qs(parsed.query, keep_blank_values=True)

    def _qs1(self, key, default=""):
        return self._qs().get(key, [default])[0]

    # ── Route dispatch ─────────────────────────────────────────────────────────

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if path == "/status":
                self._handle_status()
            elif path == "/proxy/history":
                self._handle_proxy_history()
            elif path == "/sitemap":
                self._handle_sitemap()
            elif path == "/issues":
                self._handle_issues()
            elif path == "/decode":
                self._handle_decode()
            elif path == "/cookies":
                self._handle_cookies()
            else:
                self._send_json({"error": "Not found"}, 404)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()
        try:
            if path == "/request":
                self._handle_send_request(body)
            elif path == "/scan":
                self._handle_scan(body)
            elif path == "/intruder":
                self._handle_intruder(body)
            else:
                self._send_json({"error": "Not found"}, 404)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    # ── Handlers ───────────────────────────────────────────────────────────────

    def _handle_status(self):
        burp_version = "unknown"
        try:
            burp_version = _callbacks.getBurpVersion()
            if hasattr(burp_version, '__iter__') and not isinstance(burp_version, str):
                burp_version = " ".join(str(v) for v in burp_version)
        except Exception:
            pass
        self._send_json({"status": "running", "extension": EXTENSION_NAME,
                         "burp_version": str(burp_version), "port": BURP_PORT})

    def _handle_proxy_history(self):
        host   = self._qs1("host", "")
        path_f = self._qs1("path", "")
        method = self._qs1("method", "").upper()
        try:
            limit  = int(self._qs1("limit",  "100"))
            offset = int(self._qs1("offset", "0"))
        except ValueError:
            limit, offset = 100, 0

        history = _callbacks.getProxyHistory()
        results = []
        for msg in history:
            try:
                req_info = _helpers.analyzeRequest(msg)
                url = str(req_info.getUrl())
                if host and host.lower() not in url.lower():
                    continue
                if path_f and path_f.lower() not in url.lower():
                    continue
                req_method = str(req_info.getMethod())
                if method and req_method != method:
                    continue

                req_bytes = msg.getRequest()
                resp_bytes = msg.getResponse()
                resp_info = _helpers.analyzeResponse(resp_bytes) if resp_bytes else None

                results.append({
                    "url":    url,
                    "method": req_method,
                    "status": int(resp_info.getStatusCode()) if resp_info else None,
                    "request_b64":  base64.b64encode(bytes(req_bytes)).decode()  if req_bytes  else None,
                    "response_b64": base64.b64encode(bytes(resp_bytes)).decode() if resp_bytes else None,
                    "mime_type": str(resp_info.getInferredMimeType()) if resp_info else None,
                    "params": [str(p.getName()) for p in req_info.getParameters()],
                })
            except Exception:
                continue

        total = len(results)
        page = results[offset: offset + limit]
        self._send_json({"total": total, "offset": offset, "limit": limit, "items": page})

    def _handle_sitemap(self):
        host = self._qs1("host", "")
        prefix = host if host else None
        try:
            entries = _callbacks.getSiteMap(prefix)
        except Exception as e:
            self._send_json({"error": str(e)}); return

        urls = []
        for msg in entries:
            try:
                req_info = _helpers.analyzeRequest(msg)
                url = str(req_info.getUrl())
                resp_bytes = msg.getResponse()
                resp_info = _helpers.analyzeResponse(resp_bytes) if resp_bytes else None
                urls.append({
                    "url":    url,
                    "method": str(req_info.getMethod()),
                    "status": int(resp_info.getStatusCode()) if resp_info else None,
                    "params": [str(p.getName()) for p in req_info.getParameters()],
                })
            except Exception:
                continue
        self._send_json({"host": host, "count": len(urls), "urls": urls})

    def _handle_issues(self):
        url_filter = self._qs1("url", "")
        try:
            issues = _callbacks.getScanIssues(url_filter or None)
        except Exception as e:
            self._send_json({"error": str(e)}); return

        results = []
        for issue in issues:
            try:
                results.append({
                    "name":          str(issue.getIssueName()),
                    "url":           str(issue.getUrl()),
                    "severity":      str(issue.getSeverity()),
                    "confidence":    str(issue.getConfidence()),
                    "background":    str(issue.getIssueBackground() or "")[:500],
                    "detail":        str(issue.getIssueDetail() or "")[:500],
                    "remediation":   str(issue.getRemediationBackground() or "")[:300],
                })
            except Exception:
                continue
        self._send_json({"url_filter": url_filter, "count": len(results), "issues": results})

    def _handle_send_request(self, body):
        host     = body.get("host", "")
        port     = int(body.get("port", 443))
        use_https = bool(body.get("https", True))
        req_b64  = body.get("request_b64", "")
        if not req_b64:
            self._send_json({"error": "request_b64 required"}); return

        req_bytes = base64.b64decode(req_b64)
        try:
            http_service = _helpers.buildHttpService(host, port, use_https)
            response = _callbacks.makeHttpRequest(http_service, req_bytes)
            resp_bytes = response.getResponse()
            resp_info  = _helpers.analyzeResponse(resp_bytes) if resp_bytes else None
            self._send_json({
                "status": int(resp_info.getStatusCode()) if resp_info else None,
                "response_b64": base64.b64encode(bytes(resp_bytes)).decode() if resp_bytes else None,
                "headers": [str(h) for h in (resp_info.getHeaders() if resp_info else [])],
            })
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_scan(self, body):
        host      = body.get("host", "")
        port      = int(body.get("port", 443))
        use_https = bool(body.get("https", True))
        req_b64   = body.get("request_b64", "")
        if not req_b64:
            self._send_json({"error": "request_b64 required"}); return

        req_bytes = base64.b64decode(req_b64)
        try:
            _callbacks.doActiveScan(host, port, use_https, req_bytes)
            self._send_json({"status": "scan_queued", "host": host})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_intruder(self, body):
        host      = body.get("host", "")
        port      = int(body.get("port", 443))
        use_https = bool(body.get("https", True))
        req_b64   = body.get("request_b64", "")
        positions = body.get("positions", [])   # [[start_byte, end_byte], ...]
        payloads  = body.get("payloads", [])

        if not req_b64 or not payloads:
            self._send_json({"error": "request_b64 and payloads required"}); return

        req_bytes = bytearray(base64.b64decode(req_b64))
        results = []

        for payload in payloads[:200]:  # cap at 200 to stay reasonable
            # Substitute all positions (reverse order to preserve offsets)
            modified = bytearray(req_bytes)
            for start, end in sorted(positions, reverse=True):
                payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
                modified = modified[:start] + bytearray(payload_bytes) + modified[end:]
            try:
                svc  = _helpers.buildHttpService(host, port, use_https)
                resp = _callbacks.makeHttpRequest(svc, bytes(modified))
                rb   = resp.getResponse()
                ri   = _helpers.analyzeResponse(rb) if rb else None
                status = int(ri.getStatusCode()) if ri else 0
                body_preview = bytes(rb)[ri.getBodyOffset():ri.getBodyOffset()+500].decode("utf-8", errors="replace") if (rb and ri) else ""
                results.append({
                    "payload": payload,
                    "status":  status,
                    "length":  len(rb) if rb else 0,
                    "body_preview": body_preview,
                    "interesting": status not in (400, 404, 500) and len(rb or b"") > 100,
                })
            except Exception as e:
                results.append({"payload": payload, "error": str(e)})

        self._send_json({"host": host, "total_sent": len(results), "results": results})

    def _handle_decode(self):
        value    = self._qs1("value", "")
        encoding = self._qs1("encoding", "base64").lower()
        try:
            if encoding == "base64":
                decoded = base64.b64decode(value + "==").decode("utf-8", errors="replace")
            elif encoding == "base64_encode":
                decoded = base64.b64encode(value.encode()).decode()
            elif encoding == "url":
                decoded = unquote(value)
            elif encoding == "hex":
                decoded = bytes.fromhex(value).decode("utf-8", errors="replace")
            elif encoding == "html":
                import html
                decoded = html.unescape(value)
            else:
                decoded = value
            self._send_json({"encoding": encoding, "input": value, "output": decoded})
        except Exception as e:
            self._send_json({"error": str(e)}, 400)

    def _handle_cookies(self):
        host = self._qs1("host", "")
        try:
            jar = _callbacks.getCookieJarContents()
            cookies = []
            for c in jar:
                if host and host not in str(c.getDomain()):
                    continue
                cookies.append({
                    "name":   str(c.getName()),
                    "value":  str(c.getValue()),
                    "domain": str(c.getDomain()),
                    "path":   str(c.getPath() or "/"),
                    "expiry": str(c.getExpiration()) if c.getExpiration() else None,
                })
            self._send_json({"host": host, "count": len(cookies), "cookies": cookies})
        except Exception as e:
            self._send_json({"error": str(e)})


# ── Burp extension entry point ─────────────────────────────────────────────────

class BurpExtender(IBurpExtender):

    def registerExtenderCallbacks(self, callbacks):
        global _callbacks, _helpers
        _callbacks = callbacks
        _helpers   = callbacks.getHelpers()

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.printOutput(f"[Phantom] Starting MCP bridge on port {BURP_PORT}...")

        # Start HTTP server in daemon thread
        server = HTTPServer(("127.0.0.1", BURP_PORT), PhantomHandler)
        t = threading.Thread(target=server.serve_forever)
        t.daemon = True
        t.name   = "PhantomMCPBridge"
        t.start()

        callbacks.printOutput(
            f"[Phantom] MCP bridge running at http://127.0.0.1:{BURP_PORT}\n"
            f"[Phantom] Register burp_pentest_mcp_server.py in .mcp.json to connect Phantom."
        )


# ── Standalone test (run outside Burp to verify HTTP server logic) ─────────────

if __name__ == "__main__":
    print(f"Running standalone test server on port {BURP_PORT} (no Burp callbacks)")
    print("This verifies the HTTP server starts — Burp callbacks will be None.")

    class _MockCallbacks:
        def getProxyHistory(self): return []
        def getSiteMap(self, p): return []
        def getScanIssues(self, u): return []
        def getBurpVersion(self): return "Mock 2024.x"
        def getCookieJarContents(self): return []
        def makeHttpRequest(self, *a): raise RuntimeError("No Burp in standalone mode")
        def doActiveScan(self, *a): pass
        def printOutput(self, m): print(m)

    class _MockHelpers:
        def analyzeRequest(self, m): raise RuntimeError("No Burp in standalone mode")
        def analyzeResponse(self, b): raise RuntimeError("No Burp in standalone mode")
        def buildHttpService(self, *a): raise RuntimeError("No Burp in standalone mode")

    _callbacks = _MockCallbacks()
    _helpers   = _MockHelpers()

    srv = HTTPServer(("127.0.0.1", BURP_PORT), PhantomHandler)
    print(f"Server running at http://127.0.0.1:{BURP_PORT} — Ctrl+C to stop")
    srv.serve_forever()
