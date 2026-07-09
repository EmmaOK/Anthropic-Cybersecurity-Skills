#!/usr/bin/env python3
"""
phantom/http_util.py — tiny dependency-free JSON HTTP helper.

Shared by the phishing-pipeline modules (case_sync, phishingbox_intake) so each
one doesn't re-implement urllib boilerplate. Honors the repo TLS convention
(verify defaults on; pass verify=False only for a self-signed lab endpoint).
"""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request


def http_json(url: str, headers: dict | None = None, method: str = "GET",
              data: dict | list | None = None, timeout: int = 15,
              verify: bool = True, auth: tuple[str, str] | None = None) -> dict:
    """Perform a JSON HTTP request.

    Returns the decoded JSON body (dict), or a diagnostic dict:
      {"_http_error": <status>, "_body": <text>} on an HTTP error,
      {"_error": <message>} on a transport/parse error.
    """
    hdrs = {"Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        hdrs["Authorization"] = f"Basic {token}"

    body = None
    if data is not None:
        body = json.dumps(data).encode()
        hdrs.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    ctx = None
    if url.lower().startswith("https") and not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", "replace")[:500]
        except Exception:
            detail = ""
        return {"_http_error": e.code, "_body": detail}
    except Exception as e:
        return {"_error": str(e)}


def ok(resp: dict) -> bool:
    """True if a http_json result is a real payload (not an error marker)."""
    return not (resp.get("_http_error") or resp.get("_error"))
