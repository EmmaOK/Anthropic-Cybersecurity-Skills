#!/usr/bin/env python3
"""
phantom/devsecops.py — SonarQube + Dependency-Track pipeline onboarding, wired to
DefectDojo, emitted as Bitbucket Pipelines config.

Given a repo/project, Phantom:
  1. creates the SonarQube project + a CI analysis token,
  2. creates the Dependency-Track project (+ returns its UUID),
  3. ensures the matching DefectDojo PRODUCT + a CI/CD engagement exist, so
     findings land in the exact product,
  4. generates the `bitbucket-pipelines.yml` that runs Sonar analysis + a
     CycloneDX SBOM upload to Dependency-Track, then pushes BOTH tools' findings
     into that DefectDojo product/engagement (import-scan with auto_create_context),
  5. lists the Bitbucket **secured repository variables** (secrets) to set.

One task type:
  devsecops-onboard — "onboard <repo> to Sonar + Dependency-Track + DefectDojo and
                       give me the Bitbucket pipeline and secrets."

Connectors:
  SonarQube  : SONARQUBE_URL + SONARQUBE_TOKEN (admin/create token). Token auth.
  Dep-Track  : DEPENDENCYTRACK_URL + DEPENDENCYTRACK_API_KEY (X-Api-Key).
  DefectDojo : reuses defectdojo.py (DEFECTDOJO_URL / DEFECTDOJO_API_KEY).

Writes (create Sonar/DT project, generate token, create DD product/engagement) are
gated by DEVSECOPS_ALLOW_WRITE / DEFECTDOJO_ALLOW_WRITE. With writes OFF, Phantom
still produces the FULL pipeline YAML + secrets list + a manual runbook — it just
doesn't provision live. The generated SonarQube token is a real secret: it goes
into Bitbucket **secured** variables, never committed.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from http_util import http_json, ok
from task_agent import (SKILL_TOOLS, run_agent_loop, save_report, register_task,
                        generic_report_tool, _BASE_RULES)

VERIFY_TLS = os.environ.get("SKIP_TLS_VERIFY", "").lower() not in ("1", "true", "yes")


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").lower() in ("1", "true", "yes", "on")


def _writes_on() -> bool:
    return _truthy("DEVSECOPS_ALLOW_WRITE")


# ── SonarQube connector ──────────────────────────────────────────────────────

def _sonar_base() -> str:
    return (os.environ.get("SONARQUBE_URL") or os.environ.get("SONAR_URL", "")).rstrip("/")


def _sonar_token() -> str:
    return os.environ.get("SONARQUBE_TOKEN") or os.environ.get("SONAR_TOKEN", "")


def _sonar(path: str, method: str = "POST", params: dict | None = None) -> dict:
    base, tok = _sonar_base(), _sonar_token()
    if not base:
        return {"error": "SONARQUBE_URL not set"}
    if not tok:
        return {"error": "SONARQUBE_TOKEN not set"}
    url = f"{base}{path}"
    if params:
        from urllib.parse import urlencode
        url += "?" + urlencode(params)
    # SonarQube token auth = HTTP basic with token as username, empty password
    r = http_json(url, method=method, verify=VERIFY_TLS, auth=(tok, ""))
    if not ok(r):
        return {"error": r.get("_http_error") or r.get("_error") or "sonar api error", "detail": r}
    return r


def sonar_create_project(key: str, name: str) -> dict:
    if not _writes_on():
        return {"proposed": True, "manual": f"POST {_sonar_base()}/api/projects/create?project={key}&name={name}"}
    r = _sonar("/api/projects/create", params={"project": key, "name": name})
    return {"created": not r.get("error"), "key": key, "detail": r}


def sonar_generate_token(token_name: str) -> dict:
    if not _writes_on():
        return {"proposed": True, "secret": None,
                "manual": f"Generate a project-analysis token: {_sonar_base()}/account/security "
                          f"or POST /api/user_tokens/generate?name={token_name} — store as SONAR_TOKEN (secured)"}
    r = _sonar("/api/user_tokens/generate", params={"name": token_name})
    return {"generated": bool(r.get("token")), "secret": r.get("token"),
            "note": "store as SONAR_TOKEN in Bitbucket SECURED variables; shown only once"}


def sonar_list_projects() -> dict:
    r = _sonar("/api/projects/search", method="GET")
    if r.get("error"):
        return {"available": False, **r}
    return {"available": True, "projects": [{"key": p.get("key"), "name": p.get("name")}
                                            for p in r.get("components", [])][:100]}


# ── Dependency-Track connector ───────────────────────────────────────────────

def _dt_base() -> str:
    return (os.environ.get("DEPENDENCYTRACK_URL") or os.environ.get("DT_URL", "")).rstrip("/")


def _dt_key() -> str:
    return os.environ.get("DEPENDENCYTRACK_API_KEY") or os.environ.get("DT_API_KEY", "")


def _dt(path: str, method: str = "GET", params: dict | None = None, data: dict | None = None) -> dict:
    base, key = _dt_base(), _dt_key()
    if not base:
        return {"error": "DEPENDENCYTRACK_URL not set"}
    if not key:
        return {"error": "DEPENDENCYTRACK_API_KEY not set"}
    url = f"{base}{path}"
    if params:
        from urllib.parse import urlencode
        url += "?" + urlencode(params)
    r = http_json(url, headers={"X-Api-Key": key}, method=method, data=data, verify=VERIFY_TLS)
    if not ok(r):
        return {"error": r.get("_http_error") or r.get("_error") or "dtrack api error", "detail": r}
    return r


def dt_lookup_project(name: str, version: str = "1.0.0") -> dict:
    r = _dt("/api/v1/project/lookup", params={"name": name, "version": version})
    if r.get("error"):
        return {"found": False, **r}
    return {"found": bool(r.get("uuid")), "uuid": r.get("uuid"), "name": name, "version": version}


def dt_create_project(name: str, version: str = "1.0.0") -> dict:
    if not _writes_on():
        return {"proposed": True, "uuid": None,
                "manual": f"PUT {_dt_base()}/api/v1/project with {{name:{name}, version:{version}, "
                          f"classifier:APPLICATION}} — store the returned UUID as DT_PROJECT_UUID"}
    existing = dt_lookup_project(name, version)
    if existing.get("uuid"):
        return {"created": False, "uuid": existing["uuid"], "name": name, "version": version}
    r = _dt("/api/v1/project", method="PUT",
            data={"name": name, "version": version, "classifier": "APPLICATION"})
    return {"created": not r.get("error"), "uuid": r.get("uuid"), "name": name,
            "version": version, "detail": r}


# ── DefectDojo product/engagement (reuse defectdojo.py) ──────────────────────

def dd_ensure_product(name: str) -> dict:
    from defectdojo import ensure_product
    return ensure_product(name)


def dd_ensure_engagement(product_name: str, engagement: str) -> dict:
    from defectdojo import ensure_product, ensure_engagement
    prod = ensure_product(product_name)
    if not prod.get("id"):
        return {"available": True, "product": prod, "engagement": None,
                "note": "product not created yet (writes off?) — engagement deferred"}
    return {"available": True, "product_id": prod["id"],
            "engagement": ensure_engagement(prod["id"], engagement)}


# ── Tools ─────────────────────────────────────────────────────────────────────

def _dispatch(name: str, inp: dict) -> tuple[str, dict | None]:
    if name == "sonar_create_project":
        return json.dumps(sonar_create_project(inp.get("key", ""), inp.get("name", ""))), None
    if name == "sonar_generate_token":
        return json.dumps(sonar_generate_token(inp.get("token_name", ""))), None
    if name == "sonar_list_projects":
        return json.dumps(sonar_list_projects()), None
    if name == "dt_create_project":
        return json.dumps(dt_create_project(inp.get("name", ""), inp.get("version", "1.0.0"))), None
    if name == "dt_lookup_project":
        return json.dumps(dt_lookup_project(inp.get("name", ""), inp.get("version", "1.0.0"))), None
    if name == "dd_ensure_product":
        return json.dumps(dd_ensure_product(inp.get("name", ""))), None
    if name == "dd_ensure_engagement":
        return json.dumps(dd_ensure_engagement(inp.get("product_name", ""), inp.get("engagement", ""))), None
    if name == "write_report":
        return json.dumps({"written": True}), dict(inp)
    return json.dumps({"error": f"unknown tool {name}"}), None


TOOLS = SKILL_TOOLS + [
    {"name": "sonar_create_project", "description": "Create a SonarQube project (gated). Returns proposed "
     "manual command if writes are off.", "input_schema": {"type": "object", "properties": {
         "key": {"type": "string"}, "name": {"type": "string"}}, "required": ["key", "name"]}},
    {"name": "sonar_generate_token", "description": "Generate a SonarQube CI analysis token (gated). SECRET — "
     "store in Bitbucket secured variables, never commit.", "input_schema": {"type": "object",
         "properties": {"token_name": {"type": "string"}}, "required": ["token_name"]}},
    {"name": "sonar_list_projects", "description": "List existing SonarQube projects.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "dt_create_project", "description": "Create a Dependency-Track project (gated). Returns its UUID "
     "(needed for BOM upload).", "input_schema": {"type": "object", "properties": {
         "name": {"type": "string"}, "version": {"type": "string"}}, "required": ["name"]}},
    {"name": "dt_lookup_project", "description": "Look up a Dependency-Track project UUID by name/version.",
     "input_schema": {"type": "object", "properties": {"name": {"type": "string"}, "version": {"type": "string"}},
                      "required": ["name"]}},
    {"name": "dd_ensure_product", "description": "Ensure a DefectDojo product exists (find or create, gated) — "
     "the EXACT product findings must land in.", "input_schema": {"type": "object",
         "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "dd_ensure_engagement", "description": "Ensure a CI/CD engagement exists under a DefectDojo product.",
     "input_schema": {"type": "object", "properties": {"product_name": {"type": "string"},
         "engagement": {"type": "string"}}, "required": ["product_name", "engagement"]}},
    generic_report_tool(),
]

SYSTEM = (
    "You are Phantom onboarding a repository to the DevSecOps toolchain: SonarQube (SAST), "
    "Dependency-Track (SCA), and DefectDojo (aggregation), delivered as Bitbucket Pipelines config. "
    "Pull the writing-bitbucket-pipelines and building-devsecops-pipeline skills.\n\n"
    "Steps:\n"
    "1. sonar_create_project + sonar_generate_token (the token is a SECRET → Bitbucket secured var).\n"
    "2. dt_create_project (capture the UUID for BOM upload) or dt_lookup_project if it exists.\n"
    "3. dd_ensure_product for the SAME project/product name, then dd_ensure_engagement (CI/CD) — so "
    "findings land in the EXACT DefectDojo product.\n"
    "4. Write the complete bitbucket-pipelines.yml with steps: (a) SonarQube analysis (sonar-scanner), "
    "(b) generate a CycloneDX SBOM and upload it to Dependency-Track (its UUID), (c) PUSH both tools' "
    "findings to DefectDojo via import-scan — SonarQube (scan_type 'SonarQube Scan' or 'SonarQube API "
    "Import') and Dependency-Track (scan_type 'Dependency Track Finding Packaging Format (FPF) Export') "
    "— each with product_name + engagement_name + auto_create_context=true so they route to the exact "
    "product.\n"
    "5. List every Bitbucket SECURED repository variable to set (SONAR_TOKEN, SONAR_HOST_URL, "
    "DT_API_KEY, DT_URL, DT_PROJECT_UUID, DEFECTDOJO_URL, DEFECTDOJO_API_KEY, DD_PRODUCT, DD_ENGAGEMENT), "
    "marking the true secrets.\n\n"
    "If writes are off, tools return 'proposed' with the manual command — still produce the FULL YAML + "
    "secrets list + a short manual runbook. write_report with the pipeline YAML, the secrets table (secrets "
    "masked/marked), and any live IDs/UUIDs/tokens generated. " + _BASE_RULES)


def onboard(objective: str, context: str = "") -> dict:
    task_id = f"devsecops-onboard-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    initial = (f"DEVSECOPS ONBOARD: {objective}\n{('CONTEXT: ' + context + chr(10)) if context else ''}\n"
               f"SonarQube configured: {bool(_sonar_base())}; Dependency-Track: {bool(_dt_base())}; "
               f"writes: {_writes_on()}. Begin now.")
    report, _ = run_agent_loop(SYSTEM, initial, TOOLS, _dispatch, label="devsecops")
    if not report:
        return {"error": "no report produced", "task_type": "devsecops-onboard"}
    report["task_id"] = task_id
    report["task_type"] = "devsecops-onboard"
    report["report_path"] = save_report("devsecops-onboard", task_id, report)
    return report


register_task("devsecops-onboard",
              "Onboard a repo to SonarQube + Dependency-Track + DefectDojo: create projects, generate the "
              "Bitbucket pipeline + secrets, and wire both tools' findings into the exact DefectDojo product",
              runner=lambda objective, **kw: onboard(objective, kw.get("context", "")))


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python devsecops.py '<onboard objective>'")
        raise SystemExit(0)
    out = onboard(" ".join(sys.argv[1:]))
    print("\n" + out.get("report_markdown", json.dumps(out, indent=2, default=str)))
