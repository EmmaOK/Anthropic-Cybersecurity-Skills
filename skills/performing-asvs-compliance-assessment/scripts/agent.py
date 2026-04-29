#!/usr/bin/env python3
"""
ASVS Compliance Assessment Agent

Two subcommands:
  init   — Creates a blank assessment worksheet (JSON) pre-populated with all
            ASVS v4.0.3 requirements for the chosen level (L1, L2, or L3).
  report — Reads a completed worksheet and produces a conformance report with
            pass/fail counts per chapter, overall conformance %, and a ranked
            list of failed controls.

Usage:
    agent.py init   --app "Portal" --url "https://app" --level 2 --output assessment.json
    agent.py report --assessment assessment.json --output report.json

Worksheet format (array of requirement objects in JSON):
    [
      {"control_id": "V2.1.1", "chapter": "V2_Authentication", "level": 1,
       "requirement": "Verify that ...", "status": "pass|fail|na|not_tested",
       "evidence": "...", "notes": "..."},
      ...
    ]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ASVS_VERSION = "4.0.3"

# Subset of ASVS v4.0.3 requirements used to seed an assessment worksheet.
# Each entry: (control_id, chapter_key, min_level, requirement_text)
# min_level: 1 = required for L1+, 2 = L2+, 3 = L3 only
REQUIREMENTS: list[tuple[str, str, int, str]] = [
    # V2 — Authentication
    ("V2.1.1",  "V2_Authentication", 1, "Verify that user-set passwords are at least 12 characters in length."),
    ("V2.1.2",  "V2_Authentication", 1, "Verify that passwords of at least 64 characters are permitted."),
    ("V2.1.7",  "V2_Authentication", 1, "Verify passwords submitted during account registration are checked against a breached-password list (e.g. HIBP)."),
    ("V2.2.1",  "V2_Authentication", 1, "Verify that anti-automation controls are effective to mitigate breached credential testing, brute force, and account lockout attacks."),
    ("V2.2.2",  "V2_Authentication", 1, "Verify that account lockout or rate limiting is applied after no more than 5 failed login attempts."),
    ("V2.4.1",  "V2_Authentication", 2, "Verify that passwords are stored using an approved adaptive salted hashing algorithm (bcrypt, scrypt, Argon2id, or PBKDF2)."),
    ("V2.6.1",  "V2_Authentication", 2, "Verify that look-up secrets can only be used once."),
    ("V2.8.1",  "V2_Authentication", 2, "Verify that time-based OTPs have a defined lifetime before expiry."),
    ("V2.9.1",  "V2_Authentication", 3, "Verify that cryptographic keys used in verification are stored securely in a hardware security module (HSM)."),
    # V3 — Session Management
    ("V3.2.1",  "V3_Session",        1, "Verify that the application generates a new session token on user authentication."),
    ("V3.2.3",  "V3_Session",        1, "Verify that the application only stores session tokens in the browser using secure methods (cookies with Secure and HttpOnly flags)."),
    ("V3.3.1",  "V3_Session",        1, "Verify that logout and expiration invalidate the session token."),
    ("V3.3.2",  "V3_Session",        2, "Verify idle session timeout is 30 minutes or less for applications that process sensitive data."),
    ("V3.4.1",  "V3_Session",        1, "Verify that cookie-based session tokens have the SameSite attribute set to prevent CSRF."),
    ("V3.7.1",  "V3_Session",        2, "Verify the application ensures a valid login session or requires re-authentication/secondary verification before allowing sensitive transactions."),
    # V4 — Access Control
    ("V4.1.1",  "V4_Access_Control", 1, "Verify that the application enforces access control rules on a trusted server-side component."),
    ("V4.1.2",  "V4_Access_Control", 1, "Verify that all user and data attributes used by access controls cannot be manipulated by end users."),
    ("V4.1.3",  "V4_Access_Control", 1, "Verify that the principle of least privilege exists — users only access functions, data files, URLs, controllers, services, and other resources for which they possess specific authorisation."),
    ("V4.2.1",  "V4_Access_Control", 1, "Verify that sensitive data and APIs are protected against Insecure Direct Object Reference (IDOR) attacks targeting creation, reading, updating, and deletion of records."),
    ("V4.3.1",  "V4_Access_Control", 1, "Verify that directory browsing is disabled."),
    # V5 — Validation, Sanitization, and Encoding
    ("V5.1.1",  "V5_Validation",     1, "Verify that the application has defenses against HTTP parameter pollution attacks."),
    ("V5.2.1",  "V5_Validation",     1, "Verify that all untrusted HTML input from WYSIWYG editors or similar is properly sanitized."),
    ("V5.3.1",  "V5_Validation",     1, "Verify that output encoding is relevant for the interpreter and context required (e.g. HTML, JS, CSS, URL)."),
    ("V5.3.3",  "V5_Validation",     1, "Verify that context-aware, preferably automated — or at worst, manual — output escaping protects against reflected, stored, and DOM-based XSS."),
    ("V5.3.4",  "V5_Validation",     1, "Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterised queries, ORMs, entity frameworks, or are otherwise protected from SQL injection."),
    ("V5.5.1",  "V5_Validation",     2, "Verify that serialised objects use integrity checks or are encrypted to prevent hostile object creation or data tampering."),
    # V6 — Cryptography
    ("V6.2.1",  "V6_Cryptography",   1, "Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable Padding Oracle attacks."),
    ("V6.2.2",  "V6_Cryptography",   2, "Verify that industry-proven or government-approved cryptographic algorithms, modes, and libraries are used, instead of custom coded cryptography."),
    ("V6.3.1",  "V6_Cryptography",   2, "Verify that all random numbers, random file names, random GUIDs, and random strings are generated using the cryptographic module's approved cryptographically secure random number generator."),
    # V7 — Error Handling and Logging
    ("V7.1.1",  "V7_Error_Logging",  1, "Verify that the application does not log credentials or payment details in any form."),
    ("V7.2.1",  "V7_Error_Logging",  1, "Verify that the application does not output error messages or stack traces containing sensitive data that could assist an attacker."),
    ("V7.3.1",  "V7_Error_Logging",  2, "Verify that the application logs security-relevant events including successful and failed authentication, access control failures, and input validation failures."),
    ("V7.4.1",  "V7_Error_Logging",  1, "Verify that a generic message is shown when an unexpected or security-sensitive error occurs, potentially with a unique ID which support personnel can use to investigate."),
    # V8 — Data Protection
    ("V8.1.1",  "V8_Data_Protection",2, "Verify that the application protects sensitive data from being cached in server components such as load balancers and application caches."),
    ("V8.2.1",  "V8_Data_Protection",1, "Verify that the application sets sufficient anti-caching headers so that sensitive data is not cached in modern browsers."),
    ("V8.3.1",  "V8_Data_Protection",1, "Verify that sensitive data is sent to the server in the HTTP message body or headers, and that query string parameters from any HTTP verb do not contain sensitive data."),
    # V9 — Communication
    ("V9.1.1",  "V9_Communication",  1, "Verify that TLS is used for all client connectivity, and does not fall back to insecure or unencrypted protocols."),
    ("V9.1.2",  "V9_Communication",  1, "Verify that HSTS headers are enabled with a minimum 1-year lifetime."),
    ("V9.2.1",  "V9_Communication",  2, "Verify that connections to and from the server use trusted TLS certificates. Where internally generated or self-signed certificates are used, the server must be configured to only trust specific internal CAs."),
    # V10 — Malicious Code
    ("V10.2.1", "V10_Malicious_Code",2, "Verify that the application source code and third-party libraries do not contain back doors, Easter eggs, or logic bombs."),
    ("V10.3.2", "V10_Malicious_Code",1, "Verify that the application has protection from subdomain takeovers if the application relies upon DNS entries or DNS subdomains."),
    # V11 — Business Logic
    ("V11.1.1", "V11_Business_Logic",1, "Verify that the application will only process business logic flows for the same user in sequential step order and without skipping steps."),
    ("V11.1.4", "V11_Business_Logic",1, "Verify the application has anti-automation controls to protect against excessive calls such as mass data exfiltration, business logic requests, file uploads, or denial of service attacks."),
    # V12 — Files and Resources
    ("V12.1.1", "V12_Files",         1, "Verify that the application will not accept large files that could fill up storage or cause a denial of service."),
    ("V12.3.1", "V12_Files",         1, "Verify that user-submitted filename metadata is not used directly by system or framework filesystems and that a URL API is used to protect against path traversal."),
    ("V12.5.1", "V12_Files",         1, "Verify that the web tier is configured to serve only files with specific file extensions to prevent unintentional information and source code leakage."),
    # V13 — API and Web Service
    ("V13.1.1", "V13_API",           1, "Verify that all application components use the same encodings and parsers to avoid parsing attacks that exploit different URI or file parsing behavior."),
    ("V13.2.1", "V13_API",           1, "Verify that enabled RESTful HTTP methods are a valid choice for the user or action, such as preventing normal users from using DELETE or PUT on protected API or resources."),
    ("V13.3.1", "V13_API",           1, "Verify that SOAP-based web services are compliant with Web Services-Interoperability (WS-I) Basic Profile at a minimum."),
    # V14 — Configuration
    ("V14.2.1", "V14_Configuration", 1, "Verify that all components are up to date, preferably using a dependency checker during build or compile time."),
    ("V14.3.1", "V14_Configuration", 1, "Verify that web or application server and application framework error messages are configured to deliver user-actionable, customised responses to eliminate any unintended security disclosures."),
    ("V14.4.1", "V14_Configuration", 1, "Verify that every HTTP response contains a Content-Type header. Also verify that a safe character set is specified (e.g. UTF-8, ISO 8859-1) if the Content-Type is text/*, /+xml, or application/xml."),
    ("V14.4.3", "V14_Configuration", 1, "Verify that a Content Security Policy (CSP) response header is in place to reduce the impact of XSS attacks."),
    ("V14.4.5", "V14_Configuration", 1, "Verify that a Strict-Transport-Security header is included on all responses and for all subdomains, such as Strict-Transport-Security: max-age=15724800; includeSubdomains."),
    ("V14.4.6", "V14_Configuration", 1, "Verify that a suitable Referrer-Policy header is included to avoid exposing sensitive information in the URL through the Referer header to unauthenticated parties."),
]

CHAPTERS = [
    "V2_Authentication", "V3_Session", "V4_Access_Control", "V5_Validation",
    "V6_Cryptography", "V7_Error_Logging", "V8_Data_Protection", "V9_Communication",
    "V10_Malicious_Code", "V11_Business_Logic", "V12_Files", "V13_API", "V14_Configuration",
]

VALID_STATUSES = {"pass", "fail", "na", "not_tested"}


def build_worksheet(app: str, url: str, level: int) -> list[dict]:
    worksheet = []
    for ctrl_id, chapter, min_level, requirement in REQUIREMENTS:
        if min_level > level:
            continue
        worksheet.append({
            "control_id": ctrl_id,
            "chapter": chapter,
            "level": min_level,
            "requirement": requirement,
            "status": "not_tested",
            "evidence": "",
            "notes": "",
        })
    return worksheet


def cmd_init(args) -> dict:
    level = args.level
    if level not in (1, 2, 3):
        print("[error] --level must be 1, 2, or 3", file=sys.stderr)
        sys.exit(1)

    worksheet = build_worksheet(args.app, args.url, level)
    assessment = {
        "application": args.app,
        "target_url": args.url,
        "asvs_version": ASVS_VERSION,
        "level": level,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "requirements": worksheet,
    }

    with open(args.output, "w") as f:
        json.dump(assessment, f, indent=2)

    print(f"[*] Assessment worksheet created: {args.output}")
    print(f"[*] Requirements to test: {len(worksheet)} (ASVS L{level})")
    return assessment


def cmd_report(args) -> dict:
    path = Path(args.assessment)
    if not path.exists():
        print(f"[error] Assessment file not found: {args.assessment}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        assessment = json.load(f)

    requirements: list[dict] = assessment.get("requirements", [])
    level = assessment.get("level", 2)
    app = assessment.get("application", "Unknown")
    url = assessment.get("target_url", "")

    chapter_stats: dict[str, dict] = {ch: {"passed": 0, "failed": 0, "na": 0, "not_tested": 0} for ch in CHAPTERS}
    failed_controls: list[dict] = []

    total = passed = failed = na = not_tested = 0

    STATUS_KEY = {"pass": "passed", "fail": "failed", "na": "na", "not_tested": "not_tested"}

    for req in requirements:
        status = req.get("status", "not_tested").lower()
        if status not in VALID_STATUSES:
            status = "not_tested"
        chapter = req.get("chapter", "Unknown")
        total += 1
        if chapter in chapter_stats:
            chapter_stats[chapter][STATUS_KEY[status]] += 1
        if status == "pass":
            passed += 1
        elif status == "fail":
            failed += 1
            failed_controls.append({
                "control_id": req.get("control_id"),
                "chapter": chapter,
                "requirement": req.get("requirement", "")[:120],
                "evidence": req.get("evidence", ""),
                "severity": "HIGH" if chapter in ("V4_Access_Control", "V2_Authentication", "V5_Validation") else "MEDIUM",
                "notes": req.get("notes", ""),
            })
        elif status == "na":
            na += 1
        else:
            not_tested += 1

    applicable = total - na
    conformance_pct = round(passed / applicable * 100, 1) if applicable > 0 else 0.0

    by_chapter = {}
    for ch, stats in chapter_stats.items():
        ch_applicable = stats["passed"] + stats["failed"] + stats["not_tested"]
        if ch_applicable == 0:
            continue
        ch_pct = round(stats["passed"] / ch_applicable * 100, 1) if ch_applicable > 0 else 0.0
        by_chapter[ch] = {
            "passed": stats["passed"],
            "failed": stats["failed"],
            "not_tested": stats["not_tested"],
            "conformance_pct": ch_pct,
        }

    overall_risk = (
        "CRITICAL" if failed >= 10
        else "HIGH" if failed >= 3
        else "MEDIUM" if failed >= 1
        else "LOW"
    )

    report = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "application": app,
        "target_url": url,
        "asvs_version": ASVS_VERSION,
        "level": level,
        "summary": {
            "total_requirements": total,
            "applicable": applicable,
            "passed": passed,
            "failed": failed,
            "na": na,
            "not_tested": not_tested,
            "conformance_pct": conformance_pct,
        },
        "by_chapter": by_chapter,
        "failed_controls": failed_controls,
        "overall_risk": overall_risk,
        "recommendation": (
            f"{failed} control(s) failed. Prioritise remediation of "
            f"{'access control and authentication' if any(c['chapter'] in ('V4_Access_Control','V2_Authentication') for c in failed_controls) else 'critical'} "
            f"findings before release."
            if failed > 0
            else f"All {passed} tested controls passed. Ensure not_tested ({not_tested}) items are addressed before final sign-off."
        ),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] Report saved to {args.output}")
    print(f"[*] Conformance: {conformance_pct}% ({passed}/{applicable} applicable controls)")

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)

    return report


def main():
    parser = argparse.ArgumentParser(description="ASVS Compliance Assessment Agent")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_init = sub.add_parser("init", help="Create a blank ASVS assessment worksheet")
    p_init.add_argument("--app", required=True, help="Application name")
    p_init.add_argument("--url", required=True, help="Target URL")
    p_init.add_argument("--level", type=int, choices=[1, 2, 3], default=2, help="ASVS level (default: 2)")
    p_init.add_argument("--output", default="asvs_assessment.json")

    p_report = sub.add_parser("report", help="Generate conformance report from completed worksheet")
    p_report.add_argument("--assessment", required=True, help="Completed assessment worksheet JSON")
    p_report.add_argument("--output", default="asvs_report.json")

    args = parser.parse_args()

    if args.subcommand == "init":
        cmd_init(args)
    elif args.subcommand == "report":
        cmd_report(args)


if __name__ == "__main__":
    main()
