---
name: performing-desktop-application-penetration-test
description: >-
  End-to-end penetration testing of desktop applications (Electron, .NET, native
  binaries) — static and dynamic analysis, traffic interception, credential
  extraction, and privilege escalation using Frida, Ghidra, mitmproxy, Burp, and Wireshark.
domain: cybersecurity
subdomain: application-security
tags:
  - desktop-security
  - penetration-testing
  - reverse-engineering
  - frida
  - ghidra
  - mitmproxy
  - burpsuite
  - wireshark
  - electron
  - dotnet
  - native-binary
  - dynamic-analysis
  - static-analysis
  - traffic-interception
  - credential-extraction
  - privilege-escalation
  - T1005
  - T1012
  - T1082
  - T1113
  - T1539
  - T1552
  - T1552.001
  - T1555
  - T1557.002
version: '1.0'
author: emmanuelokonkwo
license: Apache-2.0
---

# Skill: Performing Desktop Application Penetration Test

## Metadata
- **Name**: performing-desktop-application-penetration-test
- **Subdomain**: application-security
- **Tags**: desktop-security, penetration-testing, reverse-engineering, frida, ghidra, mitmproxy, burpsuite, wireshark, electron, dotnet, native-binary, dynamic-analysis, static-analysis, traffic-interception, credential-extraction, privilege-escalation
- **Has Script**: true
- **References**: OWASP Desktop App Security Top 10, MITRE ATT&CK T1005/T1012/T1082/T1113/T1539/T1552/T1555

---

## Overview

Desktop application penetration testing evaluates installed applications for vulnerabilities including insecure local storage, weak update mechanisms, protocol-level issues, binary vulnerabilities, and privilege escalation via the host OS. Targets include Electron apps, .NET apps (Windows), native macOS/Linux binaries, and thick clients communicating over HTTP/S, TCP, or proprietary protocols.

**Tool stack (all installed on this system):**
- Burp Suite Pro — HTTP/HTTPS interception and scanning
- mitmproxy / mitmdump — scriptable proxy, non-browser HTTP interception
- Wireshark / tshark — non-HTTP protocol capture and analysis
- Frida + objection — dynamic instrumentation and runtime hooking
- Ghidra — static binary analysis and decompilation
- strings / file / otool — built-in binary inspection

---

## Assessment Phases

### Phase 1 — Reconnaissance & App Profiling

**Identify app type:**
```bash
file /path/to/app-binary
otool -L /path/to/app-binary          # macOS: linked libraries
ldd /path/to/app-binary               # Linux: linked libraries
strings /path/to/app-binary | head -100
```

**Electron app detection:**
```bash
# Electron apps contain a resources/app.asar or resources/app directory
ls /Applications/AppName.app/Contents/Resources/
# Extract asar archive
npx @electron/asar extract app.asar ./app-extracted
```

**.NET app detection (macOS/Linux via Mono):**
```bash
file AppName.exe                      # PE32 with Mono/.NET indicators
strings AppName.exe | grep -i "mono\|\.net\|mscorlib"
```

**Network profile — identify protocols:**
```bash
# Capture all traffic from the app process
sudo tshark -i en0 -f "host <app-server-ip>" -w /tmp/app-capture.pcap
# Or filter by port
sudo tshark -i en0 -f "tcp port 443 or tcp port 8080" -w /tmp/app-capture.pcap
```

---

### Phase 2 — Traffic Interception

**HTTP/HTTPS apps — configure Burp Suite or mitmproxy as system proxy:**
```bash
# Set macOS system proxy (HTTP + HTTPS)
networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8080
networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8080
# Restore after testing
networksetup -setwebproxystate "Wi-Fi" off
networksetup -setsecurewebproxystate "Wi-Fi" off
```

**mitmproxy for scriptable interception:**
```bash
# Interactive TUI
mitmproxy --listen-port 8080

# Headless dump
mitmdump --listen-port 8080 -w /tmp/app-traffic.mitm

# With custom addon script
mitmdump --listen-port 8080 -s intercept_addon.py

# Install mitmproxy CA cert (macOS)
open ~/.mitmproxy/mitmproxy-ca-cert.pem    # then trust in Keychain
```

**Certificate pinning bypass via Frida:**
```bash
# List running processes
frida-ps -U                            # USB-attached device
frida-ps -l                            # local processes

# objection for automatic SSL unpinning
objection --gadget "AppName" explore
# Inside objection:
# ios sslpinning disable
# android sslpinning disable
# macos sslpinning disable

# Manual Frida SSL bypass script
frida -l ssl_bypass.js -f /path/to/AppName --no-pause
```

**Non-HTTP traffic — Wireshark / tshark:**
```bash
# Live capture with display filter
tshark -i en0 -Y "tcp.port == 5432 or tcp.port == 1433" -w /tmp/db-traffic.pcap

# Read capture and extract credentials
tshark -r /tmp/app-capture.pcap -Y "ftp or telnet or pop or imap" -T fields \
  -e frame.number -e ip.src -e ip.dst -e tcp.payload

# Follow TCP stream
tshark -r /tmp/app-capture.pcap -z follow,tcp,ascii,0
```

---

### Phase 3 — Static Analysis

**Binary inspection (native macOS/Linux):**
```bash
# Readable strings
strings -a /path/to/binary | grep -iE "password|secret|key|token|api|http|ftp|jdbc"

# Symbol table
nm -a /path/to/binary 2>/dev/null | grep -iE "crypt|auth|login|password|key"

# Linked frameworks (macOS)
otool -L /path/to/binary

# Entitlements (macOS)
codesign -d --entitlements :- /Applications/AppName.app

# Check for hardened runtime / stack canaries
otool -Iv /path/to/binary | grep -E "stack_chk|__PIE"
checksec --file=/path/to/binary       # if checksec installed
```

**Ghidra headless analysis:**
```bash
# Import binary and run auto-analysis
ghidraRun /path/to/GhidraProject ghidraRun \
  -import /path/to/binary \
  -postScript FindPasswordStrings.java \
  -scriptPath /path/to/scripts \
  -noanalysis

# Headless analysis with built-in scripts
/opt/homebrew/opt/ghidra/ghidra_*/support/analyzeHeadless \
  /tmp/ghidra_projects MyProject \
  -import /path/to/binary \
  -analysisTimeoutPerFile 300

# Extract all strings ≥ 8 chars
/opt/homebrew/opt/ghidra/ghidra_*/support/analyzeHeadless \
  /tmp/ghidra_projects MyProject \
  -process binary_name \
  -postScript ExtractStrings.java
```

**Electron app — JavaScript source analysis:**
```bash
# After extracting asar:
grep -rE "password|secret|api_key|token|hardcoded|eval\(" ./app-extracted/ --include="*.js"
grep -rE "require\('child_process'\)|exec\(|spawn\(" ./app-extracted/ --include="*.js"
grep -rE "nodeIntegration|contextIsolation|enableRemoteModule" ./app-extracted/ --include="*.json"
grep -rE "allowRunningInsecureContent|webSecurity" ./app-extracted/ --include="*.js"
```

---

### Phase 4 — Dynamic Analysis with Frida

**Attach to running process:**
```bash
# List processes
frida-ps -l

# Attach and drop to REPL
frida -n "AppName"

# Spawn and attach
frida -f /Applications/AppName.app/Contents/MacOS/AppName --no-pause

# Trace all function calls matching pattern
frida-trace -n "AppName" -i "Crypto*" -i "*password*" -i "*encrypt*"

# Trace Objective-C methods (macOS)
frida-trace -n "AppName" -m "-[*Auth *]" -m "-[*Login *]" -m "-[*Password *]"

# Trace system calls
frida-strace -n "AppName"
```

**Hook crypto functions (Frida script):**
```javascript
// hook_crypto.js — intercept CommonCrypto on macOS
Interceptor.attach(Module.getExportByName("libSystem.B.dylib", "CCCrypt"), {
    onEnter: function(args) {
        console.log("[CCCrypt] operation:", args[0], "algorithm:", args[1]);
        console.log("[CCCrypt] key:", Memory.readByteArray(args[5], parseInt(args[6])));
    }
});
```

```bash
frida -n "AppName" -l hook_crypto.js
```

**Dump memory for credentials:**
```bash
frida -n "AppName" -e "
Process.enumerateModules().forEach(m => {
    if (m.name.includes('AppName')) {
        console.log(m.name, m.base, m.size);
    }
});
"
```

**objection for structured exploration:**
```bash
objection --gadget "AppName" explore

# Inside objection:
memory list modules
memory list exports --filter "crypto"
memory search --string "password"
memory dump all /tmp/appdump.bin
ios keychain dump                 # macOS Keychain access
env                               # print app environment
```

---

### Phase 5 — Local Storage & Credential Analysis

**macOS Keychain:**
```bash
# List items accessible to app
security find-generic-password -a "AppName" -g 2>&1
security find-internet-password -s "app-server.com" -g 2>&1
security dump-keychain ~/Library/Keychains/login.keychain-db
```

**App-specific storage paths:**
```bash
# macOS app data directories
ls ~/Library/Application\ Support/AppName/
ls ~/Library/Preferences/com.company.AppName.plist
ls ~/Library/Containers/com.company.AppName/

# Read plist
plutil -p ~/Library/Preferences/com.company.AppName.plist

# SQLite databases
find ~/Library -name "*.sqlite" -path "*AppName*" 2>/dev/null
sqlite3 ~/Library/Application\ Support/AppName/app.db .dump
```

**Search for hardcoded secrets in app bundle:**
```bash
find /Applications/AppName.app -type f | while read f; do
    strings "$f" 2>/dev/null | grep -iE "(password|secret|api_key|token|private_key)\s*[=:]\s*\S{8,}"
done
```

---

### Phase 6 — Update Mechanism Testing

```bash
# Capture update traffic via mitmproxy
mitmdump --listen-port 8080 -s - << 'EOF'
def response(flow):
    if "update" in flow.request.url or "version" in flow.request.url:
        print(f"UPDATE URL: {flow.request.url}")
        print(f"RESPONSE: {flow.response.content[:500]}")
EOF

# Test for unsigned update acceptance
# 1. Intercept the update manifest response
# 2. Modify the download URL to point to a malicious binary
# 3. Observe if the app validates signatures before executing
```

---

### Phase 7 — Privilege & Permission Testing

**macOS code signing and entitlements:**
```bash
# Verify signature
codesign -v /Applications/AppName.app
spctl -a -v /Applications/AppName.app

# Check dangerous entitlements
codesign -d --entitlements :- /Applications/AppName.app | grep -E \
  "com.apple.security.cs.allow-unsigned-executable|com.apple.security.cs.disable-library-validation|com.apple.private"

# SUID binaries installed by app
find /Applications/AppName.app -perm -4000 -o -perm -2000 2>/dev/null
```

**LaunchAgents / LaunchDaemons:**
```bash
ls ~/Library/LaunchAgents/ | grep -i appname
ls /Library/LaunchDaemons/ | grep -i appname
cat /Library/LaunchDaemons/com.company.appname.plist
```

---

## Finding Categories

| ID | Title | CVSS | Technique |
|---|---|---|---|
| DAPP-001 | Cleartext credentials in local storage | 7.5 | T1552.001 |
| DAPP-002 | SSL/TLS certificate pinning bypass | 7.4 | T1557.002 |
| DAPP-003 | Hardcoded secrets in binary/resources | 8.2 | T1552.001 |
| DAPP-004 | Insecure update mechanism (no signature check) | 8.8 | T1195.002 |
| DAPP-005 | Sensitive data in plaintext plist/SQLite | 6.5 | T1005 |
| DAPP-006 | Electron — nodeIntegration enabled | 9.0 | T1059.007 |
| DAPP-007 | Electron — contextIsolation disabled | 8.8 | T1059.007 |
| DAPP-008 | Electron — webSecurity disabled (XSS→RCE) | 9.6 | T1059.007 |
| DAPP-009 | Unsafe deserialization in IPC/protocol | 8.8 | T1559 |
| DAPP-010 | Missing keychain/credential protection | 6.8 | T1555 |
| DAPP-011 | Privileged helper with weak IPC validation | 8.4 | T1548 |
| DAPP-012 | Sensitive data in process memory (cleartext) | 5.5 | T1005 |
| DAPP-013 | Unencrypted protocol (plaintext auth) | 8.1 | T1040 |
| DAPP-014 | Dangerous macOS entitlements | 7.0 | T1082 |

---

## Agent.py Usage

```bash
# Profile the app
python3 agent.py profile --app /Applications/AppName.app

# Intercept HTTP/S traffic (starts mitmproxy, sets system proxy)
python3 agent.py intercept --port 8080 --duration 60

# Analyze captured traffic dump
python3 agent.py analyze-traffic --file /tmp/app.mitm

# Static analysis of binary
python3 agent.py static --binary /path/to/binary

# Analyze Electron app
python3 agent.py electron --app /Applications/AppName.app

# Search local storage for credentials
python3 agent.py local-storage --app-name AppName

# Full assessment
python3 agent.py assess --app /Applications/AppName.app --output report.md

# Generate report
python3 agent.py report --format markdown --file report.md
```

---

## References
- OWASP Desktop App Security Top 10
- MITRE ATT&CK: T1005, T1012, T1082, T1040, T1539, T1552, T1555, T1559, T1548, T1195.002
- Electron Security Checklist: https://www.electronjs.org/docs/latest/tutorial/security
- Frida docs: https://frida.re/docs/
- Ghidra NSA: https://ghidra-sre.org/
