---
name: performing-dynamic-analysis-with-frida
description: >-
  Runtime instrumentation and dynamic analysis with Frida — function/API hooking,
  memory analysis, crypto/TLS interception, and SSL pinning bypass across macOS,
  Linux, Android, and iOS. Aligned to OWASP MASTG.
domain: cybersecurity
subdomain: application-security
tags:
  - frida
  - dynamic-analysis
  - instrumentation
  - hooking
  - runtime-analysis
  - desktop-security
  - macos
  - linux
  - android
  - ios
  - objection
  - memory-analysis
  - crypto-interception
  - ssl-bypass
  - api-hooking
  - reverse-engineering
  - T1005
  - T1040
  - T1539
  - T1552
  - T1552.001
  - T1555
  - T1557
  - T1557.002
version: '1.0'
author: emmanuelokonkwo
license: Apache-2.0
---

# Skill: Performing Dynamic Analysis with Frida

## Metadata
- **Name**: performing-dynamic-analysis-with-frida
- **Subdomain**: application-security
- **Tags**: frida, dynamic-analysis, instrumentation, hooking, runtime-analysis, desktop-security, macos, linux, android, ios, objection, memory-analysis, crypto-interception, ssl-bypass, api-hooking, reverse-engineering
- **Has Script**: true
- **References**: MITRE ATT&CK T1005/T1040/T1539/T1552/T1557, OWASP MASTG

---

## Overview

Frida is a dynamic instrumentation toolkit that injects a JavaScript engine (V8) into target processes, enabling real-time hooking, tracing, memory inspection, and function interception without recompiling or restarting the app. Installed at `/Users/emmanuelokonkwo/security-tools/bin/frida` with the full suite including `frida-trace`, `frida-strace`, `objection`.

**Core tools installed:**
- `frida` — REPL and script runner
- `frida-ps` — list processes
- `frida-trace` — auto-generate hooks for matching functions
- `frida-strace` — system call tracing
- `frida-ls` / `frida-ls-devices` — list devices and files
- `objection` — structured exploration framework built on Frida

---

## Phase 1 — Setup & Target Identification

**Activate the security-tools venv:**
```bash
source /Users/emmanuelokonkwo/security-tools/bin/activate
```

**List running processes:**
```bash
frida-ps -l                            # local processes
frida-ps -U                            # USB device (iOS/Android)
frida-ps -a                            # include app display names
frida-ps -l | grep -i "appname"
```

**List connected devices:**
```bash
frida-ls-devices
```

**Attach modes:**
```bash
# Attach to running process by name
frida -n "AppName"

# Attach by PID
frida -p 1234

# Spawn process (Frida starts it)
frida -f /Applications/AppName.app/Contents/MacOS/AppName --no-pause

# Spawn on iOS device
frida -U -f com.company.AppName --no-pause
```

---

## Phase 2 — Frida REPL Basics

Once attached, the REPL gives a JavaScript environment with full process access:

```javascript
// List all loaded modules
Process.enumerateModules().forEach(m => console.log(m.name, m.base, m.size));

// Find a module
Process.getModuleByName("libcrypto.dylib");

// List exports of a module
Module.enumerateExports("libcrypto.dylib").filter(e => e.name.includes("AES"));

// Read memory
Memory.readUtf8String(ptr("0x100001234"));
Memory.readByteArray(ptr("0x100001234"), 32);

// Write memory
Memory.writeUtf8String(ptr("0x100001234"), "injected");

// Scan memory for pattern
Memory.scan(module.base, module.size, "41 42 43 ?? 45", {
    onMatch: (address, size) => console.log("Found at:", address),
    onComplete: () => console.log("Scan done")
});

// Get current thread backtrace
Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n");
```

---

## Phase 3 — Function Hooking

**Hook a function by export name:**
```javascript
// hook_example.js
const open = Module.getExportByName(null, "open");
Interceptor.attach(open, {
    onEnter: function(args) {
        const path = args[0].readUtf8String();
        if (path && path.includes("password")) {
            console.log("[open] Sensitive file accessed:", path);
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join("\n\t"));
        }
    }
});
```

**Hook Objective-C method (macOS/iOS):**
```javascript
// hook_objc.js
const SecItemCopyMatching = ObjC.classes.NSURLCredential["+ credentialWithUser:password:persistence:"];
Interceptor.attach(SecItemCopyMatching.implementation, {
    onEnter: function(args) {
        const user = ObjC.Object(args[2]).toString();
        const pass = ObjC.Object(args[3]).toString();
        console.log(`[NSURLCredential] user=${user} password=${pass}`);
    }
});
```

**Hook Swift function (macOS):**
```javascript
// Swift symbols are mangled — use frida-trace to find them first
// frida-trace -n "AppName" -i "*swift*auth*"
const sym = DebugSymbol.fromName("$s7AppNameABClass4loginySS_SStF");
if (sym.address) {
    Interceptor.attach(sym.address, {
        onEnter: args => console.log("[Swift login] args:", args[0], args[1])
    });
}
```

**Replace function return value:**
```javascript
// Bypass license check that returns bool
const checkLicense = Module.getExportByName("AppName", "_checkLicense");
Interceptor.replace(checkLicense, new NativeCallback(function() {
    console.log("[checkLicense] bypassed — returning true");
    return 1;
}, "int", []));
```

---

## Phase 4 — SSL/TLS Interception & Certificate Pinning Bypass

**macOS — bypass SecTrustEvaluate:**
```javascript
// ssl_bypass_macos.js
const SecTrustEvaluateWithError = Module.getExportByName("Security", "SecTrustEvaluateWithError");
Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
    console.log("[SecTrustEvaluateWithError] bypassed");
    if (!error.isNull()) Memory.writePointer(error, ptr(0));
    return 1;
}, "bool", ["pointer", "pointer"]));
```

**iOS — objection automatic bypass:**
```bash
objection --gadget "com.company.AppName" explore
# Inside objection:
ios sslpinning disable
# All SSL pinning methods bypassed automatically
```

**Android — objection:**
```bash
objection --gadget "com.company.appname" explore
android sslpinning disable
```

**Network Security Config bypass (Android):**
```bash
objection --gadget "com.company.appname" explore
android network_security_config
```

---

## Phase 5 — Cryptography Interception

**Intercept CommonCrypto (macOS/iOS):**
```javascript
// hook_commoncrypto.js
const CCCrypt = Module.getExportByName("libSystem.B.dylib", "CCCrypt");
Interceptor.attach(CCCrypt, {
    onEnter: function(args) {
        const op = args[0].toInt32();         // 0=encrypt, 1=decrypt
        const alg = args[1].toInt32();         // 0=AES, 1=DES...
        const keyLen = args[6].toInt32();
        const key = Memory.readByteArray(args[5], keyLen);
        console.log(`[CCCrypt] op=${op==0?"ENC":"DEC"} alg=${alg} key=${hexdump(key, {header:false}).trim()}`);
        this.iv = args[7];
        this.ivLen = 16;
    },
    onLeave: function(retval) {
        console.log("[CCCrypt] return:", retval.toInt32());
    }
});
```

**Intercept OpenSSL (cross-platform):**
```javascript
// hook_openssl.js
["SSL_write", "SSL_read"].forEach(fn => {
    const addr = Module.getExportByName("libssl.dylib", fn) ||
                 Module.getExportByName("libssl.so", fn);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            const buf = args[1];
            const len = args[2].toInt32();
            console.log(`[${fn}] len=${len}`);
            console.log(Memory.readUtf8String(buf, len));
        }
    });
});
```

---

## Phase 6 — Memory & Credential Extraction

**Search memory for strings:**
```javascript
// search_memory.js
Process.enumerateRanges("r--").forEach(range => {
    try {
        Memory.scanSync(range.base, range.size, 
            "70 61 73 73 77 6f 72 64"  // "password" in hex
        ).forEach(m => {
            console.log("Found 'password' at:", m.address,
                Memory.readUtf8String(m.address, 64));
        });
    } catch(e) {}
});
```

**Dump macOS Keychain via objection:**
```bash
objection --gadget "AppName" explore
ios keychain dump
macos keychain dump
```

**Extract JWT/tokens from memory:**
```javascript
// token_hunter.js
const jwtPattern = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/;
Process.enumerateRanges("r--").forEach(range => {
    try {
        const chunk = Memory.readUtf8String(range.base, Math.min(range.size, 65536));
        const matches = chunk.match(jwtPattern);
        if (matches) console.log("[JWT]", matches[0], "at", range.base);
    } catch(e) {}
});
```

---

## Phase 7 — frida-trace for Rapid Attack Surface Mapping

```bash
# Trace all crypto-related function calls
frida-trace -n "AppName" -i "*crypt*" -i "*encrypt*" -i "*decrypt*" -i "*hmac*" -i "*hash*"

# Trace file system access
frida-trace -n "AppName" -i "open" -i "fopen" -i "read" -i "write"

# Trace network calls
frida-trace -n "AppName" -i "*connect*" -i "*send*" -i "*recv*" -i "*socket*"

# Trace Objective-C auth methods (macOS)
frida-trace -n "AppName" -m "-[*Auth *]" -m "-[*Login *]" -m "-[*Password *]" -m "-[*Credential *]"

# Trace all ObjC methods on a class
frida-trace -n "AppName" -m "-[NSURLSession *]" -m "+[NSURLSession *]"

# System call tracing
frida-strace -n "AppName" 2>&1 | grep -E "open|read|write|connect|execve"
```

---

## Phase 8 — objection Structured Exploration

```bash
# Attach to process
objection --gadget "AppName" explore

# Inside objection — key commands:
env                              # app directories, bundle path, data dir
memory list modules              # loaded modules
memory list exports libcrypto    # exports of a module
memory search --string "Bearer " # search for auth headers
memory dump all /tmp/dump.bin    # full memory dump

ios keychain dump                # Keychain items
ios nsuserdefaults get           # NSUserDefaults contents
ios cookies get                  # HTTP cookies
ios sslpinning disable           # bypass pinning

android root simulate            # simulate rooted environment
android intent launch_activity com.company.AppName/.LoginActivity
android clipboard monitor

# Hook a method
ios hooking watch class NSURLCredential
ios hooking watch method "-[NSURLAuthenticationChallenge init]"
ios hooking list classes         # all ObjC classes
ios hooking search methods password   # search for methods with "password"
```

---

## Finding Categories

| ID | Title | CVSS | Technique |
|---|---|---|---|
| FRDA-001 | Cleartext credentials intercepted at runtime | 8.5 | T1552 |
| FRDA-002 | SSL pinning bypassable | 7.4 | T1557.002 |
| FRDA-003 | Sensitive tokens in process memory | 6.5 | T1005 |
| FRDA-004 | Hardcoded crypto key extracted at runtime | 8.2 | T1552.001 |
| FRDA-005 | Authentication bypass via return value patch | 9.1 | T1548 |
| FRDA-006 | Keychain items accessible without auth | 7.5 | T1555 |
| FRDA-007 | JWT/session tokens extractable from memory | 7.6 | T1539 |
| FRDA-008 | Weak crypto algorithm intercepted (DES/RC4) | 6.8 | T1040 |

---

## Agent.py Usage

```bash
# List processes and find target
python3 agent.py list-processes [--filter appname]

# Attach and run a hook script
python3 agent.py hook --target "AppName" --script hook_crypto.js

# Trace function patterns
python3 agent.py trace --target "AppName" --pattern "crypt,auth,password"

# Search memory for sensitive strings
python3 agent.py memory-search --target "AppName" --pattern "password,token,Bearer,secret"

# Run SSL bypass and start mitmproxy
python3 agent.py ssl-bypass --target "AppName" --proxy-port 8080

# Full dynamic assessment
python3 agent.py assess --target "AppName" --output report.md

# Generate report from collected findings
python3 agent.py report --format markdown --file report.md
```

---

## References
- Frida documentation: https://frida.re/docs/
- objection: https://github.com/sensepost/objection
- OWASP MASTG (Mobile Application Security Testing Guide)
- MITRE ATT&CK: T1005, T1040, T1539, T1552, T1555, T1557
