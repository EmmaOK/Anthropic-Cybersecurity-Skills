---
name: reverse-engineering-binaries-with-ghidra
description: >-
  Static reverse engineering of binaries with Ghidra — decompilation, function and
  symbol recovery, and vulnerability research across PE, ELF, and Mach-O for malware
  analysis and vuln discovery.
domain: cybersecurity
subdomain: malware-analysis
tags:
  - reverse-engineering
  - ghidra
  - static-analysis
  - binary-analysis
  - decompilation
  - vulnerability-research
  - malware-analysis
  - macos
  - linux
  - windows-pe
  - elf
  - macho
  - symbol-analysis
  - function-recovery
  - memory-forensics
  - T1027
  - T1059
  - T1140
  - T1497
version: '1.0'
author: emmanuelokonkwo
license: Apache-2.0
---

# Skill: Reverse Engineering Binaries with Ghidra

## Metadata
- **Name**: reverse-engineering-binaries-with-ghidra
- **Subdomain**: malware-analysis
- **Tags**: reverse-engineering, ghidra, static-analysis, binary-analysis, decompilation, vulnerability-research, malware-analysis, macOS, linux, windows-pe, elf, macho, symbol-analysis, function-recovery, memory-forensics
- **Has Script**: true
- **References**: MITRE ATT&CK T1027/T1059/T1140/T1497, CWE-120/CWE-476/CWE-416

---

## Overview

Ghidra is NSA's open-source software reverse engineering framework supporting x86, x86-64, ARM, MIPS, and more. It provides a decompiler (C pseudocode), disassembler, symbol analysis, cross-reference mapping, and a scripting API (Java/Python). Ghidra 12+ is installed at `/opt/homebrew/Cellar/ghidra/12.0.4/`.

**Two modes:**
- **GUI** — interactive analysis: `ghidraRun`
- **Headless** — scriptable batch analysis: `analyzeHeadless`

---

## Phase 1 — Pre-Analysis (Before Ghidra)

**Identify file type:**
```bash
file /path/to/binary
```
- `Mach-O 64-bit` — macOS native binary
- `ELF 64-bit` — Linux binary
- `PE32+` — Windows 64-bit binary
- `Zip archive` — possibly JAR, APK, or Electron asar

**Quick triage:**
```bash
strings -a /path/to/binary | grep -iE "password|secret|key|token|http|ftp|cmd|exec|eval" | head -40
nm -a /path/to/binary 2>/dev/null | grep -iE "crypt|auth|login|pass|key|socket|exec" | head -20
otool -L /path/to/binary 2>/dev/null     # macOS: linked libraries
ldd /path/to/binary 2>/dev/null          # Linux: linked libraries
```

**Compute hashes for threat intel lookup:**
```bash
shasum -a 256 /path/to/binary
md5 /path/to/binary
```

---

## Phase 2 — Ghidra GUI Analysis

**Launch:**
```bash
ghidraRun
```

**Workflow:**
1. `File → New Project → Non-Shared Project` → name it
2. `File → Import File` → select binary → Accept defaults → Auto-analyze
3. Wait for analysis (progress bar bottom-right) — typically 1-5 min for small binaries
4. `Window → Decompiler` — shows C pseudocode for selected function
5. `Window → Symbol Table` — all imported/exported symbols
6. `Window → String` — all embedded strings
7. `Search → For Strings` — search with regex

**Key shortcuts:**
| Action | Shortcut |
|---|---|
| Go to function | `G` then type name |
| Rename variable | `L` |
| Rename function | `Alt+Shift+R` |
| Cross-references | `Ctrl+Shift+F` |
| Search strings | `Ctrl+Shift+E` |
| Add bookmark | `Ctrl+D` |
| Comment | `;` |
| Decompile view | `Ctrl+E` |

**Finding crypto operations:**
- Search → For Scalars: look for common crypto constants
  - AES S-box: `0x63637c7c`
  - RC4: `0x100` (256-byte key schedule)
  - MD5 init: `0x67452301`
  - SHA-1 init: `0x67452301`

---

## Phase 3 — Headless Analysis (Scripted)

**Ghidra headless binary path:**
```bash
GHIDRA_HEADLESS="/opt/homebrew/Cellar/ghidra/12.0.4/ghidra_12.0.4_PUBLIC/support/analyzeHeadless"
```

**Import and analyze a binary:**
```bash
$GHIDRA_HEADLESS /tmp/ghidra_projects MyProject \
  -import /path/to/binary \
  -analysisTimeoutPerFile 300 \
  -log /tmp/ghidra_analysis.log
```

**Re-analyze an existing project:**
```bash
$GHIDRA_HEADLESS /tmp/ghidra_projects MyProject \
  -process binary_name \
  -postScript ListFunctions.py \
  -scriptPath /path/to/scripts
```

**Delete project after analysis:**
```bash
$GHIDRA_HEADLESS /tmp/ghidra_projects MyProject \
  -import /path/to/binary \
  -postScript ExtractStrings.py \
  -deleteProject
```

---

## Phase 4 — Vulnerability Patterns

**Memory safety issues (look for in decompiler):**
```
strcpy(dest, src)          → CWE-120 buffer overflow
gets(buffer)               → CWE-120
sprintf(buf, format, ...)  → format string / overflow
malloc return not checked  → CWE-476 null dereference
free(ptr); use ptr         → CWE-416 use-after-free
```

**Dangerous function search in Ghidra:**
- `Search → Program Text` → search in `Functions` for: `strcpy`, `gets`, `sprintf`, `system`, `popen`, `execve`
- Or use Symbol Table → filter by name

**Privilege-related functions (macOS):**
```
AuthorizationCreate
AuthorizationCopyRights
setuid / seteuid
posix_spawnattr_setflags
SecTaskCopyValueForEntitlement
```

**Hardcoded credential pattern (decompiler view):**
```c
// Look for direct string comparisons:
if (strcmp(input, "hardcoded_password") == 0)  // CWE-259
// Or constant xor "encryption":
local_var ^ 0x42  // trivial obfuscation
```

---

## Phase 5 — Obfuscation & Packing

**Detect packing/obfuscation:**
```bash
# High entropy sections suggest packing/encryption
# strings output is sparse (< 20 readable strings for a large binary)
strings -a /path/to/binary | wc -l

# Check section entropy
rabin2 -S /path/to/binary 2>/dev/null    # if radare2 installed
```

**Manual unpacking in Ghidra:**
1. Find the entry point (`Entry` in Symbol Table)
2. Trace the bootstrap routine — look for `mprotect` / `VirtualProtect` calls
3. Identify the unpacking loop (XOR/ADD loops over a memory region)
4. Set breakpoint at OEP (Original Entry Point) using Frida, dump decrypted image
5. Re-import the dumped memory into Ghidra

---

## Phase 6 — macOS-Specific Analysis

**Objective-C class/method recovery:**
- Ghidra automatically recovers ObjC class names from `__objc_classrefs` and `__objc_methnames` sections
- `Window → Symbol Table` → filter by `msgSend` to find all ObjC method calls
- Cross-reference `objc_msgSend` calls to map class hierarchy

**Swift binary analysis:**
- Enable Swift demangler: `Edit → Tool Options → Demangler`
- Swift symbols appear as `$sSomeClass4funcSiF` — Ghidra demangles to readable names

**dylib injection check:**
```bash
# Check if binary respects DYLD_INSERT_LIBRARIES (absent hardened runtime)
codesign -d --entitlements :- /path/to/binary
# If no com.apple.security.cs.disable-library-validation → DYLD injection blocked
```

---

## Phase 7 — Reporting Findings

**Key artifacts to document for each finding:**
1. Function name + address (e.g., `FUN_00101234` or resolved symbol)
2. Decompiler pseudocode snippet
3. CWE classification
4. Exploitability assessment (reachability, attacker control of input)
5. Ghidra screenshot path

---

## Finding Categories

| ID | Title | CWE | CVSS |
|---|---|---|---|
| BIRE-001 | Hardcoded credentials in binary | CWE-259 | 8.2 |
| BIRE-002 | Stack buffer overflow (strcpy/gets) | CWE-120 | 8.8 |
| BIRE-003 | Format string vulnerability | CWE-134 | 7.8 |
| BIRE-004 | Use-after-free | CWE-416 | 7.8 |
| BIRE-005 | Null pointer dereference | CWE-476 | 6.5 |
| BIRE-006 | Command injection via system()/popen() | CWE-78 | 9.8 |
| BIRE-007 | Weak/custom cryptography | CWE-327 | 7.4 |
| BIRE-008 | Trivial obfuscation (XOR cipher) | CWE-261 | 5.3 |
| BIRE-009 | Sensitive strings in binary (cleartext) | CWE-312 | 6.5 |
| BIRE-010 | Missing PIE/ASLR | CWE-119 | 5.9 |
| BIRE-011 | Missing stack canaries | CWE-693 | 6.3 |
| BIRE-012 | DYLD injection vulnerability | CWE-427 | 7.3 |

---

## Agent.py Usage

```bash
# Triage a binary before Ghidra analysis
python3 agent.py triage --binary /path/to/binary

# Run headless Ghidra analysis
python3 agent.py analyze --binary /path/to/binary --project /tmp/ghidra_projects

# Search for dangerous function calls
python3 agent.py find-vulns --binary /path/to/binary

# Extract all strings and grep for patterns
python3 agent.py strings --binary /path/to/binary --pattern "password|secret|key"

# Check binary hardening (PIE, stack canary, etc.)
python3 agent.py hardening --binary /path/to/binary

# Full analysis + report
python3 agent.py assess --binary /path/to/binary --output report.md
```

---

## References
- Ghidra NSA: https://ghidra-sre.org/
- Ghidra Book (No Starch Press)
- MITRE ATT&CK: T1027, T1059, T1140, T1497
- CWE Top 25: https://cwe.mitre.org/top25/
