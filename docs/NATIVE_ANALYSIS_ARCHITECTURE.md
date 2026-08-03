# Android Native Binary Vulnerability Scanner Architecture

## Overview

The **APKTrace - Native Security Analysis Engine** is an automated static vulnerability scanner designed to detect security defects, memory safety flaws, insecure API usage, and embedded anti-analysis controls inside compiled Android shared libraries (`.so` files across ARM64, ARMv7, x86, and x86_64 architectures).

The architecture comprises a modular pipeline:
1. **Binary Ingestion & Header Parser** (`GhidraParser`)
2. **Decompilation & Heuristic Symbol Mapper** (Ghidra Headless primary / Cross-Platform Fallback)
3. **Core Scan Engine** (`ScanEngine`)
4. **Abstract Rule Engine & Analyzers** (`BaseAnalyzer` + 15 specialized vulnerability classes)
5. **JSON Report Generator** (`JsonReporter`)

---

## Technical Pipeline Architecture

```
  ┌──────────────────────────────┐
  │ Target Shared Library (.so) │
  └──────────────┬───────────────┘
                 │
                 ▼
 ┌──────────────────────────────────────────────┐
 │ GhidraParser / ELF Header Ingestion          │
 │ - Computes SHA-256 Digest                     │
 │ - Detects ABI Architecture (ARM64, x86, etc.) │
 │ - Inspects Security Controls (Canary/PIE/NX) │
 └──────────────┬───────────────────────────────┘
                │
        ┌───────┴────────────────────────┐
        │ Primary Mode Available?        │
        └───────┬────────────────┬───────┘
                │ Yes            │ No / Fallback
                ▼                ▼
  ┌───────────────────┐  ┌────────────────────────────────────┐
  │ Ghidra Headless   │  │ Cross-Platform Fallback Parser     │
  │ Jython Decompiler │  │ - Extract ASCII / UTF-8 Strings     │
  │ Output JSON       │  │ - Symbol Matching & Heuristic      │
  │ Export            │  │   Decompiled C Code Generation    │
  └─────────┬─────────┘  └─────────────────┬──────────────────┘
            │                              │
            └──────────────┬───────────────┘
                           │
                           ▼
            ┌─────────────────────────────┐
            │ ParsedBinary Data Structure │
            └──────────────┬──────────────┘
                           │
                           ▼
            ┌─────────────────────────────┐
            │ ScanEngine Workflow          │
            │ Iterates Active Analyzers   │
            └──────────────┬──────────────┘
                           │
                           ▼
   ┌───────────────────────────────────────────────┐
   │ 15 Vulnerability Analyzers (BaseAnalyzer)     │
   │ - Signature Pattern Matching                  │
   │ - Scope-level Deduplication                   │
   │ - 20-Line Memory Context Window Formatting   │
   │ - Source / Sink Data Flow Trace Assembly      │
   └──────────────┬────────────────────────────────┘
                  │
                  ▼
   ┌───────────────────────────────────────────────┐
   │ JsonReporter Output Assembly                 │
   │ Exports Final Vulnerability Audit Report      │
   └───────────────────────────────────────────────┘
```

---

## Vulnerability Detection Matrix (15 Categories)

| Category ID | Category Name | Severity | Detection Mechanics |
|---|---|---|---|
| **BOF-001** | Buffer Overflow | CRITICAL | Unchecked string/memory bounds functions (`strcpy`, `strcat`, `sprintf`, `memcpy`) |
| **INJ-001** | Command Injection | CRITICAL | Passing unsanitized input to process spawners (`system`, `popen`, `execve`) |
| **FMT-001** | Format String Flaws | HIGH | Non-literal format string arguments passed directly to variadic print sinks (`printf`, `vfprintf`, `syslog`) |
| **CRY-001** | Weak Cryptography | HIGH | Legacy algorithms (`MD5`, `DES`, `RC4`) or single-byte XOR rotation loops (`^=`) |
| **DBG-001** | Anti-Debugging | MEDIUM | Process self-attachment (`ptrace`) or inspection of `/proc/self/status` |
| **MEM-001** | Memory Lifecycle Flaws | HIGH | Double Free invocations or Use-After-Free (UAF) pointer dereferences |
| **JNI-001** | JNI Boundary Leaks | HIGH | Native pointer acquisition (`GetStringUTFChars`) without proper releases or boundary guards |
| **PRM-001** | File Permission Flaws | MEDIUM | World-writable mode bits (`0777`, `0666`, `umask(0)`) in directory/file creation APIs |
| **INT-001** | Integer Overflow | MEDIUM | Direct arithmetic operations (`count * size`) inside memory allocation arguments (`malloc`) |
| **IPC-001** | Insecure IPC Channel | HIGH | Unauthenticated UNIX domain sockets (`AF_UNIX`) initialized in shared directories (`/tmp/`) |
| **NUL-001** | Null Pointer Dereference | MEDIUM | Immediate dereferencing of dynamic memory allocation returns prior to NULL verification |
| **RND-001** | Insecure Randomness | LOW | Seeding non-cryptographic PRNGs via `srand(time(NULL))` and `rand()` calls |
| **REF-001** | JNI Reflection Abuse | HIGH | Unvalidated Java reflection invocation via JNI environment pointers (`FindClass`, `GetMethodID`) |
| **FRD-001** | Anti-Root / Anti-Frida | LOW | Filesystem checks probing for superuser binaries (`/system/xbin/su`) or Frida server sockets |
| **STR-001** | Hardcoded Secrets | LOW | High-entropy 32-character hexadecimal API keys exposed in `.rodata` string tables |

---

## Detailed Component Specifications

### 1. Ingestion & Fallback Symbol Resolution (`ghidra_parser.py`)
- Reads raw ELF header bytes (`\x7fELF`) to verify machine architecture (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`).
- Inspects string sections for binary security mitigations (`__stack_chk_fail` for Stack Canary, `GNU_RELRO` for RELRO status).
- When Ghidra Headless is unavailable, the fallback parser extracts printable ASCII/UTF-8 strings and resolves exported JNI symbols (`Java_...`).
- Constructs synthetic decompiled function blocks representing extracted native routines, assigning 16-byte aligned virtual memory addresses starting at offset `0x2b00`.

### 2. Context Window & Taint Flow Construction (`base_analyzer.py`)
- For every matched vulnerability pattern, `BaseAnalyzer` generates a 20-line context window surrounding the trigger statement (`trigger_index - 10` to `trigger_index + 10`).
- Each code line is formatted with virtual memory offset annotations and explicit trigger labels:
  `/* 0x2b40 | line 34 */ statement; // [TRIGGER]`
- Extracts variable/buffer operands to populate the `target_variable` field.
- Constructs a structured `FlowAnalysis` payload describing the JNI parameter source and unsanitized function call sink.

### 3. Scope Deduplication Engine
- To prevent duplicate finding alerts for identical functions, the engine enforces scope-level deduplication keyed by `(rule_id, function_name)`.
- Ensures exactly 1 finding per vulnerability rule per function scope while preserving full taint flow details.

---

## JSON Output Report Structure

The scanner outputs structured JSON results adhering to the following schema:

```json
{
  "scan_metadata": {
    "target_binary": "libnative.so",
    "apk_relative_path": "standalone/libnative.so",
    "architecture": "arm64-v8a",
    "sha256": "...",
    "scan_timestamp": "2026-08-03T10:00:00Z"
  },
  "summary": {
    "total_findings": 15,
    "by_severity": {
      "CRITICAL": 2,
      "HIGH": 6,
      "MEDIUM": 4,
      "LOW": 3
    }
  },
  "findings": [
    {
      "finding_id": "FIND-01",
      "rule_id": "CMD-001",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "target_file": "standalone/libnative.so",
      "location": {
        "function_name": "processUserConfig",
        "symbol_address": "0x2b00",
        "line_number": 8,
        "is_exported_jni": true
      },
      "target_variable": "cfg_buf",
      "trigger_line": "FILE* pipe = popen(cfg_buf, \"r\");",
      "flow_analysis": {
        "source": "JNI parameter passed to function 'processUserConfig' at line 1",
        "sink": "Unsanitized call via pattern 'popen\\s*\\(' at line 8",
        "data_path": [ ... ]
      }
    }
  ]
}
```
