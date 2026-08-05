# Android Native Binary Vulnerability Scanner Architecture

## Overview

The **APKTrace - Native Security Analysis Engine** is an automated static vulnerability scanner designed to detect security defects, memory safety flaws, insecure API usage, and embedded anti-analysis controls inside compiled Android shared libraries (`.so` files across ARM64, ARMv7, x86, and x86_64 architectures).

The architecture comprises a modular pipeline:
1. **Binary Ingestion & Header Parser** (`GhidraParser`)
2. **Decompilation & Heuristic Symbol Mapper** (Ghidra Headless primary / Cross-Platform Fallback)
3. **Core Scan Engine** (`ScanEngine`)
4. **Abstract Rule Engine & Analyzers** (`BaseAnalyzer` + 15 specialized vulnerability classes)
5. **JSON Report Generator** (`JsonReporter`)

7. **Shared Analysis Context Layer** (`AnalysisContext` & `ContextBuilder`)

---

## Technical Pipeline Architecture

```
  ┌──────────────────────────────┐
  │ Target Shared Library (.so) │
  └──────────────┬───────────────┘
                 │
                 ▼
 ┌──────────────────────────────────────────────┐
 │ ContextBuilder / AnalysisContext Pipeline   │
 │ - Computes SHA-256 Digest & Header Info      │
 │ - Detects ABI Architecture (ARM64, x86, etc.) │
 │ - Pre-extracts Hardening Flags & Symbols     │
 │ - Populates String Artifacts & Code Scope    │
 └──────────────┬───────────────────────────────┘
                │
        ┌───────┴────────────────────────┐
        │ Decompiler & Parser Pipeline   │
        └───────┬────────────────┬───────┘
                │ Ghidra         │ Fallback Parser
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
            │ Centralized AnalysisContext │
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

## Vulnerability Detection Matrix (15 Categories / 66 Sub-Rules)

| Sub-Rule ID | Category Name | Pattern Signature | Severity | Confidence | Targeted Vulnerability / Remediation |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **BOF-001** | Buffer Overflow | `gets\s*\(` | `CRITICAL` | `HIGH` | Inherently unsafe `gets()` call with no buffer bounds restriction. |
| **BOF-002** | Buffer Overflow | `strcpy\s*\(` | `CRITICAL` | `HIGH` | Unbounded string copy using `strcpy()`. Replace with `strncpy()` or `strlcpy()`. |
| **BOF-003** | Buffer Overflow | `strcat\s*\(` | `HIGH` | `HIGH` | Unbounded string concatenation using `strcat()`. Replace with `strncat()`. |
| **BOF-004** | Buffer Overflow | `sprintf\s*\(` | `HIGH` | `MEDIUM` | Unbounded string formatting into fixed destination buffer via `sprintf()`. Use `snprintf()`. |
| **BOF-005** | Buffer Overflow | `memcpy\s*\(` | `MEDIUM` | `MEDIUM` | Memory copy operation with `memcpy()` requiring explicit size verification. |
| **INJ-001** | Command Injection | `system\s*\(` | `CRITICAL` | `HIGH` | System shell invocation via `system()` with potential user-controlled input. |
| **INJ-002** | Command Injection | `popen\s*\(` | `CRITICAL` | `HIGH` | Process pipe creation via `popen()` executing shell commands with unvalidated arguments. |
| **INJ-003** | Command Injection | `execve\s*\(` | `HIGH` | `HIGH` | Low-level process replacement `execve()` receiving unvalidated argument array. |
| **INJ-004** | Command Injection | `execl\s*\(` | `HIGH` | `HIGH` | Process execution call `execl()` receiving potentially unvalidated paths. |
| **FMT-001** | Format String | `printf\s*\(\s*[^,"]+\s*\)` | `HIGH` | `HIGH` | Direct passing of non-literal variable to `printf()` format parameter. |
| **FMT-002** | Format String | `sprintf\s*\(\s*[^,]+,\s*[^,"]+\s*\)` | `HIGH` | `HIGH` | Non-literal format string passed to `sprintf()` enabling format string exploit. |
| **FMT-003** | Format String | `vprintf\s*\(\s*[^,"]+\s*\)` | `HIGH` | `HIGH` | Variadic `vprintf()` invocation using non-literal format string. |
| **FMT-004** | Format String | `vfprintf\s*\(\s*[^,]+,\s*[^,"]+\s*\)` | `HIGH` | `HIGH` | Stream formatting `vfprintf()` call using dynamic format string. |
| **FMT-005** | Format String | `syslog\s*\(\s*[^,]+,\s*[^,"]+\s*\)` | `MEDIUM` | `HIGH` | System log formatting `syslog()` with non-literal format parameter. |
| **FMT-006** | Format String | `__android_log_print\s*\([^,]+,\s*[^,]+,\s*[^,"]+\s*\)` | `MEDIUM` | `HIGH` | Android logging function `__android_log_print()` with dynamic format string. |
| **CRY-001** | Weak Cryptography | `MD5_Init` | `MEDIUM` | `HIGH` | Use of collision-vulnerable legacy MD5 hashing algorithm. |
| **CRY-002** | Weak Cryptography | `SHA1_Init` | `LOW` | `HIGH` | Use of weak SHA-1 hashing algorithm vulnerable to collision attacks. |
| **CRY-003** | Weak Cryptography | `DES_ecb_encrypt` | `HIGH` | `HIGH` | Legacy DES block cipher in ECB mode exposing identical plaintext blocks. |
| **CRY-004** | Weak Cryptography | `AES_cbc_encrypt` | `MEDIUM` | `MEDIUM` | AES-CBC mode requiring explicit MAC verification to prevent padding oracle. |
| **CRY-005** | Weak Cryptography | `RC4` | `HIGH` | `HIGH` | Deprecated RC4 stream cipher known for statistical biases. |
| **CRY-006** | Weak Cryptography | `\^=` | `LOW` | `MEDIUM` | Potential custom single-byte XOR rotation encryption loop. |
| **CRY-007** | Weak Cryptography | `\bXOR\b` | `LOW` | `LOW` | Insecure custom XOR obfuscation or encryption keyword reference. |
| **DBG-001** | Anti-Debugging | `ptrace\s*\(\s*PTRACE_TRACEME` | `MEDIUM` | `HIGH` | Anti-debugging check using `ptrace(PTRACE_TRACEME)` to prevent attachment. |
| **DBG-002** | Anti-Debugging | `ptrace\s*\(` | `MEDIUM` | `MEDIUM` | Generic `ptrace` system call for process tracing or anti-analysis. |
| **DBG-003** | Anti-Debugging | `/proc/self/status` | `LOW` | `HIGH` | Inspection of `/proc/self/status` pseudo-file to check `TracerPid`. |
| **DBG-004** | Anti-Debugging | `TracerPid` | `LOW` | `HIGH` | Hardcoded `TracerPid` string reference used in anti-debugging detection. |
| **MEM-001** | Memory Management | `free\s*\(` | `HIGH` | `MEDIUM` | Deallocation call using `free()` requiring verification for UAF / Double Free. |
| **MEM-002** | Memory Management | `realloc\s*\(` | `MEDIUM` | `MEDIUM` | Reallocation call using `realloc()` which may leak memory on failure. |
| **JNI-001** | JNI Boundary Leaks | `GetStringUTFChars` | `HIGH` | `HIGH` | Acquisition of Java String UTF chars without `ReleaseStringUTFChars`. |
| **JNI-002** | JNI Boundary Leaks | `GetByteArrayElements` | `HIGH` | `HIGH` | Acquisition of byte array elements without `ReleaseByteArrayElements`. |
| **JNI-003** | JNI Boundary Leaks | `ReleaseStringUTFChars` | `LOW` | `HIGH` | JNI `ReleaseStringUTFChars` cleanup boundary reference. |
| **JNI-004** | JNI Boundary Leaks | `ReleaseByteArrayElements` | `LOW` | `HIGH` | JNI `ReleaseByteArrayElements` cleanup boundary reference. |
| **PRM-001** | File Permission Flaws | `chmod\s*\([^,]+,\s*0?777\)` | `HIGH` | `HIGH` | Setting world-readable/writable `0777` file permissions via `chmod`. |
| **PRM-002** | File Permission Flaws | `chmod\s*\([^,]+,\s*0?666\)` | `MEDIUM` | `HIGH` | Setting world-readable/writable `0666` file permissions via `chmod`. |
| **PRM-003** | File Permission Flaws | `mkdir\s*\([^,]+,\s*0?777\)` | `HIGH` | `HIGH` | Directory creation with world-accessible `0777` permissions. |
| **PRM-004** | File Permission Flaws | `mkdir\s*\([^,]+,\s*0?666\)` | `MEDIUM` | `HIGH` | Directory creation with world-accessible `0666` permissions. |
| **PRM-005** | File Permission Flaws | `open\s*\([^,]+,\s*[^,]+,\s*0?666\)` | `MEDIUM` | `HIGH` | File open call setting world-accessible `0666` creation mode. |
| **PRM-006** | File Permission Flaws | `open\s*\([^,]+,\s*[^,]+,\s*0?777\)` | `HIGH` | `HIGH` | File open call setting world-accessible `0777` creation mode. |
| **PRM-007** | File Permission Flaws | `umask\s*\(\s*0\s*\)` | `HIGH` | `HIGH` | Clearing umask to 0, resulting in permissive default creation flags. |
| **INT-001** | Integer Overflow | `malloc\s*\(\s*[^)]*[*+]\s*[^)]*\)` | `HIGH` | `MEDIUM` | Arithmetic calculation inside `malloc()` parameter causing integer overflow. |
| **INT-002** | Integer Overflow | `calloc\s*\(\s*[^)]*[*+]\s*[^)]*\)` | `HIGH` | `MEDIUM` | Arithmetic calculation inside `calloc()` parameter causing wraparound. |
| **INT-003** | Integer Overflow | `realloc\s*\([^,]+,\s*[^)]*[*+]\s*[^)]*\)` | `HIGH` | `MEDIUM` | Arithmetic calculation inside `realloc()` parameter causing under-allocation. |
| **IPC-001** | Insecure IPC | `socket\s*\(\s*AF_UNIX` | `HIGH` | `HIGH` | Local UNIX domain socket creation vulnerable to unauthenticated local access. |
| **IPC-002** | Insecure IPC | `bind\s*\(` | `MEDIUM` | `MEDIUM` | Socket `bind()` operation requiring verification of local permissions. |
| **IPC-003** | Insecure IPC | `connect\s*\(` | `MEDIUM` | `LOW` | Socket `connect()` call connecting to local IPC endpoint. |
| **IPC-004** | Insecure IPC | `/tmp/` | `HIGH` | `HIGH` | Insecure usage of world-writable `/tmp/` directory for local socket or file. |
| **IPC-005** | Insecure IPC | `AF_UNIX` | `MEDIUM` | `MEDIUM` | `AF_UNIX` domain socket constant reference in native code. |
| **NUL-001** | Null Pointer Dereference | `malloc` | `MEDIUM` | `MEDIUM` | Dynamic memory allocation via `malloc` requiring immediate NULL check. |
| **NUL-002** | Null Pointer Dereference | `calloc` | `MEDIUM` | `MEDIUM` | Dynamic memory allocation via `calloc` requiring immediate NULL check. |
| **NUL-003** | Null Pointer Dereference | `realloc` | `MEDIUM` | `MEDIUM` | Dynamic memory allocation via `realloc` requiring immediate NULL check. |
| **RND-001** | Insecure Randomness | `\brand\s*\(` | `LOW` | `HIGH` | Non-cryptographic pseudo-random generator `rand()`. |
| **RND-002** | Insecure Randomness | `\bsrand\s*\(` | `LOW` | `HIGH` | Seeded PRNG initialization using `srand()`. |
| **RND-003** | Insecure Randomness | `srand\s*\(\s*time\s*\(` | `MEDIUM` | `HIGH` | Predictable time-based PRNG seeding via `srand(time(NULL))`. |
| **REF-001** | JNI Reflection Abuse | `FindClass` | `HIGH` | `MEDIUM` | Dynamic Java class lookup via `FindClass` in JNI. |
| **REF-002** | JNI Reflection Abuse | `GetMethodID` | `HIGH` | `MEDIUM` | Reflective method resolution via `GetMethodID` in JNI. |
| **REF-003** | JNI Reflection Abuse | `GetStaticMethodID` | `HIGH` | `MEDIUM` | Reflective static method resolution via `GetStaticMethodID` in JNI. |
| **REF-004** | JNI Reflection Abuse | `CallObjectMethod` | `HIGH` | `MEDIUM` | Reflective Java object method execution via `CallObjectMethod`. |
| **REF-005** | JNI Reflection Abuse | `CallVoidMethod` | `HIGH` | `MEDIUM` | Reflective Java void method execution via `CallVoidMethod`. |
| **FRD-001** | Anti-Root / Anti-Frida | `/system/bin/su` | `LOW` | `HIGH` | Root detection probing for `/system/bin/su` binary. |
| **FRD-002** | Anti-Root / Anti-Frida | `/system/xbin/su` | `LOW` | `HIGH` | Root detection probing for `/system/xbin/su` binary. |
| **FRD-003** | Anti-Root / Anti-Frida | `frida-server` | `LOW` | `HIGH` | Anti-analysis check searching for `frida-server` process. |
| **FRD-004** | Anti-Root / Anti-Frida | `27042` | `LOW` | `HIGH` | Anti-Frida check probing default Frida TCP port 27042. |
| **FRD-005** | Anti-Root / Anti-Frida | `/proc/net/tcp` | `LOW` | `MEDIUM` | Inspection of `/proc/net/tcp` to detect active instrumentation sockets. |
| **STR-001** | String Obfuscation | `http://` | `MEDIUM` | `HIGH` | Unencrypted HTTP URL endpoint exposed in plaintext string table. |
| **STR-002** | String Obfuscation | `api_key=` | `HIGH` | `HIGH` | Plaintext API key parameter exposed in native string table. |
| **STR-003** | String Obfuscation | `password=` | `HIGH` | `HIGH` | Plaintext password parameter exposed in binary string table. |
| **STR-004** | String Obfuscation | `bearer ` | `HIGH` | `HIGH` | Plaintext Bearer authentication token prefix exposed in strings. |
| **STR-005** | String Obfuscation | `[0-9a-fA-F]{32}` | `HIGH` | `HIGH` | High-entropy 32-character hexadecimal key or token string. |
| **STR-006** | String Obfuscation | `GLOBAL_SECRET_KEY` | `HIGH` | `HIGH` | Hardcoded secret key identifier exposed in native binary strings. |

---

## Detailed Component Specifications

### 1. Ingestion & Fallback Symbol Resolution (`ghidra_parser.py`)
- Reads raw ELF header bytes (`\x7fELF`) to verify machine architecture (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`).
- Inspects string sections for binary security mitigations (`__stack_chk_fail` for Stack Canary, `GNU_RELRO` for RELRO status).
- When Ghidra Headless is unavailable, the fallback parser extracts printable ASCII/UTF-8 strings and resolves exported JNI symbols (`Java_...`).
- Constructs synthetic decompiled function blocks representing extracted native routines, assigning 16-byte aligned virtual memory addresses starting at offset `0x2b00`.
- **JNI Alias Deduplication & Normalization**: Automatically detects and eliminates duplicate function entries where short demographic/mangled symbol names (e.g., `executeDiagnostic`) match the trailing identifier of fully qualified JNI exported symbols (`Java_com_example_app_NativeCoreEngine_executeDiagnostic`) at the same address or identical code lines. Prioritizes the fully qualified `Java_...` symbol as the canonical identifier (`is_exported_jni = True`) and removes redundant short aliases from `functions_code_scope`, `symbol_table`, and `parsed_binary`, ensuring each unique JNI implementation is analyzed exactly once without duplicate findings.

### 2. Rule Engine Configuration & Model Parsing (`config/rules.yaml`, `config_loader.py`, `rule.py`)
- **YAML Signature Schema**: Vulnerability detection rules in `config/rules.yaml` utilize a structured nested format:
  ```yaml
  rules:
    - id: BOF-001
      name: Buffer Overflow Vulnerability
      severity: CRITICAL
      confidence: HIGH
      category: Buffer Overflow
      description: Unsafe memory function call detected without explicit bounds checking.
      patterns:
        - id: BOF-001
          pattern: gets\s*\(
          severity: CRITICAL
          confidence: HIGH
          description: Usage of gets() which is inherently dangerous.
        - id: BOF-002
          pattern: strcpy\s*\(
          severity: CRITICAL
          confidence: HIGH
          description: Unbounded string copy using strcpy().
  ```
- **Data Models (`native_analysis/models/rule.py`)**:
  - `RulePattern`: Encapsulates pattern-level attributes (`id`, `pattern`, `severity`, `confidence`, `description`).
  - `Rule`: Top-level rule category wrapper holding a list of `RulePattern` instances (`patterns: List[RulePattern]`).
- **Loader Resolution (`ConfigLoader.load_rules`)**: Parses standard PyYAML input or fallback line-level YAML tokens into strongly-typed `Rule` and `RulePattern` objects. Missing fields automatically inherit defaults from parent category rules.

### 3. Context Window & Taint Flow Construction (`base_analyzer.py`)
- For every matched vulnerability pattern, `BaseAnalyzer._scan_function_with_patterns` iterates over `RulePattern` objects.
- Extracts sub-rule ID (`pat_obj.id`), specific pattern regex (`pat_obj.pattern`), specific severity (`pat_obj.severity`), and specific confidence (`pat_obj.confidence`).
- Generates a 20-line context window surrounding the trigger statement (`trigger_index - 10` to `trigger_index + 10`).
- Each code line is formatted with virtual memory offset annotations and explicit trigger labels:
  `/* 0x2b40 | line 34 */ statement; // [TRIGGER]`
- Extracts variable/buffer operands to populate the `target_variable` field.
- Constructs a structured `FlowAnalysis` payload describing the JNI parameter source and unsanitized function call sink.

### 4. Selective Finding Aggregation Engine
- **Selective Aggregation Logic**: Differentiates between static string/artifact findings and control-flow execution findings.
- **Rule Classification Matrix**:
  - **Aggregatable Rules**: Static binary data and string artifacts (`STR-*`, `FRD-*`, `DBG-*`, and static file paths under `IPC-004`).
  - **Non-Aggregatable Rules**: Control-flow, taint-analysis, and execution vulnerabilities (`JNI-*`, `BOF-*`, `INJ-*`, `REF-*`, `RND-*`, `CRY-*`, `PRM-*`, `INT-*`, `MEM-*`, `FMT-*`, `IPC-001`, `IPC-002`, `IPC-003`). Each occurrence remains a distinct standalone `Finding` object.
- **5-Tuple Composite Grouping Key**: Merges Aggregatable Rules into a single `Finding` object ONLY if all 5 criteria match: `rule_id`, `severity`, `confidence`, `location.function_name`, and `flow_analysis.source`.
- **Target & Finding Schema Fields**:
  - `cwe_id` (str): Common Weakness Enumeration ID (e.g., `CWE-120`).
  - `masvs_id` (str): OWASP MASVS Control ID (e.g., `MASVS-CODE-2`).
  - `functions_code_scope` (dict[str, list[str]]): Target-level map of function names to their decompiled code lines.
  - `flow_analysis` (dict): Taint flow tracking object containing `source`, `sink`, and `trigger_line_number`.
  - `total_matches` (int): Total count of matches aggregated into this finding (defaults to 1).
  - `matches` (list[dict]): Array of match occurrences containing `match_id` (e.g. `FIND-02-1`), `line_number`, `target_variable`, and `trigger_line`.

### 5. Shared Analysis Context Layer (`AnalysisContext` & `ContextBuilder`)
- **Centralized Pre-Extraction**: `ContextBuilder` initializes an `AnalysisContext` dataclass once during scanner initialization.
- **Pre-Extracted Artifacts**:
  - `binary_info`: Basic target file metadata (file name, relative path, ABI architecture, SHA-256 hash).
  - `hardening_flags`: ELF exploit mitigations (`stack_canary`, `nx_bit`, `pie_enabled`, `relro`).
  - `string_artifacts`: Static ASCII/UTF-8 string tables with length and Shannon entropy annotations.
  - `symbol_table`: Exported JNI functions, function names, and dynamic symbols.
  - `code_scope`: Decompiled C function line mappings.
  - `parsed_binary`: Single reference to the parsed binary AST.
- **O(1) Memory Lookup**: All downstream analyzers query `self.context` directly without re-reading or re-parsing the target binary.

---

## JSON Output Report Structure

The scanner outputs structured JSON results adhering to the following schema:

```json
{
  "summary": {
    "total_targets_scanned": 1,
    "total_findings": 15,
    "by_severity": {
      "CRITICAL": 3,
      "HIGH": 6,
      "MEDIUM": 4,
      "LOW": 2
    },
    "by_confidence": {
      "HIGH": 12,
      "MEDIUM": 3,
      "LOW": 0
    },
    "by_category": {
      "Buffer Overflow": 2,
      "Command Injection": 2,
      "Format String": 1
    }
  },
  "targets": [
    {
      "file_name": "libnative.so",
      "apk_relative_path": "standalone/libnative.so",
      "abi_architecture": "arm64-v8a",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "functions_code_scope": {
        "Java_com_example_app_NativeLib_processInput": [
          "/* Function: Java_com_example_app_NativeLib_processInput */",
          "JNIEXPORT jstring JNICALL",
          "Java_com_example_app_NativeLib_processInput(JNIEnv *env, jobject thiz, jstring j_str) {",
          "    char dest_buf[512];",
          "    const char* user_str = (*env)->GetStringUTFChars(env, j_str, 0);",
          "    strcpy(dest_buf, user_str);",
          "    return (*env)->NewStringUTF(env, \"OK\");",
          "}"
        ]
      },
      "target_summary": {
        "file_findings_count": 15
      },
      "findings": [
        {
          "finding_id": "FIND-01",
          "rule_id": "BOF-002",
          "cwe_id": "CWE-120",
          "masvs_id": "MASVS-CODE-2",
          "severity": "CRITICAL",
          "confidence": "HIGH",
          "location": {
            "function_name": "Java_com_example_app_NativeLib_processInput",
            "symbol_address": "0x00002b20",
            "line_number": 6,
            "is_exported_jni": true
          },
          "target_variable": "dest_buf",
          "trigger_line": "strcpy(dest_buf, user_str);",
          "flow_analysis": {
            "source": "JNI or internal parameter passed to function 'Java_com_example_app_NativeLib_processInput' at line 5",
            "sink": "Unsanitized call via pattern 'strcpy' at line 6",
            "trigger_line_number": 6
          }
        },
        {
          "finding_id": "FIND-02",
          "rule_id": "FRD-001",
          "cwe_id": "CWE-693",
          "masvs_id": "MASVS-RESILIENCE-2",
          "severity": "HIGH",
          "confidence": "HIGH",
          "location": {
            "function_name": "N/A (Static Data Section)",
            "symbol_address": "N/A",
            "line_number": 10,
            "is_exported_jni": false
          },
          "target_variable": "/system/bin/su",
          "trigger_line": "if (access(\"/system/bin/su\", F_OK) == 0)",
          "flow_analysis": {
            "source": "Hardcoded static binary string artifact",
            "sink": "Unsanitized reference via pattern '/system/bin/su' at line 10",
            "trigger_line_number": 10
          },
          "total_matches": 2,
          "matches": [
            {
              "match_id": "FIND-02-1",
              "line_number": 10,
              "target_variable": "/system/bin/su",
              "trigger_line": "if (access(\"/system/bin/su\", F_OK) == 0)"
            },
            {
              "match_id": "FIND-02-2",
              "line_number": 22,
              "target_variable": "/system/xbin/su",
              "trigger_line": "if (access(\"/system/xbin/su\", F_OK) == 0)"
            }
          ]
        }
      ]
    }
  ]
}
```
