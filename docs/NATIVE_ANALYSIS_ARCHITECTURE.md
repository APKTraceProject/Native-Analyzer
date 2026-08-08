# APKTrace - Native Analysis Module Architecture

## Overview

The **APKTrace - Native Analysis Module** is a high-performance static vulnerability analysis engine designed to detect security defects, memory safety flaws, insecure API usage, and embedded anti-analysis controls inside compiled Android dynamic native libraries (`.so` files across ARM64, ARMv7, x86, and x86_64 architectures) as well as full Android application packages (`.apk`).

Operating as a specialized native binary analysis sub-component of the broader APKTrace security ecosystem, the module supports two primary execution modes:
- **Single Mode (`.so`)**: Analyzes standalone compiled ELF shared object binaries directly.
- **Multi Mode (`.apk`)**: Automatically unpacks Android APK packages, locates all embedded native dynamic libraries (`lib/<abi>/*.so`), extracts them to an isolated workspace, and executes batch security analysis across all targets.

---

## Technical Pipeline Architecture

```
                             [ Input Target File: .so or .apk ]
                                            │
                                            ▼
                           ┌─────────────────────────────────┐
                           │     Target Resolution Layer     │
                           │        (TargetResolver)         │
                           └────────────────┬────────────────┘
                                            │
                    ┌───────────────────────┴───────────────────────┐
                    │ Single Mode (.so)                     │ Multi Mode (.apk)
                    ▼                                       ▼
     ┌─────────────────────────────┐         ┌─────────────────────────────┐
     │  Direct Target File Path    │         │  Extract .so Targets from   │
     │  (standalone .so binary)    │         │  lib/<abi>/ into Temp Dir   │
     └──────────────┬──────────────┘         └──────────────┬──────────────┘
                    │                                       │
                    └───────────────────────┬───────────────┘
                                            │
                                            ▼
                         ┌────────────────────────────────────┐
                         │  AnalysisContext / ContextBuilder  │
                         │ - Compute SHA-256 Digest           │
                         │ - Detect ABI Architecture          │
                         │ - Extract Mitigations (Canary, NX) │
                         │ - Pre-extract Strings & Entropy    │
                         └──────────────────┬─────────────────┘
                                            │
                                            ▼
                         ┌────────────────────────────────────┐
                         │    Decompilation & Parser Layer    │
                         │   (Ghidra Headless / Heuristic)    │
                         │ - Pseudo-C AST Reconstruction      │
                         │ - Symbol Table & Scope Mapping     │
                         │ - JNI Symbol Normalization         │
                         └──────────────────┬─────────────────┘
                                            │
                                            ▼
                         ┌────────────────────────────────────┐
                         │         Core ScanEngine            │
                         │ Iterates 15 Class Analyzers        │
                         └──────────────────┬─────────────────┘
                                            │
                                            ▼
                         ┌────────────────────────────────────┐
                         │    15 Vulnerability Analyzers      │
                         │ - Pattern Matching (66 Sub-Rules)  │
                         │ - Context Window (20-Line AST)     │
                         │ - AST Taint Flow Analysis          │
                         │ - Selective Finding Aggregation    │
                         └──────────────────┬─────────────────┘
                                            │
                                            ▼
                         ┌────────────────────────────────────┐
                         │    4-Level JSON Report Generator   │
                         │   Summary -> Targets -> Functions  │
                         └──────────────────┬─────────────────┘
                                            │
                                            ▼
                         ┌────────────────────────────────────┐
                         │       CLI Terminal UI Renderer     │
                         │ - Banner & Execution Metadata      │
                         │ - Progress Indicators              │
                         │ - Post-Scan Summary Tables         │
                         └────────────────────────────────────┘
```

---

## Technical Pipeline Stages

### Stage 1: Input Target Resolution (`TargetResolver` / `ScanEngine.resolve_target`)
- **Mode Auto-Detection**: Inspects the target file extension provided via configuration (`target_path`) or CLI argument (`-t / --target`).
  - `.so` -> Executes **Single Mode**.
  - `.apk` -> Executes **Multi Mode**.
- **Primary ABI Resolution & Deduplication**: Scanning identical `.so` binaries compiled for multiple ABI architectures inside an APK (e.g. `arm64-v8a`, `x86_64`, `armeabi-v7a`, `x86`) creates redundant analysis data and bloats report sizes. The target resolution layer groups discovered `.so` files by relative library filename (e.g., `libnative.so`) and selects exactly ONE primary ABI target for scanning based on the fallback priority order:
  1. `arm64-v8a` (Primary preference)
  2. `x86_64`
  3. `armeabi-v7a`
  4. `x86`
- **Audit Trail Metadata**: Bypassed duplicate ABIs are preserved in the target metadata (`primary_abi` and `associated_abis`), maintaining a complete audit trail without redundant scanning.
- **Archive Unpacking**: Unpacks selected primary ABI binaries into an isolated temporary workspace.
- **Cleanup**: Temporarily extracted files are automatically tracked and removed upon completion of the analysis run.

### Stage 2: Shared Analysis Context Layer (`ContextBuilder` & `AnalysisContext`)
- **Centralized Pre-Extraction**: `ContextBuilder` initializes an immutable `AnalysisContext` data object prior to running analyzer passes.
- **Pre-Calculated Attributes**:
  - `binary_info`: Basic target file metadata (file name, relative path, ABI architecture, SHA-256 digest).
  - `hardening_flags`: ELF exploit mitigations (`stack_canary`, `nx_bit`, `pie_enabled`, `relro`).
  - `string_artifacts`: Static ASCII/UTF-8 string tables annotated with string length and Shannon entropy metrics.
  - `symbol_table`: Exported JNI functions, function names, and dynamic symbols.
  - `code_scope`: Decompiled C function line mappings.
  - `parsed_binary`: Single reference to the parsed binary AST object.
- **Zero Overhead Querying**: All downstream analyzers query `self.context` directly, eliminating redundant file reads and re-parsing passes.

### Stage 3: Decompilation & Symbol Resolution (`GhidraParser` & Fallback Engine)
- **Primary Decompiler (Ghidra Headless)**: When Ghidra's `analyzeHeadless` executable is configured, the module invokes Ghidra via Jython scripts to produce decompiled C function blocks and mapped memory addresses starting at virtual offset `0x2b00`.
- **Zero-Dependency Fallback Engine**: If Ghidra is not available, the engine employs a cross-platform heuristic parser that extracts string tables, exported symbols, and reconstructs pseudo-C AST function bodies directly.
- **JNI Alias Deduplication & Normalization**: Automatically detects and eliminates duplicate function entries where short demographic/mangled symbol names (e.g., `executeDiagnostic`) match the trailing identifier of fully qualified JNI exported symbols (`Java_com_example_app_NativeCoreEngine_executeDiagnostic`) at the same address or identical code lines. Prioritizes the fully qualified `Java_...` symbol as the canonical identifier (`is_exported_jni = True`) and removes redundant short aliases from `functions_code_scope`, `symbol_table`, and `parsed_binary`, ensuring each unique JNI implementation is analyzed exactly once without duplicate findings.

### Stage 4: AST Pattern Matching & Taint Flow Tracking (`BaseAnalyzer` + 15 Analyzers)
- **Signature Dispatch**: The scanner dispatches function scopes across 15 category analyzers executing 66 pattern signatures defined in `config/rules.yaml`.
- **20-Line Memory Context Window**: For every matched vulnerability pattern, `BaseAnalyzer._scan_function_with_patterns` extracts a 20-line code window (`trigger_index - 10` to `trigger_index + 10`).
- **Memory Offset Annotations**: Annotates code lines with virtual memory offset tags:
  `/* 0x2b40 | line 34 */ statement; // [TRIGGER]`
- **JNI AST Taint Tracking**: Traces user-controlled inputs originating from JNI parameters (`jstring`, `jbyteArray`, `GetStringUTFChars`, `GetByteArrayElements`) into unsafe sink functions (`system`, `sprintf`, `strcpy`, `execve`, etc.).

### Stage 5: Selective Finding Aggregation Engine
- **Classification Strategy**: Distinguishes between static data/string artifacts and execution control-flow vulnerabilities.
  - **Aggregatable Rules**: Static binary data section artifacts (`STR-*`, `FRD-*`, `DBG-*`, and static paths in `IPC-004`).
  - **Non-Aggregatable Rules**: Control-flow, memory safety, and taint-analysis vulnerabilities (`JNI-*`, `BOF-*`, `INJ-*`, `REF-*`, `RND-*`, `CRY-*`, `PRM-*`, `INT-*`, `MEM-*`, `FMT-*`, `IPC-001–IPC-003`). Each occurrence remains a standalone finding.
- **5-Tuple Composite Grouping Key**: Combines aggregatable findings into a single `Finding` object ONLY if all 5 fields match identically: `rule_id`, `severity`, `confidence`, `location.function_name`, and `flow_analysis.source`. Grouped findings contain `total_matches` counts and detailed `matches` arrays.

### Stage 6: 4-Level JSON Serialization (`JSONReporter`)
Outputs structured JSON report payloads adhering to a 4-level hierarchy:
- **Level 1**: Global Scan Summary (`summary`)
- **Level 2**: Target Binary Scope (`targets[]`)
- **Level 3**: Function Objects (`functions[]`)
- **Level 4**: Granular Findings (`functions[].findings[]`)

### Stage 7: CLI Terminal UI Rendering (`cli.py`)
Provides a terminal output displaying:
1. ANSI Colorized ASCII Banner with submodule identity note.
2. **Execution Metadata Table**: Execution Mode (`SINGLE (.so)` or `MULTI (.apk)`), Target File Path, Output Report Path, and Identified Binary Count.
3. **Progress Indicators**: Step-by-step terminal logs (`[+]`, `[*]`, `[✔]`).
4. **Post-Scan Summary Table**: Total targets scanned, total findings, severity breakdown (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), and top detected categories.

---

## Configuration & Setup Architecture

### Configuration Files
- **Template Config**: `config/cli_config.example.yaml`
- **Active Config**: `config/cli_config.yaml`

Setup step:
```bash
cp config/cli_config.example.yaml config/cli_config.yaml
```

### Configuration Parameters
```yaml
target_path: "./tests/app.apk"           # Accepts .so (Single Mode) or .apk (Multi Mode)
output_json_path: "./output/report.json" # Output report path
ghidra_headless_path: null               # Optional Ghidra analyzeHeadless path
```

- `target_path` (*string*, required): Path to the target binary (`.so`) or application archive (`.apk`).
- `output_json_path` (*string*, required): Destination path for the generated JSON report.
- `ghidra_headless_path` (*string*, optional): Path to Ghidra's `analyzeHeadless` script. If `null` or omitted, the scanner uses its zero-dependency fallback parser.

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

## 4-Level JSON Report Structure

```json
{
  "summary": {
    "total_targets_scanned": 1,
    "total_findings": 15,
    "by_severity": { "CRITICAL": 3, "HIGH": 6, "MEDIUM": 4, "LOW": 2 },
    "by_confidence": { "HIGH": 12, "MEDIUM": 3, "LOW": 0 },
    "by_category": { "Buffer Overflow": 2, "Command Injection": 2 }
  },
  "targets": [
    {
      "file_name": "libnative.so",
      "apk_relative_path": "lib/arm64-v8a/libnative.so",
      "abi_architecture": "arm64-v8a",
      "primary_abi": "arm64-v8a",
      "associated_abis": ["x86_64", "armeabi-v7a", "x86"],
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "target_summary": {
        "file_findings_count": 15,
        "by_severity": { "CRITICAL": 3, "HIGH": 6, "MEDIUM": 4, "LOW": 2 },
        "by_confidence": { "HIGH": 12, "MEDIUM": 3, "LOW": 0 },
        "by_category": { "Buffer Overflow": 2, "Command Injection": 2 },
        "attack_surface_metrics": {
          "total_functions_scanned": 8,
          "exported_jni_functions": 2,
          "vulnerable_jni_functions": 2
        }
      },
      "functions": [
        {
          "function_name": "Java_com_example_app_NativeLib_processInput",
          "symbol_address": "0x00002b20",
          "is_exported_jni": true,
          "source_code": [
            "1: /* Function: Java_com_example_app_NativeLib_processInput */",
            "2: JNIEXPORT jstring JNICALL",
            "3: Java_com_example_app_NativeLib_processInput(JNIEnv *env, jobject thiz, jstring j_str) {",
            "4:     char dest_buf[512];",
            "5:     const char* user_str = (*env)->GetStringUTFChars(env, j_str, 0);",
            "6:     strcpy(dest_buf, user_str);",
            "7:     return (*env)->NewStringUTF(env, \"OK\");",
            "8: }"
          ],
          "findings": [
            {
              "finding_id": "FIND-01",
              "rule_id": "BOF-002",
              "cwe_id": "CWE-120",
              "masvs_id": "MASVS-CODE-2",
              "severity": "CRITICAL",
              "confidence": "HIGH",
              "line_number": 6,
              "target_variable": "dest_buf",
              "trigger_line": "strcpy(dest_buf, user_str);",
              "flow_analysis": {
                "trigger_line_number": 6,
                "flow_trace": "user_str (L3) -> dest_buf (L6) [SINK]"
              }
            }
          ]
        }
      ]
    }
  ]
}
```

---

## CLI Execution & Terminal Interface

### Running the Scanner
```bash
# Execute using configuration settings in config/cli_config.yaml
python cli.py

# Specify explicit target and output paths
python cli.py -t ./tests/app.apk -o ./output/report.json

# Use custom YAML configuration file
python cli.py -c config/custom_config.yaml
```

### Terminal UI Example Output
```
    _   ___ _  _______                    
   /_\ | _ \ |/ /_   _| __ __ _ ___ ___   
  / _ \|  _/ ' <  | | | '__/ _` / _| _/   
 /_/ \_\_| |_|\_\ |_| |_|  \__,_\__|___|  

  APKTrace - Native Analysis Module
  Specialized native binary analysis sub-component of the APKTrace ecosystem
======================================================================
 [+] [INFO] Loading configuration & rules...
 [+] [INFO] Config loaded successfully from 'config/cli_config.example.yaml'.

----------------------------------------------------------------------
 EXECUTION METADATA
----------------------------------------------------------------------
  * Mode:                    MULTI (.apk)
  * Target File:             ./tests/app.apk
  * Output Path:             ./output/report.json
  * Identified Binaries:     2 target(s)
----------------------------------------------------------------------

 [*] [SCAN] Extracting native targets from APK archive 'app.apk'...
 [*] [SCAN] Decompiling & analyzing symbols via Ghidra...
 [*] [TAINT] Running variable flow analysis & JNI context extraction...
 [✔] [SUCCESS] Report generated successfully at ./output/report.json

======================================================================
                      SCAN SUMMARY RESULTS                            
======================================================================
  Total Target Files Scanned : 2
  Total Vulnerabilities Found: 8
----------------------------------------------------------------------
  SEVERITY BREAKDOWN
----------------------------------------------------------------------
   CRITICAL :  2
   HIGH     :  4
   MEDIUM   :  0
   LOW      :  2
----------------------------------------------------------------------
  TOP CATEGORIES DETECTED
----------------------------------------------------------------------
   JNI Boundary Leak                  : 4
   Buffer Overflow                    : 2
   Command Injection                  : 2
======================================================================
```

---

## Python SDK Integration

```python
import native_analysis as apk_trace
from native_analysis import ScanEngine
from native_analysis.reporters.json_reporter import JSONReporter

# Convenience Functions
parsed_binary, findings = apk_trace.scan_single("path/to/libnative.so") # Single Mode (.so)
scanned_targets = apk_trace.scan_multi("path/to/app.apk")                # Multi Mode (.apk)
scanned_targets = apk_trace.scan("path/to/target_file")                 # Auto-detect Mode (.so or .apk)

# Object-Oriented Engine Instance
engine = ScanEngine(rules_path="config/rules.yaml")
scanned_targets = engine.scan("path/to/target_file")

# Generate JSON Report File
report_data = JSONReporter.generate_report(
    scanned_targets=scanned_targets,
    output_file_path="./output/report.json"
)
```
