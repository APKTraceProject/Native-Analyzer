# APKTrace - Native Analysis Engine

**APKTrace - Native Analysis Engine** is a high-performance static vulnerability analysis framework for Android dynamic native libraries (`.so` / ELF binaries) operating in **Single Mode** (`.so`) or **Multi Mode** (`.apk`). It performs automated disassembly, ARM64/ARMv7 pseudo-C AST reconstruction, symbol extraction, and multi-pattern AST taint flow analysis across 15 critical security categories.

### ✨ Key Features
- **Dual Operating Modes**:
  - **Single Mode (`.so`)**: Analyzes individual compiled shared object binaries directly.
  - **Multi Mode (`.apk`)**: Automatically extracts and scans embedded `.so` binaries from Android APK packages.
- **Dual Engine Architecture**:
  - **Fast Scan (`radare2`)**: High-speed binary disassembly, symbol extraction (`iEj`), string tables (`izzj`), and function listing (`aflj`) via `r2pipe` / radare2.
  - **Deep Scan (`ghidra`)**: In-depth headless decompilation via Ghidra 10.x+ (`analyzeHeadless`) producing full pseudo-C function bodies and memory-mapped address reconstruction.
  - **Zero-Dependency Fallback**: Automatic fallback parser for environments without external tools installed.
- **Primary ABI Resolution & Deduplication**: Intelligently groups duplicate binaries across architecture folders (`arm64-v8a`, `x86_64`, `armeabi-v7a`, `x86`) and selects a single primary ABI binary per library (fallback priority: `arm64-v8a` > `x86_64` > `armeabi-v7a` > `x86`), eliminating 75% of redundant analysis data and achieving a **75% LLM token optimization benefit** while recording complete resolution metadata (`primary_abi`, `associated_abis`, `deduplication_enabled`) in the global report summary.
- **Symbol & AST Reconstruction**: Ghidra Headless and modular Radare2 (`r2pipe`) integration paired with a zero-dependency cross-platform fallback decompiler.
- **JNI AST Taint Flow Analysis**: Traces unsanitized user inputs from JNI entrypoints (`GetStringUTFChars`, `GetByteArrayElements`) into high-risk memory, format string, and system execution sinks.
- **15 Category Vulnerability Matrix**: 66 specialized sub-rules detecting Buffer Overflows, Command Injections, JNI Leaks, Cryptography Flaws, Permission Flaws, and Anti-Analysis controls.
- **Modern CLI Terminal UI**: ASCII art banner, Execution Metadata display, real-time progress indicators, and Post-Scan Summary tables.

---

## 🏗️ Pipeline Architecture

```
                             [ Input Target File: .so or .apk ]
                                            │
                                            ▼
                           ┌──────────────────────────────────┐
                           │   CLI Interface Layer (cli.py)   │
                           │  - Config & Argument Reader      │
                           │  - Terminal Display & Output     │
                           └────────────────┬─────────────────┘
                                            │ Passes Config Variables
                                            ▼
                           ┌──────────────────────────────────┐
                           │   Core Engine (core/engine.py)   │
                           │  - Workflow Orchestrator         │
                           │  - Sub-Module Coordinator        │
                           └────────────────┬─────────────────┘
                                            │
                                            ▼
                           ┌──────────────────────────────────┐
                           │     Primary ABI Resolution       │
                           │   Deduplication (75% Token Opt)  │
                           └────────────────┬─────────────────┘
                                            │
                                            ▼
                           ┌──────────────────────────────────┐
                           │    Dual-Parser Engine Layer      │
                           │  (Radare2 Fast / Ghidra Deep)    │
                           └────────────────┬─────────────────┘
                                            │
                                            ▼
                           ┌──────────────────────────────────┐
                           │   Symbol & AST Reconstruction    │
                           │  (Mapped Addresses & JNI Alias)  │
                           └────────────────┬─────────────────┘
                                            │
                                            ▼
                           ┌──────────────────────────────────┐
                           │ 15 Category Analyzer Dispatcher  │
                           │  (Pattern & Taint Flow Tracking) │
                           └────────────────┬─────────────────┘
                                            │
                                            ▼
                           ┌──────────────────────────────────┐
                           │  Selective Finding Aggregation   │
                           └────────────────┬─────────────────┘
                                            │
                                            ▼
                           ┌──────────────────────────────────┐
                           │   4-Level JSON Report Output     │
                           │ Summary -> Target -> Func -> Find│
                           └────────────────┬─────────────────┘
                                            │ Returns Summary Payload
                                            ▼
                           ┌──────────────────────────────────┐
                           │   Terminal Summary Renderer      │
                           │ (Execution Metadata & Table)     │
                           └──────────────────────────────────┘
```

1. **Decoupled CLI & Orchestration Layer**:
   - **`cli.py` (Config Reader & Terminal Display Only)**: Parses configuration settings from `cli_config.yaml` or command line arguments (`-c`, `-t`, `-o`), passes configuration variables to `core/engine.py`, triggers pipeline execution, and formats the returned summary payload into clean terminal progress logs and results tables.
   - **`core/engine.py` (`ScanEngine`)**: Acts as the central workflow orchestrator, receiving configuration parameters, coordinating target extraction, ABI deduplication, decompiler execution, analyzer dispatch, and report generation via `JSONReporter`.
2. **Target Ingestion & Primary ABI Filtering**: Extracts native binaries from `.apk` or reads `.so` directly. Filters duplicate architecture variants by picking a single Primary ABI target (`arm64-v8a` > `x86_64` > `armeabi-v7a` > `x86`), reducing report size and LLM token overhead by up to 75%.
2. **Context & Metadata Extraction**: Computes SHA-256 digests, detects ELF exploit mitigations (Stack Canaries, NX Bit, PIE, RELRO), and extracts static strings with Shannon entropy metrics.
3. **Decompilation & Dual Parsing**:
   - **Fast Scan (`radare2`)**: Uses `Radare2Parser` (`r2pipe`) for rapid symbol extraction, string tables, and disassembly.
   - **Deep Scan (`ghidra`)**: Uses `GhidraParser` (`analyzeHeadless`) for full C pseudocode reconstruction and AST generation.
   - **Fallback**: Zero-dependency heuristic parser if external engines are not configured.
   Automatically normalizes JNI function aliases (matching short symbols to fully qualified JNI exports) to prevent duplicate scans.
4. **AST Pattern Matching & Flow Context**: Runs 15 specialized static analyzers across decompiled code blocks using 66 fine-grained sub-rule IDs (e.g., `BOF-001` for `gets()`, `INJ-001` for `system()`).
5. **Selective Finding Aggregation**: Aggregates static data & string findings (`STR-*`, `FRD-*`, `DBG-*`, `IPC-004`) sharing identical 5-tuple keys into composite findings with `matches` and `total_matches` counts.
6. **Unified 4-Level Report Serialization**: Generates standardized JSON report payloads structured across 4 distinct levels: Global Summary -> Target Objects -> Function Objects -> Granular Findings.

---

## 🔍 Supported Vulnerability Categories (15 Categories / 66 Sub-Rules)

The engine implements fine-grained pattern matching across 15 vulnerability categories comprising 66 distinct sub-rule signatures. Each sub-rule pattern independently defines its specific severity, confidence rating, and trigger description.

| Sub-Rule IDs | Category Name | Severity Range | Confidence Range | Detection Strategy & Targeted Patterns |
| :--- | :--- | :---: | :---: | :--- |
| **BOF-001 – BOF-005** | Buffer Overflow | `MEDIUM` – `CRITICAL` | `MEDIUM` – `HIGH` | Unbounded memory/string operations: `gets` (`BOF-001`), `strcpy` (`BOF-002`), `strcat` (`BOF-003`), `sprintf` (`BOF-004`), `memcpy` (`BOF-005`). |
| **INJ-001 – INJ-004** | Command Injection | `HIGH` – `CRITICAL` | `HIGH` | Process spawners receiving unsanitized input: `system` (`INJ-001`), `popen` (`INJ-002`), `execve` (`INJ-003`), `execl` (`INJ-004`). |
| **FMT-001 – FMT-006** | Format String | `MEDIUM` – `HIGH` | `HIGH` | Non-literal format string sinks: `printf` (`FMT-001`), `sprintf` (`FMT-002`), `vprintf` (`FMT-003`), `vfprintf` (`FMT-004`), `syslog` (`FMT-005`), `__android_log_print` (`FMT-006`). |
| **CRY-001 – CRY-007** | Weak Cryptography | `LOW` – `HIGH` | `LOW` – `HIGH` | Weak hashes/ciphers/loops: `MD5` (`CRY-001`), `SHA1` (`CRY-002`), `DES` (`CRY-003`), `AES-CBC` (`CRY-004`), `RC4` (`CRY-005`), `^=` XOR (`CRY-006`), `XOR` string (`CRY-007`). |
| **DBG-001 – DBG-004** | Anti-Debugging | `LOW` – `MEDIUM` | `MEDIUM` – `HIGH` | Anti-analysis checks: `ptrace(PTRACE_TRACEME)` (`DBG-001`), `ptrace` (`DBG-002`), `/proc/self/status` (`DBG-003`), `TracerPid` (`DBG-004`). |
| **MEM-001 – MEM-002** | Memory Management | `MEDIUM` – `HIGH` | `MEDIUM` | Memory deallocation/reallocation flaws: `free()` (`MEM-001`), `realloc()` (`MEM-002`). |
| **JNI-001 – JNI-004** | JNI Boundary Leaks | `LOW` – `HIGH` | `HIGH` | JNI boundary lifecycle: `GetStringUTFChars` (`JNI-001`), `GetByteArrayElements` (`JNI-002`), `ReleaseStringUTFChars` (`JNI-003`), `ReleaseByteArrayElements` (`JNI-004`). |
| **PRM-001 – PRM-007** | File Permission Flaws | `MEDIUM` – `HIGH` | `HIGH` | Overly permissive file/directory flags: `chmod 0777` (`PRM-001`), `chmod 0666` (`PRM-002`), `mkdir 0777` (`PRM-003`), `mkdir 0666` (`PRM-004`), `open 0666` (`PRM-005`), `open 0777` (`PRM-006`), `umask(0)` (`PRM-007`). |
| **INT-001 – INT-003** | Integer Overflow | `HIGH` | `MEDIUM` | Arithmetic calculations inside allocation parameters: `malloc()` (`INT-001`), `calloc()` (`INT-002`), `realloc()` (`INT-003`). |
| **IPC-001 – IPC-005** | Insecure IPC | `MEDIUM` – `HIGH` | `LOW` – `HIGH` | Unauthenticated local IPC endpoints: `socket(AF_UNIX)` (`IPC-001`), `bind` (`IPC-002`), `connect` (`IPC-003`), `/tmp/` paths (`IPC-004`), `AF_UNIX` (`IPC-005`). |
| **NUL-001 – NUL-003** | Null Pointer Dereference | `MEDIUM` | `MEDIUM` | Dynamic allocation return values without null checks: `malloc` (`NUL-001`), `calloc` (`NUL-002`), `realloc` (`NUL-003`). |
| **RND-001 – RND-003** | Insecure Randomness | `LOW` – `MEDIUM` | `HIGH` | Non-cryptographic PRNG usage: `rand()` (`RND-001`), `srand()` (`RND-002`), `srand(time(NULL))` (`RND-003`). |
| **REF-001 – REF-005** | JNI Reflection Abuse | `HIGH` | `MEDIUM` | Reflective Java calls from C: `FindClass` (`REF-001`), `GetMethodID` (`REF-002`), `GetStaticMethodID` (`REF-003`), `CallObjectMethod` (`REF-004`), `CallVoidMethod` (`REF-005`). |
| **FRD-001 – FRD-005** | Anti-Root / Anti-Frida | `LOW` | `MEDIUM` – `HIGH` | Environmental probes: `/system/bin/su` (`FRD-001`), `/system/xbin/su` (`FRD-002`), `frida-server` (`FRD-003`), port `27042` (`FRD-004`), `/proc/net/tcp` (`FRD-005`). |
| **STR-001 – STR-006** | String Obfuscation | `MEDIUM` – `HIGH` | `HIGH` | Exposed plaintext strings & secrets: `http://` (`STR-001`), `api_key=` (`STR-002`), `password=` (`STR-003`), `bearer ` (`STR-004`), hex tokens (`STR-005`), `GLOBAL_SECRET_KEY` (`STR-006`). |

---

## 💻 Installation & Setup

### Prerequisites
- **Python**: Python 3.8 or higher.
- **Dependencies**: `PyYAML` (optional; zero-dependency fallback YAML parser included), `r2pipe` (Python interface for radare2 engine).
- **Analysis Engines / Decompilers (Optional)**:
  - **Radare2 Engine**: `radare2` binary and `r2pipe` library for high-speed disassembly and symbol extraction.
  - **Ghidra Engine**: Ghidra 10.x+ `analyzeHeadless` executable for deep pseudo-C decompilation.

### Installation
```bash
# Clone repository
git clone https://github.com/apktrace/native-analysis.git
cd native-analysis

# Install dependencies (including optional YAML and radare2 bindings)
pip install pyyaml r2pipe
```

---

## 🛠️ Usage Modes

### 1. Configuration Setup
Copy the example CLI configuration template to create your local config file:

```bash
cp config/cli_config.example.yaml config/cli_config.yaml
```

Edit `config/cli_config.yaml` to configure target path, output path, selected engine, and optional decompiler executable path:

```yaml
target_path: "./tests/app.apk"
output_json_path: "./output/report.json"
output_engine_path: "./output/engine_artifacts" # Directory path for raw engine (Ghidra/Radare2) project database, logs, and outputs
engine: "ghidra" # Analysis engine choice: "ghidra" or "radare2"
decompiler_path: "C:\\Ghidra\\support\\analyzeHeadless.bat" # Path to Ghidra analyzeHeadless executable or radare2 binary
```

#### Configuration Parameters
- **`target_path`**: Accepts either a single dynamic native library path (`.so` for Single Mode) or a full Android application package (`.apk` for Multi Mode).
- **`output_json_path`**: File path destination where the final 4-level structured JSON report will be exported.
- **`output_engine_path`**: Directory path where raw output files, artifacts, execution logs, and project databases generated directly by whichever engine is active (Ghidra or Radare2) will be stored and preserved.
- **`engine`**: Decompiler engine backend (`"ghidra"` or `"radare2"`, defaults to `"ghidra"`).
- **`decompiler_path`**: Optional path to Ghidra's `analyzeHeadless` script or `radare2` binary. If set to `null` or omitted, the scanner automatically falls back to its zero-dependency cross-platform heuristic parser.

---

### 2. Command-Line Interface (`cli.py`)
Run automated security analysis directly from the command line:

```bash
# Fast Scan (Radare2 Engine): Fast disassembly & symbol extraction with persistent raw engine artifacts
python cli.py -t ./tests/app.apk -o ./output/report.json -e ./output/engine_artifacts -c config/cli_config.yaml

# Deep Scan (Ghidra Engine): In-depth pseudo-C AST decompilation with persistent raw engine artifacts
python cli.py -t ./tests/app.apk -o ./output/report.json -e ./output/engine_artifacts

# Standalone Single Mode: Run analysis directly on a single .so dynamic library
python cli.py -t ./tests/libnative.so -o ./output/report.json

# Custom Config: Run scan using a custom YAML configuration file
python cli.py -c config/custom_config.yaml
```

#### Terminal Output & UI Features
The CLI provides a modernized visual interface featuring an ASCII art banner, execution metadata table, step progress indicators, and post-scan statistical summary table:

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

  Total Target Files Scanned : 1
  Discovered ABIs            : arm64-v8a, x86_64, armeabi-v7a, x86
  Primary Target ABI         : [arm64-v8a]
  Total Vulnerabilities Found: 14

======================================================================
```

---

### 3. Python API & SDK Integration
Integrate the native analysis engine directly into custom Python tools, CI/CD pipelines, or orchestrators:

```python
import native_analysis as apk_trace
from native_analysis import ScanEngine
from native_analysis.reporters.json_reporter import JSONReporter

# ---------------------------------------------------------
# Approach A: Top-Level Convenience API
# ---------------------------------------------------------

# Single Mode: Scan a standalone .so dynamic library
parsed_binary, findings = apk_trace.scan_single("path/to/libnative.so")

# Multi Mode: Extract and scan all .so libraries inside an .apk archive
scanned_targets = apk_trace.scan_multi("path/to/app.apk")

# Auto-Detect Mode: Automatically checks file extension (.so or .apk)
scanned_targets = apk_trace.scan("path/to/target_file")


# ---------------------------------------------------------
# Approach B: Object-Oriented ScanEngine API
# ---------------------------------------------------------

# Fast Scan (Radare2)
engine_r2 = ScanEngine(
    rules_path="config/rules.yaml",
    engine="radare2",
    decompiler_path="/usr/bin/radare2"
)
scanned_targets_r2 = engine_r2.scan("path/to/app.apk")

# Deep Scan (Ghidra)
engine_ghidra = ScanEngine(
    rules_path="config/rules.yaml",
    engine="ghidra",
    decompiler_path="/opt/ghidra/support/analyzeHeadless"
)
scanned_targets = engine_ghidra.scan("path/to/app.apk")

# Headless Workflow Execution API (engine.execute)
result = engine_ghidra.execute(
    target_path="path/to/app.apk",
    output_path="./output/report.json",
    config_file_used="config/cli_config.yaml"
)

# Returned Payload Structure
{
    "success": True,
    "metadata": {
        "config_file": "config/cli_config.yaml",
        "config_content": {
            "target_path": "path/to/app.apk",
            "output_json_path": "./output/report.json",
            "engine": "ghidra",
            "decompiler_path": "/opt/ghidra/support/analyzeHeadless"
        },
        "execution": {
            "timestamp": "2026-08-10T11:26:00Z",
            "duration_seconds": 4.12,
            "active_analyzers": ["buffer_overflow", "weak_crypto", "..."]
        }
    },
    "summary": {
        "discovered_abis": ["arm64-v8a", "armeabi-v7a", "x86_64"],
        "primary_abi": "arm64-v8a",
        "scanned_files_count": 5,
        "total_vulnerabilities": 12,
        "by_category": {
            "Buffer Overflow": 4,
            "Weak Cryptography": 5
        },
        "by_severity": {
            "critical": 2,
            "high": 4,
            "medium": 5,
            "low": 1
        }
    }
}

# Export structured JSON report artifact with specified engine metadata
report_dict = JSONReporter.generate_report(
    scanned_targets=scanned_targets,
    output_file_path="./output/report.json",
    analysis_engine="ghidra"
)
```

---

## 📄 JSON Report Schema Overview

The engine produces a standardized 4-Level JSON report containing global execution summary, target file descriptors, function nodes, and granular findings:

```json
{
  "summary": {
    "analysis_engine": "ghidra",
    "total_targets_scanned": 1,
    "total_findings": 15,
    "by_severity": { "CRITICAL": 2, "HIGH": 5, "MEDIUM": 5, "LOW": 3 },
    "by_confidence": { "HIGH": 13, "MEDIUM": 2, "LOW": 0 },
    "by_category": { "Buffer Overflow": 1, "Command Injection": 1 },
    "abi_resolution": {
      "primary_abi": "arm64-v8a",
      "associated_abis": ["x86_64", "armeabi-v7a", "x86"],
      "deduplication_enabled": true
    }
  },
  "targets": [
    {
      "file_name": "libnative.so",
      "apk_relative_path": "lib/arm64-v8a/libnative.so",
      "abi_architecture": "arm64-v8a",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "target_summary": {
        "file_findings_count": 15,
        "by_severity": { "CRITICAL": 2, "HIGH": 5, "MEDIUM": 5, "LOW": 3 },
        "by_confidence": { "HIGH": 13, "MEDIUM": 2, "LOW": 0 },
        "by_category": { "Buffer Overflow": 1, "Command Injection": 1 },
        "attack_surface_metrics": {
          "total_functions_scanned": 16,
          "exported_jni_functions": 15,
          "vulnerable_jni_functions": 15
        }
      },
      "functions": [
        {
          "function_name": "Java_com_example_app_NativeLib_executeCmd",
          "symbol_address": "0x00002b40",
          "is_exported_jni": true,
          "source_code": [
            "1: /* Function: Java_com_example_app_NativeLib_executeCmd */",
            "2: JNIEXPORT jstring JNICALL",
            "3: Java_com_example_app_NativeLib_executeCmd(JNIEnv *env, jobject thiz, jstring j_cmd) {",
            "4:     char command_buf[512];",
            "5:     const char* user_input = (*env)->GetStringUTFChars(env, j_cmd, 0);",
            "6:     sprintf(command_buf, \"/system/bin/ping -c 1 %s\", user_input);",
            "7:     system(command_buf);",
            "8:     (*env)->ReleaseStringUTFChars(env, j_cmd, user_input);",
            "9:     return (*env)->NewStringUTF(env, \"OK\");",
            "10: }"
          ],
          "findings": [
            {
              "finding_id": "FIND-01",
              "rule_id": "INJ-001",
              "cwe_id": "CWE-78",
              "masvs_id": "MASVS-CODE-2",
              "severity": "CRITICAL",
              "confidence": "HIGH",
              "line_number": 7,
              "target_variable": "command_buf",
              "trigger_line": "system(command_buf);",
              "flow_analysis": {
                "trigger_line_number": 7,
                "flow_trace": "j_cmd (L3) -> user_input (L5) -> command_buf (L6) -> system (L7) [SINK]"
              }
            }
          ]
        },
        {
          "function_name": "N/A (Static Data Section)",
          "symbol_address": "N/A",
          "is_exported_jni": false,
          "source_code": [],
          "findings": [
            {
              "finding_id": "FIND-02",
              "rule_id": "FRD-001",
              "cwe_id": "CWE-693",
              "masvs_id": "MASVS-RESILIENCE-2",
              "severity": "HIGH",
              "confidence": "HIGH",
              "line_number": 10,
              "target_variable": "/system/bin/su",
              "trigger_line": "/* String artifact */ \"/system/bin/su\";",
              "flow_analysis": {
                "trigger_line_number": 10,
                "flow_trace": "Static String Data (L10) -> /system/bin/su [SINK]"
              },
              "total_matches": 2,
              "matches": [
                {
                  "match_id": "FIND-02-1",
                  "line_number": 10,
                  "target_variable": "/system/bin/su",
                  "trigger_line": "/* String artifact */ \"/system/bin/su\";"
                },
                {
                  "match_id": "FIND-02-2",
                  "line_number": 22,
                  "target_variable": "/system/xbin/su",
                  "trigger_line": "/* String artifact */ \"/system/xbin/su\";"
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

---

## 📚 Technical Documentation

For deeper details regarding module architecture, data flows, symbol resolution strategies, and decompiler fallback algorithms, consult [docs/NATIVE_ANALYSIS_ARCHITECTURE.md](docs/NATIVE_ANALYSIS_ARCHITECTURE.md).
