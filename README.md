# APKTrace - Native Analysis Engine

**APKTrace - Native Analysis Engine** is a high-performance static vulnerability analysis framework for Android dynamic native libraries (`.so` / ELF binaries). It performs automated disassembly, ARM64/ARMv7 pseudo-C AST reconstruction, symbol extraction, and multi-pattern AST taint flow analysis across 15 critical security categories.

---

## 🏗️ Pipeline Architecture

```
                                 [ ELF / Android .so Target ]
                                              │
                                              ▼
                             ┌─────────────────────────────────┐
                             │    Decompilation / Disassembly  │
                             │ (Ghidra Headless / Heuristic)   │
                             └─────────────────────────────────┘
                                              │
                                              ▼
                             ┌─────────────────────────────────┐
                             │   Symbol & AST Reconstruction   │
                             │ (Mapped Addresses 0x2b00 + N)   │
                             └─────────────────────────────────┘
                                              │
                                              ▼
                             ┌─────────────────────────────────┐
                             │ 15 Category Analyzer Dispatcher │
                             │  (Pattern & Context Extraction) │
                             └─────────────────────────────────┘
                                              │
                                              ▼
                             ┌─────────────────────────────────┐
                             │  Deduplication & Scope Filter   │
                             └─────────────────────────────────┘
                                              │
                                              ▼
                             ┌─────────────────────────────────┐
                             │    3-Tier JSON Report Output    │
                             └─────────────────────────────────┘
```

1. **Ingestion & Metadata Extraction**: Reads raw binary headers, computes SHA-256 digests, and detects binary exploit mitigations (Stack Canaries, NX Bit, PIE, RELRO).
2. **Decompilation Pipeline**: Invokes Ghidra Headless decompilation or executes the zero-dependency fallback heuristic parser to reconstruct C function bodies and `.rodata` string tables.
3. **AST Pattern Matching & Flow Context**: Runs 15 specialized static analyzers across decompiled code blocks using fine-grained, pattern-specific sub-rule IDs (e.g., `BOF-001` for `gets()`, `BOF-002` for `strcpy()`, `BOF-004` for `sprintf()`).
4. **Selective Finding Aggregation**: Aggregates static binary data & string artifact findings (`STR-*`, `FRD-*`, `DBG-*`, `IPC-004`) sharing identical 5-tuple keys (`rule_id`, `severity`, `confidence`, `location.function_name`, `flow_analysis.source`) into composite findings with `matches` and `total_matches` counts, while keeping execution-path vulnerabilities (`JNI-*`, `BOF-*`, `INJ-*`, etc.) strictly independent.
5. **Report Serialization**: Produces standardized 3-tier JSON report payloads with attack surface metrics and severity tallies.

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

### ⚙️ Pattern-Level Severity & Confidence Mechanics

To avoid coarse, one-size-fits-all categorization, rules in `config/rules.yaml` utilize a two-level nested structure parsed into strongly-typed `Rule` and `RulePattern` dataclasses (`native_analysis.models.rule`):

1. **Category Containers (`Rule`)**: Group related security checks under category identifiers (e.g., `BOF-001` for Buffer Overflow, `INJ-001` for Command Injection).
2. **Sub-Rule Patterns (`RulePattern`)**: Define individual regex pattern signatures with specific sub-rule IDs (`BOF-001`, `BOF-002`, `BOF-004`), individual severity ratings (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), and confidence levels (`HIGH`, `MEDIUM`, `LOW`).

During AST scanning (`BaseAnalyzer._scan_function_with_patterns`), pattern matching evaluates each `RulePattern` object. When a pattern matches:
- The resulting `Finding` object captures the precise sub-rule ID (e.g., `BOF-002` for `strcpy` vs `BOF-004` for `sprintf`) along with the pattern's dedicated severity and confidence.
- Selective finding aggregation groups static binary data & string artifact findings (`STR-*`, `FRD-*`, `DBG-*`, `IPC-004`) sharing identical 5-tuple keys (`rule_id`, `severity`, `confidence`, `location.function_name`, `flow_analysis.source`) into composite findings with `matches` arrays and `total_matches` counts, while keeping control-flow and execution vulnerabilities (`JNI-*`, `BOF-*`, `INJ-*`, etc.) strictly independent.

---

## 💻 Installation & Setup

### Prerequisites
- **Python**: Python 3.8 or higher.
- **Dependencies**: `PyYAML` (optional; zero-dependency fallback YAML parser included).
- **Decompiler (Optional)**: Ghidra 10.x+ analyzeHeadless executable.

### Installation
```bash
# Clone repository
git clone https://github.com/apktrace/native-analysis.git
cd native-analysis

# Install optional dependencies
pip install pyyaml
```

---

## 🛠️ Usage Modes

### 1. Command-Line Interface (`cli.py`)
Run automated security analysis on target dynamic libraries using flags or configuration file:

```bash
# Standard CLI invocation with target library and output path
python cli.py -t ./tests/libnative.so -o ./output/report.json

# Run test scan using config/cli_config.yaml
python cli.py
```

### 2. Python API Module Mode
Integrate directly into automated frameworks or orchestrators:

```python
from native_analysis.core.engine import ScanEngine
from native_analysis.reporters.json_reporter import JSONReporter

# Initialize scan engine
engine = ScanEngine(
    rules_path="config/rules.yaml",
    ghidra_headless_path=None  # Set Ghidra analyzeHeadless path if available
)

# Execute security scan against dynamic library
parsed_binary, findings = engine.scan_target(
    target_so_path="./tests/libnative.so",
    apk_relative_path="standalone/libnative-lib.so"
)

# Export structured report
report = JSONReporter.generate_report(
    scanned_targets=[(parsed_binary, findings)],
    output_file_path="./output/report.json"
)
print(f"Scan complete. Total findings: {len(findings)}")
```

---

## 📄 JSON Report Schema Overview

The engine produces a standardized 3-Tier JSON report containing executive metrics, file summaries, and findings:

```json
{
  "summary": {
    "total_targets_scanned": 1,
    "total_findings": 15,
    "by_severity": { "CRITICAL": 2, "HIGH": 5, "MEDIUM": 5, "LOW": 3 },
    "by_confidence": { "HIGH": 13, "MEDIUM": 2, "LOW": 0 },
    "by_category": { "Buffer Overflow": 1, "Command Injection": 1 }
  },
  "targets": [
    {
      "file_name": "libnative.so",
      "apk_relative_path": "standalone/libnative.so",
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
      "findings": [
        {
          "finding_id": "FIND-01",
          "rule_id": "INJ-001",
          "severity": "CRITICAL",
          "confidence": "HIGH",
          "location": {
            "function_name": "Java_com_example_app_NativeLib_executeCmd",
            "symbol_address": "0x00002b40",
            "line_number": 34,
            "is_exported_jni": true
          },
          "target_variable": "command_buf",
          "trigger_line": "system(command_buf);",
          "flow_analysis": {
            "source": "JNI String parameter 'user_input' passed from Java layer at line 28",
            "sink": "Unsanitized command execution via system() call at line 34",
            "data_path": [
              "/* 0x2b10 | line 28 */ const char* user_input = (*env)->GetStringUTFChars(env, j_cmd, 0);",
              "/* 0x2b28 | line 31 */ sprintf(command_buf, \"/system/bin/ping -c 1 %s\", user_input);",
              "/* 0x2b40 | line 34 */ system(command_buf); // [TRIGGER]"
            ]
          }
        },
        {
          "finding_id": "FIND-02",
          "rule_id": "FRD-001",
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
            "data_path": [
              "/* N/A | line 10 */ if (access(\"/system/bin/su\", F_OK) == 0) // [TRIGGER]"
            ]
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

---

## 📚 Technical Documentation

For deeper details regarding module architecture, data flows, symbol resolution strategies, and decompiler fallback algorithms, consult [docs/NATIVE_ANALYSIS_ARCHITECTURE.md](docs/NATIVE_ANALYSIS_ARCHITECTURE.md).

