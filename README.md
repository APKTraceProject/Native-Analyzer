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
3. **AST Pattern Matching & Flow Context**: Runs 15 specialized static analyzers across decompiled code blocks, extracting 20-line windowed code context paths mapping source-to-sink data flow.
4. **Scope Deduplication**: Deduplicates findings per function scope and re-indexes finding identifiers (`FIND-01`, `FIND-02`, ...).
5. **Report Serialization**: Produces standardized 3-tier JSON report payloads with attack surface metrics and severity tallies.

---

## 🔍 Supported Vulnerability Categories (15/15)

| Rule ID | Category Name | Default Severity | Default Confidence | Detection Strategy |
| :--- | :--- | :---: | :---: | :--- |
| **BOF-001** | Buffer Overflow | `CRITICAL` | `HIGH` | Scans for unbounded string/memory copy operations (`strcpy`, `strcat`, `gets`, `sprintf`, `memcpy`). |
| **INJ-001** | Command Injection | `CRITICAL` | `HIGH` | Detects process execution sinks (`system`, `popen`, `execve`, `execl`) receiving JNI input parameters. |
| **FMT-001** | Format String | `HIGH` | `HIGH` | Identifies non-literal format strings passed to variadic output functions (`printf`, `syslog`, `__android_log_print`). |
| **CRY-001** | Weak Cryptography | `HIGH` | `HIGH` | Detects legacy hashes (`MD5`, `SHA1`), ciphers (`DES`, `RC4`), and single-byte XOR rotation loops. |
| **DBG-001** | Anti-Debugging | `MEDIUM` | `HIGH` | Identifies `ptrace` self-attach calls (`PTRACE_TRACEME`) and `/proc/self/status` TracerPid probes. |
| **MEM-001** | Memory Management | `HIGH` | `HIGH` | Flags double-free (`free(p)` twice) and use-after-free conditions across execution paths. |
| **JNI-001** | JNI Boundary Leaks | `MEDIUM` | `MEDIUM` | Tracks unreleased JNI string/array pointers (`GetStringUTFChars` without `ReleaseStringUTFChars`). |
| **PRM-001** | File Permission Flaws | `MEDIUM` | `HIGH` | Detects world-readable/world-writable permission settings (`chmod 0777`, `mkdir 0777`, `umask 0`). |
| **INT-001** | Integer Overflow | `HIGH` | `HIGH` | Flags inline arithmetic multiplication/addition inside dynamic allocation sizes (`malloc(n * size)`). |
| **IPC-001** | Insecure IPC | `MEDIUM` | `MEDIUM` | Identifies unauthenticated local UNIX domain socket bindings (`AF_UNIX`) in shared `/tmp/` paths. |
| **NUL-001** | Null Pointer Dereference | `MEDIUM` | `HIGH` | Detects dynamic allocation return values (`malloc`, `calloc`) used without null check guards. |
| **RND-001** | Insecure Randomness | `LOW` | `HIGH` | Flags non-cryptographic PRNG calls (`rand()`, `srand(time(NULL))`) used for security tokens. |
| **REF-001** | JNI Reflection Abuse | `LOW` | `MEDIUM` | Identifies dynamic Java class lookup and reflection calls from C layer (`FindClass`, `GetMethodID`). |
| **FRD-001** | Anti-Root / Anti-Frida | `LOW` | `HIGH` | Detects probes for superuser binaries (`/system/xbin/su`) and `frida-server` UNIX socket ports. |
| **STR-001** | String Obfuscation | `HIGH` | `HIGH` | Flags exposed plaintext API keys, secret tokens, and endpoint URLs in global `.rodata` tables. |

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
          "target_file": "standalone/libnative.so",
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
        }
      ]
    }
  ]
}
```

---

## 📚 Technical Documentation

For deeper details regarding module architecture, data flows, symbol resolution strategies, and decompiler fallback algorithms, consult [docs/NATIVE_ANALYSIS_ARCHITECTURE.md](docs/NATIVE_ANALYSIS_ARCHITECTURE.md).
