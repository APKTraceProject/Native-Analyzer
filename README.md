# APKTrace - Native Analysis

**APKTrace - Native Analysis** is a static vulnerability analysis engine for Android dynamic native libraries (`.so` / ELF binaries). It performs automated disassembly, AST reconstruction, and pattern matching across native C/C++ decompiled code and binary symbol tables.

---

## 🛠️ Usage Modes

### 1. Imported Python Module Mode
Integrate directly into automated frameworks, orchestrators, or pipeline scripts:

```python
from native_analysis.core.engine import ScanEngine
from native_analysis.reporters.json_reporter import JSONReporter

# Initialize scan engine with rules and optional Ghidra headless path
engine = ScanEngine(
    rules_path="config/rules.yaml",
    ghidra_headless_path="C:\\Ghidra\\support\\analyzeHeadless.bat" # Optional
)

# Run target scan
parsed_binary, findings = engine.scan_target(
    target_so_path="./libnative.so",
    apk_relative_path="standalone/libnative-lib.so"
)

# Export 3-tier JSON report
report = JSONReporter.generate_report(
    scanned_targets=[(parsed_binary, findings)],
    output_file_path="./output/report.json"
)
```

### 2. Standalone Test Utility Mode (`cli.py`)
Run standalone security analysis using `cli_config.yaml`:

```bash
# Copy example configuration template
cp config/cli_config.yaml.example config/cli_config.yaml

# Run test scan
python cli.py
```

---

## 📄 JSON Report Schema Overview

The engine produces a standardized 3-Tier AI Validator JSON schema:

```json
{
  "summary": {
    "total_targets_scanned": 1,
    "total_findings": 1,
    "by_severity": { "CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0 },
    "by_confidence": { "HIGH": 1, "MEDIUM": 0, "LOW": 0 },
    "by_category": { "Command Injection": 1 }
  },
  "targets": [
    {
      "file_name": "libnative-lib.so",
      "apk_relative_path": "standalone/libnative-lib.so",
      "abi_architecture": "arm64-v8a",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "target_summary": {
        "file_findings_count": 1,
        "by_severity": { "CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0 },
        "by_confidence": { "HIGH": 1, "MEDIUM": 0, "LOW": 0 },
        "by_category": { "Command Injection": 1 },
        "attack_surface_metrics": {
          "total_functions_scanned": 12,
          "exported_jni_functions": 3,
          "vulnerable_jni_functions": 1
        }
      },
      "findings": [
        {
          "finding_id": "FIND-01",
          "rule_id": "INJ-001",
          "severity": "CRITICAL",
          "confidence": "HIGH",
          "target_file": "standalone/libnative-lib.so",
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

## 🔍 Supported Vulnerability Detectors

1. **[BOF-001] Buffer Overflow**: Detects unsafe memory manipulation (`strcpy`, `sprintf`, `gets`, `memcpy`).
2. **[INJ-001] Command Injection**: Scans for unvalidated command execution sinks (`system`, `popen`, `execve`).
3. **[FMT-001] Format String**: Identifies non-literal format strings (`printf`, `__android_log_print`).
4. **[CRY-001] Weak Cryptography**: Detects legacy hashes and ciphers (`MD5`, `SHA1`, `DES`, `RC4`).
5. **[DBG-001] Anti-Debugging**: Identifies ptrace instrumentation and process trace checks.
6. **[MEM-001] Memory Management**: Flags double-free and use-after-free conditions.
7. **[JNI-001] JNI Boundary Leaks**: Tracks unreleased JNI string/array pointers.
8. **[PRM-001] File Permission Flaws**: Detects world-writable permission modes (`chmod 0777`).
9. **[INT-001] Integer Overflow**: Flags arithmetic inside dynamic allocation parameters.
10. **[IPC-001] Insecure IPC**: Identifies unauthenticated local UNIX domain sockets.
11. **[NUL-001] Null Pointer Dereference**: Detects unchecked dynamic memory allocations.
12. **[RND-001] Insecure Randomness**: Flags predictable pseudo-random number generators.
13. **[REF-001] JNI Reflection Abuse**: Identifies unvalidated Java reflection via JNI.
14. **[FRD-001] Anti-Root / Frida**: Scans for root checks and Frida dynamic instrumentation ports.
15. **[STR-001] String Obfuscation**: Detects exposed plaintext secrets, URLs, and API tokens.
