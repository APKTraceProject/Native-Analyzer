"""
Scan Engine orchestrator executing all 15 analyzers, managing deduplication and state.
"""

import os
import sys
import time
import traceback
import zipfile
import tempfile
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding
from native_analysis.models.rule import Rule
from native_analysis.models.context import AnalysisContext
from native_analysis.parsers import GhidraParser, Radare2Parser
from native_analysis.core.config_loader import ConfigLoader
from native_analysis.core.context_builder import ContextBuilder
from native_analysis.reporters.json_reporter import JSONReporter

# Import all 15 Analyzers
from native_analysis.analyzers.buffer_overflow import BufferOverflowAnalyzer
from native_analysis.analyzers.command_injection import CommandInjectionAnalyzer
from native_analysis.analyzers.format_string import FormatStringAnalyzer
from native_analysis.analyzers.weak_crypto import WeakCryptoAnalyzer
from native_analysis.analyzers.anti_debugging import AntiDebuggingAnalyzer
from native_analysis.analyzers.memory_management import MemoryManagementAnalyzer
from native_analysis.analyzers.jni_boundary_leaks import JNIBoundaryLeaksAnalyzer
from native_analysis.analyzers.file_permission_flaws import FilePermissionFlawsAnalyzer
from native_analysis.analyzers.integer_overflow import IntegerOverflowAnalyzer
from native_analysis.analyzers.insecure_ipc import InsecureIPCAnalyzer
from native_analysis.analyzers.null_pointer_deref import NullPointerDerefAnalyzer
from native_analysis.analyzers.insecure_random import InsecureRandomAnalyzer
from native_analysis.analyzers.jni_reflection_abuse import JNIReflectionAbuseAnalyzer
from native_analysis.analyzers.anti_root_frida import AntiRootFridaAnalyzer
from native_analysis.analyzers.string_obfuscation import StringObfuscationAnalyzer

class ScanEngine:
    """
    Main Analysis Engine orchestrating parsing, decompilation, pattern analysis, and deduplication.
    
    Pipeline Execution Flow:
    1. Ingestion: Reads ELF target library and computes security mitigations.
    2. Decompilation: Invokes Ghidra or Fallback Heuristic decompiler to generate pseudo-C AST.
    3. Rule Evaluation: Dispatches 15 specialized analyzers across decompiled code and string tables.
    4. Scope Deduplication: Filters duplicate findings per function scope and re-indexes IDs.
    """

    # Mapping rule signature IDs to analyzer class constructors
    ANALYZER_MAPPING = {
        "BOF-001": BufferOverflowAnalyzer,
        "INJ-001": CommandInjectionAnalyzer,
        "FMT-001": FormatStringAnalyzer,
        "CRY-001": WeakCryptoAnalyzer,
        "DBG-001": AntiDebuggingAnalyzer,
        "MEM-001": MemoryManagementAnalyzer,
        "JNI-001": JNIBoundaryLeaksAnalyzer,
        "PRM-001": FilePermissionFlawsAnalyzer,
        "INT-001": IntegerOverflowAnalyzer,
        "IPC-001": InsecureIPCAnalyzer,
        "NUL-001": NullPointerDerefAnalyzer,
        "RND-001": InsecureRandomAnalyzer,
        "REF-001": JNIReflectionAbuseAnalyzer,
        "FRD-001": AntiRootFridaAnalyzer,
        "STR-001": StringObfuscationAnalyzer,
    }

    def __init__(
        self,
        decompiler_path: Optional[str] = None,
        engine: str = "ghidra"
    ):
        """
        Initializes engine, statically loads rules.yaml signatures internally, and configures binary decompiler/parser.
        
        @param decompiler_path Optional path to decompiler executable (Ghidra analyzeHeadless or radare2 binary).
        @param engine Decompiler engine choice ("ghidra" or "radare2").
        """
        self.rules = ConfigLoader.load_rules()
        self.rules_by_id: Dict[str, Rule] = {r.id: r for r in self.rules}
        
        self.decompiler_path = decompiler_path
        self.engine_name = engine.lower()

        if self.engine_name == "radare2":
            self.parser = Radare2Parser(decompiler_path=decompiler_path)
        else:
            self.parser = GhidraParser(decompiler_path=decompiler_path)

    def build_rule_category_map(self) -> Dict[str, str]:
        """
        Builds a lookup map from rule/pattern IDs to human-readable vulnerability categories.
        
        @return Dict[str, str] Rule ID to category mapping.
        """
        rule_map = {}
        for rule in self.rules:
            cat = rule.category or rule.name or "General Vulnerability"
            if rule.id:
                rule_map[rule.id] = cat
            for pat in rule.patterns:
                if pat.id:
                    rule_map[pat.id] = cat
        return rule_map

    def get_finding_category(self, rule_id: str, rule_map: Dict[str, str]) -> str:
        """
        Determines category string for a finding based on rule_id or prefix fallback.
        
        @param rule_id Rule ID string (e.g. 'BOF-001').
        @param rule_map Pre-built rule category dictionary.
        @return str Category display name.
        """
        if rule_id in rule_map:
            return rule_map[rule_id]
        
        prefix = rule_id.split("-")[0].upper() if "-" in rule_id else rule_id[:3].upper()
        prefix_map = {
            "BOF": "Buffer Overflow",
            "INJ": "Command Injection",
            "FMT": "Format String",
            "JNI": "JNI Boundary Leak",
            "MEM": "Memory Management",
            "INT": "Integer Overflow",
            "OVF": "Integer Overflow",
            "PRM": "File Permission Flaws",
            "PERM": "File Permission Flaws",
            "RND": "Insecure Randomness",
            "RNG": "Insecure Randomness",
            "RAND": "Insecure Randomness",
            "CRY": "Weak Cryptography",
            "NPD": "Null Pointer Dereference",
            "NUL": "Null Pointer Dereference",
            "NULL": "Null Pointer Dereference",
            "IPC": "Insecure IPC",
            "DBG": "Anti-Debugging",
            "FRD": "Anti-Root & Frida Detection",
            "ROOT": "Anti-Root & Frida Detection",
            "REF": "JNI Reflection Abuse",
            "STR": "String Obfuscation"
        }
        return prefix_map.get(prefix, f"Category ({prefix})")

    def execute(
        self,
        target_path: str,
        output_path: str = "./output/report.json",
        config_file_used: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Primary workflow orchestrator executing the full native security analysis task pipeline:
        - Target path resolution & 2-mode target identification (.so single or .apk multi)
        - Dynamic library extraction & Primary ABI deduplication
        - Parallel/Sequential decompilation & 15-category AST vulnerability scanning
        - Invokes JSONReporter sub-module to serialize 4-level JSON report artifact
        - Aggregates metrics, severity counts, category counts, progress logs, and execution status
        
        Returns structured payload schema:
        {
            "success": True/False,
            "metadata": {
                "config_file": "...",
                "config_content": { ... },
                "execution": { ... }
            },
            "summary": { ... }
        }
        
        @param target_path Path to target binary (.so) or application package (.apk).
        @param output_path File destination path for JSON report artifact.
        @param config_file_used Optional path string of loaded YAML configuration file.
        @return Dict[str, Any] Complete execution summary payload for CLI or caller consumption.
        """
        start_time = time.time()
        timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        progress_logs: List[Tuple[str, str, str, str]] = []

        if config_file_used:
            progress_logs.append(("+", "COLOR_GREEN", "INFO", f"Config loaded successfully from '{config_file_used}'."))

        mode_str = "UNKNOWN"
        binary_count = 0
        target_filename = os.path.basename(target_path) if target_path else ""

        active_analyzers = [
            "buffer_overflow", "command_injection", "format_string", "weak_crypto",
            "anti_debugging", "memory_management", "jni_boundary_leaks",
            "file_permission_flaws", "integer_overflow", "insecure_ipc",
            "null_pointer_deref", "insecure_random", "jni_reflection_abuse",
            "anti_root_frida", "string_obfuscation"
        ]

        try:
            resolved_target_path = ConfigLoader.resolve_target_path(target_path)
            if not resolved_target_path or not os.path.exists(resolved_target_path):
                raise FileNotFoundError(f"Target file '{target_path}' not found.")

            ext = os.path.splitext(resolved_target_path)[1].lower()
            if ext not in (".so", ".apk"):
                raise ValueError(
                    f"Invalid target file extension '{ext}' for '{target_path}'. "
                    "Only .so (Single Mode) and .apk (Multi Mode) are supported."
                )

            target_filename = os.path.basename(resolved_target_path)

            if ext == ".so":
                mode_str = "SINGLE (.so)"
                binary_count = 1
            else:
                mode_str = "MULTI (.apk)"
                progress_logs.append(("*", "COLOR_CYAN", "SCAN", f"Extracting native targets from APK archive '{target_filename}'..."))
                resolved_targets = self.resolve_target(resolved_target_path)
                binary_count = len(resolved_targets)

                total_found = sum(1 + len(t[3]) for t in resolved_targets if len(t) > 3)
                if binary_count == 1 and len(resolved_targets[0]) >= 3:
                    lib_filename = os.path.basename(resolved_targets[0][1])
                    primary_abi = resolved_targets[0][2]
                    progress_logs.append(("+", "COLOR_GREEN", "INFO", f"Found {total_found} binaries across ABIs -> Deduplicated to 1 primary target ({lib_filename} - {primary_abi})"))
                else:
                    progress_logs.append(("+", "COLOR_GREEN", "INFO", f"Found {total_found} binaries across ABIs -> Deduplicated to {binary_count} primary targets"))

            engine_label = "Radare2" if self.engine_name == "radare2" else "Ghidra"
            progress_logs.append(("*", "COLOR_CYAN", "SCAN", f"Decompiling & analyzing symbols via {engine_label}..."))
            progress_logs.append(("*", "COLOR_YELLOW", "TAINT", "Running variable flow analysis & JNI context extraction..."))

            # Step 1: Run security scan engine across targets
            scanned_targets = self.scan(resolved_target_path)

            # Step 2: Generate 4-level JSON report artifact via JSONReporter sub-module
            report_payload = JSONReporter.generate_report(
                scanned_targets=scanned_targets,
                output_file_path=output_path,
                analysis_engine=self.engine_name
            )
            progress_logs.append(("✔", "COLOR_GREEN", "SUCCESS", f"Report generated successfully at {output_path}"))

            # Step 3: Aggregate execution statistics and category metrics
            total_files = len(scanned_targets)
            all_findings = []
            for _, findings in scanned_targets:
                all_findings.extend(findings)
            total_findings = len(all_findings)

            discovered_abis: List[str] = []
            primary_abi = "N/A"
            if scanned_targets:
                first_pb = scanned_targets[0][0]
                primary_abi = getattr(first_pb, "primary_abi", None) or getattr(first_pb, "abi_architecture", None) or "arm64-v8a"
                for pb, _ in scanned_targets:
                    p_abi = getattr(pb, "primary_abi", None) or getattr(pb, "abi_architecture", None)
                    if p_abi and p_abi not in discovered_abis:
                        discovered_abis.append(p_abi)
                    assoc = getattr(pb, "associated_abis", []) or []
                    for a_abi in assoc:
                        if a_abi and a_abi not in discovered_abis:
                            discovered_abis.append(a_abi)

            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            rule_counts: Dict[str, int] = {}

            for finding in all_findings:
                sev = getattr(finding, "severity", "MEDIUM").upper()
                if sev in sev_counts:
                    sev_counts[sev] += 1
                else:
                    sev_counts["MEDIUM"] += 1

                rule_id = getattr(finding, "rule_id", "GEN-000")
                rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

            duration_seconds = round(time.time() - start_time, 2)

            by_severity = {
                "critical": sev_counts.get("CRITICAL", 0),
                "high": sev_counts.get("HIGH", 0),
                "medium": sev_counts.get("MEDIUM", 0),
                "low": sev_counts.get("LOW", 0)
            }

            metadata_payload = {
                "config_file": config_file_used or "config/cli_config.yaml",
                "config_content": {
                    "target_path": resolved_target_path,
                    "output_json_path": output_path,
                    "engine": self.engine_name,
                    "decompiler_path": self.decompiler_path
                },
                "execution": {
                    "timestamp": timestamp_str,
                    "duration_seconds": duration_seconds,
                    "active_analyzers": active_analyzers
                }
            }

            summary_payload = {
                "discovered_abis": discovered_abis,
                "primary_abi": primary_abi,
                "scanned_files_count": total_files,
                "total_vulnerabilities": total_findings,
                "by_category": rule_counts,
                "by_severity": by_severity
            }

            return {
                "success": True,
                "metadata": metadata_payload,
                "summary": summary_payload,
                "progress_logs": progress_logs,
                "scanned_targets": scanned_targets,
                "report_payload": report_payload,
                "error": None
            }

        except Exception as e:
            err_msg = self.format_exception(e)
            progress_logs.append(("X", "COLOR_RED", "ERROR", err_msg))
            duration_seconds = round(time.time() - start_time, 2)

            metadata_payload = {
                "config_file": config_file_used or "config/cli_config.yaml",
                "config_content": {
                    "target_path": target_path,
                    "output_json_path": output_path,
                    "engine": self.engine_name,
                    "decompiler_path": self.decompiler_path
                },
                "execution": {
                    "timestamp": timestamp_str,
                    "duration_seconds": duration_seconds,
                    "active_analyzers": active_analyzers
                }
            }

            summary_payload = {
                "discovered_abis": [],
                "primary_abi": "N/A",
                "scanned_files_count": 0,
                "total_vulnerabilities": 0,
                "by_category": {},
                "by_severity": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                }
            }

            return {
                "success": False,
                "metadata": metadata_payload,
                "summary": summary_payload,
                "progress_logs": progress_logs,
                "scanned_targets": [],
                "report_payload": None,
                "error": err_msg
            }

    @staticmethod
    def format_exception(e: Exception) -> str:
        """
        Formats exception details including filename, line number, method name, and message.
        
        @param e Exception instance.
        @return str Formatted error message string.
        """
        tb = traceback.extract_tb(e.__traceback__)
        if tb:
            last_frame = tb[-1]
            filepath = last_frame.filename
            try:
                filepath = os.path.relpath(filepath)
            except Exception:
                pass
            lineno = last_frame.lineno
            funcname = last_frame.name
            err_type = type(e).__name__
            err_msg = str(e)
            return (
                f"Critical failure:\n"
                f"    File: {filepath}\n"
                f"    Line: {lineno} (in method '{funcname}')\n"
                f"    Error: {err_type}: {err_msg}"
            )
        err_type = type(e).__name__
        return f"Critical failure:\n    Error: {err_type}: {str(e)}"

    def scan_target(
        self,
        target_so_path: str,
        apk_relative_path: Optional[str] = None,
        primary_abi: Optional[str] = None,
        associated_abis: Optional[List[str]] = None
    ) -> Tuple[ParsedBinary, List[Finding]]:
        """
        Parses target shared library (.so) and runs all 15 vulnerability analyzers.
        
        @param target_so_path File path to target dynamic library.
        @param apk_relative_path Relative path string used in JSON reporting.
        @param primary_abi Primary architecture identifier for target library group.
        @param associated_abis List of bypassed duplicate architecture identifiers.
        @return Tuple[ParsedBinary, List[Finding]] AST payload and list of findings.
        """
        try:
            # Format report relative path if unspecified
            if not apk_relative_path or apk_relative_path == "standalone/libnative-lib.so":
                file_name = os.path.basename(target_so_path)
                apk_relative_path = f"standalone/{file_name}"

            # Step 1: Pre-extract binary artifacts into a single shared AnalysisContext
            context_builder = ContextBuilder(
                target_path=target_so_path,
                parser=self.parser,
                apk_relative_path=apk_relative_path
            )
            context = context_builder.build()
            parsed_binary = context.parsed_binary

            if primary_abi:
                parsed_binary.primary_abi = primary_abi
            if associated_abis is not None:
                parsed_binary.associated_abis = associated_abis

            all_findings: List[Finding] = []

            # Step 2: Iterate registered analyzers and evaluate rules using shared AnalysisContext
            for rule_id, analyzer_cls in self.ANALYZER_MAPPING.items():
                rule = self.rules_by_id.get(rule_id)
                if not rule:
                    # Construct fallback rule instance if unconfigured in rules.yaml
                    rule = Rule(
                        id=rule_id,
                        name=rule_id,
                        severity="HIGH" if "INJ" in rule_id or "BOF" in rule_id else "MEDIUM",
                        confidence="HIGH",
                        category="Vulnerability",
                        patterns=[]
                    )

                analyzer_inst = analyzer_cls(rule, context=context)
                findings = analyzer_inst.analyze(parsed_binary)
                all_findings.extend(findings)

            # Step 3: Enforce selective finding aggregation for static data artifacts
            deduped_findings = self._aggregate_findings(all_findings)
            
            # Step 4: Re-index sequential finding identifiers (FIND-01, FIND-02, ...)
            for idx, f in enumerate(deduped_findings):
                f.finding_id = f"FIND-{idx+1:02d}"
                if f.matches:
                    for m_idx, match in enumerate(f.matches):
                        match["match_id"] = f"{f.finding_id}-{m_idx+1}"

            return parsed_binary, deduped_findings
        except Exception as e:
            # Re-raise exception for upper layer driver handling
            raise e

    @staticmethod
    def _is_aggregatable(rule_id: str) -> bool:
        """
        Determines if a rule ID belongs to aggregatable static artifact categories.
        Aggregatable categories: STR-*, FRD-*, DBG-*, and IPC-004.
        """
        if not rule_id:
            return False
        return (
            rule_id.startswith("STR-") or
            rule_id.startswith("FRD-") or
            rule_id.startswith("DBG-") or
            rule_id.startswith("IPC-004")
        )

    def _aggregate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Aggregates static data findings by 5-tuple composite key while keeping execution flow findings independent.
        
        5-Tuple Composite Grouping Key:
        (rule_id, severity, confidence, location.function_name, flow_analysis.source)
        
        @param findings Raw list of matched findings.
        @return List[Finding] Aggregated finding list.
        """
        final_findings: List[Finding] = []
        aggregatable_groups: Dict[Tuple[str, str, str, str, str], List[Finding]] = {}
        group_keys_order: List[Tuple[str, str, str, str, str]] = []

        for f in findings:
            if self._is_aggregatable(f.rule_id):
                key = (
                    f.rule_id,
                    f.severity,
                    f.confidence,
                    f.location.function_name,
                    f.flow_analysis.source,
                )
                if key not in aggregatable_groups:
                    aggregatable_groups[key] = []
                    group_keys_order.append(key)
                aggregatable_groups[key].append(f)
            else:
                final_findings.append(f)

        for key in group_keys_order:
            group = aggregatable_groups[key]
            base_finding = group[0]
            
            if len(group) > 1:
                matches_list = []
                for item in group:
                    matches_list.append({
                        "match_id": "",
                        "line_number": item.location.line_number,
                        "target_variable": item.target_variable,
                        "trigger_line": item.trigger_line
                    })
                base_finding.matches = matches_list
                base_finding.total_matches = len(group)
            else:
                base_finding.matches = None
                base_finding.total_matches = 1

            final_findings.append(base_finding)

        return final_findings

    @staticmethod
    def _extract_entry_abi(zf: zipfile.ZipFile, entry: str) -> str:
        """
        Extracts target ABI architecture from zip entry path (e.g. lib/arm64-v8a/libfoo.so)
        or header inspection fallback.
        """
        parts = entry.split("/")
        if len(parts) >= 2 and parts[0] == "lib":
            abi_cand = parts[1]
            if abi_cand in ["arm64-v8a", "x86_64", "armeabi-v7a", "x86"]:
                return abi_cand
        try:
            header = zf.read(entry)[:20]
            if len(header) >= 20 and header[:4] == b"\x7fELF":
                machine_code = int.from_bytes(header[18:20], byteorder="little")
                arch_map = {
                    183: "arm64-v8a",
                    62: "x86_64",
                    40: "armeabi-v7a",
                    3: "x86"
                }
                return arch_map.get(machine_code, "arm64-v8a")
        except Exception:
            pass
        return "arm64-v8a"

    def resolve_target(
        self,
        target_path: str,
        temp_dir: Optional[str] = None
    ) -> List[Tuple[str, str, str, List[str]]]:
        """
        Resolves target input path using strict 2-mode policy with ABI deduplication:
        - Single Mode (.so): returns [(resolved_target_path, "standalone/<filename>", primary_abi, [])]
        - Multi Mode (.apk): deduplicates .so binaries per unique library filename selecting 1 primary ABI target
          and returns list of [(extracted_so_path, apk_relative_path, primary_abi, associated_abis)]
        
        Throws explicit error for missing file or invalid extension (not .so or .apk).
        
        @param target_path Path to .so or .apk target file.
        @param temp_dir Optional directory path to extract APK contents.
        @return List[Tuple[str, str, str, List[str]]] List of target resolution tuples.
        """
        resolved_path = ConfigLoader.resolve_target_path(target_path)
        if not resolved_path or not os.path.exists(resolved_path):
            raise FileNotFoundError(f"Target file '{target_path}' not found.")
        target_path = resolved_path

        ext = os.path.splitext(target_path)[1].lower()
        if ext == ".so":
            filename = os.path.basename(target_path)
            abi_arch = "arm64-v8a"
            try:
                with open(target_path, "rb") as f:
                    header = f.read(20)
                    if len(header) >= 20 and header[:4] == b"\x7fELF":
                        machine_code = int.from_bytes(header[18:20], byteorder="little")
                        arch_map = {183: "arm64-v8a", 62: "x86_64", 40: "armeabi-v7a", 3: "x86"}
                        abi_arch = arch_map.get(machine_code, "arm64-v8a")
            except Exception:
                pass
            return [(target_path, f"standalone/{filename}", abi_arch, [])]
        elif ext == ".apk":
            if not zipfile.is_zipfile(target_path):
                raise ValueError(f"Target file '{target_path}' is not a valid zip/APK archive.")

            with zipfile.ZipFile(target_path, "r") as zf:
                so_entries = [name for name in zf.namelist() if name.lower().endswith(".so")]
                if not so_entries:
                    raise ValueError(f"No .so dynamic libraries found inside APK archive '{target_path}'.")

                # Group entries by library base filename (e.g. libfoo.so)
                groups: Dict[str, List[Tuple[str, str]]] = {}
                for entry in so_entries:
                    filename = os.path.basename(entry)
                    abi = self._extract_entry_abi(zf, entry)
                    if filename not in groups:
                        groups[filename] = []
                    groups[filename].append((entry, abi))

                # Fallback priority map: 1. arm64-v8a -> 2. x86_64 -> 3. armeabi-v7a -> 4. x86
                priority_map = {"arm64-v8a": 1, "x86_64": 2, "armeabi-v7a": 3, "x86": 4}

                dest_dir = temp_dir or tempfile.mkdtemp(prefix="apktrace_apk_")
                resolved_targets = []

                for filename, entry_list in groups.items():
                    # Sort entries by ABI preference priority
                    entry_list.sort(key=lambda x: priority_map.get(x[1], 99))
                    primary_entry, primary_abi = entry_list[0]

                    # Bypassed ABIs audit trail
                    bypassed_abis = [abi for e, abi in entry_list[1:]]
                    associated_abis = list(dict.fromkeys(bypassed_abis))

                    extracted_file = zf.extract(primary_entry, path=dest_dir)
                    resolved_targets.append((extracted_file, primary_entry, primary_abi, associated_abis))

                return resolved_targets
        else:
            raise ValueError(
                f"Invalid target file extension '{ext}' for '{target_path}'. "
                "Only .so (Single Mode) and .apk (Multi Mode) files are supported."
            )

    def scan_single(
        self,
        so_path: str,
        apk_relative_path: Optional[str] = None
    ) -> Tuple[ParsedBinary, List[Finding]]:
        """
        Executes single mode security scan against a .so dynamic library binary.
        Throws explicit error if extension is not .so.
        
        @param so_path Path to .so binary file.
        @param apk_relative_path Optional relative path string for report payload.
        @return Tuple[ParsedBinary, List[Finding]] AST payload and findings.
        """
        resolved_path = ConfigLoader.resolve_target_path(so_path)
        if not resolved_path or not os.path.exists(resolved_path):
            raise FileNotFoundError(f"Target file '{so_path}' not found.")
        so_path = resolved_path

        ext = os.path.splitext(so_path)[1].lower()
        if ext != ".so":
            raise ValueError(f"Invalid target file extension '{ext}' for scan_single(). Expected a .so file.")

        return self.scan_target(target_so_path=so_path, apk_relative_path=apk_relative_path)

    def scan_multi(
        self,
        apk_path: str
    ) -> List[Tuple[ParsedBinary, List[Finding]]]:
        """
        Executes multi mode security scan against an APK archive by extracting and scanning deduplicated primary ABI targets.
        Throws explicit error if extension is not .apk.
        
        @param apk_path Path to .apk app archive file.
        @return List[Tuple[ParsedBinary, List[Finding]]] List of (ParsedBinary, List[Finding]) scan targets.
        """
        resolved_path = ConfigLoader.resolve_target_path(apk_path)
        if not resolved_path or not os.path.exists(resolved_path):
            raise FileNotFoundError(f"Target file '{apk_path}' not found.")
        apk_path = resolved_path

        ext = os.path.splitext(apk_path)[1].lower()
        if ext != ".apk":
            raise ValueError(f"Invalid target file extension '{ext}' for scan_multi(). Expected an .apk file.")

        with tempfile.TemporaryDirectory() as temp_dir:
            targets = self.resolve_target(apk_path, temp_dir=temp_dir)
            results = []
            for item in targets:
                if len(item) == 4:
                    extracted_so, rel_path, primary_abi, associated_abis = item
                else:
                    extracted_so, rel_path = item[:2]
                    primary_abi = None
                    associated_abis = None

                parsed_binary, findings = self.scan_target(
                    target_so_path=extracted_so,
                    apk_relative_path=rel_path,
                    primary_abi=primary_abi,
                    associated_abis=associated_abis
                )
                results.append((parsed_binary, findings))
            return results

    def scan(
        self,
        file_path: str
    ) -> List[Tuple[ParsedBinary, List[Finding]]]:
        """
        Auto-detecting scan engine entry point supporting strict 2-mode resolution:
        - Single Mode (.so): Scans single binary and returns list with 1 scan result tuple.
        - Multi Mode (.apk): Extracts all .so binaries inside and returns list of scan result tuples.
        
        Throws explicit error for invalid extensions.
        
        @param file_path Path to target .so or .apk file.
        @return List[Tuple[ParsedBinary, List[Finding]]] Scanned targets list.
        """
        resolved_path = ConfigLoader.resolve_target_path(file_path)
        if not resolved_path or not os.path.exists(resolved_path):
            raise FileNotFoundError(f"Target file '{file_path}' not found.")
        file_path = resolved_path

        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".so":
            parsed_binary, findings = self.scan_single(file_path)
            return [(parsed_binary, findings)]
        elif ext == ".apk":
            return self.scan_multi(file_path)
        else:
            raise ValueError(
                f"Invalid target file extension '{ext}' for '{file_path}'. "
                "Only .so (Single Mode) and .apk (Multi Mode) files are supported."
            )

    def run(
        self,
        target_so_path: str,
        apk_relative_path: Optional[str] = None
    ) -> Tuple[ParsedBinary, List[Finding]]:
        """
        Runs full analysis pipeline by building AnalysisContext and dispatching analyzers.
        """
        return self.scan_target(target_so_path, apk_relative_path=apk_relative_path)


Engine = ScanEngine

