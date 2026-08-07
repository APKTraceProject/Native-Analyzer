"""
Scan Engine orchestrator executing all 15 analyzers, managing deduplication and state.
"""

import os
import sys
import traceback
import zipfile
import tempfile
from typing import List, Dict, Any, Tuple, Optional
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding
from native_analysis.models.rule import Rule
from native_analysis.models.context import AnalysisContext
from native_analysis.parsers.ghidra_parser import GhidraParser
from native_analysis.core.config_loader import ConfigLoader
from native_analysis.core.context_builder import ContextBuilder

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

    def __init__(self, rules_path: str = "config/rules.yaml", ghidra_headless_path: str = None):
        """
        Initializes engine, loads YAML rule signatures, and configures binary decompiler.
        
        @param rules_path Path to rules.yaml config file.
        @param ghidra_headless_path Optional path to Ghidra headless analyzer executable.
        """
        self.rules = ConfigLoader.load_rules(rules_path)
        self.rules_by_id: Dict[str, Rule] = {r.id: r for r in self.rules}
        self.parser = GhidraParser(ghidra_headless_path=ghidra_headless_path)

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
        apk_relative_path: Optional[str] = None
    ) -> Tuple[ParsedBinary, List[Finding]]:
        """
        Parses target shared library (.so) and runs all 15 vulnerability analyzers.
        
        @param target_so_path File path to target dynamic library.
        @param apk_relative_path Relative path string used in JSON reporting.
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

    def resolve_target(
        self,
        target_path: str,
        temp_dir: Optional[str] = None
    ) -> List[Tuple[str, str]]:
        """
        Resolves target input path using strict 2-mode policy:
        - Single Mode (.so): returns [(resolved_target_path, "standalone/<filename>")]
        - Multi Mode (.apk): extracts all .so binaries inside to temp_dir and returns list of [(extracted_so_path, apk_relative_path)]
        
        Throws explicit error for missing file or invalid extension (not .so or .apk).
        
        @param target_path Path to .so or .apk target file.
        @param temp_dir Optional directory path to extract APK contents.
        @return List[Tuple[str, str]] List of (extracted_or_local_so_path, relative_report_path) tuples.
        """
        resolved_path = ConfigLoader.resolve_target_path(target_path)
        if not resolved_path or not os.path.exists(resolved_path):
            raise FileNotFoundError(f"Target file '{target_path}' not found.")
        target_path = resolved_path

        ext = os.path.splitext(target_path)[1].lower()
        if ext == ".so":
            filename = os.path.basename(target_path)
            return [(target_path, f"standalone/{filename}")]
        elif ext == ".apk":
            if not zipfile.is_zipfile(target_path):
                raise ValueError(f"Target file '{target_path}' is not a valid zip/APK archive.")

            with zipfile.ZipFile(target_path, "r") as zf:
                so_entries = [name for name in zf.namelist() if name.lower().endswith(".so")]
                if not so_entries:
                    raise ValueError(f"No .so dynamic libraries found inside APK archive '{target_path}'.")

                dest_dir = temp_dir or tempfile.mkdtemp(prefix="apktrace_apk_")
                resolved_targets = []
                for entry in so_entries:
                    extracted_file = zf.extract(entry, path=dest_dir)
                    resolved_targets.append((extracted_file, entry))
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
        Executes multi mode security scan against an APK archive by extracting and scanning ALL .so binaries inside (no ABI filtering).
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
            for extracted_so, rel_path in targets:
                parsed_binary, findings = self.scan_target(
                    target_so_path=extracted_so,
                    apk_relative_path=rel_path
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

