"""
Scan Engine orchestrator executing all 15 analyzers, managing deduplication and state.
"""

import os
import sys
import traceback
from typing import List, Dict, Any, Tuple, Optional
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding
from native_analysis.models.rule import Rule
from native_analysis.parsers.ghidra_parser import GhidraParser
from native_analysis.core.config_loader import ConfigLoader

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

            # Step 1: Parse ELF binary and reconstruct functions
            parsed_binary = self.parser.parse(target_so_path, apk_relative_path=apk_relative_path)
            all_findings: List[Finding] = []

            # Step 2: Iterate registered analyzers and evaluate rules
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

                analyzer_inst = analyzer_cls(rule)
                findings = analyzer_inst.analyze(parsed_binary)
                all_findings.extend(findings)

            # Step 3: Enforce function-scope finding deduplication
            deduped_findings = self._deduplicate_findings(all_findings)
            
            # Step 4: Re-index sequential finding identifiers (FIND-01, FIND-02, ...)
            for idx, f in enumerate(deduped_findings):
                f.finding_id = f"FIND-{idx+1:02d}"

            return parsed_binary, deduped_findings
        except Exception as e:
            # Re-raise exception for upper layer driver handling
            raise e

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Deduplicates findings by enforcing uniqueness per (rule_id, function_name) tuple.
        
        @param findings Raw list of matched findings.
        @return List[Finding] Scope-deduplicated finding list.
        """
        seen_keys = set()
        unique_findings = []

        for f in findings:
            key = (f.rule_id, f.location.function_name)
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)

        return unique_findings
