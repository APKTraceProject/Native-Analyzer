"""
ContextBuilder responsible for populating AnalysisContext prior to analyzer execution.
"""

import os
from typing import Optional, Dict, Any, List
from native_analysis.models.context import AnalysisContext
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.parsers.ghidra_parser import GhidraParser


class ContextBuilder:
    """
    Pre-extracts target binary artifacts (ELF headers, hardening flags, symbols, strings,
    and decompiled function code scopes) to populate a single O(1) AnalysisContext.
    """

    def __init__(
        self,
        target_path: str,
        parser: Optional[Any] = None,
        apk_relative_path: Optional[str] = None
    ):
        self.target_path = target_path
        self.parser = parser if parser else GhidraParser()
        self.apk_relative_path = apk_relative_path

    def build(self) -> AnalysisContext:
        """
        Parses the binary once and builds the complete AnalysisContext object.
        """
        parsed_binary: ParsedBinary = self.parser.parse(
            self.target_path,
            apk_relative_path=self.apk_relative_path
        )

        file_name = parsed_binary.file_name
        apk_rel = parsed_binary.apk_relative_path
        abi_arch = parsed_binary.abi_architecture
        sha256 = parsed_binary.sha256

        # 1. Binary Info
        binary_info = {
            "file_name": file_name,
            "apk_relative_path": apk_rel,
            "abi_architecture": abi_arch,
            "primary_abi": parsed_binary.primary_abi or abi_arch,
            "associated_abis": parsed_binary.associated_abis,
            "sha256": sha256,
            "target_path": self.target_path,
        }

        # 2. Hardening Flags
        hardening_flags = {
            "stack_canary": parsed_binary.mitigations.stack_canary if parsed_binary.mitigations else False,
            "nx_bit": parsed_binary.mitigations.nx_bit if parsed_binary.mitigations else False,
            "pie_enabled": parsed_binary.mitigations.pie_enabled if parsed_binary.mitigations else False,
            "relro": parsed_binary.mitigations.relro if parsed_binary.mitigations else "NONE",
        }

        # 3. String Artifacts (with basic entropy calculation)
        string_artifacts = []
        for s in parsed_binary.strings:
            entropy = len(set(s)) / len(s) if len(s) > 0 else 0.0
            string_artifacts.append({
                "value": s,
                "length": len(s),
                "entropy": round(entropy, 4)
            })

        # 4. Symbol Table
        all_function_names = [f.name for f in parsed_binary.functions if f.name != "global_strings_section" and not f.name.endswith("_section") and not f.name.endswith("_strings")]
        symbol_table = {
            "exported_jni_functions": parsed_binary.exported_jni_functions,
            "functions": all_function_names,
            "imports": [],
            "exports": parsed_binary.exported_jni_functions,
        }

        # 5. Code Scope
        code_scope = dict(parsed_binary.functions_code_scope)
        if not code_scope:
            code_scope = {
                f.name: f.code_lines
                for f in parsed_binary.functions
                if f.name != "global_strings_section" and not f.name.endswith("_section") and not f.name.endswith("_strings")
            }

        return AnalysisContext(
            target_path=self.target_path,
            binary_info=binary_info,
            hardening_flags=hardening_flags,
            string_artifacts=string_artifacts,
            symbol_table=symbol_table,
            code_scope=code_scope,
            parsed_binary=parsed_binary
        )
