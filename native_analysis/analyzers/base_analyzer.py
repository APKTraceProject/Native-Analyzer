"""
Abstract Base Class for all 15 vulnerability analyzers with deduplication and 20-line context window formatting.
"""

import re
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from native_analysis.models.rule import Rule
from native_analysis.models.parsed_binary import ParsedBinary, DecompiledFunction
from native_analysis.models.finding import Finding, FlowAnalysis
from native_analysis.models.location import Location

class BaseAnalyzer(ABC):
    """
    Base analyzer providing signature pattern matching, 20-line context window formatting,
    taint flow generation, and scope-based deduplication.
    """

    def __init__(self, rule: Rule):
        """
        Initialize analyzer with rule configuration.
        
        Args:
            rule: Rule object defining ID, severity, category, patterns.
        """
        self.rule = rule

    @abstractmethod
    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        """
        Executes static analysis on parsed binary.
        Must be implemented by child vulnerability analyzers.
        """
        pass

    def _extract_context_window(
        self,
        code_lines: List[str],
        trigger_index: int,
        address: str
    ) -> List[str]:
        """
        Extracts up to 10 C lines before, trigger line itself, and 10 lines after (up to 20 lines total).
        Formats each line with explicit memory marker: /* 0x2b40 | line 34 */ statement; // [TRIGGER]
        """
        start_idx = max(0, trigger_index - 10)
        end_idx = min(len(code_lines), trigger_index + 11)

        formatted_lines = []
        base_addr_int = int(address, 16) if address.startswith("0x") else 0x1000

        for idx in range(start_idx, end_idx):
            line_content = code_lines[idx].rstrip()
            line_num = idx + 1
            # Compute estimated address offset per line
            line_addr = hex(base_addr_int + (idx * 4))

            if idx == trigger_index:
                marker = f"/* {line_addr} | line {line_num} */ {line_content} // [TRIGGER]"
            else:
                marker = f"/* {line_addr} | line {line_num} */ {line_content}"
            
            formatted_lines.append(marker)

        return formatted_lines

    def _extract_target_variable(self, trigger_line: str, pattern: str) -> str:
        """
        Extracts target variable/buffer parameter from C trigger statement.
        """
        match = re.search(r'\(\s*([^,)]+)', trigger_line)
        if match:
            var = match.group(1).strip()
            # Clean up pointer symbols or casts
            var = re.sub(r'^\*|^\([^\)]+\)', '', var).strip()
            return var if var else "buf"
        return "target_buffer"

    def _scan_function_with_patterns(
        self,
        binary: ParsedBinary,
        rule_override: Optional[Rule] = None
    ) -> List[Finding]:
        """
        Standardized scanner iterating through functions and matching rule patterns.
        Applies function-level deduplication to retain 1 finding per rule per function.
        """
        target_rule = rule_override if rule_override else self.rule
        findings: List[Finding] = []
        seen_function_scopes = set()

        patterns = target_rule.patterns if isinstance(target_rule.patterns, list) else []
        for func in binary.functions:
            # Check for scope deduplication
            scope_key = (target_rule.id, func.name)
            if scope_key in seen_function_scopes:
                continue

            for idx, line in enumerate(func.code_lines):
                for pattern in patterns:
                    if isinstance(pattern, str) and re.search(pattern, line):
                        # Dedup hit
                        seen_function_scopes.add(scope_key)
                        
                        context_path = self._extract_context_window(
                            code_lines=func.code_lines,
                            trigger_index=idx,
                            address=func.address
                        )

                        var_name = self._extract_target_variable(line, pattern)
                        line_no = idx + 1

                        # Check if section is a static string / data section or if static string rule
                        is_string_sec = (
                            func.name == "global_strings_section" or
                            func.name.endswith("_section") or
                            func.name.endswith("_strings") or
                            target_rule.id in ["DBG-001", "FRD-001", "STR-001"]
                        )

                        if is_string_sec:
                            loc = Location(
                                function_name="N/A (Static Data Section)",
                                symbol_address="N/A",
                                line_number=line_no,
                                is_exported_jni=False
                            )
                            source_desc = "Hardcoded static binary string artifact"
                            sink_desc = f"Unsanitized reference via pattern '{pattern}' at line {line_no}"
                        else:
                            loc = Location(
                                function_name=func.name,
                                symbol_address=func.address,
                                line_number=line_no,
                                is_exported_jni=func.is_exported_jni
                            )

                            # Search for actual function definition signature line
                            src_line_no = None
                            for s_idx, s_line in enumerate(func.code_lines[:idx]):
                                s_line_clean = s_line.strip()
                                if func.name in s_line and "(" in s_line and not s_line_clean.startswith("/*"):
                                    src_line_no = s_idx + 1
                                    break

                            if src_line_no is None:
                                src_line_no = max(1, line_no - 1)

                            source_desc = f"JNI or internal parameter passed to function '{func.name}' at line {src_line_no}"
                            sink_desc = f"Unsanitized call via pattern '{pattern}' at line {line_no}"

                        flow = FlowAnalysis(
                            source=source_desc,
                            sink=sink_desc,
                            data_path=context_path
                        )

                        finding = Finding(
                            finding_id=f"FIND-{len(findings)+1:02d}",
                            rule_id=target_rule.id,
                            severity=target_rule.severity,
                            confidence=target_rule.confidence,
                            target_file=binary.apk_relative_path,
                            location=loc,
                            target_variable=var_name,
                            trigger_line=line.strip(),
                            flow_analysis=flow
                        )
                        findings.append(finding)
                        break  # Break pattern loop once matched for this line
                if scope_key in seen_function_scopes:
                    break  # Break function line loop once matched for scope

        return findings
