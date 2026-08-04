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
        Extracts target variable, buffer parameter, or static data string artifact from C trigger statement.
        """
        if not trigger_line or not trigger_line.strip():
            return "target_buffer"

        # 1. Match regex pattern against trigger_line
        pat_match = None
        if pattern:
            try:
                pat_match = re.search(pattern, trigger_line)
            except Exception:
                pat_match = None

        # 2. If Regex pattern contains capture groups and matched, bind target_variable to group(1)
        if pat_match and pat_match.lastindex and pat_match.lastindex >= 1:
            captured = pat_match.group(1)
            if captured and captured.strip():
                return captured.strip()

        # 3. If pattern matches a specific static artifact or string literal (e.g. /system/bin/su, secrets, URLs, ports),
        #    prefer returning the matched string content directly.
        if pat_match:
            matched_text = pat_match.group(0).strip()
            if matched_text and (
                matched_text.startswith("/") or
                "http" in matched_text or
                "api_key" in matched_text or
                "password" in matched_text or
                "bearer" in matched_text or
                matched_text in ["TracerPid", "GLOBAL_SECRET_KEY", "frida-server", "27042", "AF_UNIX"] or
                re.match(r'^[0-9a-fA-F]{32}$', matched_text)
            ):
                return matched_text

        # 4. Standard C function call parameter extraction: e.g. func(var, ...)
        arg_match = re.search(r'\(\s*([^,)]+)', trigger_line)
        if arg_match:
            var = arg_match.group(1).strip()
            # Clean up pointer dereference (*), address-of (&), or C type casts e.g. (char*)
            var = re.sub(r'^\*|^\&|^\([^\)]+\)\s*', '', var).strip()
            if var and var != "void":
                return var

        # 5. Variable assignment LHS: e.g. var = rand() or buf[i] ^= 0x5A
        assign_match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*(?:\[[^\]]+\])?)\s*(?:=|\^=|\+=|-=|\*=)', trigger_line)
        if assign_match:
            var = assign_match.group(1).strip()
            if var:
                return var

        # 6. Fallback to matched text of pattern
        if pat_match:
            matched_text = pat_match.group(0).strip()
            if matched_text:
                return matched_text

        # 7. Fallback to quoted string literal in trigger_line
        str_match = re.search(r'"([^"]+)"', trigger_line)
        if str_match:
            return str_match.group(1).strip()

        return "buf"

    def _scan_function_with_patterns(
        self,
        binary: ParsedBinary,
        rule_override: Optional[Rule] = None
    ) -> List[Finding]:
        """
        Standardized scanner iterating through functions and matching rule patterns.
        Extracts fine-grained sub-rule IDs, severity, and confidence from matched RulePattern objects.
        
        @param binary ParsedBinary payload with decompiled C code and metadata.
        @param rule_override Optional custom Rule object overriding self.rule.
        @return List[Finding] Generated vulnerability findings.
        """
        target_rule = rule_override if rule_override else self.rule
        findings: List[Finding] = []
        seen_function_scopes = set()

        patterns = target_rule.patterns if isinstance(target_rule.patterns, list) else []
        for func in binary.functions:
            for idx, line in enumerate(func.code_lines):
                for pat_obj in patterns:
                    # Extract pattern string, sub-rule ID, severity, confidence
                    if hasattr(pat_obj, "pattern"):
                        pat_str = pat_obj.pattern
                        sub_rule_id = pat_obj.id
                        sev = pat_obj.severity
                        conf = pat_obj.confidence
                    elif isinstance(pat_obj, str):
                        pat_str = pat_obj
                        sub_rule_id = target_rule.id
                        sev = target_rule.severity
                        conf = target_rule.confidence
                    else:
                        continue

                    # Scope-based deduplication per sub-rule ID or parent rule ID per function
                    scope_key = (sub_rule_id, func.name)
                    if scope_key in seen_function_scopes:
                        continue

                    # Match regex pattern against C line
                    if pat_str and re.search(pat_str, line):
                        # Mark scope as analyzed to enforce single finding per sub-rule per function
                        seen_function_scopes.add(scope_key)
                        
                        # Extract 20-line window around trigger statement
                        context_path = self._extract_context_window(
                            code_lines=func.code_lines,
                            trigger_index=idx,
                            address=func.address
                        )

                        var_name = self._extract_target_variable(line, pat_str)
                        line_no = idx + 1

                        # Determine if target section represents static data or global string section
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
                            sink_desc = f"Unsanitized reference via pattern '{pat_str}' at line {line_no}"
                        else:
                            loc = Location(
                                function_name=func.name,
                                symbol_address=func.address,
                                line_number=line_no,
                                is_exported_jni=func.is_exported_jni
                            )

                            # Locate function signature or parameter declaration line
                            src_line_no = None
                            for s_idx, s_line in enumerate(func.code_lines[:idx]):
                                s_line_clean = s_line.strip()
                                if func.name in s_line and "(" in s_line and not s_line_clean.startswith("/*"):
                                    src_line_no = s_idx + 1
                                    break

                            if src_line_no is None:
                                src_line_no = max(1, line_no - 1)

                            source_desc = f"JNI or internal parameter passed to function '{func.name}' at line {src_line_no}"
                            sink_desc = f"Unsanitized call via pattern '{pat_str}' at line {line_no}"

                        flow = FlowAnalysis(
                            source=source_desc,
                            sink=sink_desc,
                            data_path=context_path
                        )

                        finding = Finding(
                            finding_id=f"FIND-{len(findings)+1:02d}",
                            rule_id=sub_rule_id,
                            severity=sev,
                            confidence=conf,
                            location=loc,
                            target_variable=var_name,
                            trigger_line=line.strip(),
                            flow_analysis=flow
                        )
                        findings.append(finding)
                        break  # Stop evaluating patterns for this line once matched

        return findings
