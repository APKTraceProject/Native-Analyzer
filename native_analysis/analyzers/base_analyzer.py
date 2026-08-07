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
from native_analysis.models.context import AnalysisContext

RULE_PREFIX_MAP = {
    "BOF": ("CWE-120", "MASVS-CODE-2"),
    "INJ": ("CWE-78",  "MASVS-CODE-2"),
    "FMT": ("CWE-134", "MASVS-CODE-2"),
    "JNI": ("CWE-200", "MASVS-CODE-2"),
    "REF": ("CWE-470", "MASVS-CODE-2"),
    "IPC": ("CWE-926", "MASVS-PLATFORM-1"),
    "PRM": ("CWE-732", "MASVS-STORAGE-1"),
    "STR": ("CWE-798", "MASVS-CRYPTO-1"),
    "CRY": ("CWE-327", "MASVS-CRYPTO-1"),
    "RND": ("CWE-330", "MASVS-CRYPTO-1"),
    "INT": ("CWE-190", "MASVS-CODE-2"),
    "MEM": ("CWE-416", "MASVS-CODE-2"),
    "DBG": ("CWE-489", "MASVS-RESILIENCE-1"),
    "FRD": ("CWE-693", "MASVS-RESILIENCE-2"),
    "SEC": ("CWE-693", "MASVS-CODE-1")
}

class BaseAnalyzer(ABC):
    """
    Base analyzer providing signature pattern matching, 20-line context window formatting,
    taint flow generation, and scope-based deduplication.
    """

    def __init__(self, rule: Rule, context: Optional[AnalysisContext] = None):
        """
        Initialize analyzer with rule configuration and optional shared analysis context.
        
        Args:
            rule: Rule object defining ID, severity, category, patterns.
            context: Optional shared AnalysisContext containing pre-extracted binary artifacts.
        """
        self.rule = rule
        self.context = context

    @abstractmethod
    def analyze(self, binary: Optional[ParsedBinary] = None) -> List[Finding]:
        """
        Executes static analysis on parsed binary.
        Must be implemented by child vulnerability analyzers.
        """
        pass

    def _build_flow_trace(
        self,
        func_name: str,
        code_lines: List[str],
        trigger_idx: int,
        pat_str: str,
        target_var: str
    ) -> str:
        """
        Constructs a concise, accurate taint flow trace propagation path from Source to Sink.
        Chains parameter bindings and intermediate variable assignments.
        """
        line_no = trigger_idx + 1
        trigger_line = code_lines[trigger_idx] if 0 <= trigger_idx < len(code_lines) else ""

        # Check for static string artifact or section
        if func_name == "global_strings_section" or func_name.endswith("_section") or func_name.endswith("_strings"):
            return f"Static String Data (L{line_no}) -> {target_var} [SINK]"

        # Parse signature and function parameters
        sig_line_no = 1
        params: Dict[str, int] = {}
        ignored_params = {"env", "thiz", "this", "JNIEnv", "jobject", "void", ""}

        for idx, line in enumerate(code_lines[:trigger_idx]):
            clean = line.strip()
            if func_name in line and "(" in line and not clean.startswith("/*"):
                sig_line_no = idx + 1
                m = re.search(r'\((.*?)\)', line)
                if m:
                    for p in m.group(1).split(','):
                        tokens = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', p.strip())
                        if tokens:
                            v = tokens[-1]
                            if v not in ignored_params:
                                params[v] = sig_line_no
                break

        # Identify sink function if applicable
        sink_func = None
        sink_match = re.search(
            r'\b(popen|system|execve|execl|strcpy|strcat|strncpy|strncat|sprintf|snprintf|printf|vfprintf|syslog|free|malloc|open|mkdir|socket|bind|connect|GetStringUTFChars|ReleaseStringUTFChars|FindClass|GetStaticMethodID|GetMethodID|CallObjectMethod|CallVoidMethod|srand|rand)\b\s*\(',
            trigger_line
        )
        if sink_match:
            sink_func = sink_match.group(1)

        # Collect variable assignment / copy dependencies prior to trigger line
        deps = []  # list of (l_no, dest_var, src_vars)
        for idx in range(sig_line_no - 1, trigger_idx):
            l_text = code_lines[idx]
            l_no = idx + 1
            l_clean = l_text.strip()
            if l_clean.startswith(("if", "return", "while", "for", "switch", "/*")):
                continue

            # Strip string literals so identifiers inside quotes are ignored
            l_no_str = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', l_clean)

            # Function copy/format calls (e.g., strcpy(cfg_buf, config_input))
            copy_m = re.search(r'\b(strcpy|strcat|strncpy|strncat|memcpy|sprintf|snprintf)\b\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*(.*)', l_no_str)
            if copy_m:
                dest = copy_m.group(2)
                rest = copy_m.group(3)
                src_ids = [
                    i for i in re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', rest)
                    if i not in {"env", "thiz", "this", "NULL", "sizeof", "int", "char", "void", "const", "unsigned", "long"}
                ]
                deps.append((l_no, dest, src_ids))
                continue

            # Assignment statements (e.g. config_input = (*env)->GetStringUTFChars(env, j_cfg, 0))
            assign_m = re.search(r'(?:[a-zA-Z_][a-zA-Z0-9_*\s]*\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=|\^=|\+=|-=|\*=)\s*(.*)', l_no_str)
            if assign_m:
                lhs = assign_m.group(1)
                rhs = assign_m.group(2)
                if lhs not in {"if", "return", "while", "for", "switch", "char", "int", "const", "void", "long"}:
                    src_ids = [
                        i for i in re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', rhs)
                        if i not in {lhs, "env", "thiz", "this", "GetStringUTFChars", "NULL", "0", "1", "2", "malloc", "rand", "time", "sizeof", "int", "char", "void", "const", "unsigned", "long"}
                    ]
                    deps.append((l_no, lhs, src_ids))
                    continue

        # Extract argument identifiers from trigger_line call
        call_args_m = re.search(r'\((.*)\)', trigger_line)
        args_list = []
        if call_args_m:
            raw_args = call_args_m.group(1).split(',')
            for a in raw_args:
                ids = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', a)
                for identifier in ids:
                    if identifier not in {"env", "thiz", "this", "NULL", "r", "w", "stdout", "sizeof", "int", "char", "void", "const"}:
                        args_list.append(identifier)
                        break

        start_var = target_var if (target_var and target_var not in {"env", "thiz", "this"}) else (args_list[0] if args_list else None)

        # Build node trace backward
        nodes = []
        if sink_func:
            nodes.append((f"{sink_func} [SINK]", line_no))
        elif start_var:
            nodes.append((f"{start_var} [SINK]", line_no))
        else:
            nodes.append(("Call [SINK]", line_no))

        curr_var = start_var
        visited_lines = set()

        while curr_var:
            if curr_var in params:
                nodes.append((curr_var, params[curr_var]))
                break

            found_dep = False
            for l_no, dest, src_ids in reversed(deps):
                if dest == curr_var and l_no not in visited_lines:
                    visited_lines.add(l_no)
                    nodes.append((curr_var, l_no))
                    curr_var = src_ids[0] if src_ids else None
                    found_dep = True
                    break

            if not found_dep:
                if curr_var in params:
                    nodes.append((curr_var, params[curr_var]))
                elif params:
                    p_name, p_line = list(params.items())[0]
                    nodes.append((p_name, p_line))
                else:
                    nodes.append((curr_var, sig_line_no))
                break

        nodes.reverse()
        formatted_nodes = []
        for item, l_num in nodes:
            if "[SINK]" in item:
                clean_item = item.replace(" [SINK]", "")
                s = f"{clean_item} (L{l_num}) [SINK]"
            else:
                s = f"{item} (L{l_num})"
            if not formatted_nodes or formatted_nodes[-1] != s:
                formatted_nodes.append(s)

        return " -> ".join(formatted_nodes)

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
        arg_match = re.search(r'\((.*)\)', trigger_line)
        if arg_match:
            raw_args = arg_match.group(1).split(',')
            for arg_str in raw_args:
                var = arg_str.strip()
                var = re.sub(r'^\*|^\&|^\([^\)]+\)\s*', '', var).strip()
                id_match = re.search(r'\b[a-zA-Z_][a-zA-Z0-9_]*(?:\[[^\]]+\])?\b', var)
                if id_match:
                    id_val = id_match.group(0)
                    if id_val and id_val not in {"env", "thiz", "this", "void", "NULL", "0", "1"}:
                        return id_val

        # 5. Variable assignment LHS: e.g. var = rand() or buf[i] ^= 0x5A
        assign_match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*(?:\[[^\]]+\])?)\s*(?:=|\^=|\+=|-=|\*=)', trigger_line)
        if assign_match:
            var = assign_match.group(1).strip()
            if var and var not in {"env", "thiz", "this", "if", "return", "while", "for"}:
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

    def _scan_function_with_patterns(
        self,
        binary: Optional[ParsedBinary] = None,
        rule_override: Optional[Rule] = None
    ) -> List[Finding]:
        """
        Standardized scanner iterating through functions and matching rule patterns.
        Extracts fine-grained sub-rule IDs, severity, and confidence from matched RulePattern objects.
        
        @param binary Optional ParsedBinary payload with decompiled C code and metadata.
        @param rule_override Optional custom Rule object overriding self.rule.
        @return List[Finding] Generated vulnerability findings.
        """
        if binary is None and self.context is not None:
            binary = self.context.parsed_binary

        if binary is None:
            return []

        if self.context and self.context.code_scope and not binary.functions_code_scope:
            binary.functions_code_scope = dict(self.context.code_scope)

        target_rule = rule_override if rule_override else self.rule
        findings: List[Finding] = []
        seen_function_scopes = set()

        patterns = target_rule.patterns if isinstance(target_rule.patterns, list) else []
        for func in binary.functions:
            is_string_sec_func = (
                func.name == "global_strings_section" or
                func.name.endswith("_section") or
                func.name.endswith("_strings")
            )
            if not is_string_sec_func:
                binary.functions_code_scope[func.name] = func.code_lines

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

                    # Scope-based deduplication per sub-rule ID per line or function
                    if self._is_aggregatable(sub_rule_id):
                        scope_key = (sub_rule_id, func.name, idx)
                    else:
                        scope_key = (sub_rule_id, func.name)

                    if scope_key in seen_function_scopes:
                        continue

                    # Match regex pattern against C line
                    if pat_str and re.search(pat_str, line):
                        # Mark scope as analyzed to enforce single finding per sub-rule per function
                        seen_function_scopes.add(scope_key)

                        var_name = self._extract_target_variable(line, pat_str)
                        line_no = idx + 1

                        # Determine if target section represents static data or global string section
                        is_string_sec = (
                            is_string_sec_func or
                            self._is_aggregatable(sub_rule_id)
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
                            flow_trace = f"Static String Data (L{line_no}) -> {var_name} [SINK]"
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
                            flow_trace = self._build_flow_trace(
                                func.name,
                                func.code_lines,
                                idx,
                                pat_str,
                                var_name
                            )

                        flow = FlowAnalysis(
                            source=source_desc,
                            sink=sink_desc,
                            trigger_line_number=line_no,
                            flow_trace=flow_trace
                        )

                        prefix = sub_rule_id.split("-")[0] if "-" in sub_rule_id else sub_rule_id[:3]
                        cwe_id, masvs_id = RULE_PREFIX_MAP.get(prefix, ("CWE-693", "MASVS-CODE-2"))

                        finding = Finding(
                            finding_id=f"FIND-{len(findings)+1:02d}",
                            rule_id=sub_rule_id,
                            cwe_id=cwe_id,
                            masvs_id=masvs_id,
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
