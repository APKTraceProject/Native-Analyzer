"""
JSON Report Generator module producing structured vulnerability report schemas.
"""

import json
import os
from typing import List, Dict, Any, Tuple, Optional
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

def _build_source_code_snippets(
    code_lines: List[str],
    findings: List[Finding],
    window_size: int = 5
) -> List[str]:
    """
    Constructs localized source code snippets around finding trigger lines.
    Applies a context window (+/- window_size lines) around each finding,
    merges overlapping intervals smoothly, and includes 1-indexed line numbers.
    If there are no findings or code_lines is empty, returns formatted lines or empty list.

    @param code_lines Full list of code lines for the function.
    @param findings List of findings associated with this function.
    @param window_size Number of context lines before and after trigger line (default 5).
    @return List[str] Merged, formatted code snippet lines with line numbers.
    """
    if not code_lines:
        return []

    if not findings:
        # If no findings, return all code lines formatted with 1-based line numbers
        return [f"{idx + 1}: {line}" for idx, line in enumerate(code_lines)]

    total_lines = len(code_lines)
    intervals = []

    for f in findings:
        trigger_line = f.location.line_number
        if trigger_line <= 0:
            trigger_line = 1
        start = max(1, trigger_line - window_size)
        end = min(total_lines, trigger_line + window_size)
        intervals.append((start, end))

    # Sort intervals by start line
    intervals.sort(key=lambda x: x[0])

    # Merge overlapping or contiguous intervals
    merged_intervals = []
    for start, end in intervals:
        if not merged_intervals:
            merged_intervals.append((start, end))
        else:
            prev_start, prev_end = merged_intervals[-1]
            if start <= prev_end + 1:
                merged_intervals[-1] = (prev_start, max(prev_end, end))
            else:
                merged_intervals.append((start, end))

    # Format lines within merged intervals
    snippet_lines = []
    for i, (start, end) in enumerate(merged_intervals):
        if i > 0:
            snippet_lines.append("...")
        for line_num in range(start, end + 1):
            line_idx = line_num - 1
            if 0 <= line_idx < total_lines:
                snippet_lines.append(f"{line_num}: {code_lines[line_idx]}")

    return snippet_lines


class JSONReporter:
    """
    Generates structured vulnerability reports matching JSON schema standards.
    
    Serializes scan metadata, attack surface metrics, severity tallies,
    and taint flow context paths into standalone JSON report files.
    """

    @staticmethod
    def generate_report(
        scanned_targets: List[Tuple[ParsedBinary, List[Finding]]],
        output_file_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Builds complete JSON report dictionary and writes serialized JSON artifact to disk.
        
        @param scanned_targets List of tuples pairing ParsedBinary AST objects with list of Finding findings.
        @param output_file_path Local filesystem destination path for report.json output.
        @return Dict[str, Any] Complete structured report dictionary.
        """
        total_targets = len(scanned_targets)
        total_findings = sum(len(findings) for _, findings in scanned_targets)

        # Global metric aggregators
        summary_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        summary_by_confidence = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        summary_by_category: Dict[str, int] = {}

        targets_json_list = []

        # Iterate target binaries and serialize findings
        for binary, findings in scanned_targets:
            file_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            file_conf = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
            file_cat: Dict[str, int] = {}

            vulnerable_jni_count = 0
            vulnerable_jni_funcs = set()

            for f in findings:
                # Severity metric tally
                sev = f.severity.upper()
                if sev in summary_by_severity:
                    summary_by_severity[sev] += 1
                    file_sev[sev] += 1
                else:
                    summary_by_severity["LOW"] += 1
                    file_sev["LOW"] += 1

                # Confidence metric tally
                conf = f.confidence.upper()
                if conf in summary_by_confidence:
                    summary_by_confidence[conf] += 1
                    file_conf[conf] += 1
                else:
                    summary_by_confidence["LOW"] += 1
                    file_conf["LOW"] += 1

                # Rule category name mapping lookup using prefix (e.g. BOF from BOF-001/BOF-002)
                prefix = f.rule_id.split("-")[0] if "-" in f.rule_id else f.rule_id
                cat_map = {
                    "BOF": "Buffer Overflow",
                    "INJ": "Command Injection",
                    "FMT": "Format String",
                    "CRY": "Weak Crypto",
                    "DBG": "Anti-Debugging",
                    "MEM": "Memory Management",
                    "JNI": "JNI Boundary Leaks",
                    "PRM": "File Permission Flaws",
                    "INT": "Integer Overflow",
                    "IPC": "Insecure IPC",
                    "NUL": "Null Pointer Dereference",
                    "RND": "Insecure Randomness",
                    "REF": "JNI Reflection Abuse",
                    "FRD": "Anti-Root/Frida",
                    "STR": "String Obfuscation"
                }
                cat_name = cat_map.get(prefix, cat_map.get(f.rule_id, "Vulnerability"))

                summary_by_category[cat_name] = summary_by_category.get(cat_name, 0) + 1
                file_cat[cat_name] = file_cat.get(cat_name, 0) + 1

                # Track JNI exposed vulnerable routines
                if f.location.is_exported_jni:
                    vulnerable_jni_funcs.add(f.location.function_name)

            vulnerable_jni_count = len(vulnerable_jni_funcs)

            # Filter real functions excluding synthetic string metadata sections
            real_functions = [
                f for f in binary.functions
                if f.name != "global_strings_section" and not f.name.endswith("_section") and not f.name.endswith("_strings")
            ]

            # Group findings by function name
            findings_by_function: Dict[str, List[Finding]] = {}
            for f in findings:
                func_name = f.location.function_name
                if func_name not in findings_by_function:
                    findings_by_function[func_name] = []
                findings_by_function[func_name].append(f)

            # Construct Level 3 function objects with Level 4 findings embedded
            functions_list = []
            seen_function_names = set()

            # Process real functions
            for func in real_functions:
                seen_function_names.add(func.name)
                func_findings = findings_by_function.get(func.name, [])
                scoped_findings = [f.to_scoped_dict() for f in func_findings]
                snippet_lines = _build_source_code_snippets(func.code_lines, func_findings, window_size=5)

                functions_list.append({
                    "function_name": func.name,
                    "symbol_address": func.address,
                    "is_exported_jni": func.is_exported_jni,
                    "source_code": snippet_lines,
                    "findings": scoped_findings
                })

            # Check for static / non-function findings or virtual function blocks
            static_func_name = "N/A (Static Data Section)"
            static_findings = findings_by_function.get(static_func_name, [])
            
            # Also check if there are any findings assigned to function names not present in real_functions
            unmapped_findings = []
            for func_name, func_findings in findings_by_function.items():
                if func_name != static_func_name and func_name not in seen_function_names:
                    unmapped_findings.extend(func_findings)

            all_static_findings = static_findings + unmapped_findings

            if all_static_findings:
                functions_list.append({
                    "function_name": static_func_name,
                    "symbol_address": "N/A",
                    "is_exported_jni": False,
                    "source_code": [],
                    "findings": [f.to_scoped_dict() for f in all_static_findings]
                })

            target_entry = {
                "file_name": binary.file_name,
                "apk_relative_path": binary.apk_relative_path,
                "abi_architecture": binary.abi_architecture,
                "sha256": binary.sha256,
                "target_summary": {
                    "file_findings_count": len(findings),
                    "by_severity": file_sev,
                    "by_confidence": file_conf,
                    "by_category": file_cat,
                    "attack_surface_metrics": {
                        "total_functions_scanned": len(real_functions),
                        "exported_jni_functions": len(binary.exported_jni_functions),
                        "vulnerable_jni_functions": vulnerable_jni_count
                    }
                },
                "functions": functions_list
            }
            targets_json_list.append(target_entry)

        primary_abi = scanned_targets[0][0].primary_abi or scanned_targets[0][0].abi_architecture if scanned_targets else "N/A"
        associated_abis = []
        for binary, _ in scanned_targets:
            for abi in binary.associated_abis:
                if abi not in associated_abis:
                    associated_abis.append(abi)

        report_payload = {
            "summary": {
                "total_targets_scanned": total_targets,
                "total_findings": total_findings,
                "by_severity": summary_by_severity,
                "by_confidence": summary_by_confidence,
                "by_category": summary_by_category,
                "abi_resolution": {
                    "primary_abi": primary_abi,
                    "associated_abis": associated_abis,
                    "deduplication_enabled": True
                }
            },
            "targets": targets_json_list
        }

        # Write formatted JSON output file to disk
        if output_file_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_file_path)), exist_ok=True)
            with open(output_file_path, "w", encoding="utf-8") as f:
                json.dump(report_payload, f, indent=2)

        return report_payload

