"""
3-Tier AI Validator JSON Report Generator matching precise APKTrace schema specifications.
"""

import json
import os
from typing import List, Dict, Any, Tuple, Optional
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class JSONReporter:
    """Generates structured 3-tier JSON report for automated ingestion and AI validation."""

    @staticmethod
    def generate_report(
        scanned_targets: List[Tuple[ParsedBinary, List[Finding]]],
        output_file_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Builds complete JSON report dictionary and writes to disk if output path is provided.
        
        Args:
            scanned_targets: List of tuples (ParsedBinary, List[Finding]).
            output_file_path: Path to save the generated JSON report.
            
        Returns:
            Structured report dictionary.
        """
        total_targets = len(scanned_targets)
        total_findings = sum(len(findings) for _, findings in scanned_targets)

        summary_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        summary_by_confidence = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        summary_by_category: Dict[str, int] = {}

        targets_json_list = []

        for binary, findings in scanned_targets:
            file_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            file_conf = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
            file_cat: Dict[str, int] = {}

            findings_json = []
            vulnerable_jni_count = 0
            vulnerable_jni_funcs = set()

            for f in findings:
                # Severity tally
                sev = f.severity.upper()
                if sev in summary_by_severity:
                    summary_by_severity[sev] += 1
                    file_sev[sev] += 1
                else:
                    summary_by_severity["LOW"] += 1
                    file_sev["LOW"] += 1

                # Confidence tally
                conf = f.confidence.upper()
                if conf in summary_by_confidence:
                    summary_by_confidence[conf] += 1
                    file_conf[conf] += 1
                else:
                    summary_by_confidence["LOW"] += 1
                    file_conf["LOW"] += 1

                # Category mapping lookup
                category = f.rule_id
                cat_map = {
                    "BOF-001": "Buffer Overflow",
                    "INJ-001": "Command Injection",
                    "FMT-001": "Format String",
                    "CRY-001": "Weak Crypto",
                    "DBG-001": "Anti-Debugging",
                    "MEM-001": "Memory Management",
                    "JNI-001": "JNI Boundary Leaks",
                    "PRM-001": "File Permission Flaws",
                    "INT-001": "Integer Overflow",
                    "IPC-001": "Insecure IPC",
                    "NUL-001": "Null Pointer Dereference",
                    "RND-001": "Insecure Randomness",
                    "REF-001": "JNI Reflection Abuse",
                    "FRD-001": "Anti-Root/Frida",
                    "STR-001": "String Obfuscation"
                }
                cat_name = cat_map.get(category, "Vulnerability")

                summary_by_category[cat_name] = summary_by_category.get(cat_name, 0) + 1
                file_cat[cat_name] = file_cat.get(cat_name, 0) + 1

                if f.location.is_exported_jni:
                    vulnerable_jni_funcs.add(f.location.function_name)

                f_dict = f.to_dict()
                f_dict["target_file"] = binary.apk_relative_path
                findings_json.append(f_dict)

            vulnerable_jni_count = len(vulnerable_jni_funcs)

            real_functions = [
                f for f in binary.functions
                if f.name != "global_strings_section" and not f.name.endswith("_section") and not f.name.endswith("_strings")
            ]

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
                "findings": findings_json
            }
            targets_json_list.append(target_entry)

        report_payload = {
            "summary": {
                "total_targets_scanned": total_targets,
                "total_findings": total_findings,
                "by_severity": summary_by_severity,
                "by_confidence": summary_by_confidence,
                "by_category": summary_by_category
            },
            "targets": targets_json_list
        }

        if output_file_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_file_path)), exist_ok=True)
            with open(output_file_path, "w", encoding="utf-8") as f:
                json.dump(report_payload, f, indent=2)

        return report_payload
