"""
JSON Report Generator module producing structured vulnerability report schemas.
"""

import json
import os
from typing import List, Dict, Any, Tuple, Optional
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

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

            findings_json = []
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

                f_dict = f.to_dict()
                findings_json.append(f_dict)

            vulnerable_jni_count = len(vulnerable_jni_funcs)

            # Filter real functions excluding synthetic string metadata sections
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

        # Write formatted JSON output file to disk
        if output_file_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_file_path)), exist_ok=True)
            with open(output_file_path, "w", encoding="utf-8") as f:
                json.dump(report_payload, f, indent=2)

        return report_payload

