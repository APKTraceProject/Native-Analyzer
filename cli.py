#!/usr/bin/env python3
"""
APKTrace - Native Security Analysis Standalone CLI Test Driver

Command-line interface driver for running static vulnerability analysis against Android
native shared libraries (.so / ELF binaries). Handles argument parsing, configuration loading,
logging, target verification, engine execution, and JSON report generation.
"""

import sys
import os
import argparse
import traceback
from typing import Optional, List, Dict, Tuple, Any

# ANSI Color Codes for terminal UI
COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[92m"
COLOR_CYAN = "\033[96m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_BOLD = "\033[1m"
COLOR_DIM = "\033[2m"

def print_header():
    """Prints clean ASCII terminal banner for the APKTrace engine."""
    banner = f"""{COLOR_CYAN}{COLOR_BOLD}
    _   ___ _  _______                 
   /_\ | _ \ |/ /_   _| __ __ _ ___ ___
  / _ \|  _/ ' <  | | | '__/ _` / _| _/
 /_/ \_\_| |_|\_\ |_| |_|  \__,_\__|___|

  APKTrace - Native Analysis Module
  Specialized native binary analysis sub-component of the APKTrace ecosystem
======================================================================{COLOR_RESET}"""
    print(banner)

def print_progress(icon: str, color: str, label: str, message: str):
    """
    Prints a clean status indicator line formatted with colored ANSI tags.
    
    @param icon Symbol icon (e.g. '+', '*', 'X', '✔').
    @param color ANSI color sequence string.
    @param label Tag label (e.g. 'INFO', 'SCAN', 'TAINT', 'SUCCESS', 'ERROR').
    @param message Text status message to display.
    """
    icon_str = f"[{color}{icon}{COLOR_RESET}]"
    label_str = f"[{color}{COLOR_BOLD}{label}{COLOR_RESET}]"
    print(f" {icon_str} {label_str} {message}")

def print_execution_metadata(mode: str, target_path: str, output_path: str, binary_count: int):
    """
    Prints a formatted execution summary header displaying scan parameters.
    
    @param mode Execution mode string ('SINGLE (.so)' or 'MULTI (.apk)').
    @param target_path File path to target binary or archive.
    @param output_path File path to output JSON report.
    @param binary_count Number of target binaries identified for scanning.
    """
    print(f"\n{COLOR_CYAN}{COLOR_BOLD}----------------------------------------------------------------------{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD} EXECUTION METADATA{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}----------------------------------------------------------------------{COLOR_RESET}")
    print(f"  * Mode:                    {COLOR_BOLD}{mode}{COLOR_RESET}")
    print(f"  * Target File:             {target_path}")
    print(f"  * Output Path:             {output_path}")
    print(f"  * Identified Binaries:     {COLOR_BOLD}{binary_count} target(s){COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}----------------------------------------------------------------------{COLOR_RESET}\n")

def build_rule_category_map(rules_path: str = "config/rules.yaml") -> Dict[str, str]:
    """
    Builds a lookup map from rule/pattern IDs to human-readable vulnerability categories.
    
    @param rules_path Path to rules configuration YAML file.
    @return Dict[str, str] Rule ID to category mapping.
    """
    rule_map = {}
    try:
        from native_analysis.core.config_loader import ConfigLoader
        rules_data = ConfigLoader.load_rules(rules_path)
        for rule in rules_data.get("rules", []):
            cat = rule.get("category") or rule.get("name") or "General Vulnerability"
            if "id" in rule:
                rule_map[rule["id"]] = cat
            for pat in rule.get("patterns", []):
                if "id" in pat:
                    rule_map[pat["id"]] = cat
    except Exception:
        pass
    return rule_map

def get_finding_category(rule_id: str, rule_map: Dict[str, str]) -> str:
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
        "PERM": "File Permission Flaws",
        "RND": "Insecure Randomness",
        "RNG": "Insecure Randomness",
        "RAND": "Insecure Randomness",
        "CRY": "Weak Cryptography",
        "NPD": "Null Pointer Dereference",
        "NULL": "Null Pointer Dereference",
        "IPC": "Insecure IPC",
        "DBG": "Anti-Debugging",
        "FRD": "Anti-Root & Frida Detection",
        "ROOT": "Anti-Root & Frida Detection",
        "STR": "String Obfuscation"
    }
    return prefix_map.get(prefix, f"Category ({prefix})")

def print_summary_table(scanned_targets: List[Tuple[Any, List[Any]]], rules_path: str = "config/rules.yaml"):
    """
    Prints a concise post-scan summary table in the terminal displaying scan statistics.
    
    @param scanned_targets List of (ParsedBinary, List[Finding]) scan output tuples.
    @param rules_path Path to rules file for category resolution.
    """
    rule_map = build_rule_category_map(rules_path)
    total_files = len(scanned_targets)
    all_findings = []
    for _, findings in scanned_targets:
        all_findings.extend(findings)
    total_findings = len(all_findings)

    # Severity counts
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    cat_counts = {}

    for finding in all_findings:
        sev = getattr(finding, "severity", "MEDIUM").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["MEDIUM"] += 1

        rule_id = getattr(finding, "rule_id", "GEN-000")
        cat = get_finding_category(rule_id, rule_map)
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    print(f"\n{COLOR_CYAN}{COLOR_BOLD}======================================================================{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}                      SCAN SUMMARY RESULTS                            {COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}======================================================================{COLOR_RESET}")
    print(f"  Total Target Files Scanned : {COLOR_BOLD}{total_files}{COLOR_RESET}")
    print(f"  Total Vulnerabilities Found: {COLOR_BOLD}{total_findings}{COLOR_RESET}")
    print(f"{COLOR_CYAN}----------------------------------------------------------------------{COLOR_RESET}")
    print(f"{COLOR_BOLD}  SEVERITY BREAKDOWN{COLOR_RESET}")
    print(f"{COLOR_CYAN}----------------------------------------------------------------------{COLOR_RESET}")
    
    crit_str = f"{COLOR_RED}{COLOR_BOLD}{sev_counts['CRITICAL']}{COLOR_RESET}" if sev_counts['CRITICAL'] > 0 else "0"
    high_str = f"{COLOR_YELLOW}{COLOR_BOLD}{sev_counts['HIGH']}{COLOR_RESET}" if sev_counts['HIGH'] > 0 else "0"
    med_str = f"{COLOR_CYAN}{sev_counts['MEDIUM']}{COLOR_RESET}" if sev_counts['MEDIUM'] > 0 else "0"
    low_str = f"{COLOR_GREEN}{sev_counts['LOW']}{COLOR_RESET}" if sev_counts['LOW'] > 0 else "0"

    print(f"   CRITICAL :  {crit_str}")
    print(f"   HIGH     :  {high_str}")
    print(f"   MEDIUM   :  {med_str}")
    print(f"   LOW      :  {low_str}")

    if cat_counts:
        print(f"{COLOR_CYAN}----------------------------------------------------------------------{COLOR_RESET}")
        print(f"{COLOR_BOLD}  TOP CATEGORIES DETECTED{COLOR_RESET}")
        print(f"{COLOR_CYAN}----------------------------------------------------------------------{COLOR_RESET}")
        sorted_cats = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)
        for cat_name, count in sorted_cats[:5]:
            print(f"   {cat_name:<35}: {COLOR_BOLD}{count}{COLOR_RESET}")
    
    print(f"{COLOR_CYAN}{COLOR_BOLD}======================================================================{COLOR_RESET}\n")

def format_exception_log(e: Exception) -> str:
    """
    Formats exception details explicitly including File Name and Line Number in bold red.
    Format example: Error in target_resolver.py:L42 - File not found
    
    @param e Exception instance captured during runtime execution.
    @return str Formatted error message string with ANSI color coding.
    """
    tb = traceback.extract_tb(e.__traceback__)
    if tb:
        last_frame = tb[-1]
        for frame in reversed(tb):
            if "native_analysis" in frame.filename or frame.filename.endswith(".py"):
                last_frame = frame
                break
        filename = os.path.basename(last_frame.filename)
        lineno = last_frame.lineno
        err_msg = str(e) or type(e).__name__
        return f"{COLOR_BOLD}{COLOR_RED}Error in {filename}:L{lineno} - {err_msg}{COLOR_RESET}"
    return f"{COLOR_BOLD}{COLOR_RED}Error in cli.py - {type(e).__name__}: {str(e)}{COLOR_RESET}"

def main():
    """
    Main CLI entry point orchestrating configuration loading, scan engine execution, and report writing.
    """
    print_header()

    # Parse command line flags
    parser = argparse.ArgumentParser(description="APKTrace - Native Analysis CLI Utility")
    parser.add_argument("-c", "--config", default="config/cli_config.yaml", help="Path to CLI config YAML file")
    parser.add_argument("-t", "--target", help="Path to target file (.so or .apk)")
    parser.add_argument("-o", "--output", help="Path to output JSON report file")
    args = parser.parse_args()

    # Step 1: Configuration loading
    print_progress("+", COLOR_GREEN, "INFO", "Loading configuration & rules...")
    try:
        from native_analysis.core.config_loader import ConfigLoader
        cli_config = ConfigLoader.load_cli_config(args.config)
        config_used = cli_config.get("_config_file_used") or args.config
        print_progress("+", COLOR_GREEN, "INFO", f"Config loaded successfully from '{config_used}'.")

        raw_target = args.target if args.target else cli_config.get("target_path")
        if not raw_target:
            raise ValueError("Target path not specified. Please pass -t/--target or configure target_path in cli_config.yaml.")

        target_path = ConfigLoader.resolve_target_path(raw_target)
        if not target_path or not os.path.exists(target_path):
            raise FileNotFoundError(f"Target binary '{raw_target}' not found.")

        output_path = args.output if args.output else cli_config.get("output_json_path", "./output/report.json")
        engine_type = cli_config.get("engine", "ghidra")
        decompiler_path = cli_config.get("decompiler_path")

        # Verify target file extension
        ext = os.path.splitext(target_path)[1].lower()
        if ext not in (".so", ".apk"):
            raise ValueError(f"Invalid target file extension '{ext}'. Only .so (Single Mode) and .apk (Multi Mode) are supported.")

        target_filename = os.path.basename(target_path)

        from native_analysis.core.engine import ScanEngine
        from native_analysis.reporters.json_reporter import JSONReporter

        # Initialize scan engine
        engine = ScanEngine(
            rules_path="config/rules.yaml",
            decompiler_path=decompiler_path,
            engine=engine_type
        )

        # Step 2: Target identification and execution metadata header
        if ext == ".so":
            mode_str = "SINGLE (.so)"
            binary_count = 1
        else:
            mode_str = "MULTI (.apk)"
            print_progress("*", COLOR_CYAN, "SCAN", f"Extracting native targets from APK archive '{target_filename}'...")
            resolved_targets = engine.resolve_target(target_path)
            binary_count = len(resolved_targets)
            
            total_found = sum(1 + len(t[3]) for t in resolved_targets if len(t) > 3)
            if binary_count == 1 and len(resolved_targets[0]) >= 3:
                lib_filename = os.path.basename(resolved_targets[0][1])
                primary_abi = resolved_targets[0][2]
                print_progress("+", COLOR_GREEN, "INFO", f"Found {total_found} binaries across ABIs -> Deduplicated to 1 primary target ({lib_filename} - {primary_abi})")
            else:
                print_progress("+", COLOR_GREEN, "INFO", f"Found {total_found} binaries across ABIs -> Deduplicated to {binary_count} primary targets")

        # Print formatted execution metadata header
        print_execution_metadata(
            mode=mode_str,
            target_path=target_path,
            output_path=output_path,
            binary_count=binary_count
        )

        # Step 3: Progressive scan stages
        engine_label = "Radare2" if engine_type == "radare2" else "Ghidra"
        print_progress("*", COLOR_CYAN, "SCAN", f"Decompiling & analyzing symbols via {engine_label}...")
        print_progress("*", COLOR_YELLOW, "TAINT", "Running variable flow analysis & JNI context extraction...")

        # Run scan (.so single mode or .apk multi mode)
        scanned_targets = engine.scan(target_path)

        # Step 4: Report generation
        JSONReporter.generate_report(
            scanned_targets=scanned_targets,
            output_file_path=output_path,
            analysis_engine=engine_type
        )

        print_progress("✔", COLOR_GREEN, "SUCCESS", f"Report generated successfully at {output_path}")

        # Step 5: Post-scan terminal summary table
        print_summary_table(scanned_targets, rules_path="config/rules.yaml")

    except Exception as e:
        print_progress("X", COLOR_RED, "ERROR", format_exception_log(e))
        sys.exit(1)

if __name__ == "__main__":
    main()
