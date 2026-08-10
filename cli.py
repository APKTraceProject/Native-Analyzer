#!/usr/bin/env python3
"""
APKTrace - Native Security Analysis Standalone CLI Test Driver

Command-line interface driver for native vulnerability analysis against Android shared libraries (.so / ELF).
Acts strictly as a configuration reader and terminal UI renderer, delegating all pipeline execution,
sub-module orchestration, and report generation to core/engine.py.
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

COLOR_MAP = {
    "COLOR_RESET": COLOR_RESET,
    "COLOR_GREEN": COLOR_GREEN,
    "COLOR_CYAN": COLOR_CYAN,
    "COLOR_YELLOW": COLOR_YELLOW,
    "COLOR_RED": COLOR_RED,
    "COLOR_BOLD": COLOR_BOLD,
    "COLOR_DIM": COLOR_DIM,
}

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

def print_execution_metadata(summary: Dict[str, Any]):
    """
    Prints a formatted execution summary header displaying scan metadata, decompiler info, and parameters.
    
    @param summary Structured execution summary payload returned from core/engine.py.
    """
    metadata = summary.get("metadata", {})
    cfg_content = metadata.get("config_content", {})
    exec_info = metadata.get("execution", {})

    target_path = cfg_content.get("target_path", "N/A")
    output_path = cfg_content.get("output_json_path", "N/A")
    output_decompiler_path = cfg_content.get("output_decompiler_path", "N/A")
    decompiler_name = (cfg_content.get("decompiler") or "ghidra").upper()
    decompiler_path = cfg_content.get("decompiler_path") or "Default System Path"
    config_file = metadata.get("config_file", "N/A")

    mode = "MULTI (.apk)" if str(target_path).lower().endswith(".apk") else "SINGLE (.so)"
    
    duration = exec_info.get("duration_seconds", 0.0)
    timestamp = exec_info.get("timestamp")
    active_analyzers = exec_info.get("active_analyzers", [])

    decompiler_badge = f"{COLOR_CYAN}{COLOR_BOLD}[{decompiler_name}]{COLOR_RESET}"

    print(f"\n{COLOR_CYAN}{COLOR_BOLD}----------------------------------------------------------------------{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD} EXECUTION METADATA & CONFIGURATION{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}----------------------------------------------------------------------{COLOR_RESET}")
    print(f"  * Mode:                    {COLOR_BOLD}{mode}{COLOR_RESET}")
    print(f"  * Target File:             {target_path}")
    print(f"  * Output Report Path:      {output_path}")
    print(f"  * Output Decompiler Path:  {output_decompiler_path}")
    print(f"  * Config File:             {config_file}")
    print(f"  * Decompiler Engine:       {decompiler_badge}")
    if decompiler_path and decompiler_path != "Default System Path":
        print(f"  * Decompiler Binary:       {decompiler_path}")
    if duration > 0:
        ts_str = f" ({timestamp})" if timestamp else ""
        print(f"  * Execution Time:          {COLOR_BOLD}{duration}s{COLOR_RESET}{ts_str}")
    if active_analyzers:
        print(f"  * Active Analyzers:        {COLOR_BOLD}{len(active_analyzers)} module(s){COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}----------------------------------------------------------------------{COLOR_RESET}\n")

def print_summary_table(summary: Dict[str, Any]):
    """
    Prints a concise post-scan summary table in the terminal displaying top-level scan metrics.
    
    @param summary Structured summary payload returned from core/engine.py.
    """
    sum_data = summary.get("summary", {})
    scanned_files_count = sum_data.get("scanned_files_count", 0)
    primary_abi = sum_data.get("primary_abi", "N/A")
    discovered_abis = sum_data.get("discovered_abis", [])
    disc_abis_str = ", ".join(discovered_abis) if discovered_abis else "N/A"
    total_vulnerabilities = sum_data.get("total_vulnerabilities", 0)

    abi_badge = f"{COLOR_GREEN}{COLOR_BOLD}[{primary_abi}]{COLOR_RESET}" if primary_abi != "N/A" else f"{COLOR_DIM}N/A{COLOR_RESET}"

    print(f"\n{COLOR_CYAN}{COLOR_BOLD}======================================================================{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}                      SCAN SUMMARY RESULTS                            {COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}======================================================================{COLOR_RESET}\n")
    print(f"Total Target Files Scanned : {COLOR_BOLD}{scanned_files_count}{COLOR_RESET}")
    if discovered_abis:
        print(f"Discovered ABIs            : {COLOR_BOLD}{disc_abis_str}{COLOR_RESET}")
    print(f"Primary Target ABI         : {abi_badge}")
    print(f"Total Vulnerabilities Found: {COLOR_BOLD}{total_vulnerabilities}{COLOR_RESET}")
    print(f"\n{COLOR_CYAN}{COLOR_BOLD}======================================================================{COLOR_RESET}\n")

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
    Main CLI entry point acting strictly as Configuration Reader and Terminal Output Renderer.
    Delegates all execution pipeline logic, task orchestration, and report building to core/engine.py.
    """
    print_header()

    # Parse command line flags
    parser = argparse.ArgumentParser(description="APKTrace - Native Analysis CLI Utility")
    parser.add_argument("-c", "--config", default="config/cli_config.yaml", help="Path to CLI config YAML file")
    parser.add_argument("-t", "--target", help="Path to target file (.so or .apk)")
    parser.add_argument("-o", "--output", help="Path to output JSON report file")
    parser.add_argument("-d", "--decompiler", help="Selected decompiler choice ('ghidra' or 'radare2')")
    parser.add_argument("-e", "--output-decompiler", "--decompiler-output", dest="output_decompiler_path", help="Directory path for storing raw decompiler project database, artifacts, logs, and outputs")
    args = parser.parse_args()

    # Step 1: Read configuration options directly from file and CLI flag overrides
    print_progress("+", COLOR_GREEN, "INFO", "Loading configuration & rules...")
    try:
        from native_analysis.core.config_loader import ConfigLoader
        cli_config = ConfigLoader.load_cli_config(args.config)
        config_used = cli_config.get("_config_file_used") or args.config

        raw_target = args.target if args.target else cli_config.get("target_path")
        if not raw_target:
            raise ValueError("Target path not specified. Please pass -t/--target or configure target_path in cli_config.yaml.")

        target_path = ConfigLoader.resolve_target_path(raw_target)
        if not target_path or not os.path.exists(target_path):
            raise FileNotFoundError(f"Target binary '{raw_target}' not found.")

        output_path = args.output if args.output else cli_config.get("output_json_path", "./output/report.json")
        output_decompiler_path = args.output_decompiler_path if args.output_decompiler_path else cli_config.get("output_decompiler_path")
        if output_decompiler_path:
            output_decompiler_path = os.path.abspath(output_decompiler_path)
            os.makedirs(output_decompiler_path, exist_ok=True)

        decompiler = args.decompiler if args.decompiler else cli_config.get("decompiler", "ghidra")
        decompiler_path = cli_config.get("decompiler_path")

        # Step 2: Call core/engine.py start entrypoint with loaded parameters
        from native_analysis.core.engine import start

        summary = start(
            target_path=target_path,
            decompiler=decompiler,
            decompiler_path=decompiler_path,
            output_decompiler_path=output_decompiler_path,
            output_json_path=output_path,
            config_file_used=config_used
        )

        # Step 4: Render progress logs & execution metadata in terminal
        metadata_printed = False
        for item in summary.get("progress_logs", []):
            if len(item) == 4:
                icon, col_key, label, msg = item
                color = COLOR_MAP.get(col_key, COLOR_RESET)

                # Render execution metadata header right before decompilation phase
                if label in ("SCAN", "TAINT") and "Decompiling" in msg and not metadata_printed:
                    print_execution_metadata(summary)
                    metadata_printed = True

                print_progress(icon, color, label, msg)

        # Fallback metadata display if not printed during logs
        if not metadata_printed:
            print_execution_metadata(summary)

        # Step 5: Render terminal summary results or error status
        if summary.get("success"):
            print_summary_table(summary)
        else:
            err_msg = summary.get("error", "Engine execution failed.")
            print_progress("X", COLOR_RED, "ERROR", err_msg)
            sys.exit(1)

    except Exception as e:
        print_progress("X", COLOR_RED, "ERROR", format_exception_log(e))
        sys.exit(1)

if __name__ == "__main__":
    main()
