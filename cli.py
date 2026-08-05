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
from typing import Optional

# ANSI Color Codes for terminal UI
COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[92m"
COLOR_CYAN = "\033[96m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_BOLD = "\033[1m"

def print_header():
    """Prints clean ASCII terminal banner and header for the APKTrace engine."""
    header = f"""
{COLOR_CYAN}{COLOR_BOLD}====================================================
           APKTrace - Native Analysis               
    Android Native Binary Vulnerability Scanner     
===================================================={COLOR_RESET}
"""
    print(header)

def print_status(icon: str, color: str, message: str):
    """
    Prints a concise status line formatted with colored ANSI icon brackets.
    
    @param icon Character or symbol icon (e.g. '+', '*', 'X', '✓').
    @param color ANSI color sequence string.
    @param message Text status message to display.
    """
    print(f" [{color}{icon}{COLOR_RESET}] {message}")

def format_exception_log(e: Exception) -> str:
    """
    Formats exception details including relative file path, line number, method name, and message.
    
    @param e Exception instance captured during runtime execution.
    @return str Multi-line formatted error traceback string.
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

def main():
    """
    Main CLI entry point orchestrating configuration loading, scan engine execution, and report writing.
    
    Execution Flow:
    1. Displays ASCII banner and parses command-line arguments (-c, -t, -o).
    2. Loads rules and CLI configuration parameters via ConfigLoader.
    3. Verifies target file on disk.
    4. Initializes ScanEngine and runs static vulnerability scan.
    5. Exports 3-tier structured JSON report artifact via JSONReporter.
    """
    print_header()

    # Parse command line flags or use config defaults
    parser = argparse.ArgumentParser(description="APKTrace - Native Analysis CLI Utility")
    parser.add_argument("-c", "--config", default="config/cli_config.yaml", help="Path to CLI config YAML file")
    parser.add_argument("-t", "--target", help="Path to target .so binary file")
    parser.add_argument("-o", "--output", help="Path to output JSON report file")
    args = parser.parse_args()

    # Load configuration
    try:
        from native_analysis.core.config_loader import ConfigLoader
        cli_config = ConfigLoader.load_cli_config(args.config)
        print_status("+", COLOR_GREEN, "Config and rules loaded successfully.")
    except Exception as e:
        print_status("X", COLOR_RED, format_exception_log(e))
        sys.exit(1)

    target_path = args.target if args.target else cli_config.get("target_so_path", "./tests/libnative.so")
    output_path = args.output if args.output else cli_config.get("output_json_path", "./output/report.json")
    ghidra_path = cli_config.get("ghidra_headless_path")

    # Verify target existence
    if not os.path.exists(target_path):
        print_status("X", COLOR_RED, f"Target binary '{target_path}' not found.")
        sys.exit(1)

    print_status("*", COLOR_CYAN, f"Binary analysis in progress for '{target_path}'...")

    try:
        from native_analysis.core.engine import ScanEngine
        from native_analysis.reporters.json_reporter import JSONReporter

        # Initialize scan engine
        engine = ScanEngine(
            rules_path="config/rules.yaml",
            ghidra_headless_path=ghidra_path
        )

        # Run scan
        parsed_binary, findings = engine.scan_target(
            target_so_path=target_path,
            apk_relative_path="standalone/libnative-lib.so"
        )

        # Generate JSON report
        JSONReporter.generate_report(
            scanned_targets=[(parsed_binary, findings)],
            output_file_path=output_path
        )

        print_status("✓", COLOR_GREEN, f"Scan completed successfully and JSON report saved to '{output_path}'.")

    except Exception as e:
        print_status("X", COLOR_RED, format_exception_log(e))
        sys.exit(1)

if __name__ == "__main__":
    main()
