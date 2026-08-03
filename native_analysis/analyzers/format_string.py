"""
[FMT-001] Format String Vulnerability Analyzer

Provides static analysis for non-literal format string vulnerabilities in Android C/C++ native binaries,
identifying direct variable formatting calls in printf, syslog, vfprintf, and __android_log_print routines.
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class FormatStringAnalyzer(BaseAnalyzer):
    """
    Detects non-literal format specifiers passed to variadic output functions [FMT-001].
    
    Analysis Strategy:
    1. Evaluates variadic printing calls (printf, syslog, vfprintf, __android_log_print).
    2. Flags occurrences where variable inputs serve directly as format strings without string literals.
    """

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        """
        Executes static analysis to catch format string vulnerability patterns.
        
        @param binary ParsedBinary payload containing decompiled functions and symbols.
        @return List[Finding] List of FMT-001 vulnerability findings.
        """
        # Execute pattern matching against FMT-001 rule definitions
        return self._scan_function_with_patterns(binary)
