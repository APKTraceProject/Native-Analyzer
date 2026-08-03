"""
[CMD-001] Command Injection Vulnerability Analyzer

Provides static analysis for shell command injection flaws in Android C/C++ native binaries,
detecting unsanitized input passed to process execution sinks (system, popen, execve, execl).
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class CommandInjectionAnalyzer(BaseAnalyzer):
    """
    Detects OS command execution sinks and unsanitized subprocess spawners [CMD-001].
    
    Analysis Strategy:
    1. Scans decompiled native functions for process spawning sinks (system, popen, execve).
    2. Identifies data flow parameters passed from JNI string imports into shell execution calls.
    """

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        """
        Executes static analysis to detect shell command injection vulnerabilities.
        
        @param binary ParsedBinary payload containing decompiled functions and symbols.
        @return List[Finding] List of CMD-001 vulnerability findings.
        """
        # Execute pattern matching against CMD-001 rule definitions
        return self._scan_function_with_patterns(binary)
