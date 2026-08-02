"""
[CMD-001] Command Injection Vulnerability Analyzer
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class CommandInjectionAnalyzer(BaseAnalyzer):
    """Detects command injection sinks (system, popen, execve, execl)."""

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        return self._scan_function_with_patterns(binary)
