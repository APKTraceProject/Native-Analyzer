"""
[FMT-001] Format String Vulnerability Analyzer
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class FormatStringAnalyzer(BaseAnalyzer):
    """Detects format string vulnerabilities in printf, sprintf, __android_log_print."""

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        return self._scan_function_with_patterns(binary)
