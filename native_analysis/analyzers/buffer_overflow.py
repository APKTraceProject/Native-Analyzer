"""
[BOF-001] Buffer Overflow Vulnerability Analyzer
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding
from native_analysis.models.rule import Rule

class BufferOverflowAnalyzer(BaseAnalyzer):
    """Detects unsafe memory functions (strcpy, strcat, gets, sprintf, memcpy) without bounds check."""

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        return self._scan_function_with_patterns(binary)
