"""
[DBG-001] Anti-Debugging Vulnerability Analyzer
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class AntiDebuggingAnalyzer(BaseAnalyzer):
    """Detects anti-debugging traps, ptrace checks, or status inspection."""

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        return self._scan_function_with_patterns(binary)
