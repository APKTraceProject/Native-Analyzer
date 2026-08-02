"""
[IPC-001] Insecure IPC Analyzer
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class InsecureIPCAnalyzer(BaseAnalyzer):
    """Detects unencrypted UNIX domain sockets and local IPC bindings."""

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        return self._scan_function_with_patterns(binary)
