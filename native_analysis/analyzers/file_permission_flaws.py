"""
[PRM-001] File Permission Flaws Analyzer
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class FilePermissionFlawsAnalyzer(BaseAnalyzer):
    """Detects overly permissive file modes (chmod 0777, umask 0)."""

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        return self._scan_function_with_patterns(binary)
