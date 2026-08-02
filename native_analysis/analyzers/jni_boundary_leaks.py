"""
[JNI-001] JNI Boundary Pointer Leak Analyzer
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class JNIBoundaryLeaksAnalyzer(BaseAnalyzer):
    """Detects JNI boundary string/byte array allocation without release."""

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        return self._scan_function_with_patterns(binary)
