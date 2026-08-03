"""
[BOF-001] Buffer Overflow Vulnerability Analyzer

Provides static analysis for stack and heap buffer overflow conditions in Android C/C++ native binaries,
identifying unsafe memory and string copy routines (strcpy, strcat, gets, sprintf, memcpy) operating without
explicit buffer bounds enforcement.
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding
from native_analysis.models.rule import Rule

class BufferOverflowAnalyzer(BaseAnalyzer):
    """
    Detects unsafe memory operations and unbounded string copy calls [BOF-001].
    
    Analysis Strategy:
    1. Evaluates decompiled functions against BOF-001 rule regex patterns.
    2. Identifies calls to legacy memory routines lacking bounds parameters.
    3. Extracts surrounding code context window and computes parameter data flows.
    """

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        """
        Executes static analysis to detect potential buffer overflow vulnerabilities.
        
        @param binary ParsedBinary payload containing decompiled functions and symbols.
        @return List[Finding] List of BOF-001 vulnerability findings.
        """
        # Execute pattern matching against BOF-001 rule definitions
        return self._scan_function_with_patterns(binary)
