"""
[JNI-001] JNI Boundary Pointer Leak Analyzer

Provides static analysis for JNI memory reference leaks across the Java/Native C boundary,
identifying GetStringUTFChars and GetByteArrayElements allocations lacking corresponding Release calls.
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class JNIBoundaryLeaksAnalyzer(BaseAnalyzer):
    """
    Detects unreleased native string/array references acquired across JNI boundary [JNI-001].
    
    Analysis Strategy:
    1. Scans JNI exported functions for string/array pointer retrieval calls (GetStringUTFChars).
    2. Flags routines where native pointers cross boundary interfaces without clean release.
    """

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        """
        Executes static analysis to detect JNI boundary memory leaks.
        
        @param binary ParsedBinary payload containing decompiled functions and symbols.
        @return List[Finding] List of JNI-001 vulnerability findings.
        """
        # Execute pattern matching against JNI-001 rule definitions
        return self._scan_function_with_patterns(binary)
