"""
[REF-001] JNI Reflection Abuse Analyzer

Provides static analysis for dynamic Java reflection calls executed from native C/C++ code via JNI,
identifying FindClass, GetMethodID, GetStaticMethodID, and Call*Method reflection chains.
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class JNIReflectionAbuseAnalyzer(BaseAnalyzer):
    """
    Detects dynamic Java reflection access and class manipulation from native layer [REF-001].
    
    Analysis Strategy:
    1. Evaluates JNI environment calls for class resolution (FindClass) and method lookup (GetMethodID).
    2. Flags invocation chains bypassing Java language access controls from C code.
    """

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        """
        Executes static analysis to detect JNI reflection abuse patterns.
        
        @param binary ParsedBinary payload containing decompiled functions and symbols.
        @return List[Finding] List of REF-001 vulnerability findings.
        """
        # Execute pattern matching against REF-001 rule definitions
        return self._scan_function_with_patterns(binary)
