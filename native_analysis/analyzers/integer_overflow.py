"""
[INT-001] Integer Overflow Analyzer

Provides static analysis for arithmetic integer overflow conditions in Android C/C++ native binaries,
detecting arithmetic operations (count * size) inside dynamic heap allocation calls (malloc, calloc).
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class IntegerOverflowAnalyzer(BaseAnalyzer):
    """
    Detects unverified integer arithmetic operations within dynamic allocation sizes [INT-001].
    
    Analysis Strategy:
    1. Evaluates dynamic allocation functions (malloc, calloc, realloc) in decompiled functions.
    2. Flags inline arithmetic multiplication/addition expressions within allocation parameters.
    """

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        """
        Executes static analysis to catch integer overflow allocation defects.
        
        @param binary ParsedBinary payload containing decompiled functions and symbols.
        @return List[Finding] List of INT-001 vulnerability findings.
        """
        # Execute pattern matching against INT-001 rule definitions
        return self._scan_function_with_patterns(binary)

