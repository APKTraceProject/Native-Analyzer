"""
[IPC-001] Insecure IPC Analyzer

Provides static analysis for insecure inter-process communication (IPC) channels in Android C/C++ native binaries,
detecting unauthenticated UNIX domain sockets (AF_UNIX) bound inside shared world-accessible paths (/tmp/).
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class InsecureIPCAnalyzer(BaseAnalyzer):
    """
    Detects unauthenticated local IPC socket bindings and exposed temporary domain channels [IPC-001].
    
    Analysis Strategy:
    1. Identifies socket instantiation calls using AF_UNIX family constants.
    2. Flags binding and connection routines targeting un-isolated filesystem paths.
    """

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        """
        Executes static analysis to locate insecure native IPC endpoints.
        
        @param binary ParsedBinary payload containing decompiled functions and symbols.
        @return List[Finding] List of IPC-001 vulnerability findings.
        """
        # Execute pattern matching against IPC-001 rule definitions
        return self._scan_function_with_patterns(binary)

