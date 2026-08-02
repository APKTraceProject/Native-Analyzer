"""
[CRY-001] Weak Cryptography Vulnerability Analyzer
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class WeakCryptoAnalyzer(BaseAnalyzer):
    """Detects usage of insecure cryptographic primitives (MD5, SHA1, DES, RC4)."""

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        return self._scan_function_with_patterns(binary)
