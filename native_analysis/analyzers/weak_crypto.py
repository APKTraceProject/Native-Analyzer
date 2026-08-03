"""
[CRY-001] Weak Cryptography Vulnerability Analyzer

Provides static analysis for legacy cryptographic primitives and roll-your-own encryption algorithms,
identifying weak hash functions (MD5, SHA1), obsolete ciphers (DES, RC4), and single-byte XOR loops.
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class WeakCryptoAnalyzer(BaseAnalyzer):
    """
    Detects insecure cryptographic primitives and custom single-byte encryption routines [CRY-001].
    
    Analysis Strategy:
    1. Scans decompiled code for broken cryptographic library calls (MD5, SHA1, DES, RC4).
    2. Detects single-byte XOR rotation loops (^= 0x..) acting as pseudo-encryption.
    """

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        """
        Executes static analysis to catch weak cryptographic routines.
        
        @param binary ParsedBinary payload containing decompiled functions and symbols.
        @return List[Finding] List of CRY-001 vulnerability findings.
        """
        # Execute pattern matching against CRY-001 rule definitions
        return self._scan_function_with_patterns(binary)
