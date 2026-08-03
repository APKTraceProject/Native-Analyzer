"""
[STR-001] String Obfuscation Analyzer

Provides static analysis for un-obfuscated sensitive strings and hardcoded credentials in native binaries,
identifying high-entropy 32-character API keys, internal URLs, and authorization headers in .rodata tables.
"""

from typing import List
from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.models.parsed_binary import ParsedBinary
from native_analysis.models.finding import Finding

class StringObfuscationAnalyzer(BaseAnalyzer):
    """
    Detects plaintext secrets, high-entropy tokens, and un-obfuscated URLs in binary string sections [STR-001].
    
    Analysis Strategy:
    1. Evaluates decompiled functions and global string sections against regex secret signatures.
    2. Flags exposed API tokens, key-value credentials, and internal endpoint URLs.
    """

    def analyze(self, binary: ParsedBinary) -> List[Finding]:
        """
        Executes static analysis to detect exposed hardcoded credentials and secrets.
        
        @param binary ParsedBinary payload containing decompiled functions and symbols.
        @return List[Finding] List of STR-001 vulnerability findings.
        """
        # Execute pattern matching against STR-001 rule definitions
        return self._scan_function_with_patterns(binary)
