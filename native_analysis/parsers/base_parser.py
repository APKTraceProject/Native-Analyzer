"""
Abstract Base Class defining the contract for ELF binary parsers.

Provides standard interface signatures for ELF disassemblers, Ghidra decompilation integrations,
and fallback heuristic AST reconstructors.
"""

from abc import ABC, abstractmethod
from typing import Optional, List
from native_analysis.models.parsed_binary import ParsedBinary

class BaseParser(ABC):
    """
    Abstract Base Class for parsing Android shared objects (.so / ELF binaries).
    
    Subclasses must implement the parse method to convert target dynamic libraries
    into ParsedBinary AST dataclass models containing functions, strings, and mitigations.
    """

    @abstractmethod
    def parse(
        self,
        target_so_path: str,
        apk_relative_path: Optional[str] = None,
        primary_abi: Optional[str] = None,
        associated_abis: Optional[List[str]] = None
    ) -> ParsedBinary:
        """
        Parses binary at specified filesystem path into a ParsedBinary model.
        
        @param target_so_path Path to target ELF file on disk.
        @param apk_relative_path Relative path string for reporting consistency inside APK archives.
        @return ParsedBinary Complete model populated with decompiled functions, mitigations, and metadata.
        """
        pass

