"""
Abstract Base Class defining the contract for ELF binary parsers.
"""

from abc import ABC, abstractmethod
from native_analysis.models.parsed_binary import ParsedBinary

class BaseParser(ABC):
    """
    Interface for parsing Android shared objects (.so / ELF binaries).
    """

    @abstractmethod
    def parse(self, target_so_path: str, apk_relative_path: str = "standalone/libnative-lib.so") -> ParsedBinary:
        """
        Parses binary at specified filesystem path into a ParsedBinary model.
        
        Args:
            target_so_path: Path to target ELF file on disk.
            apk_relative_path: Relative path string for reporting consistency.
            
        Returns:
            ParsedBinary populated with functions, mitigations, and metadata.
        """
        pass
