"""
Centralized AnalysisContext model storing pre-extracted binary artifacts and metadata.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from native_analysis.models.parsed_binary import ParsedBinary


@dataclass
class AnalysisContext:
    """
    Centralized context holding pre-extracted target binary metadata, hardening flags,
    string artifacts, symbol tables, and decompiled code scopes.
    """
    target_path: str
    binary_info: Dict[str, Any] = field(default_factory=dict)       # Architecture, ELF headers, hashes
    hardening_flags: Dict[str, Any] = field(default_factory=dict)   # Stack canary, PIE, NX, RELRO
    string_artifacts: List[Dict[str, Any]] = field(default_factory=list) # Extracted static strings & entropy
    symbol_table: Dict[str, List[str]] = field(default_factory=dict) # Imports, exports, JNI entrypoints
    code_scope: Dict[str, Any] = field(default_factory=dict)        # Function-level decompiled code maps
    parsed_binary: Optional[ParsedBinary] = None                     # Reference to ParsedBinary AST
