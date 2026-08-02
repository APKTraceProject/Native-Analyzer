"""
Data model representing parsed ELF binary metadata, functions, and mitigations.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class DecompiledFunction:
    """
    Representation of a decompiled C function or symbol block within ELF binary.
    """
    name: str
    address: str
    code_lines: List[str] = field(default_factory=list)
    is_exported_jni: bool = False

@dataclass
class BinaryMitigations:
    """
    Binary exploit mitigation flags parsed from ELF headers and dynamic section.
    """
    stack_canary: bool = False
    nx_bit: bool = True
    pie_enabled: bool = True
    relro: str = "Partial"  # 'Full', 'Partial', 'None'

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stack_canary": self.stack_canary,
            "nx_bit": self.nx_bit,
            "pie_enabled": self.pie_enabled,
            "relro": self.relro
        }

@dataclass
class ParsedBinary:
    """
    Structured model holding entire binary AST, functions, strings, and metadata.
    """
    file_name: str
    apk_relative_path: str
    abi_architecture: str
    sha256: str
    mitigations: BinaryMitigations
    functions: List[DecompiledFunction] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    exported_jni_functions: List[str] = field(default_factory=list)
