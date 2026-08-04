"""
Data model representing parsed ELF binary metadata, functions, and mitigations.

Defines AST representations for decompiled functions, dynamic section exploit mitigation flags
(stack canary, NX bit, PIE, RELRO), and binary metadata models.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class DecompiledFunction:
    """
    Representation of a decompiled C function or symbol block within ELF binary.
    
    Attributes:
        name (str): Symbol name or function identifier.
        address (str): Virtual memory address offset (e.g. '0x00002b40').
        code_lines (List[str]): Array of pseudo-C statements representing function body.
        is_exported_jni (bool): Flag indicating if symbol is exposed via JNI export tables.
    """
    name: str
    address: str
    code_lines: List[str] = field(default_factory=list)
    is_exported_jni: bool = False

@dataclass
class BinaryMitigations:
    """
    Binary exploit mitigation flags parsed from ELF headers and dynamic section.
    
    Attributes:
        stack_canary (bool): Stack protector guard availability (__stack_chk_fail).
        nx_bit (bool): No-Execute stack flag enablement.
        pie_enabled (bool): Position-Independent Executable status.
        relro (str): Relocation Read-Only state ('Full', 'Partial', 'None').
    """
    stack_canary: bool = False
    nx_bit: bool = True
    pie_enabled: bool = True
    relro: str = "Partial"  # 'Full', 'Partial', 'None'

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes binary mitigation flags to dictionary schema matching target JSON report.
        
        @return Dict[str, Any] Serialized mitigations dictionary.
        """
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
    
    Attributes:
        file_name (str): Local binary filename (e.g., 'libnative.so').
        apk_relative_path (str): Relative destination path inside APK archive.
        abi_architecture (str): Target ABI architecture ('arm64-v8a', 'armeabi-v7a', 'x86_64').
        sha256 (str): SHA-256 cryptographic checksum digest of binary file.
        mitigations (BinaryMitigations): Exploit mitigation status dataclass.
        functions (List[DecompiledFunction]): Decompiled functions list.
        strings (List[str]): Global read-only string section literals.
        exported_jni_functions (List[str]): List of exported JNI symbol names.
        functions_code_scope (Dict[str, List[str]]): Map of function names to their disassembled code lines.
    """
    file_name: str
    apk_relative_path: str
    abi_architecture: str
    sha256: str
    mitigations: BinaryMitigations
    functions: List[DecompiledFunction] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    exported_jni_functions: List[str] = field(default_factory=list)
    functions_code_scope: Dict[str, List[str]] = field(default_factory=dict)

