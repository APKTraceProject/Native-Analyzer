"""
Data model representing memory coordinates and symbol locations in native binaries.
"""

from dataclasses import dataclass

@dataclass
class Location:
    """
    Precise memory location mapping inside an ELF binary / native library function.
    
    Attributes:
        function_name: Name of the containing function (e.g. Java_com_example_app_NativeLib_executeCmd).
        symbol_address: Hexadecimal memory address offset (e.g. '0x00002b40').
        line_number: Line offset within decompiled block or function scope.
        is_exported_jni: Boolean indicating if function is exposed on the JNI surface.
    """
    function_name: str
    symbol_address: str
    line_number: int
    is_exported_jni: bool = False

    def to_dict(self) -> dict:
        """Serializes location object to dictionary schema matching target JSON report."""
        return {
            "function_name": self.function_name,
            "symbol_address": self.symbol_address,
            "line_number": self.line_number,
            "is_exported_jni": self.is_exported_jni
        }
