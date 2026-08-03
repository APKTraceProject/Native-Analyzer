"""
APKTrace Native Security Analysis Analyzers Package

Provides static code analyzers for detecting vulnerabilities across 15 security categories
in Android C/C++ dynamic native libraries (.so / ELF binaries).
"""

from native_analysis.analyzers.base_analyzer import BaseAnalyzer
from native_analysis.analyzers.buffer_overflow import BufferOverflowAnalyzer
from native_analysis.analyzers.command_injection import CommandInjectionAnalyzer
from native_analysis.analyzers.format_string import FormatStringAnalyzer
from native_analysis.analyzers.weak_crypto import WeakCryptoAnalyzer
from native_analysis.analyzers.anti_debugging import AntiDebuggingAnalyzer
from native_analysis.analyzers.memory_management import MemoryManagementAnalyzer
from native_analysis.analyzers.jni_boundary_leaks import JNIBoundaryLeaksAnalyzer
from native_analysis.analyzers.file_permission_flaws import FilePermissionFlawsAnalyzer
from native_analysis.analyzers.integer_overflow import IntegerOverflowAnalyzer
from native_analysis.analyzers.insecure_ipc import InsecureIPCAnalyzer
from native_analysis.analyzers.null_pointer_deref import NullPointerDerefAnalyzer
from native_analysis.analyzers.insecure_random import InsecureRandomAnalyzer
from native_analysis.analyzers.jni_reflection_abuse import JNIReflectionAbuseAnalyzer
from native_analysis.analyzers.anti_root_frida import AntiRootFridaAnalyzer
from native_analysis.analyzers.string_obfuscation import StringObfuscationAnalyzer

__all__ = [
    "BaseAnalyzer",
    "BufferOverflowAnalyzer",
    "CommandInjectionAnalyzer",
    "FormatStringAnalyzer",
    "WeakCryptoAnalyzer",
    "AntiDebuggingAnalyzer",
    "MemoryManagementAnalyzer",
    "JNIBoundaryLeaksAnalyzer",
    "FilePermissionFlawsAnalyzer",
    "IntegerOverflowAnalyzer",
    "InsecureIPCAnalyzer",
    "NullPointerDerefAnalyzer",
    "InsecureRandomAnalyzer",
    "JNIReflectionAbuseAnalyzer",
    "AntiRootFridaAnalyzer",
    "StringObfuscationAnalyzer",
]

