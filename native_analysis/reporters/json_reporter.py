"""
APKTrace - Android Native Binary Vulnerability Scanner Package

Provides static analysis tools, decompilation parsers, pattern matching rule engines,
and vulnerability reporting facilities for security auditing of Android shared libraries (.so).
"""

from native_analysis.core.engine import ScanEngine

__all__ = ["ScanEngine"]
