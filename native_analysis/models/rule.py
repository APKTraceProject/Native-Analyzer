"""
Data model representing a vulnerability detection rule loaded from YAML config.

Defines signature rules containing pattern definitions, severity levels, confidence ratings,
and vulnerability rule category descriptions.
"""

from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Rule:
    """
    Represents a vulnerability signature rule loaded from rules.yaml.
    
    Attributes:
        id (str): Unique identifier for the rule (e.g., 'INJ-001').
        name (str): Human-readable name of the vulnerability rule.
        severity (str): Severity rating ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
        confidence (str): Confidence level of detection ('HIGH', 'MEDIUM', 'LOW').
        category (str): Vulnerability category name.
        patterns (List[str]): List of regex patterns to match against native decompiled C / symbols.
        description (Optional[str]): Detailed description of the security risk and remediations.
    """
    id: str
    name: str
    severity: str
    confidence: str
    category: str
    patterns: List[str] = field(default_factory=list)
    description: Optional[str] = None

