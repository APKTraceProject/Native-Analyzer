"""
Data model representing a vulnerability detection rule loaded from YAML config.
"""

from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Rule:
    """
    Represents a vulnerability signature rule.
    
    Attributes:
        id: Unique identifier for the rule (e.g., 'INJ-001').
        name: Human-readable name of the vulnerability rule.
        severity: Severity rating ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
        confidence: Confidence level of detection ('HIGH', 'MEDIUM', 'LOW').
        category: Vulnerability category name.
        patterns: List of regex patterns to match against native decompiled C / symbols.
        description: Description of the security risk.
    """
    id: str
    name: str
    severity: str
    confidence: str
    category: str
    patterns: List[str] = field(default_factory=list)
    description: Optional[str] = None
