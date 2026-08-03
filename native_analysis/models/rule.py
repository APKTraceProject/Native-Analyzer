"""
Data model representing vulnerability detection rules and structured pattern definitions loaded from YAML config.

Defines category signature rules containing pattern definitions, severity levels, confidence ratings,
sub-rule identifiers, and vulnerability rule category descriptions.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Union

@dataclass
class RulePattern:
    """
    Represents an individual pattern object within a vulnerability signature rule.
    
    Attributes:
        id (str): Specific sub-rule identifier (e.g. 'BOF-001', 'BOF-002').
        pattern (str): Regex pattern to match against decompiled C code or binary symbols.
        severity (str): Specific severity level ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
        confidence (str): Specific confidence level ('HIGH', 'MEDIUM', 'LOW').
        description (Optional[str]): Targeted description for this specific pattern trigger.
    """
    id: str
    pattern: str
    severity: str = "MEDIUM"
    confidence: str = "MEDIUM"
    description: Optional[str] = None


@dataclass
class Rule:
    """
    Represents a vulnerability signature rule category loaded from rules.yaml.
    
    Attributes:
        id (str): Category rule group identifier (e.g., 'BOF-001', 'INJ-001').
        name (str): Human-readable name of the vulnerability rule category.
        severity (str): Default category severity rating ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
        confidence (str): Default category confidence level ('HIGH', 'MEDIUM', 'LOW').
        category (str): Vulnerability category name.
        patterns (List[RulePattern]): List of sub-rule pattern objects with specific metadata.
        description (Optional[str]): Detailed description of the security risk category.
    """
    id: str
    name: str
    severity: str
    confidence: str
    category: str
    patterns: List[RulePattern] = field(default_factory=list)
    description: Optional[str] = None


