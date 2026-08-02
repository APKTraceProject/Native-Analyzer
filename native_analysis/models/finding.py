"""
Data model representing vulnerability findings and taint flow context.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from native_analysis.models.location import Location

@dataclass
class FlowAnalysis:
    """
    Taint flow tracking information mapping source to sink.
    
    Attributes:
        source: Description of data entry point or source variable.
        sink: Description of vulnerability sink call.
        data_path: Array of 20-line formatted C context lines illustrating data flow.
    """
    source: str
    sink: str
    data_path: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "sink": self.sink,
            "data_path": self.data_path
        }

@dataclass
class Finding:
    """
    Security finding model containing full vulnerability metrics and context window.
    
    Attributes:
        finding_id: Unique finding identifier (e.g., 'FIND-01').
        rule_id: Rule signature identifier (e.g., 'INJ-001').
        severity: Severity rating ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
        confidence: Confidence level ('HIGH', 'MEDIUM', 'LOW').
        target_file: Path to target native library.
        location: Location object specifying function address and line.
        target_variable: Name of affected variable or buffer.
        trigger_line: Exact code statement triggering the vulnerability alert.
        flow_analysis: Data flow context object.
    """
    finding_id: str
    rule_id: str
    severity: str
    confidence: str
    target_file: str
    location: Location
    target_variable: str
    trigger_line: str
    flow_analysis: FlowAnalysis

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "target_file": self.target_file,
            "location": self.location.to_dict(),
            "target_variable": self.target_variable,
            "trigger_line": self.trigger_line,
            "flow_analysis": self.flow_analysis.to_dict()
        }
