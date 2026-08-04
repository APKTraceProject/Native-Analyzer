"""
Data model representing vulnerability findings and taint flow context.

Provides strongly-typed dataclass structures for tracking security finding items,
vulnerability metadata ratings, location references, and multi-line taint flow analysis paths.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from native_analysis.models.location import Location

@dataclass
class FlowAnalysis:
    """
    Taint flow tracking information mapping source to sink.
    
    Attributes:
        source (str): Description of data entry point or source variable.
        sink (str): Description of vulnerability sink call.
        trigger_line_number (int): Specific line number in the parent function scope.
    """
    source: str
    sink: str
    trigger_line_number: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes flow analysis object to dictionary schema matching target JSON report.
        
        @return Dict[str, Any] Serialized dictionary representation of flow analysis.
        """
        return {
            "source": self.source,
            "sink": self.sink,
            "trigger_line_number": self.trigger_line_number
        }

@dataclass
class Finding:
    """
    Security finding model containing full vulnerability metrics and context window.
    
    Attributes:
        finding_id (str): Unique finding identifier (e.g., 'FIND-01').
        rule_id (str): Rule signature identifier (e.g., 'INJ-001').
        severity (str): Severity rating ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
        confidence (str): Confidence level ('HIGH', 'MEDIUM', 'LOW').
        location (Location): Location object specifying function address and line offset.
        target_variable (str): Name of affected variable, buffer, or extracted static data string artifact.
        trigger_line (str): Exact code statement triggering the vulnerability alert.
        flow_analysis (FlowAnalysis): Data flow context object detailing source to sink.
        matches (Optional[List[Dict[str, Any]]]): List of individual match details for aggregated static findings (containing match_id, line_number, target_variable, trigger_line).
        total_matches (int): Total count of matches aggregated into this finding (default 1).
    """
    finding_id: str
    rule_id: str
    severity: str
    confidence: str
    location: Location
    target_variable: str
    trigger_line: str
    flow_analysis: FlowAnalysis
    matches: Optional[List[Dict[str, Any]]] = None
    total_matches: int = 1

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes finding object to dictionary schema matching target JSON report.
        
        @return Dict[str, Any] Serialized dictionary representation of finding payload.
        """
        d = {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "location": self.location.to_dict(),
            "target_variable": self.target_variable,
            "trigger_line": self.trigger_line,
            "flow_analysis": self.flow_analysis.to_dict(),
        }
        if self.total_matches > 1:
            d["total_matches"] = self.total_matches
            if self.matches is not None:
                d["matches"] = self.matches
        return d

