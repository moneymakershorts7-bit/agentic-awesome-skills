"""Alert data model"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class Alert:
    """Security Alert
    
    Attributes:
        id: Alert unique ID (format: {SEVERITY}-{analyzer}-{hash8})
        analyzer: Analyzer name that generated this alert
        rule: Rule name that was triggered
        severity: Alert severity (CRITICAL/HIGH/MEDIUM/LOW)
        title: Alert title
        description: Alert description
        target: Alert target (process/file/connection)
        evidence: List of evidence strings
        tags: List of tags
        timestamp: ISO format timestamp
        suppressed: Whether this alert is suppressed
        suppression_reason: Reason for suppression if suppressed
    """
    
    id: str
    analyzer: str
    rule: str
    severity: str
    title: str
    description: str
    target: str
    evidence: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    timestamp: str = ""
    suppressed: bool = False
    suppression_reason: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON output"""
        return {
            "id": self.id,
            "analyzer": self.analyzer,
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "target": self.target,
            "evidence": self.evidence,
            "tags": self.tags,
            "timestamp": self.timestamp,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason
        }
    
    @classmethod
    def from_evidence(cls, evidence) -> "Alert":
        """Create Alert from Evidence object
        
        Args:
            evidence: Evidence object from analyzer
            
        Returns:
            Alert: Created alert object
        """
        # Generate alert ID from evidence
        from .id_generator import AlertIDGenerator
        
        alert_id = AlertIDGenerator.generate(evidence)
        
        # Extract target from evidence
        target = evidence.source_path or evidence.raw_data.get("target", "")
        
        # Extract rule from evidence
        rule = evidence.attack_id or f"{evidence.module}_rule"
        
        # Extract tags
        tags = []
        if evidence.owasp_asi:
            tags.append(f"owasp:{evidence.owasp_asi}")
        if evidence.attack_tactic:
            tags.append(f"attack:{evidence.attack_tactic}")
        
        return cls(
            id=alert_id,
            analyzer=evidence.module,
            rule=rule,
            severity=evidence.severity.value,
            title=evidence.title,
            description=evidence.description,
            target=target,
            evidence=[evidence.to_summary()],
            tags=tags,
            timestamp=evidence.timestamp,
            suppressed=False,
            suppression_reason=""
        )
