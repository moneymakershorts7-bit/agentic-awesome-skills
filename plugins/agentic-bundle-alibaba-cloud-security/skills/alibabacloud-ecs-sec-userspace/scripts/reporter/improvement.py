"""ImprovementPlanData: Improvement plan data for sec-userspace reports."""
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class ImprovementPlanData:
    """Improvement plan data for reports"""
    enabled: bool = False
    reporting_status: str = "disabled"
    suggestions_count: int = 0
    suggestions: List[Dict[str, Any]] = field(default_factory=list)
    consent_required: bool = False
    privacy_notice: str = ""
    deployment_type: str = "local"
    reportable_count: int = 0
    anonymized_count: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "enabled": self.enabled,
            "reporting_status": self.reporting_status,
            "suggestions_count": self.suggestions_count,
            "suggestions": self.suggestions,
            "consent_required": self.consent_required,
            "privacy_notice": self.privacy_notice,
            "deployment_type": self.deployment_type,
            "reportable_count": self.reportable_count,
            "anonymized_count": self.anonymized_count,
        }
