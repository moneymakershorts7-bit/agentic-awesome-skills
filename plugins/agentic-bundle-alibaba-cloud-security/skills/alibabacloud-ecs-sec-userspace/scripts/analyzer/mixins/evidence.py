"""
EvidenceMixin: Evidence creation and whitelisting.

Extracted from BaseAnalyzer to modularize evidence-related functionality.
Methods: _create_evidence, _create_evidence_details, _check_whitelist
"""
import threading


_lazy_init_lock = threading.Lock()


class EvidenceMixin:
    """Mixin providing evidence creation, whitelist checking, and FP detection."""

    def _create_evidence(
        self,
        title: str,
        description: str,
        severity: 'Severity',
        confidence: float,
        attack_id: str,
        attack_tactic: str = "",
        source_path: str = "",
        raw_data: dict = None,
        remediation: str = "",
        verified_status: str = "pending",
        owasp_asi: str = "",
        evidence_details=None,
        remediation_commands=None
    ) -> 'Evidence':
        """Simplified Evidence creation, auto-fills module and timestamp

        Args:
            title: Evidence title
            description: Evidence description
            severity: Severity level
            confidence: Confidence score (0-1)
            attack_id: MITRE ATT&CK technique ID
            attack_tactic: MITRE ATT&CK tactic name
            source_path: Source file or path
            raw_data: Raw detection data
            remediation: Human-readable remediation text
            verified_status: Verification status
            owasp_asi: OWASP ASI category
            evidence_details: Optional EvidenceDetail object with structured context
            remediation_commands: Optional list of remediation commands
        """
        from ...reporter.evidence import Evidence

        self._evidence_counter += 1
        datetime, timezone = _get_datetime()
        factor = getattr(self, 'confidence_factor', 1.0)
        adjusted_confidence = max(0.0, min(1.0, confidence * factor))
        return Evidence(
            id=f"{self.name}-{self._evidence_counter}",
            module=self.name,
            title=title,
            description=description,
            severity=severity,
            confidence=adjusted_confidence,
            attack_id=attack_id,
            attack_tactic=attack_tactic,
            source_path=source_path,
            timestamp=datetime.now(timezone.utc).isoformat(),
            raw_data=raw_data or {},
            remediation=remediation,
            verified_status=verified_status,
            owasp_asi=owasp_asi,
            evidence_details=evidence_details,
            remediation_commands=remediation_commands or []
        )

    def _create_evidence_details(self, **kwargs) -> 'EvidenceDetail':
        """Create EvidenceDetail with automatic filtering of empty values.

        This helper ensures that only fields with meaningful data are populated,
        avoiding empty strings and zero values that reduce report quality.

        Args:
            **kwargs: Field name and value pairs for EvidenceDetail

        Returns:
            EvidenceDetail: Instance with only meaningful fields populated

        Example:
            self._create_evidence_details(
                pid=1234,
                cmdline='/usr/bin/test',
                file_path=''  # Will be filtered
            )
            # Returns EvidenceDetail(pid=1234, cmdline='/usr/bin/test')
        """
        from ...reporter.evidence import EvidenceDetail

        filtered_kwargs = {}
        for key, value in kwargs.items():
            if value is None:
                continue
            if isinstance(value, str) and value == '':
                continue
            filtered_kwargs[key] = value

        return EvidenceDetail(**filtered_kwargs)

    def _check_whitelist(self, evidence_value: str) -> bool:
        """Check if evidence matches whitelist

        Args:
            evidence_value: Evidence value to check

        Returns:
            bool: True if whitelisted
        """
        self._ensure_whitelist_manager()

        if not self._whitelist_manager:
            return False
        return self._whitelist_manager.is_whitelisted(self.name, evidence_value)



# Lazy import helpers used by EvidenceMixin
_datetime = None
def _get_datetime():
    """Lazy datetime import to defer loading datetime and timezone."""
    global _datetime
    if _datetime is None:
        with _lazy_init_lock:
            if _datetime is None:
                from datetime import datetime, timezone
                _datetime = (datetime, timezone)
    return _datetime
