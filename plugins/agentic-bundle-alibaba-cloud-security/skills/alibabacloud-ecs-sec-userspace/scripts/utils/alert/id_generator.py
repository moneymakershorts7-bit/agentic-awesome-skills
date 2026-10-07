"""Alert ID Generator

Generates unique IDs for security alerts.

ID Format: {SEVERITY}-{analyzer}-{hash8}
Example: HIGH-network_analyzer-a3f5c8d2
"""
import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..reporter.evidence import Evidence


class AlertIDGenerator:
    """Generate unique alert IDs"""
    
    @staticmethod
    def generate(evidence: "Evidence") -> str:
        """Generate alert ID from evidence
        
        Args:
            evidence: Evidence object
            
        Returns:
            str: Alert ID in format {SEVERITY}-{analyzer}-{hash8}
        """
        # Calculate content hash
        content = f"{evidence.module}:{evidence.attack_id}:{evidence.source_path}:{evidence.title}"
        content_hash = hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()[:8]
        
        # Build alert ID
        severity = evidence.severity.value.upper()
        analyzer = evidence.module
        alert_id = f"{severity}-{analyzer}-{content_hash}"
        
        return alert_id
    
    @staticmethod
    def generate_uuid(evidence: "Evidence") -> str:
        """Generate UUID-based alert ID for global uniqueness
        
        Args:
            evidence: Evidence object
            
        Returns:
            str: Alert ID in format {analyzer_hash}-{uuid}
            Example: net-e4762bb1-4c10-090a
        """
        import uuid
        
        analyzer_hash = hashlib.md5(evidence.module.encode(), usedforsecurity=False).hexdigest()[:3]
        unique_id = str(uuid.uuid4())[:12]
        
        return f"{analyzer_hash}-{unique_id}"
    
    @staticmethod
    def parse(alert_id: str) -> dict:
        """Parse alert ID into components
        
        Args:
            alert_id: Alert ID string
            
        Returns:
            dict: Parsed components {severity, analyzer, hash}
        """
        parts = alert_id.split("-", 2)
        if len(parts) != 3:
            return {"severity": "", "analyzer": "", "hash": ""}
        
        return {
            "severity": parts[0],
            "analyzer": parts[1],
            "hash": parts[2]
        }
