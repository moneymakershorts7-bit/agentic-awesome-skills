from dataclasses import dataclass, field
from typing import List, Optional
from .severity import Severity


@dataclass
class EvidenceDetail:
    """Detailed evidence information for precise locating and remediation."""

    file_path: Optional[str] = None
    line_number: Optional[int] = None
    content: Optional[str] = None
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)
    pid: Optional[int] = None
    cmdline: Optional[str] = None
    user: Optional[str] = None
    start_time: Optional[str] = None
    parent_pid: Optional[int] = None
    executable: Optional[str] = None
    local_address: Optional[str] = None
    remote_address: Optional[str] = None
    connection_state: Optional[str] = None
    service_type: Optional[str] = None
    credential_type: Optional[str] = None
    permission_level: Optional[str] = None
    rotation_url: Optional[str] = None
    rotation_command: Optional[str] = None
    
    # Aggregated evidence fields (for grouped alerts)
    count: Optional[int] = None
    tool_names: Optional[List[str]] = None
    top_examples: Optional[List[dict]] = None

    # Extended fields for various analyzer needs
    size: Optional[str] = None
    shell: Optional[str] = None
    UID: Optional[str] = None
    PermitRootLogin: Optional[str] = None
    PasswordAuth: Optional[str] = None
    Port: Optional[str] = None
    AllowTcpForwarding: Optional[str] = None
    GatewayPorts: Optional[str] = None
    PermitTunnel: Optional[str] = None
    PasswordAuthentication: Optional[str] = None
    PermitEmptyPasswords: Optional[str] = None
    X11Forwarding: Optional[str] = None
    MaxAuthTries: Optional[str] = None
    HostbasedAuthentication: Optional[str] = None
    IgnoreRhosts: Optional[str] = None
    cwd: Optional[str] = None
    expected: Optional[str] = None
    ListenStream: Optional[str] = None
    Paths: Optional[str] = None
    energy_ratio: Optional[str] = None
    risk: Optional[str] = None
    scanned_paths: Optional[List[str]] = None
    file_type: Optional[str] = None
    severity_label: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON output."""
        result = {}
        for key, value in self.__dict__.items():
            if value is None or value == "":
                continue
            result[key] = value
        return result


@dataclass
class Evidence:
    """Evidence Data Model"""

    id: str
    module: str
    title: str
    description: str
    severity: Severity
    confidence: float
    attack_id: str
    attack_tactic: str
    source_path: str
    timestamp: str
    raw_data: dict = field(default_factory=dict)
    remediation: str = ""
    verified_status: str = "pending"
    logid: str = ""
    owasp_asi: str = ""
    evidence_details: Optional[EvidenceDetail] = None
    remediation_commands: List[str] = field(default_factory=list)

    @property
    def weighted_score(self) -> float:
        """Return weighted score: severity.score * confidence"""
        return self.severity.score * self.confidence

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON output"""
        result = {
            "id": self.id,
            "module": self.module,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "attack_id": self.attack_id,
            "attack_tactic": self.attack_tactic,
            "source_path": self.source_path,
            "timestamp": self.timestamp,
            "raw_data": self.raw_data,
            "remediation": self.remediation,
            "verified_status": self.verified_status,
            "weighted_score": self.weighted_score,
        }
        if self.logid:
            result["logid"] = self.logid
        if self.owasp_asi:
            result["owasp_asi"] = self.owasp_asi
        if self.evidence_details:
            result["evidence_details"] = self.evidence_details.to_dict()
        result["remediation_commands"] = self.remediation_commands
        return result

    def to_summary(self) -> str:
        """Return single-line summary"""
        return f"[{self.severity.value}] {self.title} ({self.attack_id}) [{self.verified_status}]"
