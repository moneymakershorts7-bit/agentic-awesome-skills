"""
Unified Result Data Structures

Definition of detection result, evidence, remediation suggestions, and other core data classes.
"""
import sys
if sys.version_info < (3, 7):
    from ..thirdparties.dataclasses_backport import dataclass, field
else:
    from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DetectStatus(Enum):
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    UNCERTAIN = "UNCERTAIN"


class PoCStatus(Enum):
    EXPLOITABLE = "EXPLOITABLE"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    NO_POC = "NO_POC"
    ERROR = "ERROR"
    # Three-phase verification specific
    USER_EXPLOITABLE = "USER_EXPLOITABLE"
    POC_ERROR = "POC_ERROR"


@dataclass
class PrepareOperation:
    """Single preparation operation record"""
    action: str           # "load_module" | "set_sysctl" | "create_dir" | "snapshot"
    target: str           # Operation target
    result: str           # "success" | "failed" | "skipped"
    error: str = ""       # Error message
    rollback_cmd: str = ""  # Rollback command for Post phase recovery


@dataclass
class PrepareResult:
    """Prepare phase result"""
    success: bool
    operations: List[PrepareOperation]
    state_snapshot: dict  # System state snapshot for rollback
    duration: float = 0.0


@dataclass
class SelfCheckResult:
    """Self-Check sub-phase result"""
    clean: bool
    issues: List[str]     # List of issues found
    residual_files: List[str] = field(default_factory=list)
    residual_sockets: List[str] = field(default_factory=list)
    residual_processes: List[str] = field(default_factory=list)


@dataclass
class GlobalVerifyResult:
    """Global Verification sub-phase result"""
    system_restored: bool
    kernel_log_clean: bool
    residual_files: List[str] = field(default_factory=list)
    kernel_messages: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    duration: float = 0.0


@dataclass
class PostResult:
    """Post phase total result"""
    self_check: SelfCheckResult
    global_verify: GlobalVerifyResult
    success: bool
    duration: float = 0.0


@dataclass
class Evidence:
    """Detection evidence"""
    type: str           # "version_match" | "module_loaded" | "config_enabled" | "patch_applied" | "mitigation_found"
    description: str    # Human-readable description
    raw_data: str       # Raw data
    source: str         # Data source (/proc/version, lsmod, etc.)


@dataclass
class Remediation:
    """Remediation suggestions"""
    priority: str                    # "IMMEDIATE" | "SCHEDULED"
    steps: List[str]                 # Remediation steps
    backup_steps: List[str]          # Backup steps (mandatory)
    rollback_steps: List[str]        # Rollback steps
    temporary_mitigation: str        # Temporary mitigation solution
    kernel_recovery_mode: str = ""   # Kernel recovery mode instructions
    verify_steps: List[str] = field(default_factory=list)  # Verification steps


class PoCConclusion(Enum):
    """Three-phase verification final conclusion"""
    USER_EXPLOITABLE = "USER_EXPLOITABLE"           # Unprivileged user can trigger LPE
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"             # Unprivileged user cannot trigger
    POC_ERROR = "POC_ERROR"                         # Execution anomaly


@dataclass
class PoCResult:
    """PoC execution result"""
    status: str             # PoCStatus value
    confidence: float = 0.0
    evidence_file: str = ""  # Evidence file path
    stdout: str = ""
    stderr: str = ""
    returncode: int = -1
    execution_time: float = 0.0
    error_message: str = ""
    # Three-phase verification fields
    user: str = "nobody"           # User who executed Run phase
    uid: int = -1                  # UID of Run phase executor
    prepare: Optional[PrepareResult] = None
    post: Optional[PostResult] = None
    final_conclusion: Optional[str] = None  # Final conclusion from PoC verification
    # CTF mode fields
    ctf_flag: str = ""             # CTF flag extracted from PoC output
    ctf_challenge: str = ""        # CTF challenge value sent to PoC (for consistency validation)
    evidence_text: str = ""        # Extracted evidence summary (mode-specific)
    

@dataclass
class DetectResult:
    """CVE detection result"""
    cve_id: str
    severity: str
    cvss_score: float
    status: str                        # "VULNERABLE" | "NOT_VULNERABLE" | "UNCERTAIN"
    confidence: float = 0.0            # 0.0 ~ 1.0
    description: str = ""
    vuln_type: str = ""                # Vulnerability type (e.g., "local_privilege_escalation")
    affected_versions: str = ""
    detection_method: str = ""
    evidence: List[Evidence] = field(default_factory=list)  # Detection evidence list
    mitigations: List[str] = field(default_factory=list)
    remediation: Optional[Remediation] = None  # Remediation suggestions
    
    # PoC verification results (Phase 1-3)
    poc_result: Optional[PoCResult] = None
    poc_enabled: bool = False
    poc_skip_reason: str = ""  # Reason why PoC was not executed (disabled, missing binary, etc.)
