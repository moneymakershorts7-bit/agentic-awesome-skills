"""
CVE-2016-0728 Detector - Keyring refcount overflow use-after-free

VulnerabilityDescription:
    Linux Kernel keyring SubSystemin join_session_keyring() FunctionExistsin
    引forCountOverflowVulnerability。threatHandlercanTopassedConstructmassive session keyring 引for，
    Causes use-after-free Condition，fromAndImplementLocal特PrivilegeUpgrade。

ImpactVersion: 3.8.0 <= kernel < 4.4.1
CVSS: 7.2 (HIGH)
exploitationCondition: CONFIG_KEYS Enable（CoreKernelSuccesscan）
"""
import logging
from typing import List, Optional

from .base import BaseDetector
from ..core.result import (
    DetectResult, Evidence, Remediation, PoCResult,
    PrepareResult, PostResult
)
from ..core.kernel_info import KernelInfo
from ..utils.version_compare import version_in_range
from ..utils.safe_check import check_config_enabled

logger = logging.getLogger(__name__)


class CVE20160728Detector(BaseDetector):
    """CVE-2016-0728 (keyring refcount overflow UAF) Detector"""

    cve_id = "CVE-2016-0728"
    cvss_score = 7.2
    severity = "HIGH"
    description = (
        "Keyring refcount overflow use-after-free in join_session_keyring() - "
        "Local Privilege Escalation via reference count overflow"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "generic": {"min": "3.8.0", "fixed": "4.4.1"},
    }

    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2016_0728.bin"
    poc_mode = "uaf"

    _MODULE_NAME = "keyring"
    _CONFIG_KEY = "CONFIG_KEYS"
    _MIN_VERSION = "3.8.0"
    _FIXED_VERSION = "4.4.1"

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute CVE-2016-0728 detection
        """
        evidence_list: List[Evidence] = []
        confidence = 0.0

        version_vulnerable = version_in_range(
            kernel_info.version, self._MIN_VERSION, fixed_version=self._FIXED_VERSION
        )

        if not version_vulnerable:
            evidence_list.append(Evidence(
                type="version_match",
                description=(
                    f"Kernel version {kernel_info.version} not in affected range "
                    f"[{self._MIN_VERSION}, {self._FIXED_VERSION})"
                ),
                raw_data=kernel_info.version,
                source="uname -r"
            ))
            return DetectResult(
                cve_id=self.cve_id, status="NOT_VULNERABLE", confidence=0.95,
                severity=self.severity, cvss_score=self.cvss_score,
                description=self.description, vuln_type=self.vuln_type,
                evidence=evidence_list, remediation=None
            )

        evidence_list.append(Evidence(
            type="version_match",
            description=(
                f"Kernel version {kernel_info.version} in affected range "
                f"[{self._MIN_VERSION}, {self._FIXED_VERSION})"
            ),
            raw_data=kernel_info.version, source="uname -r"
        ))
        confidence = 0.5

        config_value = None
        if kernel_info.config is not None:
            config_value = check_config_enabled(self._CONFIG_KEY, kernel_info.config)

        if config_value:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY}={config_value} - keyring subsystem enabled",
                raw_data=f"{self._CONFIG_KEY}={config_value}",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence += 0.3
        elif kernel_info.config:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY} not enabled - keyring not available",
                raw_data=f"{self._CONFIG_KEY}=not set",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence -= 0.2
        else:
            evidence_list.append(Evidence(
                type="config_enabled",
                description="Cannot read kernel config - possibly in restricted environment",
                raw_data="config not accessible", source="/proc/config.gz or /boot/config-*"
            ))

        if confidence >= 0.6:
            status = "VULNERABLE"
        elif confidence >= 0.4:
            status = "UNCERTAIN"
        else:
            status = "NOT_VULNERABLE"

        confidence = max(0.0, min(1.0, confidence))

        return DetectResult(
            cve_id=self.cve_id, status=status, confidence=confidence,
            severity=self.severity, cvss_score=self.cvss_score,
            description=self.description, vuln_type=self.vuln_type,
            evidence=evidence_list,
            remediation=self.get_remediation() if status == "VULNERABLE" else None
        )

    def get_remediation(self) -> Remediation:
        """Return CVE-2016-0728 Remediation suggestions"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Solution A: Upgrade kernel (only effective method)",
                "# Ubuntu: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "# RHEL: sudo yum update kernel",
                "# Debian: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "",
                "# 2. Restart system to apply new kernel",
                "sudo reboot",
                "",
                "# 3. Verify fix",
                "uname -r  # Confirm new kernel version >= 4.4.1",
            ],
            backup_steps=[
                "# === Pre-fix backup ===",
                "sudo cp /boot/vmlinuz-$(uname -r) /boot/vmlinuz-$(uname -r).bak",
                "cat /proc/cmdline > ~/kernel_cmdline_backup.txt",
            ],
            rollback_steps=[
                "# === Rollback steps ===",
                "# If kernel upgrade causes issues, select old kernel in GRUB",
            ],
            temporary_mitigation="No temporary mitigation available - keyring is core kernel functionality",
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during restart to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup and restart"
            ),
            verify_steps=[
                "# Verify fix:",
                "uname -r  # Confirm kernel version >= 4.4.1",
            ]
        )

    def _get_poc_verifier(self):
        """Return CVE-2016-0728 PoC Verifier instance"""
        from ..poc.cve_2016_0728_poc import CVE20160728PoCVerifier
        return CVE20160728PoCVerifier()

    def prepare(self, kernel_info: KernelInfo) -> PrepareResult:
        from .cve_2016_0728_prepare import CVE20160728PrepareHandler
        handler = CVE20160728PrepareHandler(timeout=30)
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None) -> PostResult:
        from .cve_2016_0728_post import CVE20160728PostHandler
        handler = CVE20160728PostHandler(prepare_result=prepare_result, timeout=30)
        return handler.execute()

    def run_poc(self, kernel_info: KernelInfo, output_dir: str,
                enable_prepare: bool = True, enable_post: bool = True,
                poc_user: str = "nobody", force_demote: bool = True,
                force_run: bool = False) -> PoCResult:
        if not force_run:
            if not version_in_range(kernel_info.version, self._MIN_VERSION,
                                    fixed_version=self._FIXED_VERSION):
                return PoCResult(status="NOT_EXPLOITABLE", confidence=0.9,
                                 error_message="Kernel version not in affected range")

            config_enabled = check_config_enabled(self._CONFIG_KEY, kernel_info.config)
            if not config_enabled and kernel_info.config is not None:
                return PoCResult(status="NOT_EXPLOITABLE", confidence=0.8,
                                 error_message="CONFIG_KEYS not enabled")

        verifier = self._get_poc_verifier()
        if verifier is not None:
            return verifier.verify(
                kernel_info, output_dir, poc_user=poc_user,
                enable_prepare=enable_prepare, enable_post=enable_post,
                force_demote=force_demote,
                force_run=force_run,
            )

        return super().run_poc(
            kernel_info, output_dir, enable_prepare=enable_prepare,
            enable_post=enable_post, poc_user=poc_user, force_demote=force_demote,
                force_run=force_run
        )
