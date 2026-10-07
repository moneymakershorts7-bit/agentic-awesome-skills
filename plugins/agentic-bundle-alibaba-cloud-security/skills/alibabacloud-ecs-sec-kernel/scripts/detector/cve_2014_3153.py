"""
CVE-2014-3153 Detector - futex_requeue() PermissionElevate (Towelroot)

Vulnerability description:
    Linux Kernel futex SubSystemin futex_requeue() FunctionExistsinPermissionElevateVulnerability。
    threatHandlercanTopassedConstruct特定 futex System callParameter，exploitation requeue Operationin
    RaceCondition，ImplementLocalprivilege elevationTo root Permission。

ImpactVersion: 2.6.32 <= kernel < 3.14.6
CVSS: 7.2 (HIGH)
exploitationCondition: CONFIG_FUTEX Enable（CoreKernelSuccesscan，DefaultEnable）

Detection method (read-only throughout):
    1. Kernel version range match
    2. CONFIG_FUTEX Configuration check
    3. Mitigation measuresCheck（CoreKernelSuccesscan，MustPatch）
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


class CVE20143153Detector(BaseDetector):
    """CVE-2014-3153 (futex_requeue privilege escalation / Towelroot) Detector"""

    # Metadata
    cve_id = "CVE-2014-3153"
    cvss_score = 7.8
    severity = "CRITICAL"
    description = (
        "futex_requeue() privilege escalation (Towelroot) - "
        "Local Privilege Escalation via race condition in futex requeue operation"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "generic": {"min": "2.6.32", "fixed": "3.14.6"},
        "ubuntu": {
            "12.04": {"kernel": "3.2.0", "fixed_kernel": "3.2.0-65"},
            "14.04": {"kernel": "3.13.0", "fixed_kernel": "3.13.0-29"},
        },
        "rhel": {
            "6": {"kernel": "2.6.32", "fixed_kernel": "2.6.32-431.17.1"},
            "7": {"kernel": "3.10.0", "fixed_kernel": "3.10.0-123.4.2"},
        },
        "debian": {
            "7": {"kernel": "3.2.0", "fixed_kernel": "3.2.0-4"},
        },
    }

    # PoC Metadata
    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2014_3153.bin"
    poc_mode = "uaf"

    # Internal constants
    _MODULE_NAME = "futex"
    _CONFIG_KEY = "CONFIG_FUTEX"
    _MIN_VERSION = "2.6.32"
    _FIXED_VERSION = "3.14.6"

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute CVE-2014-3153 detection

        Detection strategy:
        - Version in range + config enabled + no mitigation = VULNERABLE (high confidence)
        - Version in range + config unknown = UNCERTAIN
        - Version not in range = NOT_VULNERABLE
        """
        evidence_list: List[Evidence] = []
        confidence = 0.0

        # Step 1: Version match
        version_vulnerable = version_in_range(
            kernel_info.version,
            self._MIN_VERSION,
            fixed_version=self._FIXED_VERSION
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
                cve_id=self.cve_id,
                status="NOT_VULNERABLE",
                confidence=0.95,
                severity=self.severity,
                cvss_score=self.cvss_score,
                description=self.description,
                vuln_type=self.vuln_type,
                evidence=evidence_list,
                remediation=None
            )

        # Version is in affected range
        evidence_list.append(Evidence(
            type="version_match",
            description=(
                f"Kernel version {kernel_info.version} in affected range "
                f"[{self._MIN_VERSION}, {self._FIXED_VERSION})"
            ),
            raw_data=kernel_info.version,
            source="uname -r"
        ))
        confidence = 0.5  # Base confidence

        # Step 2: Configuration detection
        config_value = None
        if kernel_info.config is not None:
            config_value = check_config_enabled(self._CONFIG_KEY, kernel_info.config)

        if config_value:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY}={config_value} - futex compiled into kernel",
                raw_data=f"{self._CONFIG_KEY}={config_value}",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence += 0.25
        elif kernel_info.config:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY} not enabled - futex subsystem not available",
                raw_data=f"{self._CONFIG_KEY}=not set",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence -= 0.2
        else:
            evidence_list.append(Evidence(
                type="config_enabled",
                description="Cannot read kernel config - possibly in restricted environment",
                raw_data="config not accessible",
                source="/proc/config.gz or /boot/config-*"
            ))

        # Step 3: Mitigation detection
        mitigation_detected = self._check_mitigation()
        if mitigation_detected:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="Mitigation detected - core kernel functionality can only be fixed via patch",
                raw_data="mitigation active",
                source="system check"
            ))
        else:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="No effective mitigation detected - kernel upgrade required",
                raw_data="no effective mitigation",
                source="system check"
            ))

        # Step 4: Comprehensive verdict
        if confidence >= 0.6:
            status = "VULNERABLE"
        elif confidence >= 0.4:
            status = "UNCERTAIN"
        else:
            status = "NOT_VULNERABLE"

        # Limit confidence range
        confidence = max(0.0, min(1.0, confidence))

        return DetectResult(
            cve_id=self.cve_id,
            status=status,
            confidence=confidence,
            severity=self.severity,
            cvss_score=self.cvss_score,
            description=self.description,
            vuln_type=self.vuln_type,
            evidence=evidence_list,
            remediation=self.get_remediation() if status == "VULNERABLE" else None
        )

    def get_remediation(self) -> Remediation:
        """Return CVE-2014-3153 Remediation suggestions"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Solution A: Upgrade kernel (only effective method)",
                "# Ubuntu: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "# RHEL: sudo yum update kernel",
                "# Debian: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "",
                "# Solution B: Temporary mitigation (not fully effective, only reduces risk)",
                "# Restricting user access to futex-related syscalls (may impact applications)",
                "# Upgrading kernel to >= 3.14.6 is the fundamental solution",
                "",
                "# 2. Restart system to apply new kernel",
                "sudo reboot",
                "",
                "# 3. Verify fix",
                "uname -r  # Confirm new kernel version >= 3.14.6 or already patched",
            ],
            backup_steps=[
                "# === Pre-fix backup (mandatory) ===",
                "sudo cp /boot/vmlinuz-$(uname -r) /boot/vmlinuz-$(uname -r).bak",
                "sudo cp /boot/initrd.img-$(uname -r) /boot/initrd.img-$(uname -r).bak 2>/dev/null || true",
                "cat /proc/cmdline > ~/kernel_cmdline_backup.txt",
            ],
            rollback_steps=[
                "# === Rollback steps ===",
                "# If system is abnormal after kernel upgrade:",
                "# 1. Select old kernel in GRUB during restart",
                "# 2. Restore backup: sudo cp /boot/vmlinuz-$(uname -r).bak /boot/vmlinuz-$(uname -r)",
            ],
            temporary_mitigation=(
                "Upgrade kernel to >= 3.14.6 or install distro security patch"
            ),
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during restart to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup in recovery shell and restart"
            ),
            verify_steps=[
                "# Verify fix:",
                "uname -r  # Confirm kernel version >= 3.14.6 or already patched",
            ]
        )

    def _check_mitigation(self) -> bool:
        """Check if mitigation measures exist

        Returns:
            True if mitigation found, False otherwise
        """
        # futex isCoreKernelSuccesscan，没has简单Mitigation measures
        # MustpassedKernelPatch修复
        return False

    def _get_poc_verifier(self):
        """Return CVE-2014-3153  PoC Verifier 实例"""
        from ..poc.cve_2014_3153_poc import CVE20143153PoCVerifier
        return CVE20143153PoCVerifier()

    def prepare(self, kernel_info: KernelInfo) -> PrepareResult:
        """
        CVE-2014-3153 Prepare phase
        """
        from .cve_2014_3153_prepare import CVE20143153PrepareHandler

        handler = CVE20143153PrepareHandler(timeout=30)
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None) -> PostResult:
        """
        CVE-2014-3153 Post phase
        """
        from .cve_2014_3153_post import CVE20143153PostHandler

        handler = CVE20143153PostHandler(
            prepare_result=prepare_result,
            timeout=30
        )
        return handler.execute()

    def run_poc(self, kernel_info: KernelInfo, output_dir: str,
                enable_prepare: bool = True,
                enable_post: bool = True,
                poc_user: str = "nobody",
                force_demote: bool = True,
                force_run: bool = False) -> PoCResult:
        """
        Execute CVE-2014-3153 PoC Verification (three-phase)

        Pre-check:
        1. Confirm version is in affected range
        2. Confirm futex Configuration enabled
        3. Execute PoC through three-phase flow (Prepare -> Run -> Post)
        """
        if not force_run:
            # Pre-check: Version
            if not version_in_range(kernel_info.version, self._MIN_VERSION,
                                    fixed_version=self._FIXED_VERSION):
                return PoCResult(
                    status="NOT_EXPLOITABLE",
                    confidence=0.9,
                    error_message="Kernel version not in affected range"
                )

            # Pre-check: ConfigurationisWhetherAvailable
            config_enabled = check_config_enabled(self._CONFIG_KEY, kernel_info.config)
            if not config_enabled and kernel_info.config is not None:
                return PoCResult(
                    status="NOT_EXPLOITABLE",
                    confidence=0.8,
                    error_message="CONFIG_FUTEX not enabled"
                )

        # Call the specialized PoC verifier (three-phase flow)
        verifier = self._get_poc_verifier()
        if verifier is not None:
            return verifier.verify(
                kernel_info, output_dir,
                poc_user=poc_user,
                enable_prepare=enable_prepare,
                enable_post=enable_post,
                force_demote=force_demote,
                force_run=force_run,
            )

        # Call the base class run_poc with three-phase support
        return super().run_poc(
            kernel_info, output_dir,
            enable_prepare=enable_prepare,
            enable_post=enable_post,
            poc_user=poc_user,
            force_demote=force_demote,
                force_run=force_run
        )
