"""
CVE-2018-18955 Detector - User namespace map_write() nested namespace privilege escalation

Vulnerability Description:
    Linux Kernel user namespace subsystem contains a privilege escalation
    vulnerability when handling nested namespace map_write() operations.
    An attacker can construct nested user namespaces and execute map_write
    operations within them to bypass permission checks and achieve local
    privilege escalation to root.

Affected Version: 4.15.0 <= kernel < 4.19.2
CVSS: 7.0 (HIGH)
Exploitation Condition: CONFIG_USER_NS enabled + kernel.unprivileged_userns_clone=1

Detection Method (read-only throughout):
    1. Kernel version range match
    2. CONFIG_USER_NS configuration check
    3. kernel.unprivileged_userns_clone sysctl check
    4. Mitigation detection
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


class CVE201818955Detector(BaseDetector):
    """CVE-2018-18955 (user namespace map_write nested LPE) Detector"""

    # Metadata
    cve_id = "CVE-2018-18955"
    cvss_score = 7.0
    severity = "HIGH"
    description = (
        "User namespace map_write() nested namespace privilege escalation - "
        "Local Privilege Escalation via nested user namespace mapping"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "generic": {"min": "4.15.0", "fixed": "4.19.2"},
        "ubuntu": {
            "18.04": {"kernel": "4.15.0", "fixed_kernel": "4.15.0-42"},
            "18.10": {"kernel": "4.18.0", "fixed_kernel": "4.18.0-12"},
        },
        "rhel": {
            "7": {"kernel": "3.10.0", "fixed_kernel": None},
        },
        "debian": {
            "9": {"kernel": "4.9.0", "fixed_kernel": None},
        },
    }

    # PoC Metadata
    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2018_18955.bin"
    poc_mode = "uaf"

    # Internal constants
    _MODULE_NAME = "user_namespace"
    _CONFIG_KEY = "CONFIG_USER_NS"
    _MIN_VERSION = "4.15.0"
    _FIXED_VERSION = "4.19.2"

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute CVE-2018-18955 detection

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
                description=f"{self._CONFIG_KEY}={config_value} - user namespace enabled",
                raw_data=f"{self._CONFIG_KEY}={config_value}",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence += 0.25
        elif kernel_info.config:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY} not enabled - user namespace subsystem not available",
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
                description="Mitigation detected - kernel.unprivileged_userns_clone=0",
                raw_data="unprivileged_userns_clone=0",
                source="sysctl kernel.unprivileged_userns_clone"
            ))
            confidence -= 0.3
        else:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="No effective mitigation detected - kernel.unprivileged_userns_clone=1 or not set",
                raw_data="no mitigation active",
                source="sysctl kernel.unprivileged_userns_clone"
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
        """Return CVE-2018-18955 Remediation suggestions"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Solution A: Upgrade kernel (only effective method)",
                "# Ubuntu: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "# RHEL: sudo yum update kernel",
                "# Debian: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "",
                "# Solution B: Temporary mitigation (disable unprivileged user namespace)",
                "sudo sysctl -w kernel.unprivileged_userns_clone=0",
                "# Make permanent:",
                "echo 'kernel.unprivileged_userns_clone=0' | sudo tee /etc/sysctl.d/99-userns.conf",
                "",
                "# 2. Restart system to apply new kernel",
                "sudo reboot",
                "",
                "# 3. Verify fix",
                "uname -r  # Confirm new kernel version >= 4.19.2 or already patched",
                "sysctl kernel.unprivileged_userns_clone  # Should be 0",
            ],
            backup_steps=[
                "# === Pre-fix backup (mandatory) ===",
                "sudo cp /boot/vmlinuz-$(uname -r) /boot/vmlinuz-$(uname -r).bak",
                "sudo cp /boot/initrd.img-$(uname -r) /boot/initrd.img-$(uname -r).bak 2>/dev/null || true",
                "cat /proc/cmdline > ~/kernel_cmdline_backup.txt",
                "sysctl kernel.unprivileged_userns_clone > ~/userns_clone_backup.txt",
            ],
            rollback_steps=[
                "# === Rollback steps ===",
                "# If system is abnormal after kernel upgrade:",
                "# 1. Select old kernel in GRUB during restart",
                "# 2. Restore backup: sudo cp /boot/vmlinuz-$(uname -r).bak /boot/vmlinuz-$(uname -r)",
                "# 3. Restore sysctl: sudo sysctl -w kernel.unprivileged_userns_clone=1",
            ],
            temporary_mitigation=(
                "sudo sysctl -w kernel.unprivileged_userns_clone=0  # Restrict unprivileged user namespace creation"
            ),
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during restart to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup in recovery shell and restart"
            ),
            verify_steps=[
                "# Verify fix:",
                "uname -r  # Confirm kernel version >= 4.19.2 or already patched",
                "sysctl kernel.unprivileged_userns_clone  # Confirm mitigation is effective",
            ]
        )

    def _check_mitigation(self) -> bool:
        """CheckisWhetherhasMitigation measures

        Returns:
            True if mitigation found, False otherwise
        """
        import subprocess

        try:
            result = subprocess.run(
                ["sysctl", "-n", "kernel.unprivileged_userns_clone"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                value = result.stdout.strip()
                return value == "0"
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return False

    def _get_poc_verifier(self):
        """Return CVE-2018-18955  PoC Verifier 实例"""
        from ..poc.cve_2018_18955_poc import CVE201818955PoCVerifier
        return CVE201818955PoCVerifier()

    def prepare(self, kernel_info: KernelInfo) -> PrepareResult:
        """
        CVE-2018-18955 Prepare phase
        """
        from .cve_2018_18955_prepare import CVE201818955PrepareHandler

        handler = CVE201818955PrepareHandler(timeout=30)
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None) -> PostResult:
        """
        CVE-2018-18955 Post phase
        """
        from .cve_2018_18955_post import CVE201818955PostHandler

        handler = CVE201818955PostHandler(
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
        Execute CVE-2018-18955 PoC Verification (three-phase)

        Pre-check:
        1. Confirm version is in affected range
        2. Confirm user namespace Configuration enabled
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
                    error_message="CONFIG_USER_NS not enabled"
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
