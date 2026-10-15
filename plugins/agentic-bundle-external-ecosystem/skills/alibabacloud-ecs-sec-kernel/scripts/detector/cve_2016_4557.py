"""
CVE-2016-4557 Detector - eBPF double-fdput() via BPF_PROG_LOAD race condition

VulnerabilityDescription:
    Linux Kernel eBPF SubSystemin BPF_PROG_LOAD OperationExistsin double-fdput()
    Race conditionConditionVulnerability。threatHandlercanToexploitationthisVulnerabilityImplementLocalPermissionElevate。

ImpactVersion: 4.4.0 <= kernel < 4.6.0
CVSS: 7.8 (HIGH)
exploitationCondition: CONFIG_BPF_SYSCALL Enable

detectionMethod（全程Read-only）:
    1. KernelVersionRangeMatch
    2. CONFIG_BPF_SYSCALL Configuration check
    3. Mitigationdetection
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


class CVE20164557Detector(BaseDetector):
    """CVE-2016-4557 (eBPF double-fdput race LPE) Detector"""

    # Metadata
    cve_id = "CVE-2016-4557"
    cvss_score = 7.8
    severity = "HIGH"
    description = (
        "eBPF double-fdput() via BPF_PROG_LOAD race condition - "
        "Local Privilege Escalation"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "generic": {"min": "4.4.0", "fixed": "4.6.0"},
        "ubuntu": {
            "16.04": {"kernel": "4.4.0", "fixed_kernel": "4.4.0-22"},
        },
        "rhel": {
            "7": {"kernel": "3.10.0", "fixed_kernel": None},
        },
        "debian": {
            "8": {"kernel": "3.16.0", "fixed_kernel": None},
        },
    }

    # PoC Metadata
    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2016_4557.bin"
    poc_mode = "uaf"

    # Internal constants
    _MODULE_NAME = "bpf"
    _CONFIG_KEY = "CONFIG_BPF_SYSCALL"
    _MIN_VERSION = "4.4.0"
    _FIXED_VERSION = "4.6.0"

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute CVE-2016-4557 detection

        detectionStrategy:
        - Version in range + config enabled + no mitigation = VULNERABLE (high confidence)
        - Version in range + config unknown = UNCERTAIN
        - Version not in range = NOT_VULNERABLE
        """
        evidence_list: List[Evidence] = []
        confidence = 0.0

        # Step 1: VersionMatch
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

        # Versionin受ImpactRangeIn
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
                description=f"{self._CONFIG_KEY}={config_value} - eBPF enabled",
                raw_data=f"{self._CONFIG_KEY}={config_value}",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence += 0.25
        elif kernel_info.config:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY} not enabled - eBPF subsystem not available",
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
                description="Mitigation detected - kernel.unprivileged_bpf_disabled=1",
                raw_data="unprivileged_bpf_disabled=1",
                source="sysctl kernel.unprivileged_bpf_disabled"
            ))
            confidence -= 0.3
        else:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="No effective mitigation detected - kernel.unprivileged_bpf_disabled=0 or not set",
                raw_data="no mitigation active",
                source="sysctl kernel.unprivileged_bpf_disabled"
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
        """Return CVE-2016-4557 Remediation suggestions"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Solution A: Upgrade kernel (only effective method)",
                "# Ubuntu: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "# RHEL: sudo yum update kernel",
                "# Debian: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "",
                "# Solution B: Temporary mitigation (disable unprivileged eBPF)",
                "sudo sysctl -w kernel.unprivileged_bpf_disabled=1",
                "# Make permanent:",
                "echo 'kernel.unprivileged_bpf_disabled=1' | sudo tee /etc/sysctl.d/99-bpf.conf",
                "",
                "# 2. Restart system to apply new kernel",
                "sudo reboot",
                "",
                "# 3. Verify fix",
                "uname -r  # Confirm new kernel version >= 4.6.0 or already patched",
                "sysctl kernel.unprivileged_bpf_disabled  # Should be 1",
            ],
            backup_steps=[
                "# === Pre-fix backup (mandatory) ===",
                "sudo cp /boot/vmlinuz-$(uname -r) /boot/vmlinuz-$(uname -r).bak",
                "sudo cp /boot/initrd.img-$(uname -r) /boot/initrd.img-$(uname -r).bak 2>/dev/null || true",
                "cat /proc/cmdline > ~/kernel_cmdline_backup.txt",
                "sysctl kernel.unprivileged_bpf_disabled > ~/bpf_disabled_backup.txt",
            ],
            rollback_steps=[
                "# === Rollback steps ===",
                "# If system is abnormal after kernel upgrade:",
                "# 1. Select old kernel in GRUB during restart",
                "# 2. Restore backup: sudo cp /boot/vmlinuz-$(uname -r).bak /boot/vmlinuz-$(uname -r)",
                "# 3. Restore sysctl: sudo sysctl -w kernel.unprivileged_bpf_disabled=0",
            ],
            temporary_mitigation=(
                "sudo sysctl -w kernel.unprivileged_bpf_disabled=1  # Restrict unprivileged user eBPF execution"
            ),
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during restart to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup in recovery shell and restart"
            ),
            verify_steps=[
                "# Verify fix:",
                "uname -r  # Confirm kernel version >= 4.6.0 or already patched",
                "sysctl kernel.unprivileged_bpf_disabled  # Confirm mitigation is effective",
            ]
        )

    def _check_mitigation(self) -> bool:
        """Check if mitigation exists

        Returns:
            True if mitigation found, False otherwise
        """
        import subprocess

        try:
            result = subprocess.run(
                ["sysctl", "-n", "kernel.unprivileged_bpf_disabled"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                value = result.stdout.strip()
                return value == "1"
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return False

    def _get_poc_verifier(self):
        """Return CVE-2016-4557  PoC Verifier 实例"""
        from ..poc.cve_2016_4557_poc import CVE20164557PoCVerifier
        return CVE20164557PoCVerifier()

    def prepare(self, kernel_info: KernelInfo) -> PrepareResult:
        """
        CVE-2016-4557 Prepare phase
        """
        from .cve_2016_4557_prepare import CVE20164557PrepareHandler

        handler = CVE20164557PrepareHandler(timeout=30)
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None) -> PostResult:
        """
        CVE-2016-4557 Post phase
        """
        from .cve_2016_4557_post import CVE20164557PostHandler

        handler = CVE20164557PostHandler(
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
        Execute CVE-2016-4557 PoC Verify (three-phase)

        Pre-check:
        1. ConfirmVersionin受ImpactRange
        2. Confirm eBPF Configuration enabled
        3. passed三phaseFlowExecute PoC（Prepare -> Run -> Post）
        """
        if not force_run:
            # Pre-check: version
            if not version_in_range(kernel_info.version, self._MIN_VERSION,
                                    fixed_version=self._FIXED_VERSION):
                return PoCResult(
                    status="NOT_EXPLOITABLE",
                    confidence=0.9,
                    error_message="Kernel version not in affected range"
                )

            # Pre-check: whether configuration is available
            config_enabled = check_config_enabled(self._CONFIG_KEY, kernel_info.config)
            if not config_enabled and kernel_info.config is not None:
                return PoCResult(
                    status="NOT_EXPLOITABLE",
                    confidence=0.8,
                    error_message="CONFIG_BPF_SYSCALL not enabled"
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
