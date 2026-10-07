"""
CVE-2023-2163 Detector - eBPF verifier miscalculation allows out-of-bounds read/write

Vulnerability Description:
    eBPF verifier miscalculation allows out-of-bounds read/write - Local Privilege Escalation

Affected Version: 5.4.0 <= kernel < 6.3.0
CVSS: 8.8 (HIGH)
Exploitation Condition: CONFIG_BPF_SYSCALL enabled

Detection Method (read-only throughout):
    1. Kernel version range match
    2. CONFIG_BPF_SYSCALL configuration check
    3. Mitigation detection
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


class CVE20232163Detector(BaseDetector):
    """CVE-2023-2163 (eBPF verifier miscalculation allows out-of-bounds ) Detector"""

    cve_id = "CVE-2023-2163"
    cvss_score = 8.8
    severity = "HIGH"
    description = (
        "eBPF verifier miscalculation allows out-of-bounds read/write - "
        "Local Privilege Escalation"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "generic": {"min": "5.4.0", "fixed": "6.3.0"},
    }

    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2023_2163.bin"
    poc_mode = "uaf"

    _MODULE_NAME = "bpf"
    _CONFIG_KEY = "CONFIG_BPF_SYSCALL"
    _MIN_VERSION = "5.4.0"
    _FIXED_VERSION = "6.3.0"

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        evidence_list: List[Evidence] = []
        confidence = 0.0

        version_vulnerable = version_in_range(
            kernel_info.version, self._MIN_VERSION,
            fixed_version=self._FIXED_VERSION
        )

        if not version_vulnerable:
            evidence_list.append(Evidence(
                type="version_match",
                description=(
                    f"Kernel version {kernel_info.version} not in affected range "
                    f"[{self._MIN_VERSION}, {self._FIXED_VERSION})"
                ),
                raw_data=kernel_info.version, source="uname -r"
            ))
            return DetectResult(
                cve_id=self.cve_id, status="NOT_VULNERABLE",
                confidence=0.95, severity=self.severity,
                cvss_score=self.cvss_score, description=self.description,
                vuln_type=self.vuln_type, evidence=evidence_list,
                remediation=None
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
                description=f"{self._CONFIG_KEY}={config_value} - BPF enabled",
                raw_data=f"{self._CONFIG_KEY}={config_value}",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence += 0.25
        elif kernel_info.config:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY} not enabled",
                raw_data=f"{self._CONFIG_KEY}=not set",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence -= 0.2
        else:
            evidence_list.append(Evidence(
                type="config_enabled",
                description="Cannot read kernel configuration",
                raw_data="config not accessible",
                source="/proc/config.gz or /boot/config-*"
            ))

        mitigation_detected = self._check_mitigation()
        if mitigation_detected:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="Mitigation detected",
                raw_data="mitigation active",
                source="system check"
            ))
            confidence -= 0.3
        else:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="No effective mitigation detected",
                raw_data="no mitigation active",
                source="system check"
            ))

        if confidence >= 0.6:
            status = "VULNERABLE"
        elif confidence >= 0.4:
            status = "UNCERTAIN"
        else:
            status = "NOT_VULNERABLE"

        confidence = max(0.0, min(1.0, confidence))

        return DetectResult(
            cve_id=self.cve_id, status=status,
            confidence=confidence, severity=self.severity,
            cvss_score=self.cvss_score, description=self.description,
            vuln_type=self.vuln_type, evidence=evidence_list,
            remediation=self.get_remediation() if status == "VULNERABLE" else None
        )

    def get_remediation(self) -> Remediation:
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Solution A: Upgrade kernel",
                "sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "",
                "# 2. Restart system to apply new kernel",
                "sudo reboot",
                "",
                "# 3. Verify fix",
                "uname -r  # Confirm new kernel version >= 6.3.0",
            ],
            backup_steps=[
                "sudo cp /boot/vmlinuz-$(uname -r) /boot/vmlinuz-$(uname -r).bak",
            ],
            rollback_steps=[
                "# Select old kernel in GRUB during restart",
            ],
            temporary_mitigation="sysctl kernel.unprivileged_bpf_disabled=1",
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during restart to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup in recovery shell and restart"
            ),
            verify_steps=[
                "uname -r  # Confirm kernel version >= 6.3.0",
            ]
        )

    def _check_mitigation(self) -> bool:
        import subprocess
        try:
            result = subprocess.run(
                ["sysctl", "-n", "kernel.unprivileged_bpf_disabled"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip() == "1"
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return False

    def _get_poc_verifier(self):
        from ..poc.cve_2023_2163_poc import CVE20232163PoCVerifier
        return CVE20232163PoCVerifier()

    def prepare(self, kernel_info: KernelInfo) -> PrepareResult:
        from .cve_2023_2163_prepare import CVE20232163PrepareHandler
        handler = CVE20232163PrepareHandler(timeout=30)
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None) -> PostResult:
        from .cve_2023_2163_post import CVE20232163PostHandler
        handler = CVE20232163PostHandler(
            prepare_result=prepare_result, timeout=30
        )
        return handler.execute()

    def run_poc(self, kernel_info: KernelInfo, output_dir: str,
                enable_prepare: bool = True, enable_post: bool = True,
                poc_user: str = "nobody", force_demote: bool = True,
                force_run: bool = False) -> PoCResult:
        if not force_run:
            if not version_in_range(kernel_info.version, self._MIN_VERSION,
                                    fixed_version=self._FIXED_VERSION):
                return PoCResult(
                    status="NOT_EXPLOITABLE", confidence=0.9,
                    error_message="Kernel version not in affected range"
                )

            config_enabled = check_config_enabled(self._CONFIG_KEY, kernel_info.config)
            if not config_enabled and kernel_info.config is not None:
                return PoCResult(
                    status="NOT_EXPLOITABLE", confidence=0.8,
                    error_message="CONFIG_BPF_SYSCALL not enabled"
                )

        verifier = self._get_poc_verifier()
        if verifier is not None:
            return verifier.verify(
                kernel_info, output_dir,
                poc_user=poc_user, enable_prepare=enable_prepare,
                enable_post=enable_post, force_demote=force_demote,
                force_run=force_run,
            )

        return super().run_poc(
            kernel_info, output_dir,
            enable_prepare=enable_prepare, enable_post=enable_post,
            poc_user=poc_user, force_demote=force_demote,
                force_run=force_run
        )
