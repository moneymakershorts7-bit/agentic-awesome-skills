"""
CVE-2026-31431 Detector - algif_aead page cache write vulnerability (Copy Fail)

Vulnerability Description:
    Linux Kernel AF_ALG subsystem algif_aead module contains a defect that
    allows local users to write data to kernel page cache via splice() syscall,
    thereby overwriting setuid binary files to achieve local privilege escalation.

Affected Version: 4.14.0 <= kernel < 6.19.0
CVSS: 7.8 (HIGH)
Exploitation Condition: algif_aead module loaded + unprivileged user can create AF_ALG socket

Detection Method (read-only throughout):
    1. Kernel version range match
    2. algif_aead module load state check
    3. CONFIG_CRYPTO_USER_API_AEAD configuration check
    4. Mitigation check (modprobe.d disable rules)
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
from ..utils.safe_check import (
    check_config_enabled,
    check_modprobe_disabled,
)

logger = logging.getLogger(__name__)


class CVE202631431Detector(BaseDetector):
    """CVE-2026-31431 (Copy Fail) Detector"""

    # Metadata
    cve_id = "CVE-2026-31431"
    cvss_score = 7.8
    severity = "HIGH"
    description = (
        "algif_aead page cache write vulnerability (Copy Fail) - "
        "Local privilege escalation via AF_ALG splice() to page cache"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "generic": {"min": "4.14.0", "fixed": "6.19.0"},
        "ubuntu": {
            "24.04": {"kernel": "6.8.0", "fixed_kernel": None},
            "22.04": {"kernel": "5.15.0", "fixed_kernel": None},
        },
        "rhel": {
            "10.1": {"kernel": "6.12.0", "fixed_kernel": None},
        },
        "amazon": {
            "2023": {"kernel": "6.1.0", "fixed_kernel": None},
        },
    }

    # PoC Metadata
    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2026_31431.bin"
    poc_mode = "write_root_file"

    # Internal constants
    _MODULE_NAME = "algif_aead"
    _CONFIG_KEY = "CONFIG_CRYPTO_USER_API_AEAD"
    _MIN_VERSION = "4.14.0"
    _FIXED_VERSION = "6.19.0"

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute CVE-2026-31431 detection

        Detection strategy:
        - Version in range + module loaded + config enabled = VULNERABLE (high confidence)
        - Version in range + config enabled (module not loaded) = VULNERABLE (medium confidence, module can be dynamically loaded)
        - Version in range + config unknown = UNCERTAIN
        - Version not in range = NOT_VULNERABLE
        - Mitigation exists = NOT_VULNERABLE (even if version in range)
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

        # Step 2: Module detection
        module_loaded = self._MODULE_NAME in kernel_info.loaded_modules
        if module_loaded:
            evidence_list.append(Evidence(
                type="module_loaded",
                description=f"Kernel module {self._MODULE_NAME} loaded - vulnerability path reachable",
                raw_data=f"{self._MODULE_NAME} (loaded)",
                source="/proc/modules"
            ))
            confidence += 0.25
        else:
            evidence_list.append(Evidence(
                type="module_loaded",
                description=f"Kernel module {self._MODULE_NAME} not loaded - but can be dynamically loaded",
                raw_data=f"{self._MODULE_NAME} (not loaded)",
                source="/proc/modules"
            ))

        # Step 3: Configuration detection
        if kernel_info.config is not None:
            config_value = check_config_enabled(self._CONFIG_KEY, kernel_info.config)
            if config_value:
                evidence_list.append(Evidence(
                    type="config_enabled",
                    description=f"{self._CONFIG_KEY}={config_value} - AEAD crypto API compiled into kernel",
                    raw_data=f"{self._CONFIG_KEY}={config_value}",
                    source=f"/boot/config-{kernel_info.version}"
                ))
                confidence += 0.15
                if config_value == "m" and not module_loaded:
                    confidence -= 0.05
            else:
                # Has configuration info but not enabled
                evidence_list.append(Evidence(
                    type="config_enabled",
                    description=f"{self._CONFIG_KEY} not enabled - vulnerability path not reachable",
                    raw_data=f"{self._CONFIG_KEY}=not set",
                    source=f"/boot/config-{kernel_info.version}"
                ))
                confidence -= 0.2
        else:
            # Cannot read configuration (common in container environments)
            evidence_list.append(Evidence(
                type="config_enabled",
                description="Cannot read kernel config - possibly in restricted environment",
                raw_data="config not accessible",
                source="/proc/config.gz or /boot/config-*"
            ))

        # Step 4: Mitigation detection
        mitigated = check_modprobe_disabled(self._MODULE_NAME)
        if mitigated:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description=f"{self._MODULE_NAME} disabled via modprobe.d - mitigation effective",
                raw_data="modprobe disable rule found",
                source="/etc/modprobe.d/"
            ))
            # Mitigation exists, significantly reduces risk
            return DetectResult(
                cve_id=self.cve_id,
                status="NOT_VULNERABLE",
                confidence=0.85,
                severity=self.severity,
                cvss_score=self.cvss_score,
                description=self.description,
                vuln_type=self.vuln_type,
                evidence=evidence_list,
                remediation=self.get_remediation()
            )

        evidence_list.append(Evidence(
            type="mitigation_found",
            description=f"No {self._MODULE_NAME} disable rule detected - no mitigation",
            raw_data="no modprobe disable rule",
            source="/etc/modprobe.d/"
        ))

        # Step 5: Comprehensive verdict
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
        """Return CVE-2026-31431 Remediation suggestions"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Plan A: Temporary mitigation (immediate, no restart required)",
                f"echo 'install {self._MODULE_NAME} /bin/false' | sudo tee /etc/modprobe.d/disable-algif-aead.conf",
                f"sudo rmmod {self._MODULE_NAME} 2>/dev/null || true  # Unload already loaded module",
                "",
                "# Plan B: Permanent fix (requires maintenance window)",
                "# 1. Upgrade kernel to >= 6.19.0 or install distro security patch",
                "# Ubuntu: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "# RHEL: sudo dnf update kernel",
                "# Amazon Linux: sudo dnf update kernel",
                "",
                "# 2. Restart system to apply new kernel",
                "sudo reboot",
                "",
                "# 3. Verify fix",
                "uname -r  # Confirm new kernel version",
                f"lsmod | grep {self._MODULE_NAME}  # Confirm module not loaded or version already fixed",
            ],
            backup_steps=[
                "# === Pre-fix backup (mandatory) ===",
                "sudo cp -a /etc/modprobe.d/ /etc/modprobe.d.bak.$(date +%Y%m%d)",
                "sudo cp /boot/vmlinuz-$(uname -r) /boot/vmlinuz-$(uname -r).bak",
                "sudo cp /boot/initrd.img-$(uname -r) /boot/initrd.img-$(uname -r).bak 2>/dev/null || true",
                "cat /proc/cmdline > ~/kernel_cmdline_backup.txt",
                "# Recommendation: if using LVM, create system snapshot",
                "# sudo lvcreate --snapshot --name snap_pre_fix --size 10G /dev/vg0/root",
            ],
            rollback_steps=[
                "# === Rollback steps ===",
                "# If mitigation causes issues (e.g. services depending on algif_aead):",
                "sudo rm /etc/modprobe.d/disable-algif-aead.conf",
                f"sudo modprobe {self._MODULE_NAME}",
                "",
                "# If system is abnormal after kernel upgrade:",
                "# 1. Select old kernel in GRUB during restart",
                "# 2. Restore backup: sudo cp -a /etc/modprobe.d.bak.<date>/* /etc/modprobe.d/",
            ],
            temporary_mitigation=(
                f"echo 'install {self._MODULE_NAME} /bin/false' | sudo tee /etc/modprobe.d/disable-algif-aead.conf && "
                f"sudo rmmod {self._MODULE_NAME} 2>/dev/null || true"
            ),
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during restart to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup in recovery shell and restart"
            ),
            verify_steps=[
                f"# Verify mitigation is effective:",
                f"lsmod | grep {self._MODULE_NAME}  # Should produce no output",
                "cat /etc/modprobe.d/disable-algif-aead.conf  # Confirm disable rule exists",
                "# Verify no impact on other services:",
                "systemctl status dm-crypt ssh  # Confirm critical services are normal",
            ]
        )

    def _get_poc_verifier(self):
        """Return CVE-2026-31431  PoC Verifier 实例"""
        from ..poc.cve_2026_31431_poc import CVE202631431PoCVerifier
        return CVE202631431PoCVerifier()

    def prepare(self, kernel_info: KernelInfo) -> PrepareResult:
        """
        CVE-2026-31431 Prepare phase

        Uses the specialized prepare handler for this CVE.
        """
        from .cve_2026_31431_prepare import CVE202631431PrepareHandler

        handler = CVE202631431PrepareHandler(timeout=30)
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None) -> PostResult:
        """
        CVE-2026-31431 Post phase

        Uses the specialized post handler for this CVE.
        """
        from .cve_2026_31431_post import CVE202631431PostHandler

        handler = CVE202631431PostHandler(
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
        Execute CVE-2026-31431 PoC Verification (three-phase)

        Pre-check:
        1. Confirm version is in affected range
        2. Confirm algif_aead ModuleAvailable
        3. 通过三阶段流程执行 PoC（Prepare → Run → Post）
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

            # Pre-check: Module is whether available
            if (self._MODULE_NAME not in kernel_info.loaded_modules and
                    kernel_info.config is not None and
                    not check_config_enabled(self._CONFIG_KEY, kernel_info.config)):
                return PoCResult(
                    status="NOT_EXPLOITABLE",
                    confidence=0.8,
                    error_message="algif_aead module not available"
                )

        # Call the specialized PoC verifier if available (three-phase flow)
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
