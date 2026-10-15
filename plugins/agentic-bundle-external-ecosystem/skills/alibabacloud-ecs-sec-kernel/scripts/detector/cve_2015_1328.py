"""
CVE-2015-1328 Detector - OverlayFS permission bypass in user namespaces

VulnerabilityDescription:
    Linux Kernel OverlayFS subsysteminUserNamespaceinHandle upper directory
    WhenexistsPermissionElevateVulnerability。threatHandlercanToinUserNamespaceinMount overlayfs，
    并in upper DirectoryinCreate setuid root File，fromAndImplementLocal特PrivilegeUpgrade。

ImpactVersion: 3.13.0 <= kernel < 3.19.3
CVSS: 7.2 (HIGH)
exploitationCondition: CONFIG_OVERLAY_FS Enable + overlay ModulenotDisable
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


class CVE20151328Detector(BaseDetector):
    """CVE-2015-1328 (OverlayFS permission bypass in user namespaces) Detector"""

    # Metadata
    cve_id = "CVE-2015-1328"
    cvss_score = 7.2
    severity = "HIGH"
    description = (
        "OverlayFS permission bypass in user namespaces allowing file creation "
        "with arbitrary permissions - Local Privilege Escalation"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "generic": {"min": "3.13.0", "fixed": "3.19.3"},
        "ubuntu": {
            "15.04": {"kernel": "3.19.0", "fixed_kernel": "3.19.0-21"},
            "14.04": {"kernel": "3.13.0", "fixed_kernel": "3.13.0-55"},
            "12.04": {"kernel": "3.2.0", "fixed_kernel": None},
        },
        "debian": {
            "8": {"kernel": "3.16.0", "fixed_kernel": None},
        },
    }

    # PoC Metadata
    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2015_1328.bin"
    poc_mode = "write_root_file"

    # Internal constants
    _MODULE_NAME = "overlay"
    _CONFIG_KEY = "CONFIG_OVERLAY_FS"
    _MIN_VERSION = "3.13.0"
    _FIXED_VERSION = "3.19.3"

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute CVE-2015-1328 detection

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

        # Step 2: Configurationdetection
        config_value = None
        if kernel_info.config is not None:
            config_value = check_config_enabled(self._CONFIG_KEY, kernel_info.config)

        if config_value:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY}={config_value} - overlayfs enabled",
                raw_data=f"{self._CONFIG_KEY}={config_value}",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence += 0.25
        elif kernel_info.config:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY} not enabled - overlayfs subsystem not available",
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

        # Step 3: Mitigationdetection
        mitigation_detected = self._check_mitigation()
        if mitigation_detected:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="Mitigation detected - overlay Modulealreadybe modprobe.d Disable",
                raw_data="overlay module disabled via modprobe.d",
                source="/etc/modprobe.d/*.conf"
            ))
            confidence -= 0.3
        else:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="No effective mitigation detected - overlay Modulecan正常Load",
                raw_data="no mitigation active",
                source="/etc/modprobe.d/*.conf"
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
        """Return CVE-2015-1328 Remediation suggestions"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Solution A: Upgrade kernel (only effective method)",
                "# Ubuntu: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "# RHEL: sudo yum update kernel",
                "# Debian: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "",
                "# Solution B: Temporary mitigation (Disable overlay Module）",
                "echo 'install overlay /bin/false' | sudo tee /etc/modprobe.d/disable-overlay.conf",
                "# such asalready loadedModule，needRestartorManual卸载:",
                "sudo rmmod overlay 2>/dev/null || true",
                "",
                "# 2. Restart system to apply new kernel",
                "sudo reboot",
                "",
                "# 3. Verify fix",
                "uname -r  # Confirm new kernel version >= 3.19.3 or already patched",
                "lsmod | grep overlay  # Should produce no output（Modulealready disabled）",
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
                "# 3. Restore overlay Module: sudo rm /etc/modprobe.d/disable-overlay.conf",
            ],
            temporary_mitigation=(
                "echo 'install overlay /bin/false' > /etc/modprobe.d/disable-overlay.conf "
                "Disable overlay ModuleLoad"
            ),
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during restart to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup in recovery shell and restart"
            ),
            verify_steps=[
                "# Verify fix:",
                "uname -r  # Confirm kernel version >= 3.19.3 or already patched",
                "lsmod | grep overlay  # Confirm overlay Modulenot loaded",
            ]
        )

    def _check_mitigation(self) -> bool:
        """CheckisWhetherhasMitigation

        Returns:
            True if mitigation found, False otherwise
        """
        import subprocess

        # Check modprobe.d configuration
        try:
            result = subprocess.run(
                ["grep", "-r", "install.*overlay.*/bin/false", "/etc/modprobe.d/"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return False

    def _get_poc_verifier(self):
        """Return CVE-2015-1328  PoC Verifier 实例"""
        from ..poc.cve_2015_1328_poc import CVE20151328PoCVerifier
        return CVE20151328PoCVerifier()

    def prepare(self, kernel_info: KernelInfo) -> PrepareResult:
        """
        CVE-2015-1328 Prepare phase
        """
        from .cve_2015_1328_prepare import CVE20151328PrepareHandler

        handler = CVE20151328PrepareHandler(timeout=30)
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None) -> PostResult:
        """
        CVE-2015-1328 Post phase
        """
        from .cve_2015_1328_post import CVE20151328PostHandler

        handler = CVE20151328PostHandler(
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
        Execute CVE-2015-1328 PoC Verify (three-phase)

        Pre-check:
        1. ConfirmVersionin受ImpactRange
        2. Confirm overlayfs Configuration enabled
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
                    error_message="CONFIG_OVERLAY_FS not enabled"
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
