"""
CVE-2013-2094 Detector - perf_swevent_init() IntegerTypeerrorCausesArrayIndexOverflow

Vulnerability description:
    The perf_swevent_init() function in Linux kernel perf_events subsystem
    UseforhasSymbolIntegerAsasArrayIndex，AllowedLocalUserpassedConstructNegative perf_event_open()
    ParameterImplementArrayOut-of-boundsAccess，fromAndPerformLocalprivilege elevation。

ImpactVersion: 3.0.0 <= kernel < 3.8.9
CVSS: 7.2 (HIGH)
exploitationCondition: CONFIG_PERF_EVENTS Enable + perf_event_paranoid < 3

Detection method (read-only throughout):
    1. Kernel version range match
    2. CONFIG_PERF_EVENTS Configuration check
    3. perf_event_paranoid mitigation measuresCheck
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


class CVE20132094Detector(BaseDetector):
    """CVE-2013-2094 (perf_swevent integer overflow) Detector"""

    # Metadata
    cve_id = "CVE-2013-2094"
    cvss_score = 7.2
    severity = "HIGH"
    description = (
        "perf_swevent_init() incorrect integer data type allowing "
        "array index overflow - Local Privilege Escalation"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "generic": {"min": "3.0.0", "fixed": "3.8.9"},
        "ubuntu": {
            "12.04": {"kernel": "3.2.0", "fixed_kernel": "3.2.0-44"},
            "13.04": {"kernel": "3.8.0", "fixed_kernel": "3.8.0-22"},
        },
        "rhel": {
            "6": {"kernel": "2.6.32", "fixed_kernel": "2.6.32-358.6.2"},
        },
        "debian": {
            "7": {"kernel": "3.2.0", "fixed_kernel": "3.2.0-4"},
        },
    }

    # PoC Metadata
    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2013_2094.bin"
    poc_mode = "uaf"

    # Internal constants
    _MODULE_NAME = "perf_event"
    _CONFIG_KEY = "CONFIG_PERF_EVENTS"
    _MIN_VERSION = "3.0.0"
    _FIXED_VERSION = "3.8.9"

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute CVE-2013-2094 detection

        Detection strategy:
        - Version in range + config enabled + no mitigation = VULNERABLE (high confidence)
        - VersioninRangeIn + Configuration enabled + paranoid >= 3 = NOT_VULNERABLE (alreadyMitigation)
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
                description=f"{self._CONFIG_KEY}={config_value} - perf_events already编译进Kernel",
                raw_data=f"{self._CONFIG_KEY}={config_value}",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence += 0.25
        elif kernel_info.config:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY} not enabled - vulnerability path not reachable",
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

        # Step 3: Mitigation detection (perf_event_paranoid)
        paranoid_value = self._check_perf_paranoid()
        if paranoid_value is not None:
            if paranoid_value >= 3:
                evidence_list.append(Evidence(
                    type="mitigation_found",
                    description=(
                        f"kernel.perf_event_paranoid={paranoid_value} (>= 3) - "
                        "perf_events already完全Disable - mitigation effective"
                    ),
                    raw_data=f"perf_event_paranoid={paranoid_value}",
                    source="/proc/sys/kernel/perf_event_paranoid"
                ))
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
            else:
                evidence_list.append(Evidence(
                    type="mitigation_found",
                    description=(
                        f"kernel.perf_event_paranoid={paranoid_value} (< 3) - "
                        "perf_events not fully disabled - No effective mitigation available"
                    ),
                    raw_data=f"perf_event_paranoid={paranoid_value}",
                    source="/proc/sys/kernel/perf_event_paranoid"
                ))
        else:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="Cannot read perf_event_paranoid - MitigationStatenot知",
                raw_data="perf_event_paranoid=unknown",
                source="/proc/sys/kernel/perf_event_paranoid"
            ))

        # Step 4: Moduledetection（补充Evidence）
        module_loaded = self._MODULE_NAME in kernel_info.loaded_modules
        if module_loaded:
            evidence_list.append(Evidence(
                type="module_loaded",
                description=f"Kernel module {self._MODULE_NAME} already loaded - vulnerability path reachable",
                raw_data=f"{self._MODULE_NAME} (loaded)",
                source="/proc/modules"
            ))
            confidence += 0.1
        else:
            evidence_list.append(Evidence(
                type="module_loaded",
                description=f"Kernel module {self._MODULE_NAME} not loaded",
                raw_data=f"{self._MODULE_NAME} (not loaded)",
                source="/proc/modules"
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
        """Return CVE-2013-2094 Remediation suggestions"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Plan A: Temporary mitigation (immediate, no restart required)",
                "sudo sysctl -w kernel.perf_event_paranoid=3",
                "echo 'kernel.perf_event_paranoid=3' | sudo tee -a /etc/sysctl.d/99-perf-paranoid.conf",
                "",
                "# Plan B: Permanent fix (requires maintenance window)",
                "# 1. Upgrade kernel to >= 3.8.9 or安装发row版ProvideSafePatch",
                "# Ubuntu: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "# RHEL: sudo yum update kernel",
                "# Debian: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "",
                "# 2. Restart system to apply new kernel",
                "sudo reboot",
                "",
                "# 3. Verify fix",
                "uname -r  # Confirm new kernel version",
                "sysctl kernel.perf_event_paranoid  # Confirm >= 3",
            ],
            backup_steps=[
                "# === Pre-fix backup (mandatory) ===",
                "sudo cp -a /etc/sysctl.d/ /etc/sysctl.d.bak.$(date +%Y%m%d)",
                "sudo cp /boot/vmlinuz-$(uname -r) /boot/vmlinuz-$(uname -r).bak",
                "sudo cp /boot/initrd.img-$(uname -r) /boot/initrd.img-$(uname -r).bak 2>/dev/null || true",
                "cat /proc/cmdline > ~/kernel_cmdline_backup.txt",
                "# Suggestion: such asResultUsefor LVM，CreateSystemSnapshot",
                "# sudo lvcreate --snapshot --name snap_pre_fix --size 10G /dev/vg0/root",
            ],
            rollback_steps=[
                "# === Rollback steps ===",
                "# such asResultMitigationSolutionCauses perf ToolnotAvailable:",
                "sudo sysctl -w kernel.perf_event_paranoid=1",
                "sudo rm /etc/sysctl.d/99-perf-paranoid.conf",
                "",
                "# If system is abnormal after kernel upgrade:",
                "# 1. Select old kernel in GRUB during restart",
                "# 2. Restore backup: sudo cp -a /etc/sysctl.d.bak.<date>/* /etc/sysctl.d/",
            ],
            temporary_mitigation=(
                "sudo sysctl -w kernel.perf_event_paranoid=3 && "
                "echo 'kernel.perf_event_paranoid=3' | sudo tee -a /etc/sysctl.d/99-perf-paranoid.conf"
            ),
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during restart to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup in recovery shell and restart"
            ),
            verify_steps=[
                "# Verify mitigation is effective:",
                "sysctl kernel.perf_event_paranoid  # Should return 3",
                "# Verify no impact on other services:",
                "perf stat ls  # Should return 'Permission denied'（预期rowas）",
                "systemctl status ssh  # Confirmcritical服务正常",
            ]
        )

    def _check_perf_paranoid(self) -> Optional[int]:
        """CheckCurrent perf_event_paranoid Value

        Returns:
            int Valueor None（Cannot readWhen）
        """
        import os
        try:
            with open("/proc/sys/kernel/perf_event_paranoid", "r", encoding="utf-8") as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None

    def _get_poc_verifier(self):
        """Return CVE-2013-2094  PoC Verifier 实例"""
        from ..poc.cve_2013_2094_poc import CVE20132094PoCVerifier
        return CVE20132094PoCVerifier()

    def prepare(self, kernel_info: KernelInfo) -> PrepareResult:
        """
        CVE-2013-2094 Prepare phase

        Uses the specialized prepare handler for this CVE.
        """
        from .cve_2013_2094_prepare import CVE20132094PrepareHandler

        handler = CVE20132094PrepareHandler(timeout=30)
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None) -> PostResult:
        """
        CVE-2013-2094 Post phase

        Uses the specialized post handler for this CVE.
        """
        from .cve_2013_2094_post import CVE20132094PostHandler

        handler = CVE20132094PostHandler(
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
        Execute CVE-2013-2094 PoC Verification (three-phase)

        Pre-check:
        1. Confirm version is in affected range
        2. Confirm perf_events Configuration enabled
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
                    error_message="CONFIG_PERF_EVENTS not enabled"
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
