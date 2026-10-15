"""
CVE-2006-2451 Detector - prctl() PR_SET_DUMPABLE privilege escalation via core dump

Vulnerability description:
    Linux Kernel 2.6.13-2.6.17.3 Versionin，prctl(PR_SET_DUMPABLE, 2) AllowedUnprivilegedUser
    willProcess dumpable FlagSetas 2 (suidsafe mode)。WhenProcess崩溃When，KernelwillCreate
    root AllPrivilege core dump File。threatHandlercanpassedinRestrictedDirectory（such as /etc/cron.d）in
    Trigger core dump，willMaliciousConfigurationInjectionSystem，ImplementLocalprivilege elevation。

ImpactVersion: 2.6.13 <= kernel < 2.6.17.4
CVSS: 7.2 (HIGH)
exploitationCondition: fs.suid_dumpable != 0 (Default valueas 1)

Detection method (read-only throughout):
    1. Kernel version range match [2.6.13, 2.6.17.4)
    2. fs.suid_dumpable sysctl ValueCheck（shouldas 0 only thenSafe）
    3. Mitigation measuresCheck（modprobe.d Disable规thennot适for，thisasKernelInSetSuccesscan）
"""
import logging
import subprocess
from typing import List, Optional

from .base import BaseDetector
from ..core.result import (
    DetectResult, Evidence, Remediation, PoCResult,
    PrepareResult, PostResult
)
from ..core.kernel_info import KernelInfo
from ..utils.version_compare import version_in_range

logger = logging.getLogger(__name__)

# Mitigation: fs.suid_dumpable SafeValue
_SUID_DUMPABLE_SAFE = "0"
_SUID_DUMPABLE_UNSAFE = "1"
_SUID_DUMPABLE_SUIDSAFE = "2"


class CVE20062451Detector(BaseDetector):
    """CVE-2006-2451 (prctl PR_SET_DUMPABLE) Detector"""

    # Metadata
    cve_id = "CVE-2006-2451"
    cvss_score = 7.2
    severity = "HIGH"
    description = (
        "prctl() PR_SET_DUMPABLE privilege escalation via core dump to "
        "directory - Local Privilege Escalation"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "generic": {"min": "2.6.13", "fixed": "2.6.17.4"},
    }

    # PoC Metadata
    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2006_2451.bin"
    poc_mode = "read_root_file"

    # Internal constants
    _MIN_VERSION = "2.6.13"
    _FIXED_VERSION = "2.6.17.4"

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute CVE-2006-2451 detection

        Detection strategy:
        - Version in range + sysctl unsafe = VULNERABLE (high confidence)
        - Version in range + sysctl safe = NOT_VULNERABLE (mitigated)
        - Version not in range = NOT_VULNERABLE
        - Cannot read sysctl = UNCERTAIN
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

        # Step 2: Check fs.suid_dumpable sysctl value
        suid_dumpable = self._get_suid_dumpable()

        if suid_dumpable == _SUID_DUMPABLE_SAFE:
            # Mitigation already enabled
            evidence_list.append(Evidence(
                type="mitigation_found",
                description=(
                    f"fs.suid_dumpable = {suid_dumpable} - "
                    f"core dumps for suid processes disabled - mitigation effective"
                ),
                raw_data=f"fs.suid_dumpable={suid_dumpable}",
                source="sysctl fs.suid_dumpable"
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
        elif suid_dumpable == _SUID_DUMPABLE_UNSAFE:
            evidence_list.append(Evidence(
                type="suid_dumpable_check",
                description=(
                    f"fs.suid_dumpable = {suid_dumpable} - "
                    f"core dumps enabled with user ownership - vulnerability exploitable"
                ),
                raw_data=f"fs.suid_dumpable={suid_dumpable}",
                source="sysctl fs.suid_dumpable"
            ))
            confidence += 0.3
        elif suid_dumpable == _SUID_DUMPABLE_SUIDSAFE:
            # Value 2 is the dangerous suidsafe mode - core dumps created as root
            evidence_list.append(Evidence(
                type="suid_dumpable_check",
                description=(
                    f"fs.suid_dumpable = {suid_dumpable} - "
                    f"core dumps with root ownership - vulnerability exploitable with higher risk"
                ),
                raw_data=f"fs.suid_dumpable={suid_dumpable}",
                source="sysctl fs.suid_dumpable"
            ))
            confidence += 0.35
        else:
            # Cannot read
            evidence_list.append(Evidence(
                type="suid_dumpable_check",
                description="Cannot read fs.suid_dumpable - may be in container environment",
                raw_data="sysctl read failed",
                source="sysctl fs.suid_dumpable"
            ))
            confidence += 0.1

        # Step 3: Comprehensive verdict
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
        """Return CVE-2006-2451 remediation suggestions"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Plan A: Temporary mitigation (immediate, no restart required)",
                "sudo sysctl -w fs.suid_dumpable=0",
                "echo 'fs.suid_dumpable=0' | sudo tee -a /etc/sysctl.conf",
                "sudo sysctl -p",
                "",
                "# Plan B: Permanent fix (requires maintenance window)",
                "# 1. Upgrade kernel to >= 2.6.17.4 or install distro security patch",
                "# Ubuntu: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "# RHEL: sudo dnf update kernel",
                "",
                "# 2. Restart system to apply new kernel",
                "sudo reboot",
                "",
                "# 3. Verify fix",
                "uname -r  # Confirm new kernel version",
                "sysctl fs.suid_dumpable  # Confirm value is 0",
            ],
            backup_steps=[
                "# === Pre-fix backup (mandatory) ===",
                "sysctl fs.suid_dumpable > ~/suid_dumpable_backup.txt",
                "sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d)",
            ],
            rollback_steps=[
                "# === Rollback steps ===",
                "# If sysctl setting causes issues:",
                "cat ~/suid_dumpable_backup.txt  # View original value",
                "sudo sysctl -w fs.suid_dumpable=<original_value>",
                "",
                "# If system is abnormal after kernel upgrade:",
                "# 1. Select old kernel in GRUB during restart",
                "# 2. Restore sysctl.conf backup",
            ],
            temporary_mitigation="sudo sysctl -w fs.suid_dumpable=0",
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during restart to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup in recovery shell and restart"
            ),
            verify_steps=[
                "# Verify mitigation is effective:",
                "sysctl fs.suid_dumpable  # Should return 0",
                "# Verify kernel version:",
                "uname -r  # Confirm >= 2.6.17.4",
            ]
        )

    def _get_suid_dumpable(self) -> Optional[str]:
        """Read fs.suid_dumpable sysctl Value

        Returns:
            "0", "1", "2" or None (read failure)
        """
        try:
            result = subprocess.run(
                ["sysctl", "-n", "fs.suid_dumpable"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return None

    def _get_poc_verifier(self):
        """Return CVE-2006-2451 PoC Verifier instance"""
        from ..poc.cve_2006_2451_poc import CVE20062451PoCVerifier
        return CVE20062451PoCVerifier()

    def prepare(self, kernel_info: KernelInfo) -> PrepareResult:
        """CVE-2006-2451 Prepare phase"""
        from .cve_2006_2451_prepare import CVE20062451PrepareHandler

        handler = CVE20062451PrepareHandler(timeout=30)
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None) -> PostResult:
        """CVE-2006-2451 Post phase"""
        from .cve_2006_2451_post import CVE20062451PostHandler

        handler = CVE20062451PostHandler(
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
        Execute CVE-2006-2451 PoC Verification (three-phase)

        Pre-check:
        1. Confirm version is in affected range
        2. Confirm fs.suid_dumpable notSetas 0
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

            # Pre-check: sysctl Mitigation measures
            suid_dumpable = self._get_suid_dumpable()
            if suid_dumpable == _SUID_DUMPABLE_SAFE:
                return PoCResult(
                    status="NOT_EXPLOITABLE",
                    confidence=0.85,
                    error_message="fs.suid_dumpable=0 mitigation is active"
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
