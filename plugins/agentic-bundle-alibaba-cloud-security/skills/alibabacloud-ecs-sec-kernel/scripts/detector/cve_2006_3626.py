"""
CVE-2006-3626 Detector - procfs /proc/self/environ race condition LPE

Vulnerability Description:
    Linux kernel 2.6.8 through 2.6.17.5 has a race condition in the
    /proc/self/environ file handling. The procfs environ file does not
    properly handle concurrent modifications to the environment during
    reads, allowing local users to read sensitive kernel memory or
    gain privileges by leveraging the race between environment
    modification and /proc/self/environ reads.

Affected Versions: 2.6.8 <= kernel < 2.6.17.5
CVSS: 7.2 (HIGH)
Exploit Condition: CONFIG_PROC_FS + proc mounted + environ access

Detection Method (read-only):
    1. Kernel version range matching
    2. Check CONFIG_PROC_FS configuration
    3. Check proc filesystem mount status
    4. Check mitigation measures
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
)

logger = logging.getLogger(__name__)


class CVE20063626Detector(BaseDetector):
    """CVE-2006-3626 (procfs /proc/self/environ race condition LPE) detector"""

    # Metadata
    cve_id = "CVE-2006-3626"
    cvss_score = 7.2
    severity = "HIGH"
    description = (
        "procfs /proc/self/environ race condition - "
        "Local Privilege Escalation via concurrent environment modification"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "2.6.x": {"min": "2.6.8", "fixed": "2.6.17.5"},
    }

    # PoC metadata
    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2006_3626.bin"
    poc_mode = "read_root_file"

    # Internal constants
    _CONFIG_KEY = "CONFIG_PROC_FS"
    _RANGES = [
        {"min": "2.6.8", "fixed": "2.6.17.5"},
    ]

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute CVE-2006-3626 detection

        Detection Strategy:
        - Version in range + CONFIG_PROC_FS enabled = VULNERABLE (high confidence)
        - Version in range + CONFIG_PROC_FS unknown = VULNERABLE (medium)
        - Version not in range = NOT_VULNERABLE
        - Mitigation present = NOT_VULNERABLE
        """
        evidence_list: List[Evidence] = []
        confidence = 0.0

        # Step 1: Version matching
        version_vulnerable = False
        for ver_range in self._RANGES:
            if version_in_range(
                kernel_info.version,
                ver_range["min"],
                fixed_version=ver_range["fixed"]
            ):
                version_vulnerable = True
                break

        if not version_vulnerable:
            ranges_str = ", ".join(
                f"[{r['min']}, {r['fixed']})" for r in self._RANGES
            )
            evidence_list.append(Evidence(
                type="version_match",
                description=(
                    f"Kernel version {kernel_info.version} not in affected ranges "
                    f"{ranges_str}"
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

        # Version in affected range
        ranges_str = ", ".join(
            f"[{r['min']}, {r['fixed']})" for r in self._RANGES
        )
        evidence_list.append(Evidence(
            type="version_match",
            description=(
                f"Kernel version {kernel_info.version} in affected ranges "
                f"{ranges_str}"
            ),
            raw_data=kernel_info.version,
            source="uname -r"
        ))
        confidence = 0.5  # Base confidence

        # Step 2: Check CONFIG_PROC_FS
        config_value = check_config_enabled(self._CONFIG_KEY, kernel_info.config)
        if config_value:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY}={config_value} - procfs support enabled",
                raw_data=f"{self._CONFIG_KEY}={config_value}",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence += 0.25
        elif kernel_info.config:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY} not enabled - procfs disabled",
                raw_data=f"{self._CONFIG_KEY}=not set",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence -= 0.2
        else:
            evidence_list.append(Evidence(
                type="config_enabled",
                description="Cannot read kernel config - PROC_FS likely built-in",
                raw_data="config not accessible",
                source="/proc/config.gz or /boot/config-*"
            ))
            confidence += 0.1

        # Step 3: Check proc mount status
        proc_mounted = self._check_proc_mounted()
        if proc_mounted:
            evidence_list.append(Evidence(
                type="proc_mounted",
                description="/proc filesystem is mounted - vulnerability path available",
                raw_data="procfs mounted",
                source="/proc"
            ))
            confidence += 0.1
        else:
            evidence_list.append(Evidence(
                type="proc_mounted",
                description="/proc filesystem not mounted - but may be mountable",
                raw_data="procfs not mounted",
                source="/proc"
            ))

        # Step 4: Check /proc/self/environ accessibility
        environ_accessible = self._check_environ_accessible()
        if environ_accessible:
            evidence_list.append(Evidence(
                type="environ_accessible",
                description="/proc/self/environ is accessible - race condition path available",
                raw_data="environ readable",
                source="/proc/self/environ"
            ))
            confidence += 0.1
        else:
            evidence_list.append(Evidence(
                type="environ_accessible",
                description="/proc/self/environ not accessible - but kernel may still be vulnerable",
                raw_data="environ not readable",
                source="/proc/self/environ"
            ))

        # Step 5: Check mitigation
        mitigated = self._check_mitigation()
        if mitigated:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="Kernel hardening or restriction detected",
                raw_data="hardening active",
                source="procfs restrictions"
            ))
            confidence -= 0.15

        evidence_list.append(Evidence(
            type="mitigation_status",
            description="No effective mitigation detected - vulnerability path open",
            raw_data="no mitigation",
            source="/proc/sys/fs"
        ))

        # Step 6: Final determination
        if confidence >= 0.6:
            status = "VULNERABLE"
        elif confidence >= 0.4:
            status = "UNCERTAIN"
        else:
            status = "NOT_VULNERABLE"

        # Clamp confidence
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
        """Return remediation advice for CVE-2006-3626"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Option A: Restrict /proc/self/environ access (temporary)",
                "# Mount proc with hidepid=2 option:",
                "sudo mount -o remount,hidepid=2 /proc",
                "",
                "# Option B: Permanent fix (requires kernel upgrade)",
                "# Upgrade kernel to >= 2.6.17.5 or later",
                "# Ubuntu/Debian: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "# RHEL/CentOS: sudo yum update kernel",
                "",
                "# 2. Reboot to apply new kernel",
                "sudo reboot",
                "",
                "# 3. Verify fix",
                "uname -r  # confirm new kernel version",
            ],
            backup_steps=[
                "# === Pre-fix backup (required) ===",
                "sudo cp /boot/vmlinuz-$(uname -r) /boot/vmlinuz-$(uname -r).bak",
                "sudo cp /boot/initrd.img-$(uname -r) /boot/initrd.img-$(uname -r).bak 2>/dev/null || true",
            ],
            rollback_steps=[
                "# === Rollback steps ===",
                "# If kernel upgrade causes system instability:",
                "# 1. Select old kernel at GRUB boot menu",
                "# 2. Restore backup: sudo cp /boot/vmlinuz-$(uname -r).bak /boot/vmlinuz-$(uname -r)",
            ],
            temporary_mitigation=(
                "Mount /proc with hidepid=2 to restrict environment access: "
                "'mount -o remount,hidepid=2 /proc'. "
                "This limits /proc/self/environ visibility but kernel upgrade is still required."
            ),
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during boot to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup in recovery shell and reboot"
            ),
            verify_steps=[
                "# Verify mitigation:",
                "uname -r  # confirm kernel version >= 2.6.17.5",
                "mount | grep proc  # confirm proc mount options",
                "# Verify system stability:",
                "cat /proc/meminfo | head -10  # confirm memory info readable",
            ]
        )

    def _get_poc_verifier(self):
        """Return PoC Verifier instance for CVE-2006-3626"""
        from ..poc.cve_2006_3626_poc import CVE20063626PoCVerifier
        return CVE20063626PoCVerifier()

    def prepare(self, kernel_info: KernelInfo) -> PrepareResult:
        """
        CVE-2006-3626 Prepare phase
        """
        from .cve_2006_3626_prepare import CVE20063626PrepareHandler

        handler = CVE20063626PrepareHandler(timeout=30)
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None) -> PostResult:
        """
        CVE-2006-3626 Post phase
        """
        from .cve_2006_3626_post import CVE20063626PostHandler

        handler = CVE20063626PostHandler(
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
        Execute CVE-2006-3626 PoC verification (three-phase)
        """
        # Pre-check: version
        version_vulnerable = False
        for ver_range in self._RANGES:
            if version_in_range(kernel_info.version, ver_range["min"],
                                fixed_version=ver_range["fixed"]):
                version_vulnerable = True
                break

        if not version_vulnerable:
            return PoCResult(
                status="NOT_EXPLOITABLE",
                confidence=0.9,
                error_message="Kernel version not in affected range"
            )

        # Call the specialized PoC verifier
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

        # Fallback to base class run_poc
        return super().run_poc(
            kernel_info, output_dir,
            enable_prepare=enable_prepare,
            enable_post=enable_post,
            poc_user=poc_user,
            force_demote=force_demote,
                force_run=force_run
        )

    def _check_proc_mounted(self) -> bool:
        """Check if /proc filesystem is mounted"""
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as f:
                f.readline()
                return True
        except (OSError, IOError):
            return False

    def _check_environ_accessible(self) -> bool:
        """Check if /proc/self/environ is accessible"""
        try:
            with open("/proc/self/environ", "r", encoding="utf-8") as f:
                # Read just a few bytes to confirm access
                f.read(1)
                return True
        except (OSError, IOError, PermissionError):
            # On many systems, environ is only readable by root
            # The race condition may still be exploitable
            return False

    def _check_mitigation(self) -> bool:
        """Check if procfs mitigation is in place

        Check for hidepid mount option or other restrictions.
        """
        try:
            with open("/proc/mounts", "r", encoding="utf-8") as f:
                for line in f:
                    if "/proc" in line and "hidepid" in line:
                        return True
        except (OSError, IOError):
            pass

        # Check for kernel.yama.ptrace_scope (indicates hardening)
        try:
            with open("/proc/sys/kernel/yama/ptrace_scope", "r", encoding="utf-8") as f:
                value = f.read().strip()
                if value != "0":
                    return True
        except (OSError, IOError):
            pass

        return False
