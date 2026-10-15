"""
CVE-2008-0600 Detector - vmsplice local privilege escalation via improper pointer validation

Vulnerability Description:
    Linux kernel 2.6.23 through 2.6.24.2 has a local privilege escalation
    vulnerability in the vmsplice() system call. The vulnerability arises from
    improper pointer validation in the vmsplice implementation, allowing local
    users to gain root privileges by passing crafted arguments that enable
    writing to arbitrary kernel memory.

    This vulnerability was famously exploited by the "mempodipper" exploit
    and similar variants.

Affected Versions: 2.6.23 <= kernel < 2.6.24.2
CVSS: 7.8 (HIGH)
Exploit Condition: CONFIG_SPLICE + vmsplice syscall available

Detection Method (read-only):
    1. Kernel version range matching
    2. Check CONFIG_SPLICE configuration
    3. Check sys_splice availability
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
from ..utils.safe_check import check_config_enabled

logger = logging.getLogger(__name__)


class CVE20080600Detector(BaseDetector):
    """CVE-2008-0600 (vmsplice LPE via improper pointer validation) detector"""

    # Metadata
    cve_id = "CVE-2008-0600"
    cvss_score = 7.8
    severity = "HIGH"
    description = (
        "vmsplice local privilege escalation via improper pointer validation - "
        "allows local users to gain root by writing to arbitrary kernel memory"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "2.6.x": {"min": "2.6.23", "fixed": "2.6.24.2"},
    }

    # PoC metadata
    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2008_0600.bin"
    poc_mode = "write_root_file"

    # Internal constants
    _CONFIG_KEY = "CONFIG_SPLICE"
    _RANGES = [
        {"min": "2.6.23", "fixed": "2.6.24.2"},
    ]

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute CVE-2008-0600 detection

        Detection Strategy:
        - Version in range + CONFIG_SPLICE enabled = VULNERABLE (high confidence)
        - Version in range + CONFIG_SPLICE unknown = VULNERABLE (medium)
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

        # Step 2: Check CONFIG_SPLICE
        config_value = check_config_enabled(self._CONFIG_KEY, kernel_info.config)
        if config_value:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY}={config_value} - splice support enabled",
                raw_data=f"{self._CONFIG_KEY}={config_value}",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence += 0.25
        elif kernel_info.config:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY} not enabled - splice disabled",
                raw_data=f"{self._CONFIG_KEY}=not set",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence -= 0.2
        else:
            evidence_list.append(Evidence(
                type="config_enabled",
                description="Cannot read kernel config - SPLICE likely built-in",
                raw_data="config not accessible",
                source="/proc/config.gz or /boot/config-*"
            ))
            confidence += 0.1

        # Step 3: Check vmsplice syscall availability
        vmsplice_available = self._check_vmsplice_available()
        if vmsplice_available:
            evidence_list.append(Evidence(
                type="syscall_available",
                description="vmsplice syscall is available - vulnerability path available",
                raw_data="vmsplice accessible",
                source="syscall test"
            ))
            confidence += 0.1
        else:
            evidence_list.append(Evidence(
                type="syscall_available",
                description="vmsplice syscall not available - but may still be vulnerable",
                raw_data="vmsplice not accessible",
                source="syscall test"
            ))

        # Step 4: Check mitigation
        mitigated = self._check_mitigation()
        if mitigated:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="Kernel hardening or restriction detected",
                raw_data="hardening active",
                source="kernel security settings"
            ))
            confidence -= 0.15

        evidence_list.append(Evidence(
            type="mitigation_status",
            description="No effective mitigation detected - vulnerability path open",
            raw_data="no mitigation",
            source="/proc/sys/kernel"
        ))

        # Step 5: Final determination
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
        """Return remediation advice for CVE-2008-0600"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Option A: Restrict vmsplice access (temporary)",
                "# Apply seccomp filter to block vmsplice syscall:",
                "# Install libseccomp and configure application profiles",
                "",
                "# Option B: Permanent fix (requires kernel upgrade)",
                "# Upgrade kernel to >= 2.6.24.2 or later",
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
                "Apply seccomp-bpf filters to block vmsplice syscall for unprivileged users. "
                "Kernel upgrade is still required for permanent fix."
            ),
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during boot to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup in recovery shell and reboot"
            ),
            verify_steps=[
                "# Verify mitigation:",
                "uname -r  # confirm kernel version >= 2.6.24.2",
                "# Verify system stability:",
                "cat /proc/meminfo | head -10  # confirm memory info readable",
            ]
        )

    def _get_poc_verifier(self):
        """Return PoC Verifier instance for CVE-2008-0600"""
        from ..poc.cve_2008_0600_poc import CVE20080600PoCVerifier
        return CVE20080600PoCVerifier()

    def prepare(self, kernel_info: KernelInfo,
                test_mode: str = "write_root_file",
                ctf_value: str = "") -> PrepareResult:
        """
        CVE-2008-0600 Prepare phase
        """
        from .cve_2008_0600_prepare import CVE20080600PrepareHandler

        handler = CVE20080600PrepareHandler(
            timeout=30,
            test_mode=test_mode,
            ctf_value=ctf_value,
        )
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None,
             test_mode: str = "write_root_file",
             ctf_value: str = "") -> PostResult:
        """
        CVE-2008-0600 Post phase
        """
        from .cve_2008_0600_post import CVE20080600PostHandler

        handler = CVE20080600PostHandler(
            prepare_result=prepare_result,
            timeout=30,
            test_mode=test_mode,
            ctf_value=ctf_value,
        )
        return handler.execute()

    def run_poc(self, kernel_info: KernelInfo, output_dir: str,
                enable_prepare: bool = True,
                enable_post: bool = True,
                poc_user: str = "nobody",
                force_demote: bool = True,
                force_run: bool = False) -> PoCResult:
        """
        Execute CVE-2008-0600 PoC verification (three-phase)
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

    def _check_vmsplice_available(self) -> bool:
        """Check if vmsplice syscall is available"""
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            # syscall number for vmsplice is 316 on x86_64, 238 on i386
            # Just check if we can call syscall at all
            result = libc.syscall(316, 0, 0, 0, 0)
            # ENOSYS (38) means syscall exists but not implemented
            # Any other result means syscall is available
            return result != -38
        except (OSError, ImportError):
            # Can't test directly, assume available
            return True

    def _check_mitigation(self) -> bool:
        """Check if mitigation is in place

        Check for kernel hardening options.
        """
        # Check for kernel.yama.ptrace_scope (indicates hardening)
        try:
            with open("/proc/sys/kernel/yama/ptrace_scope", "r", encoding="utf-8") as f:
                value = f.read().strip()
                if value != "0":
                    return True
        except (OSError, IOError):
            pass

        # Check for kernel.dmesg_restrict (indicates hardening)
        try:
            with open("/proc/sys/kernel/dmesg_restrict", "r", encoding="utf-8") as f:
                value = f.read().strip()
                if value == "1":
                    return True
        except (OSError, IOError):
            pass

        return False
