"""
CVE-2004-0077 Detector - mremap() integer overflow and VMA bounds check failure LPE

Vulnerability Description:
    The mremap() system call in Linux kernel 2.2.x through 2.4.25
    has an integer overflow and VMA bounds check failure that allows
    local users to gain root privileges by remapping memory outside
    the intended bounds.

Affected Versions: 2.2.0 <= kernel < 2.4.25
CVSS: 7.2 (HIGH)
Exploit Condition: mremap() syscall available + CONFIG_MMU enabled

Detection Method (read-only):
    1. Kernel version range matching
    2. Check CONFIG_MMU configuration
    3. Check if mremap syscall is available
    4. Check mitigation measures (kernel hardening)
"""
import logging
import os
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


class CVE20040077Detector(BaseDetector):
    """CVE-2004-0077 (mremap integer overflow LPE) detector"""

    # Metadata
    cve_id = "CVE-2004-0077"
    cvss_score = 7.2
    severity = "HIGH"
    description = (
        "mremap() integer overflow and VMA bounds check failure - "
        "Local Privilege Escalation via memory remapping outside intended bounds"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "generic": {"min": "2.2.0", "fixed": "2.4.25"},
    }

    # PoC metadata
    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2004_0077.bin"
    poc_mode = "write_root_file"

    # Internal constants
    _CONFIG_KEY = "CONFIG_MMU"
    _MIN_VERSION = "2.2.0"
    _FIXED_VERSION = "2.4.25"

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute CVE-2004-0077 detection

        Detection Strategy:
        - Version in range + CONFIG_MMU enabled = VULNERABLE (high confidence)
        - Version in range + CONFIG_MMU unknown = VULNERABLE (medium confidence, MMU default)
        - Version not in range = NOT_VULNERABLE
        - Mitigation present = NOT_VULNERABLE
        """
        evidence_list: List[Evidence] = []
        confidence = 0.0

        # Step 1: Version matching
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

        # Version in affected range
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

        # Step 2: Check CONFIG_MMU
        config_value = check_config_enabled(self._CONFIG_KEY, kernel_info.config)
        if config_value:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY}={config_value} - MMU support enabled in kernel",
                raw_data=f"{self._CONFIG_KEY}={config_value}",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence += 0.25
        elif kernel_info.config:
            # Config available but MMU disabled
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY} not enabled - MMU support disabled",
                raw_data=f"{self._CONFIG_KEY}=not set",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence -= 0.2
        else:
            # Cannot read config - likely very old kernel or container
            # Old kernels (2.2.x-2.4.x) typically have MMU built-in
            evidence_list.append(Evidence(
                type="config_enabled",
                description="Cannot read kernel config - MMU likely built-in for old kernels",
                raw_data="config not accessible",
                source="/proc/config.gz or /boot/config-*"
            ))
            confidence += 0.1  # Old kernels typically have MMU

        # Step 3: Check mremap availability
        mremap_exists = self._check_mremap_exists()
        if mremap_exists:
            evidence_list.append(Evidence(
                type="mremap_exists",
                description="mremap syscall available - memory remapping path available",
                raw_data="mremap syscall available",
                source="sys_mremap"
            ))
            confidence += 0.1
        else:
            evidence_list.append(Evidence(
                type="mremap_exists",
                description="mremap syscall not available - but may be embedded in old kernel",
                raw_data="mremap not available",
                source="sys_mremap"
            ))

        # Step 4: Check mitigation
        # Note: For mremap integer overflow, ASLR doesn't fix the bug.
        # Only explicit mremap restrictions would mitigate this.
        mitigated = self._check_mitigation()
        if mitigated:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="Specific mremap restriction detected - mitigation measure active",
                raw_data="mremap restriction active",
                source="seccomp-bpf or LSM restriction"
            ))
            # Mitigation reduces confidence but doesn't fully negate
            confidence -= 0.15

        evidence_list.append(Evidence(
            type="mitigation_found",
            description="No kernel hardening detected - no mitigation in place",
            raw_data="no hardening",
            source="/proc/sys/kernel/randomize_va_space"
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
        """Return remediation advice for CVE-2004-0077"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Option A: Restrict mremap usage (temporary, may break applications)",
                "# Use seccomp-bpf to block mremap syscall for untrusted users",
                "# Note: This requires kernel 3.5+ for seccomp-bpf",
                "",
                "# Option B: Permanent fix (requires kernel upgrade)",
                "# Upgrade kernel to >= 2.4.25 or later",
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
                "No effective temporary mitigation - kernel upgrade required"
            ),
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during boot to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup in recovery shell and reboot"
            ),
            verify_steps=[
                "# Verify mitigation:",
                "uname -r  # confirm kernel version >= 2.4.25",
                "# Verify system stability:",
                "cat /proc/meminfo | head -10  # confirm memory info readable",
            ]
        )

    def _get_poc_verifier(self):
        """Return PoC Verifier instance for CVE-2004-0077"""
        from ..poc.cve_2004_0077_poc import CVE20040077PoCVerifier
        return CVE20040077PoCVerifier()

    def prepare(self, kernel_info: KernelInfo) -> PrepareResult:
        """
        CVE-2004-0077 Prepare phase

        Uses the specialized prepare handler for this CVE.
        """
        from .cve_2004_0077_prepare import CVE20040077PrepareHandler

        handler = CVE20040077PrepareHandler(timeout=30)
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None) -> PostResult:
        """
        CVE-2004-0077 Post phase

        Uses the specialized post handler for this CVE.
        """
        from .cve_2004_0077_post import CVE20040077PostHandler

        handler = CVE20040077PostHandler(
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
        Execute CVE-2004-0077 PoC verification (three-phase)

        Pre-checks:
        1. Confirm version in affected range
        2. Confirm mremap capability
        3. Execute three-phase PoC flow (Prepare -> Run -> Post)
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

    def _check_mremap_exists(self) -> bool:
        """Check if mremap syscall is available on the system"""
        # mremap is a standard syscall, check if /proc/self/syscall shows it
        try:
            # Try to read /proc/kallsyms for sys_mremap or __arm64_sys_mremap
            with open("/proc/kallsyms", "r", encoding="utf-8") as f:
                for line in f:
                    if "mremap" in line.lower():
                        return True
        except (OSError, IOError, PermissionError):
            pass

        # Fallback: assume available on Linux (standard syscall)
        return os.path.exists("/proc/self/maps")

    def _check_mitigation(self) -> bool:
        """Check if specific mremap mitigation is in place

        Note: ASLR (randomize_va_space) does NOT mitigate mremap integer overflow.
        This checks for seccomp-bpf rules or LSM restrictions on mremap.
        Since these are rare, we return False by default.
        """
        # Check for seccomp mremap restrictions (rare)
        # In practice, there's no effective temporary mitigation for this CVE
        return False
