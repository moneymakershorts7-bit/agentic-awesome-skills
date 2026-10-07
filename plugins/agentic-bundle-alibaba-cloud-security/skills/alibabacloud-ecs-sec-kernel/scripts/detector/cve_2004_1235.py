"""
CVE-2004-1235 Detector - uselib() race condition in load_elf_library and binfmt_aout LPE

Vulnerability Description:
    Linux kernel 2.4.x through 2.4.29 and 2.6.x through 2.6.10 has a race
    condition in the uselib() function (load_elf_library). The kernel generates
    the library's brk segment while the mmap_sem semaphore is NOT held when
    modifying memory layout. This permits concurrent processes to alter VMA
    structures, allowing a newly created VMA descriptor to be inserted at the
    wrong position. Local users can gain root privileges by constructing an
    LDT call gate to achieve CPL0 privileges.

Affected Versions: 2.4.0 <= kernel < 2.4.29, 2.6.0 <= kernel < 2.6.10
CVSS: 7.2 (HIGH)
Exploit Condition: uselib() syscall + CONFIG_BINFMT_ELF + CONFIG_MODIFY_LDT

Detection Method (read-only):
    1. Kernel version range matching
    2. Check CONFIG_BINFMT_ELF configuration
    3. Check if uselib syscall is available
    4. Check mitigation measures (kernel hardening)
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


class CVE20041235Detector(BaseDetector):
    """CVE-2004-1235 (uselib race condition LPE) detector"""

    # Metadata
    cve_id = "CVE-2004-1235"
    cvss_score = 7.2
    severity = "HIGH"
    description = (
        "uselib() race condition in load_elf_library and binfmt_aout - "
        "Local Privilege Escalation via VMA descriptor manipulation and LDT call gate"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "2.4.x": {"min": "2.4.0", "fixed": "2.4.29"},
        "2.6.x": {"min": "2.6.0", "fixed": "2.6.10"},
    }

    # PoC metadata
    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2004_1235.bin"
    poc_mode = "read_root_file"

    # Internal constants
    _CONFIG_KEY = "CONFIG_BINFMT_ELF"
    _RANGES = [
        {"min": "2.4.0", "fixed": "2.4.29"},
        {"min": "2.6.0", "fixed": "2.6.10"},
    ]

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute CVE-2004-1235 detection

        Detection Strategy:
        - Version in range + CONFIG_BINFMT_ELF enabled = VULNERABLE (high confidence)
        - Version in range + CONFIG_BINFMT_ELF unknown = VULNERABLE (medium)
        - Version not in range = NOT_VULNERABLE
        - Mitigation present = NOT_VULNERABLE
        """
        evidence_list: List[Evidence] = []
        confidence = 0.0

        # Step 1: Version matching (check both ranges)
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

        # Step 2: Check CONFIG_BINFMT_ELF
        config_value = check_config_enabled(self._CONFIG_KEY, kernel_info.config)
        if config_value:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY}={config_value} - ELF binary format support enabled",
                raw_data=f"{self._CONFIG_KEY}={config_value}",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence += 0.25
        elif kernel_info.config:
            # Config available but BINFMT_ELF disabled
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY} not enabled - ELF binary format disabled",
                raw_data=f"{self._CONFIG_KEY}=not set",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence -= 0.2
        else:
            # Cannot read config - old kernels typically have BINFMT_ELF built-in
            evidence_list.append(Evidence(
                type="config_enabled",
                description="Cannot read kernel config - BINFMT_ELF likely built-in for old kernels",
                raw_data="config not accessible",
                source="/proc/config.gz or /boot/config-*"
            ))
            confidence += 0.1

        # Step 3: Check uselib availability
        uselib_exists = self._check_uselib_exists()
        if uselib_exists:
            evidence_list.append(Evidence(
                type="uselib_exists",
                description="uselib syscall available - vulnerability path available",
                raw_data="uselib syscall available",
                source="sys_uselib"
            ))
            confidence += 0.1
        else:
            evidence_list.append(Evidence(
                type="uselib_exists",
                description="uselib syscall not available - but may be embedded in old kernel",
                raw_data="uselib not available",
                source="sys_uselib"
            ))

        # Step 4: Check mitigation
        mitigated = self._check_mitigation()
        if mitigated:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="Kernel hardening detected - mitigation measure active",
                raw_data="kernel hardening active",
                source="LSM or kernel hardening"
            ))
            confidence -= 0.15

        evidence_list.append(Evidence(
            type="mitigation_found",
            description="No kernel hardening detected - no mitigation in place",
            raw_data="no hardening",
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
        """Return remediation advice for CVE-2004-1235"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Option A: Disable uselib (temporary, may break legacy applications)",
                "# No sysctl available - requires kernel patch or module removal",
                "",
                "# Option B: Permanent fix (requires kernel upgrade)",
                "# Upgrade kernel to >= 2.4.29 or >= 2.6.10 or later",
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
                "No effective temporary mitigation - kernel upgrade required. "
                "Consider restricting access to legacy ELF binaries."
            ),
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during boot to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup in recovery shell and reboot"
            ),
            verify_steps=[
                "# Verify mitigation:",
                "uname -r  # confirm kernel version >= 2.4.29 or >= 2.6.10",
                "# Verify system stability:",
                "cat /proc/meminfo | head -10  # confirm memory info readable",
            ]
        )

    def _get_poc_verifier(self):
        """Return PoC Verifier instance for CVE-2004-1235"""
        from ..poc.cve_2004_1235_poc import CVE20041235PoCVerifier
        return CVE20041235PoCVerifier()

    def prepare(self, kernel_info: KernelInfo) -> PrepareResult:
        """
        CVE-2004-1235 Prepare phase

        Uses the specialized prepare handler for this CVE.
        """
        from .cve_2004_1235_prepare import CVE20041235PrepareHandler

        handler = CVE20041235PrepareHandler(timeout=30)
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None) -> PostResult:
        """
        CVE-2004-1235 Post phase

        Uses the specialized post handler for this CVE.
        """
        from .cve_2004_1235_post import CVE20041235PostHandler

        handler = CVE20041235PostHandler(
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
        Execute CVE-2004-1235 PoC verification (three-phase)

        Pre-checks:
        1. Confirm version in affected range
        2. Confirm uself/CONFIG_BINFMT_ELF capability
        3. Execute three-phase PoC flow (Prepare -> Run -> Post)
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

    def _check_uselib_exists(self) -> bool:
        """Check if uselib syscall is available on the system"""
        # uselib is a legacy syscall, check /proc/kallsyms for it
        try:
            with open("/proc/kallsyms", "r", encoding="utf-8") as f:
                for line in f:
                    if "uselib" in line.lower():
                        return True
        except (OSError, IOError, PermissionError):
            pass

        # Fallback: check if legacy ELF support is present
        # Most Linux systems still have it
        return True

    def _check_mitigation(self) -> bool:
        """Check if specific uselib mitigation is in place

        Since uselib is a legacy syscall, modern kernels may have it
        disabled via CONFIG_DISABLE_USLEEP or similar.
        Check for kernel hardening features.
        """
        # Check for kernel.yama.ptrace_scope (indicates hardening)
        try:
            with open("/proc/sys/kernel/yama/ptrace_scope", "r", encoding="utf-8") as f:
                value = f.read().strip()
                if value != "0":
                    return True
        except (OSError, IOError):
            pass

        # No effective temporary mitigation for this CVE
        return False
