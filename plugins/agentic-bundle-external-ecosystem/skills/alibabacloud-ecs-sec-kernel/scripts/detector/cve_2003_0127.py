"""
CVE-2003-0127 Detector - ptrace/kmod kernel module loader LPE

Vulnerability Description:
    The kernel module loader (kmod) in Linux kernel 2.2.x through 2.4.21
    has a race condition that allows local users to gain root privileges
    by using ptrace to attach to a process that triggers module loading,
    allowing the attacker to execute arbitrary code as root.

Affected Versions: 2.2.0 <= kernel < 2.4.21
CVSS: 7.2 (HIGH)
Exploit Condition: ptrace access + kmod module loading triggered

Detection Method (read-only):
    1. Kernel version range matching
    2. Check CONFIG_KMOD configuration
    3. Check if modprobe binary exists and is accessible
    4. Check mitigation measures (kernel.ptrace_scope, modprobe.d restrictions)
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


class CVE20030127Detector(BaseDetector):
    """CVE-2003-0127 (ptrace/kmod LPE) detector"""

    # Metadata
    cve_id = "CVE-2003-0127"
    cvss_score = 7.2
    severity = "HIGH"
    description = (
        "ptrace/kmod kernel module loader interaction allows local root - "
        "Local Privilege Escalation via ptrace race condition during module loading"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "generic": {"min": "2.2.0", "fixed": "2.4.21"},
    }

    # PoC metadata
    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2003_0127.bin"
    poc_mode = "read_root_file"

    # Internal constants
    _CONFIG_KEY = "CONFIG_KMOD"
    _MIN_VERSION = "2.2.0"
    _FIXED_VERSION = "2.4.21"

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute CVE-2003-0127 detection

        Detection Strategy:
        - Version in range + kmod enabled = VULNERABLE (high confidence)
        - Version in range + kmod unknown = VULNERABLE (medium confidence, kmod default in old kernels)
        - Version not in range = NOT_VULNERABLE
        - Mitigation present = NOT_VULNERABLE (even if version in range)
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

        # Step 2: Check CONFIG_KMOD
        config_value = check_config_enabled(self._CONFIG_KEY, kernel_info.config)
        if config_value:
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY}={config_value} - kmod support enabled in kernel",
                raw_data=f"{self._CONFIG_KEY}={config_value}",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence += 0.25
        elif kernel_info.config:
            # Config available but kmod disabled
            evidence_list.append(Evidence(
                type="config_enabled",
                description=f"{self._CONFIG_KEY} not enabled - kmod support disabled",
                raw_data=f"{self._CONFIG_KEY}=not set",
                source=f"/boot/config-{kernel_info.version}"
            ))
            confidence -= 0.2
        else:
            # Cannot read config - likely very old kernel or container
            # Old kernels (2.2.x-2.4.x) often had kmod built-in
            evidence_list.append(Evidence(
                type="config_enabled",
                description="Cannot read kernel config - kmod likely built-in for old kernels",
                raw_data="config not accessible",
                source="/proc/config.gz or /boot/config-*"
            ))
            confidence += 0.1  # Old kernels typically have kmod

        # Step 3: Check modprobe accessibility
        modprobe_exists = self._check_modprobe_exists()
        if modprobe_exists:
            evidence_list.append(Evidence(
                type="modprobe_exists",
                description="modprobe binary exists - module loading path available",
                raw_data="modprobe found",
                source="/sbin/modprobe or /usr/sbin/modprobe"
            ))
            confidence += 0.1
        else:
            evidence_list.append(Evidence(
                type="modprobe_exists",
                description="modprobe binary not found - but may be embedded in old kernel",
                raw_data="modprobe not found",
                source="/sbin/modprobe"
            ))

        # Step 4: Check mitigation
        mitigated = self._check_mitigation()
        if mitigated:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="ptrace_scope restriction detected - mitigation measure active",
                raw_data="kernel.yama.ptrace_scope > 0",
                source="/proc/sys/kernel/yama/ptrace_scope"
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

        evidence_list.append(Evidence(
            type="mitigation_found",
            description="No ptrace restriction detected - no mitigation in place",
            raw_data="ptrace_scope=0 or not available",
            source="/proc/sys/kernel/yama/ptrace_scope"
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
        """Return remediation advice for CVE-2003-0127"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Option A: Disable kmod (temporary, may break module loading)",
                "echo 'kernel.modprobe=\"\"' | sudo tee -a /etc/sysctl.conf",
                "sudo sysctl -p",
                "",
                "# Option B: Restrict ptrace access (if Yama LSM available)",
                "echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope",
                "echo 'kernel.yama.ptrace_scope = 1' | sudo tee -a /etc/sysctl.d/10-ptrace.conf",
                "",
                "# Option C: Permanent fix (requires kernel upgrade)",
                "# Upgrade kernel to >= 2.4.21 or later",
                "# Ubuntu/Debian: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "# RHEL/CentOS: sudo yum update kernel",
                "",
                "# 2. Reboot to apply new kernel",
                "sudo reboot",
                "",
                "# 3. Verify fix",
                "uname -r  # confirm new kernel version",
                "cat /proc/sys/kernel/yama/ptrace_scope  # confirm ptrace restricted",
            ],
            backup_steps=[
                "# === Pre-fix backup (required) ===",
                "sudo cp -a /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d)",
                "sudo cp -a /etc/sysctl.d/ /etc/sysctl.d.bak.$(date +%Y%m%d)",
                "sudo cp /boot/vmlinuz-$(uname -r) /boot/vmlinuz-$(uname -r).bak",
                "sudo cp /boot/initrd.img-$(uname -r) /boot/initrd.img-$(uname -r).bak 2>/dev/null || true",
            ],
            rollback_steps=[
                "# === Rollback steps ===",
                "# If kmod disable causes service issues:",
                "sudo sed -i '/kernel.modprobe/d' /etc/sysctl.conf",
                "sudo sysctl -p",
                "",
                "# If kernel upgrade causes system instability:",
                "# 1. Select old kernel at GRUB boot menu",
                "# 2. Restore backup: sudo cp -a /etc/sysctl.d.bak.<date>/* /etc/sysctl.d/",
            ],
            temporary_mitigation=(
                "echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || "
                "echo 'kernel.modprobe=\"\"' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p"
            ),
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during boot to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup in recovery shell and reboot"
            ),
            verify_steps=[
                "# Verify mitigation:",
                "cat /proc/sys/kernel/yama/ptrace_scope  # should be >= 1",
                "uname -r  # confirm kernel version >= 2.4.21",
                "# Verify module loading still works:",
                "lsmod | head -5  # confirm modules list correctly",
            ]
        )

    def _get_poc_verifier(self):
        """Return PoC Verifier instance for CVE-2003-0127"""
        from ..poc.cve_2003_0127_poc import CVE20030127PoCVerifier
        return CVE20030127PoCVerifier()

    def prepare(self, kernel_info: KernelInfo) -> PrepareResult:
        """
        CVE-2003-0127 Prepare phase

        Uses the specialized prepare handler for this CVE.
        """
        from .cve_2003_0127_prepare import CVE20030127PrepareHandler

        handler = CVE20030127PrepareHandler(timeout=30)
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None) -> PostResult:
        """
        CVE-2003-0127 Post phase

        Uses the specialized post handler for this CVE.
        """
        from .cve_2003_0127_post import CVE20030127PostHandler

        handler = CVE20030127PostHandler(
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
        Execute CVE-2003-0127 PoC verification (three-phase)

        Pre-checks:
        1. Confirm version in affected range
        2. Confirm kmod/ptrace capability
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

    def _check_modprobe_exists(self) -> bool:
        """Check if modprobe binary exists on the system"""
        import os
        modprobe_paths = [
            "/sbin/modprobe",
            "/usr/sbin/modprobe",
            "/bin/modprobe",
            "/usr/bin/modprobe",
        ]
        return any(os.path.exists(p) for p in modprobe_paths)

    def _check_mitigation(self) -> bool:
        """Check if ptrace mitigation is in place (Yama LSM ptrace_scope)"""
        try:
            with open("/proc/sys/kernel/yama/ptrace_scope", "r", encoding="utf-8") as f:
                value = f.read().strip()
                return value != "0"
        except (OSError, IOError):
            # Yama not available, no ptrace restriction
            return False
