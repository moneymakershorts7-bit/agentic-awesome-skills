"""
CVE-2009-2692 Detector - sock_sendpage() NULL pointer dereference via PF_PPPOX

Vulnerability Description:
    Linux kernel 2.4.4 through 2.6.31 has a local privilege escalation
    vulnerability in the sock_sendpage() function. The vulnerability arises
    from a NULL pointer dereference when sock_sendpage() is called with a
    NULL socket->ops->sendpage function pointer via PF_PPPOX sockets.

    The exploit maps NULL page, crafts a socket with NULL sendpage pointer,
    and triggers a call to user-controlled memory, achieving privilege
    escalation.

Affected Versions: 2.4.4 <= kernel < 2.6.31
CVSS: 7.2 (HIGH)
Exploit Condition: CONFIG_PPPOX + ability to map NULL page

Detection Method (read-only):
    1. Kernel version range matching
    2. Check CONFIG_PPPOE configuration
    3. Check pppox module status
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


class CVE20092692Detector(BaseDetector):
    """CVE-2009-2692 (sock_sendpage NULL ptr deref via PF_PPPOX) detector"""

    # Metadata
    cve_id = "CVE-2009-2692"
    cvss_score = 7.2
    severity = "HIGH"
    description = (
        "sock_sendpage() NULL pointer dereference via PF_PPPOX - "
        "Local Privilege Escalation"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "2.x": {"min": "2.4.4", "fixed": "2.6.31"},
    }

    # PoC metadata
    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2009_2692.bin"
    poc_mode = "write_root_file"

    # Internal constants
    _CONFIG_KEY = "CONFIG_PPPOE"
    _RANGES = [
        {"min": "2.4.4", "fixed": "2.6.31"},
    ]

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute CVE-2009-2692 detection

        Detection Strategy:
        - Version in range + CONFIG_PPPOE enabled = VULNERABLE (high confidence)
        - Version in range + CONFIG_PPPOE unknown = VULNERABLE (medium)
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

        # Step 2: Check CONFIG_PPPOE
        if kernel_info.config is not None:
            config_value = check_config_enabled(self._CONFIG_KEY, kernel_info.config)
            if config_value:
                evidence_list.append(Evidence(
                    type="config_enabled",
                    description=f"{self._CONFIG_KEY}={config_value} - PPPoE support enabled",
                    raw_data=f"{self._CONFIG_KEY}={config_value}",
                    source=f"/boot/config-{kernel_info.version}"
                ))
                confidence += 0.25
            else:
                evidence_list.append(Evidence(
                    type="config_enabled",
                    description=f"{self._CONFIG_KEY} not enabled - PPPoE disabled",
                    raw_data=f"{self._CONFIG_KEY}=not set",
                    source=f"/boot/config-{kernel_info.version}"
                ))
                confidence -= 0.2
        else:
            evidence_list.append(Evidence(
                type="config_enabled",
                description="Cannot read kernel config - PPPoE may be built-in",
                raw_data="config not accessible",
                source="/proc/config.gz or /boot/config-*"
            ))
            confidence += 0.1

        # Step 3: Check pppox module status
        module_loaded = self._check_pppox_module()
        if module_loaded:
            evidence_list.append(Evidence(
                type="module_loaded",
                description="pppox module is loaded - vulnerability path available",
                raw_data="pppox loaded",
                source="lsmod"
            ))
            confidence += 0.1
        else:
            evidence_list.append(Evidence(
                type="module_loaded",
                description="pppox module not loaded - but may still be vulnerable if loaded later",
                raw_data="pppox not loaded",
                source="lsmod"
            ))

        # Step 4: Check mitigation
        mitigated = self._check_mitigation()
        if mitigated:
            evidence_list.append(Evidence(
                type="mitigation_found",
                description="Module disable mitigation detected",
                raw_data="mitigation active",
                source="/etc/modprobe.d/"
            ))
            confidence -= 0.15

        evidence_list.append(Evidence(
            type="mitigation_status",
            description="No effective mitigation detected - vulnerability path open",
            raw_data="no mitigation",
            source="modprobe.d config"
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
        """Return remediation advice for CVE-2009-2692"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "# Option A: Disable pppox module (temporary mitigation)",
                "echo 'install pppox /bin/false' > /etc/modprobe.d/disable-pppox.conf",
                "echo 'install pppoatm /bin/false' >> /etc/modprobe.d/disable-pppox.conf",
                "echo 'install pppol2tp /bin/false' >> /etc/modprobe.d/disable-pppox.conf",
                "",
                "# Option B: Permanent fix (requires kernel upgrade)",
                "# Upgrade kernel to >= 2.6.31 or later",
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
                "sudo cp -r /etc/modprobe.d /etc/modprobe.d.bak",
            ],
            rollback_steps=[
                "# === Rollback steps ===",
                "# If kernel upgrade causes system instability:",
                "# 1. Select old kernel at GRUB boot menu",
                "# 2. Restore backup: sudo cp /boot/vmlinuz-$(uname -r).bak /boot/vmlinuz-$(uname -r)",
                "# 3. Restore modprobe config: sudo rm -rf /etc/modprobe.d && sudo mv /etc/modprobe.d.bak /etc/modprobe.d",
            ],
            temporary_mitigation=(
                "Disable pppox and related modules via modprobe.d config. "
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
                "uname -r  # confirm kernel version >= 2.6.31",
                "lsmod | grep pppox  # confirm module not loaded",
                "# Verify system stability:",
                "cat /proc/meminfo | head -10  # confirm memory info readable",
            ]
        )

    def _get_poc_verifier(self):
        """Return PoC Verifier instance for CVE-2009-2692"""
        from ..poc.cve_2009_2692_poc import CVE20092692PoCVerifier
        return CVE20092692PoCVerifier()

    def prepare(self, kernel_info: KernelInfo,
                test_mode: str = "",
                ctf_value: str = "") -> PrepareResult:
        """
        CVE-2009-2692 Prepare phase
        """
        from .cve_2009_2692_prepare import CVE20092692PrepareHandler

        handler = CVE20092692PrepareHandler(
            timeout=30,
            test_mode=test_mode,
            ctf_value=ctf_value,
        )
        return handler.execute()

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None,
             test_mode: str = "",
             ctf_value: str = "") -> PostResult:
        """
        CVE-2009-2692 Post phase
        """
        from .cve_2009_2692_post import CVE20092692PostHandler

        handler = CVE20092692PostHandler(
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
        Execute CVE-2009-2692 PoC verification (three-phase)
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

    def _check_pppox_module(self) -> bool:
        """Check if pppox module is loaded"""
        try:
            with open("/proc/modules", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("pppox"):
                        return True
        except (OSError, IOError):
            pass

        # Fallback: lsmod
        try:
            import subprocess
            result = subprocess.run(
                ["lsmod"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
                encoding="utf-8"
            )
            if result.returncode == 0:
                return "pppox" in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return False

    def _check_mitigation(self) -> bool:
        """Check if mitigation is in place

        Check if pppox module is disabled via modprobe.d config.
        """
        import os

        modprobe_dirs = [
            "/etc/modprobe.d/",
            "/lib/modprobe.d/",
            "/usr/lib/modprobe.d/",
        ]

        for dir_path in modprobe_dirs:
            if not os.path.isdir(dir_path):
                continue
            try:
                for filename in os.listdir(dir_path):
                    if not filename.endswith(".conf"):
                        continue
                    conf_path = os.path.join(dir_path, filename)
                    with open(conf_path, "r", encoding="utf-8") as f:
                        content = f.read()
                        if "install pppox /bin/false" in content:
                            return True
            except (OSError, IOError):
                continue

        return False
