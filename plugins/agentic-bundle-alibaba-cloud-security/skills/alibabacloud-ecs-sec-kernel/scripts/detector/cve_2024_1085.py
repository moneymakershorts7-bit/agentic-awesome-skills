"""Detector for CVE-2024-1085 - nf_tables nft_setelem_catchall use-after-free. Double deactivation of catchall set elements during set destruction leads to UAF, allowing local privilege escalation."""
import logging
from .base import BaseDetector
from ..core.result import DetectResult

logger = logging.getLogger(__name__)

class CVE20241085Detector(BaseDetector):
    cve_id = "CVE-2024-1085"
    severity = "CRITICAL"
    cvss_score = 7.8
    has_poc = True
    poc_mode = "uaf"
    description = "nf_tables nft_setelem_catchall use-after-free. Double deactivation of catchall set elements during set destruction leads to UAF, allowing local privilege escalation."

    def detect(self, kernel_info) -> DetectResult:
        """Detect vulnerability using standard version check flow."""
        return self._standard_detect_flow(kernel_info)

    def get_remediation(self):
        """Return remediation guidance for CVE-2024-1085."""
        from ..core.result import Remediation
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "Upgrade kernel to version >= 6.8 (nf_tables nft_setelem_catchall UAF fix).",
                "sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
                "sudo reboot",
            ],
            backup_steps=[
                "sudo cp /boot/vmlinuz-$(uname -r) /boot/vmlinuz-$(uname -r).bak",
            ],
            rollback_steps=[
                "# Select old kernel in GRUB menu during restart",
            ],
            temporary_mitigation="Apply vendor-specific backport patch if kernel upgrade is not immediately possible.",
            kernel_recovery_mode=(
                "If kernel upgrade fails:\n"
                "1. Hold Shift during restart to enter GRUB menu\n"
                "2. Select Advanced options -> old kernel (recovery mode)\n"
                "3. Restore backup in recovery shell and restart"
            ),
            verify_steps=[
                "uname -r  # Confirm new kernel version",
            ]
        )
    def _get_poc_verifier(self):
        from ..poc.cve_2024_1085_poc import CVECve20241085PoCVerifier
        return CVECve20241085PoCVerifier()
