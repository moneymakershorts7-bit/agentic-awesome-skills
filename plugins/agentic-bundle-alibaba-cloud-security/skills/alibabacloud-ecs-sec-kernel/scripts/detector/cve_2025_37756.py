"""Detector for CVE-2025-37756 - TLS improper disconnect handling. Missing explicit disallow of disconnect
operation in TLS socket layer allows state corruption during connection
teardown, enabling local privilege escalation.
"""
import logging
from .base import BaseDetector
from ..core.result import DetectResult

logger = logging.getLogger(__name__)

class CVE202537756Detector(BaseDetector):
    cve_id = "CVE-2025-37756"
    severity = "CRITICAL"
    cvss_score = 7.8
    has_poc = True
    poc_mode = "uaf"
    description = "TLS improper disconnect handling. Missing explicit disallow of disconnect operation in TLS socket layer allows state corruption during connection teardown, enabling local privilege escalation."

    def detect(self, kernel_info) -> DetectResult:
        """Detect vulnerability using standard version check flow."""
        return self._standard_detect_flow(kernel_info)

    def get_remediation(self):
        """Return remediation guidance for CVE-2025-37756."""
        from ..core.result import Remediation
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "Upgrade kernel to version >= 6.15 (nf_tables element expiration race fix).",
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
        from ..poc.cve_2025_37756_poc import CVECve202537756PoCVerifier
        return CVECve202537756PoCVerifier()
