"""Detector for CVE-2026-43500 - RxRPC rxkad Page Cache Pollution vulnerability.

Allows unprivileged users to overwrite root-owned file page cache via
AF_RXRPC + fcrypt in-place decrypt on page-cache pages shared through splice().
"""
import logging
from .base import BaseDetector
from ..core.result import DetectResult

logger = logging.getLogger(__name__)

class CVE202643500Detector(BaseDetector):
    cve_id = "CVE-2026-43500"
    severity = "CRITICAL"
    cvss_score = 7.8
    has_poc = True
    poc_mode = "write_root_file"
    description = "RxRPC rxkad Page Cache Pollution vulnerability allowing unprivileged users to overwrite root-owned file page cache via AF_RXRPC + fcrypt in-place decrypt on page-cache pages shared through splice()."

    def detect(self, kernel_info) -> DetectResult:
        """Detect vulnerability using standard version check flow."""
        return self._standard_detect_flow(kernel_info)

    def get_remediation(self):
        """Return remediation guidance for CVE-2026-43500."""
        from ..core.result import Remediation
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "Upgrade kernel to latest stable version with RxRPC rxkad Page Cache Pollution fix.",
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
        from ..poc.cve_2026_43500_poc import CVECve202643500PoCVerifier
        return CVECve202643500PoCVerifier()
