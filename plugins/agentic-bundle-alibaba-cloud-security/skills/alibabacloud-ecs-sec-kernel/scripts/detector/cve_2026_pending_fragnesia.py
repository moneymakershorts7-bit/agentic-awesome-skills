"""Detector for CVE-2026-PENDING-FRAGNESIA - ESP-in-TCP Page Cache Pollution vulnerability.

Abuses logic bug in XFRM ESP-in-TCP subsystem where skb_try_coalesce()
loses SKBFL_SHARED_FRAG marker during TCP coalescing, allowing arbitrary
byte writes into read-only file page cache via AES-GCM keystream lookup table.
"""
import logging
from .base import BaseDetector
from ..core.result import DetectResult

logger = logging.getLogger(__name__)

class FragnesiaDetector(BaseDetector):
    cve_id = "CVE-2026-PENDING-FRAGNESIA"
    severity = "CRITICAL"
    cvss_score = 7.8
    has_poc = True
    poc_mode = "write_root_file"
    poc_bin = "cve_2026_pending_fragnesia.bin"
    description = "ESP-in-TCP Page Cache Pollution vulnerability (Fragnesia). Abuses skb_try_coalesce() losing SKBFL_SHARED_FRAG marker to achieve precise single-byte writes into read-only file page cache via splice-then-ULP trigger with AES-GCM keystream lookup table."

    def detect(self, kernel_info) -> DetectResult:
        """Detect vulnerability using standard version check flow."""
        return self._standard_detect_flow(kernel_info)

    def get_remediation(self):
        """Return remediation guidance for CVE-2026-PENDING-FRAGNESIA."""
        from ..core.result import Remediation
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "Upgrade kernel to latest stable version with ESP-in-TCP Page Cache Pollution fix.",
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
        from ..poc.fragnesia_poc import FragnesiaPoCVerifier
        return FragnesiaPoCVerifier()
