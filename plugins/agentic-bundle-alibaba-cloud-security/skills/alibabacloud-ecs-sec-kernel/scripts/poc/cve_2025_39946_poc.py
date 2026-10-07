"""PoC verifier for CVE-2025-39946"""
from .base import BasePoCVerifier

class CVECve202539946PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-39946"
    poc_bin = "poc-bin/cve_2025_39946.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_39946_prepare import CVECve202539946PrepareHandler
        return CVECve202539946PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_39946_post import CVECve202539946PostHandler
        return CVECve202539946PostHandler()
