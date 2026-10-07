"""PoC verifier for CVE-2025-38350"""
from .base import BasePoCVerifier

class CVECve202538350PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-38350"
    poc_bin = "poc-bin/cve_2025_38350.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_38350_prepare import CVECve202538350PrepareHandler
        return CVECve202538350PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_38350_post import CVECve202538350PostHandler
        return CVECve202538350PostHandler()
