"""PoC verifier for CVE-2025-38500"""
from .base import BasePoCVerifier

class CVECve202538500PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-38500"
    poc_bin = "poc-bin/cve_2025_38500.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_38500_prepare import CVECve202538500PrepareHandler
        return CVECve202538500PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_38500_post import CVECve202538500PostHandler
        return CVECve202538500PostHandler()
