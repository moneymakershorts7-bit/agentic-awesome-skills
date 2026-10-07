"""PoC verifier for CVE-2025-38477"""
from .base import BasePoCVerifier

class CVECve202538477PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-38477"
    poc_bin = "poc-bin/cve_2025_38477.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_38477_prepare import CVECve202538477PrepareHandler
        return CVECve202538477PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_38477_post import CVECve202538477PostHandler
        return CVECve202538477PostHandler()
