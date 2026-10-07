"""PoC verifier for CVE-2025-40019"""
from .base import BasePoCVerifier

class CVECve202540019PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-40019"
    poc_bin = "poc-bin/cve_2025_40019.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_40019_prepare import CVECve202540019PrepareHandler
        return CVECve202540019PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_40019_post import CVECve202540019PostHandler
        return CVECve202540019PostHandler()
