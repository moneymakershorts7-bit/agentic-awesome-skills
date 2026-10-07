"""PoC verifier for CVE-2025-21836"""
from .base import BasePoCVerifier

class CVECve202521836PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-21836"
    poc_bin = "poc-bin/cve_2025_21836.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_21836_prepare import CVECve202521836PrepareHandler
        return CVECve202521836PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_21836_post import CVECve202521836PostHandler
        return CVECve202521836PostHandler()
