"""PoC verifier for CVE-2025-38001"""
from .base import BasePoCVerifier

class CVECve202538001PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-38001"
    poc_bin = "poc-bin/cve_2025_38001.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_38001_prepare import CVECve202538001PrepareHandler
        return CVECve202538001PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_38001_post import CVECve202538001PostHandler
        return CVECve202538001PostHandler()
