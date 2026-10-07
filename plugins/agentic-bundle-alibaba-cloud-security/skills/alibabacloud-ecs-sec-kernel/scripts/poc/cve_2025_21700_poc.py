"""PoC verifier for CVE-2025-21700"""
from .base import BasePoCVerifier

class CVECve202521700PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-21700"
    poc_bin = "poc-bin/cve_2025_21700.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_21700_prepare import CVECve202521700PrepareHandler
        return CVECve202521700PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_21700_post import CVECve202521700PostHandler
        return CVECve202521700PostHandler()
