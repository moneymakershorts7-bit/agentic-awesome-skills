"""PoC verifier for CVE-2024-26582"""
from .base import BasePoCVerifier

class CVECve202426582PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-26582"
    poc_bin = "poc-bin/cve_2024_26582.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_26582_prepare import CVECve202426582PrepareHandler
        return CVECve202426582PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_26582_post import CVECve202426582PostHandler
        return CVECve202426582PostHandler()
