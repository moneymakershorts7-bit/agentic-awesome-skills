"""PoC verifier for CVE-2024-53125"""
from .base import BasePoCVerifier

class CVECve202453125PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-53125"
    poc_bin = "poc-bin/cve_2024_53125.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_53125_prepare import CVECve202453125PrepareHandler
        return CVECve202453125PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_53125_post import CVECve202453125PostHandler
        return CVECve202453125PostHandler()
