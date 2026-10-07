"""PoC verifier for CVE-2024-58240"""
from .base import BasePoCVerifier

class CVECve202458240PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-58240"
    poc_bin = "poc-bin/cve_2024_58240.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_58240_prepare import CVECve202458240PrepareHandler
        return CVECve202458240PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_58240_post import CVECve202458240PostHandler
        return CVECve202458240PostHandler()
