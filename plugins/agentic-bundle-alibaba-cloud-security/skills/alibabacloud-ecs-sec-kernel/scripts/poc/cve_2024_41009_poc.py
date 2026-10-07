"""PoC verifier for CVE-2024-41009"""
from .base import BasePoCVerifier

class CVECve202441009PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-41009"
    poc_bin = "poc-bin/cve_2024_41009.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_41009_prepare import CVECve202441009PrepareHandler
        return CVECve202441009PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_41009_post import CVECve202441009PostHandler
        return CVECve202441009PostHandler()
