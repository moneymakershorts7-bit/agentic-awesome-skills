"""PoC verifier for CVE-2024-41010"""
from .base import BasePoCVerifier

class CVECve202441010PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-41010"
    poc_bin = "poc-bin/cve_2024_41010.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_41010_prepare import CVECve202441010PrepareHandler
        return CVECve202441010PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_41010_post import CVECve202441010PostHandler
        return CVECve202441010PostHandler()
