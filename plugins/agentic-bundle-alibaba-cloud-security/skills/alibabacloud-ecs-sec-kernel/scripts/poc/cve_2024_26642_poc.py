"""PoC verifier for CVE-2024-26642"""
from .base import BasePoCVerifier

class CVECve202426642PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-26642"
    poc_bin = "poc-bin/cve_2024_26642.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_26642_prepare import CVECve202426642PrepareHandler
        return CVECve202426642PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_26642_post import CVECve202426642PostHandler
        return CVECve202426642PostHandler()
