"""PoC verifier for CVE-2024-26585"""
from .base import BasePoCVerifier

class CVECve202426585PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-26585"
    poc_bin = "poc-bin/cve_2024_26585.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_26585_prepare import CVECve202426585PrepareHandler
        return CVECve202426585PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_26585_post import CVECve202426585PostHandler
        return CVECve202426585PostHandler()
