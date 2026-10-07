"""PoC verifier for CVE-2024-26925"""
from .base import BasePoCVerifier

class CVECve202426925PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-26925"
    poc_bin = "poc-bin/cve_2024_26925.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_26925_prepare import CVECve202426925PrepareHandler
        return CVECve202426925PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_26925_post import CVECve202426925PostHandler
        return CVECve202426925PostHandler()
