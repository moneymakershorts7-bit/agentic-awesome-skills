"""PoC verifier for CVE-2024-58239"""
from .base import BasePoCVerifier

class CVECve202458239PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-58239"
    poc_bin = "poc-bin/cve_2024_58239.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_58239_prepare import CVECve202458239PrepareHandler
        return CVECve202458239PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_58239_post import CVECve202458239PostHandler
        return CVECve202458239PostHandler()
