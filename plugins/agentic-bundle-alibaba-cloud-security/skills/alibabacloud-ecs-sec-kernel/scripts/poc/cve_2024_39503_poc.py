"""PoC verifier for CVE-2024-39503"""
from .base import BasePoCVerifier

class CVECve202439503PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-39503"
    poc_bin = "poc-bin/cve_2024_39503.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_39503_prepare import CVECve202439503PrepareHandler
        return CVECve202439503PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_39503_post import CVECve202439503PostHandler
        return CVECve202439503PostHandler()
