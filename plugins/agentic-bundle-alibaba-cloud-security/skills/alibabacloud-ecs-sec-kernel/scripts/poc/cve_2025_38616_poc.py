"""PoC verifier for CVE-2025-38616"""
from .base import BasePoCVerifier

class CVECve202538616PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-38616"
    poc_bin = "poc-bin/cve_2025_38616.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_38616_prepare import CVECve202538616PrepareHandler
        return CVECve202538616PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_38616_post import CVECve202538616PostHandler
        return CVECve202538616PostHandler()
