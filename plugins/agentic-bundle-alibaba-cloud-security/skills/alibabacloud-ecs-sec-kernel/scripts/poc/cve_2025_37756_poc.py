"""PoC verifier for CVE-2025-37756"""
from .base import BasePoCVerifier

class CVECve202537756PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-37756"
    poc_bin = "poc-bin/cve_2025_37756.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_37756_prepare import CVECve202537756PrepareHandler
        return CVECve202537756PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_37756_post import CVECve202537756PostHandler
        return CVECve202537756PostHandler()
