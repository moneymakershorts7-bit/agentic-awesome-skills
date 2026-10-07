"""PoC verifier for CVE-2025-39965"""
from .base import BasePoCVerifier

class CVECve202539965PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-39965"
    poc_bin = "poc-bin/cve_2025_39965.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_39965_prepare import CVECve202539965PrepareHandler
        return CVECve202539965PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_39965_post import CVECve202539965PostHandler
        return CVECve202539965PostHandler()
