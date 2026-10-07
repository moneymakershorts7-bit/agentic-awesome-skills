"""PoC verifier for CVE-2025-39682"""
from .base import BasePoCVerifier

class CVECve202539682PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-39682"
    poc_bin = "poc-bin/cve_2025_39682.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_39682_prepare import CVECve202539682PrepareHandler
        return CVECve202539682PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_39682_post import CVECve202539682PostHandler
        return CVECve202539682PostHandler()
