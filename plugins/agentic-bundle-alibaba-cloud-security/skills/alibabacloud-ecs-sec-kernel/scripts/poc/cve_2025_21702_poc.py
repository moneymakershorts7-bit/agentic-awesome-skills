"""PoC verifier for CVE-2025-21702"""
from .base import BasePoCVerifier

class CVECve202521702PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-21702"
    poc_bin = "poc-bin/cve_2025_21702.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_21702_prepare import CVECve202521702PrepareHandler
        return CVECve202521702PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_21702_post import CVECve202521702PostHandler
        return CVECve202521702PostHandler()
