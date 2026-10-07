"""PoC verifier for CVE-2025-38083"""
from .base import BasePoCVerifier

class CVECve202538083PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-38083"
    poc_bin = "poc-bin/cve_2025_38083.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_38083_prepare import CVECve202538083PrepareHandler
        return CVECve202538083PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_38083_post import CVECve202538083PostHandler
        return CVECve202538083PostHandler()
