"""PoC verifier for CVE-2025-40364"""
from .base import BasePoCVerifier

class CVECve202540364PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-40364"
    poc_bin = "poc-bin/cve_2025_40364.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_40364_prepare import CVECve202540364PrepareHandler
        return CVECve202540364PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_40364_post import CVECve202540364PostHandler
        return CVECve202540364PostHandler()
