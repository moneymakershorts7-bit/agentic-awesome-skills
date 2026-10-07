"""PoC verifier for CVE-2024-26809"""
from .base import BasePoCVerifier

class CVECve202426809PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-26809"
    poc_bin = "poc-bin/cve_2024_26809.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_26809_prepare import CVECve202426809PrepareHandler
        return CVECve202426809PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_26809_post import CVECve202426809PostHandler
        return CVECve202426809PostHandler()
