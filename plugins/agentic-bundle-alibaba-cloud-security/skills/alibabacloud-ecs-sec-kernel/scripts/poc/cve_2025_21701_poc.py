"""PoC verifier for CVE-2025-21701"""
from .base import BasePoCVerifier

class CVECve202521701PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-21701"
    poc_bin = "poc-bin/cve_2025_21701.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_21701_prepare import CVECve202521701PrepareHandler
        return CVECve202521701PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_21701_post import CVECve202521701PostHandler
        return CVECve202521701PostHandler()
