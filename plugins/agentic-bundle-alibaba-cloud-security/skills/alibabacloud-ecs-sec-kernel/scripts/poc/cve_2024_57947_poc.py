"""PoC verifier for CVE-2024-57947"""
from .base import BasePoCVerifier

class CVECve202457947PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-57947"
    poc_bin = "poc-bin/cve_2024_57947.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_57947_prepare import CVECve202457947PrepareHandler
        return CVECve202457947PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_57947_post import CVECve202457947PostHandler
        return CVECve202457947PostHandler()
