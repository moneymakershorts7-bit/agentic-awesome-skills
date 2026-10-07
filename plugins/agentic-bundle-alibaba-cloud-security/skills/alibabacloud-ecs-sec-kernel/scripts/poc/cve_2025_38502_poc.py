"""PoC verifier for CVE-2025-38502"""
from .base import BasePoCVerifier

class CVECve202538502PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-38502"
    poc_bin = "poc-bin/cve_2025_38502.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_38502_prepare import CVECve202538502PrepareHandler
        return CVECve202538502PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_38502_post import CVECve202538502PostHandler
        return CVECve202538502PostHandler()
