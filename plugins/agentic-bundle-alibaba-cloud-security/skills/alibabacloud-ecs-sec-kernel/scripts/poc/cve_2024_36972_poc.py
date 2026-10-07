"""PoC verifier for CVE-2024-36972"""
from .base import BasePoCVerifier

class CVECve202436972PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-36972"
    poc_bin = "poc-bin/cve_2024_36972.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_36972_prepare import CVECve202436972PrepareHandler
        return CVECve202436972PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_36972_post import CVECve202436972PostHandler
        return CVECve202436972PostHandler()
