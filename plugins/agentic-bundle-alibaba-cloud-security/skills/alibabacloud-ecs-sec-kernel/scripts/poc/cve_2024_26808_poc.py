"""PoC verifier for CVE-2024-26808"""
from .base import BasePoCVerifier

class CVECve202426808PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-26808"
    poc_bin = "poc-bin/cve_2024_26808.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_26808_prepare import CVECve202426808PrepareHandler
        return CVECve202426808PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_26808_post import CVECve202426808PostHandler
        return CVECve202426808PostHandler()
