"""PoC verifier for CVE-2024-26824"""
from .base import BasePoCVerifier

class CVECve202426824PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-26824"
    poc_bin = "poc-bin/cve_2024_26824.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_26824_prepare import CVECve202426824PrepareHandler
        return CVECve202426824PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_26824_post import CVECve202426824PostHandler
        return CVECve202426824PostHandler()
