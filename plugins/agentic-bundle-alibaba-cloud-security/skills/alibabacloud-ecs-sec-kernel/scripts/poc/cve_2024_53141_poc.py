"""PoC verifier for CVE-2024-53141"""
from .base import BasePoCVerifier

class CVECve202453141PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-53141"
    poc_bin = "poc-bin/cve_2024_53141.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_53141_prepare import CVECve202453141PrepareHandler
        return CVECve202453141PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_53141_post import CVECve202453141PostHandler
        return CVECve202453141PostHandler()
