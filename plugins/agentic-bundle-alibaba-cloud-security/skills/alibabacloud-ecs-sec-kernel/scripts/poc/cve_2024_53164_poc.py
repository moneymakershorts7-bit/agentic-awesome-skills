"""PoC verifier for CVE-2024-53164"""
from .base import BasePoCVerifier

class CVECve202453164PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-53164"
    poc_bin = "poc-bin/cve_2024_53164.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_53164_prepare import CVECve202453164PrepareHandler
        return CVECve202453164PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_53164_post import CVECve202453164PostHandler
        return CVECve202453164PostHandler()
