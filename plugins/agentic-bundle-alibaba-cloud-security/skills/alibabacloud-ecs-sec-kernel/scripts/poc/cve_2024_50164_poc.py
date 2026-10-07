"""PoC verifier for CVE-2024-50164"""
from .base import BasePoCVerifier

class CVECve202450164PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-50164"
    poc_bin = "poc-bin/cve_2024_50164.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_50164_prepare import CVECve202450164PrepareHandler
        return CVECve202450164PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_50164_post import CVECve202450164PostHandler
        return CVECve202450164PostHandler()
