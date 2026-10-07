"""PoC verifier for CVE-2024-0582"""
from .base import BasePoCVerifier

class CVECve20240582PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-0582"
    poc_bin = "poc-bin/cve_2024_0582.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_0582_prepare import CVECve20240582PrepareHandler
        return CVECve20240582PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_0582_post import CVECve20240582PostHandler
        return CVECve20240582PostHandler()
