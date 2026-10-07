"""PoC verifier for CVE-2024-1085"""
from .base import BasePoCVerifier

class CVECve20241085PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-1085"
    poc_bin = "poc-bin/cve_2024_1085.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_1085_prepare import CVECve20241085PrepareHandler
        return CVECve20241085PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_1085_post import CVECve20241085PostHandler
        return CVECve20241085PostHandler()
