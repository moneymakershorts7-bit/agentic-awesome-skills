"""PoC verifier for CVE-2023-6931"""
from .base import BasePoCVerifier

class CVECve20236931PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2023-6931"
    poc_bin = "poc-bin/cve_2023_6931.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2023_6931_prepare import CVECve20236931PrepareHandler
        return CVECve20236931PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2023_6931_post import CVECve20236931PostHandler
        return CVECve20236931PostHandler()
