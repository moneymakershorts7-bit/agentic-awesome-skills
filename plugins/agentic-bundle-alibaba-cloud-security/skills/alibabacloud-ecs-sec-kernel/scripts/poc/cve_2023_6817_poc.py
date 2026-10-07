"""PoC verifier for CVE-2023-6817"""
from .base import BasePoCVerifier

class CVECve20236817PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2023-6817"
    poc_bin = "poc-bin/cve_2023_6817.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2023_6817_prepare import CVECve20236817PrepareHandler
        return CVECve20236817PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2023_6817_post import CVECve20236817PostHandler
        return CVECve20236817PostHandler()
