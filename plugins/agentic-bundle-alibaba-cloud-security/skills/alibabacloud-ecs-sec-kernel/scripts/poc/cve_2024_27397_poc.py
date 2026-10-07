"""PoC verifier for CVE-2024-27397"""
from .base import BasePoCVerifier

class CVECve202427397PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-27397"
    poc_bin = "poc-bin/cve_2024_27397.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_27397_prepare import CVECve202427397PrepareHandler
        return CVECve202427397PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_27397_post import CVECve202427397PostHandler
        return CVECve202427397PostHandler()
