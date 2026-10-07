"""PoC verifier for CVE-2024-26581"""
from .base import BasePoCVerifier

class CVECve202426581PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-26581"
    poc_bin = "poc-bin/cve_2024_26581.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_26581_prepare import CVECve202426581PrepareHandler
        return CVECve202426581PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_26581_post import CVECve202426581PostHandler
        return CVECve202426581PostHandler()
