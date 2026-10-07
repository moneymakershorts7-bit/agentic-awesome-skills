"""PoC verifier for CVE-2023-4622"""
from .base import BasePoCVerifier

class Cve20234622PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2023-4622"
    poc_bin = "poc-bin/cve_2023_4622.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2023_4622_prepare import Cve20234622PrepareHandler
        return Cve20234622PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2023_4622_post import Cve20234622PostHandler
        return Cve20234622PostHandler()
