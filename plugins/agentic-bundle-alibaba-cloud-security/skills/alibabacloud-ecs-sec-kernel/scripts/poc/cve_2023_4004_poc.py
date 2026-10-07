"""PoC verifier for CVE-2023-4004"""
from .base import BasePoCVerifier

class Cve20234004PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2023-4004"
    poc_bin = "poc-bin/cve_2023_4004.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2023_4004_prepare import Cve20234004PrepareHandler
        return Cve20234004PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2023_4004_post import Cve20234004PostHandler
        return Cve20234004PostHandler()
