"""PoC verifier for CVE-2023-4147"""
from .base import BasePoCVerifier

class Cve20234147PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2023-4147"
    poc_bin = "poc-bin/cve_2023_4147.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2023_4147_prepare import Cve20234147PrepareHandler
        return Cve20234147PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2023_4147_post import Cve20234147PostHandler
        return Cve20234147PostHandler()
