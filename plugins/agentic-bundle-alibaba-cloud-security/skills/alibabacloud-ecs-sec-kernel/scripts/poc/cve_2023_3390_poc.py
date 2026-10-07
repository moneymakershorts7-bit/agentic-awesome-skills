"""PoC verifier for CVE-2023-3390"""
from .base import BasePoCVerifier

class Cve20233390PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2023-3390"
    poc_bin = "poc-bin/cve_2023_3390.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2023_3390_prepare import Cve20233390PrepareHandler
        return Cve20233390PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2023_3390_post import Cve20233390PostHandler
        return Cve20233390PostHandler()
