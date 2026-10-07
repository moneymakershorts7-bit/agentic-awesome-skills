"""PoC verifier for CVE-2023-0461"""
from .base import BasePoCVerifier

class Cve20230461PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2023-0461"
    poc_bin = "poc-bin/cve_2023_0461.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2023_0461_prepare import Cve20230461PrepareHandler
        return Cve20230461PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2023_0461_post import Cve20230461PostHandler
        return Cve20230461PostHandler()
