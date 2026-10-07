"""PoC verifier for CVE-2024-49861"""
from .base import BasePoCVerifier

class CVECve202449861PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2024-49861"
    poc_bin = "poc-bin/cve_2024_49861.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2024_49861_prepare import CVECve202449861PrepareHandler
        return CVECve202449861PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2024_49861_post import CVECve202449861PostHandler
        return CVECve202449861PostHandler()
