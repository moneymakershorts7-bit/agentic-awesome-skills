"""PoC verifier for CVE-2025-37752"""
from .base import BasePoCVerifier

class CVECve202537752PoCVerifier(BasePoCVerifier):
    cve_id = "CVE-2025-37752"
    poc_bin = "poc-bin/cve_2025_37752.bin"

    def get_prepare_handler(self):
        from ..poc.handlers.cve_2025_37752_prepare import CVECve202537752PrepareHandler
        return CVECve202537752PrepareHandler()

    def get_post_handler(self):
        from ..poc.handlers.cve_2025_37752_post import CVECve202537752PostHandler
        return CVECve202537752PostHandler()
