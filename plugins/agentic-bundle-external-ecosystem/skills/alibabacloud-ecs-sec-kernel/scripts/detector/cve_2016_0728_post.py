"""
CVE-2016-0728 Post phase handler

Cleanup PoC execution residues, verify system state recovery.
"""
import glob
import logging
import os
import subprocess
from typing import List

from ..poc.phases.post import BasePostHandler
from ..core.result import (
    PrepareResult, SelfCheckResult, GlobalVerifyResult,
)

logger = logging.getLogger(__name__)

_KERNEL_ANOMALY_KEYWORDS = ["BUG:", "WARNING:", "Oops:", "panic"]
_TMP_DIR_PATTERN = "/tmp/sec-kernel-poc-*"


class CVE20160728PostHandler(BasePostHandler):
    """CVE-2016-0728 Post handler"""

    def self_check(self, run_user: str) -> SelfCheckResult:
        issues: List[str] = []
        self._check_tmp_residue(issues)
        self._check_residual_processes(issues)

        clean = len(issues) == 0
        if not clean:
            logger.warning("Self-check found %d issues: %s", len(issues), issues)

        return SelfCheckResult(clean=clean, issues=issues)

    def global_verify(self, prepare_result: PrepareResult) -> GlobalVerifyResult:
        self._rollback_operations(prepare_result.operations)
        system_restored = True

        kernel_warnings = self._check_kernel_log()
        kernel_log_clean = len(kernel_warnings) == 0

        if not kernel_log_clean:
            logger.warning("Kernel log anomalies found after PoC: %s", kernel_warnings)

        return GlobalVerifyResult(
            system_restored=system_restored,
            kernel_log_clean=kernel_log_clean,
            warnings=kernel_warnings,
        )

    def _check_tmp_residue(self, issues: List[str]) -> None:
        try:
            dirs = glob.glob(_TMP_DIR_PATTERN)
            for d in dirs:
                if os.path.isdir(d):
                    contents = os.listdir(d)
                    if contents:
                        issues.append(f"Residual files in {d}: {contents[:5]}")
                    else:
                        try:
                            os.rmdir(d)
                        except OSError:
                            pass
        except OSError as e:
            issues.append(f"Failed to check tmp residue: {e}")

    def _check_residual_processes(self, issues: List[str]) -> None:
        try:
            result = subprocess.run(["ps", "aux"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "sec-kernel-poc" in line and "grep" not in line:
                        issues.append(f"Residual process: {line.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    def _check_kernel_log(self) -> List[str]:
        warnings: List[str] = []
        try:
            result = subprocess.run(["dmesg"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
            if result.returncode != 0:
                return warnings

            lines = result.stdout.strip().split("\n")
            tail_lines = lines[-50:] if len(lines) > 50 else lines

            for line in tail_lines:
                has_anomaly = any(kw in line for kw in _KERNEL_ANOMALY_KEYWORDS)
                if has_anomaly:
                    warnings.append(line.strip())
        except subprocess.TimeoutExpired:
            warnings.append("dmesg read timeout")
        except (FileNotFoundError, OSError) as e:
            warnings.append(f"dmesg read failed: {e}")

        return warnings
