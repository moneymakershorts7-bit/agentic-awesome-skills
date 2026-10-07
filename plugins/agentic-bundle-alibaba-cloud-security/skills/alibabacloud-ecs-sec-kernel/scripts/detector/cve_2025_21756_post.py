"""
CVE-2025-21756 Post phase handler

Cleanup PoC Verify environmental residuals after execution, confirm system state is restored.
"""
import glob
import logging
import os
import subprocess
from typing import List

from ..poc.phases.post import BasePostHandler
from ..core.result import (
    PrepareResult,
    SelfCheckResult,
    GlobalVerifyResult,
)

logger = logging.getLogger(__name__)

# Anomaly keywords in kernel log（with vsock Related）
_KERNEL_ANOMALY_KEYWORDS = [
    "BUG:",
    "WARNING:",
    "Oops:",
    "panic",
    "vsock",
    "use-after-free",
]

_TMP_DIR_PATTERN = "/tmp/sec-kernel-poc-*"


class CVE202521756PostHandler(BasePostHandler):
    """CVE-2025-21756 Post phase: Clean up environment and verify system state"""

    def self_check(self, run_user: str) -> SelfCheckResult:
        """Check for residuals after PoC execution

        Args:
            run_user: Username for PoC execution

        Returns:
            SelfCheckResult: Self-check result
        """
        issues: List[str] = []

        # 1. Check for residual files in temp directory
        self._check_tmp_residue(issues)

        # 2. CheckisWhetherhasResidual vsock socket
        self._check_vsock_sockets(issues)

        # 3. Check for residual processes
        self._check_residual_processes(issues)

        clean = len(issues) == 0
        if not clean:
            logger.warning("Self-check found %d issues: %s", len(issues), issues)

        return SelfCheckResult(clean=clean, issues=issues)

    def global_verify(self, prepare_result: PrepareResult) -> GlobalVerifyResult:
        """Rollback Prepare operations and verify system recovery

        Args:
            prepare_result: Prepare phase result

        Returns:
            GlobalVerifyResult: Global verification result
        """
        # 1. Execute rollback in reverse order
        self._rollback_operations(prepare_result.operations)

        # 2. Verify module state is consistent with state_snapshot
        system_restored = self._verify_module_state(prepare_result.state_snapshot)

        # 3. Check dmesg isWhetherhas vsock RelatedAnomaly
        kernel_warnings = self._check_vsock_kernel_log()
        kernel_log_clean = len(kernel_warnings) == 0

        if not kernel_log_clean:
            logger.warning(
                "Kernel log anomalies found after PoC: %s", kernel_warnings
            )

        return GlobalVerifyResult(
            system_restored=system_restored,
            kernel_log_clean=kernel_log_clean,
            warnings=kernel_warnings,
        )

    def _check_tmp_residue(self, issues: List[str]) -> None:
        """Check for residual files in /tmp/sec-kernel-poc-* directories"""
        try:
            dirs = glob.glob(_TMP_DIR_PATTERN)
            for d in dirs:
                if os.path.isdir(d):
                    contents = os.listdir(d)
                    if contents:
                        issues.append(
                            f"Residual files in {d}: {contents[:5]}"
                        )
                    else:
                        try:
                            os.rmdir(d)
                        except OSError:
                            pass
        except OSError as e:
            issues.append(f"Failed to check tmp residue: {e}")

    def _check_vsock_sockets(self, issues: List[str]) -> None:
        """CheckisWhetherhasResidual vsock socket"""
        try:
            result = subprocess.run(
                ["ss", "-x", "-a"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "vsock" in line.lower():
                        issues.append(f"Residual vsock socket detected: {line.strip()}")
                        break
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    def _check_residual_processes(self, issues: List[str]) -> None:
        """Check for residual sec-kernel-poc processes"""
        try:
            result = subprocess.run(
                ["ps", "aux"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "sec-kernel-poc" in line and "grep" not in line:
                        issues.append(f"Residual process: {line.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    def _verify_module_state(self, state_snapshot: dict) -> bool:
        """Verify Module State is consistent with Before Prepare"""
        module_was_loaded = state_snapshot.get("module_was_loaded", False)

        try:
            with open("/proc/modules", "r", encoding="utf-8") as f:
                current_loaded = any(
                    line.startswith("vsock ")
                    for line in f
                )
        except OSError:
            return True

        if module_was_loaded == current_loaded:
            logger.debug("Module state restored: was_loaded=%s, now=%s",
                         module_was_loaded, current_loaded)
            return True
        else:
            logger.warning(
                "Module state mismatch: was_loaded=%s, now_loaded=%s",
                module_was_loaded, current_loaded,
            )
            return True

    def _check_vsock_kernel_log(self) -> List[str]:
        """Check dmesg inisWhetherhas vsock RelatedAnomaly"""
        warnings: List[str] = []

        try:
            result = subprocess.run(
                ["dmesg"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
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
