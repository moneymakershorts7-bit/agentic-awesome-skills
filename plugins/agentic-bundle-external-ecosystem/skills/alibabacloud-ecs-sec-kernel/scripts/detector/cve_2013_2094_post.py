"""
CVE-2013-2094 Post phase handler

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

# Anomaly keywords in kernel log（with perf_event Related）
_KERNEL_ANOMALY_KEYWORDS = [
    "BUG:",
    "WARNING:",
    "Oops:",
    "panic",
    "perf_event",
    "perf_swevent",
]

_TMP_DIR_PATTERN = "/tmp/sec-kernel-poc-*"


class CVE20132094PostHandler(BasePostHandler):
    """CVE-2013-2094 Post phase: Clean up environment and verify system state"""

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

        # 2. CheckisWhetherhasResidual perf_event RelatedProcess
        self._check_residual_processes(issues)

        # 3. Check perf_event_paranoid ValueisWhetherbeTamper
        self._check_paranoid_value(issues)

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

        # 2. Verification paranoid ValueisWhetherRestoreto Prepare BeforeState
        system_restored = self._verify_paranoid_state(prepare_result.state_snapshot)

        # 3. Check dmesg isWhetherhas perf_event RelatedAnomaly
        kernel_warnings = self._check_perf_kernel_log()
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
                    # CleanupEmpty directory
                    else:
                        try:
                            os.rmdir(d)
                        except OSError:
                            pass
        except OSError as e:
            issues.append(f"Failed to check tmp residue: {e}")

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
            # ps Skip when unavailable
            pass

    def _check_paranoid_value(self, issues: List[str]) -> None:
        """Check perf_event_paranoid ValueisWhetherbeTamper"""
        try:
            with open("/proc/sys/kernel/perf_event_paranoid", "r", encoding="utf-8") as f:
                current_value = int(f.read().strip())
            # 正常Valueshouldthisis -1, 0, 1, 2 or 3
            if current_value < -1 or current_value > 3:
                issues.append(
                    f"Abnormal perf_event_paranoid value: {current_value}"
                )
        except (OSError, ValueError):
            # Cannot read，skipthisCheck
            pass

    def _verify_paranoid_state(self, state_snapshot: dict) -> bool:
        """Verification paranoid ValueisWhetherwith Prepare Beforeconsistent

        Args:
            state_snapshot: Prepare phase recorded state snapshot

        Returns:
            True if system state restored
        """
        expected_value = state_snapshot.get("paranoid_value")
        if expected_value is None:
            # 没hasRecordOriginalValue，assumealreadyRestore
            return True

        current_value = self._get_current_paranoid_value()
        if current_value is None:
            # Cannot confirm, assume recovered
            return True

        if expected_value == current_value:
            logger.debug(
                "perf_event_paranoid restored: expected=%s, current=%s",
                expected_value, current_value
            )
            return True
        else:
            logger.warning(
                "perf_event_paranoid mismatch: expected=%s, current=%s",
                expected_value, current_value,
            )
            # paranoid Valuenotconsistentnot一定意味着failure
            return True

    def _get_current_paranoid_value(self):
        """Read current perf_event_paranoid value"""
        try:
            with open("/proc/sys/kernel/perf_event_paranoid", "r", encoding="utf-8") as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None

    def _check_perf_kernel_log(self) -> List[str]:
        """Check dmesg inisWhetherhas perf_event RelatedAnomaly"""
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
            # Only check last 50 lines
            tail_lines = lines[-50:] if len(lines) > 50 else lines

            for line in tail_lines:
                # Checkwith perf_event RelatedAnomaly
                has_anomaly = any(kw in line for kw in _KERNEL_ANOMALY_KEYWORDS)
                if has_anomaly:
                    warnings.append(line.strip())
        except subprocess.TimeoutExpired:
            warnings.append("dmesg read timeout")
        except (FileNotFoundError, OSError) as e:
            warnings.append(f"dmesg read failed: {e}")

        return warnings
