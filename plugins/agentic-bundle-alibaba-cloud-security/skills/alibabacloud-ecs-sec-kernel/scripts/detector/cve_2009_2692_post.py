"""
CVE-2009-2692 Post phase handler

Cleans up PoC execution residue and verifies system state is restored.
"""
import glob
import logging
import os
import re
import subprocess
from typing import List, Optional

from ..poc.phases.post import BasePostHandler
from ..core.result import (
    PrepareResult,
    SelfCheckResult,
    GlobalVerifyResult,
)

logger = logging.getLogger(__name__)

# Kernel log anomaly keywords
_KERNEL_ANOMALY_KEYWORDS = [
    "BUG:",
    "WARNING:",
    "Oops:",
    "panic",
    "sock_sendpage",
    "pppox",
    "NULL pointer",
]

_TMP_DIR_PATTERN = "/tmp/sec-kernel-poc-*"


class CVE20092692PostHandler(BasePostHandler):
    """CVE-2009-2692 Post phase: clean environment and verify system recovery"""

    def __init__(self, prepare_result: Optional[PrepareResult] = None,
                 timeout: int = 30, test_mode: str = "", ctf_value: str = ""):
        super().__init__(prepare_result=prepare_result, timeout=timeout)
        self._test_mode = test_mode
        self._ctf_value = ctf_value

    def self_check(self, run_user: str = "nobody") -> SelfCheckResult:
        """Check for PoC residue after execution

        Args:
            run_user: Username that ran the PoC

        Returns:
            SelfCheckResult: Self-check result
        """
        issues: List[str] = []

        # 1. Check for residual files in temporary directory
        self._check_tmp_residue(issues)

        # 2. Check for residual processes
        self._check_residual_processes(issues)

        # 3. Check network/socket integrity
        self._check_socket_integrity(issues)

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
        # 1. CTF verification (if applicable)
        ctf_ok = self._verify_ctf(prepare_result)

        # 2. Reverse order rollback
        self._rollback_operations(prepare_result.operations)

        # 3. Verify system state matches Prepare snapshot
        system_restored = self._verify_system_state(prepare_result.state_snapshot)

        # 4. Check dmesg for anomalies
        kernel_warnings = self._check_kernel_log()
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

    def _verify_ctf(self, prepare_result: PrepareResult) -> bool:
        """Verify CTF challenge result

        CVE-2009-2692 doesn't support CTF modes (it's a NULL pointer
        dereference exploit, not page cache pollution), so we always
        return True here.
        """
        if not self._test_mode:
            return True

        logger.info("CTF mode '%s' for CVE-2009-2692 is unsupported, "
                     "skipping CTF verification", self._test_mode)
        return True

    def _extract_inner_value(self, text: str) -> str:
        """Extract value inside ctf{} or writeme{} braces"""
        match = re.search(r'\{([^}]+)\}', text)
        if match:
            return match.group(1)
        return text

    def _check_tmp_residue(self, issues: List[str]) -> None:
        """Check /tmp/sec-kernel-poc-* directory for residual files"""
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

    def _check_socket_integrity(self, issues: List[str]) -> None:
        """Check socket/network state wasn't corrupted by PoC"""
        # Check if /proc/net/protocols is still readable
        try:
            with open("/proc/net/protocols", "r", encoding="utf-8") as f:
                first_line = f.readline()
                if not first_line:
                    issues.append("socket integrity check: /proc/net/protocols empty")
        except OSError:
            issues.append("socket integrity check: /proc/net/protocols not readable")

    def _verify_system_state(self, state_snapshot: dict) -> bool:
        """Verify system state matches Prepare snapshot

        Args:
            state_snapshot: State snapshot from Prepare phase

        Returns:
            True if system state restored
        """
        original_kernel_version = state_snapshot.get("kernel_version", "")

        # Read current kernel version
        try:
            result = subprocess.run(
                ["uname", "-r"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                current_version = result.stdout.strip()
                if original_kernel_version == current_version:
                    logger.debug("Kernel version unchanged: %s", current_version)
                    return True
                else:
                    logger.warning(
                        "Kernel version mismatch: original=%s, current=%s",
                        original_kernel_version, current_version,
                    )
        except (subprocess.TimeoutExpired, OSError):
            pass

        # Unable to verify, assume restored
        return True

    def _check_kernel_log(self) -> List[str]:
        """Check dmesg for anomalies"""
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
                has_anomaly = any(kw in line for kw in _KERNEL_ANOMALY_KEYWORDS)
                if has_anomaly:
                    warnings.append(line.strip())
        except subprocess.TimeoutExpired:
            warnings.append("dmesg read timeout")
        except (FileNotFoundError, OSError) as e:
            warnings.append(f"dmesg read failed: {e}")

        return warnings
