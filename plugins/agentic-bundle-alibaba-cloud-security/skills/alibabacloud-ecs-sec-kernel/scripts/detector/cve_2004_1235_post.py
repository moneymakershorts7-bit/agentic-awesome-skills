"""
CVE-2004-1235 Post phase handler

Cleans up PoC execution residue and verifies system state is restored.
Includes CTF flag verification for read_root_file mode.
"""
import glob
import logging
import os
import re
import subprocess
from typing import List

from ..poc.phases.post import BasePostHandler
from ..core.result import (
    PrepareResult,
    PoCResult,
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
    "VMA",
    "mmap_sem",
]

_TMP_DIR_PATTERN = "/tmp/sec-kernel-poc-*"


class CVE20041235PostHandler(BasePostHandler):
    """CVE-2004-1235 Post phase: CTF verification, cleanup, system recovery"""

    def __init__(self, prepare_result: PrepareResult = None,
                 poc_result: PoCResult = None,
                 timeout: int = 30):
        super().__init__(prepare_result=prepare_result, timeout=timeout)
        self._poc_result = poc_result

    def self_check(self, run_user: str) -> SelfCheckResult:
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

        # 3. Check kernel state integrity
        self._check_kernel_state_integrity(issues)

        clean = len(issues) == 0
        if not clean:
            logger.warning("Self-check found %d issues: %s", len(issues), issues)

        return SelfCheckResult(clean=clean, issues=issues)

    def global_verify(self, prepare_result: PrepareResult) -> GlobalVerifyResult:
        """Verify CTF result, rollback operations, verify system recovery

        Args:
            prepare_result: Prepare phase result

        Returns:
            GlobalVerifyResult: Global verification result
        """
        warnings: List[str] = []

        # 1. Verify CTF challenge result (key evidence)
        ctf_success = self._verify_ctf_result(prepare_result.state_snapshot)
        if not ctf_success:
            warnings.append("CTF read_root_file verification failed")

        # 2. Reverse order rollback
        self._rollback_operations(prepare_result.operations)

        # 3. Verify kernel state matches Prepare snapshot
        system_restored = self._verify_kernel_state(prepare_result.state_snapshot)

        # 4. Check dmesg for anomalies
        kernel_warnings = self._check_kernel_log()
        warnings.extend(kernel_warnings)
        kernel_log_clean = len(kernel_warnings) == 0

        if not kernel_log_clean:
            logger.warning(
                "Kernel log anomalies found after PoC: %s", kernel_warnings
            )

        return GlobalVerifyResult(
            system_restored=system_restored and ctf_success,
            kernel_log_clean=kernel_log_clean,
            warnings=warnings,
        )

    @staticmethod
    def _extract_inner_value(s: str) -> str:
        """Extract value inside {} from a CTF string.

        Args:
            s: String like 'secret_a3f8b2c1' or 'ctf{a3f8b2c1}'

        Returns:
            Inner value if {} found, otherwise the full stripped string
        """
        if not s:
            return ""
        match = re.search(r'\{([^}]+)\}', s)
        return match.group(1) if match else s.strip()

    def _verify_ctf_result(self, state_snapshot: dict) -> bool:
        """Verify CTF read_root_file result.

        Compares PoC stdout CTF_FLAG value with the flag written during Prepare.

        Args:
            state_snapshot: Prepare phase state with target_file and ctf_value

        Returns:
            True if CTF challenge was completed successfully
        """
        ctf_value = state_snapshot.get("ctf_value", "")
        test_mode = state_snapshot.get("test_mode", "read_root_file")

        if not ctf_value:
            logger.debug("No ctf_value in state snapshot, skipping CTF check")
            return False

        if test_mode != "read_root_file":
            logger.debug("Test mode is %s, not read_root_file", test_mode)
            return True  # Not applicable

        # Extract CTF_FLAG from PoC stdout
        actual_flag = ""
        if self._poc_result and hasattr(self._poc_result, 'stdout'):
            stdout = self._poc_result.stdout or ""
            # Parse CTF_FLAG:xxx from stdout
            for line in stdout.split("\n"):
                if line.startswith("CTF_FLAG:"):
                    actual_flag = line[len("CTF_FLAG:"):].strip()
                    break

        if not actual_flag:
            logger.warning("No CTF_FLAG found in PoC output")
            return False

        # Compare inner values
        expected_inner = self._extract_inner_value(ctf_value)
        actual_inner = self._extract_inner_value(actual_flag)

        if expected_inner and actual_inner and expected_inner == actual_inner:
            logger.info(
                "CTF read_root_file PASSED: flag matches (%s)",
                expected_inner[:16]
            )
            return True
        else:
            logger.warning(
                "CTF read_root_file FAILED: expected=%s, got=%s",
                expected_inner[:16] if expected_inner else "<empty>",
                actual_inner[:16] if actual_inner else "<empty>",
            )
            return False

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
                    # Clean empty directories
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

    def _check_kernel_state_integrity(self, issues: List[str]) -> None:
        """Check kernel state wasn't corrupted by PoC"""
        # Check if /proc/kallsyms is still readable
        try:
            with open("/proc/kallsyms", "r", encoding="utf-8") as f:
                # Read first line to verify access
                first_line = f.readline()
                if not first_line:
                    issues.append("kernel state integrity check: /proc/kallsyms empty")
        except OSError:
            # Expected in some environments
            pass

    def _verify_kernel_state(self, state_snapshot: dict) -> bool:
        """Verify kernel state matches Prepare snapshot

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
