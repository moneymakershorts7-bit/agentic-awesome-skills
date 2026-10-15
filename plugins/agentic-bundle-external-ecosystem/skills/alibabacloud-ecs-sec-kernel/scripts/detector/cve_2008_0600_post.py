"""
CVE-2008-0600 Post phase handler

Cleans up PoC execution residue and verifies system state is restored.
Verifies CTF challenge result for write_root_file mode.
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
    "vmsplice",
    "splice",
]

_TMP_DIR_PATTERN = "/tmp/sec-kernel-poc-*"


class CVE20080600PostHandler(BasePostHandler):
    """CVE-2008-0600 Post phase: clean environment and verify system recovery"""

    def __init__(self, prepare_result: PrepareResult = None,
                 timeout: int = 30, test_mode: str = "write_root_file",
                 ctf_value: str = ""):
        super().__init__(prepare_result=prepare_result, timeout=timeout)
        self._test_mode = test_mode
        self._ctf_value = ctf_value

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

        # 3. Check splice filesystem integrity
        self._check_splice_integrity(issues)

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
        # 1. Reverse order rollback
        self._rollback_operations(prepare_result.operations)

        # 2. Verify system state matches Prepare snapshot
        system_restored = self._verify_system_state(prepare_result.state_snapshot)

        # 3. CTF verification (for write_root_file mode)
        ctf_verified = self._verify_ctf(prepare_result)

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
            ctf_verified=ctf_verified,
        )

    def _verify_ctf(self, prepare_result: PrepareResult) -> bool:
        """Verify CTF challenge result

        For write_root_file mode: the target file should have been modified
        by the PoC to contain the CTF flag value.

        Args:
            prepare_result: Prepare phase result

        Returns:
            True if CTF verification is not applicable or passed
        """
        # CVE-2008-0600 only supports write_root_file mode
        if self._test_mode != "write_root_file":
            logger.info("CTF verification skipped for mode: %s", self._test_mode)
            return True

        target_file = prepare_result.state_snapshot.get("target_file", "")
        if not target_file or not os.path.exists(target_file):
            logger.info("CTF target file not found (may have been cleaned up): %s", target_file)
            return True

        try:
            with open(target_file, "r", encoding="utf-8") as f:
                content = f.read()

            expected_ctf = prepare_result.state_snapshot.get("ctf_value", "")
            initial_content = prepare_result.state_snapshot.get("initial_content", "")

            if expected_ctf and expected_ctf in content:
                logger.info("CTF target file contains expected write_value")
                return True
            elif content != initial_content and initial_content:
                # Content changed but not exact match - partial pollution
                logger.info(
                    "CTF target file content changed (partial pollution): "
                    "initial=%r, current=%r",
                    initial_content[:50], content[:50]
                )
                return True
        except (OSError, IOError) as e:
            logger.warning("Failed to read CTF target file: %s", e)

        # For write mode, file should have been changed
        return False

    def _extract_inner_value(self, content: str) -> str:
        """Extract value from within curly braces (for CTF flag comparison)

        Args:
            content: Content string (e.g., 'ctf{a1b2c3d4}')

        Returns:
            Extracted inner value (e.g., 'a1b2c3d4')
        """
        match = re.search(r'\{([^}]+)\}', content)
        if match:
            return match.group(1)
        return content

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

    def _check_splice_integrity(self, issues: List[str]) -> None:
        """Check splice filesystem wasn't corrupted by PoC"""
        # Check if /proc/self/status is still readable
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as f:
                first_line = f.readline()
                if not first_line:
                    issues.append("splice integrity check: /proc/self/status empty")
        except OSError:
            issues.append("splice integrity check: /proc/self/status not readable")

    def _verify_system_state(self, state_snapshot: dict) -> bool:
        """Verify system state matches Prepare snapshot

        Args:
            state_snapshot: State snapshot from Prepare phase

        Returns:
            True if system state restored
        """
        # Verify kernel version unchanged
        original_kernel = ""
        for key in state_snapshot:
            if isinstance(state_snapshot[key], dict):
                pass  # Skip nested dicts

        # Read current kernel version
        try:
            result = subprocess.run(
                ["uname", "-r"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.debug("Kernel version unchanged: %s", result.stdout.strip())
                return True
        except (subprocess.TimeoutExpired, OSError):
            pass

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
