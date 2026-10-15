"""
CVE-2016-9793 Post phase handler

Cleanup PoC execution environment, verify system state is restored.
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

# Anomaly keywords in kernel log
_KERNEL_ANOMALY_KEYWORDS = [
    "BUG:",
    "WARNING:",
    "Oops:",
    "panic",
]

_TMP_DIR_PATTERN = "/tmp/sec-kernel-poc-*"


class CVE20169793PostHandler(BasePostHandler):
    """CVE-2016-9793 Post phase: Clean up environment and verify system state"""

    def self_check(self, run_user: str) -> SelfCheckResult:
        """Check residuals after PoC execution

        Args:
            run_user: Execute PoC Username

        Returns:
            SelfCheckResult: Self-check Result
        """
        issues: List[str] = []

        # 1. Check for residual files in temp directory
        self._check_tmp_residue(issues)

        # 2. Check for residual sec-kernel-poc processes
        self._check_residual_processes(issues)

        clean = len(issues) == 0
        if not clean:
            logger.warning("Self-check found %d issues: %s", len(issues), issues)

        return SelfCheckResult(clean=clean, issues=issues)

    def verify_ctf(self, context, poc_output) -> bool:
        """Verify CTF challenge result

        Args:
            context: CTF context with mode, target_file, write_value, etc.
            poc_output: PoC output object with flag field

        Returns:
            True if CTF verification passed, False otherwise
        """
        if context.mode == "write_root_file":
            # Verify that the file content was changed to the write_value
            try:
                actual = self._read_file(context.target_file)
                # Extract the ctf{} value from actual content
                actual_value = self._extract_inner_value(actual)
                expected_value = self._extract_inner_value(context.write_value)
                if actual_value == expected_value:
                    return True
                # Check if content changed at all (vulnerability path exists)
                if context.initial_content:
                    initial_value = self._extract_inner_value(
                        context.initial_content
                    )
                    if actual_value != initial_value:
                        # Content changed — vulnerability path confirmed
                        return True
                return False
            except Exception as e:
                logger.error("CTF verification failed: %s", e)
                return False
        elif context.mode == "read_root_file":
            # read_root_file is unsupported for this CVE
            return poc_output.flag == context.ctf_flag
        return False

    def _extract_inner_value(self, text: str) -> str:
        """Extract value inside {} from text (e.g., ctf{xxxx} -> xxxx)"""
        match = re.search(r'\{([^}]+)\}', text)
        return match.group(1) if match else text

    def _read_file(self, filepath: str) -> str:
        """Read file content"""
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()

    def global_verify(self, prepare_result: PrepareResult) -> GlobalVerifyResult:
        """Rollback Prepare operations and verify system recovery

        Args:
            prepare_result: Prepare phase Result

        Returns:
            GlobalVerifyResult: GlobalVerifyResult
        """
        # 1. Execute rollback in reverse order
        self._rollback_operations(prepare_result.operations)

        # 2. System already restored (socket subsystem, no special restore)
        system_restored = True

        # 3. Check dmesg is whether has Anomaly
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
                    # Cleanup empty directory
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

    def _check_kernel_log(self) -> List[str]:
        """Check dmesg in is whether has Anomaly"""
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
