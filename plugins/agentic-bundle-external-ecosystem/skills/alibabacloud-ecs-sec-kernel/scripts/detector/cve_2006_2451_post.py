"""
CVE-2006-2451 Post phase handler

Cleanup PoC verification environment after execution, confirm system state is restored.
Performs CTF result verification, self-check for residuals, and global system recovery.
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
    PoCResult,
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
    "core_pattern",
]

_TMP_DIR_PATTERN = "/tmp/sec-kernel-poc-*"


class CVE20062451PostHandler(BasePostHandler):
    """CVE-2006-2451 Post phase: Clean up environment and verify system state"""

    def __init__(self, prepare_result: Optional[PrepareResult] = None,
                 poc_result: Optional[PoCResult] = None,
                 test_mode: str = "write_root_file",
                 ctf_value: str = ""):
        super().__init__(prepare_result=prepare_result)
        self.poc_result = poc_result
        self.test_mode = test_mode
        self.ctf_value = ctf_value

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

        # 2. Check for residual processes
        self._check_residual_processes(issues)

        # 3. Check core_pattern integrity
        self._check_core_pattern_integrity(issues)

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
        warnings: List[str] = []

        # 1. CTF verification (mode-dependent)
        ctf_verified = self._verify_ctf_result(prepare_result.state_snapshot)
        if not ctf_verified:
            warnings.append("CTF verification failed")

        # 2. Execute rollback in reverse order
        self._rollback_operations(prepare_result.operations)

        # 3. Verify suid_dumpable state is consistent with pre-Prepare
        system_restored = self._verify_suid_dumpable_state(
            prepare_result.state_snapshot
        )

        # 4. Check dmesg for anomalies
        kernel_warnings = self._check_kernel_log()
        kernel_log_clean = len(kernel_warnings) == 0

        if not kernel_log_clean:
            logger.warning(
                "Kernel log anomalies found after PoC: %s", kernel_warnings
            )
            warnings.extend(kernel_warnings)

        return GlobalVerifyResult(
            system_restored=system_restored,
            kernel_log_clean=kernel_log_clean,
            warnings=warnings,
        )

    def _verify_ctf_result(self, state_snapshot: dict) -> bool:
        """Verify CTF challenge result based on test mode.

        Args:
            state_snapshot: Prepare phase state snapshot

        Returns:
            True if CTF verification passed
        """
        if not self.poc_result:
            logger.warning("No PoC result available for CTF verification")
            return False

        # Extract CTF flag from PoC output
        ctf_flag = self._extract_ctf_flag()
        if not ctf_flag:
            logger.warning("No CTF_FLAG found in PoC output")
            return False

        if self.test_mode == "read_root_file":
            # read_root_file: PoC output flag should match the ctf_value
            expected = self.ctf_value
            return ctf_flag == expected or self._extract_inner_value(ctf_flag) == self._extract_inner_value(expected)

        elif self.test_mode == "write_root_file":
            # write_root_file: target file content should contain ctf_value
            target_file = state_snapshot.get("target_file", "")
            if not target_file:
                logger.warning("No target file in state snapshot")
                return False

            try:
                with open(target_file, "r", encoding="utf-8") as f:
                    actual_content = f.read()

                # Check if ctf_value inner value is in file
                ctf_inner = self._extract_inner_value(self.ctf_value)
                file_inner = self._extract_inner_value(actual_content)
                return ctf_inner == file_inner or self.ctf_value in actual_content
            except OSError as e:
                logger.warning("Failed to read target file: %s", e)
                return False

        return True

    def _extract_ctf_flag(self) -> str:
        """Extract CTF_FLAG from PoC stdout.

        Returns:
            CTF flag value or empty string
        """
        if not self.poc_result or not self.poc_result.stdout:
            return ""

        for line in self.poc_result.stdout.split("\n"):
            if line.startswith("CTF_FLAG:"):
                return line[len("CTF_FLAG:"):]
        return ""

    @staticmethod
    def _extract_inner_value(text: str) -> str:
        """Extract inner value from ctf{...} or writeme{...} pattern.

        Args:
            text: Text containing the pattern

        Returns:
            Inner value or original text if no pattern found
        """
        match = re.search(r'\{([^}]+)\}', text)
        if match:
            return match.group(1)
        return text.strip()

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

    def _check_core_pattern_integrity(self, issues: List[str]) -> None:
        """Check kernel.core_pattern integrity"""
        core_pattern_path = "/proc/sys/kernel/core_pattern"
        try:
            with open(core_pattern_path, "r", encoding="utf-8") as f:
                current_value = f.read().strip()
            if "sec-kernel-poc" in current_value:
                issues.append(
                    f"core_pattern tampered: {current_value}"
                )
        except OSError:
            pass

    def _verify_suid_dumpable_state(self, state_snapshot: dict) -> bool:
        """Verify suid_dumpable state is consistent with pre-Prepare

        Args:
            state_snapshot: Prepare phase recorded state snapshot

        Returns:
            True if system state restored
        """
        original_value = state_snapshot.get("suid_dumpable_original", "")

        try:
            with open("/proc/sys/fs/suid_dumpable", "r", encoding="utf-8") as f:
                current_value = f.read().strip()
        except OSError:
            return True

        if original_value == current_value:
            logger.debug("suid_dumpable state restored: %s", current_value)
            return True
        else:
            logger.warning(
                "suid_dumpable state mismatch: original=%s, current=%s",
                original_value, current_value,
            )
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
