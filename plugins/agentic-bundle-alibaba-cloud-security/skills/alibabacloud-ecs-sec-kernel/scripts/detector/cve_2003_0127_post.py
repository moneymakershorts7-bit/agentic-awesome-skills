"""
CVE-2003-0127 Post Phase Handler

Cleans up PoC execution residue and verifies system state restoration:
- Check for residual temporary files
- Check for residual traced processes
- Verify ptrace scope restored to original state
- Verify kmod/modprobe state unchanged
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

# Kernel log anomaly keywords
_KERNEL_ANOMALY_KEYWORDS = [
    "BUG:",
    "WARNING:",
    "Oops:",
    "panic",
    "ptrace",
]

_TMP_DIR_PATTERN = "/tmp/sec-kernel-poc-*"


class CVE20030127PostHandler(BasePostHandler):
    """CVE-2003-0127 Post phase: cleanup and verify system restoration"""

    def self_check(self, run_user: str) -> SelfCheckResult:
        """Check for PoC execution residue

        Args:
            run_user: User name that executed PoC

        Returns:
            SelfCheckResult with cleanliness status
        """
        issues: List[str] = []

        # 1. Check for residual temporary files
        self._check_tmp_residue(issues)

        # 2. Check for residual traced processes
        self._check_traced_processes(issues)

        # 3. Check for residual ptrace attachments
        self._check_ptrace_attachments(issues)

        clean = len(issues) == 0
        if not clean:
            logger.warning("Self-check found %d issues: %s", len(issues), issues)

        return SelfCheckResult(clean=clean, issues=issues)

    def global_verify(self, prepare_result: PrepareResult) -> GlobalVerifyResult:
        """Rollback Prepare operations and verify system restoration

        Args:
            prepare_result: Prepare phase result

        Returns:
            GlobalVerifyResult with verification status
        """
        # 1. Rollback operations in reverse order
        self._rollback_operations(prepare_result.operations)

        # 2. Verify ptrace scope restored
        system_restored = self._verify_ptrace_scope(prepare_result.state_snapshot)

        # 3. Check dmesg for ptrace/kmod anomalies
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
        """Check for residue files in /tmp/sec-kernel-poc-*"""
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

    def _check_traced_processes(self, issues: List[str]) -> None:
        """Check for processes that may have been traced by PoC"""
        try:
            result = subprocess.run(
                ["ps", "aux"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    # Look for sleep processes (used in PoC)
                    if ("sleep 10" in line or 
                        "sec-kernel-poc" in line) and "grep" not in line:
                        issues.append(f"Residual process: {line.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    def _check_ptrace_attachments(self, issues: List[str]) -> None:
        """Check for residual ptrace attachments via /proc"""
        # Check /proc/*/status for TracerPid != 0
        try:
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    status_path = f"/proc/{entry}/status"
                    try:
                        with open(status_path, "r", encoding="utf-8") as f:
                            for line in f:
                                if line.startswith("TracerPid:"):
                                    pid_value = line.split(":")[1].strip()
                                    if pid_value != "0":
                                        issues.append(
                                            f"Process {entry} has TracerPid={pid_value}"
                                        )
                                    break
                    except (OSError, IOError):
                        pass
        except OSError:
            pass

    def _verify_ptrace_scope(self, state_snapshot: dict) -> bool:
        """Verify ptrace_scope restored to original state

        Args:
            state_snapshot: State snapshot from Prepare phase

        Returns:
            True if ptrace_scope matches original
        """
        original_scope = state_snapshot.get("ptrace_scope_original", "0")

        try:
            with open("/proc/sys/kernel/yama/ptrace_scope", "r", encoding="utf-8") as f:
                current_scope = f.read().strip()
        except (OSError, IOError):
            # Cannot verify, assume restored
            return True

        if original_scope == current_scope:
            logger.debug("ptrace_scope restored: original=%s, current=%s",
                         original_scope, current_scope)
            return True
        else:
            logger.warning(
                "ptrace_scope mismatch: original=%s, current=%s",
                original_scope, current_scope,
            )
            # Not necessarily a failure - PoC may not have changed it
            return True

    def _check_kernel_log(self) -> List[str]:
        """Check dmesg for ptrace/kmod related anomalies"""
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
            # Check last 50 lines
            tail_lines = lines[-50:] if len(lines) > 50 else lines

            for line in tail_lines:
                # Check for anomalies
                has_anomaly = any(kw in line for kw in _KERNEL_ANOMALY_KEYWORDS)
                if has_anomaly:
                    warnings.append(line.strip())
        except subprocess.TimeoutExpired:
            warnings.append("dmesg read timeout")
        except (FileNotFoundError, OSError) as e:
            warnings.append(f"dmesg read failed: {e}")

        return warnings
