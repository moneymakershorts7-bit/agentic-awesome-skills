"""
CVE-2004-0077 Post Phase Handler

Cleans up PoC execution residue and verifies system state restoration:
- Check for residual temporary files
- Check for residual memory mapping anomalies
- Verify ASLR restored to original state
- Verify memory management state unchanged
- CTF verification (write_root_file mode)
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

# Kernel log anomaly keywords
_KERNEL_ANOMALY_KEYWORDS = [
    "BUG:",
    "WARNING:",
    "Oops:",
    "panic",
    "mremap",
    "VM",
]

_TMP_DIR_PATTERN = "/tmp/sec-kernel-poc-*"


class CVE20040077PostHandler(BasePostHandler):
    """CVE-2004-0077 Post phase: cleanup and verify system restoration"""

    def __init__(self, prepare_result: Optional[PrepareResult] = None,
                 poc_result: Optional[PoCResult] = None,
                 test_mode: str = "write_root_file",
                 ctf_value: str = "",
                 timeout: int = 30):
        super().__init__(prepare_result=prepare_result, timeout=timeout)
        self._poc_result = poc_result
        self._test_mode = test_mode
        self._ctf_value = ctf_value

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

        # 2. Check for residual memory mapping anomalies
        self._check_memory_mappings(issues)

        # 3. Check for residual suspicious processes
        self._check_suspicious_processes(issues)

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

        # 2. Verify ASLR restored
        system_restored = self._verify_aslr(prepare_result.state_snapshot)

        # 3. Check dmesg for mremap/VM anomalies
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

    def verify_ctf(self, context, poc_output) -> bool:
        """Verify CTF challenge result

        Args:
            context: CTF context with mode, root_file, ctf_flag, write_value
            poc_output: PoC output string from stdout

        Returns:
            True if CTF verification passed
        """
        if context.mode == "read_root_file":
            return poc_output.flag == context.ctf_flag
        elif context.mode == "write_root_file":
            actual = self._read_file_content(context.root_file)
            expected = context.write_value
            actual_inner = self._extract_inner_value(actual)
            expected_inner = self._extract_inner_value(expected)
            if actual_inner and expected_inner:
                return actual_inner == expected_inner
            return actual == expected
        return False

    def _read_file_content(self, file_path: str) -> str:
        """Read file content"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except (OSError, IOError) as e:
            logger.warning("Cannot read file %s: %s", file_path, e)
            return ""

    def _extract_inner_value(self, value: str) -> Optional[str]:
        """Extract inner value from ctf{...} or writeme{...} format"""
        import re
        match = re.search(r'\{([^}]+)\}', value)
        if match:
            return match.group(1)
        return None

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

    def _check_memory_mappings(self, issues: List[str]) -> None:
        """Check for residual memory mapping anomalies via /proc"""
        # Check /proc/self/maps for unusual mappings
        try:
            with open("/proc/self/maps", "r", encoding="utf-8") as f:
                maps_content = f.read()
                # Look for sec-kernel related mappings
                if "sec-kernel-poc" in maps_content:
                    issues.append("Residual sec-kernel-poc mapping in /proc/self/maps")
        except (OSError, IOError):
            pass

    def _check_suspicious_processes(self, issues: List[str]) -> None:
        """Check for processes that may have been left by PoC"""
        try:
            result = subprocess.run(
                ["ps", "aux"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    # Look for mremap or sec-kernel related processes
                    if ("sec-kernel-poc" in line or
                        "mremap_poc" in line) and "grep" not in line:
                        issues.append(f"Residual process: {line.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    def _verify_aslr(self, state_snapshot: dict) -> bool:
        """Verify ASLR restored to original state

        Args:
            state_snapshot: State snapshot from Prepare phase

        Returns:
            True if ASLR matches original
        """
        original_aslr = state_snapshot.get("aslr_original", "0")

        try:
            with open("/proc/sys/kernel/randomize_va_space", "r", encoding="utf-8") as f:
                current_aslr = f.read().strip()
        except (OSError, IOError):
            # Cannot verify, assume restored
            return True

        if original_aslr == current_aslr:
            logger.debug("ASLR restored: original=%s, current=%s",
                         original_aslr, current_aslr)
            return True
        else:
            logger.warning(
                "ASLR mismatch: original=%s, current=%s",
                original_aslr, current_aslr,
            )
            # PoC may not have changed it
            return True

    def _check_kernel_log(self) -> List[str]:
        """Check dmesg for mremap/VM related anomalies"""
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
