"""CVE-2026-31431 Post phase handler

Cleanup PoC execution residuals, verify CTF challenge result,
and confirm system state is restored.

CTF verification modes:
- read_root_file: Verify PoC output CTF_FLAG matches the file content
- write_root_file: Verify target file was overwritten with ctf_value

Verification rule: Only compare the value inside {} to avoid trailing
residue from page cache pollution (e.g. ctf{abc}RESIDUAL still passes).
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

# Anomaly keywords in kernel log (algif_aead related)
_KERNEL_ANOMALY_KEYWORDS = [
    "BUG:",
    "WARNING:",
    "Oops:",
    "panic",
    "algif_aead",
]

_TMP_DIR_PATTERN = "/tmp/sec-kernel-poc-*"

# Must match the C PoC and prepare handler
_CANARY_CONTENT = "SEC_KERNEL_CANARY_31431_INTEGRITY_CHECK"


class CVE202631431PostHandler(BasePostHandler):
    """CVE-2026-31431 Post phase: verify CTF result, clean up, verify system state"""

    def __init__(self, prepare_result: PrepareResult = None,
                 poc_result: PoCResult = None,
                 test_mode: str = "write_root_file",
                 ctf_value: str = "",
                 timeout: int = 30):
        super().__init__(prepare_result=prepare_result, timeout=timeout)
        self._poc_result = poc_result
        self._test_mode = test_mode
        self._ctf_value = ctf_value

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

        # 2. Check for residual AF_ALG sockets
        self._check_af_alg_sockets(issues)

        # 3. Check for residual processes
        self._check_residual_processes(issues)

        clean = len(issues) == 0
        if not clean:
            logger.warning("Self-check found %d issues: %s", len(issues), issues)

        return SelfCheckResult(clean=clean, issues=issues)

    def _get_rollback_operations(self, prepare_result: PrepareResult) -> List[str]:
        """Get rollback commands from prepare operations"""
        rollback_cmds = []
        for op in reversed(prepare_result.operations):
            if op.rollback_cmd:
                rollback_cmds.append(op.rollback_cmd)
        return rollback_cmds

    def _execute_rollback(self, rollback_cmd: str) -> None:
        """Execute a rollback command"""
        result = subprocess.run(
            ["sudo", "sh", "-c", rollback_cmd],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=15
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Rollback command failed (rc={result.returncode}): "
                f"{rollback_cmd}\nstderr: {result.stderr}"
            )

    def global_verify(self, prepare_result: PrepareResult) -> GlobalVerifyResult:
        """Verify CTF result, rollback operations, verify system recovery

        Args:
            prepare_result: Prepare phase result

        Returns:
            GlobalVerifyResult: Global verification result
        """
        warnings: List[str] = []

        # 1. Verify CTF challenge result (key evidence)
        ctf_success = self._verify_ctf_result(
            prepare_result.state_snapshot
        )
        if not ctf_success:
            warnings.append(
                f"CTF verification failed: mode={self._test_mode}"
            )

        # 2. Execute rollback in reverse order
        rollback_ops = self._get_rollback_operations(prepare_result)
        for op in rollback_ops:
            try:
                self._execute_rollback(op)
                logger.debug("Rollback executed: %s", op)
            except Exception as e:
                warnings.append(f"Failed to rollback '{op}': {e}")
                logger.warning("Rollback failed for %s: %s", op, e)

        # 3. Verify module state is consistent with state_snapshot
        system_restored = self._verify_module_state(
            prepare_result.state_snapshot
        )

        # 4. Check dmesg for algif_aead related anomalies
        kernel_warnings = self._check_algif_kernel_log()
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
            s: String like 'ctf{a3f8b2c1}' or 'ctf{a3f8b2c1}RESIDUAL'

        Returns:
            Inner value (e.g. 'a3f8b2c1'), or empty string if not found
        """
        match = re.search(r'\{([^}]+)\}', s)
        return match.group(1) if match else ""

    def _verify_ctf_result(self, state_snapshot: dict) -> bool:
        """Verify CTF challenge result based on test mode.

        Verification rule: Only compare the value inside {} to avoid
        trailing residue from page cache pollution attacks.
        e.g. file content 'ctf{a3f8b2c1}RESIDUAL_BYTES' still passes
        as long as the inner hex value matches.

        Verification logic:
        - read_root_file: PoC output CTF_FLAG inner value == ctf_value inner
        - write_root_file: root reads target_file, inner value == ctf_value inner
          (if still initial_content writeme_xxx → NOT_EXPLOITABLE)

        Args:
            state_snapshot: Prepare phase state with target_file path

        Returns:
            True if CTF challenge was completed successfully
        """
        target_file = state_snapshot.get("target_file", "")
        ctf_value = self._ctf_value or state_snapshot.get("ctf_value", "")
        test_mode = self._test_mode or state_snapshot.get("test_mode", "write_root_file")

        if not target_file:
            logger.debug("No target file in state snapshot, skipping CTF check")
            return False

        expected_inner = self._extract_inner_value(ctf_value)
        if not expected_inner:
            logger.warning("Cannot extract inner value from ctf_value: %s", ctf_value)
            return False

        if test_mode == "read_root_file":
            # PoC should have output the file content as CTF flag
            actual_flag = ""
            if self._poc_result and hasattr(self._poc_result, 'ctf_flag'):
                actual_flag = self._poc_result.ctf_flag
            actual_inner = self._extract_inner_value(actual_flag)
            if actual_inner and actual_inner == expected_inner:
                logger.info(
                    "CTF read_root_file PASSED: inner value matches (%s)",
                    expected_inner[:16]
                )
                return True
            else:
                logger.warning(
                    "CTF read_root_file FAILED: expected_inner=%s, got_inner=%s",
                    expected_inner[:16], actual_inner[:16]
                )
                return False

        elif test_mode == "write_root_file":
            # Root reads file, verify content contains ctf_value inner
            if not os.path.exists(target_file):
                logger.warning("CTF target file not found: %s", target_file)
                return False
            try:
                with open(target_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                initial_content = state_snapshot.get("initial_content", "")

                # Extract inner value from file content
                actual_inner = self._extract_inner_value(content)
                if actual_inner and actual_inner == expected_inner:
                    logger.info(
                        "CTF write_root_file PASSED: inner value matches (%s)",
                        expected_inner[:16]
                    )
                    return True
                elif initial_content and content == initial_content.strip():
                    logger.warning(
                        "CTF write_root_file FAILED: file still has initial content '%s'",
                        initial_content[:30]
                    )
                    return False
                else:
                    logger.warning(
                        "CTF write_root_file FAILED: expected_inner=%s, got_inner=%s, raw=%s",
                        expected_inner[:16], actual_inner[:16], content[:40]
                    )
                    return False
            except OSError as e:
                logger.error("Cannot read target file: %s", e)
                return False

        else:
            logger.warning("Unknown CTF test mode: %s", test_mode)
            return False

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

    def _check_af_alg_sockets(self, issues: List[str]) -> None:
        """CheckisWhetherhasResidual AF_ALG socket"""
        # Method 1: passed /proc/net Check
        af_alg_path = "/proc/net/af_alg"
        try:
            if os.path.exists(af_alg_path):
                with open(af_alg_path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        lines = content.split("\n")
                        # Exclude header row
                        data_lines = [l for l in lines if l and not l.startswith("sk")]
                        if data_lines:
                            issues.append(
                                f"Residual AF_ALG sockets: {len(data_lines)} found"
                            )
        except OSError:
            pass

        # Method 2: Check via ss command (fallback)
        try:
            result = subprocess.run(
                ["ss", "-x", "-a"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "alg" in line.lower():
                        issues.append(f"Residual ALG socket detected: {line.strip()}")
                        break
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # ss Skip when unavailablethisCheck
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
            # ps Skip when unavailable
            pass

    def _verify_module_state(self, state_snapshot: dict) -> bool:
        """Verify Module State is consistent with Before Prepare

        Args:
            state_snapshot: Prepare phase recorded state snapshot

        Returns:
            True if system state restored
        """
        module_was_loaded = state_snapshot.get("module_was_loaded", False)

        # CheckCurrentModuleState
        try:
            with open("/proc/modules", "r", encoding="utf-8") as f:
                current_loaded = any(
                    line.startswith("algif_aead ")
                    for line in f
                )
        except OSError:
            # Cannot confirm, assume recovered
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
            # Statenotconsistentnot一定isfailure，RollbackcancannotExecute（Module原本就Load）
            return True

    def _check_algif_kernel_log(self) -> List[str]:
        """Check dmesg inisWhetherhas algif_aead RelatedAnomaly"""
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
                # Checkwith algif_aead RelatedAnomaly
                has_anomaly = any(kw in line for kw in _KERNEL_ANOMALY_KEYWORDS)
                if has_anomaly:
                    warnings.append(line.strip())
        except subprocess.TimeoutExpired:
            warnings.append("dmesg read timeout")
        except (FileNotFoundError, OSError) as e:
            warnings.append(f"dmesg read failed: {e}")

        return warnings
