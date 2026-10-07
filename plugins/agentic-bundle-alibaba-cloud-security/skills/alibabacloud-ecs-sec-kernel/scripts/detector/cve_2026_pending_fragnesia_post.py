"""
CVE-2026-PENDING-FRAGNESIA Post phase handler

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
    PostResult,
)

logger = logging.getLogger(__name__)

# Anomaly keywords in kernel log (xfrm/ESP related)
_KERNEL_ANOMALY_KEYWORDS = [
    "BUG:",
    "WARNING:",
    "Oops:",
    "panic",
    "esp",
    "xfrm",
    "fragnesia",
]

_TMP_DIR_PATTERN = "/tmp/sec-kernel-poc-*"

_ESP_MODULES = ["esp4", "esp6"]


class CVE2026PendingFragnesiaPostHandler(BasePostHandler):
    """CVE-2026-PENDING-FRAGNESIA Post phase: verify CTF result, clean up, verify system state"""

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

        # 2. Check for residual xfrm/ESP sockets
        self._check_xfrm_sockets(issues)

        # 3. Check for residual processes
        self._check_residual_processes(issues)

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

        # 1. Verify CTF challenge result
        ctf_success = self._verify_ctf_result(
            prepare_result.state_snapshot
        )
        if not ctf_success:
            warnings.append(
                f"CTF verification failed: mode={self._test_mode}"
            )

        # 2. Execute rollback in reverse order
        rollback_ops = self._get_rollback_operations(prepare_result)
        for op_cmd in rollback_ops:
            try:
                self._execute_rollback(op_cmd)
                logger.debug("Rollback executed: %s", op_cmd)
            except Exception as e:
                warnings.append(f"Failed to rollback '{op_cmd}': {e}")
                logger.warning("Rollback failed for %s: %s", op_cmd, e)

        # 3. Drop page caches
        self._drop_caches()

        # 4. Verify module state
        system_restored = self._verify_module_state(
            prepare_result.state_snapshot
        )

        # 5. Check dmesg for xfrm/ESP related anomalies
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

    def post(self, kernel_info, prepare_result: PrepareResult) -> PostResult:
        """Post phase entry point

        Args:
            kernel_info: Kernel info
            prepare_result: Prepare phase result

        Returns:
            PostResult with verification status
        """
        import time
        start_time = time.time()

        # Self-check
        self_check_result = self.self_check(run_user="nobody")

        # Global verify
        effective_prepare = prepare_result or PrepareResult(
            success=False, operations=[], state_snapshot={}
        )
        global_verify_result = self.global_verify(effective_prepare)

        success = self_check_result.clean and global_verify_result.system_restored
        duration = time.time() - start_time

        return PostResult(
            self_check=self_check_result,
            global_verify=global_verify_result,
            success=success,
            duration=duration
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
                    expected_inner[:16], actual_inner[:16] if actual_inner else ""
                )
                return False

        elif test_mode == "write_root_file":
            if not os.path.exists(target_file):
                logger.warning("CTF target file not found: %s", target_file)
                return False
            try:
                with open(target_file, "rb") as f:
                    raw = f.read()

                # Method 1: Substring search in raw bytes
                # ESP page cache write produces ctf{flag} at offset 0,
                # but may have trailing residue from partial writes.
                expected_inner_bytes = expected_inner.encode("utf-8")
                if expected_inner_bytes in raw:
                    logger.info(
                        "CTF write_root_file PASSED: "
                        "flag_number found via substring search (%s)",
                        expected_inner[:16]
                    )
                    return True

                # Method 2 (backward-compatible): exact ctf{...} match
                # Strip null padding (target file is padded to 4096 bytes)
                content = raw.split(b'\x00', 1)[0].decode("utf-8", errors="replace").strip()
                initial_content = state_snapshot.get("initial_content", "")

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
                        "CTF write_root_file FAILED: expected_inner=%s, got_inner=%s",
                        expected_inner[:16], actual_inner[:16] if actual_inner else ""
                    )
                    return False
            except OSError as e:
                logger.error("Cannot read target file: %s", e)
                return False

        else:
            logger.warning("Unknown CTF test mode: %s", test_mode)
            return False

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
            rollback_cmd,
            shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
            timeout=15
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Rollback command failed (rc={result.returncode}): "
                f"{rollback_cmd}\nstderr: {result.stderr}"
            )

    def _drop_caches(self) -> None:
        """Drop page caches to clean up after exploitation"""
        try:
            subprocess.run(
                ["sh", "-c", "echo 3 > /proc/sys/vm/drop_caches"],
                timeout=5,
                check=False
            )
            logger.debug("Page caches dropped")
        except (subprocess.TimeoutExpired, OSError):
            pass

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

    def _check_xfrm_sockets(self, issues: List[str]) -> None:
        """Check for residual xfrm/netlink sockets"""
        try:
            result = subprocess.run(
                ["ss", "-x", "-a"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "xfrm" in line.lower() or "netlink" in line.lower():
                        # Only flag if sec-kernel related
                        if "sec-kernel" in line:
                            issues.append(f"Residual socket: {line.strip()}")
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
        """Verify module state is consistent with before prepare

        Args:
            state_snapshot: Prepare phase recorded state snapshot

        Returns:
            True if system state restored
        """
        esp_was_loaded = state_snapshot.get("esp_loaded", {})

        try:
            with open("/proc/modules", "r", encoding="utf-8") as f:
                lines = f.readlines()

            current_esp_loaded = {
                mod: any(line.startswith(mod + " ") for line in lines)
                for mod in _ESP_MODULES
            }
        except OSError:
            return True

        esp_match = all(
            esp_was_loaded.get(mod, False) == current_esp_loaded.get(mod, False)
            for mod in _ESP_MODULES
        )

        if not esp_match:
            logger.warning(
                "Module state mismatch: was=%s, now=%s",
                esp_was_loaded, current_esp_loaded
            )

        return esp_match

    def _check_kernel_log(self) -> List[str]:
        """Check dmesg for xfrm/ESP related anomalies"""
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
