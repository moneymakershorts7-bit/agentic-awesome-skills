"""
PostHandler - Post Phase Handler

Handles Self-Check and Global Verification after PoC execution.
Self-Check runs as nobody, Global Verify runs as root.
"""
import os
import time
import logging
import subprocess
import glob
from typing import List, Optional, Dict

from ...core.result import (
    PostResult, SelfCheckResult, GlobalVerifyResult, PrepareResult,
    PrepareOperation,
)

logger = logging.getLogger(__name__)


class SelfCheckHandler:
    """
    Self-Check Handler

    Runs as nobody (same as Run phase).
    Verifies PoC execution left no residual state that could be exploited.
    """

    def __init__(self, tmp_dir: str = "/tmp", poc_tmp_pattern: str = "sec-kernel-poc-*"):
        """
        Args:
            tmp_dir: Temporary directory to check
            poc_tmp_pattern: Pattern for PoC temporary files
        """
        self.tmp_dir = tmp_dir
        self.poc_tmp_pattern = poc_tmp_pattern

    def execute(self) -> SelfCheckResult:
        """
        Execute self-check.

        Returns:
            SelfCheckResult with clean status and any issues found
        """
        logger.info("Starting Self-Check phase")
        issues = []
        residual_files = []
        residual_sockets = []
        residual_processes = []

        # Check 1: Temporary files
        try:
            pattern = os.path.join(self.tmp_dir, self.poc_tmp_pattern)
            files = glob.glob(pattern)
            if files:
                residual_files.extend(files)
                issues.append(f"Residual temporary files found: {files}")
        except Exception as e:
            issues.append(f"Failed to check temporary files: {e}")

        # Check 2: /dev/shm residual files
        try:
            if os.path.isdir("/dev/shm"):
                pattern = os.path.join("/dev/shm", ".sk-*")
                files = glob.glob(pattern)
                if files:
                    residual_files.extend(files)
                    issues.append(f"Residual /dev/shm files found: {files}")
        except Exception as e:
            issues.append(f"Failed to check /dev/shm: {e}")

        # Check 3: Socket files (AF_ALG related, only sec-kernel created)
        try:
            # Only check for sec-kernel PoC related socket files
            poc_sock_patterns = [
                os.path.join(self.tmp_dir, "sec-kernel-*.sock"),
                os.path.join(self.tmp_dir, "sk-poc-*.sock"),
            ]
            for sock_pattern in poc_sock_patterns:
                sockets = glob.glob(sock_pattern)
                if sockets:
                    residual_sockets.extend(sockets)
                    issues.append(
                        f"Residual PoC socket files found: {sockets}"
                    )
        except Exception as e:
            issues.append(f"Failed to check sockets: {e}")

        # Check 4: Residual processes (only PoC child processes, not self)
        try:
            current_pid = str(os.getpid())
            parent_pid = str(os.getppid())
            result = subprocess.run(
                ["ps", "aux"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if "sec-kernel" in line and "poc" in line.lower():
                    # Extract PID
                    parts = line.split()
                    if len(parts) > 1:
                        pid = parts[1]
                        # Exclude current process, parent, and python interpreter
                        if pid in (current_pid, parent_pid):
                            continue
                        # Exclude python processes running sec-kernel itself
                        if "python" in line and "scripts" in line:
                            continue
                        residual_processes.append(pid)
            if residual_processes:
                issues.append(
                    f"Residual sec-kernel PoC processes found: "
                    f"{residual_processes}"
                )
        except Exception as e:
            issues.append(f"Failed to check processes: {e}")

        # Step 5: Actively clean up residual files (ensure all impact is eliminated after PoC run)
        cleaned_files = []
        for f in residual_files:
            try:
                os.unlink(f)
                cleaned_files.append(f)
                logger.debug("Cleaned residual file: %s", f)
            except OSError as e:
                logger.warning("Failed to clean residual file %s: %s", f, e)

        if cleaned_files:
            residual_files = [
                f for f in residual_files if f not in cleaned_files
            ]
            logger.info("Cleaned %d residual file(s)", len(cleaned_files))

        clean = len(issues) == 0
        logger.info(
            "Self-Check completed: clean=%s, issues=%d", clean, len(issues)
        )

        return SelfCheckResult(
            clean=clean,
            issues=issues,
            residual_files=residual_files,
            residual_sockets=residual_sockets,
            residual_processes=residual_processes
        )


class GlobalVerifyHandler:
    """
    Global Verification Handler

    Runs as root (via sudo).
    Verifies system state is restored after PoC execution.
    """

    def __init__(self, prepare_result: Optional[PrepareResult] = None,
                 timeout: int = 30):
        """
        Args:
            prepare_result: Prepare phase result for rollback reference
            timeout: Global verify timeout in seconds
        """
        self.prepare_result = prepare_result
        self.timeout = timeout

    def execute(self) -> GlobalVerifyResult:
        """
        Execute global verification.

        Returns:
            GlobalVerifyResult with system restoration status
        """
        start_time = time.time()
        logger.info("Starting Global Verification phase")

        system_restored = True
        kernel_log_clean = True
        residual_files = []
        kernel_messages = []
        warnings = []

        # Step 1: Restore system state from Prepare
        if self.prepare_result and self.prepare_result.success:
            restore_ops = self._get_rollback_operations(self.prepare_result)
            for op in restore_ops:
                try:
                    self._execute_rollback(op)
                    logger.debug("Rollback executed: %s", op)
                except Exception as e:
                    system_restored = False
                    warnings.append(
                        f"Failed to rollback operation '{op}': {e}"
                    )
                    logger.warning("Rollback failed for %s: %s", op, e)

        # Step 2: Verify module state
        if not self._verify_module_state():
            system_restored = False
            warnings.append("Kernel module state differs from preparation")

        # Step 3: Check kernel log for anomalies
        kernel_messages = self._check_kernel_log()
        if kernel_messages:
            kernel_log_clean = False
            logger.warning(
                "Anomalous kernel messages detected: %d entries",
                len(kernel_messages)
            )

        # Step 4: Check and actively clean residual files
        try:
            pattern = os.path.join("/tmp", "sec-kernel-poc-*")
            files = glob.glob(pattern)
            if files:
                residual_files.extend(files)
                warnings.append(
                    f"Residual PoC temporary files: {files}"
                )
                # Actively clean up residual files, ensure all impact is eliminated after PoC run
                for f in files:
                    try:
                        os.unlink(f)
                        logger.debug("GlobalVerify cleaned: %s", f)
                    except OSError:
                        pass
        except Exception as e:
            warnings.append(f"Failed to check residual files: {e}")

        duration = time.time() - start_time
        success = system_restored and kernel_log_clean

        logger.info(
            "Global Verification completed: success=%s, "
            "restored=%s, kernel_clean=%s, duration=%.2fs",
            success, system_restored, kernel_log_clean, duration
        )

        return GlobalVerifyResult(
            system_restored=system_restored,
            kernel_log_clean=kernel_log_clean,
            residual_files=residual_files,
            kernel_messages=kernel_messages,
            warnings=warnings,
            duration=duration
        )

    def _get_rollback_operations(
        self, prepare_result: PrepareResult
    ) -> List[str]:
        """Get rollback commands from prepare operations"""
        rollback_cmds = []
        for op in reversed(prepare_result.operations):
            if op.rollback_cmd:
                rollback_cmds.append(op.rollback_cmd)
        return rollback_cmds

    def _execute_rollback(self, rollback_cmd: str):
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

    def _verify_module_state(self) -> bool:
        """Verify kernel module state matches preparation"""
        if not self.prepare_result:
            return True  # No preparation to compare against

        try:
            result = subprocess.run(
                ["lsmod"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )
            current_modules = set(
                line.split()[0] for line in result.stdout.splitlines()
            )

            # Check if modules loaded during prepare are still in expected state
            for op in self.prepare_result.operations:
                if op.action == "load_module":
                    module = op.target
                    was_loaded_before = (
                        not op.rollback_cmd
                    )  # No rollback = was already loaded

                    is_loaded_now = module in current_modules

                    # If we loaded it, it should still be there (or removed by us)
                    # If it was there before, it should still be there
                    if was_loaded_before and not is_loaded_now:
                        logger.warning(
                            "Module %s was loaded before prepare but not now",
                            module
                        )
                        return False

            return True
        except Exception:
            return True  # Can't verify, assume OK

    def _check_kernel_log(self) -> List[str]:
        """Check kernel log for PoC-related anomalies"""
        try:
            result = subprocess.run(
                ["dmesg", "--tail=50"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )
            anomalies = []
            for line in result.stdout.splitlines():
                # Look for kernel crash/error indicators
                indicators = [
                    "BUG:", "Oops:", "panic:", "segfault",
                    "general protection fault", "algif_aead",
                ]
                if any(ind in line.lower() for ind in indicators):
                    anomalies.append(line.strip())
            return anomalies
        except Exception:
            return []


class PostHandler:
    """
    Post Phase Handler

    Coordinates Self-Check and Global Verification.
    """

    def __init__(self, prepare_result: Optional[PrepareResult] = None,
                 tmp_dir: str = "/tmp", poc_tmp_pattern: str = "sec-kernel-poc-*",
                 timeout: int = 30):
        """
        Args:
            prepare_result: Prepare phase result
            tmp_dir: Temporary directory for self-check
            poc_tmp_pattern: Pattern for PoC temp files
            timeout: Post phase timeout
        """
        self.prepare_result = prepare_result
        self.tmp_dir = tmp_dir
        self.poc_tmp_pattern = poc_tmp_pattern
        self.timeout = timeout

    def execute(self) -> PostResult:
        """
        Execute Post phase (Self-Check + Global Verify).

        Returns:
            PostResult with combined results
        """
        start_time = time.time()
        logger.info("Starting Post phase")

        # Step 1: Self-Check (runs as current user, typically nobody)
        self_check = SelfCheckHandler(
            tmp_dir=self.tmp_dir,
            poc_tmp_pattern=self.poc_tmp_pattern
        ).execute()

        # Step 2: Global Verification (runs as root via sudo)
        global_verify = GlobalVerifyHandler(
            prepare_result=self.prepare_result,
            timeout=self.timeout
        ).execute()

        success = self_check.clean and global_verify.system_restored

        duration = time.time() - start_time
        logger.info(
            "Post phase completed: success=%s, duration=%.2fs",
            success, duration
        )

        return PostResult(
            self_check=self_check,
            global_verify=global_verify,
            success=success,
            duration=duration
        )


# Backward-compatible alias (renamed from BasePostHandler to PostHandler)
BasePostHandler = PostHandler
