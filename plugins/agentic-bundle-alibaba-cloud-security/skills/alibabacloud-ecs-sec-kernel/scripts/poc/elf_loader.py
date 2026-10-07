"""
ELF loader and executor for CTF mode

Safely load masked ELF, execute with CLI arguments, and retry on failure.

Flow:
1. Read poc-bin/xxx.bin (masked ELF, magic="CVE\\x00")
2. Restore ELF magic in memory ("CVE\\x00" -> "\\x7fELF")
3. Write to workspace/.poc_tmp/xxx.elf
4. Set permissions 0755
5. Execute with CLI args (retry on failure)
6. Delete after execution
"""
import os
import sys
import stat
import time
import subprocess
import logging
import tempfile
from pathlib import Path
from typing import Optional, Tuple, List, Dict

logger = logging.getLogger(__name__)


class FilelessELFLoader:
    """
    ELF loader and executor with CTF retry support

    Safety features:
    - Restore ELF magic before execution
    - Execute from workspace/.poc_tmp/ directory
    - Proper cleanup after execution
    - Timeout control
    - Retry mechanism for transient failures
    - CLI argument passing for CTF mode
    """

    ELF_MAGIC = b'\x7fELF'
    MASK_MAGIC = b'CVE\x00'

    def __init__(self, bin_path: str, workspace_dir: str = "./workspace"):
        """
        Args:
            bin_path: masked ELF binary file path
            workspace_dir: workspace directory for temporary files
        """
        self.bin_path = bin_path
        self.workspace_dir = workspace_dir
        self._tmp_file = None

    def load_and_execute(self, cli_args: list = None, env: dict = None,
                         timeout: int = 10, retry_count: int = 3) -> Tuple[str, str, int]:
        """
        Load masked ELF, restore magic, write to temp file, execute, delete.
        Supports retry: if returncode != 0 and not timeout, retry up to retry_count times.

        Args:
            cli_args: CLI arguments passed to PoC binary
                      e.g. ["--mode", "write_root_file", "--root-file", "/tmp/xxx"]
            env: Environment variables (kept for backward compatibility)
            timeout: Execution timeout (seconds)
            retry_count: Number of retries on failure (default 3)

        Returns:
            (stdout, stderr, returncode)

        Raises:
            ValueError: masked ELF format error
            OSError: Execution failed
        """
        try:
            # 1. Read masked binary
            logger.debug("Loading masked ELF: %s", self.bin_path)
            with open(self.bin_path, 'rb') as f:
                data = bytearray(f.read())

            if len(data) < 16:
                raise ValueError(
                    f"File too small to be valid ELF: {len(data)} bytes"
                )

            # 2. Verify and restore ELF magic
            if data[:4] != self.MASK_MAGIC:
                raise ValueError(
                    f"Invalid masked ELF: expected magic {self.MASK_MAGIC!r}, "
                    f"got {bytes(data[:4])!r}"
                )
            data[:4] = self.ELF_MAGIC
            logger.debug("ELF magic restored")

            # 3. Verify basic ELF format
            if data[4] not in (1, 2):  # EI_CLASS: 32-bit or 64-bit
                raise ValueError(f"Invalid ELF class: {data[4]}")

            # 4. Write to workspace/.poc_tmp/
            tmp_file = self._write_to_workspace(data)

            # 5. Execute with retry
            stdout, stderr, rc = self._execute_with_retry(
                tmp_file, cli_args, env, timeout, retry_count, user=None
            )
            return stdout, stderr, rc

        except FileNotFoundError:
            error_msg = f"Masked ELF not found: {self.bin_path}"
            logger.error(error_msg)
            return "", error_msg, -1

        except ValueError as e:
            error_msg = f"Invalid ELF format: {e}"
            logger.error(error_msg)
            return "", error_msg, -1

        finally:
            # Cleanup temporary file
            self._cleanup_tmp_file()

    def execute_as_user(self, user: str, cli_args: list = None,
                        env: dict = None, timeout: int = 10,
                        retry_count: int = 3) -> Tuple[str, str, int]:
        """Execute PoC with specified user privileges (dropped privileges)

        Privilege drop strategy:
        - root user: use runuser -u <user> to drop privileges
        - non-root user: current user is already unprivileged, execute directly

        Args:
            user: Target username (e.g. "nobody"), only effective when root
            cli_args: CLI arguments passed to PoC binary
            env: Environment variables (kept for backward compatibility)
            timeout: Execution timeout (seconds)
            retry_count: Number of retries on failure (default 3)

        Returns:
            (stdout, stderr, returncode)
        """
        # Non-root user: execute directly
        if os.getuid() != 0:
            logger.debug("Non-root user (uid=%d), executing directly without demotion",
                         os.getuid())
            return self.load_and_execute(cli_args=cli_args, env=env,
                                         timeout=timeout, retry_count=retry_count)

        # Root user: use runuser to drop privileges
        import shlex
        import shutil

        try:
            # 1. Read masked binary
            logger.debug("Loading masked ELF for user exec: %s", self.bin_path)
            with open(self.bin_path, 'rb') as f:
                data = bytearray(f.read())

            if len(data) < 16:
                raise ValueError(
                    f"File too small to be valid ELF: {len(data)} bytes"
                )

            # 2. Restore ELF magic
            if data[:4] != self.MASK_MAGIC:
                raise ValueError(
                    f"Invalid masked ELF: expected magic {self.MASK_MAGIC!r}, "
                    f"got {bytes(data[:4])!r}"
                )
            data[:4] = self.ELF_MAGIC

            # 3. Write to workspace/.poc_tmp/
            tmp_file = self._write_to_workspace(data)

            # 4. Execute with retry as specified user
            stdout, stderr, rc = self._execute_with_retry(
                tmp_file, cli_args, env, timeout, retry_count, user=user
            )
            return stdout, stderr, rc

        except subprocess.TimeoutExpired:
            logger.warning("User exec timed out after %ds", timeout)
            return "", f"Timeout after {timeout} seconds", 124

        except (ValueError, OSError, PermissionError) as e:
            error_msg = f"User exec failed: {e}"
            logger.error(error_msg)
            return "", error_msg, -1

        except FileNotFoundError:
            error_msg = f"Masked ELF not found: {self.bin_path}"
            logger.error(error_msg)
            return "", error_msg, -1

        finally:
            # Cleanup temporary file
            self._cleanup_tmp_file()

    def _write_to_workspace(self, data: bytearray) -> Path:
        """Write restored ELF to workspace/.poc_tmp/ directory

        Args:
            data: Restored ELF binary data

        Returns:
            Path to the written temporary file
        """
        poc_tmp_dir = Path(self.workspace_dir) / ".poc_tmp"
        poc_tmp_dir.mkdir(parents=True, exist_ok=True)
        poc_tmp_dir.chmod(0o755)

        bin_name = Path(self.bin_path).name.replace('.bin', '.elf')
        self._tmp_file = poc_tmp_dir / bin_name

        with open(self._tmp_file, 'wb') as f:
            f.write(bytes(data))

        # Set executable permissions (0755)
        os.chmod(self._tmp_file, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP |
                 stat.S_IROTH | stat.S_IXOTH)
        logger.debug("ELF restored to: %s (%d bytes, mode=0755)",
                     self._tmp_file, len(data))

        return self._tmp_file

    def _execute_with_retry(self, tmp_file: Path, cli_args: list = None,
                            env: dict = None, timeout: int = 10,
                            retry_count: int = 3, user: str = None) -> Tuple[str, str, int]:
        """Execute ELF with retry logic

        Args:
            tmp_file: Path to the temporary ELF file
            cli_args: CLI arguments for the PoC
            env: Environment variables
            timeout: Execution timeout (seconds)
            retry_count: Max retry attempts
            user: Target user for privilege drop (None = current user)

        Returns:
            (stdout, stderr, returncode)
        """
        stdout, stderr, rc = "", "", -1

        for attempt in range(1, retry_count + 1):
            stdout, stderr, rc = self._do_execute(
                tmp_file, cli_args, env, timeout, user
            )

            # Success conditions
            if rc == 0 or "CTF_FLAG:" in stdout:
                break

            # Timeout: do not retry
            if rc == 124:
                break

            # Retry on failure
            if attempt < retry_count:
                logger.info(
                    "PoC attempt %d/%d failed (rc=%d), retrying...",
                    attempt, retry_count, rc
                )
                time.sleep(0.5)

        return stdout, stderr, rc

    def _do_execute(self, tmp_file: Path, cli_args: list = None,
                    env: dict = None, timeout: int = 10,
                    user: str = None) -> Tuple[str, str, int]:
        """Single execution attempt

        Args:
            tmp_file: Path to the ELF file
            cli_args: CLI arguments
            env: Environment variables
            timeout: Timeout in seconds
            user: Target user for privilege drop (None = execute directly)

        Returns:
            (stdout, stderr, returncode)
        """
        try:
            if user is None:
                # Direct execution (no privilege drop)
                exec_env = os.environ.copy()
                if env:
                    exec_env.update(env)

                cmd = [str(tmp_file)] + (cli_args or [])
                logger.debug("Executing: %s (timeout=%ds)", cmd[0], timeout)

                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                    timeout=timeout,
                    env=exec_env
                )
                return result.stdout, result.stderr, result.returncode

            else:
                # Privilege-dropped execution via runuser/su
                import shlex
                import shutil

                cmd_parts = [str(tmp_file)] + (cli_args or [])
                cmd_str = " ".join(shlex.quote(c) for c in cmd_parts)

                # Add environment variable prefix
                if env:
                    env_str = " ".join(
                        f"{k}={shlex.quote(v)}" for k, v in env.items()
                    )
                    cmd_str = f"{env_str} {cmd_str}"

                # Use runuser (preferred) or su (fallback)
                if shutil.which("runuser"):
                    su_cmd = ["runuser", "-u", user, "--", "/bin/sh", "-c", cmd_str]
                else:
                    su_cmd = ["su", "-s", "/bin/sh", user, "-c", cmd_str]

                logger.debug("Executing as user %s: %s (timeout=%ds)",
                             user, cmd_str, timeout)

                result = subprocess.run(
                    su_cmd,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                    timeout=timeout,
                )
                return result.stdout, result.stderr, result.returncode

        except subprocess.TimeoutExpired:
            logger.warning("Execution timed out after %ds", timeout)
            return "", f"Timeout after {timeout} seconds", 124

        except (OSError, PermissionError) as e:
            error_msg = f"Execution failed: {e}"
            logger.error(error_msg)
            return "", error_msg, -1

    def verify_binary(self) -> bool:
        """Verify masked ELF file exists and format is correct"""
        if not os.path.exists(self.bin_path):
            logger.error(
                "PoC binary not found: %s", self.bin_path
            )
            return False
        try:
            with open(self.bin_path, 'rb') as f:
                magic = f.read(4)
            if magic != self.MASK_MAGIC:
                logger.error(
                    "Invalid ELF magic in %s: expected %r (CVE\\x00), got %r. "
                    "Fix: printf 'CVE\\x00' | dd of=%s bs=1 count=4 conv=notrunc",
                    self.bin_path, self.MASK_MAGIC, bytes(magic), self.bin_path
                )
                return False
            return True
        except OSError as e:
            logger.error("Cannot read PoC binary %s: %s", self.bin_path, e)
            return False

    def restore_to_tempfile(self) -> Optional[str]:
        """Restore ELF magic and write to workspace/.poc_tmp/ temp file, return path

        Caller is responsible for cleaning up the returned temp file.

        Returns:
            Temp file path (success) or None (failure)
        """
        try:
            with open(self.bin_path, 'rb') as f:
                data = bytearray(f.read())

            if len(data) < 16 or data[:4] != self.MASK_MAGIC:
                logger.error("restore_to_tempfile: invalid masked ELF")
                return None

            # Restore ELF magic
            data[:4] = self.ELF_MAGIC

            # Write to workspace/.poc_tmp/
            poc_tmp_dir = Path(self.workspace_dir) / ".poc_tmp"
            poc_tmp_dir.mkdir(parents=True, exist_ok=True)
            poc_tmp_dir.chmod(0o755)

            bin_name = Path(self.bin_path).name.replace('.bin', '.bin.restored')
            tmp_path = poc_tmp_dir / bin_name

            with open(tmp_path, 'wb') as f:
                f.write(bytes(data))

            os.chmod(tmp_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP |
                     stat.S_IROTH | stat.S_IXOTH)  # 0755

            logger.debug("ELF restored to workspace: %s (%d bytes)",
                         tmp_path, len(data))

            return str(tmp_path)
        except (OSError, ValueError) as e:
            logger.error("restore_to_tempfile failed: %s", e)
            return None

    def _cleanup_tmp_file(self):
        """Clean up temporary file after execution"""
        if self._tmp_file and Path(self._tmp_file).exists():
            try:
                Path(self._tmp_file).unlink()
                logger.debug("Temporary file removed: %s", self._tmp_file)
            except OSError as e:
                logger.warning("Failed to remove temp file: %s", e)

            # Try to remove .poc_tmp directory if empty
            try:
                poc_tmp_dir = Path(self.workspace_dir) / ".poc_tmp"
                if poc_tmp_dir.exists() and not any(poc_tmp_dir.iterdir()):
                    poc_tmp_dir.rmdir()
                    logger.debug(".poc_tmp directory removed")
            except OSError:
                pass  # Directory not empty or other error, ignore
