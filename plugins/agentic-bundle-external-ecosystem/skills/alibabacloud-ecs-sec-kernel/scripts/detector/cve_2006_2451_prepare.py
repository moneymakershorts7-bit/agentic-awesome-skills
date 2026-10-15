"""
CVE-2006-2451 Prepare phase handler

Create CTF challenge environment for prctl(PR_SET_DUMPABLE) vulnerability:
- Creates temporary test directory
- Creates root-owned target file with CTF-appropriate content based on test mode:
  - read_root_file: root:root 0400 with ctf_value as content
  - write_root_file: root:root 0644 with writeme_{hex} initial content
- Records system state snapshot for Post phase rollback
"""
import logging
import os
import secrets
import subprocess
import tempfile
from typing import List

from ..poc.phases.prepare import BasePrepareHandler
from ..core.result import PrepareOperation

logger = logging.getLogger(__name__)

_SUID_DUMPABLE_PATH = "/proc/sys/fs/suid_dumpable"
_CORE_PATTERN_PATH = "/proc/sys/kernel/core_pattern"


class CVE20062451PrepareHandler(BasePrepareHandler):
    """CVE-2006-2451 Prepare phase: create CTF target for prctl dumpable exploit"""

    def __init__(self, timeout: int = 30, test_mode: str = "write_root_file",
                 ctf_value: str = ""):
        super().__init__(timeout=timeout)
        self._tmp_dir = ""
        self._target_file = ""
        self._suid_dumpable_original = ""
        self._core_pattern_original = ""
        self._test_mode = test_mode
        self._ctf_value = ctf_value
        self._initial_content = ""

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Return list of prepare operations

        Args:
            kernel_info: Kernel info dictionary

        Returns:
            List of PrepareOperation
        """
        operations: List[PrepareOperation] = []

        # Operation 1: Record suid_dumpable state
        self._suid_dumpable_original = self._read_sysctl(_SUID_DUMPABLE_PATH)
        operations.append(PrepareOperation(
            action="snapshot",
            target="suid_dumpable_state",
            result="pending",
        ))

        # Operation 2: Record core_pattern state
        self._core_pattern_original = self._read_sysctl(_CORE_PATTERN_PATH)
        operations.append(PrepareOperation(
            action="snapshot",
            target="core_pattern_state",
            result="pending",
        ))

        # Operation 3: Create temporary test directory
        self._tmp_dir = os.path.join(
            tempfile.gettempdir(),
            f"sec-kernel-poc-{os.getpid()}"
        )
        operations.append(PrepareOperation(
            action="create_dir",
            target=self._tmp_dir,
            result="pending",
            rollback_cmd=f"rm -rf {self._tmp_dir}",
        ))

        # Operation 4: Create root-owned CTF target file
        self._target_file = os.path.join(self._tmp_dir, "poc_target_canary")
        operations.append(PrepareOperation(
            action="create_target_file",
            target=self._target_file,
            result="pending",
            rollback_cmd=f"rm -f {self._target_file}",
        ))

        # Operation 5: System state snapshot
        operations.append(PrepareOperation(
            action="snapshot",
            target="system_state",
            result="pending",
        ))

        return operations

    def _execute_operation(self, op: PrepareOperation) -> PrepareOperation:
        """Override execution logic to handle CVE-specific scenarios

        Args:
            op: Prepare operation object

        Returns:
            Operation object after execution
        """
        if op.action == "snapshot" and op.target == "suid_dumpable_state":
            return self._snapshot_suid_dumpable(op)
        elif op.action == "snapshot" and op.target == "core_pattern_state":
            return self._snapshot_core_pattern(op)
        elif op.action == "create_target_file":
            return self._create_target_file(op)
        elif op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        else:
            return super()._execute_operation(op)

    def _snapshot_suid_dumpable(self, op: PrepareOperation) -> PrepareOperation:
        """Record fs.suid_dumpable current value"""
        try:
            value = self._read_sysctl(_SUID_DUMPABLE_PATH)
            op.result = "success"
            logger.debug("suid_dumpable = %s", value)
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
        return op

    def _snapshot_core_pattern(self, op: PrepareOperation) -> PrepareOperation:
        """Record kernel.core_pattern current value"""
        try:
            value = self._read_sysctl(_CORE_PATTERN_PATH)
            op.result = "success"
            logger.debug("core_pattern = %s", value)
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
        return op

    def _create_target_file(self, op: PrepareOperation) -> PrepareOperation:
        """Create root-owned target file for CTF challenge.

        CTF mode determines file content and permissions:
        - read_root_file: Write ctf_value as flag, set 0400 (nobody cannot access)
        - write_root_file: Write writeme_{hex} initial content, set 0644

        File permissions rationale:
        - write mode (0644): core dump attack path needs directory access,
          the security breach is "writing to restricted dirs"
        - read mode (0400): true info leak should bypass VFS permission
        """
        target_path = op.target
        try:
            # Determine content and permissions based on CTF test mode
            if self._test_mode == "read_root_file":
                content = self._ctf_value
                file_mode = 0o400  # nobody cannot access at all
            else:
                self._initial_content = f"writeme_{secrets.token_hex(8)}"
                content = self._initial_content
                file_mode = 0o644  # nobody can read not write

            # Pad content to full page size (4096 bytes) for safety
            padded_content = content.ljust(4096, '\x00')

            fd = os.open(
                target_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, file_mode
            )
            os.write(fd, padded_content.encode("utf-8"))
            os.close(fd)

            # Ensure ownership is root:root (prepare runs as root)
            os.chown(target_path, 0, 0)
            os.chmod(target_path, file_mode)

            # Verify setup
            st = os.stat(target_path)
            if st.st_uid != 0:
                op.result = "failed"
                op.error = f"Target file uid={st.st_uid}, expected 0 (root)"
                return op

            op.result = "success"
            logger.info(
                "Created CTF target: %s (mode=%s, uid=%d, perm=%o, size=%d, content=%s)",
                target_path, self._test_mode,
                st.st_uid, st.st_mode & 0o777, st.st_size,
                content[:30],
            )
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
            logger.error(
                "Failed to create target file %s: %s", target_path, e
            )

        return op

    def _snapshot_system_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record system state snapshot (uname, suid_dumpable, core_pattern)"""
        snapshot_parts = []

        # uname -r
        try:
            result = subprocess.run(
                ["uname", "-r"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                snapshot_parts.append(f"kernel={result.stdout.strip()}")
        except (subprocess.TimeoutExpired, OSError):
            snapshot_parts.append("kernel=unknown")

        snapshot_parts.append(f"suid_dumpable={self._suid_dumpable_original}")
        snapshot_parts.append(f"core_pattern={self._core_pattern_original}")

        op.result = "success"
        logger.debug("System state snapshot: %s", "; ".join(snapshot_parts))
        return op

    def _read_sysctl(self, path: str) -> str:
        """Read sysctl value

        Args:
            path: /proc/sys path

        Returns:
            sysctl value, empty string on failure
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return ""

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """Build enhanced state snapshot including CTF challenge info"""
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["suid_dumpable_original"] = self._suid_dumpable_original
        base_snapshot["core_pattern_original"] = self._core_pattern_original
        base_snapshot["tmp_dir"] = self._tmp_dir
        base_snapshot["target_file"] = self._target_file
        base_snapshot["test_mode"] = self._test_mode
        base_snapshot["ctf_value"] = self._ctf_value
        base_snapshot["initial_content"] = self._initial_content
        return base_snapshot
