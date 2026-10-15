"""
CVE-2004-1235 Prepare phase handler

Create CTF challenge environment for uselib() race condition verification.
Creates root-owned target file with CTF flag content for read verification.

The target file is owned by root:root with mode 0400 (nobody cannot access).
The PoC (running as nobody) must use the vulnerability path to read the content.
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


class CVE20041235PrepareHandler(BasePrepareHandler):
    """CVE-2004-1235 Prepare phase: create CTF challenge environment"""

    def __init__(self, timeout: int = 30, test_mode: str = "read_root_file",
                 ctf_value: str = ""):
        super().__init__(timeout=timeout)
        self._tmp_dir = ""
        self._target_file = ""
        self._test_mode = test_mode
        self._ctf_value = ctf_value
        self._initial_content = ""
        self._kernel_version = ""
        self._uselib_state = ""
        self._ldt_state = ""

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Return list of prepare operations

        Args:
            kernel_info: Kernel info dict

        Returns:
            List of operations
        """
        operations: List[PrepareOperation] = []

        # Operation 1: Record kernel version
        operations.append(PrepareOperation(
            action="snapshot",
            target="kernel_version_state",
            result="pending",
        ))

        # Operation 2: Record uselib state
        operations.append(PrepareOperation(
            action="snapshot",
            target="uselib_state",
            result="pending",
        ))

        # Operation 3: Record LDT state
        operations.append(PrepareOperation(
            action="snapshot",
            target="ldt_state",
            result="pending",
        ))

        # Operation 4: Create temporary test directory
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

        # Operation 5: Create root-owned target file with CTF content
        self._target_file = os.path.join(self._tmp_dir, "poc_target_canary")
        operations.append(PrepareOperation(
            action="create_target_file",
            target=self._target_file,
            result="pending",
            rollback_cmd=f"rm -f {self._target_file}",
        ))

        # Operation 6: System state snapshot
        operations.append(PrepareOperation(
            action="snapshot",
            target="system_state",
            result="pending",
        ))

        return operations

    def _execute_operation(self, op: PrepareOperation) -> PrepareOperation:
        """Override execution logic for CVE-specific scenarios

        Args:
            op: Prepare operation object

        Returns:
            Executed operation object
        """
        if op.action == "snapshot" and op.target == "kernel_version_state":
            return self._snapshot_kernel_version(op)
        elif op.action == "snapshot" and op.target == "uselib_state":
            return self._snapshot_uselib(op)
        elif op.action == "snapshot" and op.target == "ldt_state":
            return self._snapshot_ldt(op)
        elif op.action == "create_target_file":
            return self._create_target_file(op)
        elif op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        else:
            return super()._execute_operation(op)

    def _snapshot_kernel_version(self, op: PrepareOperation) -> PrepareOperation:
        """Record kernel version"""
        try:
            result = subprocess.run(
                ["uname", "-r"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                self._kernel_version = result.stdout.strip()
                op.result = "success"
                logger.debug("kernel_version = %s", self._kernel_version)
            else:
                op.result = "failed"
                op.error = "uname failed"
        except (subprocess.TimeoutExpired, OSError) as e:
            op.result = "failed"
            op.error = str(e)
        return op

    def _snapshot_uselib(self, op: PrepareOperation) -> PrepareOperation:
        """Record uselib syscall availability"""
        uselib_found = False
        try:
            with open("/proc/kallsyms", "r", encoding="utf-8") as f:
                for line in f:
                    if "uselib" in line.lower():
                        uselib_found = True
                        break
            self._uselib_state = "present" if uselib_found else "absent"
            op.result = "success"
            logger.debug("uselib = %s", self._uselib_state)
        except (OSError, PermissionError) as e:
            self._uselib_state = "unknown"
            op.result = "success"  # Not a failure, just unknown
            logger.debug("uselib state unknown: %s", e)
        return op

    def _snapshot_ldt(self, op: PrepareOperation) -> PrepareOperation:
        """Record LDT (Local Descriptor Table) availability"""
        ldt_found = False
        try:
            with open("/proc/kallsyms", "r", encoding="utf-8") as f:
                for line in f:
                    if "modify_ldt" in line.lower() or "ldt" in line.lower():
                        ldt_found = True
                        break
            self._ldt_state = "present" if ldt_found else "absent"
            op.result = "success"
            logger.debug("ldt = %s", self._ldt_state)
        except (OSError, PermissionError) as e:
            self._ldt_state = "unknown"
            op.result = "success"
            logger.debug("ldt state unknown: %s", e)
        return op

    def _create_target_file(self, op: PrepareOperation) -> PrepareOperation:
        """Create root-owned target file for CTF challenge.

        CTF mode determines file content and permissions:
        - read_root_file: Write ctf_value as flag, set 0400 (nobody cannot access)

        File permissions rationale:
        - read mode (0400): true kernel info leak should bypass VFS permission,
          if open() is needed, it's not a real arbitrary read vulnerability
        """
        target_path = op.target
        try:
            # CVE-2004-1235 only supports read_root_file mode
            if self._test_mode == "read_root_file":
                # PoC needs to read this value out as CTF flag
                content = self._ctf_value
                file_mode = 0o400  # nobody cannot access at all — real CTF
            else:
                # write_root_file is not supported for this CVE
                self._initial_content = f"writeme_{secrets.token_hex(8)}"
                content = self._initial_content
                file_mode = 0o644

            fd = os.open(
                target_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, file_mode
            )
            os.write(fd, content.encode("utf-8"))
            os.close(fd)

            # Ensure ownership is root:root (prepare runs as root)
            os.chown(target_path, 0, 0)
            # Enforce permissions explicitly
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
        """Record system state snapshot (uname, dmesg tail)"""
        snapshot_parts = []

        # uname -r
        snapshot_parts.append(f"kernel={self._kernel_version}")

        # uselib state
        snapshot_parts.append(f"uselib={self._uselib_state}")

        # ldt state
        snapshot_parts.append(f"ldt={self._ldt_state}")

        op.result = "success"
        logger.debug("System state snapshot: %s", "; ".join(snapshot_parts))
        return op

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """Build enhanced state snapshot"""
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["kernel_version"] = self._kernel_version
        base_snapshot["uselib_state"] = self._uselib_state
        base_snapshot["ldt_state"] = self._ldt_state
        base_snapshot["tmp_dir"] = self._tmp_dir
        base_snapshot["target_file"] = self._target_file
        base_snapshot["test_mode"] = self._test_mode
        base_snapshot["ctf_value"] = self._ctf_value
        base_snapshot["initial_content"] = self._initial_content
        return base_snapshot
