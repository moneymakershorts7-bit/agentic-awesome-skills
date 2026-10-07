"""
CVE-2026-31431 Prepare phase handler

Ensure algif_aead module available, create root-owned target file with canary
content for splice page cache overwrite verification.

The target file is owned by root:root with mode 0644 (read-only for others).
The PoC (running as uid=1000) cannot normally write to this file.
If the PoC manages to overwrite the canary via AEAD splice, it proves the
vulnerability is exploitable.
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

_MODULE_NAME = "algif_aead"

# Must match the C PoC CANARY_MAGIC definition
CANARY_CONTENT = "SEC_KERNEL_CANARY_31431_INTEGRITY_CHECK"


class CVE202631431PrepareHandler(BasePrepareHandler):
    """CVE-2026-31431 Prepare phase: load module + create root-owned CTF target"""

    def __init__(self, timeout: int = 30, test_mode: str = "write_root_file",
                 ctf_value: str = ""):
        super().__init__(timeout=timeout)
        self._tmp_dir = ""
        self._target_file = ""
        self._module_was_loaded = False
        self._test_mode = test_mode
        self._ctf_value = ctf_value
        self._initial_content = ""

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Return list of prepare operations

        Args:
            kernel_info: Kernel info dictionary

        Returns:
            List of operations
        """
        operations: List[PrepareOperation] = []

        # Operation 1: Record current module state (snapshot)
        self._module_was_loaded = self._is_module_loaded()
        operations.append(PrepareOperation(
            action="snapshot",
            target="module_state",
            result="pending",
        ))

        # Operation 2: Load algif_aead module (if not loaded)
        if self._module_was_loaded:
            operations.append(PrepareOperation(
                action="load_module",
                target=_MODULE_NAME,
                result="pending",
                rollback_cmd="",
            ))
        else:
            operations.append(PrepareOperation(
                action="load_module",
                target=_MODULE_NAME,
                result="pending",
                rollback_cmd=f"rmmod {_MODULE_NAME}",
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

        # Operation 4: Create root-owned target file with canary content
        # This file will be root:root 0644 - uid=1000 can read but NOT write
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
        if op.action == "snapshot" and op.target == "module_state":
            return self._snapshot_module_state(op)
        elif op.action == "load_module" and op.target == _MODULE_NAME:
            return self._handle_load_module(op)
        elif op.action == "create_target_file":
            return self._create_target_file(op)
        elif op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        else:
            # Other operations use base class default logic
            return super()._execute_operation(op)

    def _snapshot_module_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record current module state"""
        try:
            loaded = self._is_module_loaded()
            op.result = "success"
            logger.debug(
                "Module %s state: %s",
                _MODULE_NAME,
                "loaded" if loaded else "not loaded",
            )
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
        - write mode (0644): splice attack path needs open(O_RDONLY) to get page,
          but the security breach is "writing" - nobody pollutes page cache
        - read mode (0400): true kernel info leak should bypass VFS permission,
          if open() is needed, it's not a real arbitrary read vulnerability
        """
        target_path = op.target
        try:
            # Determine content and permissions based on CTF test mode
            if self._test_mode == "read_root_file":
                # PoC needs to read this value out as CTF flag
                content = self._ctf_value
                file_mode = 0o400  # nobody cannot access at all — real CTF
            else:
                # write_root_file: generate writeme_{hex} as initial content
                self._initial_content = f"writeme_{secrets.token_hex(8)}"
                content = self._initial_content
                file_mode = 0o644  # nobody can read not write — exploit needs open(O_RDONLY)

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

    def _handle_load_module(self, op: PrepareOperation) -> PrepareOperation:
        """Handle module loading"""
        if self._module_was_loaded:
            # Already loaded, skip
            op.result = "success"
            logger.debug("Module %s already loaded, skipping", _MODULE_NAME)
            return op

        # Attempt to load module
        try:
            result = subprocess.run(
                ["modprobe", _MODULE_NAME],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=10,
            )
            if result.returncode == 0:
                op.result = "success"
                logger.info("Module %s loaded successfully", _MODULE_NAME)
            else:
                op.result = "failed"
                op.error = result.stderr.strip() or f"returncode={result.returncode}"
                # Clear rollback_cmd on load failure (no need to rollback)
                op.rollback_cmd = ""
                logger.warning(
                    "Failed to load module %s: %s", _MODULE_NAME, op.error
                )
        except subprocess.TimeoutExpired:
            op.result = "failed"
            op.error = "modprobe timeout (10s)"
            op.rollback_cmd = ""
        except FileNotFoundError:
            op.result = "failed"
            op.error = "modprobe command not found"
            op.rollback_cmd = ""
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
            op.rollback_cmd = ""

        return op

    def _snapshot_system_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record system state snapshot (uname, lsmod, dmesg tail)"""
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

        # lsmod | grep algif
        try:
            result = subprocess.run(
                "lsmod | grep algif",
                shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                snapshot_parts.append(f"algif_modules={result.stdout.strip()}")
            else:
                snapshot_parts.append("algif_modules=none")
        except (subprocess.TimeoutExpired, OSError):
            snapshot_parts.append("algif_modules=check_failed")

        # dmesg tail 10
        try:
            result = subprocess.run(
                ["dmesg"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                tail = lines[-10:] if len(lines) >= 10 else lines
                snapshot_parts.append(f"dmesg_tail={len(tail)} lines")
            else:
                snapshot_parts.append("dmesg_tail=unavailable")
        except (subprocess.TimeoutExpired, OSError):
            snapshot_parts.append("dmesg_tail=read_failed")

        op.result = "success"
        logger.debug("System state snapshot: %s", "; ".join(snapshot_parts))
        return op

    def _is_module_loaded(self) -> bool:
        """Check if algif_aead module is already loaded

        Returns:
            True if loaded, False otherwise
        """
        try:
            with open("/proc/modules", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith(_MODULE_NAME + " "):
                        return True
        except OSError:
            # Assume not loaded when /proc/modules cannot be read
            pass
        return False

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """Build enhanced state snapshot including CTF challenge info"""
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["module_was_loaded"] = self._module_was_loaded
        base_snapshot["tmp_dir"] = self._tmp_dir
        base_snapshot["target_file"] = self._target_file
        base_snapshot["canary_content"] = CANARY_CONTENT
        base_snapshot["test_mode"] = self._test_mode
        base_snapshot["ctf_value"] = self._ctf_value
        base_snapshot["initial_content"] = self._initial_content
        return base_snapshot
