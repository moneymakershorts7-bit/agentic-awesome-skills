"""
CVE-2026-43500 Prepare phase handler

Ensure rxrpc module available, create root-owned target file with canary
content for RxRPC rxkad page cache overwrite verification.

The target file is owned by root:root with mode 0644 (read-only for others).
The PoC (running as nobody) cannot normally write to this file.
If the PoC overwrites the canary via RxRPC rxkad splice page cache corruption,
it proves the vulnerability is exploitable.

Does NOT require unprivileged user namespaces.
"""
import logging
import os
import secrets
import socket
import subprocess
import tempfile
from typing import List

from ..poc.phases.prepare import BasePrepareHandler
from ..core.result import PrepareOperation

logger = logging.getLogger(__name__)

_MODULE_NAME = "rxrpc"


class CVE202643500PrepareHandler(BasePrepareHandler):
    """CVE-2026-43500 Prepare phase: load rxrpc module + create root-owned CTF target"""

    def __init__(self, timeout: int = 60, test_mode: str = "write_root_file",
                 ctf_value: str = ""):
        super().__init__(timeout=timeout)
        self._tmp_dir = ""
        self._target_file = ""
        self._module_was_loaded = False
        self._test_mode = test_mode
        self._ctf_value = ctf_value
        self._initial_content = ""

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Return list of prepare operations"""
        operations: List[PrepareOperation] = []

        self._module_was_loaded = self._is_module_loaded()
        operations.append(PrepareOperation(
            action="snapshot",
            target="module_state",
            result="pending",
        ))

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

        self._target_file = os.path.join(self._tmp_dir, "poc_target_canary")
        operations.append(PrepareOperation(
            action="create_target_file",
            target=self._target_file,
            result="pending",
            rollback_cmd=f"rm -f {self._target_file}",
        ))

        operations.append(PrepareOperation(
            action="snapshot",
            target="system_state",
            result="pending",
        ))

        return operations

    def _execute_operation(self, op: PrepareOperation) -> PrepareOperation:
        """Override execution logic for CVE-specific scenarios"""
        if op.action == "snapshot" and op.target == "module_state":
            return self._snapshot_module_state(op)
        elif op.action == "load_module" and op.target == _MODULE_NAME:
            return self._handle_load_module(op)
        elif op.action == "create_target_file":
            return self._create_target_file(op)
        elif op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        else:
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
        """Create root-owned target file for CTF challenge."""
        target_path = op.target
        try:
            if self._test_mode == "read_root_file":
                content = self._ctf_value
                file_mode = 0o400
            else:
                self._initial_content = f"writeme_{secrets.token_hex(8)}"
                content = self._initial_content.ljust(4096, '\x00')
                file_mode = 0o644

            fd = os.open(
                target_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, file_mode
            )
            os.write(fd, content.encode("utf-8"))
            os.close(fd)

            os.chown(target_path, 0, 0)
            os.chmod(target_path, file_mode)

            st = os.stat(target_path)
            if st.st_uid != 0:
                op.result = "failed"
                op.error = f"Target file uid={st.st_uid}, expected 0 (root)"
                return op

            op.result = "success"
            logger.info(
                "Created CTF target: %s (mode=%s, uid=%d, perm=%o, size=%d)",
                target_path, self._test_mode,
                st.st_uid, st.st_mode & 0o777, st.st_size,
            )
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
            logger.error("Failed to create target file %s: %s", target_path, e)

        return op

    def _handle_load_module(self, op: PrepareOperation) -> PrepareOperation:
        """Handle rxrpc module loading via modprobe or socket autoload"""
        if self._module_was_loaded:
            op.result = "success"
            logger.debug("Module %s already loaded, skipping", _MODULE_NAME)
            return op

        try:
            result = subprocess.run(
                ["modprobe", _MODULE_NAME],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=10,
            )
            if result.returncode == 0:
                op.result = "success"
                logger.info("Module %s loaded via modprobe", _MODULE_NAME)
                return op
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        try:
            AF_RXRPC = 33
            s = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, 0)
            s.close()
            if self._is_module_loaded():
                op.result = "success"
                logger.info("Module %s loaded via socket autoload", _MODULE_NAME)
                return op
        except OSError:
            pass

        op.result = "failed"
        op.error = f"Cannot load module {_MODULE_NAME} via modprobe or socket"
        op.rollback_cmd = ""
        logger.warning("Failed to load module %s", _MODULE_NAME)
        return op

    def _snapshot_system_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record system state snapshot"""
        snapshot_parts = []

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

        try:
            result = subprocess.run(
                "lsmod | grep rxrpc",
                shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                snapshot_parts.append(f"rxrpc_modules={result.stdout.strip()}")
            else:
                snapshot_parts.append("rxrpc_modules=none")
        except (subprocess.TimeoutExpired, OSError):
            snapshot_parts.append("rxrpc_modules=check_failed")

        op.result = "success"
        logger.debug("System state snapshot: %s", "; ".join(snapshot_parts))
        return op

    def _is_module_loaded(self) -> bool:
        """Check if rxrpc module is already loaded"""
        try:
            with open("/proc/modules", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith(_MODULE_NAME + " "):
                        return True
        except OSError:
            pass
        return False

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """Build enhanced state snapshot including CTF challenge info"""
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["module_was_loaded"] = self._module_was_loaded
        base_snapshot["tmp_dir"] = self._tmp_dir
        base_snapshot["target_file"] = self._target_file
        base_snapshot["test_mode"] = self._test_mode
        base_snapshot["ctf_value"] = self._ctf_value
        base_snapshot["initial_content"] = self._initial_content
        return base_snapshot
